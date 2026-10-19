//! Client for DeGiro's unofficial web API (the endpoints trader.degiro.nl's own frontend calls).
//!
//! The session is kept alive across tool calls and only re-established when it is older than DeGiro's
//! ~30 minute idle timeout or a call comes back 401. Logins are throttled hard: the /totp endpoint
//! answers 429 on fast retries, and repeated failures lock the account or trigger a captcha.
const std = @import("std");
const fetch = @import("fetch.zig");
const totp = @import("totp.zig");

const log = std.log.scoped(.degiro);

const login_url = "https://trader.degiro.nl/login/secure/login/totp";
const config_url = "https://trader.degiro.nl/login/secure/config";
const chart_url = "https://charting.vwdservices.com/hchart/v1/deGiro/data.js";

/// Re-login well before DeGiro's 1800s idle timeout.
const session_max_idle = 25 * 60;
/// Minimum time between two login attempts.
const login_min_interval = 60;
/// After a failed login, wait this long before trying again.
const login_failure_backoff = 10 * 60;

pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
    totp_key: []const u8,
};

pub const Base = enum { trading, pa, product_search, reporting };

pub const Error = error{
    LoginFailed,
    LoginThrottled,
    Upstream,
    Unauthorized,
};

const Session = struct {
    id: []const u8,
    int_account: i64,
    client_id: i64,
    trading_url: []const u8,
    pa_url: []const u8,
    product_search_url: []const u8,
    reporting_url: []const u8,
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    http: *fetch.Http,
    creds: Credentials,

    mutex: std.Io.Mutex = .init,
    session_arena: std.heap.ArenaAllocator,
    session: ?Session = null,
    last_ok: i64 = 0,
    last_login_attempt: i64 = 0,
    login_blocked_until: i64 = 0,
    last_login_error: []const u8 = "",
    last_login_error_buf: [160]u8 = undefined,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, http: *fetch.Http, creds: Credentials) Client {
        return .{ .gpa = gpa, .io = io, .http = http, .creds = creds, .session_arena = .init(gpa) };
    }

    pub fn deinit(self: *Client) void {
        self.session_arena.deinit();
    }

    fn now(self: *Client) i64 {
        return std.Io.Timestamp.now(self.io, .real).toSeconds();
    }

    pub const Request = struct {
        method: std.http.Method = .GET,
        base: Base,
        /// Path relative to the base URL, e.g. "v5/update/{intAccount}". `{intAccount}` is substituted.
        path: []const u8,
        /// Extra query string without the leading '?', already URL-encoded.
        query: []const u8 = "",
        body: ?[]const u8 = null,
        /// Trading endpoints carry the session as a `;jsessionid=` path parameter as well.
        jsessionid_path: bool = false,
        /// On an upstream error, receives DeGiro's error body so the caller can surface it.
        diag: ?*[]const u8 = null,
    };

    /// Performs an authenticated call and returns the parsed JSON body (allocated in `arena`).
    /// A 401 triggers one re-login and a retry.
    pub fn call(self: *Client, arena: std.mem.Allocator, req: Request) !std.json.Value {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const s = try self.ensureSession();
            const res = try self.send(arena, s, req);
            if (res.status == .unauthorized and attempt == 0) {
                log.info("session rejected, logging in again", .{});
                self.session = null;
                continue;
            }
            if (!res.ok()) {
                if (req.diag) |d| d.* = res.body;
                return upstreamError(res);
            }
            self.last_ok = self.now();
            if (res.body.len == 0) return .null;
            return std.json.parseFromSliceLeaky(std.json.Value, arena, res.body, .{}) catch {
                log.err("non-JSON response ({d} bytes) from {s}", .{ res.body.len, req.path });
                return error.Upstream;
            };
        }
    }

    /// Same as `call`, but for vwd's charting service which only needs the numeric clientId.
    pub fn chart(self: *Client, arena: std.mem.Allocator, query: []const u8) !std.json.Value {
        const client_id = blk: {
            try self.mutex.lock(self.io);
            defer self.mutex.unlock(self.io);
            break :blk (try self.ensureSession()).client_id;
        };
        const url = try std.fmt.allocPrint(arena, "{s}?requestid=1&format=json&culture=nl-NL&tz=Europe%2FAmsterdam&userToken={d}&{s}", .{ chart_url, client_id, query });
        const res = try self.http.send(arena, .GET, url, .{ .headers = &browser_headers });
        if (!res.ok()) return upstreamError(res);
        // Without a callback param vwd answers plain JSON, but strip a JSONP wrapper just in case.
        var body: []const u8 = res.body;
        if (std.mem.indexOfScalar(u8, body, '(')) |open| if (open < 80 and body[0] != '{') {
            const close = std.mem.lastIndexOfScalar(u8, body, ')') orelse body.len;
            body = body[open + 1 .. close];
        };
        return std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch error.Upstream;
    }

    pub fn intAccount(self: *Client) !i64 {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        return (try self.ensureSession()).int_account;
    }

    fn send(self: *Client, arena: std.mem.Allocator, s: Session, req: Request) !fetch.Response {
        const base = switch (req.base) {
            .trading => s.trading_url,
            .pa => s.pa_url,
            .product_search => s.product_search_url,
            .reporting => s.reporting_url,
        };
        var acct_buf: [24]u8 = undefined;
        const acct = std.fmt.bufPrint(&acct_buf, "{d}", .{s.int_account}) catch unreachable;
        const path = try std.mem.replaceOwned(u8, arena, req.path, "{intAccount}", acct);
        const url = try std.fmt.allocPrint(arena, "{s}{s}{s}{s}?{s}{s}intAccount={d}&sessionId={s}", .{
            base,
            path,
            if (req.jsessionid_path) ";jsessionid=" else "",
            if (req.jsessionid_path) s.id else "",
            req.query,
            if (req.query.len > 0) "&" else "",
            s.int_account,
            s.id,
        });
        const cookie = try std.fmt.allocPrint(arena, "JSESSIONID={s}", .{s.id});
        const headers = browser_headers ++ [_]std.http.Header{.{ .name = "Cookie", .value = cookie }};
        return self.http.send(arena, req.method, url, .{ .headers = &headers, .body = req.body });
    }

    fn ensureSession(self: *Client) !Session {
        const t = self.now();
        if (self.session) |s| {
            if (t - self.last_ok < session_max_idle) return s;
            log.info("session idle for {d}s, logging in again", .{t - self.last_ok});
            self.session = null;
        }
        if (t < self.login_blocked_until) {
            log.warn("login blocked for another {d}s after: {s}", .{ self.login_blocked_until - t, self.last_login_error });
            return error.LoginThrottled;
        }
        if (t - self.last_login_attempt < login_min_interval) return error.LoginThrottled;
        self.last_login_attempt = t;

        _ = self.session_arena.reset(.retain_capacity);
        const s = self.login(self.session_arena.allocator()) catch |err| {
            self.login_blocked_until = t + login_failure_backoff;
            return err;
        };
        self.session = s;
        self.last_ok = self.now();
        log.info("logged in", .{});
        return s;
    }

    fn login(self: *Client, arena: std.mem.Allocator) !Session {
        const otp = totp.code(self.creds.totp_key, self.now());
        var otp_buf: [6]u8 = undefined;
        _ = std.fmt.bufPrint(&otp_buf, "{d:0>6}", .{otp}) catch unreachable;

        const body = try std.json.Stringify.valueAlloc(arena, .{
            .username = self.creds.username,
            .password = self.creds.password,
            .isPassCodeReset = false,
            .isRedirectToMobile = false,
            .queryParams = .{},
            .oneTimePassword = otp_buf[0..],
        }, .{});
        const res = try self.http.send(arena, .POST, login_url, .{ .headers = &browser_headers, .body = body });
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, res.body, .{}) catch .null;
        const sid = getStr(parsed, "sessionId");
        if (!res.ok() or sid == null) {
            self.last_login_error = std.fmt.bufPrint(&self.last_login_error_buf, "HTTP {d}, status={?d} {s}", .{
                @intFromEnum(res.status),
                getInt(parsed, "status"),
                getStr(parsed, "statusText") orelse "",
            }) catch "(error text too long)";
            log.err("login failed: {s}", .{self.last_login_error});
            return if (res.status == .too_many_requests) error.LoginThrottled else error.LoginFailed;
        }

        const cookie = try std.fmt.allocPrint(arena, "JSESSIONID={s}", .{sid.?});
        const headers = browser_headers ++ [_]std.http.Header{.{ .name = "Cookie", .value = cookie }};

        const cfg_res = try self.http.send(arena, .GET, config_url, .{ .headers = &headers });
        if (!cfg_res.ok()) return error.LoginFailed;
        const cfg = (try std.json.parseFromSliceLeaky(std.json.Value, arena, cfg_res.body, .{})).object.get("data") orelse return error.LoginFailed;

        var s: Session = .{
            .id = sid.?,
            .int_account = 0,
            .client_id = getInt(cfg, "clientId") orelse 0,
            .trading_url = getStr(cfg, "tradingUrl") orelse return error.LoginFailed,
            .pa_url = getStr(cfg, "paUrl") orelse return error.LoginFailed,
            .product_search_url = getStr(cfg, "productSearchUrl") orelse return error.LoginFailed,
            .reporting_url = getStr(cfg, "reportingUrl") orelse return error.LoginFailed,
        };

        const client_url = try std.fmt.allocPrint(arena, "{s}client?sessionId={s}", .{ s.pa_url, s.id });
        const cl_res = try self.http.send(arena, .GET, client_url, .{ .headers = &headers });
        if (!cl_res.ok()) return error.LoginFailed;
        const cl = (try std.json.parseFromSliceLeaky(std.json.Value, arena, cl_res.body, .{})).object.get("data") orelse return error.LoginFailed;
        s.int_account = getInt(cl, "intAccount") orelse return error.LoginFailed;
        return s;
    }
};

const browser_headers = [_]std.http.Header{
    .{ .name = "Origin", .value = "https://trader.degiro.nl" },
    .{ .name = "Referer", .value = "https://trader.degiro.nl/trader/" },
    .{ .name = "Accept", .value = "application/json, text/plain, */*" },
};

/// Logs only the status: error bodies can echo account data, and the caller already hands DeGiro's
/// message to the tool result via `diag`.
fn upstreamError(res: fetch.Response) Error {
    log.err("upstream HTTP {d}", .{@intFromEnum(res.status)});
    return if (res.status == .unauthorized) error.Unauthorized else error.Upstream;
}

pub fn getStr(v: std.json.Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

pub fn getInt(v: std.json.Value, key: []const u8) ?i64 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return switch (x) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        .string, .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}
