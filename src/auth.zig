//! Bearer-token check for /mcp: OIDC-issued RS256 JWTs (JWKS discovered from the issuer), plus an
//! optional static token for clients that can't do OAuth.
const std = @import("std");
const fetch = @import("fetch.zig");
const jwt = @import("jwt.zig");

const log = std.log.scoped(.auth);

/// Refetch the JWKS at least this often, and at most once per `refetch_min` when an unknown kid shows up.
const keys_max_age = 60 * 60;
const refetch_min = 60;

pub const Verifier = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    http: *fetch.Http,
    issuer: []const u8,
    audience: []const u8 = "",
    static_token: []const u8 = "",
    /// Comma-separated; empty means any user the issuer lets through.
    allowed_emails: []const u8 = "",

    mutex: std.Io.Mutex = .init,
    keys_arena: ?std.heap.ArenaAllocator = null,
    keys: []const jwt.Key = &.{},
    fetched_at: i64 = 0,
    /// From the issuer's discovery document; used by the OAuth front (oauth.zig).
    authorization_endpoint: []const u8 = "",
    token_endpoint: []const u8 = "",

    pub fn deinit(self: *Verifier) void {
        if (self.keys_arena) |*a| a.deinit();
    }

    pub fn check(self: *Verifier, arena: std.mem.Allocator, authorization: ?[]const u8) bool {
        const header = authorization orelse return false;
        const prefix = "bearer ";
        if (header.len <= prefix.len or !std.ascii.startsWithIgnoreCase(header, prefix)) return false;
        const token = std.mem.trim(u8, header[prefix.len..], " ");

        if (self.static_token.len > 0 and constantTimeEql(token, self.static_token)) return true;
        if (self.issuer.len == 0) return false;

        const claims = self.verifyJwt(arena, token, self.audience) catch |err| {
            log.info("rejected bearer token: {t}", .{err});
            return false;
        };
        if (self.allowed_emails.len > 0 and !emailAllowed(self.allowed_emails, claims.email)) {
            log.info("rejected token for '{s}': not in MCP_ALLOWED_EMAILS", .{claims.email});
            return false;
        }
        return true;
    }

    /// Verifies an issuer-signed JWT (an access or id token) and returns its claims.
    pub fn verifyJwt(self: *Verifier, arena: std.mem.Allocator, token: []const u8, audience: []const u8) !jwt.Claims {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
        if (self.fetched_at == 0 or now - self.fetched_at > keys_max_age) try self.refreshKeys(now);

        const expect: jwt.Expect = .{ .issuer = self.issuer, .audience = audience, .now = now };
        return jwt.verify(arena, token, self.keys, expect) catch |err| switch (err) {
            error.UnknownKey => {
                if (now - self.fetched_at < refetch_min) return err;
                try self.refreshKeys(now);
                return jwt.verify(arena, token, self.keys, expect);
            },
            else => err,
        };
    }

    pub const Endpoints = struct { authorization: []const u8, token: []const u8 };

    /// The issuer's authorize and token endpoints, copied into `arena`.
    pub fn endpoints(self: *Verifier, arena: std.mem.Allocator) !Endpoints {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
        if (self.fetched_at == 0 or now - self.fetched_at > keys_max_age) try self.refreshKeys(now);
        if (self.authorization_endpoint.len == 0 or self.token_endpoint.len == 0) return error.DiscoveryFailed;
        return .{ .authorization = try arena.dupe(u8, self.authorization_endpoint), .token = try arena.dupe(u8, self.token_endpoint) };
    }

    fn refreshKeys(self: *Verifier, now: i64) !void {
        var tmp: std.heap.ArenaAllocator = .init(self.gpa);
        errdefer tmp.deinit();
        const a = tmp.allocator();

        const disco_url = try std.fmt.allocPrint(a, "{s}/.well-known/openid-configuration", .{std.mem.trimEnd(u8, self.issuer, "/")});
        const disco = try self.http.send(a, .GET, disco_url, .{});
        if (!disco.ok()) return error.DiscoveryFailed;
        const doc = try std.json.parseFromSliceLeaky(std.json.Value, a, disco.body, .{});
        const jwks_uri = if (doc == .object) doc.object.get("jwks_uri") else null;
        if (jwks_uri == null or jwks_uri.? != .string) return error.DiscoveryFailed;

        const res = try self.http.send(a, .GET, jwks_uri.?.string, .{});
        if (!res.ok()) return error.DiscoveryFailed;
        const keys = try jwt.parseJwks(a, res.body);

        if (self.keys_arena) |*old| old.deinit();
        self.keys_arena = tmp;
        self.keys = keys;
        self.authorization_endpoint = docStr(doc, "authorization_endpoint");
        self.token_endpoint = docStr(doc, "token_endpoint");
        self.fetched_at = now;
        log.info("loaded {d} signing key(s) from {s}", .{ keys.len, jwks_uri.?.string });
    }
};

fn docStr(doc: std.json.Value, key: []const u8) []const u8 {
    const v = doc.object.get(key) orelse return "";
    return if (v == .string) v.string else "";
}

pub fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

pub fn emailAllowed(list: []const u8, email: []const u8) bool {
    if (email.len == 0) return false;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |e| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, e, " "), email)) return true;
    }
    return false;
}

test emailAllowed {
    try std.testing.expect(emailAllowed("a@x.nl, B@y.nl", "b@y.nl"));
    try std.testing.expect(!emailAllowed("a@x.nl", "c@x.nl"));
    try std.testing.expect(!emailAllowed("a@x.nl", ""));
}
