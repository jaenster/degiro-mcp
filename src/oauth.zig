//! OAuth 2.1 authorization server for MCP clients (claude.ai, Claude Code), federated to an OIDC
//! provider (e.g. Authentik) for the human login: dynamic client registration, authorization code +
//! PKCE, and refresh tokens.
//!
//! Stateless: client ids, the upstream login state, authorization codes and tokens are all
//! XChaCha20-Poly1305 sealed JSON under one server key (OAUTH_KEY), so restarts and redeploys log
//! nobody out. The refresh token carries the provider's own refresh token and every refresh goes
//! through the provider, so disabling the user there ends the session within one access-token
//! lifetime.
const std = @import("std");
const auth = @import("auth.zig");
const fetch = @import("fetch.zig");
const url = @import("url.zig");
const sealed = @import("sealed.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.url_safe_no_pad;
const log = std.log.scoped(.oauth);

const state_ttl = 10 * 60;
const code_ttl = 2 * 60;
const access_ttl = 60 * 60;
const refresh_ttl = 30 * 24 * 60 * 60;
const max_redirect_uris = 10;

const Kind = sealed.Kind;

/// A registered client: just its redirect URIs. `exp` 0 = never expires.
const ClientP = struct { r: []const []const u8, n: []const u8 = "", exp: i64 = 0 };
/// The pending MCP authorization request, carried through the provider's login as `state`.
const StateP = struct { cid: []const u8, ru: []const u8, cc: []const u8, st: []const u8, v: []const u8, exp: i64 };
const CodeP = struct { cid: []const u8, ru: []const u8, cc: []const u8, sub: []const u8, em: []const u8, urt: []const u8, jti: []const u8, exp: i64 };
pub const AccessP = struct { cid: []const u8, sub: []const u8, em: []const u8, exp: i64 };
const RefreshP = struct { cid: []const u8, sub: []const u8, em: []const u8, urt: []const u8, exp: i64 };

pub const Reply = struct {
    status: std.http.Status = .ok,
    body: []const u8 = "",
    content_type: []const u8 = "application/json",
    location: ?[]const u8 = null,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    http: *fetch.Http,
    /// The OIDC provider: discovery, JWKS and id_token verification.
    upstream: *auth.Verifier,
    base_url: []const u8,
    /// This server's own confidential client at the provider.
    client_id: []const u8,
    client_secret: []const u8,
    key: sealed.Key,
    /// Comma-separated; empty means anyone the provider lets through.
    allowed_emails: []const u8 = "",

    mutex: std.Io.Mutex = .init,
    /// Authorization codes are single-use: jti -> expiry, pruned as they expire.
    used_codes: std.StringHashMapUnmanaged(i64) = .empty,

    pub fn deinit(self: *Server) void {
        var it = self.used_codes.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.used_codes.deinit(self.gpa);
    }

    fn now(self: *Server) i64 {
        return sealed.now(self.io);
    }

    pub fn metadata(self: *Server, arena: std.mem.Allocator) !Reply {
        const base = self.base_url;
        return .{ .body = try std.json.Stringify.valueAlloc(arena, .{
            .issuer = base,
            .authorization_endpoint = try std.fmt.allocPrint(arena, "{s}/oauth/authorize", .{base}),
            .token_endpoint = try std.fmt.allocPrint(arena, "{s}/oauth/token", .{base}),
            .registration_endpoint = try std.fmt.allocPrint(arena, "{s}/oauth/register", .{base}),
            .response_types_supported = &[_][]const u8{"code"},
            .response_modes_supported = &[_][]const u8{"query"},
            .grant_types_supported = &[_][]const u8{ "authorization_code", "refresh_token" },
            .code_challenge_methods_supported = &[_][]const u8{"S256"},
            .token_endpoint_auth_methods_supported = &[_][]const u8{"none"},
            .scopes_supported = &[_][]const u8{"degiro"},
        }, .{}) };
    }

    /// RFC 7591. Every client is public (PKCE, no secret); the client id itself encodes the redirect
    /// URIs, which must point at Claude or a local loopback listener.
    pub fn register(self: *Server, arena: std.mem.Allocator, body: []const u8) !Reply {
        const req = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch
            return regError(arena, "invalid_client_metadata", "body must be a JSON object");
        if (req != .object) return regError(arena, "invalid_client_metadata", "body must be a JSON object");
        const uris_v = req.object.get("redirect_uris") orelse return regError(arena, "invalid_redirect_uri", "redirect_uris is required");
        if (uris_v != .array or uris_v.array.items.len == 0 or uris_v.array.items.len > max_redirect_uris)
            return regError(arena, "invalid_redirect_uri", "redirect_uris must be a list of 1-10 URIs");
        const uris = try arena.alloc([]const u8, uris_v.array.items.len);
        for (uris_v.array.items, uris) |u, *o| {
            if (u != .string or !allowedRedirect(u.string))
                return regError(arena, "invalid_redirect_uri", "only claude.ai, claude.com and loopback redirect URIs are accepted");
            o.* = u.string;
        }
        const name: []const u8 = if (req.object.get("client_name")) |n| (if (n == .string) n.string else "") else "";
        const cid = try self.seal(arena, .client, ClientP{ .r = uris, .n = name[0..@min(name.len, 100)] });
        log.info("registered client '{s}'", .{name});
        return .{ .status = .created, .body = try std.json.Stringify.valueAlloc(arena, .{
            .client_id = cid,
            .client_id_issued_at = self.now(),
            .client_name = name,
            .redirect_uris = uris,
            .grant_types = &[_][]const u8{ "authorization_code", "refresh_token" },
            .response_types = &[_][]const u8{"code"},
            .token_endpoint_auth_method = "none",
        }, .{}) };
    }

    /// Validates the MCP client's request and sends the browser to the provider.
    pub fn authorize(self: *Server, arena: std.mem.Allocator, q: url.Form) !Reply {
        const cid = q.get("client_id") orelse "";
        if (cid.len == 0 or cid.len > 1024) return page(.bad_request, "client_id is required");
        // Clients keep their registration per server URL, so claude.ai may come back with a client_id
        // from an earlier setup. Registration proves nothing anyway (it is open to anyone); what
        // matters is that the redirect goes to Claude or loopback, so an unknown id is held to the
        // same redirect allowlist as a registration.
        const ru = if (self.open(ClientP, arena, .client, cid)) |client| blk: {
            const ru = q.get("redirect_uri") orelse (if (client.r.len == 1) client.r[0] else return page(.bad_request, "redirect_uri is required"));
            if (!contains(client.r, ru)) return page(.bad_request, "redirect_uri is not registered for this client");
            break :blk ru;
        } else blk: {
            const ru = q.get("redirect_uri") orelse return page(.bad_request, "redirect_uri is required");
            if (!allowedRedirect(ru)) return page(.bad_request, "redirect_uri is not allowed");
            break :blk ru;
        };

        // From here on, errors go back to the client.
        const st = q.get("state") orelse "";
        if (!std.mem.eql(u8, q.get("response_type") orelse "", "code"))
            return redirectError(arena, ru, st, "unsupported_response_type", "only response_type=code is supported");
        const cc = q.get("code_challenge") orelse
            return redirectError(arena, ru, st, "invalid_request", "PKCE code_challenge is required");
        if (!std.mem.eql(u8, q.get("code_challenge_method") orelse "plain", "S256"))
            return redirectError(arena, ru, st, "invalid_request", "code_challenge_method must be S256");

        const ep = self.upstream.endpoints(arena) catch |err| {
            log.err("oidc discovery failed: {t}", .{err});
            return redirectError(arena, ru, st, "temporarily_unavailable", "identity provider unreachable");
        };
        const verifier = try self.randomToken(arena, 32);
        const upstream_state = try self.seal(arena, .state, StateP{
            .cid = cid,
            .ru = ru,
            .cc = cc,
            .st = st,
            .v = verifier,
            .exp = self.now() + state_ttl,
        });
        const location = try std.fmt.allocPrint(arena, "{s}{s}response_type=code&client_id={f}&redirect_uri={f}&scope={f}&state={f}&code_challenge={s}&code_challenge_method=S256", .{
            ep.authorization,
            if (std.mem.indexOfScalar(u8, ep.authorization, '?') == null) "?" else "&",
            url.encoded(self.client_id),
            url.encoded(try self.callbackUrl(arena)),
            url.encoded("openid email profile offline_access"),
            url.encoded(upstream_state),
            try challengeOf(arena, verifier),
        });
        return .{ .status = .found, .location = location };
    }

    /// The provider sends the browser back here: redeem its code, check who logged in, and hand the MCP
    /// client its own authorization code.
    pub fn callback(self: *Server, arena: std.mem.Allocator, q: url.Form) !Reply {
        const sp = self.open(StateP, arena, .state, q.get("state") orelse "") orelse
            return page(.bad_request, "This login link expired or is invalid. Start again from Claude.");
        if (q.get("error")) |e| {
            log.info("oidc provider returned error: {s}", .{e});
            return redirectError(arena, sp.ru, sp.st, "access_denied", q.get("error_description") orelse e);
        }
        const code = q.get("code") orelse return redirectError(arena, sp.ru, sp.st, "server_error", "no code from identity provider");

        const body = try std.fmt.allocPrint(arena, "grant_type=authorization_code&code={f}&redirect_uri={f}&code_verifier={f}", .{
            url.encoded(code), url.encoded(try self.callbackUrl(arena)), url.encoded(sp.v),
        });
        const tokens = self.upstreamToken(arena, body) catch
            return redirectError(arena, sp.ru, sp.st, "server_error", "could not redeem the identity provider's code");
        const who = self.identify(arena, tokens) catch
            return redirectError(arena, sp.ru, sp.st, "access_denied", "this account may not use the connector");

        const mcp_code = try self.seal(arena, .code, CodeP{
            .cid = sp.cid,
            .ru = sp.ru,
            .cc = sp.cc,
            .sub = who.sub,
            .em = who.email,
            .urt = getStr(tokens, "refresh_token") orelse "",
            .jti = try self.randomToken(arena, 16),
            .exp = self.now() + code_ttl,
        });
        log.info("login ok for {s}", .{who.email});
        return .{ .status = .found, .location = try std.fmt.allocPrint(arena, "{s}{s}code={f}&state={f}", .{
            sp.ru, if (std.mem.indexOfScalar(u8, sp.ru, '?') == null) "?" else "&", url.encoded(mcp_code), url.encoded(sp.st),
        }) };
    }

    pub fn token(self: *Server, arena: std.mem.Allocator, form: url.Form) !Reply {
        const grant = form.get("grant_type") orelse "";
        if (std.mem.eql(u8, grant, "authorization_code")) {
            const cp = self.open(CodeP, arena, .code, form.get("code") orelse "") orelse
                return tokenError(arena, "invalid_grant", "invalid or expired authorization code");
            if (form.get("client_id")) |c| if (!std.mem.eql(u8, c, cp.cid)) return tokenError(arena, "invalid_grant", "code was issued to another client");
            if (!std.mem.eql(u8, form.get("redirect_uri") orelse cp.ru, cp.ru)) return tokenError(arena, "invalid_grant", "redirect_uri mismatch");
            const verifier = form.get("code_verifier") orelse return tokenError(arena, "invalid_request", "code_verifier is required");
            if (!auth.constantTimeEql(try challengeOf(arena, verifier), cp.cc)) return tokenError(arena, "invalid_grant", "PKCE verification failed");
            if (!try self.markUsed(cp.jti, cp.exp)) return tokenError(arena, "invalid_grant", "authorization code already used");
            return self.issue(arena, cp.cid, cp.sub, cp.em, cp.urt);
        }
        if (std.mem.eql(u8, grant, "refresh_token")) {
            const rp = self.open(RefreshP, arena, .refresh, form.get("refresh_token") orelse "") orelse
                return tokenError(arena, "invalid_grant", "invalid or expired refresh token");
            if (form.get("client_id")) |c| if (!std.mem.eql(u8, c, rp.cid)) return tokenError(arena, "invalid_grant", "token was issued to another client");
            if (rp.urt.len == 0) return tokenError(arena, "invalid_grant", "session cannot be refreshed; log in again");

            // Ask the provider first: if the user was disabled or the session revoked, this fails.
            const body = try std.fmt.allocPrint(arena, "grant_type=refresh_token&refresh_token={f}", .{url.encoded(rp.urt)});
            const tokens = self.upstreamToken(arena, body) catch
                return tokenError(arena, "invalid_grant", "identity provider session ended; log in again");
            var email = rp.em;
            if (getStr(tokens, "id_token") != null) {
                const who = self.identify(arena, tokens) catch return tokenError(arena, "invalid_grant", "account may no longer use the connector");
                email = who.email;
            }
            return self.issue(arena, rp.cid, rp.sub, email, getStr(tokens, "refresh_token") orelse rp.urt);
        }
        return tokenError(arena, "unsupported_grant_type", "use authorization_code or refresh_token");
    }

    /// Returns the claims of a valid access token this server issued.
    pub fn verifyAccess(self: *Server, arena: std.mem.Allocator, bearer: []const u8) ?AccessP {
        return self.open(AccessP, arena, .access, bearer);
    }

    fn issue(self: *Server, arena: std.mem.Allocator, cid: []const u8, sub: []const u8, email: []const u8, urt: []const u8) !Reply {
        const t = self.now();
        const access = try self.seal(arena, .access, AccessP{ .cid = cid, .sub = sub, .em = email, .exp = t + access_ttl });
        const refresh = try self.seal(arena, .refresh, RefreshP{ .cid = cid, .sub = sub, .em = email, .urt = urt, .exp = t + refresh_ttl });
        return .{ .body = try std.json.Stringify.valueAlloc(arena, .{
            .access_token = access,
            .token_type = "Bearer",
            .expires_in = access_ttl,
            .refresh_token = refresh,
            .scope = "degiro",
        }, .{}) };
    }

    const Identity = struct { sub: []const u8, email: []const u8 };

    /// Verifies the id_token the provider returned (signature, issuer, audience, expiry) and the email
    /// allowlist.
    fn identify(self: *Server, arena: std.mem.Allocator, tokens: std.json.Value) !Identity {
        const id_token = getStr(tokens, "id_token") orelse return error.NoIdToken;
        const claims = self.upstream.verifyJwt(arena, id_token, self.client_id) catch |err| {
            log.warn("id_token rejected: {t}", .{err});
            return err;
        };
        if (self.allowed_emails.len > 0 and !auth.emailAllowed(self.allowed_emails, claims.email)) {
            log.warn("login refused for '{s}': not in MCP_ALLOWED_EMAILS", .{claims.email});
            return error.NotAllowed;
        }
        return .{ .sub = claims.sub, .email = claims.email };
    }

    fn upstreamToken(self: *Server, arena: std.mem.Allocator, grant_body: []const u8) !std.json.Value {
        const ep = try self.upstream.endpoints(arena);
        const body = try std.fmt.allocPrint(arena, "{s}&client_id={f}&client_secret={f}", .{
            grant_body, url.encoded(self.client_id), url.encoded(self.client_secret),
        });
        const res = try self.http.send(arena, .POST, ep.token, .{ .body = body, .content_type = "application/x-www-form-urlencoded" });
        if (!res.ok()) {
            const v = std.json.parseFromSliceLeaky(std.json.Value, arena, res.body, .{}) catch std.json.Value.null;
            log.warn("oidc token endpoint: HTTP {d} {s}", .{ @intFromEnum(res.status), getStr(v, "error") orelse "" });
            return error.UpstreamRejected;
        }
        return std.json.parseFromSliceLeaky(std.json.Value, arena, res.body, .{});
    }

    fn markUsed(self: *Server, jti: []const u8, exp: i64) !bool {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        const t = self.now();
        var stale: std.ArrayList([]const u8) = .empty;
        defer stale.deinit(self.gpa);
        var it = self.used_codes.iterator();
        while (it.next()) |e| if (e.value_ptr.* < t) try stale.append(self.gpa, e.key_ptr.*);
        for (stale.items) |k| {
            _ = self.used_codes.remove(k);
            self.gpa.free(k);
        }
        if (self.used_codes.contains(jti)) return false;
        try self.used_codes.put(self.gpa, try self.gpa.dupe(u8, jti), exp);
        return true;
    }

    fn callbackUrl(self: *Server, arena: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "{s}/oauth/callback", .{self.base_url});
    }

    fn randomToken(self: *Server, arena: std.mem.Allocator, comptime n: usize) ![]const u8 {
        var raw: [n]u8 = undefined;
        try self.io.randomSecure(&raw);
        const out = try arena.alloc(u8, b64.Encoder.calcSize(n));
        return b64.Encoder.encode(out, &raw);
    }

    pub fn seal(self: *Server, arena: std.mem.Allocator, kind: Kind, payload: anytype) ![]const u8 {
        return sealed.seal(arena, self.io, self.key, kind, payload);
    }

    pub fn open(self: *Server, comptime T: type, arena: std.mem.Allocator, kind: Kind, blob: []const u8) ?T {
        return sealed.open(T, arena, self.io, self.key, kind, blob);
    }
};

/// claude.ai / claude.com callbacks, or a loopback listener (Claude Code, MCP inspector).
fn allowedRedirect(u: []const u8) bool {
    if (std.mem.indexOfAny(u8, u, "#\r\n \\") != null) return false;
    const prefixes = [_][]const u8{
        "https://claude.ai/",        "https://claude.com/",
        "http://localhost:",         "http://localhost/",
        "http://127.0.0.1:",         "http://127.0.0.1/",
    };
    for (prefixes) |p| if (std.mem.startsWith(u8, u, p)) return true;
    return false;
}

fn contains(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

fn challengeOf(arena: std.mem.Allocator, verifier: []const u8) ![]const u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(verifier, &digest, .{});
    const out = try arena.alloc(u8, b64.Encoder.calcSize(digest.len));
    return b64.Encoder.encode(out, &digest);
}

fn getStr(v: std.json.Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

fn page(status: std.http.Status, msg: []const u8) Reply {
    return .{ .status = status, .body = msg, .content_type = "text/plain; charset=utf-8" };
}

fn redirectError(arena: std.mem.Allocator, ru: []const u8, st: []const u8, code: []const u8, desc: []const u8) !Reply {
    return .{ .status = .found, .location = try std.fmt.allocPrint(arena, "{s}{s}error={s}&error_description={f}&state={f}", .{
        ru, if (std.mem.indexOfScalar(u8, ru, '?') == null) "?" else "&", code, url.encoded(desc), url.encoded(st),
    }) };
}

fn tokenError(arena: std.mem.Allocator, code: []const u8, desc: []const u8) !Reply {
    return .{ .status = .bad_request, .body = try std.json.Stringify.valueAlloc(arena, .{ .@"error" = code, .error_description = desc }, .{}) };
}

fn regError(arena: std.mem.Allocator, code: []const u8, desc: []const u8) !Reply {
    return tokenError(arena, code, desc);
}

fn testServer() Server {
    return .{
        .gpa = std.testing.allocator,
        .io = std.testing.io,
        .http = undefined,
        .upstream = undefined,
        .base_url = "https://degiro.example",
        .client_id = "up",
        .client_secret = "s",
        .key = [_]u8{7} ** sealed.key_length,
    };
}

test "sealed blobs round-trip and reject tampering, wrong kind and expiry" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = testServer();
    defer s.deinit();

    const t = try s.seal(a, .access, AccessP{ .cid = "c", .sub = "u", .em = "me@x.nl", .exp = s.now() + 60 });
    try std.testing.expectEqualStrings("me@x.nl", s.verifyAccess(a, t).?.em);
    try std.testing.expect(s.open(AccessP, a, .refresh, t) == null);

    const tampered = try a.dupe(u8, t);
    tampered[30] = if (tampered[30] == 'A') 'B' else 'A';
    try std.testing.expect(s.verifyAccess(a, tampered) == null);

    const old = try s.seal(a, .access, AccessP{ .cid = "c", .sub = "u", .em = "e", .exp = s.now() - 1 });
    try std.testing.expect(s.verifyAccess(a, old) == null);

    var other = testServer();
    other.key[0] = 8;
    try std.testing.expect(other.verifyAccess(a, t) == null);
}

test "registration only accepts claude and loopback redirects" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = testServer();
    defer s.deinit();

    const ok = try s.register(a, "{\"redirect_uris\":[\"https://claude.ai/api/mcp/auth_callback\"],\"client_name\":\"Claude\"}");
    try std.testing.expectEqual(std.http.Status.created, ok.status);
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, ok.body, .{});
    const cid = parsed.object.get("client_id").?.string;
    try std.testing.expectEqualStrings("https://claude.ai/api/mcp/auth_callback", s.open(ClientP, a, .client, cid).?.r[0]);

    try std.testing.expectEqual(std.http.Status.bad_request, (try s.register(a, "{\"redirect_uris\":[\"https://evil.example/cb\"]}")).status);
    try std.testing.expectEqual(std.http.Status.bad_request, (try s.register(a, "{\"redirect_uris\":[\"https://claude.ai.evil.example/cb\"]}")).status);
    try std.testing.expectEqual(std.http.Status.bad_request, (try s.register(a, "{}")).status);
    try std.testing.expect(allowedRedirect("http://localhost:33418/callback"));
    try std.testing.expect(!allowedRedirect("http://localhost.evil.example/cb"));
}

test "authorization code exchange enforces PKCE, redirect_uri and single use" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = testServer();
    defer s.deinit();

    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const code = try s.seal(a, .code, CodeP{
        .cid = "client-1",
        .ru = "https://claude.ai/api/mcp/auth_callback",
        .cc = try challengeOf(a, verifier),
        .sub = "u",
        .em = "me@x.nl",
        .urt = "upstream-rt",
        .jti = "jti-1",
        .exp = s.now() + 60,
    });
    const form = struct {
        fn make(al: std.mem.Allocator, c: []const u8, v: []const u8, ru: []const u8) !url.Form {
            const body = try std.fmt.allocPrint(al, "grant_type=authorization_code&code={f}&code_verifier={s}&redirect_uri={f}&client_id=client-1", .{ url.encoded(c), v, url.encoded(ru) });
            return url.parseForm(al, body);
        }
    }.make;

    try std.testing.expectEqual(std.http.Status.bad_request, (try s.token(a, try form(a, code, "wrong-verifier", "https://claude.ai/api/mcp/auth_callback"))).status);
    try std.testing.expectEqual(std.http.Status.bad_request, (try s.token(a, try form(a, code, verifier, "https://claude.ai/other"))).status);

    const ok = try s.token(a, try form(a, code, verifier, "https://claude.ai/api/mcp/auth_callback"));
    try std.testing.expectEqual(std.http.Status.ok, ok.status);
    const tokens = try std.json.parseFromSliceLeaky(std.json.Value, a, ok.body, .{});
    const access = tokens.object.get("access_token").?.string;
    try std.testing.expectEqualStrings("me@x.nl", s.verifyAccess(a, access).?.em);
    const rt = s.open(RefreshP, a, .refresh, tokens.object.get("refresh_token").?.string).?;
    try std.testing.expectEqualStrings("upstream-rt", rt.urt);

    // Replay of the same code is refused.
    try std.testing.expectEqual(std.http.Status.bad_request, (try s.token(a, try form(a, code, verifier, "https://claude.ai/api/mcp/auth_callback"))).status);
}

test "unregistered client ids are held to the redirect allowlist" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var s = testServer();
    defer s.deinit();

    var q: url.Form = .empty;
    try q.put(a, "client_id", "stale-client");
    try q.put(a, "redirect_uri", "https://evil.example/cb");
    try std.testing.expectEqual(std.http.Status.bad_request, (try s.authorize(a, q)).status);

    // An allowed redirect gets past the client check; the bad response_type then goes back to it.
    try q.put(a, "redirect_uri", "https://claude.ai/api/mcp/auth_callback");
    try q.put(a, "response_type", "token");
    const r = try s.authorize(a, q);
    try std.testing.expectEqual(std.http.Status.found, r.status);
    try std.testing.expect(std.mem.startsWith(u8, r.location.?, "https://claude.ai/api/mcp/auth_callback?error=unsupported_response_type"));
}
