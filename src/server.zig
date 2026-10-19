//! HTTP front: /mcp (bearer-protected), the RFC 9728 protected-resource document, the OAuth
//! authorization server endpoints (oauth.zig) and /healthz. One thread per connection, keep-alive.
const std = @import("std");
const auth = @import("auth.zig");
const mcp = @import("mcp.zig");
const oauth = @import("oauth.zig");
const url = @import("url.zig");
const tools = @import("tools.zig");

const log = std.log.scoped(.http);

const max_body = 1 << 20;

pub const Config = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    port: u16,
    public_base_url: []const u8,
    verifier: *auth.Verifier,
    /// When set, this server is its own authorization server (federated to the OIDC provider) and the
    /// protected-resource document points at itself.
    oauth: ?*oauth.Server = null,
    toolbox: *tools.Toolbox,
};

pub fn run(cfg: Config) !void {
    const addr = try std.Io.net.IpAddress.parse("0.0.0.0", cfg.port);
    var listener = try addr.listen(cfg.io, .{ .reuse_address = true });
    defer listener.deinit(cfg.io);
    log.info("listening on :{d} ({s})", .{ cfg.port, cfg.public_base_url });

    while (true) {
        const stream = listener.accept(cfg.io) catch |err| {
            log.err("accept: {t}", .{err});
            continue;
        };
        const t = std.Thread.spawn(.{}, serveConnection, .{ cfg, stream }) catch |err| {
            log.err("spawn: {t}", .{err});
            stream.close(cfg.io);
            continue;
        };
        t.detach();
    }
}

fn serveConnection(cfg: Config, stream: std.Io.net.Stream) void {
    defer stream.close(cfg.io);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var reader = stream.reader(cfg.io, &rbuf);
    var writer = stream.writer(cfg.io, &wbuf);
    var http: std.http.Server = .init(&reader.interface, &writer.interface);

    var arena: std.heap.ArenaAllocator = .init(cfg.gpa);
    defer arena.deinit();

    while (true) {
        _ = arena.reset(.retain_capacity);
        var req = http.receiveHead() catch |err| {
            if (err != error.HttpConnectionClosing) log.debug("receiveHead: {t}", .{err});
            return;
        };
        handle(cfg, arena.allocator(), &req) catch |err| {
            log.err("{s} {s}: {t}", .{ @tagName(req.head.method), req.head.target, err });
            return;
        };
        if (!req.head.keep_alive) return;
    }
}

const Ctx = struct {
    authorization: ?[]const u8 = null,
    origin: ?[]const u8 = null,
};

fn handle(cfg: Config, arena: std.mem.Allocator, req: *std.http.Server.Request) !void {
    // std's keep-alive handling asserts that a POST/PUT has a length, so a bodiless POST would panic
    // the whole process. Refuse it and close the connection instead.
    if (req.head.method.requestHasBody() and req.head.content_length == null and req.head.transfer_encoding == .none)
        return req.respond("length required\n", .{ .status = .length_required, .keep_alive = false });

    // Header strings point into the read buffer and are invalidated by reading the body: copy first.
    var ctx: Ctx = .{};
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) ctx.authorization = try arena.dupe(u8, h.value);
        if (std.ascii.eqlIgnoreCase(h.name, "origin")) ctx.origin = try arena.dupe(u8, h.value);
    }
    const target = try arena.dupe(u8, req.head.target);
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    const method = req.head.method;

    if (std.mem.eql(u8, path, "/healthz")) return req.respond("ok\n", .{});

    if (std.mem.startsWith(u8, path, "/.well-known/oauth-protected-resource")) {
        const cors = corsHeaders(ctx.origin, "GET, OPTIONS");
        if (method == .OPTIONS) return req.respond("", .{ .status = .no_content, .extra_headers = &cors });
        const as: []const u8 = if (cfg.oauth != null) cfg.public_base_url else cfg.verifier.issuer;
        const doc = try std.json.Stringify.valueAlloc(arena, .{
            .resource = try std.fmt.allocPrint(arena, "{s}/mcp", .{cfg.public_base_url}),
            .authorization_servers = if (as.len > 0) &[_][]const u8{as} else &[_][]const u8{},
            .bearer_methods_supported = &[_][]const u8{"header"},
            .scopes_supported = if (cfg.oauth != null) &[_][]const u8{"degiro"} else &[_][]const u8{ "openid", "profile", "email", "offline_access" },
        }, .{});
        return req.respond(doc, .{ .extra_headers = &(cors ++ json_ct) });
    }

    if (cfg.oauth) |o| {
        if (std.mem.eql(u8, path, "/.well-known/oauth-authorization-server") or std.mem.eql(u8, path, "/.well-known/openid-configuration")) {
            const cors = corsHeaders(ctx.origin, "GET, OPTIONS");
            if (method == .OPTIONS) return req.respond("", .{ .status = .no_content, .extra_headers = &cors });
            return sendReply(req, try o.metadata(arena), &cors);
        }
        if (std.mem.startsWith(u8, path, "/oauth/")) {
            const cors = corsHeaders(ctx.origin, "GET, POST, OPTIONS");
            if (method == .OPTIONS) return req.respond("", .{ .status = .no_content, .extra_headers = &cors });
            const query = if (std.mem.indexOfScalar(u8, target, '?')) |i| target[i + 1 ..] else "";
            const reply: ?oauth.Reply = if (std.mem.eql(u8, path, "/oauth/authorize") and method == .GET)
                try o.authorize(arena, try url.parseForm(arena, query))
            else if (std.mem.eql(u8, path, "/oauth/callback") and method == .GET)
                try o.callback(arena, try url.parseForm(arena, query))
            else if (std.mem.eql(u8, path, "/oauth/token") and method == .POST)
                try o.token(arena, try url.parseForm(arena, (try readBody(req, arena)) orelse return tooLarge(req)))
            else if (std.mem.eql(u8, path, "/oauth/register") and method == .POST)
                try o.register(arena, (try readBody(req, arena)) orelse return tooLarge(req))
            else
                null;
            if (reply) |r| return sendReply(req, r, &cors);
            return req.respond("not found\n", .{ .status = .not_found });
        }
    }

    if (std.mem.eql(u8, path, "/mcp")) {
        const cors = corsHeaders(ctx.origin, "POST, OPTIONS");
        if (method == .OPTIONS) return req.respond("", .{ .status = .no_content, .extra_headers = &cors });

        if (!authorized(cfg, arena, ctx.authorization)) {
            const www = try std.fmt.allocPrint(arena, "Bearer resource_metadata=\"{s}/.well-known/oauth-protected-resource\"", .{cfg.public_base_url});
            const body = try mcp.errorReply(arena, .null, -32001, "Unauthorized: missing or invalid bearer token");
            return req.respond(body, .{
                .status = .unauthorized,
                .extra_headers = &(cors ++ json_ct ++ [_]std.http.Header{.{ .name = "WWW-Authenticate", .value = www }}),
            });
        }
        if (method != .POST) {
            const body = try mcp.errorReply(arena, .null, -32000, "Method not allowed (stateless MCP: POST only)");
            return req.respond(body, .{ .status = .method_not_allowed, .extra_headers = &(cors ++ json_ct ++ [_]std.http.Header{.{ .name = "Allow", .value = "POST, OPTIONS" }}) });
        }

        const body = (try readBody(req, arena)) orelse return tooLarge(req);

        const out = try mcp.handle(arena, cfg.toolbox, body);
        if (out) |json| return req.respond(json, .{ .extra_headers = &(cors ++ json_ct) });
        return req.respond("", .{ .status = .accepted, .extra_headers = &cors });
    }

    return req.respond("not found\n", .{ .status = .not_found });
}

/// Our own access tokens first, then whatever the verifier accepts (static token, provider JWTs).
fn authorized(cfg: Config, arena: std.mem.Allocator, authorization: ?[]const u8) bool {
    if (cfg.oauth) |o| if (authorization) |h| {
        const prefix = "bearer ";
        if (h.len > prefix.len and std.ascii.startsWithIgnoreCase(h, prefix)) {
            if (o.verifyAccess(arena, std.mem.trim(u8, h[prefix.len..], " ")) != null) return true;
        }
    };
    return cfg.verifier.check(arena, authorization);
}

/// null when the body exceeds `max_body`.
fn readBody(req: *std.http.Server.Request, arena: std.mem.Allocator) !?[]u8 {
    var body_buf: [8 * 1024]u8 = undefined;
    const body_reader = try req.readerExpectContinue(&body_buf);
    return body_reader.allocRemaining(arena, .limited(max_body)) catch |err| switch (err) {
        error.StreamTooLong => null,
        else => err,
    };
}

fn tooLarge(req: *std.http.Server.Request) !void {
    return req.respond("request too large\n", .{ .status = .payload_too_large, .keep_alive = false });
}

fn sendReply(req: *std.http.Server.Request, r: oauth.Reply, cors: []const std.http.Header) !void {
    var headers: [8]std.http.Header = undefined;
    var n: usize = 0;
    for (cors) |h| {
        headers[n] = h;
        n += 1;
    }
    headers[n] = .{ .name = "Content-Type", .value = r.content_type };
    n += 1;
    headers[n] = .{ .name = "Cache-Control", .value = "no-store" };
    n += 1;
    if (r.location) |l| {
        headers[n] = .{ .name = "Location", .value = l };
        n += 1;
    }
    return req.respond(r.body, .{ .status = r.status, .extra_headers = headers[0..n] });
}

const json_ct = [_]std.http.Header{.{ .name = "Content-Type", .value = "application/json" }};

fn corsHeaders(origin: ?[]const u8, methods: []const u8) [5]std.http.Header {
    return .{
        .{ .name = "Access-Control-Allow-Origin", .value = allowedOrigin(origin) },
        .{ .name = "Vary", .value = "Origin" },
        .{ .name = "Access-Control-Allow-Methods", .value = methods },
        .{ .name = "Access-Control-Allow-Headers", .value = "Authorization, Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-Id" },
        .{ .name = "Access-Control-Expose-Headers", .value = "Mcp-Session-Id, Mcp-Protocol-Version, WWW-Authenticate" },
    };
}

fn allowedOrigin(origin: ?[]const u8) []const u8 {
    const o = origin orelse return "https://claude.ai";
    if (std.mem.eql(u8, o, "https://claude.ai")) return o;
    if (std.mem.startsWith(u8, o, "https://") and std.mem.endsWith(u8, o, ".claude.ai")) return o;
    if (std.mem.startsWith(u8, o, "http://localhost:") or std.mem.startsWith(u8, o, "http://127.0.0.1:")) return o;
    return "https://claude.ai";
}
