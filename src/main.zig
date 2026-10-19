const std = @import("std");
const fetch = @import("fetch.zig");
const degiro = @import("degiro.zig");
const totp = @import("totp.zig");
const auth = @import("auth.zig");
const server = @import("server.zig");
const oauth = @import("oauth.zig");
const tools = @import("tools.zig");
const sealed = @import("sealed.zig");
const mcp = @import("mcp.zig");

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const cmd: []const u8 = if (args.len > 1) args[1] else "serve";

    var totp_buf: [128]u8 = undefined;
    const totp_key = totp.decodeBase32(&totp_buf, totp.seedFromInput(env.get("DEGIRO_TOTP_SECRET") orelse "")) catch {
        std.log.err("DEGIRO_TOTP_SECRET is not valid base32", .{});
        return 1;
    };
    const creds: degiro.Credentials = .{
        .username = env.get("DEGIRO_USERNAME") orelse "",
        .password = env.get("DEGIRO_PASSWORD") orelse "",
        .totp_key = totp_key,
    };
    if (creds.username.len == 0 or creds.password.len == 0 or totp_key.len == 0) {
        std.log.err("DEGIRO_USERNAME, DEGIRO_PASSWORD and DEGIRO_TOTP_SECRET must be set", .{});
        return 1;
    }

    // OAUTH_KEY seals confirmation_ids and, when serving, every OAuth client id, code and token.
    // Without it a random key is used, so those don't survive a restart.
    var key: sealed.Key = undefined;
    const key_hex = env.get("OAUTH_KEY") orelse "";
    if (key_hex.len > 0) {
        if (key_hex.len != 64 or (std.fmt.hexToBytes(&key, key_hex) catch null) == null) {
            std.log.err("OAUTH_KEY must be 64 hex characters (openssl rand -hex 32)", .{});
            return 1;
        }
    } else try io.randomSecure(&key);

    var http: fetch.Http = .init(gpa, io);
    defer http.deinit();
    var client: degiro.Client = .init(gpa, io, &http, creds);
    defer client.deinit();

    var toolbox: tools.Toolbox = .{
        .gpa = gpa,
        .io = io,
        .dg = &client,
        .trading = isTrue(env.get("DEGIRO_TRADING")),
        .debug = isTrue(env.get("DEGIRO_DEBUG")),
        .key = key,
    };
    defer toolbox.deinit();

    // `degiro-mcp call <tool> [json-args]` runs one tool locally and prints the TOON result.
    if (std.mem.eql(u8, cmd, "call")) {
        toolbox.debug = true;
        if (args.len < 3) {
            std.log.err("usage: degiro-mcp call <tool> [json-args]", .{});
            return 2;
        }
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const tool_args = try std.json.parseFromSliceLeaky(std.json.Value, a, if (args.len > 3) args[3] else "{}", .{});
        const result = try toolbox.call(a, args[2], tool_args);
        var out_buf: [4096]u8 = undefined;
        var out = std.Io.File.stdout().writer(io, &out_buf);
        try out.interface.print("{s}{s}\n", .{ if (result.is_error) "ERROR: " else "", result.text });
        try out.interface.flush();
        return if (result.is_error) 1 else 0;
    }

    // `degiro-mcp stdio` is a local MCP server for Claude Desktop / Claude Code: one JSON-RPC
    // message per line on stdin, replies on stdout, logs on stderr.
    if (std.mem.eql(u8, cmd, "stdio")) {
        try serveStdio(gpa, io, &toolbox);
        return 0;
    }

    if (!std.mem.eql(u8, cmd, "serve")) {
        std.log.err("unknown command '{s}' (expected serve, stdio or call)", .{cmd});
        return 2;
    }

    var verifier: auth.Verifier = .{
        .gpa = gpa,
        .io = io,
        .http = &http,
        .issuer = env.get("MCP_OIDC_ISSUER") orelse "",
        .audience = env.get("MCP_OIDC_AUDIENCE") orelse "",
        .static_token = env.get("MCP_TOKEN") orelse "",
        .allowed_emails = env.get("MCP_ALLOWED_EMAILS") orelse "",
    };
    defer verifier.deinit();
    if (verifier.issuer.len == 0 and verifier.static_token.len == 0) {
        std.log.err("refusing to start without auth: set MCP_OIDC_ISSUER and/or MCP_TOKEN", .{});
        return 1;
    }

    const base_url = std.mem.trimEnd(u8, env.get("PUBLIC_BASE_URL") orelse "http://localhost:8080", "/");

    // With OAUTH_KEY this server is its own authorization server; OAUTH_CLIENT_ID/SECRET are its
    // client at the OIDC provider.
    var oauth_server: ?oauth.Server = null;
    defer if (oauth_server) |*o| o.deinit();
    if (key_hex.len > 0) {
        const cid = env.get("OAUTH_CLIENT_ID") orelse "";
        const secret = env.get("OAUTH_CLIENT_SECRET") orelse "";
        if (cid.len == 0 or secret.len == 0 or verifier.issuer.len == 0) {
            std.log.err("OAUTH_KEY needs OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET and MCP_OIDC_ISSUER", .{});
            return 1;
        }
        oauth_server = .{
            .gpa = gpa,
            .io = io,
            .http = &http,
            .upstream = &verifier,
            .base_url = base_url,
            .client_id = cid,
            .client_secret = secret,
            .key = key,
            .allowed_emails = verifier.allowed_emails,
        };
        std.log.info("OAuth authorization server enabled (upstream {s})", .{verifier.issuer});
    }

    const port = std.fmt.parseInt(u16, env.get("PORT") orelse "8080", 10) catch 8080;
    try server.run(.{
        .gpa = gpa,
        .io = io,
        .port = port,
        .public_base_url = base_url,
        .verifier = &verifier,
        .oauth = if (oauth_server) |*o| o else null,
        .toolbox = &toolbox,
    });
    return 0;
}

fn serveStdio(gpa: std.mem.Allocator, io: std.Io, toolbox: *tools.Toolbox) !void {
    const in_buf = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(in_buf);
    var in = std.Io.File.stdin().reader(io, in_buf);
    var out_buf: [64 * 1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &out_buf);

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    while (try in.interface.takeDelimiter('\n')) |line| {
        _ = arena.reset(.retain_capacity);
        if (std.mem.trim(u8, line, " \t\r").len == 0) continue;
        const res = try mcp.handle(arena.allocator(), toolbox, line) orelse continue;
        try out.interface.print("{s}\n", .{res});
        try out.interface.flush();
    }
}

fn isTrue(v: ?[]const u8) bool {
    const s = v orelse return false;
    return std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "true") or std.ascii.eqlIgnoreCase(s, "yes");
}

test {
    _ = @import("totp.zig");
    _ = @import("jwt.zig");
    _ = @import("mcp.zig");
    _ = @import("tools.zig");
    _ = @import("dates.zig");
    _ = @import("auth.zig");
    _ = @import("oauth.zig");
    _ = @import("url.zig");
    _ = @import("fetch.zig");
    _ = @import("sealed.zig");
}
