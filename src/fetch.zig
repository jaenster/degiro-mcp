//! Outbound HTTPS. One shared std.http.Client, serialized by a mutex: the client's CA bundle rescan
//! isn't safe to race, and a single-user connector never needs parallel upstream calls anyway.
//!
//! Every request gets its own connection. Upstreams drop idle keep-alive connections without
//! notice (vwd after 10 s, DeGiro after 120 s), and a request sent on one of those fails; a fresh
//! TLS handshake per call costs far less than handling that.
const std = @import("std");

pub const user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

pub const Response = struct {
    status: std.http.Status,
    body: []u8,
    /// Raw Set-Cookie header values.
    cookies: []const []const u8,

    pub fn ok(r: Response) bool {
        return @intFromEnum(r.status) >= 200 and @intFromEnum(r.status) < 300;
    }
};

pub const Options = struct {
    headers: []const std.http.Header = &.{},
    body: ?[]const u8 = null,
    content_type: []const u8 = "application/json;charset=UTF-8",
    max_body: usize = 16 << 20,
};

pub const Http = struct {
    client: std.http.Client,
    mutex: std.Io.Mutex = .init,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Http {
        // A pool of size 0 closes each connection when its request is done.
        return .{ .client = .{ .allocator = gpa, .io = io, .connection_pool = .{ .free_size = 0 } } };
    }

    pub fn deinit(self: *Http) void {
        self.client.deinit();
    }

    /// Everything returned lives in `arena`.
    pub fn send(self: *Http, arena: std.mem.Allocator, method: std.http.Method, url: []const u8, opts: Options) !Response {
        const io = self.client.io;
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);

        const uri = try std.Uri.parse(url);
        var req = try self.client.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{
                .user_agent = .{ .override = user_agent },
                .accept_encoding = .{ .override = "identity" },
                .content_type = if (opts.body != null) .{ .override = opts.content_type } else .default,
            },
            .extra_headers = opts.headers,
        });
        defer req.deinit();

        if (opts.body) |b| {
            try req.sendBodyComplete(try arena.dupe(u8, b));
        } else {
            try req.sendBodiless();
        }

        var redirect_buf: [8 * 1024]u8 = undefined;
        var res = try req.receiveHead(&redirect_buf);

        var cookies: std.ArrayList([]const u8) = .empty;
        var it = res.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) try cookies.append(arena, try arena.dupe(u8, h.value));
        }

        var transfer_buf: [16 * 1024]u8 = undefined;
        const reader = res.reader(&transfer_buf);
        const body = try reader.allocRemaining(arena, .limited(opts.max_body));
        return .{ .status = res.head.status, .body = body, .cookies = cookies.items };
    }
};

/// Answers one request per connection, then hangs up although the response promised keep-alive.
fn hangUpAfterEachResponse(io: std.Io, listener: *std.Io.net.Server, count: usize) void {
    for (0..count) |i| {
        const stream = listener.accept(io) catch return;
        defer stream.close(io);
        var rbuf: [4096]u8 = undefined;
        var wbuf: [256]u8 = undefined;
        var reader = stream.reader(io, &rbuf);
        var writer = stream.writer(io, &wbuf);
        var http: std.http.Server = .init(&reader.interface, &writer.interface);
        var req = http.receiveHead() catch return;
        const body: []const u8 = if (i == 0) "first" else "again";
        req.respond(body, .{ .keep_alive = true }) catch return;
    }
}

test "a connection the server hung up on is never reused" {
    const io = std.testing.io;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const t = try std.Thread.spawn(.{}, hangUpAfterEachResponse, .{ io, &listener, 2 });

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var http: Http = .init(std.testing.allocator, io);
    defer http.deinit();
    const url = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}/", .{listener.socket.address.getPort()});

    try std.testing.expectEqualStrings("first", (try http.send(a, .GET, url, .{})).body);
    try std.testing.expectEqualStrings("again", (try http.send(a, .POST, url, .{ .body = "{}" })).body);
    t.join();
}
