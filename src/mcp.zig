//! Stateless MCP: one JSON-RPC message in, one reply out. Carried by Streamable HTTP (one message
//! per POST) or stdio (one message per line).
const std = @import("std");
const tools = @import("tools.zig");

const log = std.log.scoped(.mcp);

const supported_versions = [_][]const u8{ "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };

const instructions =
    "DeGiro brokerage account (unofficial web API). Tool results are TOON (indentation-based, CSV-style rows " ++
    "for uniform arrays). Amounts are in the product's currency unless a field says otherwise. Placing an order " ++
    "is two steps: check_order returns costs and a confirmation_id, then confirm_order places it. Never call " ++
    "confirm_order without the user explicitly approving that exact order.";

/// Returns the JSON response body, or null for a notification (which gets 202 and no body).
pub fn handle(arena: std.mem.Allocator, toolbox: *tools.Toolbox, body: []const u8) !?[]const u8 {
    const msg = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch
        return try errorReply(arena, .null, -32700, "Parse error");
    if (msg != .object) return try errorReply(arena, .null, -32600, "Invalid Request: expected a single JSON-RPC object");

    const id = msg.object.get("id") orelse return null;
    const method = if (msg.object.get("method")) |m| (if (m == .string) m.string else "") else "";
    const params = msg.object.get("params") orelse .null;

    if (std.mem.eql(u8, method, "initialize")) {
        const asked = if (params == .object) params.object.get("protocolVersion") else null;
        var version: []const u8 = supported_versions[0];
        if (asked) |v| if (v == .string) for (supported_versions) |s| {
            if (std.mem.eql(u8, s, v.string)) version = s;
        };
        return try reply(arena, id, .{
            .protocolVersion = version,
            .capabilities = .{ .tools = .{ .listChanged = false } },
            .serverInfo = .{ .name = "degiro", .version = "0.1.0" },
            .instructions = instructions,
        });
    }
    if (std.mem.eql(u8, method, "ping")) return try reply(arena, id, std.json.Value{ .object = .empty });
    if (std.mem.eql(u8, method, "tools/list")) {
        return try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":{f},\"result\":{{\"tools\":{s}}}}}", .{
            std.json.fmt(id, .{}), toolbox.listJson(),
        });
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        if (params != .object) return try errorReply(arena, id, -32602, "Invalid params");
        const name = params.object.get("name") orelse return try errorReply(arena, id, -32602, "Missing tool name");
        if (name != .string) return try errorReply(arena, id, -32602, "Invalid tool name");
        const args = params.object.get("arguments") orelse .null;
        const result = try toolbox.call(arena, name.string, args);
        return try reply(arena, id, .{
            .content = .{.{ .type = "text", .text = result.text }},
            .isError = result.is_error,
        });
    }
    return try errorReply(arena, id, -32601, "Method not found");
}

fn reply(arena: std.mem.Allocator, id: std.json.Value, result: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(arena, .{ .jsonrpc = "2.0", .id = id, .result = result }, .{});
}

pub fn errorReply(arena: std.mem.Allocator, id: std.json.Value, code: i32, message: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(arena, .{ .jsonrpc = "2.0", .id = id, .@"error" = .{ .code = code, .message = message } }, .{});
}

test "initialize negotiates the protocol version" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var tb: tools.Toolbox = .{ .gpa = std.testing.allocator, .io = std.testing.io, .dg = undefined, .trading = false, .key = @splat(1) };
    const a = arena.allocator();

    const r1 = (try handle(a, &tb, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\"}}")).?;
    try std.testing.expect(std.mem.indexOf(u8, r1, "\"protocolVersion\":\"2025-03-26\"") != null);
    const r2 = (try handle(a, &tb, "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}")).?;
    try std.testing.expect(std.mem.indexOf(u8, r2, "\"protocolVersion\":\"2025-11-25\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, r2, "\"id\":\"x\"") != null);

    try std.testing.expectEqual(@as(?[]const u8, null), try handle(a, &tb, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}", (try handle(a, &tb, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}")).?);

    const list = (try handle(a, &tb, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}")).?;
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, list, .{});
    try std.testing.expect(parsed.object.get("result").?.object.get("tools").?.array.items.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, list, "confirm_order") == null);

    const missing = (try handle(a, &tb, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"nope\"}")).?;
    try std.testing.expect(std.mem.indexOf(u8, missing, "-32601") != null);
}
