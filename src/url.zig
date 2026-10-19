//! Percent-encoding and application/x-www-form-urlencoded parsing.
const std = @import("std");

pub fn encoded(s: []const u8) std.fmt.Alt([]const u8, formatEncoded) {
    return .{ .data = s };
}

fn formatEncoded(s: []const u8, w: *std.Io.Writer) std.Io.Writer.Error!void {
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try w.writeByte(c);
        } else {
            try w.print("%{X:0>2}", .{c});
        }
    }
}

/// Decodes %XX escapes and '+' (as space). Malformed escapes are kept literally.
pub fn decodeAlloc(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try arena.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '+') {
            out[n] = ' ';
        } else if (c == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                out[n] = b;
                i += 2;
            } else |_| out[n] = c;
        } else {
            out[n] = c;
        }
        n += 1;
    }
    return out[0..n];
}

pub const Form = std.StringHashMapUnmanaged([]const u8);

/// Parses "a=1&b=two" (a query string or a form body). Later duplicates win.
pub fn parseForm(arena: std.mem.Allocator, s: []const u8) !Form {
    var form: Form = .empty;
    var it = std.mem.splitScalar(u8, s, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const k = try decodeAlloc(arena, pair[0..eq]);
        const v = if (eq < pair.len) try decodeAlloc(arena, pair[eq + 1 ..]) else "";
        try form.put(arena, k, v);
    }
    return form;
}

test parseForm {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const f = try parseForm(arena.allocator(), "grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&x=a+b&bad=%zz&empty");
    try std.testing.expectEqualStrings("authorization_code", f.get("grant_type").?);
    try std.testing.expectEqualStrings("https://claude.ai/cb", f.get("redirect_uri").?);
    try std.testing.expectEqualStrings("a b", f.get("x").?);
    try std.testing.expectEqualStrings("%zz", f.get("bad").?);
    try std.testing.expectEqualStrings("", f.get("empty").?);
}

test encoded {
    var buf: [64]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "{f}", .{encoded("vwdkey:MRVL.BATS,E a&b")});
    try std.testing.expectEqualStrings("vwdkey%3AMRVL.BATS%2CE%20a%26b", s);
}
