//! RFC 6238 TOTP (SHA1, 30s step, 6 digits), which is what DeGiro's authenticator setup uses.
const std = @import("std");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

pub const Error = error{InvalidBase32};

/// Decodes an RFC 4648 base32 secret. Spaces, dashes and '=' padding are ignored and case does not matter,
/// so a seed copied straight out of an authenticator app works.
pub fn decodeBase32(out: []u8, in: []const u8) Error![]u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var n: usize = 0;
    for (in) |c| {
        const v: u32 = switch (c) {
            'A'...'Z' => c - 'A',
            'a'...'z' => c - 'a',
            '2'...'7' => c - '2' + 26,
            ' ', '-', '=' => continue,
            else => return error.InvalidBase32,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n == out.len) return error.InvalidBase32;
            out[n] = @truncate(acc >> bits);
            n += 1;
        }
    }
    return out[0..n];
}

/// Accepts either a bare base32 seed or a full `otpauth://totp/...?secret=XXX&...` URI (what password
/// managers export) and returns the base32 part.
pub fn seedFromInput(in: []const u8) []const u8 {
    const s = std.mem.trim(u8, in, " \t\r\n");
    if (!std.ascii.startsWithIgnoreCase(s, "otpauth://")) return s;
    const q = std.mem.indexOfScalar(u8, s, '?') orelse return s;
    var it = std.mem.splitScalar(u8, s[q + 1 ..], '&');
    while (it.next()) |kv| {
        if (std.ascii.startsWithIgnoreCase(kv, "secret=")) return kv["secret=".len..];
    }
    return s;
}

pub fn code(key: []const u8, unix_seconds: i64) u32 {
    const counter: u64 = @intCast(@divFloor(unix_seconds, 30));
    var msg: [8]u8 = undefined;
    std.mem.writeInt(u64, &msg, counter, .big);
    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, &msg, key);
    const off = mac[mac.len - 1] & 0x0f;
    const bin = std.mem.readInt(u32, mac[off..][0..4], .big) & 0x7fff_ffff;
    return bin % 1_000_000;
}

test "rfc 6238 sha1 vectors" {
    var buf: [64]u8 = undefined;
    const key = try decodeBase32(&buf, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    try std.testing.expectEqualStrings("12345678901234567890", key);
    try std.testing.expectEqual(@as(u32, 287082), code(key, 59));
    try std.testing.expectEqual(@as(u32, 81804), code(key, 1111111109));
    try std.testing.expectEqual(@as(u32, 279037), code(key, 2000000000));
}

test "seed from otpauth uri" {
    try std.testing.expectEqualStrings("ABCD", seedFromInput("otpauth://totp/DEGIRO:me?issuer=DEGIRO&secret=ABCD&period=30"));
    try std.testing.expectEqualStrings("ABCD", seedFromInput(" ABCD\n"));
}

test "base32 tolerates formatting" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("12345678901234567890", try decodeBase32(&buf, "gezd gnbv-gy3t qojq gezd gnbv gy3t qojq=="));
    try std.testing.expectError(error.InvalidBase32, decodeBase32(&buf, "GEZ1"));
}
