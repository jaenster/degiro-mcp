//! RS256 JWT verification against a JWKS, enough to check OIDC-issued access tokens.
const std = @import("std");
const rsa = std.crypto.Certificate.rsa;

const b64 = std.base64.url_safe_no_pad;

pub const Key = struct {
    kid: []const u8,
    /// Big-endian modulus and exponent, base64url-decoded from the JWK.
    n: []const u8,
    e: []const u8,
};

pub const Expect = struct {
    issuer: []const u8,
    /// Checked only when non-empty.
    audience: []const u8 = "",
    now: i64,
    /// Seconds of clock skew allowed on exp/nbf.
    leeway: i64 = 30,
};

pub const Claims = struct {
    sub: []const u8 = "",
    email: []const u8 = "",
};

pub const Error = error{
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    BadIssuer,
    BadAudience,
    Expired,
    NotYetValid,
} || std.mem.Allocator.Error;

/// Decodes the JWKS `keys` array into raw RSA keys, skipping anything that isn't an RSA signing key.
pub fn parseJwks(arena: std.mem.Allocator, json: []const u8) ![]Key {
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
    const arr = switch (parsed) {
        .object => |o| (o.get("keys") orelse return error.Malformed),
        else => return error.Malformed,
    };
    if (arr != .array) return error.Malformed;
    var keys: std.ArrayList(Key) = .empty;
    for (arr.array.items) |k| {
        if (k != .object) continue;
        const o = k.object;
        if (!strEq(o.get("kty"), "RSA")) continue;
        if (o.get("use")) |u| if (u == .string and !std.mem.eql(u8, u.string, "sig")) continue;
        const n = str(o.get("n")) orelse continue;
        const e = str(o.get("e")) orelse continue;
        try keys.append(arena, .{
            .kid = str(o.get("kid")) orelse "",
            .n = try decodeAlloc(arena, n),
            .e = try decodeAlloc(arena, e),
        });
    }
    return keys.items;
}

pub fn verify(arena: std.mem.Allocator, token: []const u8, keys: []const Key, expect: Expect) Error!Claims {
    var parts = std.mem.splitScalar(u8, token, '.');
    const h64 = parts.next() orelse return error.Malformed;
    const p64 = parts.next() orelse return error.Malformed;
    const s64 = parts.next() orelse return error.Malformed;
    if (parts.next() != null) return error.Malformed;

    const header = try decodeJson(arena, h64);
    if (!strEq(header.get("alg"), "RS256")) return error.UnsupportedAlgorithm;
    const kid = str(header.get("kid")) orelse "";

    const key = for (keys) |k| {
        if (kid.len == 0 or std.mem.eql(u8, k.kid, kid)) break k;
    } else return error.UnknownKey;

    const sig = decodeAlloc(arena, s64) catch return error.Malformed;
    try verifySignature(token[0 .. h64.len + 1 + p64.len], sig, key);

    const payload = try decodeJson(arena, p64);
    if (!strEq(payload.get("iss"), expect.issuer)) return error.BadIssuer;
    const exp = int(payload.get("exp")) orelse return error.Malformed;
    if (expect.now > exp + expect.leeway) return error.Expired;
    if (int(payload.get("nbf"))) |nbf| if (expect.now + expect.leeway < nbf) return error.NotYetValid;
    if (expect.audience.len > 0 and !audienceMatches(payload.get("aud"), expect.audience)) return error.BadAudience;

    return .{
        .sub = str(payload.get("sub")) orelse "",
        .email = str(payload.get("email")) orelse "",
    };
}

fn verifySignature(signed: []const u8, sig: []const u8, key: Key) Error!void {
    const pk = rsa.PublicKey.fromBytes(key.e, stripZeros(key.n)) catch return error.BadSignature;
    switch (sig.len) {
        inline 256, 384, 512 => |len| {
            if (stripZeros(key.n).len != len) return error.BadSignature;
            rsa.PKCS1v1_5Signature.verify(len, sig[0..len].*, signed, pk, std.crypto.hash.sha2.Sha256) catch
                return error.BadSignature;
        },
        else => return error.BadSignature,
    }
}

fn audienceMatches(aud: ?std.json.Value, want: []const u8) bool {
    const v = aud orelse return false;
    switch (v) {
        .string => |s| return std.mem.eql(u8, s, want),
        .array => |a| for (a.items) |item| {
            if (item == .string and std.mem.eql(u8, item.string, want)) return true;
        },
        else => {},
    }
    return false;
}

fn stripZeros(b: []const u8) []const u8 {
    var i: usize = 0;
    while (i + 1 < b.len and b[i] == 0) i += 1;
    return b[i..];
}

fn decodeAlloc(arena: std.mem.Allocator, s: []const u8) ![]u8 {
    // Tolerate padded input too: some JWKS publishers emit '=' anyway.
    const trimmed = std.mem.trimEnd(u8, s, "=");
    const out = try arena.alloc(u8, b64.Decoder.calcSizeForSlice(trimmed) catch return error.Malformed);
    b64.Decoder.decode(out, trimmed) catch return error.Malformed;
    return out;
}

fn decodeJson(arena: std.mem.Allocator, s: []const u8) Error!std.json.ObjectMap {
    const raw = decodeAlloc(arena, s) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else error.Malformed;
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{}) catch return error.Malformed;
    return if (v == .object) v.object else error.Malformed;
}

fn str(v: ?std.json.Value) ?[]const u8 {
    const x = v orelse return null;
    return if (x == .string) x.string else null;
}

fn strEq(v: ?std.json.Value, want: []const u8) bool {
    const s = str(v) orelse return false;
    return std.mem.eql(u8, s, want);
}

fn int(v: ?std.json.Value) ?i64 {
    const x = v orelse return null;
    return switch (x) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

const testdata = @import("testdata/jwt.zig");

test "verifies a real RS256 token" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const keys = try parseJwks(a, testdata.jwks);
    try std.testing.expectEqual(@as(usize, 1), keys.len);

    const claims = try verify(a, testdata.token, keys, .{ .issuer = testdata.issuer, .audience = testdata.audience, .now = testdata.iat });
    try std.testing.expectEqualStrings("test@example.com", claims.email);

    try std.testing.expectError(error.Expired, verify(a, testdata.token, keys, .{ .issuer = testdata.issuer, .now = testdata.iat + 7200 }));
    try std.testing.expectError(error.BadIssuer, verify(a, testdata.token, keys, .{ .issuer = "https://evil/", .now = testdata.iat }));
    try std.testing.expectError(error.BadAudience, verify(a, testdata.token, keys, .{ .issuer = testdata.issuer, .audience = "other", .now = testdata.iat }));

    // Flip one character of the payload: the signature must no longer match.
    const tampered = try a.dupe(u8, testdata.token);
    const dot = std.mem.indexOfScalar(u8, tampered, '.').?;
    tampered[dot + 5] = if (tampered[dot + 5] == 'A') 'B' else 'A';
    try std.testing.expectError(error.BadSignature, verify(a, tampered, keys, .{ .issuer = testdata.issuer, .now = testdata.iat }));
}
