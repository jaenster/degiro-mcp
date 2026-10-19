//! Sealed blobs: JSON encrypted and authenticated with XChaCha20-Poly1305 under a server key, then
//! base64url encoded. Lets the server hand out ids and tokens that it can trust later without
//! remembering them.
const std = @import("std");

const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const b64 = std.base64.url_safe_no_pad;

pub const key_length = Aead.key_length;
pub const Key = [key_length]u8;

/// Distinguishes the blob types (used as AEAD associated data), so a blob of one kind can never be
/// replayed as another.
pub const Kind = enum(u8) { client = 'c', state = 's', code = 'a', access = 't', refresh = 'r', order = 'o' };

pub fn now(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toSeconds();
}

pub fn seal(arena: std.mem.Allocator, io: std.Io, key: Key, kind: Kind, payload: anytype) ![]const u8 {
    const json = try std.json.Stringify.valueAlloc(arena, payload, .{});
    const raw = try arena.alloc(u8, Aead.nonce_length + json.len + Aead.tag_length);
    const nonce = raw[0..Aead.nonce_length];
    try io.randomSecure(nonce);
    const ct = raw[Aead.nonce_length..][0..json.len];
    const tag = raw[Aead.nonce_length + json.len ..][0..Aead.tag_length];
    Aead.encrypt(ct, tag, json, &.{@intFromEnum(kind)}, nonce.*, key);
    const out = try arena.alloc(u8, b64.Encoder.calcSize(raw.len));
    return b64.Encoder.encode(out, raw);
}

/// Decrypts and parses a blob of `kind`; null if forged, of another kind, or past its `exp` (0 = no
/// expiry).
pub fn open(comptime T: type, arena: std.mem.Allocator, io: std.Io, key: Key, kind: Kind, sealed: []const u8) ?T {
    if (sealed.len == 0 or sealed.len > 8192) return null;
    const raw = arena.alloc(u8, b64.Decoder.calcSizeForSlice(sealed) catch return null) catch return null;
    b64.Decoder.decode(raw, sealed) catch return null;
    if (raw.len < Aead.nonce_length + Aead.tag_length) return null;
    const json_len = raw.len - Aead.nonce_length - Aead.tag_length;
    const json = arena.alloc(u8, json_len) catch return null;
    Aead.decrypt(
        json,
        raw[Aead.nonce_length..][0..json_len],
        raw[Aead.nonce_length + json_len ..][0..Aead.tag_length].*,
        &.{@intFromEnum(kind)},
        raw[0..Aead.nonce_length].*,
        key,
    ) catch return null;
    const v = std.json.parseFromSliceLeaky(T, arena, json, .{ .ignore_unknown_fields = true }) catch return null;
    if (v.exp != 0 and v.exp < now(io)) return null;
    return v;
}
