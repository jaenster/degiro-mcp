//! Civil-date helpers. Times are handled as naive wall-clock seconds: DeGiro and vwd already answer in
//! Europe/Amsterdam, so no time zone math is needed.
const std = @import("std");

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's days_from_civil).
pub fn daysFromCivil(year: i32, month: u8, day: u8) i64 {
    const y: i64 = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const doy = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

pub const Civil = struct { year: u16, month: u8, day: u8, hour: u8 = 0, minute: u8 = 0, second: u8 = 0 };

pub fn civilFromSeconds(secs: i64) Civil {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(secs) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return .{
        .year = yd.year,
        .month = md.month.numeric(),
        .day = @as(u8, md.day_index) + 1,
        .hour = ds.getHoursIntoDay(),
        .minute = ds.getMinutesIntoHour(),
        .second = ds.getSecondsIntoMinute(),
    };
}

/// Parses "YYYY-MM-DD" with an optional "THH:MM[:SS]" suffix (anything after the seconds is ignored).
pub fn parse(s: []const u8) ?i64 {
    if (s.len < 10 or s[4] != '-' or s[7] != '-') return null;
    const y = std.fmt.parseInt(i32, s[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31) return null;
    var secs = daysFromCivil(y, mo, d) * 86400;
    if (s.len >= 16 and s[10] == 'T' and s[13] == ':') {
        secs += (std.fmt.parseInt(i64, s[11..13], 10) catch return null) * 3600;
        secs += (std.fmt.parseInt(i64, s[14..16], 10) catch return null) * 60;
        if (s.len >= 19 and s[16] == ':') secs += std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    }
    return secs;
}

/// DeGiro's reporting endpoints want dd/MM/yyyy.
pub fn degiroDate(buf: *[10]u8, secs: i64) []const u8 {
    const c = civilFromSeconds(secs);
    return std.fmt.bufPrint(buf, "{d:0>2}/{d:0>2}/{d:0>4}", .{ c.day, c.month, c.year }) catch unreachable;
}

pub fn isoDate(buf: *[10]u8, secs: i64) []const u8 {
    const c = civilFromSeconds(secs);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ c.year, c.month, c.day }) catch unreachable;
}

/// "YYYY-MM-DD" for whole days, "YYYY-MM-DD HH:MM" otherwise.
pub fn formatAlloc(arena: std.mem.Allocator, secs: i64) ![]const u8 {
    const c = civilFromSeconds(secs);
    if (@mod(secs, 86400) == 0) return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}", .{ c.year, c.month, c.day });
    return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{ c.year, c.month, c.day, c.hour, c.minute });
}

/// Seconds in an ISO 8601 duration like PT15M, PT1H, P1D or P1W. Months and years are not fixed-length
/// and return null.
pub fn durationSeconds(s: []const u8) ?i64 {
    if (s.len < 3 or s[0] != 'P') return null;
    const time = s[1] == 'T';
    const body = s[(if (time) @as(usize, 2) else 1) .. s.len - 1];
    const n = std.fmt.parseInt(i64, body, 10) catch return null;
    const unit: i64 = switch (s[s.len - 1]) {
        'S' => if (time) 1 else return null,
        'M' => if (time) 60 else return null,
        'H' => if (time) 3600 else return null,
        'D' => if (!time) 86400 else return null,
        'W' => if (!time) 7 * 86400 else return null,
        else => return null,
    };
    return n * unit;
}

test "civil round trip" {
    const t = parse("2026-10-19").?;
    var buf: [10]u8 = undefined;
    try std.testing.expectEqualStrings("19/10/2026", degiroDate(&buf, t));
    try std.testing.expectEqualStrings("2024-02-29", isoDate(&buf, parse("2024-02-29").?));
    try std.testing.expectEqual(@as(i64, 0), parse("1970-01-01").?);
    try std.testing.expectEqual(parse("2026-10-16").? + 15 * 3600 + 30 * 60, parse("2026-10-16T15:30:00+02:00").?);
    try std.testing.expectEqual(@as(?i64, null), parse("19/10/2026"));
}

test durationSeconds {
    try std.testing.expectEqual(@as(?i64, 3600), durationSeconds("PT1H"));
    try std.testing.expectEqual(@as(?i64, 900), durationSeconds("PT15M"));
    try std.testing.expectEqual(@as(?i64, 86400), durationSeconds("P1D"));
    try std.testing.expectEqual(@as(?i64, null), durationSeconds("P1M"));
}
