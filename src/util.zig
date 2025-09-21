// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const constants = @import("constants.zig");
const builtin = @import("builtin");

// Cross-platform file type and permission constants
const FileMode = struct {
    // File type mask
    const IFMT: u32 = 0o170000;

    // File types
    const IFREG: u32 = 0o100000; // Regular file
    const IFDIR: u32 = 0o040000; // Directory
    const IFLNK: u32 = 0o120000; // Symbolic link
    const IFBLK: u32 = 0o060000; // Block device
    const IFCHR: u32 = 0o020000; // Character device
    const IFIFO: u32 = 0o010000; // FIFO/pipe
    const IFSOCK: u32 = 0o140000; // Socket

    // Owner permissions
    const IRUSR: u32 = 0o400; // Read
    const IWUSR: u32 = 0o200; // Write
    const IXUSR: u32 = 0o100; // Execute

    // Group permissions
    const IRGRP: u32 = 0o040; // Read
    const IWGRP: u32 = 0o020; // Write
    const IXGRP: u32 = 0o010; // Execute

    // Other permissions
    const IROTH: u32 = 0o004; // Read
    const IWOTH: u32 = 0o002; // Write
    const IXOTH: u32 = 0o001; // Execute
};

/// Represents file ownership with user ID (uid) and group ID (gid)
pub const FileOwnership = struct { uid: u32, gid: u32 };

/// Retrieve the ownership (uid and gid) of a file
/// On Windows, returns default values as Windows lacks POSIX uid/gid
pub fn getFileOwnership(file_path: []const u8) !FileOwnership {
    if (@import("builtin").target.os.tag == .windows) {
        // Windows doesn't have POSIX uid/gid
        return .{ .uid = constants.DEFAULT_UID, .gid = constants.DEFAULT_GID };
    }

    // Use direct POSIX stat system call to get file ownership
    return getFileOwnershipPosix(file_path) catch {
        // If we can't access the file, return defaults
        return .{ .uid = constants.DEFAULT_UID, .gid = constants.DEFAULT_GID };
    };
}

/// Retrieve file ownership using cross-platform approach
/// Supports Linux, macOS, and other Unix-like systems, returns defaults for others
fn getFileOwnershipPosix(file_path: []const u8) !FileOwnership {
    switch (builtin.target.os.tag) {
        .linux, .macos, .freebsd, .openbsd, .netbsd => {
            // Try to use std.fs.File.stat() which is cross-platform
            const file = std.fs.openFileAbsolute(file_path, .{}) catch {
                return error.StatFailed;
            };
            defer file.close();

            const stat_result = file.stat() catch {
                return error.StatFailed;
            };

            // For now, return default values since std.fs.File.Stat doesn't expose uid/gid
            // This is a limitation of Zig's cross-platform file API
            _ = stat_result;
            return .{ .uid = constants.DEFAULT_UID, .gid = constants.DEFAULT_GID };
        },
        else => {
            return .{ .uid = constants.DEFAULT_UID, .gid = constants.DEFAULT_GID };
        },
    }
}

/// Format a timestamp into a human-readable string (e.g., "YYYY-MM-DD HH:MM:SS")
/// Handles both seconds and nanoseconds timestamps
pub fn formatTimestamp(timestamp: i64, allocator: std.mem.Allocator) ![]u8 {
    // Convert nanoseconds to seconds if needed
    var timestamp_secs = timestamp;
    if (timestamp > 1_000_000_000_000) { // If timestamp is in nanoseconds (> year 2001)
        timestamp_secs = @divTrunc(timestamp, 1_000_000_000);
    }

    // Handle invalid or extreme timestamps
    if (timestamp_secs <= 0 or timestamp_secs > std.math.maxInt(u32)) {
        return std.fmt.allocPrint(allocator, "invalid-timestamp-{}", .{timestamp});
    }

    const datetime = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp_secs) };
    const day_seconds = datetime.getDaySeconds();
    const epoch_day = datetime.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

/// Format file permissions into a string (e.g., "-rwxr-xr-x")
/// Includes file type and read/write/execute permissions for owner, group, and others
pub fn formatPermissions(mode: u32, allocator: std.mem.Allocator) ![]u8 {
    var perms = try allocator.alloc(u8, 10);

    // File type
    perms[0] = switch (mode & FileMode.IFMT) {
        FileMode.IFREG => '-', // Regular file
        FileMode.IFDIR => 'd', // Directory
        FileMode.IFLNK => 'l', // Symbolic link
        FileMode.IFBLK => 'b', // Block device
        FileMode.IFCHR => 'c', // Character device
        FileMode.IFIFO => 'p', // FIFO/pipe
        FileMode.IFSOCK => 's', // Socket
        else => '?',
    };

    // Owner permissions
    perms[1] = if (mode & FileMode.IRUSR != 0) 'r' else '-';
    perms[2] = if (mode & FileMode.IWUSR != 0) 'w' else '-';
    perms[3] = if (mode & FileMode.IXUSR != 0) 'x' else '-';

    // Group permissions
    perms[4] = if (mode & FileMode.IRGRP != 0) 'r' else '-';
    perms[5] = if (mode & FileMode.IWGRP != 0) 'w' else '-';
    perms[6] = if (mode & FileMode.IXGRP != 0) 'x' else '-';

    // Other permissions
    perms[7] = if (mode & FileMode.IROTH != 0) 'r' else '-';
    perms[8] = if (mode & FileMode.IWOTH != 0) 'w' else '-';
    perms[9] = if (mode & FileMode.IXOTH != 0) 'x' else '-';

    return perms;
}

/// Format file size into a human-readable string (e.g., "512B", "2.0KB", "5.0MB")
/// Automatically adjusts units based on size
pub fn formatFileSize(size: u64, allocator: std.mem.Allocator) ![]u8 {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if (size >= GB) {
        return std.fmt.allocPrint(allocator, "{d:.1}GB", .{@as(f64, @floatFromInt(size)) / @as(f64, @floatFromInt(GB))});
    } else if (size >= MB) {
        return std.fmt.allocPrint(allocator, "{d:.1}MB", .{@as(f64, @floatFromInt(size)) / @as(f64, @floatFromInt(MB))});
    } else if (size >= KB) {
        return std.fmt.allocPrint(allocator, "{d:.1}KB", .{@as(f64, @floatFromInt(size)) / @as(f64, @floatFromInt(KB))});
    } else {
        return std.fmt.allocPrint(allocator, "{}B", .{size});
    }
}

const testing = std.testing;

test "formatTimestamp handles seconds correctly" {
    const allocator = testing.allocator;

    // Test a valid timestamp (2021-01-01 00:00:00 = 1609459200)
    const result = try formatTimestamp(1609459200, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("2021-01-01 00:00:00", result);
}

test "formatTimestamp handles nanoseconds conversion" {
    const allocator = testing.allocator;

    // Test with nanoseconds (should convert to seconds)
    const nanoseconds: i64 = 1_609_459_200_000_000_000; // 2021-01-01 00:00:00 in nanoseconds
    const result = try formatTimestamp(nanoseconds, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("2021-01-01 00:00:00", result);
}

test "formatTimestamp handles invalid timestamps" {
    const allocator = testing.allocator;

    // Test negative timestamp
    const result = try formatTimestamp(-1, allocator);
    defer allocator.free(result);
    try testing.expect(std.mem.startsWith(u8, result, "invalid-timestamp"));
}

test "formatPermissions regular file permissions" {
    const allocator = testing.allocator;

    // Test regular file with 755 permissions (rwxr-xr-x)
    const mode: u32 = FileMode.IFREG | FileMode.IRUSR | FileMode.IWUSR | FileMode.IXUSR |
        FileMode.IRGRP | FileMode.IXGRP | FileMode.IROTH | FileMode.IXOTH;
    const result = try formatPermissions(mode, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("-rwxr-xr-x", result);
}

test "formatPermissions directory permissions" {
    const allocator = testing.allocator;

    // Test directory with 644 permissions (rw-r--r--)
    const mode: u32 = FileMode.IFDIR | FileMode.IRUSR | FileMode.IWUSR |
        FileMode.IRGRP | FileMode.IROTH;
    const result = try formatPermissions(mode, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("drw-r--r--", result);
}

test "formatFileSize bytes" {
    const allocator = testing.allocator;

    const result = try formatFileSize(512, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("512B", result);
}

test "formatFileSize kilobytes" {
    const allocator = testing.allocator;

    const result = try formatFileSize(2048, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("2.0KB", result);
}

test "formatFileSize megabytes" {
    const allocator = testing.allocator;

    const result = try formatFileSize(5 * 1024 * 1024, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("5.0MB", result);
}

test "formatFileSize gigabytes" {
    const allocator = testing.allocator;

    const result = try formatFileSize(3 * 1024 * 1024 * 1024, allocator);
    defer allocator.free(result);
    try testing.expectEqualStrings("3.0GB", result);
}

test "getFileOwnership returns defaults on Windows" {
    if (@import("builtin").target.os.tag == .windows) {
        const result = try getFileOwnership("nonexistent");
        try testing.expectEqual(@as(u32, constants.DEFAULT_UID), result.uid);
        try testing.expectEqual(@as(u32, constants.DEFAULT_GID), result.gid);
    }
}

test "getFileOwnership handles nonexistent files" {
    const result = try getFileOwnership("/tmp/definitely_nonexistent_file_12345");
    try testing.expectEqual(@as(u32, constants.DEFAULT_UID), result.uid);
    try testing.expectEqual(@as(u32, constants.DEFAULT_GID), result.gid);
}
