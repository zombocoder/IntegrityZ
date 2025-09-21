// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");

/// Display comprehensive metadata for any filesystem node record
/// Formats and prints detailed information including hashes, permissions, timestamps
/// Output format varies by node type (file, directory, symlink, special)
pub fn displayNodeRecord(allocator: std.mem.Allocator, record: *const records.Record, writer: ?std.io.AnyWriter) !void {
    const path = record.getPath();
    const permissions = try util.formatPermissions(records.getRecordMode(record), allocator);
    defer allocator.free(permissions);

    const mtime_str = try util.formatTimestamp(records.getRecordMtime(record), allocator);
    defer allocator.free(mtime_str);

    const ctime_str = try util.formatTimestamp(records.getRecordCtime(record), allocator);
    defer allocator.free(ctime_str);

    if (writer) |w| {
        try w.print("  {s} [{s}]\n", .{ path, @tagName(record.*) });
    } else {
        std.debug.print("  {s} [{s}]\n", .{ path, @tagName(record.*) });
    }

    switch (record.*) {
        .file => |file_record| {
            const hex_hash = try crypto.hashToHex(file_record.checksum, allocator);
            defer allocator.free(hex_hash);

            const size_str = try util.formatFileSize(file_record.size, allocator);
            defer allocator.free(size_str);

            if (writer) |w| {
                try w.print("    Hash: {s}\n", .{hex_hash});
                try w.print("    Size: {s} | Inode: {} | Dev: {} | Links: {}\n", .{ size_str, file_record.inode, file_record.dev, file_record.nlink });
                try w.print("    Mode: {s} (0o{o}) | uid:{} gid:{}\n", .{ permissions, file_record.mode, file_record.uid, file_record.gid });
                try w.print("    Modified: {s} | Changed: {s}\n", .{ mtime_str, ctime_str });
            } else {
                std.debug.print("    Hash: {s}\n", .{hex_hash});
                std.debug.print("    Size: {s} | Inode: {} | Dev: {} | Links: {}\n", .{ size_str, file_record.inode, file_record.dev, file_record.nlink });
                std.debug.print("    Mode: {s} (0o{o}) | uid:{} gid:{}\n", .{ permissions, file_record.mode, file_record.uid, file_record.gid });
                std.debug.print("    Modified: {s} | Changed: {s}\n", .{ mtime_str, ctime_str });
            }
        },
        .dir => |dir_record| {
            const manifest_hex = try crypto.hashToHex(dir_record.manifest, allocator);
            defer allocator.free(manifest_hex);

            if (writer) |w| {
                try w.print("    Manifest: {s}\n", .{manifest_hex});
                try w.print("    Entries: {} | Inode: {} | Dev: {} | Links: {}\n", .{ dir_record.entry_count, dir_record.inode, dir_record.dev, dir_record.nlink });
                try w.print("    Mode: {s} (0o{o}) | uid:{} gid:{}\n", .{ permissions, dir_record.mode, dir_record.uid, dir_record.gid });
                try w.print("    Modified: {s} | Changed: {s}\n", .{ mtime_str, ctime_str });
            } else {
                std.debug.print("    Manifest: {s}\n", .{manifest_hex});
                std.debug.print("    Entries: {} | Inode: {} | Dev: {} | Links: {}\n", .{ dir_record.entry_count, dir_record.inode, dir_record.dev, dir_record.nlink });
                std.debug.print("    Mode: {s} (0o{o}) | uid:{} gid:{}\n", .{ permissions, dir_record.mode, dir_record.uid, dir_record.gid });
                std.debug.print("    Modified: {s} | Changed: {s}\n", .{ mtime_str, ctime_str });
            }
        },
        .symlink => |symlink_record| {
            const target_hex = try crypto.hashToHex(symlink_record.target_hash, allocator);
            defer allocator.free(target_hex);

            if (writer) |w| {
                try w.print("    Target: {s} (hash: {s})\n", .{ symlink_record.target, target_hex });
                try w.print("    Inode: {} | Dev: {} | Mode: {s} (0o{o})\n", .{ symlink_record.inode, symlink_record.dev, permissions, symlink_record.mode });
                try w.print("    Owner: uid:{} gid:{} | Modified: {s} | Changed: {s}\n", .{ symlink_record.uid, symlink_record.gid, mtime_str, ctime_str });
            } else {
                std.debug.print("    Target: {s} (hash: {s})\n", .{ symlink_record.target, target_hex });
                std.debug.print("    Inode: {} | Dev: {} | Mode: {s} (0o{o})\n", .{ symlink_record.inode, symlink_record.dev, permissions, symlink_record.mode });
                std.debug.print("    Owner: uid:{} gid:{} | Modified: {s} | Changed: {s}\n", .{ symlink_record.uid, symlink_record.gid, mtime_str, ctime_str });
            }
        },
        .block, .char, .fifo, .socket => |special_record| {
            if (writer) |w| {
                try w.print("    Device ID: {} | Inode: {} | Dev: {}\n", .{ special_record.device_id, special_record.inode, special_record.dev });
                try w.print("    Mode: {s} (0o{o}) | uid:{} gid:{}\n", .{ permissions, special_record.mode, special_record.uid, special_record.gid });
                try w.print("    Modified: {s} | Changed: {s}\n", .{ mtime_str, ctime_str });
            } else {
                std.debug.print("    Device ID: {} | Inode: {} | Dev: {}\n", .{ special_record.device_id, special_record.inode, special_record.dev });
                std.debug.print("    Mode: {s} (0o{o}) | uid:{} gid:{}\n", .{ permissions, special_record.mode, special_record.uid, special_record.gid });
                std.debug.print("    Modified: {s} | Changed: {s}\n", .{ mtime_str, ctime_str });
            }
        },
    }
}

const testing = std.testing;

test "displayNodeRecord handles file record" {
    const allocator = testing.allocator;

    // Create a file record for testing
    const file_record = records.FileRecord{
        .path = "/test/file.txt",
        .checksum = [_]u8{ 0x01, 0x02, 0x03, 0x04 } ++ [_]u8{0} ** 28, // 32 bytes total
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .inode = 12345,
        .dev = 2049,
        .nlink = 1,
        .mtime = 1609459200, // 2021-01-01 00:00:00
        .ctime = 1609459200,
    };

    const record = records.Record{ .file = file_record };

    // This test mainly checks that the function doesn't crash
    // In a real test environment, we would capture stdout
    try displayNodeRecord(allocator, &record, null);
}

test "displayNodeRecord handles directory record" {
    const allocator = testing.allocator;

    const dir_record = records.DirRecord{
        .path = "/test/dir",
        .manifest = [_]u8{ 0x05, 0x06, 0x07, 0x08 } ++ [_]u8{0} ** 28,
        .entry_count = 5,
        .mode = 0o755,
        .uid = 1000,
        .gid = 1000,
        .inode = 54321,
        .dev = 2049,
        .nlink = 2,
        .mtime = 1609459200,
        .ctime = 1609459200,
        .acl_hash = [_]u8{0} ** 32,
    };

    const record = records.Record{ .dir = dir_record };
    try displayNodeRecord(allocator, &record, null);
}

test "displayNodeRecord handles symlink record" {
    const allocator = testing.allocator;

    const symlink_record = records.SymlinkRecord{
        .path = "/test/link",
        .target = "/test/target",
        .target_hash = [_]u8{ 0x09, 0x0a, 0x0b, 0x0c } ++ [_]u8{0} ** 28,
        .mode = 0o777,
        .uid = 1000,
        .gid = 1000,
        .inode = 98765,
        .dev = 2049,
        .mtime = 1609459200,
        .ctime = 1609459200,
    };

    const record = records.Record{ .symlink = symlink_record };
    try displayNodeRecord(allocator, &record, null);
}

test "displayNodeRecord handles special device record" {
    const allocator = testing.allocator;

    const special_record = records.SpecialRecord{
        .path = "/dev/null",
        .device_id = 259,
        .mode = 0o666,
        .uid = 0,
        .gid = 0,
        .inode = 3,
        .dev = 5,
        .mtime = 1609459200,
        .ctime = 1609459200,
    };

    const record = records.Record{ .char = special_record };
    try displayNodeRecord(allocator, &record, null);
}

test "record getPath utility" {
    const file_record = records.FileRecord{
        .path = "/test/path.txt",
        .checksum = [_]u8{0} ** 32,
        .size = 0,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .inode = 1,
        .dev = 1,
        .nlink = 1,
        .mtime = 0,
        .ctime = 0,
    };

    const record = records.Record{ .file = file_record };
    const path = record.getPath();
    try testing.expectEqualStrings("/test/path.txt", path);
}

test "record mode and timestamp utilities" {
    const file_record = records.FileRecord{
        .path = "/test/file",
        .checksum = [_]u8{0} ** 32,
        .size = 0,
        .mode = 0o755,
        .uid = 1000,
        .gid = 1000,
        .inode = 1,
        .dev = 1,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459300,
    };

    const record = records.Record{ .file = file_record };

    try testing.expectEqual(@as(u32, 0o755), records.getRecordMode(&record));
    try testing.expectEqual(@as(i64, 1609459200), records.getRecordMtime(&record));
    try testing.expectEqual(@as(i64, 1609459300), records.getRecordCtime(&record));
}
