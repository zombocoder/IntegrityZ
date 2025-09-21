// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const manifest = @import("manifest.zig");
const display = @import("display.zig");
const crypto = @import("crypto.zig");
const constants = @import("constants.zig");

// Forward declaration - BaselineDB will be imported from baseline.zig
const BaselineDB = @import("baseline.zig").BaselineDB;

/// Debug print wrapper that can be disabled during tests
fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (!@import("builtin").is_test) {
        std.debug.print(fmt, args);
    }
}

/// Recursively scan a filesystem path and populate baseline database
/// Creates records for the directory itself and all its children
/// Avoids duplicate directory records during recursive traversal
pub fn scanPath(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8) anyerror!void {
    // Check if path is a directory by trying to open it as a directory first
    // This approach works better on Windows
    if (std.fs.openDirAbsolute(path, .{})) |mut_dir| {
        var dir = mut_dir;
        dir.close();

        // It's a directory, create a record for the directory itself
        const dir_record = try createDirRecord(allocator, path);

        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Scanning directory: {s}\n", .{path});
        }
        try baseline.addRecord(dir_record);

        // Scan children without creating duplicate directory records
        try scanPathChildren(allocator, baseline, path);
    } else |_| {
        // Not a directory, check if it's a file by trying to get its stat info
        const stat = std.fs.cwd().statFile(path) catch |err| {
            if (@import("builtin").mode == .Debug) {
                std.debug.print("[DEBUG] Error accessing path {s}: {}\n", .{ path, err });
            }
            return;
        };

        // It's a file or other node type, create appropriate record
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Scanning file: {s}\n", .{path});
        }
        const file_record = try createNodeRecord(allocator, path, stat.kind);
        try baseline.addRecord(file_record);
    }
}

/// Scan only the children of a directory path
/// Used internally to avoid creating duplicate directory records during recursion
pub fn scanPathChildren(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8) anyerror!void {
    var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch |err| {
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Error opening directory {s}: {}\n", .{ path, err });
        }
        return;
    };
    defer dir.close();

    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });
        defer allocator.free(full_path);

        const record = try createNodeRecord(allocator, full_path, entry.kind);
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Created record for: {s}\n", .{full_path});
        }

        try baseline.addRecord(record);

        // Recursively scan subdirectories - but only scan their children, not create duplicate directory records
        if (entry.kind == .directory) {
            try scanPathChildren(allocator, baseline, full_path);
        }
    }
}

/// Create appropriate record type based on filesystem node kind
/// Delegates to specific record creation functions based on node type
pub fn createNodeRecord(allocator: std.mem.Allocator, path: []const u8, kind: std.fs.File.Kind) !records.Record {
    const node_meta = try manifest.statNode(path);

    return switch (kind) {
        .file => records.Record{ .file = try createFileRecordFromMeta(allocator, path, node_meta) },
        .directory => records.Record{ .dir = try createDirRecordFromMeta(allocator, path, node_meta) },
        .sym_link => records.Record{ .symlink = try createSymlinkRecord(allocator, path, node_meta) },
        .block_device => records.Record{ .block = try createSpecialRecord(allocator, path, node_meta) },
        .character_device => records.Record{ .char = try createSpecialRecord(allocator, path, node_meta) },
        .named_pipe => records.Record{ .fifo = try createSpecialRecord(allocator, path, node_meta) },
        .unix_domain_socket => records.Record{ .socket = try createSpecialRecord(allocator, path, node_meta) },
        else => records.Record{ .file = try createFileRecordFromMeta(allocator, path, node_meta) }, // Fallback
    };
}

/// Create a directory record for the specified path
/// Convenience function that handles metadata extraction and record creation
pub fn createDirRecord(allocator: std.mem.Allocator, path: []const u8) !records.Record {
    const node_meta = try manifest.statNode(path);
    return records.Record{ .dir = try createDirRecordFromMeta(allocator, path, node_meta) };
}

/// Create a file record from metadata
/// Includes file size, permissions, ownership, and checksum
fn createFileRecordFromMeta(allocator: std.mem.Allocator, path: []const u8, meta: manifest.NodeMeta) !records.FileRecord {
    // Calculate BLAKE3 hash of file contents
    const checksum = crypto.blake3HashFile(path, allocator) catch |err| switch (err) {
        error.AccessDenied => std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
        else => return err,
    };

    // Get file size
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.AccessDenied => {
            return records.FileRecord{
                .path = try allocator.dupe(u8, path),
                .inode = meta.inode,
                .dev = meta.dev,
                .size = 0,
                .mode = meta.mode,
                .uid = meta.uid,
                .gid = meta.gid,
                .nlink = meta.nlink,
                .mtime = meta.mtime,
                .ctime = meta.ctime,
                .checksum = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
            };
        },
        else => return err,
    };
    defer file.close();
    const stat = try file.stat();

    return records.FileRecord{
        .path = try allocator.dupe(u8, path),
        .inode = meta.inode,
        .dev = meta.dev,
        .size = stat.size,
        .mode = meta.mode,
        .uid = meta.uid,
        .gid = meta.gid,
        .nlink = meta.nlink,
        .mtime = meta.mtime,
        .ctime = meta.ctime,
        .checksum = checksum,
    };
}

/// Create a directory record from metadata
/// Includes manifest hash, entry count, and permissions
fn createDirRecordFromMeta(allocator: std.mem.Allocator, path: []const u8, meta: manifest.NodeMeta) !records.DirRecord {
    // Compute directory manifest hash
    const manifest_hash = manifest.hashDirManifest(allocator, path) catch std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8);

    // Count entries in directory
    var entry_count: u32 = 0;
    if (std.fs.openDirAbsolute(path, .{ .iterate = true })) |mut_dir| {
        var dir = mut_dir;
        defer dir.close();
        var iterator = dir.iterate();
        while (iterator.next() catch null) |_| {
            entry_count += 1;
        }
    } else |_| {}

    return records.DirRecord{
        .path = try allocator.dupe(u8, path),
        .inode = meta.inode,
        .dev = meta.dev,
        .mode = meta.mode,
        .uid = meta.uid,
        .gid = meta.gid,
        .nlink = meta.nlink,
        .mtime = meta.mtime,
        .ctime = meta.ctime,
        .acl_hash = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8), // TODO: implement ACL hashing
        .manifest = manifest_hash,
        .entry_count = entry_count,
    };
}

/// Create a symbolic link record from metadata
/// Includes target path and its hash
fn createSymlinkRecord(allocator: std.mem.Allocator, path: []const u8, meta: manifest.NodeMeta) !records.SymlinkRecord {
    var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const target_slice = std.fs.readLinkAbsolute(path, &buffer) catch |err| switch (err) {
        error.AccessDenied => "[access-denied]",
        else => return err,
    };
    const target = try allocator.dupe(u8, target_slice);

    const target_hash = crypto.blake3Hash(target);

    return records.SymlinkRecord{
        .path = try allocator.dupe(u8, path),
        .inode = meta.inode,
        .dev = meta.dev,
        .mode = meta.mode,
        .uid = meta.uid,
        .gid = meta.gid,
        .mtime = meta.mtime,
        .ctime = meta.ctime,
        .target = target,
        .target_hash = target_hash,
    };
}

/// Create a special file record (e.g., block/character device, FIFO, socket)
/// Includes device ID and permissions
fn createSpecialRecord(allocator: std.mem.Allocator, path: []const u8, meta: manifest.NodeMeta) !records.SpecialRecord {
    return records.SpecialRecord{
        .path = try allocator.dupe(u8, path),
        .inode = meta.inode,
        .dev = meta.dev,
        .mode = meta.mode,
        .uid = meta.uid,
        .gid = meta.gid,
        .mtime = meta.mtime,
        .ctime = meta.ctime,
        .device_id = 0, // TODO: extract actual device ID for block/char devices
    };
}

const testing = std.testing;

test "createNodeRecord handles file kind" {
    const allocator = testing.allocator;

    // Create a temporary file for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "test.txt", .data = "test content" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const file_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, "test.txt" });
    defer allocator.free(file_path);

    const record = try createNodeRecord(allocator, file_path, .file);
    defer {
        switch (record) {
            .file => |file_record| allocator.free(file_record.path),
            else => {},
        }
    }

    try testing.expect(record == .file);
    try testing.expectEqualStrings(file_path, record.file.path);
}

test "createNodeRecord handles directory kind" {
    const allocator = testing.allocator;

    // Create a temporary directory for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("subdir");

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const dir_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, "subdir" });
    defer allocator.free(dir_path);

    const record = try createNodeRecord(allocator, dir_path, .directory);
    defer {
        switch (record) {
            .dir => |dir_record| allocator.free(dir_record.path),
            else => {},
        }
    }

    try testing.expect(record == .dir);
    try testing.expectEqualStrings(dir_path, record.dir.path);
}

test "createFileRecordFromMeta basic functionality" {
    const allocator = testing.allocator;

    // Create a temporary file
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "test.txt", .data = "test content" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const file_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, "test.txt" });
    defer allocator.free(file_path);

    const meta = try manifest.statNode(file_path);
    const file_record = try createFileRecordFromMeta(allocator, file_path, meta);
    defer allocator.free(file_record.path);

    try testing.expectEqualStrings(file_path, file_record.path);
    try testing.expect(file_record.size > 0);

    // On Windows, inode is 0 since Windows doesn't have real inodes
    if (@import("builtin").target.os.tag == .windows) {
        try testing.expect(file_record.inode == 0);
    } else {
        try testing.expect(file_record.inode > 0);
    }
}

test "createDirRecordFromMeta basic functionality" {
    const allocator = testing.allocator;

    // Create a temporary directory with some files
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "file1.txt", .data = "content1" });
    try tmp.dir.writeFile(.{ .sub_path = "file2.txt", .data = "content2" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const meta = try manifest.statNode(tmp_path);
    const dir_record = try createDirRecordFromMeta(allocator, tmp_path, meta);
    defer allocator.free(dir_record.path);

    try testing.expectEqualStrings(tmp_path, dir_record.path);
    try testing.expect(dir_record.entry_count >= 2); // At least our 2 files

    // On Windows, inode is 0 since Windows doesn't have real inodes
    if (@import("builtin").target.os.tag == .windows) {
        try testing.expect(dir_record.inode == 0);
    } else {
        try testing.expect(dir_record.inode > 0);
    }
}

test "createSpecialRecord basic functionality" {
    const allocator = testing.allocator;

    const meta = manifest.NodeMeta{
        .inode = 123,
        .dev = 456,
        .mode = 0o666,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
    };

    const special_record = try createSpecialRecord(allocator, "/dev/null", meta);
    defer allocator.free(special_record.path);

    try testing.expectEqualStrings("/dev/null", special_record.path);
    try testing.expectEqual(@as(u64, 123), special_record.inode);
    try testing.expectEqual(@as(u64, 456), special_record.dev);
    try testing.expectEqual(@as(u32, 0o666), special_record.mode);
}
