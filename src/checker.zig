// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const database = @import("database.zig");
const scanner = @import("scanner.zig");
const crypto = @import("crypto.zig");
const constants = @import("constants.zig");

/// Types of changes that can be detected during integrity checks
pub const ChangeType = enum {
    added, // File/directory was added
    deleted, // File/directory was removed
    modified, // File content or metadata changed
    moved, // File was moved/renamed
};

/// Represents a detected change in the filesystem
pub const Change = struct {
    change_type: ChangeType,
    path: []const u8,
    old_record: ?records.Record, // null for additions
    new_record: ?records.Record, // null for deletions
    details: []const u8, // Human-readable description of the change

    /// Cleanup allocated memory for this change
    pub fn deinit(self: *Change, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.details);
        if (self.old_record) |*record| {
            record.deinit(allocator);
        }
        if (self.new_record) |*record| {
            record.deinit(allocator);
        }
    }
};

/// Result of an integrity check operation
pub const CheckResult = struct {
    changes: std.ArrayList(Change),
    total_files_checked: u32,
    baseline_records: u32,
    current_records: u32,

    /// Initialize a new check result
    pub fn init(allocator: std.mem.Allocator) CheckResult {
        return CheckResult{
            .changes = std.ArrayList(Change).init(allocator),
            .total_files_checked = 0,
            .baseline_records = 0,
            .current_records = 0,
        };
    }

    /// Cleanup all allocated memory
    pub fn deinit(self: *CheckResult) void {
        for (self.changes.items) |*change| {
            change.deinit(self.changes.allocator);
        }
        self.changes.deinit();
    }

    /// Add a detected change to the result
    pub fn addChange(self: *CheckResult, change: Change) !void {
        try self.changes.append(change);
    }

    /// Check if any changes were detected
    pub fn hasChanges(self: *const CheckResult) bool {
        return self.changes.items.len > 0;
    }
};

/// Main function to check filesystem integrity against a baseline
/// Loads the baseline database and compares current filesystem state
pub fn checkIntegrity(allocator: std.mem.Allocator, baseline_path: []const u8, paths: [][]const u8) !CheckResult {
    var result = CheckResult.init(allocator);

    // Load baseline database
    if (@import("builtin").mode == .Debug) {
        std.debug.print("[DEBUG] Loading baseline from: {s}\n", .{baseline_path});
    }
    var baseline_db = database.BaselineDB.loadFromFile(allocator, baseline_path) catch |err| switch (err) {
        error.FileNotFound => {
            // Error handled in main.zig
            return err;
        },
        error.InvalidFileFormat => {
            // Error handled in main.zig
            return err;
        },
        error.UnsupportedVersion => {
            // Error handled in main.zig
            return err;
        },
        else => return err,
    };
    defer baseline_db.deinit();

    result.baseline_records = @intCast(baseline_db.records.items.len);
    if (@import("builtin").mode == .Debug) {
        std.debug.print("[DEBUG] Loaded baseline with {} records\n", .{result.baseline_records});
    }

    // Create lookup map for baseline records by path
    var baseline_map = std.HashMap([]const u8, *const records.Record, std.hash_map.StringContext, 80).init(allocator);
    defer baseline_map.deinit();

    for (baseline_db.records.items) |*record| {
        try baseline_map.put(record.getPath(), record);
    }

    // Scan current filesystem state
    if (@import("builtin").mode == .Debug) {
        std.debug.print("[DEBUG] Scanning current filesystem state...\n", .{});
    }
    var current_db = try scanMultiplePaths(allocator, if (paths.len > 0) paths else try extractPathsFromBaseline(allocator, &baseline_db));
    defer current_db.deinit();

    result.current_records = @intCast(current_db.records.items.len);
    if (@import("builtin").mode == .Debug) {
        std.debug.print("[DEBUG] Found {} current records\n", .{result.current_records});
    }

    // Create lookup map for current records by path
    var current_map = std.HashMap([]const u8, *const records.Record, std.hash_map.StringContext, 80).init(allocator);
    defer current_map.deinit();

    for (current_db.records.items) |*record| {
        try current_map.put(record.getPath(), record);
    }

    // Check for modifications and deletions
    for (baseline_db.records.items) |*baseline_record| {
        const path = baseline_record.getPath();
        result.total_files_checked += 1;

        if (current_map.get(path)) |current_record| {
            // File exists in both - check for modifications
            const changes = try compareRecords(allocator, baseline_record, current_record);
            for (changes) |change| {
                try result.addChange(change);
            }
        } else {
            // File was deleted
            const change = Change{
                .change_type = .deleted,
                .path = try allocator.dupe(u8, path),
                .old_record = try duplicateRecord(allocator, baseline_record),
                .new_record = null,
                .details = try std.fmt.allocPrint(allocator, "File deleted: {s}", .{path}),
            };
            try result.addChange(change);
        }
    }

    // Check for additions
    for (current_db.records.items) |*current_record| {
        const path = current_record.getPath();

        if (!baseline_map.contains(path)) {
            // File was added
            const change = Change{
                .change_type = .added,
                .path = try allocator.dupe(u8, path),
                .old_record = null,
                .new_record = try duplicateRecord(allocator, current_record),
                .details = try std.fmt.allocPrint(allocator, "File added: {s}", .{path}),
            };
            try result.addChange(change);
        }
    }

    return result;
}

/// Scan multiple paths and create a database
fn scanMultiplePaths(allocator: std.mem.Allocator, paths: [][]const u8) !database.BaselineDB {
    var db = database.BaselineDB.init(allocator);

    for (paths) |path| {
        // Convert relative paths to absolute before processing
        const absolute_path = if (std.fs.path.isAbsolute(path))
            try allocator.dupe(u8, path)
        else
            try std.fs.cwd().realpathAlloc(allocator, path);
        defer allocator.free(absolute_path);

        try scanner.scanPathAdaptive(allocator, &db, absolute_path);
    }

    return db;
}

/// Extract the original paths from baseline database (simplified version - gets unique directory paths)
fn extractPathsFromBaseline(allocator: std.mem.Allocator, baseline_db: *const database.BaselineDB) ![][]const u8 {
    var path_set = std.HashMap([]const u8, void, std.hash_map.StringContext, 80).init(allocator);
    defer path_set.deinit();

    // Extract unique directory paths from all records
    for (baseline_db.records.items) |*record| {
        const record_path = record.getPath();

        // Get directory containing this file/dir
        const dir_path = if (record.* == .dir)
            record_path
        else
            std.fs.path.dirname(record_path) orelse record_path;

        try path_set.put(dir_path, {});
    }

    // Convert to array
    var paths = try allocator.alloc([]const u8, path_set.count());
    var i: usize = 0;
    var iterator = path_set.iterator();
    while (iterator.next()) |entry| {
        paths[i] = try allocator.dupe(u8, entry.key_ptr.*);
        i += 1;
    }

    return paths;
}

/// Compare two records and return any detected changes
fn compareRecords(allocator: std.mem.Allocator, baseline: *const records.Record, current: *const records.Record) ![]Change {
    var changes = std.ArrayList(Change).init(allocator);
    defer changes.deinit(); // We'll return the owned slice

    const path = baseline.getPath();

    // Check if record types match
    if (@as(records.NodeType, baseline.*) != @as(records.NodeType, current.*)) {
        const change = Change{
            .change_type = .modified,
            .path = try allocator.dupe(u8, path),
            .old_record = try duplicateRecord(allocator, baseline),
            .new_record = try duplicateRecord(allocator, current),
            .details = try std.fmt.allocPrint(allocator, "File type changed from {s} to {s}", .{ @tagName(baseline.*), @tagName(current.*) }),
        };
        try changes.append(change);
        return changes.toOwnedSlice();
    }

    // Compare based on record type
    switch (baseline.*) {
        .file => |baseline_file| {
            const current_file = current.file;

            // Check for any file changes and consolidate into a single change record
            var change_details = std.ArrayList([]const u8).init(allocator);
            defer {
                for (change_details.items) |detail| {
                    allocator.free(detail);
                }
                change_details.deinit();
            }

            var has_changes = false;

            // Check file content (checksum)
            if (!std.mem.eql(u8, &baseline_file.checksum, &current_file.checksum)) {
                has_changes = true;
                try change_details.append(try std.fmt.allocPrint(allocator, "Content changed (checksum mismatch)", .{}));
            }

            // Check file size
            if (baseline_file.size != current_file.size) {
                has_changes = true;
                try change_details.append(try std.fmt.allocPrint(allocator, "Size changed from {} to {} bytes", .{ baseline_file.size, current_file.size }));
            }

            // Check permissions
            if (baseline_file.mode != current_file.mode) {
                has_changes = true;
                try change_details.append(try std.fmt.allocPrint(allocator, "Permissions changed from 0o{o} to 0o{o}", .{ baseline_file.mode, current_file.mode }));
            }

            // Check modification time
            if (baseline_file.mtime != current_file.mtime) {
                has_changes = true;
                try change_details.append(try std.fmt.allocPrint(allocator, "Modification time changed", .{}));
            }

            // If any changes detected, create a single consolidated change record
            if (has_changes) {
                // Join all details with "; "
                const details = try std.mem.join(allocator, "; ", change_details.items);

                const change = Change{
                    .change_type = .modified,
                    .path = try allocator.dupe(u8, path),
                    .old_record = try duplicateRecord(allocator, baseline),
                    .new_record = try duplicateRecord(allocator, current),
                    .details = details,
                };
                try changes.append(change);
            }
        },
        .dir => |baseline_dir| {
            const current_dir = current.dir;

            // Check directory manifest (contents)
            if (!std.mem.eql(u8, &baseline_dir.manifest, &current_dir.manifest)) {
                const change = Change{
                    .change_type = .modified,
                    .path = try allocator.dupe(u8, path),
                    .old_record = try duplicateRecord(allocator, baseline),
                    .new_record = try duplicateRecord(allocator, current),
                    .details = try std.fmt.allocPrint(allocator, "Directory contents changed", .{}),
                };
                try changes.append(change);
            }

            // Check entry count
            if (baseline_dir.entry_count != current_dir.entry_count) {
                const change = Change{
                    .change_type = .modified,
                    .path = try allocator.dupe(u8, path),
                    .old_record = try duplicateRecord(allocator, baseline),
                    .new_record = try duplicateRecord(allocator, current),
                    .details = try std.fmt.allocPrint(allocator, "Directory entry count changed from {} to {}", .{ baseline_dir.entry_count, current_dir.entry_count }),
                };
                try changes.append(change);
            }

            // Check permissions
            if (baseline_dir.mode != current_dir.mode) {
                const change = Change{
                    .change_type = .modified,
                    .path = try allocator.dupe(u8, path),
                    .old_record = try duplicateRecord(allocator, baseline),
                    .new_record = try duplicateRecord(allocator, current),
                    .details = try std.fmt.allocPrint(allocator, "Directory permissions changed from 0o{o} to 0o{o}", .{ baseline_dir.mode, current_dir.mode }),
                };
                try changes.append(change);
            }
        },
        .symlink => |baseline_symlink| {
            const current_symlink = current.symlink;

            // Check symlink target
            if (!std.mem.eql(u8, baseline_symlink.target, current_symlink.target)) {
                const change = Change{
                    .change_type = .modified,
                    .path = try allocator.dupe(u8, path),
                    .old_record = try duplicateRecord(allocator, baseline),
                    .new_record = try duplicateRecord(allocator, current),
                    .details = try std.fmt.allocPrint(allocator, "Symlink target changed from '{s}' to '{s}'", .{ baseline_symlink.target, current_symlink.target }),
                };
                try changes.append(change);
            }
        },
        .block, .char, .fifo, .socket => |baseline_special| {
            const current_special = switch (current.*) {
                .block, .char, .fifo, .socket => |special| special,
                else => unreachable,
            };

            // Check device ID for special files
            if (baseline_special.device_id != current_special.device_id) {
                const change = Change{
                    .change_type = .modified,
                    .path = try allocator.dupe(u8, path),
                    .old_record = try duplicateRecord(allocator, baseline),
                    .new_record = try duplicateRecord(allocator, current),
                    .details = try std.fmt.allocPrint(allocator, "Device ID changed from {} to {}", .{ baseline_special.device_id, current_special.device_id }),
                };
                try changes.append(change);
            }
        },
    }

    return changes.toOwnedSlice();
}

/// Create a duplicate of a record for storing in changes
fn duplicateRecord(allocator: std.mem.Allocator, record: *const records.Record) !records.Record {
    return switch (record.*) {
        .file => |file_record| records.Record{ .file = records.FileRecord{
            .path = try allocator.dupe(u8, file_record.path),
            .inode = file_record.inode,
            .dev = file_record.dev,
            .size = file_record.size,
            .mode = file_record.mode,
            .uid = file_record.uid,
            .gid = file_record.gid,
            .nlink = file_record.nlink,
            .mtime = file_record.mtime,
            .ctime = file_record.ctime,
            .checksum = file_record.checksum,
        } },
        .dir => |dir_record| records.Record{ .dir = records.DirRecord{
            .path = try allocator.dupe(u8, dir_record.path),
            .inode = dir_record.inode,
            .dev = dir_record.dev,
            .mode = dir_record.mode,
            .uid = dir_record.uid,
            .gid = dir_record.gid,
            .nlink = dir_record.nlink,
            .mtime = dir_record.mtime,
            .ctime = dir_record.ctime,
            .acl_hash = dir_record.acl_hash,
            .manifest = dir_record.manifest,
            .entry_count = dir_record.entry_count,
        } },
        .symlink => |symlink_record| records.Record{ .symlink = records.SymlinkRecord{
            .path = try allocator.dupe(u8, symlink_record.path),
            .inode = symlink_record.inode,
            .dev = symlink_record.dev,
            .mode = symlink_record.mode,
            .uid = symlink_record.uid,
            .gid = symlink_record.gid,
            .mtime = symlink_record.mtime,
            .ctime = symlink_record.ctime,
            .target = try allocator.dupe(u8, symlink_record.target),
            .target_hash = symlink_record.target_hash,
        } },
        .block, .char, .fifo, .socket => |special_record| {
            const new_special = records.SpecialRecord{
                .path = try allocator.dupe(u8, special_record.path),
                .inode = special_record.inode,
                .dev = special_record.dev,
                .mode = special_record.mode,
                .uid = special_record.uid,
                .gid = special_record.gid,
                .mtime = special_record.mtime,
                .ctime = special_record.ctime,
                .device_id = special_record.device_id,
            };

            return switch (record.*) {
                .block => records.Record{ .block = new_special },
                .char => records.Record{ .char = new_special },
                .fifo => records.Record{ .fifo = new_special },
                .socket => records.Record{ .socket = new_special },
                else => unreachable,
            };
        },
    };
}

const testing = std.testing;

test "CheckResult initialization and cleanup" {
    const allocator = testing.allocator;
    var result = CheckResult.init(allocator);
    defer result.deinit();

    try testing.expect(result.changes.items.len == 0);
    try testing.expect(!result.hasChanges());
    try testing.expectEqual(@as(u32, 0), result.total_files_checked);
}

test "Change detection basic functionality" {
    const allocator = testing.allocator;

    // Create a test change
    const change = Change{
        .change_type = .modified,
        .path = try allocator.dupe(u8, "/test/file.txt"),
        .old_record = null,
        .new_record = null,
        .details = try allocator.dupe(u8, "File content changed"),
    };

    var result = CheckResult.init(allocator);
    defer result.deinit();

    try result.addChange(change);

    try testing.expect(result.hasChanges());
    try testing.expectEqual(@as(usize, 1), result.changes.items.len);
    try testing.expectEqual(ChangeType.modified, result.changes.items[0].change_type);
    try testing.expectEqualStrings("/test/file.txt", result.changes.items[0].path);
}

test "duplicateRecord file record" {
    const allocator = testing.allocator;

    const original = records.Record{ .file = records.FileRecord{
        .path = try allocator.dupe(u8, "/test/original.txt"),
        .inode = 123,
        .dev = 456,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
        .checksum = [_]u8{0x01} ** 32,
    } };
    defer {
        var orig = original;
        orig.deinit(allocator);
    }

    const duplicate = try duplicateRecord(allocator, &original);
    defer {
        var dup = duplicate;
        dup.deinit(allocator);
    }

    try testing.expectEqualStrings(original.file.path, duplicate.file.path);
    try testing.expectEqual(original.file.size, duplicate.file.size);
    try testing.expectEqual(original.file.mode, duplicate.file.mode);
    try testing.expect(std.mem.eql(u8, &original.file.checksum, &duplicate.file.checksum));
}

test "compareRecords file with single change" {
    const allocator = testing.allocator;

    const baseline = records.Record{ .file = records.FileRecord{
        .path = try allocator.dupe(u8, "/test/file.txt"),
        .inode = 123,
        .dev = 456,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
        .checksum = [_]u8{0x01} ** 32,
    } };
    defer {
        var base = baseline;
        base.deinit(allocator);
    }

    const current = records.Record{
        .file = records.FileRecord{
            .path = try allocator.dupe(u8, "/test/file.txt"),
            .inode = 123,
            .dev = 456,
            .size = 2048, // Size changed
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .checksum = [_]u8{0x01} ** 32,
        },
    };
    defer {
        var curr = current;
        curr.deinit(allocator);
    }

    const changes = try compareRecords(allocator, &baseline, &current);
    defer {
        for (changes) |*change| {
            change.deinit(allocator);
        }
        allocator.free(changes);
    }

    try testing.expectEqual(@as(usize, 1), changes.len);
    try testing.expectEqual(ChangeType.modified, changes[0].change_type);
    try testing.expect(std.mem.indexOf(u8, changes[0].details, "Size changed from 1024 to 2048 bytes") != null);
}

test "compareRecords file with multiple changes consolidated" {
    const allocator = testing.allocator;

    const baseline = records.Record{ .file = records.FileRecord{
        .path = try allocator.dupe(u8, "/test/file.txt"),
        .inode = 123,
        .dev = 456,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
        .checksum = [_]u8{0x01} ** 32,
    } };
    defer {
        var base = baseline;
        base.deinit(allocator);
    }

    const current = records.Record{
        .file = records.FileRecord{
            .path = try allocator.dupe(u8, "/test/file.txt"),
            .inode = 123,
            .dev = 456,
            .size = 2048, // Size changed
            .mode = 0o755, // Permissions changed
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 1609459300, // Mtime changed
            .ctime = 1609459200,
            .checksum = [_]u8{0x02} ** 32, // Checksum changed
        },
    };
    defer {
        var curr = current;
        curr.deinit(allocator);
    }

    const changes = try compareRecords(allocator, &baseline, &current);
    defer {
        for (changes) |*change| {
            change.deinit(allocator);
        }
        allocator.free(changes);
    }

    // Should consolidate all changes into a single change record
    try testing.expectEqual(@as(usize, 1), changes.len);
    try testing.expectEqual(ChangeType.modified, changes[0].change_type);

    // Check that all change types are mentioned in the consolidated details
    try testing.expect(std.mem.indexOf(u8, changes[0].details, "Content changed") != null);
    try testing.expect(std.mem.indexOf(u8, changes[0].details, "Size changed from 1024 to 2048 bytes") != null);
    try testing.expect(std.mem.indexOf(u8, changes[0].details, "Permissions changed from 0o644 to 0o755") != null);
    try testing.expect(std.mem.indexOf(u8, changes[0].details, "Modification time changed") != null);

    // Check that details are properly joined with "; "
    try testing.expect(std.mem.indexOf(u8, changes[0].details, "; ") != null);
}

test "compareRecords file with no changes" {
    const allocator = testing.allocator;

    const baseline = records.Record{ .file = records.FileRecord{
        .path = try allocator.dupe(u8, "/test/file.txt"),
        .inode = 123,
        .dev = 456,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
        .checksum = [_]u8{0x01} ** 32,
    } };
    defer {
        var base = baseline;
        base.deinit(allocator);
    }

    const current = records.Record{ .file = records.FileRecord{
        .path = try allocator.dupe(u8, "/test/file.txt"),
        .inode = 123,
        .dev = 456,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
        .checksum = [_]u8{0x01} ** 32,
    } };
    defer {
        var curr = current;
        curr.deinit(allocator);
    }

    const changes = try compareRecords(allocator, &baseline, &current);
    defer allocator.free(changes);

    // Should return no changes when files are identical
    try testing.expectEqual(@as(usize, 0), changes.len);
}
