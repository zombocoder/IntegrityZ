// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const scanner = @import("scanner.zig");
const database = @import("database.zig");

// Re-export BaselineDB from database module for backward compatibility
pub const BaselineDB = database.BaselineDB;

/// Create a new baseline by scanning the specified filesystem paths
/// Performs recursive directory traversal and collects integrity metadata
/// Returns populated BaselineDB ready for serialization or comparison
pub fn createBaseline(allocator: std.mem.Allocator, paths: [][]const u8) !BaselineDB {
    var baseline = BaselineDB.init(allocator);

    for (paths) |path| {
        // Convert relative paths to absolute before processing
        const absolute_path = if (std.fs.path.isAbsolute(path))
            try allocator.dupe(u8, path)
        else
            try std.fs.cwd().realpathAlloc(allocator, path);
        defer allocator.free(absolute_path);

        try scanner.scanPath(allocator, &baseline, absolute_path);
    }

    return baseline;
}

const testing = std.testing;

test "createBaseline basic functionality" {
    const allocator = testing.allocator;

    // Create a temporary directory structure for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "test.txt", .data = "test content" });
    try tmp.dir.makeDir("subdir");
    try tmp.dir.writeFile(.{ .sub_path = "subdir/nested.txt", .data = "nested content" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    var paths = [_][]const u8{tmp_path};
    var baseline = try createBaseline(allocator, &paths);
    defer baseline.deinit();

    // Should have created records for the directory and its contents
    try testing.expect(baseline.records.items.len > 0);
}
