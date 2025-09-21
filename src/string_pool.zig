// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// String interning pool to reduce memory allocations for repeated strings
/// Particularly useful for filesystem paths that share common prefixes
pub const StringPool = struct {
    strings: std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    total_saved: usize, // Statistics: total bytes saved through interning
    intern_count: usize, // Statistics: number of successful interns

    const Self = @This();

    /// Initialize a new string pool
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .strings = std.HashMap([]const u8, []const u8, std.hash_map.StringContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
            .total_saved = 0,
            .intern_count = 0,
        };
    }

    /// Clean up the string pool and free all interned strings
    pub fn deinit(self: *Self) void {
        // Free all interned strings
        var iterator = self.strings.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.strings.deinit();
    }

    /// Intern a string - returns existing copy if already interned, or creates new copy
    /// The returned string is owned by the pool and should not be freed by the caller
    pub fn intern(self: *Self, str: []const u8) ![]const u8 {
        // Check if string is already interned
        if (self.strings.get(str)) |interned| {
            self.total_saved += str.len;
            self.intern_count += 1;
            return interned;
        }

        // Create new copy and intern it
        const owned = try self.allocator.dupe(u8, str);
        try self.strings.put(owned, owned);
        return owned;
    }

    /// Get statistics about memory savings from interning
    pub fn getStats(self: *Self) StringPoolStats {
        return StringPoolStats{
            .interned_strings = self.strings.count(),
            .total_bytes_saved = self.total_saved,
            .intern_hits = self.intern_count,
        };
    }

    /// Clear all interned strings (useful for memory pressure situations)
    pub fn clear(self: *Self) void {
        var iterator = self.strings.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.strings.clearAndFree();
        self.total_saved = 0;
        self.intern_count = 0;
    }
};

/// Statistics for string pool usage
pub const StringPoolStats = struct {
    interned_strings: u32,
    total_bytes_saved: usize,
    intern_hits: usize,
};

/// Path-optimized string pool that takes advantage of filesystem path structure
/// Provides additional optimizations for common path operations
pub const PathPool = struct {
    string_pool: StringPool,
    common_prefixes: std.ArrayList([]const u8), // Track common path prefixes

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .string_pool = StringPool.init(allocator),
            .common_prefixes = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.common_prefixes.deinit();
        self.string_pool.deinit();
    }

    /// Intern a filesystem path with prefix optimization
    pub fn internPath(self: *Self, path: []const u8) ![]const u8 {
        // Check for common prefixes and potentially intern just the suffix
        for (self.common_prefixes.items) |prefix| {
            if (std.mem.startsWith(u8, path, prefix)) {
                // For now, just intern the whole path
                // This could be optimized further to store prefix + suffix separately
                return self.string_pool.intern(path);
            }
        }

        // Intern the full path and potentially add to common prefixes
        const interned = try self.string_pool.intern(path);

        // Add directory prefixes to common prefixes list
        if (std.fs.path.dirname(path)) |dirname| {
            if (dirname.len > 10) { // Only track reasonably long prefixes
                // Check if this prefix should be added
                var should_add = true;
                for (self.common_prefixes.items) |existing| {
                    if (std.mem.eql(u8, existing, dirname)) {
                        should_add = false;
                        break;
                    }
                }

                if (should_add and self.common_prefixes.items.len < 100) { // Limit prefix list size
                    const prefix_copy = try self.string_pool.intern(dirname);
                    try self.common_prefixes.append(prefix_copy);
                }
            }
        }

        return interned;
    }

    /// Get combined statistics
    pub fn getStats(self: *Self) PathPoolStats {
        const base_stats = self.string_pool.getStats();
        return PathPoolStats{
            .base_stats = base_stats,
            .common_prefixes_count = self.common_prefixes.items.len,
        };
    }
};

/// Statistics for path pool usage
pub const PathPoolStats = struct {
    base_stats: StringPoolStats,
    common_prefixes_count: usize,
};

// Unit tests
test "StringPool basic functionality" {
    const allocator = std.testing.allocator;

    var pool = StringPool.init(allocator);
    defer pool.deinit();

    // Test interning new strings
    const str1 = try pool.intern("hello");
    const str2 = try pool.intern("world");
    const str3 = try pool.intern("hello"); // Duplicate

    // str1 and str3 should be the same pointer (interned)
    try std.testing.expect(str1.ptr == str3.ptr);
    try std.testing.expect(str1.ptr != str2.ptr);

    // Test content is correct
    try std.testing.expectEqualStrings("hello", str1);
    try std.testing.expectEqualStrings("hello", str3);
    try std.testing.expectEqualStrings("world", str2);
}

test "StringPool statistics" {
    const allocator = std.testing.allocator;

    var pool = StringPool.init(allocator);
    defer pool.deinit();

    _ = try pool.intern("test");
    _ = try pool.intern("test"); // Should hit the intern
    _ = try pool.intern("other");

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u32, 2), stats.interned_strings); // "test" and "other"
    try std.testing.expectEqual(@as(usize, 1), stats.intern_hits); // One hit for duplicate "test"
    try std.testing.expectEqual(@as(usize, 4), stats.total_bytes_saved); // 4 bytes saved from "test"
}

test "PathPool basic functionality" {
    const allocator = std.testing.allocator;

    var pool = PathPool.init(allocator);
    defer pool.deinit();

    // Test path interning
    const path1 = try pool.internPath("/home/user/documents/file1.txt");
    _ = try pool.internPath("/home/user/documents/file2.txt");
    const path3 = try pool.internPath("/home/user/documents/file1.txt"); // Duplicate

    // path1 and path3 should be the same (interned)
    try std.testing.expect(path1.ptr == path3.ptr);
    try std.testing.expectEqualStrings("/home/user/documents/file1.txt", path1);

    const stats = pool.getStats();
    try std.testing.expect(stats.base_stats.interned_strings >= 2);
}

test "StringPool memory management" {
    const allocator = std.testing.allocator;

    var pool = StringPool.init(allocator);
    defer pool.deinit();

    // Intern many strings to test memory management
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var buffer: [32]u8 = undefined;
        const str = try std.fmt.bufPrint(&buffer, "string_{}", .{i});
        _ = try pool.intern(str);
    }

    // Test clearing the pool
    const stats_before = pool.getStats();
    try std.testing.expect(stats_before.interned_strings > 0);

    pool.clear();

    const stats_after = pool.getStats();
    try std.testing.expectEqual(@as(u32, 0), stats_after.interned_strings);
}

test "StringPool handles empty strings" {
    const allocator = std.testing.allocator;

    var pool = StringPool.init(allocator);
    defer pool.deinit();

    const empty1 = try pool.intern("");
    const empty2 = try pool.intern("");

    // Empty strings should be interned
    try std.testing.expect(empty1.ptr == empty2.ptr);
    try std.testing.expectEqualStrings("", empty1);

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u32, 1), stats.interned_strings);
    try std.testing.expectEqual(@as(usize, 1), stats.intern_hits);
}

test "StringPool handles very long strings" {
    const allocator = std.testing.allocator;

    var pool = StringPool.init(allocator);
    defer pool.deinit();

    // Create a very long string
    const long_string = "a" ** 10000;

    const str1 = try pool.intern(long_string);
    const str2 = try pool.intern(long_string);

    try std.testing.expect(str1.ptr == str2.ptr);
    try std.testing.expectEqual(@as(usize, 10000), str1.len);

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(usize, 10000), stats.total_bytes_saved);
}

test "PathPool common prefix optimization" {
    const allocator = std.testing.allocator;

    var pool = PathPool.init(allocator);
    defer pool.deinit();

    // Test paths with common prefixes
    const paths = [_][]const u8{
        "/home/user/documents/file1.txt",
        "/home/user/documents/file2.txt",
        "/home/user/documents/subdir/file3.txt",
        "/home/user/pictures/photo1.jpg",
        "/home/user/pictures/photo2.jpg",
    };

    var interned_paths: [paths.len][]const u8 = undefined;

    for (paths, 0..) |path, i| {
        interned_paths[i] = try pool.internPath(path);
    }

    // Verify all paths were interned correctly
    for (paths, interned_paths) |original, interned| {
        try std.testing.expectEqualStrings(original, interned);
    }

    const stats = pool.getStats();

    // Should have tracked some common prefixes
    try std.testing.expect(stats.common_prefixes_count > 0);
    try std.testing.expect(stats.base_stats.interned_strings >= paths.len);
}

test "PathPool handles relative and absolute paths" {
    const allocator = std.testing.allocator;

    var pool = PathPool.init(allocator);
    defer pool.deinit();

    const paths = [_][]const u8{
        "/absolute/path/file.txt",
        "relative/path/file.txt",
        "./current/file.txt",
        "../parent/file.txt",
        "file.txt",
    };

    for (paths) |path| {
        const interned = try pool.internPath(path);
        try std.testing.expectEqualStrings(path, interned);
    }

    const stats = pool.getStats();
    // PathPool may intern additional prefix strings, so check for at least the expected count
    try std.testing.expect(stats.base_stats.interned_strings >= paths.len);
}

test "StringPool performance with many duplicates" {
    const allocator = std.testing.allocator;

    var pool = StringPool.init(allocator);
    defer pool.deinit();

    const base_strings = [_][]const u8{
        "common_string_1",
        "common_string_2",
        "common_string_3",
    };

    // Intern each string many times
    var total_interns: usize = 0;
    for (base_strings) |str| {
        var i: usize = 0;
        while (i < 1000) : (i += 1) {
            _ = try pool.intern(str);
            total_interns += 1;
        }
    }

    const stats = pool.getStats();

    // Should only have 3 unique strings
    try std.testing.expectEqual(@as(u32, 3), stats.interned_strings);

    // Should have many hits
    try std.testing.expectEqual(total_interns - 3, stats.intern_hits);

    // Should have saved significant memory
    var expected_saved: usize = 0;
    for (base_strings) |str| {
        expected_saved += str.len * 999; // 999 duplicates per string
    }
    try std.testing.expectEqual(expected_saved, stats.total_bytes_saved);
}

test "PathPool prefix limit enforcement" {
    const allocator = std.testing.allocator;

    var pool = PathPool.init(allocator);
    defer pool.deinit();

    // Try to add more than 100 different prefixes (the limit)
    var i: usize = 0;
    while (i < 150) : (i += 1) {
        var path_buffer: [256]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "/unique/prefix/{}/file.txt", .{i});
        _ = try pool.internPath(path);
    }

    const stats = pool.getStats();

    // Should not exceed the prefix limit
    try std.testing.expect(stats.common_prefixes_count <= 100);
}
