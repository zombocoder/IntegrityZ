// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const constants = @import("constants.zig");

/// Configuration structure for IntegrityZ
pub const Config = struct {
    /// Default baseline file location
    baseline_path: []const u8,

    /// Whether baseline_path was allocated and should be freed
    baseline_path_owned: bool,

    /// Patterns to include in scans (glob patterns)
    include_patterns: std.ArrayList([]const u8),

    /// Patterns to exclude from scans (glob patterns)
    exclude_patterns: std.ArrayList([]const u8),

    /// Maximum file size to scan (in bytes, 0 = no limit)
    max_file_size: u64,

    /// Follow symbolic links during scanning
    follow_symlinks: bool,

    /// Default paths to scan if none specified
    default_scan_paths: std.ArrayList([]const u8),

    /// Allocator used for dynamic allocations
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize configuration with default values
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .baseline_path = constants.DEFAULT_BASELINE_FILENAME,
            .baseline_path_owned = false,
            .include_patterns = std.ArrayList([]const u8).init(allocator),
            .exclude_patterns = std.ArrayList([]const u8).init(allocator),
            .max_file_size = 0, // No limit by default
            .follow_symlinks = false,
            .default_scan_paths = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Free all allocated memory
    pub fn deinit(self: *Self) void {
        // Free string arrays
        for (self.include_patterns.items) |pattern| {
            self.allocator.free(pattern);
        }
        self.include_patterns.deinit();

        for (self.exclude_patterns.items) |pattern| {
            self.allocator.free(pattern);
        }
        self.exclude_patterns.deinit();

        for (self.default_scan_paths.items) |path| {
            self.allocator.free(path);
        }
        self.default_scan_paths.deinit();

        // Free baseline_path if it was allocated
        if (self.baseline_path_owned) {
            self.allocator.free(self.baseline_path);
        }
    }

    /// Load configuration from file
    pub fn loadFromFile(allocator: std.mem.Allocator, config_path: []const u8) !Self {
        var config = Self.init(allocator);
        errdefer config.deinit();

        const file_content = std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => {
                // Config file doesn't exist, use defaults
                try config.addDefaultExclusions();
                return config;
            },
            else => return err,
        };
        defer allocator.free(file_content);

        try config.parseConfigContent(file_content);
        return config;
    }

    /// Parse configuration content from string
    fn parseConfigContent(self: *Self, content: []const u8) !void {
        var lines = std.mem.split(u8, content, "\n");

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");

            // Skip empty lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            // Parse key=value pairs
            if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                try self.setConfigValue(key, value);
            }
        }

        // Add default exclusions if none were specified
        if (self.exclude_patterns.items.len == 0) {
            try self.addDefaultExclusions();
        }
    }

    /// Set a configuration value from key-value pair
    fn setConfigValue(self: *Self, key: []const u8, value: []const u8) !void {
        if (std.mem.eql(u8, key, "baseline_path")) {
            if (self.baseline_path_owned) {
                self.allocator.free(self.baseline_path);
            }
            self.baseline_path = try self.allocator.dupe(u8, value);
            self.baseline_path_owned = true;
        } else if (std.mem.eql(u8, key, "include")) {
            try self.include_patterns.append(try self.allocator.dupe(u8, value));
        } else if (std.mem.eql(u8, key, "exclude")) {
            try self.exclude_patterns.append(try self.allocator.dupe(u8, value));
        } else if (std.mem.eql(u8, key, "max_file_size")) {
            self.max_file_size = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, key, "follow_symlinks")) {
            self.follow_symlinks = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, key, "default_scan_path")) {
            try self.default_scan_paths.append(try self.allocator.dupe(u8, value));
        }
        // Ignore unknown keys for forward compatibility
    }

    /// Add sensible default exclusions
    fn addDefaultExclusions(self: *Self) !void {
        const default_exclusions = [_][]const u8{
            "*.tmp",
            "*.swp",
            "*.log",
            ".git/*",
            ".svn/*",
            ".hg/*",
            "node_modules/*",
            ".DS_Store",
            "Thumbs.db",
            "*.pyc",
            "__pycache__/*",
            ".zig-cache/*",
            "zig-out/*",
            ".vscode/*",
            ".idea/*",
        };

        for (default_exclusions) |pattern| {
            try self.exclude_patterns.append(try self.allocator.dupe(u8, pattern));
        }
    }

    /// Check if a file path should be excluded based on patterns
    pub fn shouldExclude(self: *const Self, file_path: []const u8) bool {
        for (self.exclude_patterns.items) |pattern| {
            if (self.matchesPattern(file_path, pattern)) {
                return true;
            }
        }
        return false;
    }

    /// Check if a file path should be included based on patterns
    pub fn shouldInclude(self: *const Self, file_path: []const u8) bool {
        // If no include patterns specified, include everything (subject to exclusions)
        if (self.include_patterns.items.len == 0) {
            return true;
        }

        for (self.include_patterns.items) |pattern| {
            if (self.matchesPattern(file_path, pattern)) {
                return true;
            }
        }
        return false;
    }

    /// Simple glob pattern matching (supports * and ?)
    fn matchesPattern(self: *const Self, path: []const u8, pattern: []const u8) bool {
        _ = self; // Suppress unused parameter warning

        // For now, implement simple wildcard matching
        // This is a simplified version - could be enhanced with full glob support

        // Handle directory patterns ending with /*
        if (std.mem.endsWith(u8, pattern, "/*")) {
            const dir_pattern = pattern[0 .. pattern.len - 2];
            return std.mem.startsWith(u8, path, dir_pattern);
        }

        // Handle simple * wildcards
        if (std.mem.indexOf(u8, pattern, "*")) |star_pos| {
            const prefix = pattern[0..star_pos];
            const suffix = pattern[star_pos + 1 ..];

            return std.mem.startsWith(u8, path, prefix) and std.mem.endsWith(u8, path, suffix);
        }

        // Exact match
        return std.mem.eql(u8, path, pattern);
    }

    /// Save configuration to file
    pub fn saveToFile(self: *const Self, config_path: []const u8) !void {
        const file = try std.fs.cwd().createFile(config_path, .{});
        defer file.close();

        const writer = file.writer();

        // Write header
        try writer.writeAll("# IntegrityZ Configuration File\n");
        try writer.writeAll("# Lines starting with # are comments\n\n");

        // Write baseline path
        try writer.print("baseline_path={s}\n\n", .{self.baseline_path});

        // Write include patterns
        if (self.include_patterns.items.len > 0) {
            try writer.writeAll("# Include patterns (glob style)\n");
            for (self.include_patterns.items) |pattern| {
                try writer.print("include={s}\n", .{pattern});
            }
            try writer.writeAll("\n");
        }

        // Write exclude patterns
        if (self.exclude_patterns.items.len > 0) {
            try writer.writeAll("# Exclude patterns (glob style)\n");
            for (self.exclude_patterns.items) |pattern| {
                try writer.print("exclude={s}\n", .{pattern});
            }
            try writer.writeAll("\n");
        }

        // Write other settings
        try writer.print("max_file_size={}\n", .{self.max_file_size});
        try writer.print("follow_symlinks={}\n", .{self.follow_symlinks});

        // Write default scan paths
        if (self.default_scan_paths.items.len > 0) {
            try writer.writeAll("\n# Default paths to scan if none specified\n");
            for (self.default_scan_paths.items) |path| {
                try writer.print("default_scan_path={s}\n", .{path});
            }
        }
    }
};

/// Default configuration file name
pub const DEFAULT_CONFIG_FILENAME = "integrityz.conf";

/// Load configuration from default location or create default config
pub fn loadConfig(allocator: std.mem.Allocator) !Config {
    return Config.loadFromFile(allocator, DEFAULT_CONFIG_FILENAME);
}

const testing = std.testing;

test "config initialization" {
    var config = Config.init(testing.allocator);
    defer config.deinit();

    try testing.expect(std.mem.eql(u8, config.baseline_path, constants.DEFAULT_BASELINE_FILENAME));
    try testing.expect(config.include_patterns.items.len == 0);
    try testing.expect(config.max_file_size == 0);
    try testing.expect(config.follow_symlinks == false);
}

test "pattern matching" {
    var config = Config.init(testing.allocator);
    defer config.deinit();

    try config.exclude_patterns.append(try testing.allocator.dupe(u8, "*.tmp"));
    try config.exclude_patterns.append(try testing.allocator.dupe(u8, ".git/*"));

    try testing.expect(config.shouldExclude("test.tmp"));
    try testing.expect(config.shouldExclude(".git/config"));
    try testing.expect(!config.shouldExclude("test.txt"));
}

test "config file parsing" {
    var config = Config.init(testing.allocator);
    defer config.deinit();

    const test_config =
        \\# Test config
        \\baseline_path=custom.db
        \\exclude=*.log
        \\exclude=temp/*
        \\max_file_size=1000000
        \\follow_symlinks=true
    ;

    try config.parseConfigContent(test_config);

    try testing.expectEqualStrings("custom.db", config.baseline_path);
    try testing.expect(config.exclude_patterns.items.len >= 2); // Including defaults
    try testing.expect(config.max_file_size == 1000000);
    try testing.expect(config.follow_symlinks == true);
}
