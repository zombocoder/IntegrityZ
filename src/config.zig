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

    /// Webhook URL for change notifications (optional)
    webhook_url: ?[]const u8,

    /// Whether webhook_url was allocated and should be freed
    webhook_url_owned: bool,

    /// Webhook timeout in seconds
    webhook_timeout: u32,

    /// Watch mode: minimum interval between integrity checks (seconds)
    watch_check_interval: u32,

    /// Watch mode: maximum events to batch before forcing integrity check
    watch_max_event_batch: u32,

    /// Watch mode: enable recursive monitoring
    watch_recursive: bool,

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
            .webhook_url = null,
            .webhook_url_owned = false,
            .webhook_timeout = 30,
            .watch_check_interval = 5,
            .watch_max_event_batch = 10,
            .watch_recursive = true,
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

        // Free webhook_url if it was allocated
        if (self.webhook_url_owned) {
            if (self.webhook_url) |url| {
                self.allocator.free(url);
            }
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
        } else if (std.mem.eql(u8, key, "webhook_url")) {
            if (self.webhook_url_owned) {
                if (self.webhook_url) |url| {
                    self.allocator.free(url);
                }
            }
            self.webhook_url = try self.allocator.dupe(u8, value);
            self.webhook_url_owned = true;
        } else if (std.mem.eql(u8, key, "webhook_timeout")) {
            self.webhook_timeout = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, key, "watch_check_interval")) {
            self.watch_check_interval = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, key, "watch_max_event_batch")) {
            self.watch_max_event_batch = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, key, "watch_recursive")) {
            self.watch_recursive = std.mem.eql(u8, value, "true");
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

        // Write webhook settings
        if (self.webhook_url) |url| {
            try writer.print("webhook_url={s}\n", .{url});
        }
        try writer.print("webhook_timeout={}\n", .{self.webhook_timeout});

        // Write watch mode settings
        try writer.print("watch_check_interval={}\n", .{self.watch_check_interval});
        try writer.print("watch_max_event_batch={}\n", .{self.watch_max_event_batch});
        try writer.print("watch_recursive={}\n", .{self.watch_recursive});

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

    // Test new webhook and watch mode defaults
    try testing.expect(config.webhook_url == null);
    try testing.expect(config.webhook_url_owned == false);
    try testing.expect(config.webhook_timeout == 30);
    try testing.expect(config.watch_check_interval == 5);
    try testing.expect(config.watch_max_event_batch == 10);
    try testing.expect(config.watch_recursive == true);
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

test "webhook and watch mode config parsing" {
    var config = Config.init(testing.allocator);
    defer config.deinit();

    const test_config =
        \\# Webhook and watch mode config
        \\webhook_url=https://example.com/webhook
        \\webhook_timeout=45
        \\watch_check_interval=10
        \\watch_max_event_batch=25
        \\watch_recursive=false
    ;

    try config.parseConfigContent(test_config);

    try testing.expect(config.webhook_url != null);
    try testing.expectEqualStrings("https://example.com/webhook", config.webhook_url.?);
    try testing.expect(config.webhook_url_owned == true);
    try testing.expect(config.webhook_timeout == 45);
    try testing.expect(config.watch_check_interval == 10);
    try testing.expect(config.watch_max_event_batch == 25);
    try testing.expect(config.watch_recursive == false);
}

test "webhook url memory management" {
    var config = Config.init(testing.allocator);
    defer config.deinit();

    // Test setting webhook URL multiple times
    const test_config1 =
        \\webhook_url=https://first.com/webhook
    ;

    const test_config2 =
        \\webhook_url=https://second.com/webhook
    ;

    try config.parseConfigContent(test_config1);
    try testing.expectEqualStrings("https://first.com/webhook", config.webhook_url.?);

    // Parse second config - should free the first URL
    try config.parseConfigContent(test_config2);
    try testing.expectEqualStrings("https://second.com/webhook", config.webhook_url.?);
    try testing.expect(config.webhook_url_owned == true);
}

test "config save includes new settings" {
    var config = Config.init(testing.allocator);
    defer config.deinit();

    // Set some webhook and watch mode values
    config.webhook_url = "https://test.com/hook";
    config.webhook_timeout = 60;
    config.watch_check_interval = 15;
    config.watch_max_event_batch = 50;
    config.watch_recursive = false;

    // Test that saveToFile includes the new settings
    const temp_file = "/tmp/test_config_save.conf";
    try config.saveToFile(temp_file);

    // Read the file back and verify content
    const file = std.fs.cwd().openFile(temp_file, .{}) catch |err| {
        std.debug.print("Failed to open test config file: {}\n", .{err});
        return err;
    };
    defer file.close();
    defer std.fs.cwd().deleteFile(temp_file) catch {};

    var buffer: [2048]u8 = undefined;
    const bytes_read = try file.readAll(&buffer);
    const output = buffer[0..bytes_read];

    // Check that new settings appear in output
    try testing.expect(std.mem.indexOf(u8, output, "webhook_url=https://test.com/hook") != null);
    try testing.expect(std.mem.indexOf(u8, output, "webhook_timeout=60") != null);
    try testing.expect(std.mem.indexOf(u8, output, "watch_check_interval=15") != null);
    try testing.expect(std.mem.indexOf(u8, output, "watch_max_event_batch=50") != null);
    try testing.expect(std.mem.indexOf(u8, output, "watch_recursive=false") != null);
}
