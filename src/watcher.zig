// SPDX-License-Identifier: Apache-2.0

//! Filesystem watcher module for real-time monitoring
//!
//! This module provides cross-platform filesystem event monitoring using:
//! - inotify on Linux
//! - kqueue on macOS/BSD
//! - Polling fallback for unsupported platforms
//!
//! Features:
//! - Real-time filesystem change detection
//! - Integrity checking on detected changes
//! - HTTP webhook notifications
//! - Configurable monitoring options

const std = @import("std");
const builtin = @import("builtin");
const print = std.debug.print;
const checker = @import("checker.zig");
const config = @import("config.zig");
const reporter = @import("reporter.zig");

/// Filesystem event types
pub const EventType = enum {
    created,
    modified,
    deleted,
    moved,
    permission_changed,
};

/// Filesystem event structure
pub const Event = struct {
    path: []const u8,
    event_type: EventType,
    timestamp: i64,
};

/// Watch configuration options
pub const WatchConfig = struct {
    /// Paths to monitor
    watch_paths: []const []const u8,
    /// Enable recursive monitoring
    recursive: bool = true,
    /// Webhook URL for notifications (optional)
    webhook_url: ?[]const u8 = null,
    /// Webhook timeout in seconds
    webhook_timeout: u32 = 30,
    /// Minimum interval between integrity checks (seconds)
    check_interval: u32 = 5,
    /// Maximum events to batch before forcing integrity check
    max_event_batch: u32 = 100,
};

/// Cross-platform filesystem watcher
pub const Watcher = struct {
    allocator: std.mem.Allocator,
    config: *const config.Config,
    watch_config: WatchConfig,
    baseline_path: []const u8,
    event_queue: std.ArrayList(Event),
    last_check_time: i64,
    should_stop: bool,
    reported_changes: std.StringHashMap(i64), // Track reported changes with timestamp

    // Platform-specific handles
    platform_data: union(enum) {
        linux: LinuxWatcher,
        darwin: DarwinWatcher,
        fallback: FallbackWatcher,
    },

    const Self = @This();

    /// Initialize a new filesystem watcher
    pub fn init(
        allocator: std.mem.Allocator,
        app_config: *const config.Config,
        watch_config: WatchConfig,
    ) !Self {
        const watcher = Self{
            .allocator = allocator,
            .config = app_config,
            .watch_config = watch_config,
            .baseline_path = app_config.baseline_path,
            .event_queue = std.ArrayList(Event).init(allocator),
            .last_check_time = std.time.timestamp(),
            .should_stop = false,
            .reported_changes = std.StringHashMap(i64).init(allocator),
            .platform_data = undefined,
        };

        return watcher;
    }

    /// Initialize platform-specific watcher after Watcher is in final memory location
    pub fn initPlatform(self: *Self) !void {
        // Initialize platform-specific watcher
        switch (builtin.os.tag) {
            .linux => {
                if (@import("builtin").mode == .Debug) {
                    print("[DEBUG] Using Linux inotify watcher\n", .{});
                }
                self.platform_data = .{ .linux = try LinuxWatcher.init(self.allocator, self) };
            },
            .macos, .freebsd, .netbsd, .openbsd => {
                if (@import("builtin").mode == .Debug) {
                    print("[DEBUG] Using Darwin kqueue watcher\n", .{});
                }
                self.platform_data = .{ .darwin = try DarwinWatcher.init(self.allocator, self) };
            },
            else => {
                if (@import("builtin").mode == .Debug) {
                    print("[DEBUG] Using fallback polling watcher\n", .{});
                }
                self.platform_data = .{ .fallback = try FallbackWatcher.init(self.allocator, self) };
            },
        }
    }

    /// Clean up watcher resources
    pub fn deinit(self: *Self) void {
        switch (self.platform_data) {
            .linux => |*linux_watcher| linux_watcher.deinit(),
            .darwin => |*darwin_watcher| darwin_watcher.deinit(),
            .fallback => |*fallback_watcher| fallback_watcher.deinit(),
        }

        // Free event queue
        for (self.event_queue.items) |event| {
            self.allocator.free(event.path);
        }
        self.event_queue.deinit();

        // Free reported changes map
        var iterator = self.reported_changes.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.reported_changes.deinit();
    }

    /// Start watching for filesystem events
    pub fn watch(self: *Self) !void {
        print("Starting filesystem monitoring...\n", .{});
        print("Watching {} path(s) for changes\n", .{self.watch_config.watch_paths.len});

        if (self.watch_config.webhook_url) |url| {
            print("Webhook notifications enabled: {s}\n", .{url});
        }

        // Add all watch paths
        for (self.watch_config.watch_paths) |path| {
            try self.addWatchPath(path);
            print("✓ Monitoring: {s}\n", .{path});
        }

        // Main event loop
        while (!self.should_stop) {
            if (@import("builtin").mode == .Debug) {
                print("[DEBUG] Loop iteration start: queue has {} events\n", .{self.event_queue.items.len});
            }

            // Process platform-specific events
            try self.processEvents();

            if (@import("builtin").mode == .Debug and self.event_queue.items.len > 0) {
                print("[DEBUG] After processEvents: queue has {} events\n", .{self.event_queue.items.len});
            }

            // Check if we should perform integrity check
            const now = std.time.timestamp();
            const time_since_check = now - self.last_check_time;
            const has_enough_events = self.event_queue.items.len >= self.watch_config.max_event_batch;
            const enough_time_passed = time_since_check >= self.watch_config.check_interval;

            if (@import("builtin").mode == .Debug and self.event_queue.items.len > 0) {
                print("[DEBUG] Loop: queue has {} events, time_since_check: {}, enough_time_passed: {}, has_enough_events: {}\n", .{ self.event_queue.items.len, time_since_check, enough_time_passed, has_enough_events });
            }

            // Only trigger integrity checks when there are filesystem events
            // This prevents continuous re-detection of the same persistent changes
            if (self.event_queue.items.len > 0 and (has_enough_events or enough_time_passed)) {
                if (@import("builtin").mode == .Debug) {
                    print("[DEBUG] Triggering integrity check: {} events, {} seconds elapsed\n", .{ self.event_queue.items.len, time_since_check });
                }
                try self.performIntegrityCheck();
            } else if (enough_time_passed and self.event_queue.items.len == 0) {
                if (@import("builtin").mode == .Debug) {
                    print("[DEBUG] Time elapsed but no events in queue\n", .{});
                }
                // Update timestamp to prevent continuous logging when no events
                self.last_check_time = std.time.timestamp();
            }

            // Small sleep to prevent busy waiting
            std.time.sleep(100 * std.time.ns_per_ms);
        }

        print("Filesystem monitoring stopped\n", .{});
    }

    /// Stop the watcher
    pub fn stop(self: *Self) void {
        self.should_stop = true;
    }

    /// Add a path to watch
    fn addWatchPath(self: *Self, path: []const u8) !void {
        switch (self.platform_data) {
            .linux => |*linux_watcher| try linux_watcher.addWatch(path),
            .darwin => |*darwin_watcher| try darwin_watcher.addWatch(path),
            .fallback => |*fallback_watcher| try fallback_watcher.addWatch(path),
        }
    }

    /// Process filesystem events
    fn processEvents(self: *Self) !void {
        switch (self.platform_data) {
            .linux => |*linux_watcher| try linux_watcher.processEvents(),
            .darwin => |*darwin_watcher| try darwin_watcher.processEvents(),
            .fallback => |*fallback_watcher| try fallback_watcher.processEvents(),
        }
    }

    /// Add an event to the queue
    pub fn addEvent(self: *Self, path: []const u8, event_type: EventType) !void {
        const event = Event{
            .path = try self.allocator.dupe(u8, path),
            .event_type = event_type,
            .timestamp = std.time.timestamp(),
        };

        try self.event_queue.append(event);

        if (@import("builtin").mode == .Debug) {
            print("[DEBUG] Event: {s} - {s} (queue size: {})\n", .{ @tagName(event_type), path, self.event_queue.items.len });
        }
    }

    /// Perform integrity check and send notifications
    fn performIntegrityCheck(self: *Self) !void {
        print("Performing integrity check ({} events pending)...\n", .{self.event_queue.items.len});

        // Use the full watch paths for integrity check, not just event paths
        // This ensures we get a complete picture of the current filesystem state
        var result = checker.checkIntegrity(
            self.allocator,
            self.baseline_path,
            @constCast(self.watch_config.watch_paths),
        ) catch |err| {
            print("Error during integrity check: {}\n", .{err});
            return;
        };
        defer result.deinit();

        // Send webhook notification only for new changes
        if (result.hasChanges() and self.watch_config.webhook_url != null) {
            const has_new_changes = try self.hasNewChanges(&result);
            if (has_new_changes) {
                try self.sendWebhookNotification(&result);
                try self.markChangesAsReported(&result);
            } else {
                print("No new changes detected - skipping webhook notification\n", .{});
            }
        }

        // Report results
        if (result.hasChanges()) {
            reporter.reportCheckResults(&result);
        } else {
            print("✓ No integrity violations found\n", .{});
        }

        // Clear event queue and update timestamp
        if (@import("builtin").mode == .Debug) {
            print("[DEBUG] Clearing event queue with {} items\n", .{self.event_queue.items.len});
        }
        for (self.event_queue.items) |event| {
            self.allocator.free(event.path);
        }
        self.event_queue.clearRetainingCapacity();
        self.last_check_time = std.time.timestamp();
    }

    /// Send HTTP webhook notification
    fn sendWebhookNotification(self: *Self, result: *const checker.CheckResult) !void {
        const webhook_url = self.watch_config.webhook_url orelse return;

        print("Sending webhook notification to: {s}\n", .{webhook_url});

        // Generate JSON payload
        const json_report = try reporter.generateJsonReport(self.allocator, result);
        defer self.allocator.free(json_report);

        // Create HTTP client
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Parse URL
        const uri = try std.Uri.parse(webhook_url);

        // Create request with proper header buffer
        var header_buffer: [4096]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &header_buffer,
            .headers = .{
                .content_type = .{ .override = "application/json" },
            },
        });
        defer req.deinit();

        // Send request with body
        req.transfer_encoding = .{ .content_length = json_report.len };
        try req.send();
        try req.writeAll(json_report);
        try req.finish();
        try req.wait();

        if (req.response.status == .ok) {
            print("✓ Webhook notification sent successfully\n", .{});
        } else {
            print("⚠ Webhook notification failed with status: {}\n", .{req.response.status});
        }
    }

    /// Check if there are any new changes that haven't been reported
    fn hasNewChanges(self: *Self, result: *const checker.CheckResult) !bool {
        for (result.changes.items) |change| {
            // Create a unique key for this change (path + change type + details hash)
            const change_key = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ change.path, change.details });
            defer self.allocator.free(change_key);

            if (!self.reported_changes.contains(change_key)) {
                return true; // Found a new change
            }
        }
        return false; // All changes have been reported before
    }

    /// Mark all changes in the result as reported
    fn markChangesAsReported(self: *Self, result: *const checker.CheckResult) !void {
        const now = std.time.timestamp();
        for (result.changes.items) |change| {
            const change_key = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ change.path, change.details });
            try self.reported_changes.put(try self.allocator.dupe(u8, change_key), now);
            self.allocator.free(change_key);
        }
    }
};

/// Linux-specific watcher using inotify
const LinuxWatcher = struct {
    watcher: *Watcher,
    inotify_fd: i32,
    watch_descriptors: std.AutoHashMap(i32, []const u8),
    buffer: [4096]u8,

    const Self = @This();

    fn init(allocator: std.mem.Allocator, watcher: *Watcher) !Self {
        _ = allocator;
        const inotify_fd = try std.posix.inotify_init1(std.os.linux.IN.CLOEXEC);

        return Self{
            .watcher = watcher,
            .inotify_fd = inotify_fd,
            .watch_descriptors = std.AutoHashMap(i32, []const u8).init(watcher.allocator),
            .buffer = undefined,
        };
    }

    fn deinit(self: *Self) void {
        self.watch_descriptors.deinit();
        std.posix.close(self.inotify_fd);
    }

    fn addWatch(self: *Self, path: []const u8) !void {
        const mask = std.os.linux.IN.CREATE | std.os.linux.IN.MODIFY |
            std.os.linux.IN.DELETE | std.os.linux.IN.MOVE |
            std.os.linux.IN.ATTRIB;

        const path_cstr = try std.posix.toPosixPath(path);
        const wd = std.os.linux.inotify_add_watch(self.inotify_fd, &path_cstr, mask);
        if (wd == std.math.maxInt(usize)) {
            return error.AccessDenied; // Simplified error handling
        }
        try self.watch_descriptors.put(@intCast(wd), try self.watcher.allocator.dupe(u8, path));
    }

    fn processEvents(self: *Self) !void {
        const bytes_read = std.posix.read(self.inotify_fd, &self.buffer) catch |err| switch (err) {
            error.WouldBlock => return, // No events available
            else => return err,
        };

        var offset: usize = 0;
        while (offset < bytes_read) {
            const event = @as(*const std.os.linux.inotify_event, @ptrCast(@alignCast(&self.buffer[offset])));

            if (self.watch_descriptors.get(event.wd)) |watch_path| {
                const event_type = self.mapLinuxEventType(event.mask);

                if (event.getName()) |name| {
                    const full_path = try std.fmt.allocPrint(self.watcher.allocator, "{s}/{s}", .{ watch_path, name });
                    defer self.watcher.allocator.free(full_path);
                    try self.watcher.addEvent(full_path, event_type);
                } else {
                    try self.watcher.addEvent(watch_path, event_type);
                }
            }

            offset += @sizeOf(std.os.linux.inotify_event) + event.len;
        }
    }

    fn mapLinuxEventType(self: *Self, mask: u32) EventType {
        _ = self;
        if (mask & std.os.linux.IN.CREATE != 0) return .created;
        if (mask & std.os.linux.IN.DELETE != 0) return .deleted;
        if (mask & std.os.linux.IN.MODIFY != 0) return .modified;
        if (mask & std.os.linux.IN.MOVE != 0) return .moved;
        if (mask & std.os.linux.IN.ATTRIB != 0) return .permission_changed;
        return .modified; // Default fallback
    }
};

/// macOS/BSD-specific watcher using kqueue
const DarwinWatcher = if (builtin.os.tag == .macos or builtin.os.tag == .freebsd or builtin.os.tag == .netbsd or builtin.os.tag == .openbsd) struct {
    watcher: *Watcher,
    kqueue_fd: i32,
    file_descriptors: std.AutoHashMap(i32, []const u8),

    const Self = @This();

    fn init(allocator: std.mem.Allocator, watcher: *Watcher) !Self {
        _ = allocator;
        const kqueue_fd = try std.posix.kqueue();

        return Self{
            .watcher = watcher,
            .kqueue_fd = kqueue_fd,
            .file_descriptors = std.AutoHashMap(i32, []const u8).init(watcher.allocator),
        };
    }

    fn deinit(self: *Self) void {
        var iterator = self.file_descriptors.iterator();
        while (iterator.next()) |entry| {
            std.posix.close(entry.key_ptr.*);
            self.watcher.allocator.free(entry.value_ptr.*);
        }
        self.file_descriptors.deinit();
        std.posix.close(self.kqueue_fd);
    }

    fn addWatch(self: *Self, path: []const u8) !void {
        // Check if path is a directory or file
        const stat = std.fs.cwd().statFile(path) catch |err| {
            print("Warning: Could not stat {s}: {}\n", .{ path, err });
            return;
        };

        if (stat.kind == .directory) {
            // Watch the directory itself for new files/deletions
            try self.addFileWatch(path);

            // Recursively watch all files in the directory
            try self.addWatchRecursive(path);
        } else {
            // Just watch this single file
            try self.addFileWatch(path);
        }
    }

    fn addFileWatch(self: *Self, file_path: []const u8) !void {
        const file_fd = std.posix.open(file_path, .{ .ACCMODE = .RDONLY }, 0) catch |err| {
            print("Warning: Could not open {s}: {}\n", .{ file_path, err });
            return;
        };

        const kevent_change = std.posix.Kevent{
            .ident = @intCast(file_fd),
            .filter = std.c.EVFILT_VNODE,
            .flags = std.c.EV_ADD | std.c.EV_CLEAR,
            .fflags = std.c.NOTE_DELETE | std.c.NOTE_WRITE | std.c.NOTE_EXTEND |
                std.c.NOTE_ATTRIB | std.c.NOTE_RENAME,
            .data = 0,
            .udata = 0,
        };

        _ = try std.posix.kevent(self.kqueue_fd, &[_]std.posix.Kevent{kevent_change}, &[_]std.posix.Kevent{}, null);
        try self.file_descriptors.put(file_fd, try self.watcher.allocator.dupe(u8, file_path));
    }

    fn addWatchRecursive(self: *Self, dir_path: []const u8) !void {
        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
            print("Warning: Could not open directory {s}: {}\n", .{ dir_path, err });
            return;
        };
        defer dir.close();

        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            // Build full path
            const full_path = try std.fs.path.join(self.watcher.allocator, &[_][]const u8{ dir_path, entry.name });
            defer self.watcher.allocator.free(full_path);

            switch (entry.kind) {
                .file => {
                    try self.addFileWatch(full_path);
                },
                .directory => {
                    if (self.watcher.watch_config.recursive) {
                        try self.addFileWatch(full_path); // Watch directory itself
                        try self.addWatchRecursive(full_path); // Recursively watch contents
                    }
                },
                else => {},
            }
        }
    }

    fn processEvents(self: *Self) !void {
        var events: [10]std.posix.Kevent = undefined;
        const timeout = std.posix.timespec{ .tv_sec = 0, .tv_nsec = 100 * std.time.ns_per_ms };

        const nevents = std.posix.kevent(self.kqueue_fd, &[_]std.posix.Kevent{}, &events, &timeout) catch {
            // Handle timeout or other errors gracefully
            return;
        };

        for (events[0..nevents]) |event| {
            if (self.file_descriptors.get(@intCast(event.ident))) |file_path| {
                // Determine event type based on kqueue flags
                const event_type: EventType = if (event.fflags & std.c.NOTE_DELETE != 0) .deleted else if (event.fflags & std.c.NOTE_WRITE != 0 or event.fflags & std.c.NOTE_EXTEND != 0) .modified else if (event.fflags & std.c.NOTE_ATTRIB != 0) .permission_changed else .modified;

                try self.watcher.addEvent(file_path, event_type);
            }
        }
    }

    fn mapDarwinEventType(self: *Self, fflags: u32) EventType {
        _ = self;
        if (fflags & std.c.NOTE_DELETE != 0) return .deleted;
        if (fflags & std.c.NOTE_WRITE != 0) return .modified;
        if (fflags & std.c.NOTE_EXTEND != 0) return .modified;
        if (fflags & std.c.NOTE_ATTRIB != 0) return .permission_changed;
        if (fflags & std.c.NOTE_RENAME != 0) return .moved;
        return .modified; // Default fallback
    }
} else struct {
    // Stub implementation for non-Darwin platforms
    const Self = @This();

    fn init(allocator: std.mem.Allocator, watcher: *Watcher) !Self {
        _ = allocator;
        _ = watcher;
        return Self{};
    }

    fn deinit(self: *Self) void {
        _ = self;
    }

    fn addWatch(self: *Self, path: []const u8) !void {
        _ = self;
        _ = path;
    }

    fn processEvents(self: *Self) !void {
        _ = self;
    }
};

/// Fallback watcher using polling for unsupported platforms
const FallbackWatcher = struct {
    watcher: *Watcher,
    watched_paths: std.ArrayList([]const u8),
    last_poll_time: i64,

    const Self = @This();

    fn init(allocator: std.mem.Allocator, watcher: *Watcher) !Self {
        _ = allocator;
        return Self{
            .watcher = watcher,
            .watched_paths = std.ArrayList([]const u8).init(watcher.allocator),
            .last_poll_time = std.time.timestamp(),
        };
    }

    fn deinit(self: *Self) void {
        for (self.watched_paths.items) |path| {
            self.watcher.allocator.free(path);
        }
        self.watched_paths.deinit();
    }

    fn addWatch(self: *Self, path: []const u8) !void {
        try self.watched_paths.append(try self.watcher.allocator.dupe(u8, path));
    }

    fn processEvents(self: *Self) !void {
        const now = std.time.timestamp();

        // Poll every 5 seconds
        if (now - self.last_poll_time < 5) {
            return;
        }

        // Simple polling - trigger modified event for all watched paths
        // This is a basic implementation that would need enhancement for production use
        for (self.watched_paths.items) |path| {
            try self.watcher.addEvent(path, .modified);
        }

        self.last_poll_time = now;
    }
};

// Tests
const testing = std.testing;

test "EventType enum values" {
    const created = EventType.created;
    const modified = EventType.modified;
    const deleted = EventType.deleted;
    const moved = EventType.moved;
    const permission_changed = EventType.permission_changed;

    try testing.expect(created != modified);
    try testing.expect(modified != deleted);
    try testing.expect(deleted != moved);
    try testing.expect(moved != permission_changed);
}

test "Event creation" {
    const allocator = testing.allocator;
    const test_path = try allocator.dupe(u8, "/test/path");
    defer allocator.free(test_path);

    const event = Event{
        .path = test_path,
        .event_type = .modified,
        .timestamp = std.time.timestamp(),
    };

    try testing.expectEqualStrings("/test/path", event.path);
    try testing.expectEqual(EventType.modified, event.event_type);
    try testing.expect(event.timestamp > 0);
}

test "WatchConfig default values" {
    const watch_paths = [_][]const u8{"/test"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    try testing.expect(watch_config.recursive == true);
    try testing.expect(watch_config.webhook_url == null);
    try testing.expect(watch_config.webhook_timeout == 30);
    try testing.expect(watch_config.check_interval == 5);
    try testing.expect(watch_config.max_event_batch == 100);
    try testing.expectEqual(@as(usize, 1), watch_config.watch_paths.len);
    try testing.expectEqualStrings("/test", watch_config.watch_paths[0]);
}

test "WatchConfig custom values" {
    const watch_paths = [_][]const u8{ "/path1", "/path2" };
    const webhook_url = "https://example.com/webhook";

    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
        .recursive = false,
        .webhook_url = webhook_url,
        .webhook_timeout = 60,
        .check_interval = 10,
        .max_event_batch = 50,
    };

    try testing.expect(watch_config.recursive == false);
    try testing.expectEqualStrings("https://example.com/webhook", watch_config.webhook_url.?);
    try testing.expect(watch_config.webhook_timeout == 60);
    try testing.expect(watch_config.check_interval == 10);
    try testing.expect(watch_config.max_event_batch == 50);
    try testing.expectEqual(@as(usize, 2), watch_config.watch_paths.len);
}

test "Watcher initialization" {
    const allocator = testing.allocator;

    var app_config = config.Config.init(allocator);
    defer app_config.deinit();

    const watch_paths = [_][]const u8{"/test/path"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    var watcher = try Watcher.init(allocator, &app_config, watch_config);

    // Initialize with fallback watcher to avoid platform-specific issues in tests
    watcher.platform_data = .{ .fallback = try FallbackWatcher.init(allocator, &watcher) };
    defer watcher.deinit();

    try testing.expect(watcher.allocator.ptr == allocator.ptr);
    try testing.expect(watcher.config == &app_config);
    try testing.expectEqual(@as(usize, 1), watcher.watch_config.watch_paths.len);
    try testing.expectEqualStrings("/test/path", watcher.watch_config.watch_paths[0]);
    try testing.expectEqual(@as(usize, 0), watcher.event_queue.items.len);
    try testing.expect(watcher.should_stop == false);
    try testing.expect(watcher.last_check_time > 0);
}

test "Watcher addEvent functionality" {
    const allocator = testing.allocator;

    var app_config = config.Config.init(allocator);
    defer app_config.deinit();

    const watch_paths = [_][]const u8{"/test"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    var watcher = try Watcher.init(allocator, &app_config, watch_config);

    // Initialize with fallback watcher to avoid platform-specific issues in tests
    watcher.platform_data = .{ .fallback = try FallbackWatcher.init(allocator, &watcher) };
    defer watcher.deinit();

    // Add some events
    try watcher.addEvent("/test/file1.txt", .created);
    try watcher.addEvent("/test/file2.txt", .modified);
    try watcher.addEvent("/test/file3.txt", .deleted);

    try testing.expectEqual(@as(usize, 3), watcher.event_queue.items.len);

    // Check event details
    try testing.expectEqualStrings("/test/file1.txt", watcher.event_queue.items[0].path);
    try testing.expectEqual(EventType.created, watcher.event_queue.items[0].event_type);

    try testing.expectEqualStrings("/test/file2.txt", watcher.event_queue.items[1].path);
    try testing.expectEqual(EventType.modified, watcher.event_queue.items[1].event_type);

    try testing.expectEqualStrings("/test/file3.txt", watcher.event_queue.items[2].path);
    try testing.expectEqual(EventType.deleted, watcher.event_queue.items[2].event_type);
}

test "Watcher stop functionality" {
    const allocator = testing.allocator;

    var app_config = config.Config.init(allocator);
    defer app_config.deinit();

    const watch_paths = [_][]const u8{"/test"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    var watcher = try Watcher.init(allocator, &app_config, watch_config);

    // Initialize with fallback watcher to avoid platform-specific issues in tests
    watcher.platform_data = .{ .fallback = try FallbackWatcher.init(allocator, &watcher) };
    defer watcher.deinit();

    try testing.expect(watcher.should_stop == false);

    watcher.stop();

    try testing.expect(watcher.should_stop == true);
}

test "FallbackWatcher initialization" {
    const allocator = testing.allocator;

    var app_config = config.Config.init(allocator);
    defer app_config.deinit();

    const watch_paths = [_][]const u8{"/test"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    var watcher = try Watcher.init(allocator, &app_config, watch_config);

    // Initialize with fallback watcher to avoid platform-specific issues in tests
    watcher.platform_data = .{ .fallback = try FallbackWatcher.init(allocator, &watcher) };
    defer watcher.deinit();

    var fallback = try FallbackWatcher.init(allocator, &watcher);
    defer fallback.deinit();

    try testing.expect(fallback.watcher == &watcher);
    try testing.expectEqual(@as(usize, 0), fallback.watched_paths.items.len);
    try testing.expect(fallback.last_poll_time > 0);
}

test "FallbackWatcher addWatch" {
    const allocator = testing.allocator;

    var app_config = config.Config.init(allocator);
    defer app_config.deinit();

    const watch_paths = [_][]const u8{"/test"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    var watcher = try Watcher.init(allocator, &app_config, watch_config);

    // Initialize with fallback watcher to avoid platform-specific issues in tests
    watcher.platform_data = .{ .fallback = try FallbackWatcher.init(allocator, &watcher) };
    defer watcher.deinit();

    var fallback = try FallbackWatcher.init(allocator, &watcher);
    defer fallback.deinit();

    try fallback.addWatch("/test/path1");
    try fallback.addWatch("/test/path2");

    try testing.expectEqual(@as(usize, 2), fallback.watched_paths.items.len);
    try testing.expectEqualStrings("/test/path1", fallback.watched_paths.items[0]);
    try testing.expectEqualStrings("/test/path2", fallback.watched_paths.items[1]);
}

test "reported changes tracking" {
    const allocator = testing.allocator;

    var app_config = config.Config.init(allocator);
    defer app_config.deinit();

    const watch_paths = [_][]const u8{"/test"};
    const watch_config = WatchConfig{
        .watch_paths = &watch_paths,
    };

    var watcher = try Watcher.init(allocator, &app_config, watch_config);

    // Initialize with fallback watcher to avoid platform-specific issues in tests
    watcher.platform_data = .{ .fallback = try FallbackWatcher.init(allocator, &watcher) };
    defer watcher.deinit();

    // Test that reported_changes map is initialized
    try testing.expectEqual(@as(u32, 0), watcher.reported_changes.count());
}
