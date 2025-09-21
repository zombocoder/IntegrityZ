// SPDX-License-Identifier: Apache-2.0

//! IntegrityZ - Filesystem Integrity Monitor
//!
//! This is the main entry point for the IntegrityZ application, which provides
//! filesystem integrity monitoring capabilities. The application supports several
//! commands for creating baselines, checking file integrity, real-time monitoring,
//! and approving changes.

const std = @import("std");
const print = std.debug.print;
const baseline = @import("baseline.zig");
const constants = @import("constants.zig");
const checker = @import("checker.zig");
const reporter = @import("reporter.zig");
const config = @import("config.zig");
const watcher = @import("watcher.zig");

/// Main entry point for the IntegrityZ application
/// Parses command-line arguments and dispatches to appropriate handlers
pub fn main() !void {
    // Initialize general purpose allocator for memory management
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load configuration
    var app_config = config.loadConfig(allocator) catch |err| blk: {
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Failed to load config: {}\n", .{err});
        }
        // Use default config if loading fails
        break :blk config.Config.init(allocator);
    };
    defer app_config.deinit();

    // Parse command-line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Ensure at least one command argument is provided
    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    // Dispatch to appropriate command handler based on first argument
    if (std.mem.eql(u8, command, "init")) {
        try handleInit(allocator, &app_config, args[2..]);
    } else if (std.mem.eql(u8, command, "check")) {
        try handleCheck(allocator, &app_config, args[2..]);
    } else if (std.mem.eql(u8, command, "watch")) {
        try handleWatch(allocator, &app_config, args[2..]);
    } else if (std.mem.eql(u8, command, "config")) {
        try handleConfig(allocator, &app_config, args[2..]);
    } else {
        print("Unknown command: {s}\n", .{command});
        printUsage();
    }
}

/// Prints usage information and available commands to stdout
fn printUsage() void {
    print("IntegrityZ - Filesystem Integrity Monitor\n\n", .{});
    print("Usage:\n", .{});
    print("  integrityz init <paths...>        - Create baseline for specified paths\n", .{});
    print("  integrityz check [--json] [paths] - Check filesystem against baseline\n", .{});
    print("  integrityz watch                  - Watch for realtime changes\n", .{});
    print("  integrityz config [--init]        - Show or initialize configuration\n", .{});
    print("\nOptions:\n", .{});
    print("  --json                            - Output results in JSON format\n", .{});
    print("  --init                            - Create default configuration file\n", .{});
    print("\nNote: Watch mode settings (webhook URL, intervals) are configured via config file\n", .{});
}

/// Handles the 'init' command to create a new filesystem baseline
///
/// This function scans the specified paths, creates a baseline database
/// containing file metadata and checksums, and saves it to the default
/// baseline file location.
///
/// @param allocator Memory allocator for dynamic allocations
/// @param app_config Application configuration
/// @param paths Array of filesystem paths to include in the baseline
fn handleInit(allocator: std.mem.Allocator, app_config: *const config.Config, paths: [][]const u8) !void {
    // Use default scan paths from config if none provided
    const scan_paths = if (paths.len == 0) app_config.default_scan_paths.items else paths;

    if (scan_paths.len == 0) {
        print("Error: No paths specified for baseline creation\n", .{});
        print("Either provide paths on command line or set default_scan_path in config\n", .{});
        return;
    }

    // Create baseline database
    print("Creating baseline for {} path(s)...\n", .{scan_paths.len});
    var db = try baseline.createBaseline(allocator, scan_paths);
    defer db.deinit();

    // Save baseline to file using configured path
    const baseline_path = app_config.baseline_path;
    try db.saveToFile(baseline_path);
    print("✓ Baseline created: {} files in {s}\n", .{ db.records.items.len, baseline_path });
}

/// Handles the 'check' command to verify filesystem integrity against baseline
///
/// Loads the baseline database and compares current filesystem state against
/// the stored baseline. Reports any detected changes, additions, or deletions.
///
/// Supports --json flag to output results in JSON format for automation.
///
/// @param allocator Memory allocator for dynamic allocations
/// @param app_config Application configuration
/// @param args Additional command arguments (--json flag and optional paths to check)
fn handleCheck(allocator: std.mem.Allocator, app_config: *const config.Config, args: [][]const u8) !void {
    // Parse arguments to check for --json flag
    var json_output = false;
    var check_paths: [][]const u8 = args;

    if (args.len > 0 and std.mem.eql(u8, args[0], "--json")) {
        json_output = true;
        check_paths = args[1..]; // Skip the --json flag
    }

    if (!json_output) {
        print("Checking filesystem integrity...\n", .{});
    }

    const baseline_path = app_config.baseline_path;

    // Perform integrity check
    var result = checker.checkIntegrity(allocator, baseline_path, check_paths) catch |err| switch (err) {
        error.FileNotFound => {
            if (json_output) {
                print("{{\"error\":\"Baseline file not found: {s}\",\"suggestion\":\"Run 'integrityz init <paths>' to create a baseline first.\"}}\n", .{baseline_path});
            } else {
                print("Error: Baseline file not found: {s}\n", .{baseline_path});
                print("Run 'integrityz init <paths>' to create a baseline first.\n", .{});
            }
            return;
        },
        error.InvalidFileFormat => {
            if (json_output) {
                print("{{\"error\":\"Invalid baseline file format: {s}\",\"suggestion\":\"The baseline file may be corrupted or from an incompatible version.\"}}\n", .{baseline_path});
            } else {
                print("Error: Invalid baseline file format: {s}\n", .{baseline_path});
                print("The baseline file may be corrupted or from an incompatible version.\n", .{});
            }
            return;
        },
        error.UnsupportedVersion => {
            if (json_output) {
                print("{{\"error\":\"Unsupported baseline file version: {s}\",\"suggestion\":\"The baseline was created with an incompatible version of IntegrityZ.\"}}\n", .{baseline_path});
            } else {
                print("Error: Unsupported baseline file version: {s}\n", .{baseline_path});
                print("The baseline was created with an incompatible version of IntegrityZ.\n", .{});
            }
            return;
        },
        else => return err,
    };
    defer result.deinit();

    // Report results in requested format
    if (json_output) {
        const json_report = try reporter.generateJsonReport(allocator, &result);
        defer allocator.free(json_report);
        print("{s}\n", .{json_report});
    } else {
        reporter.reportCheckResults(&result);
    }

    // Set exit code based on results
    if (result.hasChanges()) {
        std.process.exit(1); // Exit with error code if changes detected
    }
}

/// Handles the 'watch' command for real-time filesystem monitoring
///
/// Sets up cross-platform filesystem watchers to monitor changes in real-time
/// and perform integrity checks when modifications are detected. Uses webhook
/// settings from configuration file for notifications.
///
/// @param allocator Memory allocator for dynamic allocations
/// @param app_config Application configuration
/// @param args Additional command arguments (currently unused)
fn handleWatch(allocator: std.mem.Allocator, app_config: *const config.Config, args: [][]const u8) !void {
    _ = args; // Unused for now

    // Use default scan paths from config
    const watch_paths = app_config.default_scan_paths.items;

    if (watch_paths.len == 0) {
        print("Error: No paths specified for monitoring\n", .{});
        print("Set default_scan_path in config file or run 'integrityz init <paths>' first\n", .{});
        return;
    }

    // Check if baseline exists
    const baseline_path = app_config.baseline_path;
    std.fs.cwd().access(baseline_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            print("Error: Baseline file not found: {s}\n", .{baseline_path});
            print("Run 'integrityz init <paths>' to create a baseline first.\n", .{});
            return;
        },
        else => return err,
    };

    // Configure watch settings from config file
    const watch_config = watcher.WatchConfig{
        .watch_paths = watch_paths,
        .recursive = app_config.watch_recursive,
        .webhook_url = app_config.webhook_url,
        .webhook_timeout = app_config.webhook_timeout,
        .check_interval = app_config.watch_check_interval,
        .max_event_batch = app_config.watch_max_event_batch,
    };

    // Initialize and start watcher
    var fs_watcher = watcher.Watcher.init(allocator, app_config, watch_config) catch |err| {
        print("Error initializing filesystem watcher: {}\n", .{err});
        return;
    };
    defer fs_watcher.deinit();

    // Initialize platform-specific watcher after Watcher is in final memory location
    fs_watcher.initPlatform() catch |err| {
        print("Error initializing platform-specific watcher: {}\n", .{err});
        return;
    };

    // Start monitoring (simplified for initial implementation)
    print("Starting watch mode. Press Ctrl+C to stop.\n", .{});

    fs_watcher.watch() catch |err| {
        print("Watch error: {}\n", .{err});
        return;
    };

    print("\nShutdown complete.\n", .{});
}

/// Handles the 'config' command to show or initialize configuration
///
/// This command can either show the current configuration or create a
/// default configuration file with the --init flag.
///
/// @param allocator Memory allocator for dynamic allocations
/// @param app_config Application configuration
/// @param args Command arguments, expecting optional ["--init"]
fn handleConfig(_: std.mem.Allocator, app_config: *const config.Config, args: [][]const u8) !void {
    if (args.len > 0 and std.mem.eql(u8, args[0], "--init")) {
        // Create default configuration file
        try app_config.saveToFile(config.DEFAULT_CONFIG_FILENAME);
        print("✓ Created default configuration: {s}\n", .{config.DEFAULT_CONFIG_FILENAME});
        return;
    }

    // Show current configuration
    print("IntegrityZ Configuration:\n\n", .{});
    print("Baseline path: {s}\n", .{app_config.baseline_path});
    print("Max file size: {}\n", .{app_config.max_file_size});
    print("Follow symlinks: {}\n", .{app_config.follow_symlinks});

    if (app_config.include_patterns.items.len > 0) {
        print("\nInclude patterns:\n", .{});
        for (app_config.include_patterns.items) |pattern| {
            print("  {s}\n", .{pattern});
        }
    }

    if (app_config.exclude_patterns.items.len > 0) {
        print("\nExclude patterns:\n", .{});
        for (app_config.exclude_patterns.items) |pattern| {
            print("  {s}\n", .{pattern});
        }
    }

    if (app_config.default_scan_paths.items.len > 0) {
        print("\nDefault scan paths:\n", .{});
        for (app_config.default_scan_paths.items) |path| {
            print("  {s}\n", .{path});
        }
    }

    // Display webhook settings
    print("\nWebhook settings:\n", .{});
    if (app_config.webhook_url) |url| {
        print("  URL: {s}\n", .{url});
    } else {
        print("  URL: (not configured)\n", .{});
    }
    print("  Timeout: {} seconds\n", .{app_config.webhook_timeout});

    // Display watch mode settings
    print("\nWatch mode settings:\n", .{});
    print("  Check interval: {} seconds\n", .{app_config.watch_check_interval});
    print("  Max event batch: {}\n", .{app_config.watch_max_event_batch});
    print("  Recursive monitoring: {}\n", .{app_config.watch_recursive});

    print("\nConfiguration file: {s}\n", .{config.DEFAULT_CONFIG_FILENAME});
}
