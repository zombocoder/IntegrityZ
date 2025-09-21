// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const checker = @import("checker.zig");
const constants = @import("constants.zig");

/// Convert a binary checksum to hex string
fn checksumToHex(allocator: std.mem.Allocator, checksum: [constants.HASH_DIGEST_LENGTH]u8) ![]u8 {
    const hex_string = try allocator.alloc(u8, constants.HASH_HEX_LENGTH);
    _ = try std.fmt.bufPrint(hex_string, "{}", .{std.fmt.fmtSliceHexLower(&checksum)});
    return hex_string;
}

/// Report check results to the user in a human-readable format
pub fn reportCheckResults(result: *const checker.CheckResult) void {
    if (!result.hasChanges()) {
        std.debug.print("✓ No integrity violations detected\n", .{});
        std.debug.print("Checked {} files against baseline\n", .{result.current_records});
        return;
    }

    std.debug.print("Integrity violations detected!\n", .{});
    std.debug.print("Found {} change(s) in {} files\n", .{ result.changes.items.len, result.current_records });
    std.debug.print("\n", .{});

    // Group changes by type for better organization
    var additions: u32 = 0;
    var deletions: u32 = 0;
    var modifications: u32 = 0;
    var moves: u32 = 0;

    for (result.changes.items) |change| {
        switch (change.change_type) {
            .added => additions += 1,
            .deleted => deletions += 1,
            .modified => modifications += 1,
            .moved => moves += 1,
        }
    }

    // Print summary
    std.debug.print("Summary:\n", .{});
    if (additions > 0) std.debug.print("  {} files added\n", .{additions});
    if (deletions > 0) std.debug.print("  {} files deleted\n", .{deletions});
    if (modifications > 0) std.debug.print("  {} files modified\n", .{modifications});
    if (moves > 0) std.debug.print("  {} files moved\n", .{moves});
    std.debug.print("\n", .{});

    // Print detailed changes
    std.debug.print("Details:\n", .{});
    for (result.changes.items) |change| {
        const type_symbol = switch (change.change_type) {
            .added => "+",
            .deleted => "-",
            .modified => "M",
            .moved => "→",
        };

        std.debug.print("  {s} {s}: {s}\n", .{ type_symbol, change.path, change.details });
    }

    std.debug.print("\n", .{});
    std.debug.print("Total: {} baseline records, {} current files, {} changes\n", .{ result.baseline_records, result.current_records, result.changes.items.len });
}

/// Generate a JSON report of the check results for machine consumption
pub fn generateJsonReport(allocator: std.mem.Allocator, result: *const checker.CheckResult) ![]u8 {
    // Create a struct that matches what we want to serialize
    const ChangeReport = struct {
        type: []const u8,
        path: []const u8,
        details: []const u8,
        old_checksum: ?[]const u8 = null, // For modified files
        new_checksum: ?[]const u8 = null, // For modified files
    };

    const Report = struct {
        timestamp: i64, // Unix timestamp in seconds
        has_changes: bool,
        total_files_checked: u32,
        baseline_records: u32,
        current_records: u32,
        changes_count: u32,
        changes: []ChangeReport,
    };

    // Prepare changes array
    var changes_list = try allocator.alloc(ChangeReport, result.changes.items.len);
    defer {
        // Clean up allocated checksum strings
        for (changes_list) |change_report| {
            if (change_report.old_checksum) |old| allocator.free(old);
            if (change_report.new_checksum) |new| allocator.free(new);
        }
        allocator.free(changes_list);
    }

    for (result.changes.items, 0..) |change, i| {
        var old_checksum: ?[]const u8 = null;
        var new_checksum: ?[]const u8 = null;

        // For modified files, extract checksums from old and new records
        if (change.change_type == .modified) {
            if (change.old_record) |old_record| {
                if (old_record == .file) {
                    old_checksum = try checksumToHex(allocator, old_record.file.checksum);
                }
            }
            if (change.new_record) |new_record| {
                if (new_record == .file) {
                    new_checksum = try checksumToHex(allocator, new_record.file.checksum);
                }
            }
        }

        changes_list[i] = ChangeReport{
            .type = @tagName(change.change_type),
            .path = change.path,
            .details = change.details,
            .old_checksum = old_checksum,
            .new_checksum = new_checksum,
        };
    }

    // Get current timestamp
    const timestamp = std.time.timestamp();

    // Create the report struct
    const report = Report{
        .timestamp = timestamp,
        .has_changes = result.hasChanges(),
        .total_files_checked = result.total_files_checked,
        .baseline_records = result.baseline_records,
        .current_records = result.current_records,
        .changes_count = @intCast(result.changes.items.len),
        .changes = changes_list,
    };

    // Use std.json.stringify to generate JSON
    var json_output = std.ArrayList(u8).init(allocator);
    defer json_output.deinit();

    try std.json.stringify(report, .{}, json_output.writer());

    return try allocator.dupe(u8, json_output.items);
}

const testing = std.testing;

test "report with no changes" {
    var result = checker.CheckResult.init(testing.allocator);
    defer result.deinit();

    result.baseline_records = 10;
    result.current_records = 10;
    result.total_files_checked = 10;

    // This test mainly checks that reporting doesn't crash
    reportCheckResults(&result);
}

test "report with changes" {
    var result = checker.CheckResult.init(testing.allocator);
    defer result.deinit();

    result.baseline_records = 10;
    result.current_records = 11;
    result.total_files_checked = 10;

    const change = checker.Change{
        .change_type = .added,
        .path = try testing.allocator.dupe(u8, "/test/new_file.txt"),
        .old_record = null,
        .new_record = null,
        .details = try testing.allocator.dupe(u8, "File added"),
    };

    try result.addChange(change);

    // This test mainly checks that reporting doesn't crash
    reportCheckResults(&result);
}

test "JSON report generation" {
    var result = checker.CheckResult.init(testing.allocator);
    defer result.deinit();

    result.baseline_records = 5;
    result.current_records = 6;
    result.total_files_checked = 5;

    const change = checker.Change{
        .change_type = .modified,
        .path = try testing.allocator.dupe(u8, "/test/changed.txt"),
        .old_record = null,
        .new_record = null,
        .details = try testing.allocator.dupe(u8, "File content changed"),
    };

    try result.addChange(change);

    const json_report = try generateJsonReport(testing.allocator, &result);
    defer testing.allocator.free(json_report);

    // Verify JSON contains expected fields including new timestamp
    try testing.expect(std.mem.indexOf(u8, json_report, "timestamp") != null);
    try testing.expect(std.mem.indexOf(u8, json_report, "has_changes") != null);
    try testing.expect(std.mem.indexOf(u8, json_report, "baseline_records") != null);
    try testing.expect(std.mem.indexOf(u8, json_report, "changes") != null);
    try testing.expect(std.mem.indexOf(u8, json_report, "/test/changed.txt") != null);
}

test "JSON report with checksums for modified files" {
    const records = @import("records.zig");
    var result = checker.CheckResult.init(testing.allocator);
    defer result.deinit();

    result.baseline_records = 1;
    result.current_records = 1;
    result.total_files_checked = 1;

    // Create file records with different checksums
    const old_record = records.Record{
        .file = records.FileRecord{
            .path = try testing.allocator.dupe(u8, "/test/modified.txt"),
            .inode = 123,
            .dev = 456,
            .size = 1024,
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .checksum = [_]u8{ 0x01, 0x02, 0x03 } ++ [_]u8{0x00} ** 29, // Old checksum
        },
    };

    const new_record = records.Record{
        .file = records.FileRecord{
            .path = try testing.allocator.dupe(u8, "/test/modified.txt"),
            .inode = 123,
            .dev = 456,
            .size = 1024,
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .checksum = [_]u8{ 0x04, 0x05, 0x06 } ++ [_]u8{0x00} ** 29, // New checksum
        },
    };

    const change = checker.Change{
        .change_type = .modified,
        .path = try testing.allocator.dupe(u8, "/test/modified.txt"),
        .old_record = old_record,
        .new_record = new_record,
        .details = try testing.allocator.dupe(u8, "Content changed (checksum mismatch)"),
    };

    try result.addChange(change);

    const json_report = try generateJsonReport(testing.allocator, &result);
    defer testing.allocator.free(json_report);

    // Verify JSON contains checksum fields for modified files
    try testing.expect(std.mem.indexOf(u8, json_report, "old_checksum") != null);
    try testing.expect(std.mem.indexOf(u8, json_report, "new_checksum") != null);
    try testing.expect(std.mem.indexOf(u8, json_report, "010203") != null); // Hex representation of old checksum start
    try testing.expect(std.mem.indexOf(u8, json_report, "040506") != null); // Hex representation of new checksum start
}

test "JSON report timestamp is current" {
    var result = checker.CheckResult.init(testing.allocator);
    defer result.deinit();

    result.baseline_records = 1;
    result.current_records = 1;
    result.total_files_checked = 1;

    const before_timestamp = std.time.timestamp();

    const json_report = try generateJsonReport(testing.allocator, &result);
    defer testing.allocator.free(json_report);

    const after_timestamp = std.time.timestamp();

    // Parse JSON to verify timestamp is reasonable
    const parsed = std.json.parseFromSlice(std.json.Value, testing.allocator, json_report, .{}) catch |err| {
        std.debug.print("Failed to parse JSON: {}\n", .{err});
        std.debug.print("JSON content: {s}\n", .{json_report});
        return err;
    };
    defer parsed.deinit();

    const timestamp_value = parsed.value.object.get("timestamp").?;
    const report_timestamp = timestamp_value.integer;

    // Verify timestamp is within reasonable range (within a few seconds of generation)
    try testing.expect(report_timestamp >= before_timestamp);
    try testing.expect(report_timestamp <= after_timestamp + 1); // Allow 1 second tolerance
}
