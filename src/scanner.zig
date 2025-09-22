// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const manifest = @import("manifest.zig");
const display = @import("display.zig");
const crypto = @import("crypto.zig");
const constants = @import("constants.zig");
const string_pool = @import("string_pool.zig");

// Forward declaration - BaselineDB will be imported from baseline.zig
const BaselineDB = @import("baseline.zig").BaselineDB;

/// Work item for parallel processing
const ScanJob = struct {
    path: []const u8,
    path_owned: bool, // Whether this job owns the path memory
    is_directory: bool,
};

/// Thread-safe work queue for parallel scanning
const WorkQueue = struct {
    mutex: std.Thread.Mutex,
    condition: std.Thread.Condition,
    jobs: std.ArrayList(ScanJob),
    finished: bool,

    const Self = @This();

    fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .mutex = std.Thread.Mutex{},
            .condition = std.Thread.Condition{},
            .jobs = std.ArrayList(ScanJob).init(allocator),
            .finished = false,
        };
    }

    fn deinit(self: *Self) void {
        // Clean up any remaining jobs
        for (self.jobs.items) |job| {
            if (job.path_owned) {
                self.jobs.allocator.free(job.path);
            }
        }
        self.jobs.deinit();
    }

    fn push(self: *Self, job: ScanJob) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.jobs.append(job);
        self.condition.signal();
    }

    fn pop(self: *Self) ?ScanJob {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (self.jobs.items.len == 0 and !self.finished) {
            self.condition.wait(&self.mutex);
        }

        if (self.jobs.items.len > 0) {
            return self.jobs.orderedRemove(0);
        }

        return null; // Queue is finished and empty
    }

    fn finish(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.finished = true;
        self.condition.broadcast();
    }

    fn isEmpty(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.jobs.items.len == 0;
    }
};

/// Worker thread context for parallel scanning
const WorkerContext = struct {
    allocator: std.mem.Allocator,
    work_queue: *WorkQueue,
    baseline: *BaselineDB,
    worker_id: usize,
    records_processed: *std.atomic.Value(usize),

    fn workerThread(context: *WorkerContext) void {
        while (true) {
            const job = context.work_queue.pop() orelse break;
            defer {
                if (job.path_owned) {
                    context.allocator.free(job.path);
                }
            }

            // Process the job
            if (job.is_directory) {
                context.processDirectory(job.path) catch |err| {
                    if (@import("builtin").mode == .Debug) {
                        std.debug.print("[DEBUG] Worker {}: Error processing directory {s}: {}\n", .{ context.worker_id, job.path, err });
                    }
                };
            } else {
                context.processFile(job.path) catch |err| {
                    if (@import("builtin").mode == .Debug) {
                        std.debug.print("[DEBUG] Worker {}: Error processing file {s}: {}\n", .{ context.worker_id, job.path, err });
                    }
                };
            }

            _ = context.records_processed.fetchAdd(1, .monotonic);
        }
    }

    fn processDirectory(self: *WorkerContext, path: []const u8) !void {
        // Create directory record
        const dir_record = createDirRecord(self.allocator, path) catch |err| {
            if (@import("builtin").mode == .Debug) {
                std.debug.print("[DEBUG] Worker {}: Failed to create dir record for {s}: {}\n", .{ self.worker_id, path, err });
            }
            return;
        };

        try self.baseline.addRecord(dir_record);

        // Queue children for processing
        var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch return;
        defer dir.close();

        var iterator = dir.iterate();
        while (iterator.next() catch null) |entry| {
            const full_path = std.fs.path.join(self.allocator, &[_][]const u8{ path, entry.name }) catch continue;

            const job = ScanJob{
                .path = full_path,
                .path_owned = true,
                .is_directory = entry.kind == .directory,
            };

            self.work_queue.push(job) catch {
                self.allocator.free(full_path);
                continue;
            };
        }
    }

    fn processFile(self: *WorkerContext, path: []const u8) !void {
        const stat = std.fs.cwd().statFile(path) catch return;
        const file_record = createNodeRecord(self.allocator, path, stat.kind) catch return;
        try self.baseline.addRecord(file_record);
    }
};

/// Debug print wrapper that can be disabled during tests
fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (!@import("builtin").is_test) {
        std.debug.print(fmt, args);
    }
}

/// Parallel filesystem scanning for large directory structures
/// Uses multiple worker threads to scan directories concurrently
/// More efficient than sequential scanning for large filesystems (>100k files)
pub fn scanPathParallel(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8) !void {
    // Determine optimal number of worker threads
    const cpu_count = std.Thread.getCpuCount() catch 4;
    const num_workers = @min(cpu_count, constants.PARALLEL_PROCESSING.MAX_WORKER_THREADS);

    if (@import("builtin").mode == .Debug) {
        std.debug.print("[DEBUG] Starting parallel scan with {} workers\n", .{num_workers});
    }

    // Initialize work queue and shared state
    var work_queue = WorkQueue.init(allocator);
    defer work_queue.deinit();

    var records_processed = std.atomic.Value(usize).init(0);

    // Create and start worker threads
    const worker_threads = try allocator.alloc(std.Thread, num_workers);
    defer allocator.free(worker_threads);

    const worker_contexts = try allocator.alloc(WorkerContext, num_workers);
    defer allocator.free(worker_contexts);

    // Initialize worker contexts
    for (worker_contexts, 0..) |*context, i| {
        context.* = WorkerContext{
            .allocator = allocator,
            .work_queue = &work_queue,
            .baseline = baseline,
            .worker_id = i,
            .records_processed = &records_processed,
        };
    }

    // Start worker threads
    for (worker_threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, WorkerContext.workerThread, .{&worker_contexts[i]});
    }

    // Queue initial job
    const initial_path = try allocator.dupe(u8, path);
    const initial_job = ScanJob{
        .path = initial_path,
        .path_owned = true,
        .is_directory = true, // Assume root path is a directory
    };

    try work_queue.push(initial_job);

    // Monitor progress and wait for completion
    var last_processed: usize = 0;
    var idle_cycles: usize = 0;
    const max_idle_cycles = 10; // Wait this many cycles before considering work done

    while (true) {
        std.time.sleep(100 * std.time.ns_per_ms); // Sleep 100ms

        const current_processed = records_processed.load(.monotonic);

        if (@import("builtin").mode == .Debug and current_processed != last_processed) {
            std.debug.print("[DEBUG] Processed {} records so far\n", .{current_processed});
            last_processed = current_processed;
            idle_cycles = 0;
        } else {
            idle_cycles += 1;
        }

        // Check if all work is done
        if (work_queue.isEmpty() and idle_cycles >= max_idle_cycles) {
            break;
        }
    }

    // Signal workers to finish and wait for them
    work_queue.finish();

    for (worker_threads) |*thread| {
        thread.join();
    }

    if (@import("builtin").mode == .Debug) {
        const final_count = records_processed.load(.monotonic);
        std.debug.print("[DEBUG] Parallel scan completed. Processed {} records total\n", .{final_count});
    }
}

/// Automatically choose between sequential and parallel scanning based on estimated workload
/// Uses heuristics to determine the optimal scanning approach
pub fn scanPathAdaptive(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8) !void {
    // Quick estimation of directory size to decide on scanning strategy
    const estimated_files = estimateDirectorySize(path) catch 1000; // Default to small if estimation fails

    if (estimated_files > constants.PERFORMANCE_THRESHOLDS.MANY_FILES_THRESHOLD) {
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Large directory detected ({} estimated files), using parallel scanning\n", .{estimated_files});
        }
        try scanPathParallel(allocator, baseline, path);
    } else {
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Small/medium directory detected ({} estimated files), using sequential scanning\n", .{estimated_files});
        }
        try scanPath(allocator, baseline, path);
    }
}

/// Memory-optimized scanning using string pooling for path deduplication
/// Recommended for very large filesystems where memory usage is a concern
pub fn scanPathWithStringPool(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8) !void {
    var path_pool = string_pool.PathPool.init(allocator);
    defer path_pool.deinit();

    // Quick estimation to choose scanning strategy
    const estimated_files = estimateDirectorySize(path) catch 1000;

    if (estimated_files > constants.PERFORMANCE_THRESHOLDS.MANY_FILES_THRESHOLD) {
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Large directory with string pooling ({} estimated files)\n", .{estimated_files});
        }
        try scanPathParallelWithPool(allocator, baseline, path, &path_pool);
    } else {
        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Sequential scanning with string pooling ({} estimated files)\n", .{estimated_files});
        }
        try scanPathWithPool(allocator, baseline, path, &path_pool);
    }

    // Report string pool statistics
    if (@import("builtin").mode == .Debug) {
        const stats = path_pool.getStats();
        std.debug.print("[DEBUG] String pool stats: {} interned strings, {} bytes saved\n", .{ stats.base_stats.interned_strings, stats.base_stats.total_bytes_saved });
    }
}

/// Sequential scanning with string pool optimization
fn scanPathWithPool(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8, path_pool: *string_pool.PathPool) !void {
    // Intern the path to reduce duplicate allocations
    const interned_path = try path_pool.internPath(path);

    // Check if path is a directory by trying to open it as a directory first
    if (std.fs.openDirAbsolute(interned_path, .{})) |mut_dir| {
        var dir = mut_dir;
        dir.close();

        // It's a directory, create a record for the directory itself
        const dir_record = try createDirRecord(allocator, interned_path);
        try baseline.addRecord(dir_record);

        // Scan children with path pooling
        try scanPathChildrenWithPool(allocator, baseline, interned_path, path_pool);
    } else |_| {
        // Not a directory, check if it's a file
        const stat = std.fs.cwd().statFile(interned_path) catch return;
        const file_record = try createNodeRecord(allocator, interned_path, stat.kind);
        try baseline.addRecord(file_record);
    }
}

/// Parallel scanning with string pool optimization
fn scanPathParallelWithPool(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8, path_pool: *string_pool.PathPool) !void {
    // For now, fall back to regular parallel scanning
    // A full implementation would need thread-safe string pools
    _ = path_pool;
    try scanPathParallel(allocator, baseline, path);
}

/// Scan directory children with string pool optimization
fn scanPathChildrenWithPool(allocator: std.mem.Allocator, baseline: *BaselineDB, path: []const u8, path_pool: *string_pool.PathPool) !void {
    var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ path, entry.name });
        defer allocator.free(full_path);

        // Intern the full path to reduce duplicates
        const interned_path = try path_pool.internPath(full_path);

        const record = try createNodeRecord(allocator, interned_path, entry.kind);
        try baseline.addRecord(record);

        // Recursively scan subdirectories
        if (entry.kind == .directory) {
            try scanPathChildrenWithPool(allocator, baseline, interned_path, path_pool);
        }
    }
}

/// Estimate the number of files in a directory tree
/// Uses sampling to avoid full traversal for estimation
fn estimateDirectorySize(path: []const u8) !usize {
    var dir = std.fs.openDirAbsolute(path, .{ .iterate = true }) catch |err| switch (err) {
        error.NotDir => return 1, // It's a file, not a directory
        else => return err,
    };
    defer dir.close();

    var file_count: usize = 0;
    var dir_count: usize = 0;
    var sample_count: usize = 0;
    const max_samples = 100; // Sample at most 100 entries for estimation

    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        sample_count += 1;
        if (entry.kind == .directory) {
            dir_count += 1;
        } else {
            file_count += 1;
        }

        // Stop sampling after max_samples to avoid long delays
        if (sample_count >= max_samples) break;
    }

    // Rough estimation: multiply by a factor based on directory density
    const total_sampled = file_count + dir_count;
    if (total_sampled == 0) return 0;

    // Estimate total files: if we found many directories, multiply by higher factor
    const dir_multiplier: usize = if (dir_count * 2 > total_sampled) 50 else 10;
    return total_sampled * dir_multiplier;
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
    const checksum = crypto.blake3HashFileAdaptive(path, allocator) catch |err| switch (err) {
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

test "estimateDirectorySize basic functionality" {
    const allocator = testing.allocator;

    // Create a temporary directory with some files
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "file1.txt", .data = "content1" });
    try tmp.dir.writeFile(.{ .sub_path = "file2.txt", .data = "content2" });
    try tmp.dir.makeDir("subdir");
    try tmp.dir.writeFile(.{ .sub_path = "subdir/file3.txt", .data = "content3" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const estimated = try estimateDirectorySize(tmp_path);

    // Should estimate more than 0 files
    try testing.expect(estimated > 0);

    // Should be a reasonable estimate (multiplied by estimation factor)
    try testing.expect(estimated >= 30); // At least 3 entries * 10 multiplier
}

test "estimateDirectorySize handles empty directory" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const estimated = try estimateDirectorySize(tmp_path);

    // Empty directory should return 0
    try testing.expectEqual(@as(usize, 0), estimated);
}

test "scanPathAdaptive chooses sequential for small directories" {
    const allocator = testing.allocator;

    // Create a small test directory
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "small_file.txt", .data = "test content" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create baseline and scan
    var baseline = @import("database.zig").BaselineDB.init(allocator);
    defer baseline.deinit();

    // This should complete without error and use sequential scanning
    try scanPathAdaptive(allocator, &baseline, tmp_path);

    // Verify records were created
    try testing.expect(baseline.records.items.len >= 1);
}

test "scanPathWithStringPool basic functionality" {
    const allocator = testing.allocator;

    // Create a test directory structure
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "test1.txt", .data = "content1" });
    try tmp.dir.writeFile(.{ .sub_path = "test2.txt", .data = "content2" });
    try tmp.dir.makeDir("subdir");
    try tmp.dir.writeFile(.{ .sub_path = "subdir/test3.txt", .data = "content3" });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Create baseline and scan with string pooling
    var baseline = @import("database.zig").BaselineDB.init(allocator);
    defer baseline.deinit();

    try scanPathWithStringPool(allocator, &baseline, tmp_path);

    // Verify records were created
    try testing.expect(baseline.records.items.len >= 4); // Directory + 3 files
}

test "WorkQueue basic operations" {
    const allocator = testing.allocator;

    var queue = WorkQueue.init(allocator);
    defer queue.deinit();

    // Test initial state
    try testing.expect(queue.isEmpty());

    // Test pushing jobs
    const job1 = ScanJob{
        .path = "test/path1",
        .path_owned = false,
        .is_directory = true,
    };

    try queue.push(job1);
    try testing.expect(!queue.isEmpty());

    // Test popping jobs
    const popped = queue.pop();
    try testing.expect(popped != null);
    if (popped) |job| {
        try testing.expectEqualStrings("test/path1", job.path);
        try testing.expect(job.is_directory);
    }

    try testing.expect(queue.isEmpty());
}

test "WorkQueue handles multiple jobs" {
    const allocator = testing.allocator;

    var queue = WorkQueue.init(allocator);
    defer queue.deinit();

    // Push multiple jobs
    const jobs = [_]ScanJob{
        ScanJob{ .path = "path1", .path_owned = false, .is_directory = true },
        ScanJob{ .path = "path2", .path_owned = false, .is_directory = false },
        ScanJob{ .path = "path3", .path_owned = false, .is_directory = true },
    };

    for (jobs) |job| {
        try queue.push(job);
    }

    // Pop all jobs and verify order
    for (jobs) |expected_job| {
        const popped = queue.pop();
        try testing.expect(popped != null);
        if (popped) |job| {
            try testing.expectEqualStrings(expected_job.path, job.path);
            try testing.expectEqual(expected_job.is_directory, job.is_directory);
        }
    }

    try testing.expect(queue.isEmpty());
}

test "WorkQueue finish functionality" {
    const allocator = testing.allocator;

    var queue = WorkQueue.init(allocator);
    defer queue.deinit();

    // Finish the queue
    queue.finish();

    // Pop should return null for finished empty queue
    const popped = queue.pop();
    try testing.expect(popped == null);
}
