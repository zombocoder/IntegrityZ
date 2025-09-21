// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const constants = @import("constants.zig");

/// Magic bytes for database file format identification
const DATABASE_MAGIC: u32 = 0x5A495442; // "ZITB" in little endian

/// Binary header structure for baseline database files
const DatabaseHeader = struct {
    magic: u32,
    version: u32,
    created_at: i64,
    record_count: u32,
    root_manifest: [constants.HASH_DIGEST_LENGTH]u8,
    signature: [64]u8,
};

/// In-memory database storing filesystem baseline records
/// Manages collection, storage, and serialization of filesystem integrity data
pub const BaselineDB = struct {
    version: u32,
    created_at: i64,
    records: std.ArrayList(records.Record),
    root_manifest: [constants.HASH_DIGEST_LENGTH]u8, // Root directory manifest hash
    signature: [64]u8, // Ed25519 signature

    /// Initialize a new empty baseline database
    pub fn init(allocator: std.mem.Allocator) BaselineDB {
        return BaselineDB{
            .version = constants.BASELINE_DB_VERSION,
            .created_at = std.time.timestamp(),
            .records = std.ArrayList(records.Record).init(allocator),
            .root_manifest = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
            .signature = std.mem.zeroes([64]u8),
        };
    }

    /// Cleanup all allocated memory and resources
    pub fn deinit(self: *BaselineDB) void {
        for (self.records.items) |*record| {
            record.deinit(self.records.allocator);
        }
        self.records.deinit();
    }

    /// Add a new filesystem record to the database
    pub fn addRecord(self: *BaselineDB, record: records.Record) !void {
        try self.records.append(record);
    }

    /// Serialize database to file for persistent storage
    /// Binary format: [Header][Record1][Record2]...[RecordN]
    pub fn saveToFile(self: *BaselineDB, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        const writer = file.writer();

        // Write header
        const header = DatabaseHeader{
            .magic = DATABASE_MAGIC,
            .version = self.version,
            .created_at = self.created_at,
            .record_count = @intCast(self.records.items.len),
            .root_manifest = self.root_manifest,
            .signature = self.signature,
        };

        // Write header fields manually
        try writer.writeInt(u32, header.magic, .little);
        try writer.writeInt(u32, header.version, .little);
        try writer.writeInt(i64, header.created_at, .little);
        try writer.writeInt(u32, header.record_count, .little);
        try writer.writeAll(&header.root_manifest);
        try writer.writeAll(&header.signature);

        // Write each record
        for (self.records.items) |*record| {
            try serializeRecord(writer, record);
        }

        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Saving baseline to: {s}\n", .{path});
            std.debug.print("[DEBUG] Records count: {}\n", .{self.records.items.len});
        }
    }

    /// Optimized batch saving for large databases
    /// Uses buffered I/O and batched writes for better performance with large datasets
    pub fn saveToFileBatched(self: *BaselineDB, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        // Use buffered writer for better I/O performance
        var buffered_writer = std.io.bufferedWriter(file.writer());
        const writer = buffered_writer.writer();

        // Write header
        const header = DatabaseHeader{
            .magic = DATABASE_MAGIC,
            .version = self.version,
            .created_at = self.created_at,
            .record_count = @intCast(self.records.items.len),
            .root_manifest = self.root_manifest,
            .signature = self.signature,
        };

        // Write header fields manually
        try writer.writeInt(u32, header.magic, .little);
        try writer.writeInt(u32, header.version, .little);
        try writer.writeInt(i64, header.created_at, .little);
        try writer.writeInt(u32, header.record_count, .little);
        try writer.writeAll(&header.root_manifest);
        try writer.writeAll(&header.signature);

        // Flush header immediately
        try buffered_writer.flush();

        // Write records in batches for better performance
        var i: usize = 0;
        const batch_size = constants.DATABASE_IO.BATCH_SIZE;

        while (i < self.records.items.len) {
            const end = @min(i + batch_size, self.records.items.len);

            // Write a batch of records
            for (self.records.items[i..end]) |*record| {
                try serializeRecord(writer, record);
            }

            // Flush after each batch to prevent excessive memory usage
            try buffered_writer.flush();

            if (@import("builtin").mode == .Debug and self.records.items.len > batch_size) {
                const progress = (end * 100) / self.records.items.len;
                std.debug.print("[DEBUG] Batch save progress: {}% ({}/{})\n", .{ progress, end, self.records.items.len });
            }

            i = end;
        }

        // Final flush
        try buffered_writer.flush();

        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Batched save completed: {s}\n", .{path});
            std.debug.print("[DEBUG] Records count: {}\n", .{self.records.items.len});
        }
    }

    /// Save with automatic optimization based on database size
    /// Chooses between regular and batched saving based on record count
    pub fn saveToFileOptimized(self: *BaselineDB, path: []const u8) !void {
        if (self.records.items.len > constants.DATABASE_IO.BATCH_SIZE) {
            if (@import("builtin").mode == .Debug) {
                std.debug.print("[DEBUG] Large database detected ({}), using batched save\n", .{self.records.items.len});
            }
            try self.saveToFileBatched(path);
        } else {
            try self.saveToFile(path);
        }
    }

    /// Load database from persistent storage
    /// Binary format: [Header][Record1][Record2]...[RecordN]
    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !BaselineDB {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const reader = file.reader();

        // Read and validate header
        const magic = try reader.readInt(u32, .little);
        const version = try reader.readInt(u32, .little);
        const created_at = try reader.readInt(i64, .little);
        const record_count = try reader.readInt(u32, .little);
        var root_manifest: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
        try reader.readNoEof(&root_manifest);
        var signature: [64]u8 = undefined;
        try reader.readNoEof(&signature);

        const header = DatabaseHeader{
            .magic = magic,
            .version = version,
            .created_at = created_at,
            .record_count = record_count,
            .root_manifest = root_manifest,
            .signature = signature,
        };
        if (header.magic != DATABASE_MAGIC) {
            return error.InvalidFileFormat;
        }
        if (header.version != constants.BASELINE_DB_VERSION) {
            return error.UnsupportedVersion;
        }

        // Create database instance
        var db = BaselineDB{
            .version = header.version,
            .created_at = header.created_at,
            .records = std.ArrayList(records.Record).init(allocator),
            .root_manifest = header.root_manifest,
            .signature = header.signature,
        };

        // Read records
        var i: u32 = 0;
        while (i < header.record_count) : (i += 1) {
            const record = try deserializeRecord(reader, allocator);
            try db.records.append(record);
        }

        if (@import("builtin").mode == .Debug) {
            std.debug.print("[DEBUG] Loading baseline from: {s}\n", .{path});
            std.debug.print("[DEBUG] Loaded {} records\n", .{db.records.items.len});
        }

        return db;
    }
};

/// Serialize a single record to the writer
/// Format: [RecordType:u8][PathLength:u32][Path][RecordData]
fn serializeRecord(writer: anytype, record: *const records.Record) !void {
    // Write record type tag
    const record_type: u8 = switch (record.*) {
        .file => 0,
        .dir => 1,
        .symlink => 2,
        .block => 3,
        .char => 4,
        .fifo => 5,
        .socket => 6,
    };
    try writer.writeByte(record_type);

    // Write path
    const path = record.getPath();
    try writer.writeInt(u32, @intCast(path.len), .little);
    try writer.writeAll(path);

    // Write record-specific data
    switch (record.*) {
        .file => |file_record| {
            try writer.writeInt(u64, file_record.inode, .little);
            try writer.writeInt(u64, file_record.dev, .little);
            try writer.writeInt(u64, file_record.size, .little);
            try writer.writeInt(u32, file_record.mode, .little);
            try writer.writeInt(u32, file_record.uid, .little);
            try writer.writeInt(u32, file_record.gid, .little);
            try writer.writeInt(u32, file_record.nlink, .little);
            try writer.writeInt(i64, file_record.mtime, .little);
            try writer.writeInt(i64, file_record.ctime, .little);
            try writer.writeAll(&file_record.checksum);
        },
        .dir => |dir_record| {
            try writer.writeInt(u64, dir_record.inode, .little);
            try writer.writeInt(u64, dir_record.dev, .little);
            try writer.writeInt(u32, dir_record.mode, .little);
            try writer.writeInt(u32, dir_record.uid, .little);
            try writer.writeInt(u32, dir_record.gid, .little);
            try writer.writeInt(u32, dir_record.nlink, .little);
            try writer.writeInt(i64, dir_record.mtime, .little);
            try writer.writeInt(i64, dir_record.ctime, .little);
            try writer.writeAll(&dir_record.acl_hash);
            try writer.writeAll(&dir_record.manifest);
            try writer.writeInt(u32, dir_record.entry_count, .little);
        },
        .symlink => |symlink_record| {
            try writer.writeInt(u64, symlink_record.inode, .little);
            try writer.writeInt(u64, symlink_record.dev, .little);
            try writer.writeInt(u32, symlink_record.mode, .little);
            try writer.writeInt(u32, symlink_record.uid, .little);
            try writer.writeInt(u32, symlink_record.gid, .little);
            try writer.writeInt(i64, symlink_record.mtime, .little);
            try writer.writeInt(i64, symlink_record.ctime, .little);
            try writer.writeAll(&symlink_record.target_hash);
            // Write target path
            try writer.writeInt(u32, @intCast(symlink_record.target.len), .little);
            try writer.writeAll(symlink_record.target);
        },
        .block, .char, .fifo, .socket => |special_record| {
            try writer.writeInt(u64, special_record.inode, .little);
            try writer.writeInt(u64, special_record.dev, .little);
            try writer.writeInt(u32, special_record.mode, .little);
            try writer.writeInt(u32, special_record.uid, .little);
            try writer.writeInt(u32, special_record.gid, .little);
            try writer.writeInt(i64, special_record.mtime, .little);
            try writer.writeInt(i64, special_record.ctime, .little);
            try writer.writeInt(u64, special_record.device_id, .little);
        },
    }
}

/// Deserialize a single record from the reader
fn deserializeRecord(reader: anytype, allocator: std.mem.Allocator) !records.Record {
    // Read record type
    const record_type = try reader.readByte();

    // Read path
    const path_len = try reader.readInt(u32, .little);
    const path = try allocator.alloc(u8, path_len);
    try reader.readNoEof(path);

    switch (record_type) {
        0 => { // file
            const inode = try reader.readInt(u64, .little);
            const dev = try reader.readInt(u64, .little);
            const size = try reader.readInt(u64, .little);
            const mode = try reader.readInt(u32, .little);
            const uid = try reader.readInt(u32, .little);
            const gid = try reader.readInt(u32, .little);
            const nlink = try reader.readInt(u32, .little);
            const mtime = try reader.readInt(i64, .little);
            const ctime = try reader.readInt(i64, .little);
            var checksum: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
            try reader.readNoEof(&checksum);

            return records.Record{ .file = records.FileRecord{
                .path = path,
                .inode = inode,
                .dev = dev,
                .size = size,
                .mode = mode,
                .uid = uid,
                .gid = gid,
                .nlink = nlink,
                .mtime = mtime,
                .ctime = ctime,
                .checksum = checksum,
            } };
        },
        1 => { // dir
            const inode = try reader.readInt(u64, .little);
            const dev = try reader.readInt(u64, .little);
            const mode = try reader.readInt(u32, .little);
            const uid = try reader.readInt(u32, .little);
            const gid = try reader.readInt(u32, .little);
            const nlink = try reader.readInt(u32, .little);
            const mtime = try reader.readInt(i64, .little);
            const ctime = try reader.readInt(i64, .little);
            var acl_hash: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
            try reader.readNoEof(&acl_hash);
            var manifest: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
            try reader.readNoEof(&manifest);
            const entry_count = try reader.readInt(u32, .little);

            return records.Record{ .dir = records.DirRecord{
                .path = path,
                .inode = inode,
                .dev = dev,
                .mode = mode,
                .uid = uid,
                .gid = gid,
                .nlink = nlink,
                .mtime = mtime,
                .ctime = ctime,
                .acl_hash = acl_hash,
                .manifest = manifest,
                .entry_count = entry_count,
            } };
        },
        2 => { // symlink
            const inode = try reader.readInt(u64, .little);
            const dev = try reader.readInt(u64, .little);
            const mode = try reader.readInt(u32, .little);
            const uid = try reader.readInt(u32, .little);
            const gid = try reader.readInt(u32, .little);
            const mtime = try reader.readInt(i64, .little);
            const ctime = try reader.readInt(i64, .little);
            var target_hash: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
            try reader.readNoEof(&target_hash);
            const target_len = try reader.readInt(u32, .little);
            const target = try allocator.alloc(u8, target_len);
            try reader.readNoEof(target);

            return records.Record{ .symlink = records.SymlinkRecord{
                .path = path,
                .inode = inode,
                .dev = dev,
                .mode = mode,
                .uid = uid,
                .gid = gid,
                .mtime = mtime,
                .ctime = ctime,
                .target = target,
                .target_hash = target_hash,
            } };
        },
        3, 4, 5, 6 => { // block, char, fifo, socket
            const inode = try reader.readInt(u64, .little);
            const dev = try reader.readInt(u64, .little);
            const mode = try reader.readInt(u32, .little);
            const uid = try reader.readInt(u32, .little);
            const gid = try reader.readInt(u32, .little);
            const mtime = try reader.readInt(i64, .little);
            const ctime = try reader.readInt(i64, .little);
            const device_id = try reader.readInt(u64, .little);

            const special_record = records.SpecialRecord{
                .path = path,
                .inode = inode,
                .dev = dev,
                .mode = mode,
                .uid = uid,
                .gid = gid,
                .mtime = mtime,
                .ctime = ctime,
                .device_id = device_id,
            };

            return switch (record_type) {
                3 => records.Record{ .block = special_record },
                4 => records.Record{ .char = special_record },
                5 => records.Record{ .fifo = special_record },
                6 => records.Record{ .socket = special_record },
                else => unreachable,
            };
        },
        else => return error.InvalidRecordType,
    }
}

/// Serialization structures for binary format
const FileRecordData = struct {
    inode: u64,
    dev: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: i64,
    ctime: i64,
    checksum: [constants.HASH_DIGEST_LENGTH]u8,
};

const DirRecordData = struct {
    inode: u64,
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: i64,
    ctime: i64,
    acl_hash: [constants.HASH_DIGEST_LENGTH]u8,
    manifest: [constants.HASH_DIGEST_LENGTH]u8,
    entry_count: u32,
};

const SymlinkRecordData = struct {
    inode: u64,
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    ctime: i64,
    target_hash: [constants.HASH_DIGEST_LENGTH]u8,
};

const SpecialRecordData = struct {
    inode: u64,
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    ctime: i64,
    device_id: u64,
};

const testing = std.testing;

test "BaselineDB initialization" {
    const allocator = testing.allocator;
    var db = BaselineDB.init(allocator);
    defer db.deinit();

    try testing.expectEqual(constants.BASELINE_DB_VERSION, db.version);
    try testing.expect(db.records.items.len == 0);
    try testing.expect(std.mem.eql(u8, &db.root_manifest, &std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8)));
    try testing.expect(std.mem.eql(u8, &db.signature, &std.mem.zeroes([64]u8)));
}

test "BaselineDB addRecord" {
    const allocator = testing.allocator;
    var db = BaselineDB.init(allocator);
    defer db.deinit();

    const record = records.Record{
        .file = records.FileRecord{
            .path = try allocator.dupe(u8, "test_file"),
            .inode = 1234,
            .dev = 5678,
            .size = 1024,
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 0,
            .ctime = 0,
            .checksum = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
        },
    };

    try db.addRecord(record);
    try testing.expectEqual(1, db.records.items.len);
    try testing.expectEqualStrings("test_file", db.records.items[0].file.path);
}

test "BaselineDB save and load" {
    const allocator = testing.allocator;
    var db = BaselineDB.init(allocator);
    defer db.deinit();

    // Add a test record
    const record = records.Record{
        .file = records.FileRecord{
            .path = try allocator.dupe(u8, "test_file.txt"),
            .inode = 1234,
            .dev = 5678,
            .size = 1024,
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .checksum = [_]u8{ 0x01, 0x02, 0x03, 0x04 } ++ [_]u8{0} ** 28,
        },
    };
    try db.addRecord(record);

    const test_path = "test_baseline.db";

    // Save the database
    try db.saveToFile(test_path);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Load the database
    var loaded_db = try BaselineDB.loadFromFile(allocator, test_path);
    defer loaded_db.deinit();

    try testing.expectEqual(db.version, loaded_db.version);
    try testing.expectEqual(db.records.items.len, loaded_db.records.items.len);
    try testing.expectEqualStrings(db.records.items[0].file.path, loaded_db.records.items[0].file.path);
    try testing.expectEqual(db.records.items[0].file.inode, loaded_db.records.items[0].file.inode);
    try testing.expectEqual(db.records.items[0].file.size, loaded_db.records.items[0].file.size);
}

test "Database serialization round-trip with different record types" {
    const allocator = testing.allocator;
    var db = BaselineDB.init(allocator);
    defer db.deinit();

    // Add different types of records
    try db.addRecord(records.Record{
        .file = records.FileRecord{
            .path = try allocator.dupe(u8, "/test/file.txt"),
            .inode = 123,
            .dev = 456,
            .size = 2048,
            .mode = 0o644,
            .uid = 1000,
            .gid = 1000,
            .nlink = 1,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .checksum = [_]u8{0x01} ** 32,
        },
    });

    try db.addRecord(records.Record{
        .dir = records.DirRecord{
            .path = try allocator.dupe(u8, "/test/dir"),
            .inode = 789,
            .dev = 456,
            .mode = 0o755,
            .uid = 1000,
            .gid = 1000,
            .nlink = 2,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .acl_hash = [_]u8{0x02} ** 32,
            .manifest = [_]u8{0x03} ** 32,
            .entry_count = 5,
        },
    });

    try db.addRecord(records.Record{
        .symlink = records.SymlinkRecord{
            .path = try allocator.dupe(u8, "/test/link"),
            .inode = 321,
            .dev = 456,
            .mode = 0o777,
            .uid = 1000,
            .gid = 1000,
            .mtime = 1609459200,
            .ctime = 1609459200,
            .target = try allocator.dupe(u8, "/test/target"),
            .target_hash = [_]u8{0x04} ** 32,
        },
    });

    const test_path = "test_multi_record.db";

    // Save and reload
    try db.saveToFile(test_path);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    var loaded_db = try BaselineDB.loadFromFile(allocator, test_path);
    defer loaded_db.deinit();

    // Verify all records were preserved
    try testing.expectEqual(@as(usize, 3), loaded_db.records.items.len);

    // Check file record
    try testing.expect(loaded_db.records.items[0] == .file);
    try testing.expectEqualStrings("/test/file.txt", loaded_db.records.items[0].file.path);
    try testing.expectEqual(@as(u64, 2048), loaded_db.records.items[0].file.size);

    // Check dir record
    try testing.expect(loaded_db.records.items[1] == .dir);
    try testing.expectEqualStrings("/test/dir", loaded_db.records.items[1].dir.path);
    try testing.expectEqual(@as(u32, 5), loaded_db.records.items[1].dir.entry_count);

    // Check symlink record
    try testing.expect(loaded_db.records.items[2] == .symlink);
    try testing.expectEqualStrings("/test/link", loaded_db.records.items[2].symlink.path);
    try testing.expectEqualStrings("/test/target", loaded_db.records.items[2].symlink.target);
}

test "BaselineDB saveToFileBatched basic functionality" {
    const allocator = testing.allocator;

    var db = BaselineDB.init(allocator);
    defer db.deinit();

    // Add multiple records to test batching
    var i: usize = 0;
    while (i < 1500) : (i += 1) { // More than BATCH_SIZE (1000)
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "/test/file_{}.txt", .{i});
        const owned_path = try allocator.dupe(u8, path);

        try db.addRecord(records.Record{
            .file = records.FileRecord{
                .path = owned_path,
                .checksum = [_]u8{@intCast(i % 256)} ** 32,
                .size = 1024 + i,
                .inode = @intCast(i + 1000),
                .dev = 2049,
                .mode = 0o644,
                .uid = 1000,
                .gid = 1000,
                .nlink = 1,
                .mtime = 1609459200,
                .ctime = 1609459200,
            },
        });
    }

    const test_path = "test_batched.db";

    // Test batched save
    try db.saveToFileBatched(test_path);
    defer std.fs.cwd().deleteFile(test_path) catch {};

    // Verify the file was created
    var file = try std.fs.cwd().openFile(test_path, .{});
    file.close();

    // Load and verify
    var loaded_db = try BaselineDB.loadFromFile(allocator, test_path);
    defer loaded_db.deinit();

    try testing.expectEqual(@as(usize, 1500), loaded_db.records.items.len);

    // Verify first and last records
    try testing.expect(loaded_db.records.items[0] == .file);
    try testing.expectEqualStrings("/test/file_0.txt", loaded_db.records.items[0].file.path);

    try testing.expect(loaded_db.records.items[1499] == .file);
    try testing.expectEqualStrings("/test/file_1499.txt", loaded_db.records.items[1499].file.path);
}

test "BaselineDB saveToFileOptimized chooses correct method" {
    const allocator = testing.allocator;

    // Test small database (should use regular save)
    var small_db = BaselineDB.init(allocator);
    defer small_db.deinit();

    // Add fewer records than BATCH_SIZE
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "/test/small_{}.txt", .{i});
        const owned_path = try allocator.dupe(u8, path);

        try small_db.addRecord(records.Record{
            .file = records.FileRecord{
                .path = owned_path,
                .checksum = [_]u8{@intCast(i)} ** 32,
                .size = 1024,
                .inode = @intCast(i + 1000),
                .dev = 2049,
                .mode = 0o644,
                .uid = 1000,
                .gid = 1000,
                .nlink = 1,
                .mtime = 1609459200,
                .ctime = 1609459200,
            },
        });
    }

    const small_test_path = "test_optimized_small.db";
    try small_db.saveToFileOptimized(small_test_path);
    defer std.fs.cwd().deleteFile(small_test_path) catch {};

    // Test large database (should use batched save)
    var large_db = BaselineDB.init(allocator);
    defer large_db.deinit();

    // Add more records than BATCH_SIZE
    i = 0;
    while (i < 1200) : (i += 1) {
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "/test/large_{}.txt", .{i});
        const owned_path = try allocator.dupe(u8, path);

        try large_db.addRecord(records.Record{
            .file = records.FileRecord{
                .path = owned_path,
                .checksum = [_]u8{@intCast(i % 256)} ** 32,
                .size = 1024,
                .inode = @intCast(i + 2000),
                .dev = 2049,
                .mode = 0o644,
                .uid = 1000,
                .gid = 1000,
                .nlink = 1,
                .mtime = 1609459200,
                .ctime = 1609459200,
            },
        });
    }

    const large_test_path = "test_optimized_large.db";
    try large_db.saveToFileOptimized(large_test_path);
    defer std.fs.cwd().deleteFile(large_test_path) catch {};

    // Verify both files were created successfully
    var small_file = try std.fs.cwd().openFile(small_test_path, .{});
    small_file.close();

    var large_file = try std.fs.cwd().openFile(large_test_path, .{});
    large_file.close();
}

test "BaselineDB saveToFileBatched produces same result as saveToFile" {
    const allocator = testing.allocator;

    var db = BaselineDB.init(allocator);
    defer db.deinit();

    // Add some test records
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var path_buffer: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buffer, "/test/compare_{}.txt", .{i});
        const owned_path = try allocator.dupe(u8, path);

        try db.addRecord(records.Record{
            .file = records.FileRecord{
                .path = owned_path,
                .checksum = [_]u8{@intCast(i)} ** 32,
                .size = 1024 + i,
                .inode = @intCast(i + 3000),
                .dev = 2049,
                .mode = 0o644,
                .uid = 1000,
                .gid = 1000,
                .nlink = 1,
                .mtime = 1609459200,
                .ctime = 1609459200,
            },
        });
    }

    const regular_path = "test_regular.db";
    const batched_path = "test_batched_compare.db";

    // Save with both methods
    try db.saveToFile(regular_path);
    defer std.fs.cwd().deleteFile(regular_path) catch {};

    try db.saveToFileBatched(batched_path);
    defer std.fs.cwd().deleteFile(batched_path) catch {};

    // Load both and verify they're identical
    var regular_db = try BaselineDB.loadFromFile(allocator, regular_path);
    defer regular_db.deinit();

    var batched_db = try BaselineDB.loadFromFile(allocator, batched_path);
    defer batched_db.deinit();

    // Should have same number of records
    try testing.expectEqual(regular_db.records.items.len, batched_db.records.items.len);
    try testing.expectEqual(@as(usize, 100), regular_db.records.items.len);

    // Verify all records are identical
    for (regular_db.records.items, batched_db.records.items) |regular_record, batched_record| {
        try testing.expect(regular_record == .file);
        try testing.expect(batched_record == .file);

        try testing.expectEqualStrings(regular_record.file.path, batched_record.file.path);
        try testing.expectEqual(regular_record.file.size, batched_record.file.size);
        try testing.expectEqual(regular_record.file.inode, batched_record.file.inode);
        try testing.expectEqualSlices(u8, &regular_record.file.checksum, &batched_record.file.checksum);
    }
}
