// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const constants = @import("constants.zig");

/// Filesystem node types supported by IntegrityZ
pub const NodeType = enum { file, dir, symlink, block, char, fifo, socket };

/// Metadata record for regular files
/// Contains comprehensive file attributes including BLAKE3 hash for content integrity
pub const FileRecord = struct {
    path: []const u8,
    inode: u64,
    dev: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: i64,
    ctime: i64,
    checksum: [constants.HASH_DIGEST_LENGTH]u8, // BLAKE3 hash

    /// Cleanup allocated memory for this file record
    pub fn deinit(self: *FileRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

/// Metadata record for directories
/// Includes manifest hash computed from sorted child entries for fast tree diffs
pub const DirRecord = struct {
    path: []const u8,
    inode: u64,
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: i64,
    ctime: i64,
    acl_hash: [constants.HASH_DIGEST_LENGTH]u8, // BLAKE3 of canonical ACL/xattrs
    manifest: [constants.HASH_DIGEST_LENGTH]u8, // BLAKE3 over sorted child entries
    entry_count: u32,

    /// Cleanup allocated memory for this directory record
    pub fn deinit(self: *DirRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

/// Metadata record for symbolic links
/// Stores both the target path and its BLAKE3 hash for integrity verification
pub const SymlinkRecord = struct {
    path: []const u8,
    inode: u64,
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    ctime: i64,
    target: []const u8,
    target_hash: [constants.HASH_DIGEST_LENGTH]u8, // BLAKE3(target)

    /// Cleanup allocated memory for this symlink record
    pub fn deinit(self: *SymlinkRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.target);
    }
};

/// Metadata record for special filesystem nodes
/// Includes block devices, character devices, FIFOs, and Unix domain sockets
pub const SpecialRecord = struct {
    path: []const u8,
    inode: u64,
    dev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    ctime: i64,
    device_id: u64, // For block/char devices

    /// Cleanup allocated memory for this special file record
    pub fn deinit(self: *SpecialRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
    }
};

/// Union type representing any filesystem node record
/// Uses tagged union to efficiently store different node types
pub const Record = union(NodeType) {
    file: FileRecord,
    dir: DirRecord,
    symlink: SymlinkRecord,
    block: SpecialRecord,
    char: SpecialRecord,
    fifo: SpecialRecord,
    socket: SpecialRecord,

    /// Cleanup allocated memory for any record type
    pub fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .file => |*record| record.deinit(allocator),
            .dir => |*record| record.deinit(allocator),
            .symlink => |*record| record.deinit(allocator),
            .block, .char, .fifo, .socket => |*record| record.deinit(allocator),
        }
    }

    /// Get the filesystem path for any record type
    pub fn getPath(self: *const Record) []const u8 {
        return switch (self.*) {
            .file => |record| record.path,
            .dir => |record| record.path,
            .symlink => |record| record.path,
            .block, .char, .fifo, .socket => |record| record.path,
        };
    }
};

/// Extract the mode (permissions) from any record type
pub fn getRecordMode(record: *const Record) u32 {
    return switch (record.*) {
        .file => |r| r.mode,
        .dir => |r| r.mode,
        .symlink => |r| r.mode,
        .block, .char, .fifo, .socket => |r| r.mode,
    };
}

/// Extract the modification time from any record type
pub fn getRecordMtime(record: *const Record) i64 {
    return switch (record.*) {
        .file => |r| r.mtime,
        .dir => |r| r.mtime,
        .symlink => |r| r.mtime,
        .block, .char, .fifo, .socket => |r| r.mtime,
    };
}

/// Extract the change time from any record type
pub fn getRecordCtime(record: *const Record) i64 {
    return switch (record.*) {
        .file => |r| r.ctime,
        .dir => |r| r.ctime,
        .symlink => |r| r.ctime,
        .block, .char, .fifo, .socket => |r| r.ctime,
    };
}

/// Convert Zig's File.Kind enum to IntegrityZ's NodeType enum
pub fn kindToNodeType(kind: std.fs.File.Kind) NodeType {
    return switch (kind) {
        .file => .file,
        .directory => .dir,
        .sym_link => .symlink,
        .block_device => .block,
        .character_device => .char,
        .named_pipe => .fifo,
        .unix_domain_socket => .socket,
        else => .file, // Default fallback
    };
}

// Unit tests
test "kindToNodeType conversion" {
    try std.testing.expectEqual(NodeType.file, kindToNodeType(.file));
    try std.testing.expectEqual(NodeType.dir, kindToNodeType(.directory));
    try std.testing.expectEqual(NodeType.symlink, kindToNodeType(.sym_link));
    try std.testing.expectEqual(NodeType.block, kindToNodeType(.block_device));
    try std.testing.expectEqual(NodeType.char, kindToNodeType(.character_device));
    try std.testing.expectEqual(NodeType.fifo, kindToNodeType(.named_pipe));
    try std.testing.expectEqual(NodeType.socket, kindToNodeType(.unix_domain_socket));

    // Test fallback for unknown types
    try std.testing.expectEqual(NodeType.file, kindToNodeType(.unknown));
}

test "FileRecord creation and cleanup" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_path = "/test/path/file.txt";
    var file_record = FileRecord{
        .path = try allocator.dupe(u8, test_path),
        .inode = 12345,
        .dev = 67890,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1640995200, // 2022-01-01 00:00:00 UTC
        .ctime = 1640995200,
        .checksum = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
    };

    // Verify the path is correctly set
    try std.testing.expectEqualStrings(test_path, file_record.path);

    // Test cleanup
    file_record.deinit(allocator);
}

test "Record union getPath method" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_path = "/test/file.txt";

    // Create a file record wrapped in the Record union
    var record = Record{ .file = FileRecord{
        .path = try allocator.dupe(u8, test_path),
        .inode = 12345,
        .dev = 67890,
        .size = 1024,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1640995200,
        .ctime = 1640995200,
        .checksum = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
    } };

    // Test getPath method
    try std.testing.expectEqualStrings(test_path, record.getPath());

    // Test deinit method
    record.deinit(allocator);
}

test "Record utility functions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_path = "/test/file.txt";
    const test_mode: u32 = 0o644;
    const test_mtime: i64 = 1640995200;
    const test_ctime: i64 = 1640995210;

    var record = Record{ .file = FileRecord{
        .path = try allocator.dupe(u8, test_path),
        .inode = 12345,
        .dev = 67890,
        .size = 1024,
        .mode = test_mode,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = test_mtime,
        .ctime = test_ctime,
        .checksum = std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
    } };
    defer record.deinit(allocator);

    // Test utility functions
    try std.testing.expectEqual(test_mode, getRecordMode(&record));
    try std.testing.expectEqual(test_mtime, getRecordMtime(&record));
    try std.testing.expectEqual(test_ctime, getRecordCtime(&record));
}
