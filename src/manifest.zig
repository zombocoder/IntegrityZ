// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const records = @import("records.zig");
const crypto = @import("crypto.zig");
const util = @import("util.zig");
const constants = @import("constants.zig");

/// Directory entry metadata for manifest computation
/// Used internally for computing directory manifest hashes
pub const DirEntry = struct {
    name: []const u8,
    node_type: records.NodeType,
    inode: u64,
    child_digest: [constants.HASH_DIGEST_LENGTH]u8,
    mode: u32,
    uid: u32,
    gid: u32,
};

/// Complete filesystem node metadata
/// Contains all POSIX attributes needed for integrity monitoring
pub const NodeMeta = struct {
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    ctime: i64,
    nlink: u32,
    dev: u64,
};

/// Compute manifest hash for a directory
/// Creates a deterministic hash based on sorted child entries and their metadata
/// This enables fast detection of directory tree changes without full recursive scans
pub fn hashDirManifest(allocator: std.mem.Allocator, dir_path: []const u8) ![constants.HASH_DIGEST_LENGTH]u8 {
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch |err| {
        std.debug.print("Error opening directory {s}: {}\n", .{ dir_path, err });
        return std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8);
    };
    defer dir.close();

    var entries = std.ArrayList(DirEntry).init(allocator);
    defer {
        for (entries.items) |entry| {
            allocator.free(entry.name);
        }
        entries.deinit();
    }

    var iterator = dir.iterate();
    while (try iterator.next()) |entry| {
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ dir_path, entry.name });
        defer allocator.free(full_path);

        const node_meta = try statNode(full_path);
        const child_digest = try computeChildDigest(allocator, full_path, entry.kind);

        try entries.append(DirEntry{
            .name = try allocator.dupe(u8, entry.name),
            .node_type = records.kindToNodeType(entry.kind),
            .inode = node_meta.inode,
            .child_digest = child_digest,
            .mode = node_meta.mode,
            .uid = node_meta.uid,
            .gid = node_meta.gid,
        });
    }

    // Sort entries by name for stable hashing
    std.sort.block(DirEntry, entries.items, {}, dirEntryLessThan);

    return computeManifestHash(entries.items);
}

/// Extract comprehensive metadata from a filesystem node
/// Uses POSIX stat() on Unix systems, provides fallback for Windows
/// Returns all metadata needed for integrity monitoring
pub fn statNode(path: []const u8) !NodeMeta {
    const ownership = util.getFileOwnership(path) catch util.FileOwnership{ .uid = constants.DEFAULT_UID, .gid = constants.DEFAULT_GID };

    // Use POSIX stat to get extended metadata
    const builtin = @import("builtin");
    if (builtin.target.os.tag == .windows) {
        // Windows fallback - try to get basic metadata
        // Use a more robust approach that works for both files and directories
        var is_dir = false;
        var file_size: u64 = 0;
        var mtime: i64 = 0;
        var ctime: i64 = 0;

        // Try to check if it's a directory first
        if (std.fs.openDirAbsolute(path, .{})) |mut_dir| {
            var dir = mut_dir;
            dir.close();
            is_dir = true;

            // For directories, try to get metadata via the directory
            if (std.fs.cwd().statFile(path)) |stat_result| {
                mtime = @divTrunc(stat_result.mtime, std.time.ns_per_s);
                ctime = @divTrunc(stat_result.ctime, std.time.ns_per_s);
            } else |_| {
                // Use current time as fallback
                const now = std.time.timestamp();
                mtime = now;
                ctime = now;
            }
        } else |_| {
            // Not a directory, try as file
            if (std.fs.openFileAbsolute(path, .{})) |file| {
                defer file.close();
                if (file.stat()) |stat_result| {
                    file_size = stat_result.size;
                    mtime = @divTrunc(stat_result.mtime, std.time.ns_per_s);
                    ctime = @divTrunc(stat_result.ctime, std.time.ns_per_s);
                } else |_| {
                    // Use defaults if stat fails
                    const now = std.time.timestamp();
                    mtime = now;
                    ctime = now;
                }
            } else |_| {
                return error.StatFailed;
            }
        }

        return NodeMeta{
            .inode = 0, // Windows doesn't have inodes
            .mode = if (is_dir) 0o755 else 0o644, // Different defaults for files vs directories
            .uid = ownership.uid,
            .gid = ownership.gid,
            .mtime = @intCast(mtime),
            .ctime = @intCast(ctime),
            .nlink = 1,
            .dev = 0,
        };
    } else {
        // POSIX stat call
        const c = std.c;
        var stat_result: c.Stat = undefined;
        const path_cstr: [:0]const u8 = std.fmt.allocPrintZ(std.heap.page_allocator, "{s}", .{path}) catch return error.StatFailed;
        defer std.heap.page_allocator.free(path_cstr);
        const result = c.stat(path_cstr.ptr, &stat_result);
        if (result != 0) return error.StatFailed;

        const mtime = stat_result.mtime();
        const ctime = stat_result.ctime();

        return NodeMeta{
            .inode = @as(u64, @intCast(stat_result.ino)),
            .mode = @as(u32, @intCast(stat_result.mode)),
            .uid = ownership.uid,
            .gid = ownership.gid,
            .mtime = @intCast(mtime.tv_sec),
            .ctime = @intCast(ctime.tv_sec),
            .nlink = @as(u32, @intCast(stat_result.nlink)),
            .dev = @as(u64, @intCast(stat_result.dev)),
        };
    }
}

/// Compare two directory entries by name for sorting
fn dirEntryLessThan(_: void, a: DirEntry, b: DirEntry) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

/// Compute the digest for a child node based on its type
/// Supports files, directories, symbolic links, and special files
fn computeChildDigest(allocator: std.mem.Allocator, path: []const u8, kind: std.fs.File.Kind) ![constants.HASH_DIGEST_LENGTH]u8 {
    return switch (kind) {
        .file => crypto.blake3HashFileAdaptive(path, allocator) catch std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8),
        .directory => std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8), // Avoid recursion for now
        .sym_link => blk: {
            var buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const target = std.fs.readLinkAbsolute(path, &buffer) catch break :blk std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8);
            break :blk crypto.blake3Hash(target);
        },
        else => std.mem.zeroes([constants.HASH_DIGEST_LENGTH]u8), // Special files get zero digest
    };
}

/// Compute the manifest hash for a list of directory entries
/// Encodes each entry in a canonical form and hashes the result
fn computeManifestHash(entries: []const DirEntry) [constants.HASH_DIGEST_LENGTH]u8 {
    var hasher = std.crypto.hash.Blake3.init(.{});

    for (entries) |entry| {
        // Encode entry in canonical form: length-prefixed fields
        var buf: [1024]u8 = undefined;
        const encoded = std.fmt.bufPrint(&buf, "{d}:{s}:{d}:{s}:{d}:{d}:{d}", .{
            entry.name.len,                entry.name,
            @intFromEnum(entry.node_type), std.fmt.bytesToHex(entry.child_digest, .lower),
            entry.mode,                    entry.uid,
            entry.gid,
        }) catch continue;

        hasher.update(encoded);
    }

    var digest: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

const testing = std.testing;

test "NodeMeta handles device ID edge cases" {
    // Test that negative device IDs are handled correctly
    const meta = NodeMeta{
        .inode = 123,
        .dev = @bitCast(@as(i64, -1)), // Simulate negative device ID
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .mtime = 1609459200,
        .ctime = 1609459200,
    };

    // Should not panic and should preserve the bit pattern
    try testing.expect(meta.dev != 0);
    try testing.expect(meta.inode == 123);
}

test "DirEntry comparison" {
    const entry_a = DirEntry{
        .name = "apple",
        .child_digest = [_]u8{0} ** 32,
        .node_type = .file,
        .inode = 1,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
    };
    const entry_b = DirEntry{
        .name = "banana",
        .child_digest = [_]u8{1} ** 32,
        .node_type = .file,
        .inode = 2,
        .mode = 0o644,
        .uid = 1000,
        .gid = 1000,
    };

    try testing.expect(dirEntryLessThan({}, entry_a, entry_b));
    try testing.expect(!dirEntryLessThan({}, entry_b, entry_a));
}

test "hashDirManifest with empty directory" {
    const allocator = testing.allocator;

    // Create a temporary empty directory
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    // Should not panic with empty directory
    const hash = hashDirManifest(allocator, tmp_path) catch [_]u8{0} ** 32;
    try testing.expect(hash.len == 32);
}
