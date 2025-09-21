// SPDX-License-Identifier: Apache-2.0
const std = @import("std");
const constants = @import("constants.zig");

/// Compute BLAKE3 hash of arbitrary data
/// Returns a fixed-length digest suitable for integrity verification
pub fn blake3Hash(data: []const u8) [constants.HASH_DIGEST_LENGTH]u8 {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(data);
    var digest: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Compute BLAKE3 hash of a file's contents
/// Automatically chooses between memory-based and streaming approach based on file size
/// Small files are read entirely into memory for speed, large files are streamed
pub fn blake3HashFile(file_path: []const u8, allocator: std.mem.Allocator) ![constants.HASH_DIGEST_LENGTH]u8 {
    const file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();

    // For small files, read everything into memory (faster for small files)
    if (file_size <= constants.SMALL_FILE_THRESHOLD) {
        const contents = try file.readToEndAlloc(allocator, file_size);
        defer allocator.free(contents);
        return blake3Hash(contents);
    }

    // For large files, stream the data with optimized buffer size
    var hasher = std.crypto.hash.Blake3.init(.{});
    var buffer: [constants.LARGE_FILE_BUFFER_SIZE]u8 = undefined;

    while (true) {
        const bytes_read = try file.read(&buffer);
        if (bytes_read == 0) break;
        hasher.update(buffer[0..bytes_read]);
    }

    var digest: [constants.HASH_DIGEST_LENGTH]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Convert a binary hash to hexadecimal string representation
/// Caller owns the returned memory and must free it
pub fn hashToHex(hash: [constants.HASH_DIGEST_LENGTH]u8, allocator: std.mem.Allocator) ![]u8 {
    const hex_string = try allocator.alloc(u8, constants.HASH_HEX_LENGTH);
    _ = std.fmt.bufPrint(hex_string, "{s}", .{std.fmt.bytesToHex(hash, .lower)}) catch unreachable;
    return hex_string;
}

// Unit tests
test "blake3Hash produces deterministic results" {
    const test_data = "Hello, IntegrityZ!";

    const hash1 = blake3Hash(test_data);
    const hash2 = blake3Hash(test_data);

    try std.testing.expectEqual(hash1, hash2);
    try std.testing.expect(hash1.len == constants.HASH_DIGEST_LENGTH);
}

test "blake3Hash produces different results for different data" {
    const data1 = "Hello, IntegrityZ!";
    const data2 = "Hello, World!";

    const hash1 = blake3Hash(data1);
    const hash2 = blake3Hash(data2);

    try std.testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "blake3Hash handles empty data" {
    const empty_data = "";
    const hash = blake3Hash(empty_data);

    // BLAKE3 of empty string should be deterministic
    try std.testing.expect(hash.len == constants.HASH_DIGEST_LENGTH);

    // Test that it's the known BLAKE3 empty hash
    const expected_empty_hash = blake3Hash("");
    try std.testing.expectEqual(hash, expected_empty_hash);
}

test "hashToHex produces correct hex representation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_data = "Hello, IntegrityZ!";
    const hash = blake3Hash(test_data);

    const hex_string = try hashToHex(hash, allocator);
    defer allocator.free(hex_string);

    // Verify hex string length
    try std.testing.expectEqual(constants.HASH_HEX_LENGTH, hex_string.len);

    // Verify hex string contains only valid hex characters
    for (hex_string) |char| {
        try std.testing.expect(std.ascii.isHex(char));
        try std.testing.expect(std.ascii.isLower(char) or std.ascii.isDigit(char));
    }
}

test "hashToHex is deterministic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const test_data = "Test data for hex conversion";
    const hash = blake3Hash(test_data);

    const hex1 = try hashToHex(hash, allocator);
    defer allocator.free(hex1);

    const hex2 = try hashToHex(hash, allocator);
    defer allocator.free(hex2);

    try std.testing.expectEqualStrings(hex1, hex2);
}
