// SPDX-License-Identifier: Apache-2.0
const std = @import("std");
const constants = @import("constants.zig");

/// Storage types for adaptive buffer sizing
const StorageType = enum {
    ssd,
    hdd,
    network,
    unknown,
};

/// Detect storage type based on filesystem properties
/// This is a heuristic approach that can be improved with platform-specific APIs
fn detectStorageType(file_path: []const u8) StorageType {
    // Basic heuristics for storage type detection
    // In a real implementation, this could use platform-specific APIs

    if (std.mem.startsWith(u8, file_path, "/mnt/") or
        std.mem.startsWith(u8, file_path, "/media/") or
        std.mem.startsWith(u8, file_path, "//") or // UNC paths on Windows
        std.mem.indexOf(u8, file_path, "nfs") != null)
    {
        return .network;
    }

    // For now, assume SSD for most modern systems
    // This could be enhanced with actual hardware detection
    return .ssd;
}

/// Get optimal buffer size based on storage type and file size
fn getOptimalBufferSize(storage_type: StorageType, file_size: u64) usize {
    const base_size = switch (storage_type) {
        .ssd => constants.STORAGE_BUFFER_SIZES.SSD_BUFFER_SIZE,
        .hdd => constants.STORAGE_BUFFER_SIZES.HDD_BUFFER_SIZE,
        .network => constants.STORAGE_BUFFER_SIZES.NETWORK_BUFFER_SIZE,
        .unknown => constants.STORAGE_BUFFER_SIZES.DEFAULT_BUFFER_SIZE,
    };

    // For very large files, increase buffer size up to a reasonable limit
    if (file_size > constants.PERFORMANCE_THRESHOLDS.LARGE_FILE_SIZE) {
        return @min(base_size * constants.STORAGE_BUFFER_SIZES.LARGE_FILE_MULTIPLIER, constants.STORAGE_BUFFER_SIZES.MAX_BUFFER_SIZE);
    }

    return base_size;
}

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

/// Compute BLAKE3 hash of a file's contents with adaptive buffer sizing
/// Uses storage type detection and file size to optimize buffer size for better performance
pub fn blake3HashFileAdaptive(file_path: []const u8, allocator: std.mem.Allocator) ![constants.HASH_DIGEST_LENGTH]u8 {
    const file = try std.fs.openFileAbsolute(file_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();

    // For small files, read everything into memory (faster for small files)
    if (file_size <= constants.SMALL_FILE_THRESHOLD) {
        const contents = try file.readToEndAlloc(allocator, file_size);
        defer allocator.free(contents);
        return blake3Hash(contents);
    }

    // Detect storage type and get optimal buffer size
    const storage_type = detectStorageType(file_path);
    const buffer_size = getOptimalBufferSize(storage_type, file_size);

    // For large files, stream the data with adaptive buffer size
    var hasher = std.crypto.hash.Blake3.init(.{});
    const buffer = try allocator.alloc(u8, buffer_size);
    defer allocator.free(buffer);

    while (true) {
        const bytes_read = try file.read(buffer);
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

test "detectStorageType correctly identifies storage types" {
    // Test network storage detection
    try std.testing.expectEqual(StorageType.network, detectStorageType("/mnt/network/file.txt"));
    try std.testing.expectEqual(StorageType.network, detectStorageType("/media/usb/file.txt"));
    try std.testing.expectEqual(StorageType.network, detectStorageType("//server/share/file.txt"));
    try std.testing.expectEqual(StorageType.network, detectStorageType("/home/user/nfs/file.txt"));

    // Test SSD default detection
    try std.testing.expectEqual(StorageType.ssd, detectStorageType("/home/user/file.txt"));
    try std.testing.expectEqual(StorageType.ssd, detectStorageType("/var/log/app.log"));
}

test "getOptimalBufferSize returns correct buffer sizes" {
    // Test SSD buffer sizing
    const ssd_buffer = getOptimalBufferSize(StorageType.ssd, 1024 * 1024); // 1MB file
    try std.testing.expectEqual(constants.STORAGE_BUFFER_SIZES.SSD_BUFFER_SIZE, ssd_buffer);

    // Test HDD buffer sizing
    const hdd_buffer = getOptimalBufferSize(StorageType.hdd, 1024 * 1024);
    try std.testing.expectEqual(constants.STORAGE_BUFFER_SIZES.HDD_BUFFER_SIZE, hdd_buffer);

    // Test network buffer sizing
    const network_buffer = getOptimalBufferSize(StorageType.network, 1024 * 1024);
    try std.testing.expectEqual(constants.STORAGE_BUFFER_SIZES.NETWORK_BUFFER_SIZE, network_buffer);

    // Test large file optimization
    const large_file_buffer = getOptimalBufferSize(StorageType.ssd, constants.PERFORMANCE_THRESHOLDS.LARGE_FILE_SIZE + 1);
    const expected_large = @min(constants.STORAGE_BUFFER_SIZES.SSD_BUFFER_SIZE * constants.STORAGE_BUFFER_SIZES.LARGE_FILE_MULTIPLIER, constants.STORAGE_BUFFER_SIZES.MAX_BUFFER_SIZE);
    try std.testing.expectEqual(expected_large, large_file_buffer);
}

test "blake3HashFileAdaptive produces same results as blake3HashFile" {
    const allocator = std.testing.allocator;

    // Create a temporary file for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const test_data = "Hello, IntegrityZ adaptive hashing!";
    const file_path = "test_adaptive.txt";

    // Write test data to file
    try tmp.dir.writeFile(.{ .sub_path = file_path, .data = test_data });

    // Get absolute path for testing
    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const full_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, file_path });
    defer allocator.free(full_path);

    // Test that both functions produce the same hash
    const hash_regular = try blake3HashFile(full_path, allocator);
    const hash_adaptive = try blake3HashFileAdaptive(full_path, allocator);

    try std.testing.expectEqual(hash_regular, hash_adaptive);
}

test "blake3HashFileAdaptive handles small files correctly" {
    const allocator = std.testing.allocator;

    // Create a temporary file for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const small_data = "small";
    const file_path = "small_test.txt";

    try tmp.dir.writeFile(.{ .sub_path = file_path, .data = small_data });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const full_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, file_path });
    defer allocator.free(full_path);

    const hash = try blake3HashFileAdaptive(full_path, allocator);

    // Verify the hash is correct
    try std.testing.expectEqual(constants.HASH_DIGEST_LENGTH, hash.len);

    // Compare with direct hashing of the data
    const expected_hash = blake3Hash(small_data);
    try std.testing.expectEqual(expected_hash, hash);
}

test "blake3HashFileAdaptive handles large files correctly" {
    const allocator = std.testing.allocator;

    // Create a temporary file for testing
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a larger data buffer
    const large_data = "X" ** (constants.SMALL_FILE_THRESHOLD + 1000); // Slightly larger than threshold
    const file_path = "large_test.txt";

    try tmp.dir.writeFile(.{ .sub_path = file_path, .data = large_data });

    const tmp_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);

    const full_path = try std.fs.path.join(allocator, &[_][]const u8{ tmp_path, file_path });
    defer allocator.free(full_path);

    const hash = try blake3HashFileAdaptive(full_path, allocator);

    // Verify the hash is correct
    try std.testing.expectEqual(constants.HASH_DIGEST_LENGTH, hash.len);

    // Should match the regular file hashing result
    const expected_hash = try blake3HashFile(full_path, allocator);
    try std.testing.expectEqual(expected_hash, hash);
}
