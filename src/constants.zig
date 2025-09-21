// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

// File hashing constants
pub const HASH_DIGEST_LENGTH: usize = 32; // BLAKE3 hash size in bytes
pub const HASH_HEX_LENGTH: usize = 64; // BLAKE3 hash hex string length

// File I/O buffer sizes
pub const SMALL_FILE_THRESHOLD: u64 = 16 * 1024 * 1024; // 16MB
pub const LARGE_FILE_BUFFER_SIZE: usize = 64 * 1024; // 64KB
pub const MEDIUM_FILE_BUFFER_SIZE: usize = 8 * 1024; // 8KB
pub const SMALL_FILE_BUFFER_SIZE: usize = 4 * 1024; // 4KB

// Database constants
pub const BASELINE_DB_VERSION: u32 = 1;
pub const DEFAULT_BASELINE_FILENAME: []const u8 = "baseline.db";

// File metadata constants
pub const DEFAULT_UID: u32 = 0;
pub const DEFAULT_GID: u32 = 0;

// Memory limits
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_FILES_PER_SCAN: usize = 1_000_000;

// Error handling
pub const MAX_PERMISSION_ERRORS: usize = 100;
