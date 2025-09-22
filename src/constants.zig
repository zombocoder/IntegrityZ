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

// Adaptive buffer sizes for different storage types
pub const STORAGE_BUFFER_SIZES = struct {
    pub const SSD_BUFFER_SIZE: usize = 1024 * 1024; // 1MB for SSDs - better performance with larger buffers
    pub const HDD_BUFFER_SIZE: usize = 64 * 1024; // 64KB for HDDs - balances seek time vs memory
    pub const NETWORK_BUFFER_SIZE: usize = 32 * 1024; // 32KB for network storage - reduces network calls
    pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024; // 64KB default fallback
    pub const LARGE_FILE_MULTIPLIER: usize = 4; // Multiply buffer size by this for large files
    pub const MAX_BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4MB maximum buffer size
};

// Performance thresholds for optimization
pub const PERFORMANCE_THRESHOLDS = struct {
    pub const LARGE_FILE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB - consider parallel processing
    pub const PARALLEL_CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64MB chunks for parallel hashing
    pub const MANY_FILES_THRESHOLD: usize = 100_000; // Switch to parallel scanning above this
};

// Parallel processing constants
pub const PARALLEL_PROCESSING = struct {
    pub const MAX_WORKER_THREADS: usize = 8; // Maximum number of worker threads
    pub const WORK_QUEUE_SIZE: usize = 1000; // Maximum items in work queue
    pub const PATH_BUFFER_SIZE: usize = 4096; // Buffer size for path handling
};

// Database constants
pub const BASELINE_DB_VERSION: u32 = 1;
pub const DEFAULT_BASELINE_FILENAME: []const u8 = "baseline.db";

// Database I/O optimization constants
pub const DATABASE_IO = struct {
    pub const WRITE_BUFFER_SIZE: usize = 1024 * 1024; // 1MB write buffer
    pub const BATCH_SIZE: usize = 1000; // Records per batch
    pub const COMPRESSION_THRESHOLD: usize = 10_000; // Enable compression above this many records
};

// File metadata constants
pub const DEFAULT_UID: u32 = 0;
pub const DEFAULT_GID: u32 = 0;

// Memory limits
pub const MAX_PATH_LENGTH: usize = 4096;
pub const MAX_FILES_PER_SCAN: usize = 1_000_000;

// Error handling
pub const MAX_PERMISSION_ERRORS: usize = 100;
