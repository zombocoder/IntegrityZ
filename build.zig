// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

/// Zig build configuration for IntegrityZ filesystem integrity monitor
/// Supports cross-compilation to multiple platforms and comprehensive testing
pub fn build(b: *std.Build) void {
    // Standard build options for target platform and optimization level
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main executable configuration
    const exe = b.addExecutable(.{
        .name = "integrityz",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link against libc for system calls and file operations
    exe.linkLibC();

    // Install the executable to zig-out/bin/
    b.installArtifact(exe);

    // Configure run command with argument forwarding
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // Forward command line arguments to the application
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Create 'zig build run' step for easy execution
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Comprehensive test suite - automatically discovers all tests
    // Add new source files here to include their tests in the suite
    const test_files = [_][]const u8{
        "src/crypto.zig", // Cryptographic hash functions and utilities
        "src/records.zig", // Filesystem record structures and operations
        "src/manifest.zig", // Directory manifest generation and validation
        "src/baseline.zig", // Baseline database creation and management
        "src/display.zig", // Record display and formatting functions
        "src/scanner.zig", // Filesystem scanning and traversal
        "src/util.zig", // Utility functions (permissions, timestamps, etc.)
        "src/main.zig", // Main application entry point and CLI tests
        "src/database.zig", // Database interaction and storage tests
        "src/checker.zig", // Integrity checking logic and tests
        "src/reporter.zig", // Reporting and output formatting tests
        "src/config.zig", // Configuration parsing and validation tests
    };

    // Create test step that runs all unit tests across modules
    const test_step = b.step("test", "Run all unit tests");

    // Add each source file's tests to the test suite
    for (test_files) |test_file| {
        const unit_tests = b.addTest(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = .Debug, // Always use debug mode for tests
        });

        // Link against libc for tests that use system calls
        unit_tests.linkLibC();

        const run_unit_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_unit_tests.step);
    }
}
