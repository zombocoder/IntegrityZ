# SPDX-License-Identifier: Apache-2.0

.PHONY: all build build-release clean test fmt fmt-check download_zig

# Default target
all: build

# Download Zig compiler if not already available
download_zig:
	@if [ ! -f "./zig/zig" ]; then \
		echo "Downloading Zig compiler..."; \
		chmod +x ./zig/download.sh; \
		./zig/download.sh; \
	else \
		echo "Zig compiler already downloaded."; \
	fi

# Build the project
build: download_zig
	@echo "Building IntegrityZ..."
	@./zig/zig build

# Build optimized release version
build-release: download_zig
	@echo "Building IntegrityZ (Release)..."
	@./zig/zig build -Doptimize=ReleaseFast

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf zig-out zig-cache .zig-cache
	@rm -f data/*.db data/*.sock

# Run all unit tests using Zig's test framework
test: download_zig
	@echo "Running IntegrityZ unit tests..."
	@./zig/zig build test
	@echo "All tests completed successfully."

# Format all source code using Zig formatter
fmt: download_zig
	@echo "Formatting source code..."
	@./zig/zig fmt src/

# Check if source code is properly formatted
fmt-check: download_zig
	@echo "Checking code formatting..."
	@./zig/zig fmt --check src/

# Stop the running cluster
stop:
	@echo "Stopping IntegrityZ cluster..."
	@pkill -f IntegrityZ || echo "No IntegrityZ processes found to stop."

# Display help information
help:
	@echo "IntegrityZ Makefile targets:"
	@echo "  make                      - Build the project (same as 'make build')"
	@echo "  make build                - Build the IntegrityZ binary (debug)"
	@echo "  make build-release        - Build optimized release version"
	@echo "  make clean                - Remove build artifacts and database files"
	@echo "  make test                 - Run the complete test suite"
	@echo "  make fmt                  - Format all source code using Zig formatter"
	@echo "  make fmt-check            - Check if source code is properly formatted"
	@echo "  make stop                 - Stop the running cluster"
	@echo "  make download_zig         - Download the Zig compiler if not present"
	@echo "  make help                 - Display this help message"
	@echo ""