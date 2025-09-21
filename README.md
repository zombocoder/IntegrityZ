# 🔒 IntegrityZ

[![CI](https://github.com/zombocoder/IntegrityZ/actions/workflows/ci.yml/badge.svg)](https://github.com/zombocoder/IntegrityZ/actions/workflows/ci.yml)
[![Release](https://github.com/zombocoder/IntegrityZ/actions/workflows/release.yml/badge.svg)](https://github.com/zombocoder/IntegrityZ/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig](https://img.shields.io/badge/Zig-0.13.0-orange.svg)](https://ziglang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)](#)
[![Dashboard](https://img.shields.io/badge/Dashboard-Live-success.svg)](https://integrityz.linkzip.app)

**IntegrityZ** is a cross-platform **filesystem integrity monitoring tool** written in [Zig](https://ziglang.org).  
It detects unauthorized changes to files, permissions, and metadata — helping you secure your system against tampering, malware, and insider threats.

IntegrityZ is a modern alternative to classic tools like Tripwire or AIDE, but with:

- ⚡ **BLAKE3 hashing** for ultra-fast checksum validation
- 🧩 **Modular design** with clear CLI commands
- 📊 **JSON output support** for automation and integration
- 🖥️ **Cross-compilation** (build once, run anywhere)
- 👁️ **Real-time monitoring** with filesystem events (inotify/kqueue)
- 🔗 **Webhook integration** for instant notifications

---

## ✨ Features

- Create a **baseline snapshot** of directories
- Detect:
  - File additions / deletions / renames
  - Content changes (via BLAKE3 checksums)
  - Permission / ownership / POSIX metadata changes
- Export **JSON reports** with timestamps and checksums for integration
- **Configuration file support** with include/exclude patterns
- **Real-time monitoring** with `inotify` (Linux), `kqueue` (BSD/macOS)
- **HTTP webhook notifications** for instant alerts
- **Web dashboard** for visualizing integrity reports
- **Comprehensive test suite** with 169+ unit tests

---

## 🚀 Getting Started

### Build

```bash
git clone https://github.com/yourname/integrityz.git
cd integrityz
make build
```

Or for optimized release build:

```bash
make build-release
```

Resulting binary will be at:

```
./zig-out/bin/integrityz
```

### Basic Usage

**Initialize baseline:**

```bash
integrityz init /etc /usr/bin
```

**Check filesystem:**

```bash
integrityz check
```

**Check specific paths with JSON output:**

```bash
integrityz check --json /etc /usr/bin
```

**Watch for changes (real-time monitoring):**

```bash
integrityz watch /etc /usr/bin
```

**Manage configuration:**

```bash
# Show current configuration
integrityz config

# Create default configuration file
integrityz config --init
```

**Visualize results with the web dashboard:**

```bash
# Generate JSON report
integrityz check --json > report.json

# Option 1: Use the live dashboard
# Visit https://integrityz.linkzip.app and drag your report.json file

# Option 2: Use locally
# Open web-dashboard/index.html in browser and drag the report file
```

---

## 📋 CLI Commands

### Available Commands

```bash
integrityz init <paths...>        # Create baseline for specified paths
integrityz check [--json] [paths] # Check filesystem against baseline
integrityz watch [paths]          # Watch for real-time changes with webhooks
integrityz config [--init]        # Show or initialize configuration
```

### Command Options

- `--json` - Output results in JSON format for automation
- `--init` - Create default configuration file

### Configuration File

IntegrityZ supports configuration via `integrityz.conf`:

```ini
# IntegrityZ Configuration File
baseline_path=integrityz.db

# Include patterns (glob style)
include=*.conf
include=/etc/*

# Exclude patterns (glob style)  
exclude=*.tmp
exclude=*.log
exclude=.git/*
exclude=node_modules/*

# File scanning settings
max_file_size=0
follow_symlinks=false

# Webhook settings for real-time notifications
webhook_url=https://your-webhook-endpoint.com/integrityz
webhook_timeout=30

# Watch mode settings
watch_check_interval=5
watch_max_event_batch=10
watch_recursive=true

# Default paths to scan if none specified
default_scan_path=/etc
default_scan_path=/usr/bin
```

---

## 📊 Example Report

```json
{
  "timestamp": 1727777284,
  "has_changes": true,
  "total_files_checked": 1250,
  "baseline_records": 1248,
  "current_records": 1250,
  "changes_count": 3,
  "changes": [
    {
      "type": "added",
      "path": "/etc/new.conf",
      "details": "File added",
      "old_checksum": null,
      "new_checksum": null
    },
    {
      "type": "modified",
      "path": "/usr/bin/ssh",
      "details": "Content changed (checksum mismatch); Size changed from 1024 to 1152 bytes",
      "old_checksum": "a1b2c3d4e5f6789...",
      "new_checksum": "d4e5f6a1b2c3789..."
    },
    {
      "type": "deleted",
      "path": "/etc/unused.conf",
      "details": "File deleted",
      "old_checksum": null,
      "new_checksum": null
    }
  ]
}
```

---

## 🛠 Project Structure

```
integrityz/
├── src/             # Core Zig modules
│   ├── main.zig     # CLI entry point
│   ├── watcher.zig  # Real-time filesystem monitoring
│   ├── checker.zig  # Integrity checking logic
│   ├── reporter.zig # JSON reporting with timestamps
│   └── config.zig   # Configuration management
├── web-dashboard/   # Visualization dashboard
├── build.zig        # Zig build script with comprehensive tests
├── Makefile         # Build automation
└── README.md
```

---

## 📅 Roadmap

- [x] MVP: Baseline + scan + JSON report
- [x] Configuration file support with patterns
- [x] Web dashboard for JSON report visualization
- [x] HTTP webhook integration for 3rd party systems
- [x] Real-time monitoring (inotify/kqueue)
- [x] Comprehensive test suite (169+ tests)
- [x] Enhanced JSON reports with timestamps and checksums
- [ ] Windows platform support (ReadDirectoryChangesW)
- [ ] Performance optimization for large filesystems

---

## 🧪 Testing & Development

IntegrityZ includes a comprehensive test suite with 169+ unit tests covering all modules:

### Run Tests

```bash
# Run all tests
make test

# Run tests for specific modules
./zig/zig test src/watcher.zig
./zig/zig test src/checker.zig
./zig/zig test src/config.zig
```

### Test Coverage

- **watcher.zig**: Real-time monitoring, event handling, webhook integration
- **checker.zig**: Integrity comparison, consolidated change detection 
- **reporter.zig**: JSON generation, timestamp handling, checksum formatting
- **config.zig**: Configuration parsing, webhook settings, memory management
- **All core modules**: Crypto, records, database, scanner, utilities

### Available Make Targets

```bash
make build           # Debug build
make build-release   # Optimized release build  
make test           # Run comprehensive test suite
make clean          # Clean build artifacts
make fmt            # Format source code
make fmt-check      # Check code formatting
```

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue first to discuss major changes.
This project is in early development — design discussions are encouraged.
