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

---

## ✨ Features

- Create a **baseline snapshot** of directories
- Detect:
  - File additions / deletions / renames
  - Content changes (via BLAKE3 checksums)
  - Permission / ownership / POSIX metadata changes
- Export **JSON reports** for integration with other tools
- **Configuration file support** with include/exclude patterns
- **Realtime monitoring** with `inotify` (Linux), `kqueue` (BSD/macOS), and `ReadDirectoryChangesW` (Windows)
- Signed **audit logs** to ensure integrity of the monitor itself

---

## 🚀 Getting Started

### Build

```bash
git clone https://github.com/yourname/integrityz.git
cd integrityz
zig build -Drelease-safe
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

**Watch for changes (realtime):**

```bash
integrityz watch
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
integrityz watch                  # Watch for realtime changes (not yet implemented)
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

# Other settings
max_file_size=0
follow_symlinks=false

# Default paths to scan if none specified
default_scan_path=/etc
default_scan_path=/usr/bin
```

---

## 📊 Example Report

```json
{
  "added": ["/etc/new.conf"],
  "deleted": ["/etc/unused.conf"],
  "modified": [
    {
      "path": "/usr/bin/ssh",
      "old_checksum": "a1b2c3...",
      "new_checksum": "d4e5f6..."
    }
  ],
  "meta_changed": [
    {
      "path": "/etc/passwd",
      "old_mode": "0644",
      "new_mode": "0666"
    }
  ]
}
```

---

## 🛠 Project Structure

```
integrityz/
├── src/         # Core Zig modules
├── tests/       # Unit & integration tests
├── docs/        # Technical docs, design notes
├── build.zig    # Zig build script
└── README.md
```

---

## 📅 Roadmap

- [x] MVP: Baseline + scan + JSON report
- [x] Configuration file support with patterns
- [x] Web dashboard for JSON report visualization
- [ ] Windows platform support
- [ ] HTTP webhook integration for 3rd party systems
- [ ] Realtime monitoring (inotify/kqueue/Windows API)

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue first to discuss major changes.
This project is in early development — design discussions are encouraged.
