# Contributing to IntegrityZ

Thank you for your interest in contributing to IntegrityZ! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites

- [Zig 0.13.0](https://ziglang.org/download/) or use the included download script
- Basic knowledge of systems programming and filesystem concepts
- Familiarity with Git and GitHub workflows

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/zombocoder/IntegrityZ.git
   cd IntegrityZ
   ```

2. **Download Zig compiler (if not installed):**
   ```bash
   make download_zig
   ```

3. **Build the project:**
   ```bash
   make build
   ```

4. **Run tests:**
   ```bash
   make test
   ```

5. **Check code formatting:**
   ```bash
   make fmt-check
   ```

## 📋 Development Workflow

### Before You Start

1. **Check existing issues** to see if your idea is already being discussed
2. **Open an issue** for new features or significant changes to discuss the approach
3. **Fork the repository** and create a feature branch from `main`

### Making Changes

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards below

3. **Write or update tests** for your changes

4. **Format your code:**
   ```bash
   make fmt
   ```

5. **Run the test suite:**
   ```bash
   make test
   ```

6. **Test cross-platform compatibility** if applicable

### Submitting Changes

1. **Commit your changes** with clear, descriptive messages:
   ```bash
   git commit -m "Add feature: brief description of what was added"
   ```

2. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create a pull request** with:
   - Clear title and description
   - Reference to any related issues
   - Screenshots or examples if applicable
   - List of changes made

## 🛠 Coding Standards

### Code Style

- **Follow Zig conventions** - use `zig fmt` to format code
- **Use descriptive variable names** - prefer clarity over brevity
- **Add comments** for complex logic and public APIs
- **Keep functions focused** - one responsibility per function

### Documentation

- **Document public functions** with clear parameter descriptions
- **Include usage examples** for complex APIs
- **Update README.md** if adding new features or changing CLI commands
- **Add inline comments** for non-obvious code logic

### Testing

- **Write unit tests** for all new functionality
- **Test edge cases** and error conditions
- **Ensure cross-platform compatibility** (Linux, macOS, Windows)
- **Add integration tests** for CLI functionality

### Git Practices

- **Use conventional commits** where possible
- **Keep commits atomic** - one logical change per commit
- **Write clear commit messages** explaining the why, not just the what
- **Rebase feature branches** before merging to keep history clean

## 🏗 Project Structure

```
IntegrityZ/
├── src/                    # Core Zig source code
│   ├── main.zig           # CLI entry point
│   ├── baseline.zig       # Baseline creation and management
│   ├── checker.zig        # Integrity checking logic
│   ├── config.zig         # Configuration file handling
│   ├── crypto.zig         # BLAKE3 hashing utilities
│   ├── database.zig       # Binary serialization
│   ├── display.zig        # Output formatting
│   ├── manifest.zig       # Directory manifest generation
│   ├── records.zig        # Filesystem record structures
│   ├── reporter.zig       # Report generation (JSON/text)
│   ├── scanner.zig        # Filesystem traversal
│   └── util.zig           # Utility functions
├── .github/workflows/     # CI/CD pipelines
├── zig/                   # Zig compiler (downloaded automatically)
├── build.zig              # Build configuration
├── Makefile               # Development commands
└── README.md              # Project documentation
```

## 🎯 Areas for Contribution

### High Priority

- **Real-time monitoring** implementation (inotify/kqueue/Windows API)
- **Cryptographic signing** for baseline integrity
- **Performance optimizations** for large filesystems
- **Cross-platform testing** and compatibility fixes

### Medium Priority

- **Configuration enhancements** (more flexible patterns, etc.)
- **Output format improvements** (YAML, XML support)
- **Error handling** improvements and user experience
- **Documentation** and usage examples

### Low Priority

- **Web dashboard** for monitoring
- **Plugin system** for extensibility
- **Advanced filtering** options
- **Compression** for baseline files

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Zig version** and operating system
2. **Steps to reproduce** the issue
3. **Expected vs actual behavior**
4. **Relevant log output** or error messages
5. **Sample files or directories** if applicable

Use the bug report template when creating issues.

## 💡 Feature Requests

For feature requests, please provide:

1. **Clear description** of the proposed feature
2. **Use case** - why is this feature needed?
3. **Proposed implementation** approach if you have ideas
4. **Alternative solutions** you've considered

## 🔒 Security

If you discover security vulnerabilities:

1. **Do NOT open a public issue**
2. **Email the maintainers** directly
3. **Provide detailed information** about the vulnerability
4. **Allow time** for the issue to be addressed before disclosure

## 🤝 Code of Conduct

This project follows a simple code of conduct:

- **Be respectful** and inclusive
- **Focus on constructive feedback**
- **Help create a welcoming environment** for all contributors
- **Assume good intentions** from other contributors

## 📞 Getting Help

- **GitHub Issues** - for bugs and feature requests
- **GitHub Discussions** - for questions and general discussion
- **Pull Request Reviews** - for code-related questions

## 🎉 Recognition

Contributors are recognized in several ways:

- **Contributor list** in the README
- **Changelog entries** for significant contributions
- **GitHub contributor graphs** and statistics

Thank you for contributing to IntegrityZ! 🔒