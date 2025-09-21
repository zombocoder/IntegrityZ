---
name: Performance Issue
about: Report performance problems or suggest optimizations
title: '[PERFORMANCE] '
labels: 'performance'
assignees: ''
---

## ⚡ Performance Issue Description

**Describe the performance problem**
A clear and concise description of the performance issue you're experiencing.

**Expected performance**
What performance level did you expect?

**Actual performance**
What performance are you actually seeing?

## 📊 Performance Metrics

**Timing measurements:**
```
# Paste timing information here
Command: integrityz check
Time taken: X minutes Y seconds
Files scanned: N files
Average files/second: X
```

**Resource usage:**
- CPU usage: [percentage or detailed breakdown]
- Memory usage: [peak memory, average memory]
- Disk I/O: [read/write patterns if known]
- Network usage: [if applicable]

**System specifications:**
- CPU: [processor model and cores]
- RAM: [total amount]
- Storage: [SSD/HDD, filesystem type]
- OS: [operating system and version]

## 🔄 Reproducible Test Case

**Dataset characteristics:**
- Total files: [number]
- Total size: [GB/TB]
- Directory depth: [maximum depth]
- File types: [mix of file types]
- Average file size: [if known]

**Command used:**
```bash
# Exact command that shows performance issue
integrityz [command] [options]
```

**Performance comparison:**
```
# Before (if applicable):
Operation X: Y seconds

# After some change:
Operation X: Z seconds

# Or comparison with other tools:
Tool A: X seconds
IntegrityZ: Y seconds
```

## 🎯 Performance Goals

**What would be acceptable performance?**
- [ ] 2x faster than current
- [ ] Comparable to [other tool]
- [ ] Specific target: [X files/second, Y GB/minute, etc.]

**Performance priorities:**
- [ ] Faster scanning
- [ ] Lower memory usage
- [ ] Reduced disk I/O
- [ ] Better CPU utilization
- [ ] Faster startup time
- [ ] Other: [specify]

## 🔍 Analysis and Investigation

**Have you profiled the performance?**
- [ ] Yes, using [tool name]
- [ ] No, but willing to help
- [ ] Need guidance on profiling

**Suspected bottlenecks:**
- [ ] File I/O operations
- [ ] Hash calculation (BLAKE3)
- [ ] Memory allocation
- [ ] Directory traversal
- [ ] Database operations
- [ ] JSON serialization
- [ ] Unknown/Other

**Profiling data (if available):**
```
# Paste profiling output, flame graphs, or performance analysis
```

## 💡 Suggested Optimizations

**Ideas for improvement:**
- [ ] Parallel processing
- [ ] Better caching
- [ ] Algorithm optimization
- [ ] Reduced memory allocations
- [ ] Streaming processing
- [ ] Other: [describe]

**Are you willing to work on a fix?**
- [ ] Yes, I can contribute code
- [ ] Yes, but need guidance
- [ ] No, but can test solutions
- [ ] No, just reporting

## 📈 Impact Assessment

**How critical is this performance issue?**
- [ ] Blocking daily usage
- [ ] Significantly impacts productivity
- [ ] Noticeable but manageable
- [ ] Minor annoyance

**Affected use cases:**
- [ ] Regular integrity checks
- [ ] Initial baseline creation
- [ ] Large filesystem monitoring
- [ ] Automated/scheduled scans
- [ ] CI/CD integration

## 🛠️ Workarounds

**Temporary solutions you've found:**
<!-- Describe any workarounds or optimizations you've applied -->

**Configuration tweaks that help:**
```ini
# Any configuration changes that improve performance
setting=value
```

## 📋 Additional Context

**Related issues:**
<!-- Link to any related performance issues -->

**Environment details:**
- File system: [ext4, NTFS, APFS, etc.]
- Mount options: [if relevant]
- Network storage: [NFS, SMB, etc. if applicable]
- Virtualization: [Docker, VM, etc. if applicable]

---

**Checklist:**
- [ ] I have measured the performance issue objectively
- [ ] I have provided system specifications and dataset characteristics
- [ ] I have searched for existing performance issues
- [ ] I am using the latest version of IntegrityZ