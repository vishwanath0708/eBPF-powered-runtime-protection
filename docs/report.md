# Vanguard Project Report

## Project Overview
Vanguard is a runtime protection system that uses eBPF to detect and block attacks at the kernel level.

## Architecture Decisions
- **eBPF**: Kernel-level monitoring with minimal overhead
- **Spring Boot**: Professional web applications (target + dashboard)
- **Python + BCC**: Standard for eBPF programming
- **JSON Logs**: Shared data between components

## Vulnerabilities
1. **Command Injection** (Diagnostics page)
   - User input directly executed in shell
   - Detected via process tree analysis

2. **Local File Inclusion** (Reports page)
   - No path validation on file reads
   - Detected via file access monitoring

## Progress Log

### Day 1: Environment Setup ✅
- Ubuntu 6.17.0 kernel verified
- CONFIG_BPF=y, CONFIG_BPF_LSM=y confirmed
- BCC tools installed
- execsnoop-bpfcc verified working

### Day 2: (Scheduled)
- Write custom execve probe
- Test with ls, cat, echo
- Add CPU field enhancement
