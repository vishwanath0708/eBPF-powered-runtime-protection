#!/usr/bin/env python3
"""
Vanguard Agent - Day 3: execve + openat + connect Probes
Captures process executions, file accesses, and network connections

Functional Requirements:
- FR1.1: Capture all process executions (execve)
- FR1.2: Capture all file accesses (openat)
- FR1.3: Capture all network connections (connect)
- FR1.4: Capture PID, PPID, UID, timestamp, command, filename
- FR1.5: Operate at kernel level using eBPF
"""

from bcc import BPF
from datetime import datetime
import ctypes
import sys

# 1. Define the C struct for our event data
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("event_type", ctypes.c_uint32),  # 1=execve, 2=openat, 3=connect
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 128),  # Increased size for file paths
    ]

# 2. eBPF C program with 3 probes
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event types
#define EVENT_EXECVE 1
#define EVENT_OPENAT 2
#define EVENT_CONNECT 3

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp;
    u32 event_type;
    char comm[16];
    char filename[128];
};

BPF_RINGBUF_OUTPUT(events, 64);

// ==================== PROBE 1: Process Execution ====================
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = EVENT_EXECVE;

    bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
    bpf_probe_read_str(&event.filename, sizeof(event.filename), (void *)args->data_loc_filename);

    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// ==================== PROBE 2: File Access (openat) ====================
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = EVENT_OPENAT;

    bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
    bpf_probe_read_str(&event.filename, sizeof(event.filename), (void *)args->filename);

    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// ==================== PROBE 3: Network Connection (connect) ====================
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = EVENT_CONNECT;

    bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
    // For connect, we read the socket address
    bpf_probe_read_str(&event.filename, sizeof(event.filename), (void *)args->uservaddr);

    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
"""

# Event type names
EVENT_TYPES = {
    1: "EXECVE",
    2: "OPENAT",
    3: "CONNECT"
}

# Color codes for terminal output
COLORS = {
    "EXECVE": "\033[92m",   # Green
    "OPENAT": "\033[94m",   # Blue
    "CONNECT": "\033[93m",  # Yellow
    "RESET": "\033[0m"
}

def print_event(ctx, data, size):
    """Callback function for ring buffer events"""
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    ts = datetime.fromtimestamp(event.timestamp / 1_000_000_000).strftime("%H:%M:%S.%f")[:-3]
    comm = event.comm.decode('utf-8', errors='ignore')
    filename = event.filename.decode('utf-8', errors='ignore')
    event_type = EVENT_TYPES.get(event.event_type, "UNKNOWN")

    # Color-code output
    color = COLORS.get(event_type, "")
    reset = COLORS["RESET"]

    # Truncate long filenames for display
    display_filename = filename[:60] + "..." if len(filename) > 60 else filename

    print(f"{color}[{ts}] {event_type:6} PID:{event.pid:6} PPID:{event.ppid:6} "
          f"COMM:{comm:12} FILE:{display_filename}{reset}")

def main():
    print("🔄 Loading eBPF probes (execve, openat, connect)...")
    print("   (Compiler warnings are normal - they don't affect functionality)\n")

    try:
        b = BPF(text=bpf_program)
        print("✅ All probes loaded successfully!\n")
    except Exception as e:
        print(f"❌ Failed to load BPF: {e}")
        sys.exit(1)

    b["events"].open_ring_buffer(print_event)

    print("📊 Monitoring:")
    print("   🟢 EXECVE - Process executions (for RCE detection)")
    print("   🔵 OPENAT - File accesses (for LFI detection)")
    print("   🟡 CONNECT - Network connections (for monitoring)")
    print("\nPress Ctrl+C to stop.\n")

    try:
        while True:
            b.ring_buffer_poll()
    except KeyboardInterrupt:
        print("\n👋 Stopped.")

if __name__ == "__main__":
    main()