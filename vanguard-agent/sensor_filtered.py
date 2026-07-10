#!/usr/bin/env python3
"""
Vanguard Agent - Filtered Version
Only shows process executions (EXECVE events)
"""

from bcc import BPF
from datetime import datetime
import ctypes
import sys

# 1. Define the C struct
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 64),
    ]

# 2. eBPF C program - Only execve
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u64 timestamp;
    char comm[16];
    char filename[64];
};

BPF_RINGBUF_OUTPUT(events, 64);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();

    bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
    bpf_probe_read_str(&event.filename, sizeof(event.filename), (void *)args->data_loc_filename);

    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
"""

# Interesting processes to watch
INTERESTING = ['sh', 'bash', 'cat', 'java', 'curl', 'python', 'mvn', 'ping']

def print_event(ctx, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    ts = datetime.fromtimestamp(event.timestamp / 1_000_000_000).strftime("%H:%M:%S.%f")[:-3]
    
    comm = event.comm.decode('utf-8', errors='ignore')
    filename = event.filename.decode('utf-8', errors='ignore')
    
    # ONLY show interesting processes
    if comm in INTERESTING:
        print(f"[{ts}] 🛡️ {comm} (PID:{event.pid}) → FILE:{filename}")

if __name__ == "__main__":
    print("🔄 Vanguard Agent - Filtered Mode")
    print("📌 Watching only: sh, bash, cat, java, curl, python, mvn, ping\n")
    
    b = BPF(text=bpf_program)
    print("✅ eBPF program loaded!")
    b["events"].open_ring_buffer(print_event)
    print("✅ Waiting for attacks...\n")
    
    try:
        while True:
            b.ring_buffer_poll()
    except KeyboardInterrupt:
        print("\n👋 Stopped.")
