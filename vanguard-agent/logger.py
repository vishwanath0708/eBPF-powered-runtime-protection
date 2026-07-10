#!/usr/bin/env python3
"""
Vanguard Agent - Day 5: JSON Logging
Writes all events to logs/events.json in real-time

Functional Requirements:
- FR2.3: Write events to JSON log file in real-time
- FR2.2: Structure events as typed data
"""

from bcc import BPF
from datetime import datetime
import ctypes
import json
import os
import sys
import time
from threading import Lock

# 1. Event Structure
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 128),
    ]

# 2. eBPF Program (same as Day 4)
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

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

BPF_RINGBUF_OUTPUT(events, 128);

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

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = EVENT_CONNECT;

    bpf_probe_read_str(&event.comm, sizeof(event.comm), task->comm);
    bpf_probe_read_str(&event.filename, sizeof(event.filename), (void *)args->uservaddr);

    events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}
"""

EVENT_TYPES = {1: "EXECVE", 2: "OPENAT", 3: "CONNECT"}

class VanguardLogger:
    """Sensor with JSON logging"""

    def __init__(self, log_file="logs/events.json"):
        self.log_file = log_file
        self.lock = Lock()
        self.event_count = 0

        # Create log directory
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Open log file in append mode
        self.fd = open(log_file, 'a')
        print(f"📝 Logging to: {log_file}")

    def log_event(self, event_dict):
        """Write event to JSON log"""
        with self.lock:
            json_line = json.dumps(event_dict, default=str) + '\n'
            self.fd.write(json_line)
            self.fd.flush()
            self.event_count += 1

    def handle_event(self, ctx, data, size):
        """Process ring buffer event"""
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents

        ts = datetime.fromtimestamp(event.timestamp / 1_000_000_000).isoformat()
        comm = event.comm.decode('utf-8', errors='ignore')
        filename = event.filename.decode('utf-8', errors='ignore')
        event_type = EVENT_TYPES.get(event.event_type, "UNKNOWN")

        # Create structured event
        event_dict = {
            "timestamp": ts,
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "event_type": event_type,
            "comm": comm,
            "filename": filename
        }

        # Write to JSON log
        self.log_event(event_dict)

        # Print every 10th event
        if self.event_count % 10 == 0:
            print(f"[{ts}] {event_type:6} PID:{event.pid:6} COMM:{comm:12}")

    def close(self):
        self.fd.close()

    def run(self):
        print("🔄 Loading eBPF probes...")
        b = BPF(text=bpf_program)
        print("✅ Probes loaded!")

        b["events"].open_ring_buffer(self.handle_event)
        print("✅ Ring buffer open. Logging events...")
        print("Press Ctrl+C to stop.\n")

        try:
            while True:
                b.ring_buffer_poll()
        except KeyboardInterrupt:
            print("\n👋 Stopped.")
            self.close()
            print(f"📊 Total events logged: {self.event_count}")

if __name__ == "__main__":
    logger = VanguardLogger()
    logger.run()