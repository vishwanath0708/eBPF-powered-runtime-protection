#!/usr/bin/env python3
"""
Vanguard Agent - Day 4: Optimized Ring Buffer
Performance improvements and error handling

Functional Requirements:
- FR1.1-1.5: All monitoring capabilities
- NFR1.1: Detection latency < 10ms
- NFR1.3: CPU overhead < 5%
"""

from bcc import BPF
from datetime import datetime
import ctypes
import sys
import signal
import time

# 1. Define the C struct
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

# 2. eBPF Program (Optimized)
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

// Larger ring buffer for better performance
BPF_RINGBUF_OUTPUT(events, 128);  // 128 pages = 512KB

// EXECVE Probe
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

// OPENAT Probe
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

// CONNECT Probe
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
COLORS = {"EXECVE": "\033[92m", "OPENAT": "\033[94m", "CONNECT": "\033[93m", "RESET": "\033[0m"}

class VanguardSensor:
    """Optimized sensor with performance tracking"""

    def __init__(self):
        self.event_count = 0
        self.start_time = time.time()
        self.bpf = None

    def load_probes(self):
        """Load eBPF programs"""
        print("🔄 Loading optimized eBPF probes...")
        try:
            self.bpf = BPF(text=bpf_program)
            print("✅ All probes loaded successfully!")
            return True
        except Exception as e:
            print(f"❌ Failed to load BPF: {e}")
            return False

    def handle_event(self, ctx, data, size):
        """Process ring buffer events"""
        self.event_count += 1

        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        event_type = EVENT_TYPES.get(event.event_type, "UNKNOWN")

        ts = datetime.fromtimestamp(event.timestamp / 1_000_000_000).strftime("%H:%M:%S.%f")[:-3]
        comm = event.comm.decode('utf-8', errors='ignore')
        filename = event.filename.decode('utf-8', errors='ignore')[:60]

        # Display every 10th event to reduce output flooding
        if self.event_count % 10 == 0:
            print(f"{COLORS.get(event_type, '')}[{ts}] {event_type:6} "
                  f"PID:{event.pid:6} COMM:{comm:12} FILE:{filename}{COLORS['RESET']}")

    def run(self):
        """Main loop with performance monitoring"""
        if not self.load_probes():
            return

        self.bpf["events"].open_ring_buffer(self.handle_event)
        print("📊 Monitoring optimized...\n")

        try:
            while True:
                self.bpf.ring_buffer_poll()

                # Print stats every 30 seconds
                elapsed = time.time() - self.start_time
                if elapsed % 30 < 0.1:  # ~every 30 seconds
                    rate = self.event_count / elapsed if elapsed > 0 else 0
                    print(f"\r📊 Events: {self.event_count} | Rate: {rate:.1f}/s", end="")

        except KeyboardInterrupt:
            print("\n\n📊 Final Stats:")
            elapsed = time.time() - self.start_time
            rate = self.event_count / elapsed if elapsed > 0 else 0
            print(f"   Total Events: {self.event_count}")
            print(f"   Runtime: {elapsed:.1f}s")
            print(f"   Avg Rate: {rate:.1f} events/sec")
            print("\n👋 Stopped.")

if __name__ == "__main__":
    sensor = VanguardSensor()
    sensor.run()