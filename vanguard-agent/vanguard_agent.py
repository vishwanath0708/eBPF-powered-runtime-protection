#!/usr/bin/env python3
"""
VANGUARD AGENT - Simplified (No LSM)
Detects and kills malicious processes using SIGKILL only
"""

from bcc import BPF
from datetime import datetime
import ctypes
import os
import signal
import time
import sys

# ============================================
# CONFIGURATION
# ============================================
MALICIOUS_COMMANDS = ["curl", "wget", "nc", "ncat", "telnet", "cat"]

# ============================================
# eBPF PROGRAM (Sensor only)
# ============================================
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

# ============================================
# EVENT STRUCTURE
# ============================================
class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 64),
    ]

# ============================================
# VANGUARD AGENT CLASS
# ============================================
class VanguardAgent:
    def __init__(self):
        self.bpf = None
        self.attack_count = 0
        self.event_count = 0
        self.malicious_pids = set()
        self.process_tree = {}

        print("🛡️ VANGUARD AGENT - SIMPLIFIED")
        print("=" * 50)
        print("📌 Mode: Detection + Kill (SIGKILL)")
        print(f"📌 Blocking: {', '.join(MALICIOUS_COMMANDS)}")
        print("📌 NOTE: LSM disabled - using process killing only")
        print()

    def load_bpf(self):
        """Load the eBPF program"""
        try:
            self.bpf = BPF(text=bpf_program)
            print("✅ eBPF program loaded successfully!")
            return True
        except Exception as e:
            print(f"❌ Failed to load BPF: {e}")
            return False

    def is_malicious(self, comm, ppid):
        """Check if a process is malicious"""
        # Direct malicious commands
        if comm in MALICIOUS_COMMANDS:
            return True

        # Check if process is cat and parent is suspicious
        if comm == "cat":
            parent = self.process_tree.get(ppid, {})
            parent_comm = parent.get("comm", "")
            if parent_comm in ["sh", "bash", "curl"]:
                return True

        return False

    def kill_process(self, pid):
        """Kill a process by PID"""
        try:
            os.kill(pid, signal.SIGKILL)
            return True
        except Exception as e:
            return False

    def handle_event(self, ctx, data, size):
        """Process events from ring buffer"""
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        self.event_count += 1

        ts = datetime.fromtimestamp(event.timestamp / 1_000_000_000).strftime("%H:%M:%S.%f")[:-3]
        comm = event.comm.decode('utf-8', errors='ignore')
        filename = event.filename.decode('utf-8', errors='ignore')

        # Store in process tree
        self.process_tree[event.pid] = {
            "ppid": event.ppid,
            "comm": comm,
            "timestamp": ts
        }

        # Check if malicious
        if self.is_malicious(comm, event.ppid):
            print(f"\n{'='*60}")
            print(f"🚨 [{ts}] ATTACK DETECTED!")
            print(f"   📌 Process: {comm} (PID:{event.pid})")
            print(f"   📌 Parent PID: {event.ppid}")
            print(f"   📌 File: {filename}")

            # KILL THE PROCESS
            if self.kill_process(event.pid):
                print(f"   ✅ Process KILLED (SIGKILL)")
                self.attack_count += 1
                self.malicious_pids.add(event.pid)
            else:
                print(f"   ⚠️ Could not kill process (already exited)")

            print(f"{'='*60}\n")

        # Show suspicious activity (every 5 events)
        elif self.event_count % 5 == 0:
            if comm in ["curl", "wget", "nc", "cat", "sh", "bash"]:
                print(f"[{ts}] 🔍 {comm} (PID:{event.pid}) -> {filename[:40]}...")

    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 50)
        print(f"📊 STATISTICS")
        print(f"   Total events: {self.event_count}")
        print(f"   Attacks blocked: {self.attack_count}")
        print(f"   Malicious PIDs: {len(self.malicious_pids)}")
        print("=" * 50)

    def run(self):
        """Main loop"""
        if not self.load_bpf():
            return

        self.bpf["events"].open_ring_buffer(self.handle_event)
        print("✅ Monitoring started...")
        print("🛡️ Vanguard Agent is protecting the system!")
        print("Press Ctrl+C to stop.\n")

        try:
            last_stats = time.time()

            while True:
                self.bpf.ring_buffer_poll()

                # Print stats every 30 seconds
                if time.time() - last_stats > 30:
                    self.print_stats()
                    last_stats = time.time()

        except KeyboardInterrupt:
            print("\n👋 Stopping Vanguard Agent...")
            self.print_stats()
            print(f"🛡️ System was protected!")
            print("✅ Goodbye!")

# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    agent = VanguardAgent()
    agent.run()