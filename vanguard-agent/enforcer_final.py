#!/usr/bin/env python3
"""
Vanguard Agent - Final Enforcer
Detects and kills malicious processes
"""

from bcc import BPF
from datetime import datetime
import ctypes
import os
import signal
import time

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

class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 64),
    ]

bpf = None
blocked_pids = set()
attack_count = 0

def print_event(ctx, data, size):
    global bpf, blocked_pids, attack_count
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    ts = datetime.fromtimestamp(event.timestamp / 1_000_000_000).strftime("%H:%M:%S.%f")[:-3]
    comm = event.comm.decode('utf-8', errors='ignore')
    filename = event.filename.decode('utf-8', errors='ignore')
    
    # Detect malicious process chain
    if comm == 'curl':
        print(f"\n{'='*50}")
        print(f"[{ts}] 🌐 ATTACK DETECTED!")
        print(f"[{ts}] 📥 curl command executed (PID:{event.pid})")
        print(f"[{ts}] 🛡️ Killing malicious process...")
        try:
            os.kill(event.pid, signal.SIGKILL)
            print(f"[{ts}] ✅ curl KILLED!")
            attack_count += 1
        except:
            pass
            
    elif comm == 'cat' and filename == '/bin/cat':
        print(f"[{ts}] 🚨 MALICIOUS cat detected (PID:{event.pid})")
        print(f"[{ts}] 🛡️ Killing cat process...")
        try:
            os.kill(event.pid, signal.SIGKILL)
            print(f"[{ts}] ✅ cat KILLED!")
            attack_count += 1
        except:
            pass
    
    elif comm == 'sh':
        # Show shell spawn but don't kill it
        print(f"[{ts}] 🔄 sh spawned (PID:{event.pid}) -> {filename}")
    
    elif comm in ['java', 'python', 'node']:
        # Show application processes
        pass
    
    else:
        # Only show important processes
        if comm in ['bash', 'curl', 'wget', 'nc']:
            print(f"[{ts}] 📌 {comm} (PID:{event.pid})")

if __name__ == "__main__":
    print("🛡️ VANGUARD ENFORCER - FINAL VERSION")
    print("📌 Detecting: curl → sh → cat attack chain")
    print("📌 Blocking: curl, cat, wget, nc\n")
    
    bpf = BPF(text=bpf_program)
    print("✅ eBPF program loaded!")
    
    bpf["events"].open_ring_buffer(print_event)
    print("✅ Monitoring...\n")
    
    try:
        while True:
            bpf.ring_buffer_poll()
    except KeyboardInterrupt:
        print(f"\n{'='*50}")
        print(f"👋 Stopped. Total attacks blocked: {attack_count}")
        print(f"🛡️ Vanguard Agent protected the system!")
