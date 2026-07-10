#!/usr/bin/env python3
import time
import subprocess

print("🛡️ Vanguard Alert System")
print("📌 Monitoring for attacks...\n")

while True:
    # Check for cat processes
    result = subprocess.run(["pgrep", "-f", "cat"], capture_output=True, text=True)
    if result.stdout:
        pids = result.stdout.strip().split('\n')
        for pid in pids:
            print(f"🚨 ALERT: Malicious process detected! PID: {pid}")
            print(f"   Action: Blocking PID {pid}")
            # Kill the process (block)
            subprocess.run(["sudo", "kill", "-9", pid])
            print(f"   ✅ Blocked!\n")
    time.sleep(1)
