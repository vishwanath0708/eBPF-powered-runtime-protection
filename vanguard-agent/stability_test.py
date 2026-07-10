#!/usr/bin/env python3
"""
Vanguard Agent - Day 7: Stability Test
Runs sensor for extended period and validates performance

Non-Functional Requirements:
- NFR2.1: Agent uptime 99.9%
- NFR1.4: Memory usage < 100MB
- NFR1.3: CPU overhead < 5%
"""

import subprocess
import time
import json
import os
import sys
import psutil
from datetime import datetime

class StabilityTest:
    """Stability and performance testing"""

    def __init__(self, duration_minutes=15):
        self.duration_minutes = duration_minutes
        self.log_file = "logs/events.json"
        self.process = None
        self.start_time = None
        self.event_count = 0

    def start_agent(self, sensor_file="sensor.py"):
        """Start the sensor process"""
        print(f"🚀 Starting Vanguard Agent ({sensor_file})...")

        if not os.path.exists(sensor_file):
            print(f"❌ Error: {sensor_file} not found!")
            return False

        self.process = subprocess.Popen(
            ["sudo", "python3", sensor_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        time.sleep(3)  # Give it time to start
        if self.process.poll() is not None:
            print("❌ Agent crashed on startup!")
            return False

        self.start_time = datetime.now()
        print(f"✅ Agent started (PID: {self.process.pid})")
        return True

    def stop_agent(self):
        """Stop the sensor process"""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            print("✅ Agent stopped")
            return True
        return False

    def count_events(self):
        """Count events in log file"""
        if not os.path.exists(self.log_file):
            return 0

        count = 0
        try:
            with open(self.log_file, 'r') as f:
                for _ in f:
                    count += 1
        except:
            pass
        return count

    def monitor_performance(self):
        """Check CPU and memory usage"""
        if not self.process:
            return None

        try:
            proc = psutil.Process(self.process.pid)
            mem_info = proc.memory_info()
            cpu_percent = proc.cpu_percent(interval=0.5)

            return {
                "cpu_percent": cpu_percent,
                "memory_mb": mem_info.rss / 1024 / 1024,
                "memory_vms_mb": mem_info.vms / 1024 / 1024
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def run(self):
        """Run the stability test"""
        print(f"🧪 Starting {self.duration_minutes} minute stability test...")

        # Clear old log
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

        # Start agent
        if not self.start_agent():
            return

        # Monitor
        interval = 30  # seconds
        elapsed_minutes = 0

        print("\n📊 Monitoring performance...")
        print("   Time | Events | CPU % | Memory MB")
        print("   " + "-" * 40)

        try:
            while elapsed_minutes < self.duration_minutes:
                time.sleep(interval)
                elapsed_minutes += interval / 60

                events = self.count_events()
                perf = self.monitor_performance()

                if perf:
                    print(f"   {elapsed_minutes:4.1f}m | {events:6} | {perf['cpu_percent']:5.1f}% | {perf['memory_mb']:8.1f}MB")
                else:
                    print(f"   {elapsed_minutes:4.1f}m | {events:6} | ?")

                # Check if agent is still running
                if self.process and self.process.poll() is not None:
                    print("\n⚠️ Agent crashed!")
                    break

        except KeyboardInterrupt:
            print("\n🛑 Test interrupted by user")

        # Stop agent and collect results
        self.stop_agent()
        total_events = self.count_events()
        duration = (datetime.now() - self.start_time).total_seconds() / 60

        print("\n" + "=" * 50)
        print("📊 TEST RESULTS")
        print("=" * 50)
        print(f"   Duration: {duration:.1f} minutes")
        print(f"   Total events: {total_events}")
        print(f"   Event rate: {total_events/(duration):.1f} events/min")

        if total_events == 0:
            print("   ⚠️ WARNING: No events captured!")
        else:
            print("   ✅ Events captured successfully!")

        # Save results
        results = {
            "duration_minutes": duration,
            "total_events": total_events,
            "event_rate": total_events/duration if duration > 0 else 0,
            "timestamp": datetime.now().isoformat()
        }

        with open("logs/stability_test.json", "w") as f:
            json.dump(results, f, indent=2)
        print("\n📁 Results saved to logs/stability_test.json")

        return results

def main():
    # Quick test (5 minutes) or full test (15 minutes)
    test = StabilityTest(duration_minutes=5)
    test.run()

if __name__ == "__main__":
    main()