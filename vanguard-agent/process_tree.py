#!/usr/bin/env python3
"""
Vanguard Agent - Day 6: Process Tree Tracking
Builds and maintains PID→PPID→COMM mapping

Functional Requirements:
- FR2.4: Maintain a process tree (PID → PPID → command)
- FR3.1: Detect Command Injection attacks
"""

import json
import os
from collections import defaultdict
from datetime import datetime
import sys

class ProcessTree:
    """Tracks process relationships"""

    def __init__(self):
        self.processes = {}  # PID -> {ppid, comm, start_time, children}
        self.children = defaultdict(list)  # PPID -> [child PIDs]

    def add_process(self, pid, ppid, comm, timestamp):
        """Add a process to the tree"""
        if pid not in self.processes:
            self.processes[pid] = {
                "pid": pid,
                "ppid": ppid,
                "comm": comm,
                "start_time": timestamp,
                "children": []
            }

            # Add to parent's children list
            if ppid > 0:
                self.children[ppid].append(pid)
                if ppid in self.processes:
                    self.processes[ppid]["children"].append(pid)

    def get_parent_chain(self, pid):
        """Get full parent chain (ancestry)"""
        chain = []
        current = pid
        while current > 0 and current in self.processes:
            proc = self.processes[current]
            chain.append({"pid": current, "comm": proc["comm"], "ppid": proc["ppid"]})
            current = proc["ppid"]
        return chain[::-1]  # Root first

    def get_process_tree_string(self, pid, indent=0):
        """Visual tree representation"""
        if pid not in self.processes:
            return ""

        proc = self.processes[pid]
        result = "  " * indent + f"├── {proc['comm']} (PID:{pid})\n"
        for child_pid in self.children.get(pid, []):
            result += self.get_process_tree_string(child_pid, indent + 1)
        return result

    def find_attacks(self):
        """Detect suspicious process chains (RCE detection)"""
        alerts = []

        # Look for Java → shell → sensitive file access
        for pid, info in self.processes.items():
            if info["comm"] == "java":
                children = self.children.get(pid, [])
                for child_pid in children:
                    child = self.processes.get(child_pid, {})
                    if child.get("comm") in ["sh", "bash", "cat"]:
                        # Check if child accessed sensitive files
                        alerts.append({
                            "type": "Potential RCE",
                            "java_pid": pid,
                            "child_pid": child_pid,
                            "child_comm": child.get("comm")
                        })

        return alerts

    def get_full_tree(self):
        """Get full system tree"""
        roots = [pid for pid in self.processes.keys()
                 if self.processes[pid]["ppid"] == 0 or
                 self.processes[pid]["ppid"] not in self.processes]

        result = "System Process Tree:\n"
        for root in roots:
            result += self.get_process_tree_string(root, 0)
        return result

class ProcessTreeBuilder:
    """Builds tree from event logs"""

    def __init__(self, log_file="logs/events.json"):
        self.log_file = log_file
        self.tree = ProcessTree()

    def build_from_logs(self, limit=10000):
        """Build tree from event logs"""
        if not os.path.exists(self.log_file):
            print(f"⚠️ Log file {self.log_file} not found")
            return

        count = 0
        with open(self.log_file, 'r') as f:
            for line in f:
                if count >= limit:
                    break
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "EXECVE":
                        self.tree.add_process(
                            event["pid"],
                            event["ppid"],
                            event["comm"],
                            event["timestamp"]
                        )
                        count += 1
                except json.JSONDecodeError:
                    continue

        print(f"✅ Built process tree with {len(self.tree.processes)} processes")
        return self.tree

def main():
    """Example usage"""
    builder = ProcessTreeBuilder()
    tree = builder.build_from_logs()

    if tree.processes:
        print("\n🔍 Finding suspicious process chains...")
        alerts = tree.find_attacks()

        if alerts:
            print("\n🚨 ALERTS DETECTED:")
            for alert in alerts:
                print(f"   ⚠️ {alert['type']}: Java (PID:{alert['java_pid']}) "
                      f"→ {alert['child_comm']} (PID:{alert['child_pid']})")
        else:
            print("✅ No suspicious chains found")

        print("\n" + tree.get_full_tree())

if __name__ == "__main__":
    main()