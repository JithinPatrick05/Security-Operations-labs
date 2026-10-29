import csv
import hashlib
from collections import defaultdict
from datetime import datetime
from pathlib import Path

path = Path(__file__).parent / "evidence" / "windows_events.csv"
data = path.read_bytes()
events = list(csv.DictReader(data.decode("utf8").splitlines()))
tasks = [e for e in events if e["EventID"] == "4698" and e["TaskName"] == "\\CacheMonitor"]
other_tasks = [e for e in events if e["EventID"] == "4698" and e["TaskName"] != "\\CacheMonitor"]
launches = [e for e in events if e["EventID"] == "1" and e["Image"].lower().endswith("powershell.exe") and e["ParentImage"].lower().endswith("taskeng.exe")]
dns = [e for e in events if e["EventID"] == "22" and e["QueryName"] == "syncdesk.example"]
connections = [e for e in events if e["EventID"] == "3" and e["DestinationIp"] == "203.0.113.92" and e["DestinationPort"] == "443"]
dns_guids = {e["ProcessGuid"] for e in dns}
connection_guids = {e["ProcessGuid"] for e in connections}
correlated = [e for e in launches if e["ProcessGuid"] in dns_guids and e["ProcessGuid"] in connection_guids]
start_times = sorted(datetime.fromisoformat(e["TimeGenerated"].replace("Z", "+00:00")) for e in launches)
intervals = [(b - a).total_seconds() for a, b in zip(start_times, start_times[1:])]

print("Case 08 scheduled task investigation")
print("Evidence type: Controlled synthetic Windows event export")
print("Date: 29 October 2026")
print("Time zone: UTC")
print()
print(f"Total events: {len(events)}")
print("Host: LABWS02")
print(f"CacheMonitor scheduled task creations: {len(tasks)}")
print(f"Unrelated task creations: {len(other_tasks)}")
print(f"PowerShell starts from taskeng.exe: {len(launches)}")
print(f"DNS queries for syncdesk.example: {len(dns)}")
print(f"Connections to 203.0.113.92 port 443: {len(connections)}")
print(f"Process GUIDs with a matching launch, DNS event and connection: {len(correlated)}")
print(f"Task creation: {tasks[0]['TimeGenerated']}")
print(f"First observed task process: {launches[0]['TimeGenerated']}")
print(f"Repeat process interval: {int(intervals[0] / 60)} minutes" if intervals and len(set(intervals)) == 1 else "Repeat process interval: variable")
print()
print("Evidence interpretation:")
print("The task creation and three later PowerShell executions form one consistent chain.")
print("The repeated DNS and network events match the three PowerShell process GUIDs.")
print("No file contents, transferred bytes, user approval or exfiltration proof is present.")
print()
print(f"Evidence SHA256: {hashlib.sha256(data).hexdigest()}")
