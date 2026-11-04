from pathlib import Path
import csv
import json

BASE = Path(__file__).resolve().parent
EVIDENCE = BASE / "evidence"

def read_csv(name):
    with (EVIDENCE / name).open(newline="", encoding="utf8") as handle:
        return list(csv.DictReader(handle))

with (EVIDENCE / "sentinel_alert.json").open(encoding="utf8") as handle:
    sentinel = json.load(handle)

security = read_csv("windows_security.csv")
sysmon = read_csv("sysmon_events.csv")
defender = read_csv("defender_events.csv")
packets = read_csv("wireshark_packet_summary.csv")

successful_logon = [
    row for row in security
    if row["event_id"] == "4624"
    and row["account"] == r"CORP\svc_backup"
    and row["source_ip"] == "10.40.8.27"
]

privileged_logon = [
    row for row in security
    if row["event_id"] == "4672"
    and row["account"] == r"CORP\svc_backup"
]

service_install = [
    row for row in security
    if row["event_id"] == "7045"
    and "WinTelemetry" in row["details"]
]

file_create = [
    row for row in sysmon
    if row["event_id"] == "11"
    and row["target"].endswith(r"WinTelemetry\telemetrysvc.exe")
]

service_process = [
    row for row in sysmon
    if row["event_id"] == "1"
    and row["image"].endswith(r"WinTelemetry\telemetrysvc.exe")
    and row["parent_image"].endswith("services.exe")
]

outbound = [
    row for row in sysmon
    if row["event_id"] == "3"
    and row["image"].endswith(r"WinTelemetry\telemetrysvc.exe")
    and row["destination_port"] == "443"
]

smb_packets = [
    row for row in packets
    if row["protocol"] == "SMB2"
    and row["source"] in ("10.40.8.27", "10.40.20.18")
]

session_success = [
    row for row in packets
    if row["protocol"] == "SMB2"
    and "Session Setup Response Success" in row["info"]
]

print("CASE 010 CORRELATION RESULTS")
print()
print("Sentinel severity:", sentinel["severity"])
print("Sentinel SMB attempts:", sentinel["network_observation"])
print("Windows Security records reviewed:", len(security))
print("Sysmon records reviewed:", len(sysmon))
print("Defender records reviewed:", len(defender))
print("Packet summary rows reviewed:", len(packets))
print()
print("Correlation checks")
print("Successful privileged network logon from FINWS042:", bool(successful_logon))
print("Special privileges assigned:", bool(privileged_logon))
print("WinTelemetry service installed:", bool(service_install))
print("telemetrysvc.exe created:", bool(file_create))
print("telemetrysvc.exe launched by services.exe:", bool(service_process))
print("SMB2 session setup success observed:", bool(session_success))
print("SMB2 packet records in target conversation:", len(smb_packets))
print("Outbound TLS connections from telemetrysvc.exe:", len(outbound))
print()
print("Target scope")
print("Source host:", sentinel["source_host"])
print("Target host:", sentinel["target_host"])
print("Account:", sentinel["account"])
print("Confirmed service:", "WinTelemetry" if service_install else "Not confirmed")
print("Confirmed file:", r"C:\ProgramData\WinTelemetry\telemetrysvc.exe" if file_create else "Not confirmed")
