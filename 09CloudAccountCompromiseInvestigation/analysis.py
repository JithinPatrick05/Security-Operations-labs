from pathlib import Path
import csv

BASE = Path(__file__).resolve().parent
EVIDENCE = BASE / "evidence"

def load_csv(name):
    with (EVIDENCE / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

signins = load_csv("signins.csv")
office = load_csv("office_activity.csv")

source_ip = "203.0.113.44"
affected_user = "finance.manager@lab.example"
forward_target = "archive.notice@example.net"

source_events = [r for r in signins if r["ip_address"] == source_ip]
successful_source = [r for r in source_events if r["status"] == "Success"]
targeted_users = sorted({r["user"] for r in source_events})

mail_events = [
    r for r in office
    if r["user"] == affected_user and forward_target in r["parameters"]
]

containment = [
    r for r in office
    if r["actor"] == "security.admin@lab.example"
]

print("SOC LAB 009 evidence review")
print()
print(f"Sign-in records reviewed: {len(signins)}")
print(f"Microsoft 365 audit records reviewed: {len(office)}")
print(f"Events from suspicious IP: {len(source_events)}")
print(f"Successful sign-ins from suspicious IP: {len(successful_source)}")
print(f"Accounts targeted from suspicious IP: {len(targeted_users)}")
print(f"Forwarding-related events on affected mailbox: {len(mail_events)}")
print(f"Containment actions recorded: {len(containment)}")
print()
print("Accounts observed from suspicious IP")
for user in targeted_users:
    attempts = [r for r in source_events if r["user"] == user]
    successes = [r for r in attempts if r["status"] == "Success"]
    print(f"{user}: attempts={len(attempts)}, successes={len(successes)}")
print()
print("Correlation checks")
print("Successful abnormal sign-in:", any(
    r["user"] == affected_user
    and r["ip_address"] == source_ip
    and r["status"] == "Success"
    for r in signins
))
print("External inbox rule created:", any(
    r["operation"] == "New-InboxRule"
    and r["user"] == affected_user
    and forward_target in r["parameters"]
    for r in office
))
print("Mailbox forwarding configured:", any(
    r["operation"] == "Set-Mailbox"
    and r["user"] == affected_user
    and forward_target in r["parameters"]
    for r in office
))
print("Inbox rule removed:", any(r["operation"] == "Remove-InboxRule" for r in containment))
print("Sessions revoked:", any(r["operation"] == "Revoke-Sessions" for r in containment))
print("Password reset:", any(r["operation"] == "Reset-Password" for r in containment))
