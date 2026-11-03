from pathlib import Path
import csv

BASE = Path(__file__).resolve().parent
EVIDENCE = BASE / "evidence"

def load_csv(name):
    with (EVIDENCE / name).open(newline="", encoding="utf8") as handle:
        return list(csv.DictReader(handle))

signins = load_csv("signins.csv")
office = load_csv("office_activity.csv")

affected_user = "Finance Manager"
suspicious_source = "Public IP redacted"
forwarding_value = "external mailbox redacted"

source_events = [row for row in signins if row["source"] == suspicious_source]
successful_source = [row for row in source_events if row["status"] == "Success"]
targeted_users = sorted({row["user"] for row in source_events})

forwarding_events = [
    row for row in office
    if row["user"] == affected_user and forwarding_value in row["parameters"]
]

containment = [
    row for row in office
    if row["actor"] == "Security Administrator"
]

print("SOC CASE 009 EVIDENCE REVIEW")
print()
print(f"Sign in records reviewed: {len(signins)}")
print(f"Microsoft 365 audit records reviewed: {len(office)}")
print(f"Events from suspicious source: {len(source_events)}")
print(f"Successful sign ins from suspicious source: {len(successful_source)}")
print(f"Accounts targeted from suspicious source: {len(targeted_users)}")
print(f"Forwarding related events on affected mailbox: {len(forwarding_events)}")
print(f"Containment actions recorded: {len(containment)}")
print()
print("Accounts observed from suspicious source")
for user in targeted_users:
    attempts = [row for row in source_events if row["user"] == user]
    successes = [row for row in attempts if row["status"] == "Success"]
    print(f"{user}: attempts {len(attempts)}, successes {len(successes)}")
print()
print("Correlation checks")
print("Successful abnormal sign in:", any(
    row["user"] == affected_user
    and row["source"] == suspicious_source
    and row["status"] == "Success"
    for row in signins
))
print("External inbox rule created:", any(
    row["operation"] == "New-InboxRule"
    and row["user"] == affected_user
    and forwarding_value in row["parameters"]
    for row in office
))
print("Mailbox forwarding configured:", any(
    row["operation"] == "Set-Mailbox"
    and row["user"] == affected_user
    and forwarding_value in row["parameters"]
    for row in office
))
print("Inbox rule removed:", any(row["operation"] == "Remove-InboxRule" for row in containment))
print("Sessions revoked:", any(row["operation"] == "Revoke-Sessions" for row in containment))
print("Password reset:", any(row["operation"] == "Reset-Password" for row in containment))
