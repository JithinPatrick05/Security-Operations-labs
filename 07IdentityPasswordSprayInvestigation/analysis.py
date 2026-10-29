import csv
import hashlib
from collections import Counter
from pathlib import Path

path = Path(__file__).parent / "evidence" / "signins.csv"
data = path.read_bytes()
events = list(csv.DictReader(data.decode("utf8").splitlines()))
ip = "203.0.113.45"
suspect = [event for event in events if event["IPAddress"] == ip]
counts = Counter(event["ResultType"] for event in suspect)
users = {event["UserPrincipalName"] for event in suspect}
other = [event for event in events if event["IPAddress"] == "198.51.100.44" and event["ResultType"] == "0"]

print("Case 07 identity investigation")
print("Evidence type: Controlled synthetic training export")
print("Date: 29 October 2026")
print("Time zone: UTC")
print()
print(f"Total sign in records: {len(events)}")
print(f"Suspect source: {ip}")
print(f"Suspect source records: {len(suspect)}")
print(f"Distinct targeted accounts: {len(users)}")
print(f"Invalid password results 50126: {counts['50126']}")
print(f"MFA failure results 500121: {counts['500121']}")
print(f"Successful results from suspect source: {counts['0']}")
print(f"First suspect event: {min(r['TimeGenerated'] for r in suspect)}")
print(f"Last suspect event: {max(r['TimeGenerated'] for r in suspect)}")
print(f"Other source 198.51.100.44 successful sign ins: {len(other)}")
print()
print("Evidence interpretation:")
print("The source attempted authentication across 12 accounts in two passes.")
print("The MFA failure belongs to maya@contoso.example.")
print("The success from another IP must not be attributed to the suspect source.")
print("An MFA failure does not establish a completed account takeover.")
print()
print(f"Evidence SHA256: {hashlib.sha256(data).hexdigest()}")
