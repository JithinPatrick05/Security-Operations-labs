# Shift Handoff Notes

## End-of-Shift Summary

During this exercise I created SOC tickets from lab events reviewed in Elastic/Kibana and Windows/Sysmon telemetry.

### Environment

```text
SIEM: Elastic / Kibana
Endpoint: DESKTOP-3JKM5O9
User: DESKTOP-3JKM5O9\mmajeed
Log sources:
- Microsoft-Windows-Sysmon/Operational
- Windows Security
```

### Tickets

```text
PowerShell whoami                         Closed as benign lab activity
Local Administrators enumeration         Closed as benign lab activity
curl.exe to GitHub                       Closed as benign lab activity
nslookup GitHub                          Closed as benign lab activity
Single 4625 failed logon                 Closed as likely user error
```

### Findings

No confirmed malicious activity was identified in the reviewed lab events.

Several events were useful SOC examples because the technique could be suspicious in another context:

- PowerShell user discovery
- local privilege-group enumeration
- command-line web requests
- DNS lookup from PowerShell
- authentication failure

### Open Items

No open incidents remained from the controlled exercise.

### Watch Conditions for Similar Production Activity

Increase severity if any of the following appear:

```text
unknown or unexpected user
repeated authentication failures
privileged account targeting
unusual source IP
suspicious or newly registered domain
payload download
follow-on process execution
new user creation
addition to Administrators
remote access after failed logons
```

## Handoff Principle

A useful shift handoff should allow the next analyst to answer four questions immediately:

1. What did I review?
2. What did I close?
3. What is still open?
4. What should be watched next?
