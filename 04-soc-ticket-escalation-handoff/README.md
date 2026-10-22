# SOC Ticket Writing, Escalation and Shift Handoff

**Status:** Completed  
**Lab date:** 23 May 2026  
**Primary tools:** Elastic, Kibana Discover, Sysmon, Windows Security logs, Elastic Agent / Fleet

## Overview

This lab focused on the part of SOC work that happens after the first technical review: documenting what happened, choosing an appropriate severity, recording the analyst verdict, deciding whether to close or escalate, and handing open context to the next analyst.

The source events came from a Windows 10 victim VM sending Sysmon and Windows logs into an Elastic/Kibana lab environment.

The main objective was to convert raw events into concise SOC documentation without overstating what the evidence proved.

## Lab Environment

| Component | Role | Address / Identity |
|---|---|---|
| Ubuntu SIEM VM | Elasticsearch, Kibana, Fleet Server, analyst search interface | 192.168.56.101 |
| Windows 10 Victim VM | Monitored endpoint sending Sysmon and Windows logs | 192.168.56.104 |
| Endpoint hostname | Windows victim | DESKTOP-3JKM5O9 |
| Lab user | User generating authorised activity | DESKTOP-3JKM5O9\mmajeed |

## Deliverables

- 5 SOC tickets
- 3 escalation-writing exercises
- 2 shift handoff notes
- Severity reasoning model
- SOC ticket template
- Escalation template
- Analyst documentation lessons

## Tickets Reviewed

| # | Activity | Source | Severity | Verdict |
|---|---|---|---|---|
| 1 | PowerShell launched `whoami.exe` | Sysmon Event ID 1 | Medium | Benign by context / suspicious by technique |
| 2 | Local Administrators group enumeration | Sysmon Event ID 1 | Medium | Benign by context / suspicious by technique |
| 3 | `curl.exe` request to GitHub | Sysmon Event ID 1 | Medium | Benign by context / suspicious by technique |
| 4 | `nslookup.exe github.com` | Sysmon Event ID 1 | Low | Benign by context |
| 5 | Failed local logon | Windows Security Event ID 4625 | Low | Likely user error / benign by context |

[View detailed SOC tickets](./soc-tickets.md)

## Key Event Evidence

### PowerShell user discovery

```text
Process: C:\Windows\system32\whoami.exe
Parent: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command whoami
User: DESKTOP-3JKM5O9\mmajeed
Process ID: 7980
Parent Process ID: 8272
Log source: Microsoft-Windows-Sysmon/Operational
Event ID: 1
```

### Local administrator enumeration

```text
Process: C:\Windows\system32\net1.exe localgroup administrators
Parent: C:\Windows\system32\net.exe localgroup administrators
User: DESKTOP-3JKM5O9\mmajeed
Process ID: 9992
Parent Process ID: 1804
Log source: Microsoft-Windows-Sysmon/Operational
Event ID: 1
```

### Command-line web request

```text
Process: C:\Windows\system32\curl.exe https://github.com
Parent: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: DESKTOP-3JKM5O9\mmajeed
Process ID: 9900
Parent Process ID: 8272
Log source: Microsoft-Windows-Sysmon/Operational
Event ID: 1
```

### DNS lookup

```text
Process: C:\Windows\system32\nslookup.exe github.com
Parent: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: DESKTOP-3JKM5O9\mmajeed
Process ID: 1616
Parent Process ID: 8272
Log source: Microsoft-Windows-Sysmon/Operational
Event ID: 1
```

### Failed logon

```text
Host: DESKTOP-3JKM5O9
User: DESKTOP-3JKM5O9\mmajeed
Log source: Windows Security
Event ID: 4625
Timestamp: 2026-05-22 21:00:17.106
Observed count in reviewed context: 1
```

## Severity Reasoning

I used context rather than command name alone.

```text
Command
+ user
+ parent process
+ destination
+ frequency
+ follow-on activity
+ business/host impact
= severity decision
```

Examples:

- A single failed logon from a known user: low.
- `whoami` from PowerShell: medium technique, but benign if authorised and isolated.
- Repeated failed logons from an unknown source: medium/high.
- New account creation, administrator-group changes or suspicious service installation: high.
- Confirmed credential dumping, ransomware or active compromise: high/critical.

## Escalation Practice

The lab also included three escalation-writing exercises:

1. Multiple failed logons from an unknown or unexpected user.
2. `curl.exe` launched from PowerShell.
3. Local Administrators group enumeration.

These were written as analyst escalation scenarios. They should not be read as three confirmed malicious incidents observed in the lab.

[View escalation exercises](./escalation-exercises.md)

## Shift Handoff

At the end of the exercise, the reviewed lab-generated tickets were closed with no confirmed malicious activity. The handoff documented:

- what was reviewed
- what was closed
- what remained open
- what conditions should increase severity if similar activity appeared in production

[View shift handoff notes](./shift-handoff.md)

## What I Learned

- Evidence in the ticket must match the alert being documented.
- A log proves the event it records, not assumptions about intent or authorisation.
- Severity and verdict are separate decisions.
- Process and parent process must be recorded separately.
- Windows Security events and Sysmon events must not be mixed up.
- Escalation notes should quickly explain what happened, why it matters, what was checked and what L2 should do next.
- Benign activity can still be useful SOC practice when the technique itself is security relevant.

## Portfolio Note

The events in this lab were generated in a controlled environment. The analyst documentation reflects the reviewed evidence and intentionally distinguishes between authorised lab activity and hypothetical production escalation scenarios.
