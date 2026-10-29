# Investigation 08 | Scheduled Task Persistence and Outbound Connections

**Date:** 29 October 2026  
**Case:** SOC LAB 008  
**Status:** Completed lab investigation  
**Severity:** High priority endpoint triage  
**Host:** LABWS02  
**Evidence:** Synthetic Windows Security and Sysmon event export  
**Tools:** Windows Event ID review, Sysmon process correlation, Python, Microsoft Sentinel KQL templates

## Alert received

The case started with a new scheduled task on a workstation. The task action called PowerShell using a script stored under the Public user directory. I checked whether this was normal administrative activity or a persistence mechanism that deserved escalation.

This is a controlled scenario. I created no real scheduled task, executed no suspicious script and made no external connection. The events in the CSV are training records. They are not copied from a customer endpoint.

## Initial evidence

| Time UTC | Event | Finding |
| :--- | :--- | :--- |
| 13:20:00 | Sysmon 1 | `cachehelper.exe` starts from `C:\Users\Public\Tools` |
| 13:20:01 | Sysmon 11 | Script file created under Public Libraries |
| 13:20:02 | Sysmon 1 | `schtasks.exe` runs, parent is the helper process |
| 13:20:03 | Security 4698 | New task `\CacheMonitor` is registered |
| 13:20:04 | Sysmon 11 | Task definition file is recorded |
| 13:50:03 | Sysmon 1 | Scheduled task launches PowerShell |
| 13:50:04 | Sysmon 22 | PowerShell queries `syncdesk.example` |
| 13:50:05 | Sysmon 3 | Same process contacts `203.0.113.92:443` |
| 14:20 and 14:50 | Sysmon 1, 22, 3 | Similar process, DNS and network sequence repeats |

## How I investigated it

### 1. Review the task registration

I started with Security Event ID `4698` and inspected the task name and action rather than relying on the task name alone.

The task was called `\CacheMonitor`. Its action started PowerShell with a script under `C:\Users\Public\Libraries`. That location is not proof of malware, but it is worth checking when the script has no obvious business owner.

### 2. Find how the task was created

I checked Sysmon process creation and file creation records. A helper executable under `C:\Users\Public\Tools` ran before the task appeared. The next process was `schtasks.exe`, with the helper as its parent.

The timeline shows the script file creation, the task registration command and the recorded task file. Together, those records support the conclusion that a scheduled task was configured to launch the script.

### 3. Follow the process activity

The task launched PowerShell three times, at 13:50, 14:20 and 14:50 UTC. Each run has a different process GUID.

I used each GUID to join the process start with its later DNS and network events. All three PowerShell runs queried `syncdesk.example` and connected to `203.0.113.92` on port `443`.

The repetition every 30 minutes is consistent with the task schedule. It does not prove data theft. The exported records do not contain network payloads, file contents, byte counts or endpoint file reputation.

### 4. Check unrelated tasks

I kept an unrelated task creation event at 15:02 UTC in the dataset. It has a different name, runs under SYSTEM and uses a different action. I excluded it from the suspected task chain instead of counting all task creation events as malicious.

### 5. Reproduce the review

~~~bash
python3 analysis.py
~~~

The script reads the [Windows event export](./evidence/windows_events.csv), counts the relevant events and checks that the three network connections share process GUIDs with the PowerShell starts. It prints a SHA256 digest for evidence verification.

The saved [analysis output](./evidence/analysis.txt) records the result. The [KQL templates](./queries.kql) show how I would repeat the investigation in Microsoft Sentinel. They were not run on live data.

## Investigation material

| File | Purpose |
| :--- | :--- |
| [Windows event export](./evidence/windows_events.csv) | Complete synthetic timeline |
| [Python analysis](./analysis.py) | Reproducible process and network correlation |
| [Analysis output](./evidence/analysis.txt) | Counts and evidence summary |
| [Sentinel queries](./queries.kql) | Hunting logic for the same event chain |
| [SOC incident report](./incident_report.md) | Severity, limitations and handover |

## Analyst decision

**Verdict:** Suspicious scheduled task persistence mechanism and repeated outbound communication observed in the lab evidence.

**Severity reasoning:** I would treat the alert as high priority because the task launches a script from a shared writable area and the process repeatedly reaches an external destination. Authorisation and purpose remain unknown.

**MITRE ATT&CK:** T1053.005 Scheduled Task fits the observed task creation and repeated execution. T1059.001 PowerShell fits the process activity. These are behaviour mappings, not proof that the script is malicious.

## Follow up actions

1. Confirm whether the task, helper binary and script were approved by the endpoint owner.
2. Collect the task XML, script and executable for static review and hashing.
3. Check file signatures, script contents and the initiating user account.
4. Review EDR process ancestry and search other endpoints for the same task and paths.
5. Expand network searches for the domain and destination using actual organisational logs.
6. If authorisation cannot be established and risk warrants it, escalate for containment according to policy.
7. Document the approved response and preserve evidence before changing or deleting a task.

**Case status:** Investigation documented. No containment or remediation was performed in the lab.
