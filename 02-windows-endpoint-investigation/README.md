# Windows Endpoint Investigation - Sysmon

> **Lab type:** Completed controlled endpoint investigation  
> **Host:** JPtest1  
> **Operating system:** Windows 11  
> **Data sources:** Sysmon, Windows Event Viewer  
> **Related case:** [Wireshark Traffic Analysis](../01-wireshark-traffic-analysis/)

## Summary

The earlier Wireshark capture showed JPtest1 making short TLS connections to the same remote address at roughly one-minute intervals. The network capture could show the destination and timing, but not which process on the workstation was creating the traffic.

This lab continues that investigation on the endpoint.

Sysmon events showed that the traffic came from a PowerShell process launched from the user's desktop session. The same process queried the hostname seen in Wireshark, connected to the same remote IP over TCP/443 and wrote a small file under the Public profile. A registry Run value was also created for the same PowerShell command.

The activity was generated in a controlled lab so I could practise correlating network and endpoint telemetry without using a live incident.

## Environment

| Item | Value |
|---|---|
| Hostname | JPtest1 |
| Host IP | 192.168.1.143 |
| User | JPtest1\\jpatrick |
| OS | Windows 11 |
| Endpoint logging | Sysmon |
| Log path | Microsoft-Windows-Sysmon/Operational |
| Remote IP | 203.0.113.77 |
| DNS name | cdn-storage-sync.test |
| Primary process | powershell.exe |
| Process ID | 6124 |
| Parent process | explorer.exe |
| Initial severity | Medium |

Wireshark displayed packet times in local time. Sysmon's \`UtcTime\` field is UTC, so the endpoint events appear 5 hours 30 minutes earlier in the raw event data.

## What I was trying to answer

The network capture left three main questions:

1. Which process created the connections to 203.0.113.77?
2. Did the DNS activity and network activity come from the same process?
3. Was there any related file or persistence activity on the endpoint?

## Process tree

The process creation event showed:

~~~text
explorer.exe
  └── powershell.exe
      PID: 6124
      User: JPtest1\jpatrick
      Command:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Libraries\sync-check.ps1
~~~

The parent process was the logged-in user's \`explorer.exe\` session, not a Windows service.

That does not make PowerShell malicious by itself, but the command line was worth following because it referenced a script from a Public directory and lined up with the suspicious network activity.

## Timeline

| Local time | Sysmon UTC time | Event | Detail |
|---|---|---|---|
| 22:16:02.811 | 16:46:02.811 | Event ID 1 | powershell.exe PID 6124 created by explorer.exe |
| 22:16:03.041 | 16:46:03.041 | Event ID 11 | jp-cache.dat created under C:\\Users\\Public\\Libraries |
| 22:16:03.447 | 16:46:03.447 | Event ID 22 | powershell.exe queries cdn-storage-sync.test |
| 22:16:04.118 | 16:46:04.118 | Event ID 3 | powershell.exe connects to 203.0.113.77:443 |
| 22:16:04.944 | 16:46:04.944 | Event ID 13 | HKCU Run value UpdateCheck modified |
| 22:17:03.977 | 16:47:03.977 | Event ID 3 | Second connection to 203.0.113.77:443 |
| 22:18:04.502 | 16:48:04.502 | Event ID 3 | Third connection |
| 22:19:04.146 | 16:49:04.146 | Event ID 3 | Fourth connection |
| 22:20:03.814 | 16:50:03.814 | Event ID 3 | Fifth connection |
| 22:21:03.472 | 16:51:03.472 | Event ID 22 | cdn-storage-sync.test queried again |
| 22:21:04.321 | 16:51:04.321 | Event ID 3 | Sixth connection |

The endpoint timestamps line up with the network capture to within milliseconds.

## 1. Process creation - Event ID 1

The first useful event was Sysmon Event ID 1.

Key fields:

| Field | Value |
|---|---|
| Image | C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
| ProcessId | 6124 |
| User | JPtest1\\jpatrick |
| ParentImage | C:\\Windows\\explorer.exe |
| ParentProcessId | 4288 |
| IntegrityLevel | Medium |
| CurrentDirectory | C:\\Users\\jpatrick\\ |
| CommandLine | powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\Libraries\\sync-check.ps1 |

The process was running in the context of the interactive user and was started from Explorer.

### Assessment

The suspicious part was not simply that PowerShell ran. The useful detail was the combination of:

- script execution from a Public directory
- \`ExecutionPolicy Bypass\`
- matching DNS activity
- matching outbound connections
- later persistence-related registry activity

That made the process a sensible pivot point for the rest of the investigation.

**MITRE ATT&CK:** T1059.001 - PowerShell

## 2. File creation - Event ID 11

At 22:16:03.041 local time, the same PowerShell process created:

~~~text
C:\Users\Public\Libraries\jp-cache.dat
~~~

Relevant fields:

| Field | Value |
|---|---|
| Image | powershell.exe |
| ProcessId | 6124 |
| TargetFilename | C:\\Users\\Public\\Libraries\\jp-cache.dat |
| CreationUtcTime | 16:46:03.041 |

The file was only 2.6 KB in the lab and contained non-sensitive test data.

### Assessment

A file under the Public profile is not automatically suspicious, but in this case it was created by the same process that generated the later DNS and network activity. That correlation increased its relevance.

## 3. DNS query - Event ID 22

Sysmon Event ID 22 showed:

| Field | Value |
|---|---|
| ProcessId | 6124 |
| Image | powershell.exe |
| QueryName | cdn-storage-sync.test |
| QueryStatus | 0 |
| QueryResults | 203.0.113.77 |

Local time:

~~~text
22:16:03.447
~~~

This matched the hostname and timestamp found in the Wireshark capture.

The DNS query occurred 406 ms after the file creation event and 671 ms before the first outbound connection.

## 4. Network connection - Event ID 3

The next event tied the PowerShell process directly to the remote IP.

| Field | Value |
|---|---|
| Image | powershell.exe |
| ProcessId | 6124 |
| User | JPtest1\\jpatrick |
| Protocol | tcp |
| SourceIp | 192.168.1.143 |
| SourcePort | 50342 |
| DestinationIp | 203.0.113.77 |
| DestinationPort | 443 |
| DestinationPortName | https |
| Initiated | true |

Time:

~~~text
22:16:04.118 local
16:46:04.118 UTC
~~~

The source port \`50342\` also matched the first TCP conversation documented in the Wireshark lab.

The later Event ID 3 records used source ports:

~~~text
50363
50381
50405
50426
50444
~~~

These matched the six Wireshark conversations.

### Assessment

This was the most important correlation in the lab.

Wireshark had shown that JPtest1 was talking to 203.0.113.77, but Sysmon identified the process responsible: \`powershell.exe\`, PID 6124.

## 5. Registry modification - Event ID 13

At 22:16:04.944 local time, Sysmon recorded a registry value modification.

| Field | Value |
|---|---|
| Event ID | 13 |
| Image | powershell.exe |
| ProcessId | 6124 |
| TargetObject | HKU\\<USER-SID>\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateCheck |
| Details | powershell.exe -NoProfile -WindowStyle Hidden -File C:\\Users\\Public\\Libraries\\sync-check.ps1 |

A Run key causes the configured command to start when the user signs in.

### Assessment

In this lab, the Run value was intentionally created as part of the simulation. In an unknown incident, this would be treated as a persistence lead and checked against expected software and change history.

**MITRE ATT&CK:** T1060 / current ATT&CK mapping T1547.001 - Registry Run Keys / Startup Folder

## 6. Repeated connections

Filtering Event ID 3 for PID 6124 and destination 203.0.113.77 produced six records.

| Local time | Source port | Destination |
|---|---:|---|
| 22:16:04.118 | 50342 | 203.0.113.77:443 |
| 22:17:03.977 | 50363 | 203.0.113.77:443 |
| 22:18:04.502 | 50381 | 203.0.113.77:443 |
| 22:19:04.146 | 50405 | 203.0.113.77:443 |
| 22:20:03.814 | 50426 | 203.0.113.77:443 |
| 22:21:04.321 | 50444 | 203.0.113.77:443 |

Average interval: **60.04 seconds**

The timings and source ports matched the Wireshark findings.

This changed the earlier network-only assessment from:

> automated traffic from JPtest1

to:

> automated traffic generated by a PowerShell process running as JPtest1\\jpatrick

That is a much stronger finding because it ties the network behaviour back to an endpoint process.

## Correlation with Wireshark

| Wireshark finding | Sysmon confirmation |
|---|---|
| JPtest1 connected to 203.0.113.77 | Event ID 3 identified powershell.exe as the process |
| First source port 50342 | Event ID 3 recorded SourcePort 50342 |
| DNS query for cdn-storage-sync.test | Event ID 22 showed powershell.exe making the query |
| Six roughly one-minute connections | Six Event ID 3 records from PID 6124 |
| Network payload encrypted | Endpoint telemetry supplied the missing process context |

## Findings

The endpoint evidence supports the following conclusions:

- PowerShell PID 6124 was launched under user JPtest1\\jpatrick.
- The process executed a script from C:\\Users\\Public\\Libraries.
- The same process created jp-cache.dat.
- The same process queried cdn-storage-sync.test.
- The DNS result was 203.0.113.77.
- The same process initiated TCP/443 connections to 203.0.113.77.
- Six network events matched the source ports and timing seen in Wireshark.
- The same process modified a user Run key for persistence.

Because this is a controlled exercise, the activity is intentionally generated for the lab. In an unknown case, the same combination would justify escalation and further endpoint review.

## MITRE ATT&CK mapping

| Behaviour | Technique | ID |
|---|---|---|
| PowerShell execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| HTTPS communication | Application Layer Protocol: Web Protocols | T1071.001 |
| DNS use | Application Layer Protocol: DNS | T1071.004 |
| Run key modification | Registry Run Keys / Startup Folder | T1547.001 |

## Triage decision

**Severity: Medium, escalate for further endpoint review**

The network behaviour alone was suspicious but inconclusive. Sysmon added process context and showed that the same PowerShell process was responsible for DNS, outbound network traffic, file creation and a persistence-related registry modification.

In a production environment, I would preserve the endpoint evidence and verify whether the PowerShell execution was authorised before making a final malicious/benign determination.

## Next steps

1. Collect the script and calculate its SHA-256 hash.
2. Review the full PowerShell command history and PowerShell Operational log.
3. Check the Run key value directly and determine when it was created.
4. Review the file at C:\\Users\\Public\\Libraries\\jp-cache.dat.
5. Search other endpoints for the same DNS name, IP and script path.
6. Review Defender/EDR telemetry for PID 6124 and its parent process.
7. Check for scheduled tasks, services or additional persistence.
8. If the activity is unauthorised, isolate the endpoint and remove persistence after evidence is preserved.

## What this lab demonstrated

The useful part of the exercise was the correlation between network and endpoint data.

Wireshark showed **where the host was communicating**. Sysmon showed **which process was doing it**.

Neither data source was as useful on its own as the two were together.


## Detection opportunities

After correlating the events, I noted a few conditions that would be useful for detection rather than relying on a single indicator.

### PowerShell from a user-writable location

A useful alert condition would be PowerShell executing a script from locations such as:

~~~text
C:\Users\Public\
C:\Users\<user>\AppData\
C:\ProgramData\
~~~

The path alone is not enough to call the activity malicious, but it becomes more useful when paired with suspicious command-line options or network activity.

### PowerShell followed by outbound HTTPS

In this case, the sequence was:

~~~text
Event ID 1  -> powershell.exe created
Event ID 22 -> DNS query
Event ID 3  -> outbound TCP/443
~~~

That sequence is stronger than any one event by itself.

### Run key modification

A user Run key changed by PowerShell would be worth reviewing, especially if the configured command points to a script in a user-writable directory.

Useful registry path:

~~~text
Software\Microsoft\Windows\CurrentVersion\Run
~~~

### Repeated connections to the same destination

Six connections to the same host at an average interval of 60.04 seconds were visible in both Wireshark and Sysmon.

The timing pattern would be useful as a hunting lead when combined with process context.

## Containment and remediation

If this had been an unauthorised production event, my response would be:

1. Preserve the relevant Sysmon and Windows event logs.
2. Record the process tree, command line, destination IP and DNS name.
3. Isolate the endpoint if additional evidence confirms malicious activity.
4. Stop the responsible process after evidence collection.
5. Remove the Run key persistence entry.
6. Quarantine the script and related file.
7. Block the confirmed malicious destination at the appropriate control point.
8. Search other endpoints for the same script path, domain and destination.
9. Reset affected credentials if there is evidence they were exposed.
10. Re-run endpoint and network checks before returning the host to service.

## Lab cleanup

Because this was a controlled exercise, the persistence and test artefacts should be removed after the investigation.

Items to remove:

~~~text
C:\Users\Public\Libraries\sync-check.ps1
C:\Users\Public\Libraries\jp-cache.dat
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateCheck
~~~

The endpoint should then be checked to confirm the repeated outbound connection no longer occurs.

## Final assessment

**Disposition: Suspicious activity confirmed within the controlled lab scenario**

The important finding was not simply that PowerShell was present. The same ProcessGuid and PID linked process creation, file creation, DNS resolution, network communication and registry persistence.

Wireshark first identified a repeated network pattern. Sysmon then supplied the missing process and user context.

If the same chain appeared on an unmanaged production workstation without an approved explanation, I would treat it as a high-priority endpoint investigation.

## Lessons learned

- Network telemetry can identify a suspicious pattern without identifying the process behind it.
- Sysmon Event ID 3 is useful for tying a remote connection back to a process.
- ProcessGuid is a better correlation key than PID when reviewing events over time.
- DNS events provide a useful link between a hostname and later network activity.
- PowerShell should be judged in context rather than treated as malicious by default.
- Persistence activity significantly changes the risk of an otherwise ambiguous process.
- Time-zone differences need to be normalised before correlating endpoint and network data.
