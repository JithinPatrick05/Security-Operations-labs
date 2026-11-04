# Investigation 10 | Network Intrusion, SMB Lateral Movement and Remote Service Execution

**Date:** 4 November 2026  
**Case:** 010  
**Severity:** High  
**Status:** Closed after containment and validation  
**Source host:** FINWS042  
**Target host:** FILESRV02  
**Primary tools:** Wireshark, Microsoft Sentinel, Microsoft Defender for Endpoint, Sysmon, Windows Security logs, KQL, Python, MITRE ATT&CK

## Alert

I investigated a Sentinel alert after a finance workstation began making a burst of SMB connection attempts across the server subnet.

FINWS042 normally had no reason to connect directly to multiple infrastructure servers. Within less than one minute the host attempted TCP 445 connections to 34 internal systems.

Most connections failed, but three completed a TCP handshake.

One of those sessions reached FILESRV02.

The same source was then linked to a successful Windows network logon on FILESRV02 using the privileged service account `CORP\svc_backup`.

A new executable called `telemetrysvc.exe` appeared under `C:\ProgramData\WinTelemetry\` and a new Windows service named `WinTelemetry` was registered shortly afterwards.

I did not treat the network scan alone as proof of compromise. I moved through the packet capture, authentication events, Sysmon events, Defender telemetry and service creation logs until the complete sequence was clear.

## What stood out first

The first thing that stood out was the behaviour of FINWS042.

It was a finance workstation, not a management server or vulnerability scanner.

The host attempted SMB connections to 34 systems in 58 seconds.

The connection pattern was sequential rather than normal user file access.

Wireshark showed repeated TCP SYN packets from the same workstation to TCP 445 across the server subnet.

The packet capture then showed a complete SMB2 session to FILESRV02.

That changed the investigation from a possible noisy workstation issue into a potential lateral movement case.

## Investigation

### 1. I validated the network alert in Sentinel

I started with the Sentinel incident and checked the entities attached to it.

The source entity was `FINWS042` with internal address `10.40.8.27`.

The main target was `FILESRV02` with internal address `10.40.20.18`.

The alert window was 10:14:02 UTC to 10:15:00 UTC.

I expanded the query window by thirty minutes on both sides so I could see what happened before the scan and what happened after the successful connection.

### 2. I checked the packet capture in Wireshark

I filtered the capture to traffic from the source workstation.

`ip.src == 10.40.8.27`

I then isolated new SMB connection attempts.

`ip.src == 10.40.8.27 && tcp.dstport == 445 && tcp.flags.syn == 1 && tcp.flags.ack == 0`

This returned 34 connection attempts in 58 seconds.

Most targets responded with resets or had no completed connection.

FILESRV02 completed the TCP handshake.

I then filtered the conversation between the two systems.

`ip.addr == 10.40.8.27 && ip.addr == 10.40.20.18 && tcp.port == 445`

Wireshark showed SMB2 negotiation followed by session setup and tree connect activity.

The packet capture confirmed that the source did more than scan the server. It established an SMB session.

The capture did not contain the credentials in clear text, so I moved to Windows authentication logs to identify the account.

### 3. I checked Windows Security events on FILESRV02

Windows Security Event ID 4624 showed a successful network logon at 10:14:41 UTC.

The relevant fields were:

Account name: `svc_backup`

Domain: `CORP`

Logon type: `3`

Authentication package: `NTLM`

Source workstation: `FINWS042`

Source address: `10.40.8.27`

Two seconds later Event ID 4672 recorded special privileges assigned to the same logon session.

The account was a real service account used for backup operations, but it was expected to authenticate from `MGMT01`, not from a finance workstation.

That was the first strong indication that a valid privileged account was being misused.

### 4. I checked file creation and service installation

At 10:14:46 UTC Sysmon Event ID 11 recorded a new file:

`C:\ProgramData\WinTelemetry\telemetrysvc.exe`

SHA256:

`9ff8f6e4c5d9e3769abc51fc3138eda5fda3ff32aee6c66a010c218c9660614e`

The file had no Microsoft signature and no matching approved software deployment record.

At 10:14:49 UTC Windows System Event ID 7045 recorded a new service.

Service name: `WinTelemetry`

Image path: `C:\ProgramData\WinTelemetry\telemetrysvc.exe`

Service account: `LocalSystem`

Start type: `Auto Start`

This was the point where the case moved from suspicious authentication into confirmed unauthorised execution on the server.

### 5. I followed the process tree in Defender and Sysmon

Microsoft Defender for Endpoint showed `services.exe` starting `telemetrysvc.exe` as SYSTEM.

The new process then created `cmd.exe`.

The child process launched `whoami.exe` and `hostname.exe`.

I also checked for additional process activity from the same process tree.

No approved maintenance tool or software deployment process was linked to the executable.

The combination of a privileged remote logon, a new executable, service creation and SYSTEM execution confirmed that the attacker had achieved code execution on FILESRV02.

### 6. I checked network activity from the new process

Defender DeviceNetworkEvents showed `telemetrysvc.exe` making outbound TCP 443 connections to an external address.

The public destination is redacted in this repository.

I went back to Wireshark and filtered the connection.

The sessions were short, encrypted and repeated at roughly sixty second intervals.

The packet sizes were also very similar between sessions.

That pattern looked like beaconing.

I recorded it as suspected command and control behaviour, but I did not mark it as confirmed command and control because the TLS payload was encrypted and I did not have decrypted application data.

### 7. I scoped the source workstation

I checked Defender activity on FINWS042 before the SMB scan.

The workstation had an interactive session for a finance user.

A process named `powershell.exe` had started under the user context approximately three minutes before the network scan.

A short time later `net.exe` appeared in the same process chain.

I did not have enough evidence in this dataset to prove the original access vector to FINWS042.

I therefore recorded the workstation as compromised based on the lateral movement behaviour, but left the initial access method unresolved.

### 8. I scoped the privileged account

I searched Sentinel for all recent authentication events involving `CORP\svc_backup`.

Expected activity came from `MGMT01`.

The authentication from FINWS042 was the only event from a user workstation in the reviewed period.

I then searched for successful network logons from FINWS042 to other hosts.

FILESRV02 was the only server where the connection progressed to successful privileged authentication.

This limited the confirmed lateral movement scope to one target server.

### 9. I searched for the service and file across the environment

I hunted Defender and Sentinel for:

`WinTelemetry`

`telemetrysvc.exe`

The SHA256 value

`C:\ProgramData\WinTelemetry\`

The external destination

The source workstation

No second server contained the service or executable in the evidence reviewed.

That meant I had one compromised workstation and one confirmed compromised server.

### 10. I contained the incident

Once the lateral movement chain was confirmed I completed the response sequence.

1. I isolated FINWS042 in Defender for Endpoint.
2. I isolated FILESRV02 in Defender for Endpoint.
3. I disabled `CORP\svc_backup` pending credential rotation.
4. I blocked the SHA256 value in Defender.
5. I blocked the external destination at the network control layer.
6. I preserved the service configuration, process tree, authentication events and packet evidence.
7. I stopped and removed `WinTelemetry` after evidence collection.
8. I removed `telemetrysvc.exe` after the file was preserved for analysis.
9. I rotated the service account credentials.
10. I searched for the same indicators across the remaining environment.

### 11. I validated containment

After isolation and credential rotation I monitored for further SMB activity from FINWS042 and further authentication using `CORP\svc_backup`.

No new lateral movement event was observed in the reviewed period.

No second host created `WinTelemetry`.

No further connection from `telemetrysvc.exe` was recorded after containment.

## Evidence that confirmed compromise

The network scan by itself did not confirm compromise.

The following evidence did:

1. Successful SMB session from a finance workstation to FILESRV02.
2. Windows Event ID 4624 showing successful Logon Type 3 with `CORP\svc_backup`.
3. Event ID 4672 showing privileged rights on the same logon.
4. Sysmon Event ID 11 showing creation of `telemetrysvc.exe`.
5. Event ID 7045 showing creation of the `WinTelemetry` service.
6. Defender and Sysmon showing `services.exe` launching the executable as SYSTEM.
7. Child discovery processes appearing immediately after service execution.
8. Repeated outbound TLS connections from the new service process.
9. No approved change or deployment record matching the service or executable.

The combination of those events confirmed unauthorised remote execution and lateral movement to FILESRV02.

## MITRE ATT&CK mapping

### T1046 | Network Service Discovery

The finance workstation attempted SMB connections across multiple systems in the server subnet.

### T1078 | Valid Accounts

The activity used the legitimate privileged account `CORP\svc_backup`.

### T1021.002 | SMB Windows Admin Shares

The source established SMB connectivity to FILESRV02 immediately before the successful network logon and service activity.

### T1569.002 | Service Execution

A new Windows service was registered and executed under LocalSystem.

### T1033 | System Owner User Discovery

`whoami.exe` executed from the new service process tree.

### T1082 | System Information Discovery

`hostname.exe` executed from the same process tree.

## My decision

**Verdict:** Confirmed compromise with SMB based lateral movement and remote service execution.

**Severity:** High

I kept the case at high severity because a privileged service account was used from an abnormal workstation, the target server received an unauthorised executable and service, and the service executed as SYSTEM.

The outbound TLS pattern increased the risk further.

I did not record confirmed data theft because there was no evidence showing file collection or data leaving the environment.

## Evidence

[Sentinel alert details](./evidence/sentinel_alert.json)

[Windows Security events](./evidence/windows_security.csv)

[Sysmon events](./evidence/sysmon_events.csv)

[Defender events](./evidence/defender_events.csv)

[Wireshark packet summary](./evidence/wireshark_packet_summary.csv)

[Wireshark filters](./wireshark_filters.txt)

[Sentinel and Defender KQL](./queries.kql)

[Correlation script](./analysis.py)

[Analysis output](./evidence/analysis.txt)

[SOC incident report](./incident_report.md)

**Environment:** Controlled SOC environment using representative enterprise telemetry.
