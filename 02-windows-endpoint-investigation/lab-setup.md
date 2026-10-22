# Lab Setup

## Host

| Item | Value |
|---|---|
| Hostname | JPtest1 |
| Operating system | Windows 11 |
| Host IP | 192.168.1.143 |
| User | JPtest1\jpatrick |
| Logging | Sysmon |
| Log source | Microsoft-Windows-Sysmon/Operational |

## Sysmon events used

The investigation focused on:

| Event ID | Use |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 11 | File creation |
| 13 | Registry value modification |
| 22 | DNS query |

## Investigation starting point

The previous Wireshark lab identified repeated TLS connections from JPtest1 to:

~~~text
203.0.113.77:443
~~~

The first observed source port was:

~~~text
50342
~~~

The related DNS name was:

~~~text
cdn-storage-sync.test
~~~

These values were used as pivots in Event Viewer.

## Event Viewer workflow

The Sysmon Operational log was reviewed at:

~~~text
Applications and Services Logs
  -> Microsoft
  -> Windows
  -> Sysmon
  -> Operational
~~~

The first search pivot was the destination IP:

~~~text
203.0.113.77
~~~

That identified Event ID 3 activity from PowerShell PID 6124.

From there I pivoted on:

- ProcessId 6124
- the ProcessGuid
- cdn-storage-sync.test
- the script path under C:\Users\Public\Libraries
- the Run key modification

## Correlation method

I used the same process identity across multiple event types rather than treating each event separately.

~~~text
Process creation
   |
   +-- File creation
   |
   +-- DNS query
   |
   +-- TCP/443 connection
   |
   +-- Registry Run key
   |
   +-- Repeated TCP/443 connections
~~~

The resulting timeline was then compared with the Wireshark capture.
