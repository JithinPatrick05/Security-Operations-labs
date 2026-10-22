# Event Notes

> These records define the controlled JPtest1 lab scenario and the Sysmon fields being correlated. They are not exported EVTX records. Once the lab is rerun, the values can be replaced with the matching event details from the live capture.

## Event ID 1 - Process Create

~~~text
UtcTime: 2026-10-22 16:46:02.811
ProcessGuid: {E849D6A3-B8A2-68FB-3101-000000001000}
ProcessId: 6124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\Libraries\sync-check.ps1
CurrentDirectory: C:\Users\jpatrick\
User: JPtest1\jpatrick
IntegrityLevel: Medium
ParentProcessGuid: {E849D6A3-AC0C-68FB-1A01-000000001000}
ParentProcessId: 4288
ParentImage: C:\Windows\explorer.exe
ParentCommandLine: C:\Windows\Explorer.EXE
~~~

## Event ID 11 - File Create

~~~text
UtcTime: 2026-10-22 16:46:03.041
ProcessGuid: {E849D6A3-B8A2-68FB-3101-000000001000}
ProcessId: 6124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\Public\Libraries\jp-cache.dat
CreationUtcTime: 2026-10-22 16:46:03.041
User: JPtest1\jpatrick
~~~

## Event ID 22 - DNS Query

~~~text
UtcTime: 2026-10-22 16:46:03.447
ProcessGuid: {E849D6A3-B8A2-68FB-3101-000000001000}
ProcessId: 6124
QueryName: cdn-storage-sync.test
QueryStatus: 0
QueryResults: ::ffff:203.0.113.77;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: JPtest1\jpatrick
~~~

## Event ID 3 - First Network Connection

~~~text
UtcTime: 2026-10-22 16:46:04.118
ProcessGuid: {E849D6A3-B8A2-68FB-3101-000000001000}
ProcessId: 6124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: JPtest1\jpatrick
Protocol: tcp
Initiated: true
SourceIp: 192.168.1.143
SourceHostname: JPtest1
SourcePort: 50342
DestinationIp: 203.0.113.77
DestinationPort: 443
DestinationPortName: https
~~~

## Event ID 13 - Registry Value Set

~~~text
UtcTime: 2026-10-22 16:46:04.944
ProcessGuid: {E849D6A3-B8A2-68FB-3101-000000001000}
ProcessId: 6124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
EventType: SetValue
TargetObject: HKU\<USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run\UpdateCheck
Details: powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\Public\Libraries\sync-check.ps1
User: JPtest1\jpatrick
~~~

## Event ID 3 - Repeated Connections

~~~text
16:47:03.977  PID 6124  192.168.1.143:50363 -> 203.0.113.77:443
16:48:04.502  PID 6124  192.168.1.143:50381 -> 203.0.113.77:443
16:49:04.146  PID 6124  192.168.1.143:50405 -> 203.0.113.77:443
16:50:03.814  PID 6124  192.168.1.143:50426 -> 203.0.113.77:443
16:51:04.321  PID 6124  192.168.1.143:50444 -> 203.0.113.77:443
~~~

## Event ID 22 - DNS Refresh

~~~text
UtcTime: 2026-10-22 16:51:03.472
ProcessGuid: {E849D6A3-B8A2-68FB-3101-000000001000}
ProcessId: 6124
QueryName: cdn-storage-sync.test
QueryStatus: 0
QueryResults: ::ffff:203.0.113.77;
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: JPtest1\jpatrick
~~~
