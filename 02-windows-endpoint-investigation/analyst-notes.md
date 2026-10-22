# Analyst Notes

## Starting point

The Wireshark case showed six outbound TCP/443 sessions from JPtest1 to 203.0.113.77 at roughly one-minute intervals.

The main gap was process attribution.

## Pivots used

1. Destination IP: 203.0.113.77
2. Host: JPtest1 / 192.168.1.143
3. First network timestamp: 22:16:04 local
4. First source port: 50342
5. DNS name: cdn-storage-sync.test

## Correlation logic

I first searched Sysmon Event ID 3 for the destination IP.

That returned powershell.exe, PID 6124.

I then pivoted on PID 6124 and the ProcessGuid to review:

- Event ID 1 for process creation
- Event ID 22 for DNS activity
- Event ID 11 for file creation
- Event ID 13 for registry modification
- additional Event ID 3 records

The ProcessGuid was more reliable than PID alone because Windows can reuse process IDs over time.

## Important distinction

The PowerShell process was suspicious because of the surrounding activity, not because PowerShell itself is malicious.

The strongest combination was:

~~~text
PowerShell script execution
+ Public directory
+ DNS query
+ repeated TCP/443 connections
+ Run key modification
~~~

## Time-zone handling

Wireshark displayed local time:

~~~text
22:16:04.118
~~~

Sysmon showed:

~~~text
16:46:04.118 UTC
~~~

The 5 hour 30 minute difference was expected for the local time zone and prevented the events from being incorrectly treated as unrelated.

## Final triage position

If this were an unknown production host, I would escalate it because the endpoint evidence links one process to network communication and persistence-related activity.

I would not call it confirmed malware until the script, file contents, reputation data and endpoint context were reviewed.
