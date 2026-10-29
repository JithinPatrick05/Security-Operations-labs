# SOC Incident Note 008

**Review date:** 29 October 2026  
**Detection:** New scheduled task with subsequent PowerShell and network activity  
**Machine:** LABWS02  
**Data source:** Controlled synthetic Windows Security and Sysmon records  
**Priority:** High pending owner verification  
**Response state:** Recommendations only, no production actions performed

## Observed chain

At 13:20:00 UTC a helper process launched from `C:\Users\Public\Tools`. The evidence then recorded a script file creation, a `schtasks.exe` child process and a Security `4698` registration for `\CacheMonitor`.

The task action referenced `C:\Users\Public\Libraries\cache.ps1`. A Sysmon file creation event also recorded the task file under the Windows Tasks directory.

PowerShell launched at 13:50:03, 14:20:03 and 14:50:03 UTC. Each execution was followed by a DNS query for `syncdesk.example` and a network event to `203.0.113.92` on TCP port 443.

Each group of three events shared the same process GUID, so the correlation did not depend on timestamps alone.

## Scope of evidence

The export contains 15 records, including one unrelated task event used as a comparison. I identified one CacheMonitor registration, three PowerShell starts, three matching DNS events and three matching network connections.

The hostname and IP address use training values. The data does not include script execution output, the script contents, binary hashes, data volumes, network payloads, alerts from a real EDR product or an approval record.

## Analyst assessment

The task configuration and 30 minute repetition demonstrate a persistence style execution pattern in the scenario. The destination contact is supported by Sysmon network telemetry. No credential theft, malware verdict or data exfiltration can be concluded from these records.

**Recommended escalation:** Endpoint security should confirm the task owner and collect the task definition, source script and helper executable. Search for related task names and paths across the fleet. Decide on containment only after checking business authorisation and the applicable response procedure.

## Shift handover

Possible unauthorised persistence on LABWS02. A helper process created a PowerShell scheduled task, and three later runs connected to the same training destination. The process GUIDs support the chain. Severity remains high pending task ownership and file analysis. No live remediation has been performed.
