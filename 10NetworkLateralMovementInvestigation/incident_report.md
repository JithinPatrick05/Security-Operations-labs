# SOC Incident Report | Case 010

## Summary

I investigated anomalous SMB activity from `FINWS042`, a finance workstation that attempted connections to 34 systems in the server subnet within 58 seconds.

The source established a successful SMB session to `FILESRV02`.

Windows Security logs then showed a successful Logon Type 3 using the privileged service account `CORP\svc_backup` from FINWS042.

Within seconds, `C:\ProgramData\WinTelemetry\telemetrysvc.exe` appeared on FILESRV02 and Windows Event ID 7045 recorded the creation of a new service called `WinTelemetry`.

Defender and Sysmon confirmed that the service executable started under SYSTEM and spawned discovery processes.

The same executable then initiated repeated outbound TLS sessions.

## Classification

**Incident type:** Network intrusion and lateral movement  
**Severity:** High  
**Confidence:** High  
**Source host:** FINWS042  
**Target host:** FILESRV02  
**Account involved:** CORP\svc_backup  
**Service created:** WinTelemetry  
**File:** C:\ProgramData\WinTelemetry\telemetrysvc.exe  
**SHA256:** 9ff8f6e4c5d9e3769abc51fc3138eda5fda3ff32aee6c66a010c218c9660614e

## Confirmed findings

1. FINWS042 attempted SMB connections to 34 internal hosts in 58 seconds.
2. FILESRV02 completed an SMB session with FINWS042.
3. FILESRV02 recorded a successful Logon Type 3 from FINWS042 using CORP\svc_backup.
4. The same session received special privileges.
5. telemetrysvc.exe was created under ProgramData.
6. Windows registered WinTelemetry as a new automatic service.
7. services.exe launched telemetrysvc.exe as SYSTEM.
8. The service process spawned account and host discovery processes.
9. The service process made repeated outbound TLS connections.
10. No approved software deployment matched the service, path or file.

## Assessment

The evidence confirms successful lateral movement from FINWS042 to FILESRV02 using a valid privileged account.

The service creation and SYSTEM execution confirm unauthorised code execution on the target server.

The outbound traffic is consistent with beacon like behaviour, but the encrypted payload means I did not classify the destination as confirmed command and control.

The evidence did not establish the original access method to FINWS042.

## MITRE ATT&CK

**T1046 Network Service Discovery**

**T1078 Valid Accounts**

**T1021.002 SMB Windows Admin Shares**

**T1569.002 Service Execution**

**T1033 System Owner User Discovery**

**T1082 System Information Discovery**

## Containment completed

1. Isolated FINWS042.
2. Isolated FILESRV02.
3. Disabled CORP\svc_backup.
4. Blocked the telemetrysvc.exe SHA256.
5. Blocked the external destination.
6. Preserved packet, endpoint and authentication evidence.
7. Removed WinTelemetry after evidence collection.
8. Removed telemetrysvc.exe after preservation.
9. Rotated the service account credentials.
10. Completed an environment wide hunt for matching indicators.

## Closure

No additional server contained WinTelemetry or telemetrysvc.exe in the reviewed evidence.

No further SMB lateral movement was observed from FINWS042 after isolation.

No further telemetrysvc.exe network events were observed after containment.

The initial access method to FINWS042 remained unresolved and was documented for further investigation.

**Environment:** Controlled SOC environment using representative enterprise telemetry.
