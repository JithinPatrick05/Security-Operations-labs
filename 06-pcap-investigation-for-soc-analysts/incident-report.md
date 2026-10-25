# SOC Incident Report

## Incident Details

**Case ID:** LAB-2026-10-25-PCAP-01  
**Title:** Suspicious HTTP Download and Repeated Outbound TCP Connection Attempts  
**Severity:** Medium  
**Status:** Escalated for endpoint validation  
**Data Source:** PCAP / network traffic  
**Affected Host:** `10.0.0.25`

## Executive Summary

A packet capture associated with workstation `10.0.0.25` was reviewed after unusual outbound traffic was reported.

The capture shows the host resolving `portal-login.example`, establishing an HTTP connection to `198.51.100.25` and requesting `/download/update.exe`. The server returned an HTTP 200 response with `application/octet-stream` content.

The host then generated repeated TCP SYN attempts to `203.0.113.77:4444`. A later DNS query for `telemetry-sync.example` resolved to the same destination, followed by another TCP/4444 attempt.

The activity is suspicious and warrants endpoint investigation. The packet evidence alone does not prove malware execution or successful command-and-control.

## Evidence

### DNS

```text
portal-login.example -> 198.51.100.25
telemetry-sync.example -> 203.0.113.77
```

### HTTP

```text
GET /download/update.exe HTTP/1.1
Host: portal-login.example
User-Agent: TrainingClient/1.0

HTTP/1.1 200 OK
Content-Type: application/octet-stream
```

### TCP

Multiple outbound initial SYN packets were observed from the workstation to:

```text
203.0.113.77:4444
```

A successful handshake to that destination is not present in the capture.

## Analyst Assessment

**Classification:** Suspicious network activity  
**Confidence:** High confidence in network observations; low confidence in host-compromise determination without endpoint telemetry

### Why the case is suspicious

- executable-style HTTP path
- binary-style HTTP response
- repeated outbound attempts to an uncommon TCP port
- DNS resolution correlating with the repeated destination
- sequence of events consistent with activity that should be investigated further

### Why compromise is not confirmed

The network capture does not identify the process responsible for the traffic and does not prove execution, persistence, credential access or a successful C2 session.

## Recommended Actions

1. Query EDR for the process tree associated with network connections from `10.0.0.25`.
2. Determine whether `update.exe` or another downloaded object exists on disk.
3. Calculate file hashes and perform authorised static/dynamic analysis as appropriate.
4. Review Sysmon / Windows process-creation telemetry.
5. Search firewall, DNS and proxy logs for the same destinations across the environment.
6. Search SIEM data for other endpoints resolving the same domains or contacting the same IP/port combination.
7. Validate whether any legitimate application explains the traffic.
8. If malicious execution is confirmed, isolate the endpoint and follow the organisation's incident-response process.

## Evidence Limitations

This lab intentionally uses a small synthetic packet capture.

Not available:

- EDR telemetry
- process command lines
- file-system artifacts
- user activity
- identity logs
- broader firewall history
- real threat-intelligence context

The final verdict therefore remains **suspicious activity requiring endpoint validation**, rather than confirmed compromise.
