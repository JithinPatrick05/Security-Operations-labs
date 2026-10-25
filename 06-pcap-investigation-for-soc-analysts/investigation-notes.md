# PCAP Investigation Notes

## Case

**Case ID:** LAB-2026-10-25-PCAP-01  
**Analyst:** Jithin Patrick  
**Evidence:** `evidence/soc-pcap-training.pcap`  
**Scope:** Network evidence only

## 1. Evidence Integrity

```text
File: soc-pcap-training.pcap
Packets: 13
Link type: Ethernet
MD5: b759b4fd09889ec4834bbd584748b14e
SHA-1: af7c9841e5a842a06ae9441e792c4c9ec402b166
SHA-256: a5c13dc4eac65ee0710f49610ce2e21fd220aef4c30348b0a8306623dcc1ca63
```

## 2. Host Identification

Primary internal host:

```text
10.0.0.25
```

Relevant external/documentation addresses:

```text
8.8.8.8          DNS resolver used in the training capture
198.51.100.25    HTTP destination
203.0.113.77     Repeated TCP/4444 destination
```

The `198.51.100.0/24` and `203.0.113.0/24` networks are documentation ranges used here intentionally.

## 3. DNS Review

Filter:

```text
dns
```

Observed query 1:

```text
portal-login.example
A -> 198.51.100.25
```

Observed query 2:

```text
telemetry-sync.example
A -> 203.0.113.77
```

Analyst note:

The names are suspicious by scenario design, but domain naming alone is weak evidence. The important step is correlating DNS with subsequent network connections.

## 4. HTTP Review

Filter:

```text
http.request || http.response
```

Observed request:

```text
GET /download/update.exe HTTP/1.1
Host: portal-login.example
User-Agent: TrainingClient/1.0
```

Observed response:

```text
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 15
```

The body contains the harmless training string:

```text
TRAINING-BINARY
```

Analyst note:

The file name and MIME type justify investigation, but a PCAP filename or payload label does not prove malicious execution.

## 5. TCP Connection Review

Filter:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

The internal host sends repeated SYN packets to:

```text
203.0.113.77:4444
```

There is no SYN-ACK from that destination in the capture.

Interpretation:

- repeated outbound connection attempts are visible
- the destination port is unusual for normal user web traffic
- the capture does not show a successful TCP session to that destination
- this behaviour should be correlated with endpoint and firewall telemetry

## 6. Correlation

The strongest correlation in the capture is:

```text
telemetry-sync.example
        ↓ DNS A record
203.0.113.77
        ↓ subsequent traffic
TCP destination port 4444
```

This makes the DNS event more relevant than reviewing the domain name in isolation.

## 7. Analyst Assessment

### Confirmed by packet evidence

- `10.0.0.25` generated DNS requests.
- `portal-login.example` resolved to `198.51.100.25`.
- HTTP content was requested from `/download/update.exe`.
- An HTTP 200 response returned binary-style content.
- Multiple outbound TCP SYN attempts targeted `203.0.113.77:4444`.
- `telemetry-sync.example` resolved to `203.0.113.77`.

### Not confirmed by packet evidence

- malware execution
- process responsible for the connections
- persistence
- credential theft
- successful command-and-control
- data exfiltration
- user interaction

## 8. Escalation Decision

**Escalate for endpoint validation.**

Recommended data sources:

- EDR process tree
- Windows Security / Sysmon logs
- browser download history
- DNS resolver logs
- firewall/proxy logs
- file-system evidence
- identity sign-in telemetry

The investigation should move from network evidence to endpoint and SIEM correlation before a final compromise determination is made.
