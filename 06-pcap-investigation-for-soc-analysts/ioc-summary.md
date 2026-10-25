# IOC and Evidence Summary

> These are **training indicators only**. The domains use the reserved `.example` namespace and the external IPs are documentation ranges. They are not live threat intelligence.

## Network Indicators

| Indicator | Type | Observation | Assessment |
|---|---|---|---|
| `10.0.0.25` | Internal IPv4 | Investigated workstation | Source host |
| `portal-login.example` | Domain | Queried before HTTP session | Suspicious in training scenario |
| `198.51.100.25` | IPv4 | HTTP destination | Documentation-only address |
| `/download/update.exe` | URI path | Requested over HTTP | Requires file/endpoint validation |
| `telemetry-sync.example` | Domain | Resolved to TCP/4444 destination | Correlated training indicator |
| `203.0.113.77` | IPv4 | Repeated outbound SYN destination | Documentation-only address |
| `4444/tcp` | Port | Multiple outbound connection attempts | Unusual; investigate process/context |

## HTTP Evidence

```text
Host: portal-login.example
Method: GET
URI: /download/update.exe
User-Agent: TrainingClient/1.0
Response: 200 OK
Content-Type: application/octet-stream
```

## PCAP Hashes

```text
MD5:
b759b4fd09889ec4834bbd584748b14e

SHA-1:
af7c9841e5a842a06ae9441e792c4c9ec402b166

SHA-256:
a5c13dc4eac65ee0710f49610ce2e21fd220aef4c30348b0a8306623dcc1ca63
```

## Confidence Notes

### High confidence

- the DNS queries occurred
- the HTTP request and response occurred
- binary-style content was transferred
- repeated TCP/4444 SYN attempts occurred

### Moderate confidence

- the download and later connection attempts may be related based on timing and scenario design
- `telemetry-sync.example` is relevant because it resolves to the same address targeted on TCP/4444

### Not established

- malicious execution
- malware family
- successful C2
- persistence
- credential theft
- data exfiltration

## SOC Use

In a production investigation, validated malicious indicators could be used to:

- search DNS, proxy, firewall and SIEM data
- identify additional affected endpoints
- enrich an incident ticket
- support containment decisions
- create or tune detections

Indicators should be validated before blocking to reduce false positives.
