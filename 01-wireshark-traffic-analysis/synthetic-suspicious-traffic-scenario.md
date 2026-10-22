# Simulated Suspicious Traffic Investigation

> **Lab classification:** Simulated / controlled exercise  
> **Endpoint under investigation:** `JPtest1`  
> **Purpose:** Practise identifying reconnaissance and beacon-like outbound traffic in Wireshark.  
> **Important:** The values in this case are synthetic and use documentation-only IP ranges. They are not presented as evidence of a real compromise.

## Executive Summary

A packet capture from Windows 11 workstation `JPtest1` was reviewed after unusual network activity was observed during a controlled security exercise.

Two behaviours stood out:

1. A host on the local lab network rapidly probed multiple TCP ports on `JPtest1`, consistent with network service scanning.
2. Shortly afterwards, `JPtest1` generated repeated DNS lookups for the same hostname followed by TLS connections to the same external address at almost exactly 60-second intervals.

The repeated timing was not consistent with ordinary interactive browsing and was treated as potential beacon-like behaviour. Because the application payload was encrypted, the packet capture alone could not prove command-and-control activity. The appropriate next step would be endpoint correlation using process, DNS and network telemetry from Sysmon or an EDR platform.

## Incident Details

| Field | Value |
|---|---|
| Host | `JPtest1` |
| Host IP | `192.168.50.23` |
| Operating System | Windows 11 |
| Capture Tool | Wireshark |
| Lab scanner | `192.168.50.99` |
| Synthetic external destination | `198.51.100.44` |
| Synthetic hostname | `sync-check.example.com` |
| Capture window | 14:21:50 - 14:29:10 |
| Initial severity | Medium |
| Final assessment | Suspicious simulated activity requiring endpoint correlation |

> `198.51.100.0/24` is reserved for documentation and examples. It is used here intentionally so the simulated destination cannot be mistaken for identified real-world malicious infrastructure.

---

## Investigation Timeline

| Time | Source | Destination | Activity | Analyst Interpretation |
|---|---|---|---|---|
| 14:22:08.104 | 192.168.50.99 | 192.168.50.23 | TCP SYN to 135 | Start of rapid port probing |
| 14:22:08.221 | 192.168.50.99 | 192.168.50.23 | TCP SYN to 139 | Reconnaissance continues |
| 14:22:08.394 | 192.168.50.99 | 192.168.50.23 | TCP SYN to 445 | SMB service discovery attempt |
| 14:22:08.612 | 192.168.50.99 | 192.168.50.23 | TCP SYN to 3389 | RDP service discovery attempt |
| 14:22:08.827 | 192.168.50.99 | 192.168.50.23 | TCP SYN to 5985 | WinRM service discovery attempt |
| 14:23:15.442 | 192.168.50.23 | 192.168.50.1 | DNS query for `sync-check.example.com` | First observed lookup |
| 14:23:15.468 | 192.168.50.1 | 192.168.50.23 | DNS response: `198.51.100.44` | Name resolution completed |
| 14:23:16.031 | 192.168.50.23 | 198.51.100.44:443 | TCP/TLS session established | First outbound session |
| 14:24:16.087 | 192.168.50.23 | 198.51.100.44:443 | New TLS session | ~60-second interval |
| 14:25:16.114 | 192.168.50.23 | 198.51.100.44:443 | New TLS session | Pattern repeats |
| 14:26:16.169 | 192.168.50.23 | 198.51.100.44:443 | New TLS session | Pattern repeats |
| 14:27:16.202 | 192.168.50.23 | 198.51.100.44:443 | New TLS session | Pattern repeats |
| 14:28:16.253 | 192.168.50.23 | 198.51.100.44:443 | New TLS session | Pattern persists |

---

## Finding 1 - Rapid Multi-Port Reconnaissance

The display filter:

```text
ip.src == 192.168.50.99 && ip.dst == 192.168.50.23 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

isolated a short burst of SYN packets from `192.168.50.99` toward `JPtest1`.

Observed target ports included:

| Port | Common Service | Observation |
|---|---|---|
| 135 | MSRPC | SYN probe |
| 139 | NetBIOS Session Service | SYN probe |
| 445 | SMB | SYN probe |
| 3389 | RDP | SYN probe |
| 5985 | WinRM HTTP | SYN probe |

The probes occurred within less than one second and targeted several common Windows administration and remote-access services.

### Assessment

This pattern is consistent with **network service scanning** rather than normal user traffic.

In the controlled lab, the source was a known simulation host. In a real environment, the source host would require investigation to determine whether the activity was authorised vulnerability scanning, administrator activity, or hostile reconnaissance.

### MITRE ATT&CK

- **T1046 - Network Service Scanning**

### Evidence Placeholder

`screenshots/09-simulated-port-scan.png`

Expected screenshot:
- Wireshark display filter visible
- source `192.168.50.99`
- destination `192.168.50.23`
- multiple SYN packets to different destination ports
- timestamps showing rapid sequence

---

## Finding 2 - Repeated DNS Resolution

DNS traffic for the endpoint was isolated using:

```text
ip.addr == 192.168.50.23 && dns
```

The host queried:

```text
sync-check.example.com
```

The synthetic DNS response returned:

```text
198.51.100.44
```

The first lookup occurred immediately before the first suspicious outbound TLS session.

A more targeted filter:

```text
dns.qry.name == "sync-check.example.com"
```

would isolate the relevant requests.

### Assessment

A single DNS query is not suspicious by itself. Its significance comes from correlation with the repeated outbound connections that followed.

### Evidence Placeholder

`screenshots/10-simulated-dns-query.png`

Expected screenshot:
- query name `sync-check.example.com`
- response mapping to `198.51.100.44`
- query/response transaction visible

---

## Finding 3 - Periodic Outbound TLS Connections

Traffic between `JPtest1` and the synthetic destination was isolated with:

```text
ip.addr == 192.168.50.23 && ip.addr == 198.51.100.44 && tcp.port == 443
```

Five additional TLS sessions appeared after the first connection.

Observed session start times:

```text
14:23:16.031
14:24:16.087
14:25:16.114
14:26:16.169
14:27:16.202
14:28:16.253
```

Approximate intervals:

```text
60.056 seconds
60.027 seconds
60.055 seconds
60.033 seconds
60.051 seconds
```

Average interval:

```text
~60.04 seconds
```

The low variation between connection intervals suggests machine-driven periodic behaviour rather than manually initiated browsing.

### Why This Matters

Malware and remote-management software can use periodic network callbacks. However, legitimate software such as update agents, monitoring software and cloud applications can produce similar patterns.

For that reason, **periodicity is an investigative lead, not proof of command-and-control**.

### Evidence Placeholder

`screenshots/11-simulated-periodic-tls.png`

Expected screenshot:
- repeated connections between `192.168.50.23` and `198.51.100.44`
- timestamps visible
- TCP/443 or TLS protocol visible

---

## Finding 4 - TLS Limits Packet-Level Visibility

The outbound sessions used TCP port 443 and were decoded as TLS.

Useful filters:

```text
tls
```

and:

```text
ip.dst == 198.51.100.44 && tls
```

The packet capture provided network metadata including:

- source and destination IP addresses
- source and destination ports
- timestamps
- session frequency
- packet sizes
- TLS handshake metadata where available

The application payload itself was encrypted.

### Assessment

Wireshark alone could not determine what commands or data were exchanged inside the encrypted session. Further endpoint evidence would be required.

This is an important investigative boundary: **encrypted traffic can be suspicious based on context and behaviour without the analyst being able to claim what the encrypted payload contains.**

---

## Traffic Pattern Summary

```text
LAB-SCANNER
192.168.50.99
      |
      | Rapid SYN probes
      | 135, 139, 445, 3389, 5985
      v
JPtest1
192.168.50.23
      |
      | DNS query
      v
sync-check.example.com
      |
      | resolves to
      v
198.51.100.44
      |
      | TLS/443 approximately every 60 seconds
      v
Repeated outbound sessions
```

---

## Wireshark Filters Used

| Investigation | Display Filter |
|---|---|
| Traffic involving JPtest1 | `ip.addr == 192.168.50.23` |
| SYN probes toward JPtest1 | `ip.src == 192.168.50.99 && ip.dst == 192.168.50.23 && tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| DNS involving JPtest1 | `ip.addr == 192.168.50.23 && dns` |
| Synthetic suspicious hostname | `dns.qry.name == "sync-check.example.com"` |
| Synthetic destination | `ip.addr == 198.51.100.44` |
| Outbound TLS destination | `ip.src == 192.168.50.23 && ip.dst == 198.51.100.44 && tcp.port == 443` |
| TLS only | `tls` |

---

## Analyst Assessment

### Confirmed from the simulated packet evidence

- `JPtest1` was the target of rapid multi-port SYN probing.
- The source of the probes was `192.168.50.99`.
- `JPtest1` resolved `sync-check.example.com` to `198.51.100.44`.
- `JPtest1` established repeated outbound TLS sessions to `198.51.100.44:443`.
- Those sessions occurred at approximately 60-second intervals.

### Reasonable inference

- The SYN pattern is consistent with network reconnaissance.
- The outbound periodicity is consistent with automated beacon-like behaviour.

### Not proven by the packet capture

- That malware was present on `JPtest1`.
- That `198.51.100.44` was a real command-and-control server.
- Which process initiated the network connections.
- What data was exchanged inside the encrypted TLS payload.
- Whether any credentials or files were compromised.

This evidence/inference separation is intentional and reflects how a real investigation should be documented.

---

## Recommended Next Steps

If the same pattern appeared in a production environment, I would:

1. Correlate `198.51.100.44` and the DNS query with endpoint telemetry.
2. Identify the process responsible for the connections using Sysmon Event ID 3 or EDR network telemetry.
3. Review process creation telemetry around 14:23 for unusual parent-child process relationships.
4. Check whether the destination or domain appears in threat-intelligence sources.
5. Review whether the source of the SYN scan is an authorised scanner.
6. Inspect DNS history for additional related hostnames.
7. Search other endpoints for connections to the same destination.
8. Consider containment if endpoint evidence confirms malicious execution.

---

## MITRE ATT&CK Mapping

| Behaviour | Technique | ID | Confidence |
|---|---|---|---|
| Rapid probing of Windows services | Network Service Scanning | T1046 | High |
| Periodic HTTPS communication | Application Layer Protocol: Web Protocols | T1071.001 | Medium - behavioural hypothesis |
| DNS resolution associated with outbound activity | Application Layer Protocol: DNS | T1071.004 | Low - contextual only |

The ATT&CK mappings describe behaviours demonstrated in the simulated exercise. They do not claim that an actual attacker compromised the endpoint.

---

## Verdict

**Suspicious - simulated security event**

The packet capture demonstrates two investigation-worthy patterns: rapid service discovery against `JPtest1` and highly periodic outbound TLS communication from the endpoint.

In a real SOC workflow, the network evidence would justify escalation for endpoint correlation. It would **not** by itself justify declaring the endpoint compromised.

---

## Evidence Files

The following names are reserved for screenshots from a recreated version of this simulation:

```text
09-simulated-port-scan.png
10-simulated-dns-query.png
11-simulated-periodic-tls.png
12-simulated-conversations.png
```

Until actual lab screenshots are added, these remain evidence placeholders rather than claimed packet captures.

## Lessons Learned

- Fast SYN probes across multiple service ports are easy to isolate using TCP flag filters.
- DNS becomes more valuable when correlated with subsequent connections.
- Regular connection intervals can reveal automated behaviour that is not obvious from individual packets.
- TLS encryption limits payload visibility but does not remove useful network metadata.
- Suspicious behaviour should be described separately from conclusions that the available evidence cannot prove.
- Network evidence is strongest when correlated with endpoint telemetry.
