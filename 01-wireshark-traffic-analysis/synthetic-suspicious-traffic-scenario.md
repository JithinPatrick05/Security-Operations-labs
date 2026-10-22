# Simulated Suspicious Traffic Investigation

> **Important:** This is a synthetic lab scenario used to practise packet-analysis methodology. The IP addresses and domain names below are reserved/example values and do not represent a real compromise.

## Scenario Summary

During review of a controlled packet capture, two patterns were identified for investigation:

1. A short burst of TCP SYN packets from an internal host probing multiple destination ports on another internal system.
2. Repeated outbound TLS connections from the target host to the same external destination at near-regular intervals.

The purpose of the exercise was to determine whether the observed traffic was consistent with normal user activity or warranted further investigation.

## Lab Network

| System | Address | Role |
|---|---:|---|
| Analyst workstation / target | 192.168.56.10 | Windows 11 endpoint |
| Simulated scanning host | 192.168.56.50 | Controlled lab host |
| Local DNS resolver | 192.168.56.1 | Lab DNS service |
| Synthetic external destination | 198.51.100.42 | Reserved TEST-NET-2 address |
| Synthetic hostname | telemetry-lab.example.com | Example domain used for the exercise |

## Investigation Timeline

| Time | Observation |
|---|---|
| 10:14:03.120 | First TCP SYN observed from 192.168.56.50 to 192.168.56.10 |
| 10:14:03.120–10:14:05.490 | 24 destination ports probed in approximately 2.4 seconds |
| 10:14:03.410 | SYN/ACK returned from TCP/80 |
| 10:14:03.662 | SYN/ACK returned from TCP/443 |
| 10:14:04.118 | SYN/ACK returned from TCP/445 |
| 10:14:04.702 | SYN/ACK returned from TCP/3389 |
| 10:18:00.204 | DNS query for telemetry-lab.example.com |
| 10:18:00.231 | Synthetic DNS response returned 198.51.100.42 |
| 10:18:00.268 | TLS connection initiated to 198.51.100.42:443 |
| 10:18:30.377 | Second outbound TLS connection to the same destination |
| 10:19:00.181 | Third outbound TLS connection |
| 10:19:30.422 | Fourth outbound TLS connection |
| 10:20:00.306 | Fifth outbound TLS connection |
| 10:20:30.192 | Sixth outbound TLS connection |

## Finding 1 — TCP Port-Scan Pattern

The following display filter was used to isolate initial connection attempts:

```text
ip.src == 192.168.56.50 &&
ip.dst == 192.168.56.10 &&
tcp.flags.syn == 1 &&
tcp.flags.ack == 0
```

### Observed Pattern

- 24 distinct TCP destination ports were probed in approximately 2.4 seconds.
- Each probe originated from the same internal source address.
- Most destination ports responded with TCP RST/ACK, indicating that no service was listening.
- TCP ports 80, 443, 445 and 3389 responded with SYN/ACK in the synthetic scenario.
- The scanning host immediately terminated successful handshakes with RST rather than establishing normal application sessions.

Representative sequence:

```text
192.168.56.50 -> 192.168.56.10:80     SYN
192.168.56.10 -> 192.168.56.50        SYN, ACK
192.168.56.50 -> 192.168.56.10        RST

192.168.56.50 -> 192.168.56.10:445    SYN
192.168.56.10 -> 192.168.56.50        SYN, ACK
192.168.56.50 -> 192.168.56.10        RST
```

### Assessment

The speed, breadth and repeated SYN-only probing pattern is inconsistent with ordinary user web browsing and is consistent with a **TCP SYN port scan** in a controlled lab environment.

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Network Service Scanning | T1046 |

### Verdict

**True Positive — Simulated Reconnaissance**

The traffic pattern is consistent with deliberate service discovery against the target host.

---

## Finding 2 — Repeated DNS and TLS Activity

The second pattern involved recurring communication from the Windows endpoint to the same external destination.

DNS filter:

```text
dns.qry.name == "telemetry-lab.example.com"
```

Destination filter:

```text
ip.addr == 198.51.100.42 && tcp.port == 443
```

### Observed Pattern

Six outbound TLS sessions were observed over approximately three minutes.

Approximate intervals:

| Session | Start Time | Interval from Previous |
|---|---|---:|
| 1 | 10:18:00.268 | — |
| 2 | 10:18:30.377 | 30.1 s |
| 3 | 10:19:00.181 | 29.8 s |
| 4 | 10:19:30.422 | 30.2 s |
| 5 | 10:20:00.306 | 29.9 s |
| 6 | 10:20:30.192 | 29.9 s |

Each connection:

- targeted TCP port 443;
- completed a TCP handshake;
- negotiated a TLS session;
- transferred a relatively small amount of data;
- closed before a new connection was created roughly 30 seconds later.

Synthetic session sizes were approximately:

- 700–950 bytes client to server;
- 300–550 bytes server to client.

### Assessment

The regular timing, repeated destination and relatively consistent transfer size are characteristics that can appear in **beacon-like network activity**.

However, the payload is encrypted with TLS. Packet capture alone does **not** prove command-and-control traffic or malware execution.

A responsible analyst would correlate the network evidence with:

- endpoint process telemetry;
- DNS client logs;
- Sysmon Event ID 1 process creation;
- Sysmon Event ID 3 network connections;
- EDR process/network relationships;
- reputation and threat-intelligence data for the real destination.

### Verdict

**Suspicious — Requires Endpoint Correlation**

The traffic warrants investigation because of its periodicity and repeated destination, but it cannot be conclusively classified as malicious from network evidence alone.

---

## Example Packet-Level Evidence Table

The following values are synthetic and are included to demonstrate how packet evidence can be summarised.

| Packet | Time | Source | Destination | Protocol | Information |
|---:|---:|---|---|---|---|
| 4182 | 10:14:03.120 | 192.168.56.50 | 192.168.56.10 | TCP | 52144 -> 22 [SYN] |
| 4185 | 10:14:03.183 | 192.168.56.50 | 192.168.56.10 | TCP | 52145 -> 80 [SYN] |
| 4186 | 10:14:03.410 | 192.168.56.10 | 192.168.56.50 | TCP | 80 -> 52145 [SYN, ACK] |
| 4187 | 10:14:03.423 | 192.168.56.50 | 192.168.56.10 | TCP | 52145 -> 80 [RST] |
| 4194 | 10:14:03.650 | 192.168.56.50 | 192.168.56.10 | TCP | 52147 -> 443 [SYN] |
| 4195 | 10:14:03.662 | 192.168.56.10 | 192.168.56.50 | TCP | 443 -> 52147 [SYN, ACK] |
| 6120 | 10:18:00.204 | 192.168.56.10 | 192.168.56.1 | DNS | Query A telemetry-lab.example.com |
| 6121 | 10:18:00.231 | 192.168.56.1 | 192.168.56.10 | DNS | Response A 198.51.100.42 |
| 6123 | 10:18:00.268 | 192.168.56.10 | 198.51.100.42 | TCP | 53421 -> 443 [SYN] |
| 6124 | 10:18:00.301 | 198.51.100.42 | 192.168.56.10 | TCP | 443 -> 53421 [SYN, ACK] |
| 6127 | 10:18:00.366 | 192.168.56.10 | 198.51.100.42 | TLS | Client Hello |
| 6142 | 10:18:01.044 | 192.168.56.10 | 198.51.100.42 | TLS | Application Data |
| 6458 | 10:18:30.377 | 192.168.56.10 | 198.51.100.42 | TCP | New session -> 443 [SYN] |

---

## Wireshark Filters Used

### SYN scan

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Scan source

```text
ip.src == 192.168.56.50
```

### Target host

```text
ip.dst == 192.168.56.10
```

### External destination

```text
ip.addr == 198.51.100.42
```

### TLS sessions to the destination

```text
ip.addr == 198.51.100.42 && tls
```

### DNS query

```text
dns.qry.name == "telemetry-lab.example.com"
```

---

## Overall Analyst Assessment

**Severity: Medium**

The simulated traffic contains two distinct behaviours worth investigating:

1. **Reconnaissance:** rapid SYN probes across multiple ports against an internal Windows endpoint.
2. **Potential beaconing:** periodic outbound TLS sessions to a single destination at approximately 30-second intervals.

The port-scan activity can be classified confidently because the packet behaviour itself is characteristic of active network service discovery.

The recurring TLS traffic is more ambiguous. Its timing and consistency are suspicious, but encrypted network traffic alone cannot establish malicious intent.

### Recommended Analyst Actions

1. Identify the owner and purpose of 192.168.56.50.
2. Confirm whether scanning activity was authorised.
3. Correlate 192.168.56.10 outbound connections with endpoint telemetry.
4. Identify the process responsible for the recurring TLS sessions.
5. Review DNS and EDR telemetry for the associated hostname/destination.
6. Assess whether the destination is expected for the host's business function.
7. Escalate if endpoint evidence confirms an unknown or suspicious process.

## Lessons Learned

This scenario demonstrates why packet analysis should distinguish between **evidence** and **inference**.

A rapid SYN pattern across many destination ports provides strong packet-level evidence of scanning. Periodic encrypted outbound traffic may resemble command-and-control beaconing, but the network capture alone is not enough to prove that conclusion.

The strongest investigation combines network telemetry with endpoint and threat-intelligence evidence.
