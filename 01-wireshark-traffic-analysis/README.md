# Wireshark Traffic Analysis

## Overview

This project demonstrates practical network traffic capture and packet analysis using Wireshark on a Windows 11 endpoint. The objective was to generate normal user traffic, isolate relevant protocols, reconstruct client-server communication and document how common network protocols appear in a packet capture.

The exercise focuses on foundational skills used in security operations, incident response and network troubleshooting.

## Project Status

**Completed lab exercise.**  
The written analysis has been migrated into this portfolio. Evidence screenshots are being re-added from the original lab capture.

## Objectives

- Capture live traffic from the active Windows network interface.
- Identify common network protocols in a packet capture.
- Inspect TCP connection establishment.
- Investigate DNS queries and responses.
- Review unencrypted HTTP request/response traffic.
- Examine TLS-encrypted web sessions.
- Generate and inspect ICMP echo traffic.
- Use Wireshark statistics to identify endpoints, conversations and protocol distribution.
- Document findings using a repeatable analyst workflow.

## Environment

| Component | Details |
|---|---|
| Host Operating System | Windows 11 |
| Packet Analysis Tool | Wireshark |
| Traffic Generation | Web browser and Windows Command Prompt |
| Capture Source | Active network adapter |
| Traffic Type | Normal user-generated lab traffic |
| Analysis Type | Protocol identification, packet inspection and session analysis |

## Traffic Generation

Normal user activity was generated during the capture, including:

- DNS lookups
- Web browsing
- HTTPS sessions
- ICMP echo requests
- Local network communication

Example commands used during the exercise:

```cmd
nslookup example.com
ping example.com
```

A browser was used to generate additional HTTP/HTTPS traffic.

## Investigation Methodology

The capture was reviewed in five stages:

1. **Establish scope** — identify the active capture interface and time window.
2. **Identify protocols** — use the Protocol column and Protocol Hierarchy statistics.
3. **Inspect individual sessions** — filter DNS, TCP, HTTP, TLS and ICMP traffic.
4. **Correlate communication** — associate name resolution, connection establishment and application traffic.
5. **Summarise findings** — document normal network behaviour and analyst observations.

---

## 1. Packet Capture

Wireshark was started on the active Windows network adapter while normal user activity was generated.

A capture filter can be used when analysis needs to be limited to a specific host:

```text
host <IP_ADDRESS>
```

For this exercise, most filtering was performed after capture using Wireshark display filters.

### Evidence

`screenshots/01-capture-overview.png`

Expected evidence:
- Wireshark capture window
- active adapter traffic
- packet number, time, source, destination, protocol and info columns

---

## 2. Protocol Identification

The packet list was reviewed to identify common protocols present in the capture.

Protocols relevant to the exercise included:

- TCP
- UDP
- DNS
- HTTP
- TLS
- ICMP

Additional local-network protocols such as ARP may also appear depending on host activity during the capture.

The following Wireshark views were useful:

```text
Statistics -> Protocol Hierarchy
Statistics -> Conversations
Statistics -> Endpoints
Statistics -> I/O Graphs
```

These views provide a high-level summary before deeper packet inspection.

### Evidence

`screenshots/02-protocol-hierarchy.png`

---

## 3. TCP Three-Way Handshake

A successful TCP session was identified and the connection-establishment sequence inspected.

Typical sequence:

```text
Client -> Server    SYN
Server -> Client    SYN, ACK
Client -> Server    ACK
```

This sequence confirms that both hosts completed TCP connection establishment before application data was exchanged.

Useful display filters:

```text
tcp
```

```text
tcp.flags.syn == 1
```

For initial connection attempts only:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Finding

The capture contained successful TCP connection establishment consistent with normal client-server web communication.

### Evidence

`screenshots/03-tcp-handshake.png`

---

## 4. DNS Analysis

DNS traffic was filtered using:

```text
dns
```

A controlled lookup was generated with:

```cmd
nslookup example.com
```

The query and corresponding response were inspected for:

- requested hostname
- query type
- transaction relationship
- returned address records
- response timing

### Analyst Observation

DNS analysis is often an early step in network investigations because it can connect user or process activity to external hostnames before the subsequent network session is analysed.

### Finding

The capture showed normal hostname-resolution behaviour: a DNS query was issued for the requested domain and a corresponding response returned address information used for subsequent communication.

### Evidence

`screenshots/04-dns-query-response.png`

---

## 5. HTTP Analysis

Unencrypted HTTP traffic was isolated using:

```text
http
```

Where present, the analysis focused on:

- request method
- requested URI
- Host header
- response status code
- response headers

Representative structure:

```http
GET / HTTP/1.1
Host: example.com
```

### Security Relevance

Unlike HTTPS, HTTP does not encrypt application-layer request and response content. Where HTTP is present, packet capture can expose considerably more information about the request.

### Finding

The exercise demonstrated the difference between directly readable HTTP application data and encrypted HTTPS/TLS application traffic.

### Evidence

`screenshots/05-http-request.png`

---

## 6. HTTPS / TLS Analysis

Encrypted web traffic was filtered using:

```text
tls
```

The capture was inspected for TLS session-establishment traffic and encrypted application data.

Depending on the negotiated TLS version, visible handshake information can include:

- Client Hello
- Server Hello
- negotiated protocol parameters
- server name information where available
- encrypted application data

### Analyst Observation

TLS encryption prevents the payload from being read directly in a normal packet capture without appropriate session keys. However, useful metadata such as communicating endpoints, ports, timing, handshake details and traffic volume can still support an investigation.

### Finding

HTTPS sessions were observed using TCP port 443. Application payloads were encrypted, while connection and TLS-session metadata remained available for analysis.

### Evidence

`screenshots/06-tls-session.png`

---

## 7. ICMP Analysis

ICMP traffic was generated using:

```cmd
ping example.com
```

The capture was filtered with:

```text
icmp
```

The analysis focused on:

- Echo Request
- Echo Reply
- source and destination
- sequence relationship
- round-trip behaviour

### Finding

ICMP echo requests and replies demonstrated basic reachability testing and showed how troubleshooting traffic appears in a packet capture.

### Evidence

`screenshots/07-icmp-echo.png`

---

## 8. Packet Statistics

Wireshark statistics were used to move from individual packets to higher-level traffic patterns.

### Protocol Hierarchy

Used to understand the protocol distribution in the capture.

### Conversations

Used to identify pairs of endpoints communicating with each other.

### Endpoints

Used to identify active hosts observed in the capture.

### I/O Graphs

Used to visualise packet activity over time.

### Evidence

`screenshots/08-conversations-endpoints.png`

---

## Useful Wireshark Display Filters

| Purpose | Filter |
|---|---|
| DNS | `dns` |
| HTTP | `http` |
| TLS | `tls` |
| TCP | `tcp` |
| UDP | `udp` |
| ICMP | `icmp` |
| ARP | `arp` |
| Specific host | `ip.addr == <IP_ADDRESS>` |
| Initial TCP SYN | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| TCP retransmissions | `tcp.analysis.retransmission` |

> Modern Wireshark versions commonly decode DHCP using the `dhcp` display filter. Older material may refer to BOOTP because DHCP is based on the BOOTP message format.

## Key Findings

- Successfully captured and inspected live network traffic from a Windows endpoint.
- Identified multiple network and application protocols within the same capture.
- Correlated DNS hostname resolution with subsequent network communication.
- Verified TCP connection establishment through SYN, SYN-ACK and ACK packets.
- Inspected readable HTTP request information where unencrypted traffic was present.
- Observed TLS session establishment and encrypted HTTPS application traffic.
- Analysed ICMP echo request/reply behaviour.
- Used Wireshark statistics to summarise endpoints, conversations and protocol distribution.
- Demonstrated how packet-level evidence can support security investigation and network troubleshooting.

## Security Operations Relevance

Packet analysis can support investigations involving:

- suspicious outbound connections
- command-and-control traffic
- DNS anomalies
- scanning and reconnaissance
- unexpected services or ports
- network performance issues
- incident timeline reconstruction

The main lesson from this exercise was that individual packets provide limited context by themselves. Stronger analysis comes from correlating DNS, TCP and application-layer behaviour across a complete communication sequence.

## Skills Demonstrated

- Network traffic analysis
- Packet inspection
- TCP/IP networking
- DNS analysis
- HTTP analysis
- TLS/HTTPS analysis
- Protocol filtering
- Network troubleshooting
- Security investigation fundamentals
- Technical documentation

## Lessons Learned

This project strengthened my understanding of how normal network activity appears at packet level. It reinforced the relationship between DNS resolution, TCP connection establishment and application-layer communication.

It also demonstrated an important security-analysis distinction: encryption can prevent direct inspection of application payloads while still leaving useful network metadata available for investigation.

## Future Improvements

Future iterations of this lab will extend the same methodology into more security-focused traffic analysis, including:

- suspicious DNS behaviour
- port-scan identification
- authentication-related traffic
- abnormal outbound connections
- PCAP reconstruction and timeline analysis
- Zeek log correlation
- detection of known malicious network patterns

## Evidence

Screenshots are stored in the `screenshots/` directory.

The evidence set is designed to show the investigation rather than simply prove that Wireshark was installed. Each screenshot should clearly demonstrate a specific observation referenced in this report.
