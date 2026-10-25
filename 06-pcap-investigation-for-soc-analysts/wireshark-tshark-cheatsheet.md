# Wireshark and tshark PCAP Investigation Cheat Sheet

This cheat sheet is intended for defensive SOC analysis of authorised packet captures.

## Fast Triage in Wireshark

### Focus on one host

```text
ip.addr == 10.0.0.25
```

Outbound only:

```text
ip.src == 10.0.0.25
```

Inbound only:

```text
ip.dst == 10.0.0.25
```

## DNS

All DNS:

```text
dns
```

Queries only:

```text
dns.flags.response == 0
```

Responses only:

```text
dns.flags.response == 1
```

Specific query:

```text
dns.qry.name == "portal-login.example"
```

DNS traffic from the investigated host:

```text
ip.src == 10.0.0.25 && dns
```

## HTTP

HTTP requests:

```text
http.request
```

GET requests:

```text
http.request.method == "GET"
```

Specific host header:

```text
http.host == "portal-login.example"
```

HTTP responses:

```text
http.response
```

Successful HTTP response:

```text
http.response.code == 200
```

## TCP

Initial SYN packets:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

SYN-ACK packets:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

TCP resets:

```text
tcp.flags.reset == 1
```

Specific port:

```text
tcp.port == 4444
```

Packets carrying TCP payload:

```text
tcp.len > 0
```

Retransmissions:

```text
tcp.analysis.retransmission
```

Follow a selected connection:

```text
tcp.stream eq 0
```

## TLS

TLS handshakes:

```text
tls.handshake
```

Server Name Indication where visible:

```text
tls.handshake.extensions_server_name
```

## Useful Wireshark Views

- **Statistics → Protocol Hierarchy**
- **Statistics → Endpoints**
- **Statistics → Conversations**
- **Statistics → I/O Graphs**
- **Analyze → Expert Information**
- **Follow → TCP Stream**
- **File → Export Objects → HTTP** when authorised and applicable

## tshark Commands

Set the PCAP path first:

```bash
PCAP="evidence/soc-pcap-training.pcap"
```

Protocol hierarchy:

```bash
tshark -r "$PCAP" -q -z io,phs
```

IP endpoints:

```bash
tshark -r "$PCAP" -q -z endpoints,ip
```

Conversations:

```bash
tshark -r "$PCAP" -q -z conv,ip
```

DNS queries and answers:

```bash
tshark -r "$PCAP" -Y "dns" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e dns.qry.name -e dns.a
```

HTTP requests:

```bash
tshark -r "$PCAP" -Y "http.request" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e http.request.method -e http.host -e http.request.uri
```

HTTP responses:

```bash
tshark -r "$PCAP" -Y "http.response" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e http.response.code -e http.content_type
```

Initial TCP SYNs:

```bash
tshark -r "$PCAP" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
```

Traffic involving TCP/4444:

```bash
tshark -r "$PCAP" -Y "tcp.port == 4444" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags
```

## Analyst Reminder

Filters find evidence. They do not provide the verdict automatically.

Always distinguish:

- **Observation:** what the packet actually contains
- **Inference:** what the activity may represent
- **Confirmation:** what is proven by multiple evidence sources
