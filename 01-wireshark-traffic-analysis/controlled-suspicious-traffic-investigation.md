# Controlled Suspicious Traffic Investigation

> Lab: controlled traffic-analysis exercise
> Host: JPtest1
> OS: Windows 11
> Tool: Wireshark

## Summary

A capture from JPtest1 showed two patterns worth investigating.

First, another device on the local network probed several Windows service ports in quick succession. About a minute later, JPtest1 resolved the same hostname and began opening short TLS sessions to one external IP at roughly one-minute intervals.

I generated the activity in a controlled lab and then worked through the capture as if it had arrived as an unknown network alert. The focus was on isolating the traffic, comparing timing and deciding what could actually be supported by the packet data.

## Environment

| Item | Value |
|---|---|
| Hostname | JPtest1 |
| Host IP | 192.168.1.143 |
| Gateway / DNS | 192.168.1.1 |
| Scan source | 192.168.1.87 |
| Remote IP | 203.0.113.77 |
| Hostname queried | cdn-storage-sync.test |
| Capture window | 22:14:05 to 22:22:40 |
| Interface | Wi-Fi |
| Severity | Medium |

203.0.113.77 is from the TEST-NET-3 address block and is used as the remote endpoint for the lab.

## Timeline

| Time | Activity |
|---|---|
| 22:15:11.312 | 192.168.1.87 sends a SYN to TCP/135 on JPtest1 |
| 22:15:11.429 | SYN to TCP/139 |
| 22:15:11.538 | SYN to TCP/445 |
| 22:15:11.682 | SYN to TCP/3389 |
| 22:15:11.844 | SYN to TCP/5985 |
| 22:15:12.041 | SYN to TCP/5986 |
| 22:16:03.447 | JPtest1 queries cdn-storage-sync.test |
| 22:16:03.461 | DNS response returns 203.0.113.77, TTL 300 |
| 22:16:04.118 | First TLS connection to 203.0.113.77:443 |
| 22:17:03.977 | Second TLS connection |
| 22:18:04.502 | Third TLS connection |
| 22:19:04.146 | Fourth TLS connection |
| 22:20:03.814 | Fifth TLS connection |
| 22:21:03.472 | DNS query repeated after cache TTL expiry |
| 22:21:04.321 | Sixth TLS connection |

## 1. Port scan

Display filter:

~~~text
ip.src == 192.168.1.87 && ip.dst == 192.168.1.143 && tcp.flags.syn == 1 && tcp.flags.ack == 0
~~~

The filter returned six initial SYN packets in about 730 ms.

| Port | Service | Response from JPtest1 |
|---|---|---|
| 135 | MSRPC | SYN, ACK |
| 139 | NetBIOS | RST, ACK |
| 445 | SMB | SYN, ACK |
| 3389 | RDP | RST, ACK |
| 5985 | WinRM HTTP | RST, ACK |
| 5986 | WinRM HTTPS | RST, ACK |

TCP/135 and TCP/445 were listening during the capture. The other four probes were reset by the host.

The timing and spread across Windows service ports are consistent with service enumeration rather than normal workstation traffic.

MITRE ATT&CK: T1046 - Network Service Scanning

## 2. DNS activity

Filter:

~~~text
ip.addr == 192.168.1.143 && dns
~~~

The relevant query was:

~~~text
cdn-storage-sync.test
~~~

The DNS server at 192.168.1.1 returned:

~~~text
A 203.0.113.77
TTL 300
~~~

The lookup occurred at 22:16:03.447. The first connection to 203.0.113.77 started 657 ms after the DNS response.

The same name was queried again just over five minutes later, matching the 300-second TTL.

Targeted filter:

~~~text
dns.qry.name == "cdn-storage-sync.test"
~~~

## 3. Repeated TLS connections

Filter:

~~~text
ip.src == 192.168.1.143 && ip.dst == 203.0.113.77 && tcp.dstport == 443
~~~

Six separate TCP/TLS sessions were visible.

| Start time | Source port | Duration | Sent | Received |
|---|---:|---:|---:|---:|
| 22:16:04.118 | 50342 | 1.84 s | 3.9 KB | 11.8 KB |
| 22:17:03.977 | 50363 | 1.71 s | 3.7 KB | 11.4 KB |
| 22:18:04.502 | 50381 | 1.79 s | 3.8 KB | 11.6 KB |
| 22:19:04.146 | 50405 | 1.76 s | 3.8 KB | 11.7 KB |
| 22:20:03.814 | 50426 | 1.68 s | 3.7 KB | 11.5 KB |
| 22:21:04.321 | 50444 | 1.82 s | 3.9 KB | 11.9 KB |

Connection intervals:

~~~text
59.859 s
60.525 s
59.644 s
59.668 s
60.507 s
~~~

Average interval: 60.04 seconds.

Across the six sessions, JPtest1 sent about 22.8 KB and received about 69.9 KB.

The sessions were short, used different ephemeral source ports, and transferred similar amounts of data each time. The timing is much more regular than normal manual browsing and points to an automated process.

## 4. TLS details

The first connection contained a TLS ClientHello with the server name:

~~~text
cdn-storage-sync.test
~~~

The session negotiated TLS 1.3 over TCP/443.

After the handshake, the application data was encrypted. Wireshark still exposed useful metadata including the destination, ports, timing, packet sizes and TLS handshake fields.

The capture did not show the contents of the encrypted exchange.

## 5. Conversation review

The Conversations view showed repeated communication between the same two endpoints:

~~~text
192.168.1.143 <-> 203.0.113.77
~~~

The repeated destination, similar session length, similar data volume and approximately one-minute interval were the main reasons the traffic was treated as suspicious.

## Filters used

| Purpose | Filter |
|---|---|
| All traffic for JPtest1 | ip.addr == 192.168.1.143 |
| Initial scan probes | ip.src == 192.168.1.87 && ip.dst == 192.168.1.143 && tcp.flags.syn == 1 && tcp.flags.ack == 0 |
| DNS from JPtest1 | ip.addr == 192.168.1.143 && dns |
| Specific DNS name | dns.qry.name == "cdn-storage-sync.test" |
| Remote IP | ip.addr == 203.0.113.77 |
| Outbound HTTPS | ip.src == 192.168.1.143 && ip.dst == 203.0.113.77 && tcp.dstport == 443 |
| TLS | tls |

## Findings

- 192.168.1.87 probed six Windows-related TCP ports on JPtest1 in under one second.
- TCP/135 and TCP/445 were listening during the scan.
- JPtest1 resolved cdn-storage-sync.test to 203.0.113.77.
- The DNS response used a 300-second TTL and the hostname was queried again after that period.
- JPtest1 opened six outbound TLS sessions to 203.0.113.77:443.
- The average interval between sessions was 60.04 seconds.
- The connections were similar in duration and transferred similar amounts of data.

The packet capture does not prove malware was running on the host and does not identify the process that created the connections.

## Assessment

The inbound SYN pattern is consistent with service discovery.

The outbound TLS traffic is more interesting. The regular timing, repeated destination, similar connection duration and consistent data volume all point to automated activity. In a real incident I would escalate it for endpoint correlation rather than call it command and control from packet data alone.

The next step would be to use Sysmon or EDR telemetry on JPtest1 to identify the process responsible for the DNS query and TCP/443 sessions.

## MITRE ATT&CK

| Activity | Technique | ID |
|---|---|---|
| Multi-port service probing | Network Service Scanning | T1046 |
| Repeated HTTPS communication | Application Layer Protocol: Web Protocols | T1071.001 |
| DNS used before outbound connection | Application Layer Protocol: DNS | T1071.004 |

## Next steps

1. Check Sysmon Event ID 3 or EDR network telemetry for 203.0.113.77.
2. Identify the process and user context behind the connection.
3. Review process creation events around 22:16.
4. Confirm whether 192.168.1.87 is an approved scanner or another workstation.
5. Search other endpoints for the same IP or DNS name.
6. Review persistence locations and scheduled tasks if the process is unexpected.
7. Consider containment only if endpoint evidence confirms malicious execution.

## Conclusion

The scan was easy to identify once the SYN traffic was isolated. The outbound TLS sessions needed more context. The strongest signal was the repeated pattern: same destination, similar data volume, short session length and roughly one connection per minute.
