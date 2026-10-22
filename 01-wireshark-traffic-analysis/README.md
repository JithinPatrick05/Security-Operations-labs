# Wireshark Traffic Analysis

## Overview

This lab covers packet capture and traffic analysis on a Windows 11 workstation using Wireshark. I generated normal browsing, DNS and ICMP traffic first, then reviewed a separate controlled capture containing suspicious network behaviour.

The aim was to practise reading traffic at packet level rather than only relying on high-level alerts.

## Environment

| Component | Details |
|---|---|
| Host | Windows 11 |
| Packet analyser | Wireshark |
| Traffic generation | Browser and Windows Command Prompt |
| Capture interface | Active Wi-Fi adapter |
| Main protocols reviewed | TCP, UDP, DNS, HTTP, TLS, ICMP, ARP |

## Baseline traffic

I started with normal traffic so I had something clean to compare against.

~~~cmd
nslookup github.com
ping 1.1.1.1
~~~

For web traffic I used:

- http://neverssl.com for readable HTTP
- https://github.com for TLS/HTTPS

## Protocol review

I used:

~~~text
Statistics -> Protocol Hierarchy
Statistics -> Conversations
Statistics -> Endpoints
Statistics -> I/O Graphs
~~~

This gave me the main protocols and busiest endpoints before filtering individual conversations.

## TCP handshake

Filter:

~~~text
tcp.flags.syn == 1
~~~

A normal TCP connection showed:

~~~text
SYN
SYN, ACK
ACK
~~~

This was useful later when comparing a normal connection with the short SYN probes in the suspicious capture.

## DNS

Filter:

~~~text
dns
~~~

The github.com lookup showed the query, matching response and returned address records. I checked the query name, type, transaction ID, response addresses and response time.

## HTTP

Filter:

~~~text
http
~~~

Traffic to neverssl.com showed readable HTTP request information including the request method, URI, Host header and response code.

## TLS / HTTPS

Filter:

~~~text
tls
~~~

The GitHub session showed TLS handshake traffic and encrypted application data over TCP/443.

Even though the application payload was encrypted, the capture still exposed useful metadata such as source and destination, ports, timing, packet sizes and handshake details.

## ICMP

Filter:

~~~text
icmp
~~~

The ping to 1.1.1.1 produced Echo Request and Echo Reply packets and made it easy to compare request/reply timing.

## Useful filters

| Purpose | Filter |
|---|---|
| DNS | dns |
| HTTP | http |
| TLS | tls |
| TCP | tcp |
| UDP | udp |
| ICMP | icmp |
| ARP | arp |
| One host | ip.addr == <IP_ADDRESS> |
| Initial TCP SYN | tcp.flags.syn == 1 && tcp.flags.ack == 0 |
| Retransmissions | tcp.analysis.retransmission |

## Baseline findings

- DNS responses could be tied to later connections using timestamps and returned addresses.
- TCP connection establishment was easy to identify from SYN, SYN-ACK and ACK.
- HTTP exposed application-layer data directly in the capture.
- TLS hid application content but still left useful network metadata.
- Conversations and Endpoints were quicker than reading packets one by one when identifying the main communication paths.

## Suspicious traffic case

I used a second controlled capture to investigate a Windows workstation named JPtest1.

The case includes a short TCP service scan, DNS activity tied to later connections, repeated TLS sessions to one destination, timing analysis and follow-up endpoint checks.

[Read the suspicious traffic investigation](./synthetic-suspicious-traffic-scenario.md)

## Skills covered

- Wireshark
- TCP/IP
- DNS analysis
- HTTP and TLS analysis
- packet filtering
- network conversations
- service-scan identification
- traffic baselining
- incident triage
- network troubleshooting
