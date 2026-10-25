# Cybersecurity Lab: How to Investigate PCAPs as a SOC Analyst

**Status:** Completed — controlled training dataset  
**Date:** 25 October 2026  
**Focus:** PCAP triage, network forensics, DNS/HTTP/TCP analysis, IOC extraction, analyst judgement and SOC escalation  
**Tools / Concepts:** Wireshark, tshark, tcpdump, TCP/IP, DNS, HTTP, packet filtering, stream analysis, incident documentation

## Overview

This lab demonstrates a repeatable SOC Analyst workflow for investigating a packet capture (PCAP) from initial triage through to escalation.

The capture used in this project is a **safe synthetic training PCAP** created specifically for this repository. It uses RFC/documentation-only addressing and reserved example domains, so it does not contact or reproduce live malicious infrastructure.

The goal is not simply to find "bad-looking" packets. The goal is to build an evidence-based timeline, distinguish facts from assumptions, identify useful indicators, document limitations and decide what additional telemetry a SOC analyst would need before declaring a compromise.

## Scenario

A workstation at `10.0.0.25` has been flagged for unusual outbound network activity.

The analyst is given a PCAP and asked to determine:

1. Which hosts and protocols are involved?
2. Which DNS queries were made?
3. Was content downloaded over HTTP?
4. Are there unusual outbound connection attempts?
5. What indicators should be extracted?
6. Does the traffic prove compromise?
7. What should be escalated or investigated next?

## Evidence Set

The lab includes the reproducible capture:

- [Synthetic SOC training PCAP](./evidence/soc-pcap-training.pcap)
- [Evidence notes and hashes](./evidence/README.md)

PCAP SHA-256:

```text
a5c13dc4eac65ee0710f49610ce2e21fd220aef4c30348b0a8306623dcc1ca63
```

## Investigation Workflow

### 1. Preserve and identify the evidence

Before analysis:

- record the file name
- calculate a cryptographic hash
- work from a copy where appropriate
- record the time zone and investigation scope
- avoid changing the original evidence

### 2. Establish the traffic baseline

Review:

- capture duration
- packet count
- protocol hierarchy
- IPv4/IPv6 endpoints
- conversations
- top talkers
- common ports

In Wireshark these are available under **Statistics**.

### 3. Identify the affected host

Start with the suspected endpoint:

```text
ip.addr == 10.0.0.25
```

Then separate inbound and outbound traffic:

```text
ip.src == 10.0.0.25
ip.dst == 10.0.0.25
```

### 4. Review DNS

Useful filters:

```text
dns
dns.flags.response == 0
dns.flags.response == 1
dns.qry.name
```

The capture shows queries for:

```text
portal-login.example
telemetry-sync.example
```

### 5. Review web traffic

Useful filters:

```text
http
http.request
http.response
http.request.method == "GET"
```

The workstation requests:

```text
GET /download/update.exe
Host: portal-login.example
User-Agent: TrainingClient/1.0
```

The server replies with:

```text
HTTP/1.1 200 OK
Content-Type: application/octet-stream
```

This supports the conclusion that binary-style content was transferred over HTTP.

### 6. Hunt for unusual TCP behaviour

Filter for initial SYN packets:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Filter for the unusual destination port used in this lab:

```text
tcp.port == 4444
```

The workstation repeatedly attempts connections to:

```text
203.0.113.77:4444
```

No successful TCP handshake to that destination is present in this capture.

### 7. Build a timeline

The observed sequence is:

1. `10.0.0.25` queries `portal-login.example`.
2. DNS resolves the training domain to `198.51.100.25`.
3. The workstation establishes HTTP connectivity.
4. It requests `/download/update.exe`.
5. The server returns binary-style content.
6. The workstation makes repeated outbound SYN attempts to `203.0.113.77:4444`.
7. It later queries `telemetry-sync.example`, which resolves to the same `203.0.113.77` address.
8. Another outbound connection attempt to TCP/4444 follows.

## Analyst Verdict

**Verdict:** Suspicious network activity requiring endpoint validation  
**Lab severity:** Medium

The PCAP demonstrates:

- suspicious-looking DNS activity
- an executable-style HTTP download path
- successful transfer of binary-style content
- repeated outbound connection attempts to an uncommon port
- DNS resolution associated with the same destination used for those attempts

However, **the PCAP does not prove that malware executed on the host**.

A packet capture cannot by itself establish:

- which process initiated the connection
- whether the downloaded content executed
- whether persistence was created
- whether credentials were stolen
- whether the host was successfully controlled

Those conclusions require endpoint, identity and additional network telemetry.

## Recommended SOC Next Steps

1. Retrieve EDR telemetry for `10.0.0.25`.
2. Identify the process that generated the HTTP request and TCP/4444 attempts.
3. Locate and hash the downloaded object if it exists on disk.
4. Review process creation, PowerShell, script and persistence telemetry.
5. Check proxy, firewall and DNS logs for the same indicators across other hosts.
6. Search SIEM data for connections to the training indicators.
7. Validate whether the traffic has an authorised business explanation.
8. Escalate for containment if endpoint evidence confirms malicious execution or unauthorised persistence.

## Detailed Lab Files

- [Investigation notes](./investigation-notes.md)
- [Wireshark and tshark filter cheat sheet](./wireshark-tshark-cheatsheet.md)
- [IOC summary](./ioc-summary.md)
- [SOC incident report](./incident-report.md)
- [Evidence folder](./evidence/)

## Skills Demonstrated

- structured PCAP triage
- host and conversation identification
- DNS investigation
- HTTP request/response analysis
- TCP flag and connection-attempt analysis
- IOC extraction
- evidence-based analyst judgement
- distinguishing observation from inference
- SOC ticket writing and escalation
- identifying the additional telemetry required to confirm compromise

## Key Learning

A strong SOC investigation does not stop at "this looks malicious."

The analyst should be able to explain:

**what was observed, why it matters, what cannot yet be proven, and what evidence should be collected next.**
