# Reproduction Notes

This document provides a repeatable way to reproduce the traffic-analysis exercise if the original packet capture needs to be regenerated.

## 1. Start Wireshark

Select the active Windows network adapter and begin capture.

## 2. Generate DNS Traffic

```cmd
nslookup example.com
```

Filter:

```text
dns
```

## 3. Generate ICMP Traffic

```cmd
ping example.com
```

Filter:

```text
icmp
```

## 4. Generate Web Traffic

Browse to normal web pages or use a controlled test page.

Filters:

```text
http
```

```text
tls
```

## 5. Inspect TCP Sessions

Filters:

```text
tcp
```

```text
tcp.flags.syn == 1
```

## 6. Review Statistics

Open:

- Statistics -> Protocol Hierarchy
- Statistics -> Conversations
- Statistics -> Endpoints
- Statistics -> I/O Graphs

## 7. Save Evidence

Save the capture locally if desired and export screenshots using the filenames listed in `screenshots/README.md`.

> Only capture traffic on networks and systems you are authorised to analyse.
