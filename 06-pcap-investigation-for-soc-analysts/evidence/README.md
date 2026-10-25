# Evidence

## Training Dataset

`soc-pcap-training.pcap` is a controlled synthetic packet capture created for this defensive SOC investigation lab.

It contains **13 Ethernet/IPv4 packets** representing:

1. DNS query for `portal-login.example`
2. DNS response mapping it to `198.51.100.25`
3. TCP handshake to `198.51.100.25:80`
4. HTTP GET request for `/download/update.exe`
5. HTTP 200 response containing harmless training content
6. repeated outbound SYN attempts to `203.0.113.77:4444`
7. DNS query for `telemetry-sync.example`
8. DNS response mapping it to `203.0.113.77`
9. another outbound TCP/4444 attempt

## Safety

No live malicious infrastructure is used.

- `198.51.100.0/24` and `203.0.113.0/24` are documentation networks.
- `.example` is a reserved namespace.
- the HTTP body is the harmless string `TRAINING-BINARY`
- no exploit code, malware or credentials are included

## Hashes

```text
MD5:
b759b4fd09889ec4834bbd584748b14e

SHA-1:
af7c9841e5a842a06ae9441e792c4c9ec402b166

SHA-256:
a5c13dc4eac65ee0710f49610ce2e21fd220aef4c30348b0a8306623dcc1ca63
```

## Reproduction

Open the PCAP in Wireshark and work through the filters in:

- [../wireshark-tshark-cheatsheet.md](../wireshark-tshark-cheatsheet.md)
- [../investigation-notes.md](../investigation-notes.md)

This allows the findings in the incident report to be independently checked against the packet evidence.
