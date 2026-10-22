# Evidence Checklist

This directory is reserved for screenshots from the original Wireshark exercise and from recreated controlled simulations.

## Baseline Traffic Analysis

| Filename | Evidence to capture |
|---|---|
| `01-capture-overview.png` | Wireshark packet list showing the active capture |
| `02-protocol-hierarchy.png` | Statistics -> Protocol Hierarchy |
| `03-tcp-handshake.png` | SYN -> SYN,ACK -> ACK sequence |
| `04-dns-query-response.png` | DNS query and matching response |
| `05-http-request.png` | HTTP request/response where available |
| `06-tls-session.png` | TLS handshake/session and encrypted application data |
| `07-icmp-echo.png` | ICMP Echo Request and Echo Reply |
| `08-conversations-endpoints.png` | Conversations or Endpoints statistics |

## Simulated Suspicious Traffic Case

| Filename | Evidence to recreate |
|---|---|
| `09-simulated-port-scan.png` | Rapid SYN probes from `192.168.50.99` to `JPtest1` / `192.168.50.23` |
| `10-simulated-dns-query.png` | Query for `sync-check.example.com` resolving to documentation IP `198.51.100.44` |
| `11-simulated-periodic-tls.png` | Repeated TLS/443 sessions approximately 60 seconds apart |
| `12-simulated-conversations.png` | Wireshark Conversations view showing the simulated destination |

## Evidence Quality

Before uploading:

- Crop unrelated desktop content.
- Remove or redact personal information.
- Keep packet timestamps and relevant protocol fields visible.
- Make sure each screenshot supports a statement made in the corresponding report.
- Do not alter packet values or create synthetic screenshots presented as original evidence.
- For simulated traffic, keep the report labelled as a controlled/simulated exercise.

If a recreated capture produces different timestamps, ports or addresses, update the report so the written findings match the actual evidence.
