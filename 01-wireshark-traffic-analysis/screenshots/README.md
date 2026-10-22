# Evidence Checklist

This directory is reserved for screenshots from the original Wireshark lab capture.

Use the following filenames so the evidence links in the main report render automatically.

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

## Evidence Quality

Before uploading:

- Crop unrelated desktop content.
- Remove or redact personal information.
- Keep packet timestamps and relevant protocol fields visible.
- Make sure each screenshot supports a statement made in the report.
- Do not alter packet values or create synthetic evidence presented as an original capture.

If the original capture used different domains, IP addresses or protocol details, update the report so the written findings match the evidence.
