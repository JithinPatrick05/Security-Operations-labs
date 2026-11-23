#!/usr/bin/env python3
"""Offline email header and URL triage. Does not contact remote services."""
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
MESSAGE = ROOT / "evidence" / "message.eml"

class LinkReader(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.active = None
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self.active = {"href": dict(attrs).get("href", ""), "label": ""}
    def handle_data(self, data):
        if self.active is not None:
            self.active["label"] += data
    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.active is not None:
            self.links.append(self.active)
            self.active = None

def domain_from_address(header):
    address = parseaddr(header or "")[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""

def auth_result(header, name):
    match = re.search(r"(?i)\b" + name + r"\s*=\s*([a-z]+)", header or "")
    return match.group(1).lower() if match else "not reported"

raw = MESSAGE.read_bytes()
msg = BytesParser(policy=policy.default).parsebytes(raw)
html = msg.get_body(preferencelist=("html",))
reader = LinkReader()
reader.feed(html.get_content() if html else "")
auth_header = str(msg.get("Authentication-Results", ""))
from_domain = domain_from_address(str(msg.get("From", "")))
return_domain = domain_from_address(str(msg.get("Return-Path", "")))
reply_domain = domain_from_address(str(msg.get("Reply-To", "")))
spf_match = re.search(r"smtp\.mailfrom=([\w.-]+)", auth_header)
dkim_match = re.search(r"header\.d=([\w.-]+)", auth_header)
spf_domain = spf_match.group(1).lower() if spf_match else ""
dkim_domain = dkim_match.group(1).lower() if dkim_match else ""

def aligned(auth_domain, visible_domain):
    return bool(auth_domain and visible_domain and
                (auth_domain == visible_domain or auth_domain.endswith("." + visible_domain)))

links = []
for entry in reader.links:
    url, label = entry["href"], entry["label"].strip()
    label_host = urlsplit(label).hostname if label.startswith(("http://", "https://")) else None
    target_host = urlsplit(url).hostname
    links.append({"displayed_text": label, "actual_href": url,
                  "displayed_host": label_host, "destination_host": target_host,
                  "host_mismatch": bool(label_host and target_host and label_host.lower() != target_host.lower())})

result = {
    "case": str(msg.get("X-Lab-Case", "")),
    "message_sha256": hashlib.sha256(raw).hexdigest(),
    "subject": str(msg.get("Subject", "")),
    "message_id": str(msg.get("Message-ID", "")),
    "from": str(msg.get("From", "")),
    "reply_to": str(msg.get("Reply-To", "")),
    "return_path": str(msg.get("Return-Path", "")),
    "received": str(msg.get("Received", "")),
    "authentication_as_recorded_in_message": {
        "spf": auth_result(auth_header, "spf"),
        "dkim": auth_result(auth_header, "dkim"),
        "dmarc": auth_result(auth_header, "dmarc"),
        "visible_from_domain": from_domain,
        "envelope_domain": return_domain,
        "reply_to_domain": reply_domain,
        "spf_authenticated_domain": spf_domain,
        "dkim_signing_domain_reported": dkim_domain,
        "spf_aligned_to_from": aligned(spf_domain, from_domain),
        "dkim_aligned_to_from": aligned(dkim_domain, from_domain)
    },
    "html_links": links,
    "attachments": [p.get_filename() for p in msg.iter_attachments()],
    "limits": [
        "Authentication-Results is a header claim in the case message, not an independent verification of SPF/DKIM/DMARC.",
        "No live URL visit or sandbox execution was performed.",
        "No mail trace, click, sign-in or endpoint logs were available for this case."
    ]
}
(ROOT / "evidence" / "findings.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
a = result["authentication_as_recorded_in_message"]
lines = [
    "EMAIL-011 | Offline email header and URL review",
    f"Case message SHA-256: {result['message_sha256']}",
    f"Subject: {result['subject']}",
    f"From: {result['from']}",
    f"Reply-To: {result['reply_to']}",
    f"Return-Path: {result['return_path']}",
    f"Message-ID: {result['message_id']}",
    f"SPF (recorded): {a['spf']} | domain: {spf_domain} | aligned: {a['spf_aligned_to_from']}",
    f"DKIM (recorded): {a['dkim']} | domain: {dkim_domain} | aligned: {a['dkim_aligned_to_from']}",
    f"DMARC (recorded): {a['dmarc']} | header.from: {from_domain}",
    f"HTML links inspected: {len(links)}"
]
for i, link in enumerate(links, 1):
    lines.extend([
        f"Link {i} visible: {link['displayed_text']}",
        f"Link {i} actual: {link['actual_href']}",
        f"Link {i} destination differs from display: {link['host_mismatch']}"
    ])
lines.extend([
    f"Attachments: {len(result['attachments'])}",
    "Assessment: suspected credential-phishing lure; no proof of clicks or credential submission.",
    "Scope: local case file only. Recorded authentication results are not independently validated."
])
(ROOT / "evidence" / "analysis.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
