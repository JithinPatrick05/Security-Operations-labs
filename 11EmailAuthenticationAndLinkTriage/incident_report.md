# Case 011 | Email authentication and misleading link investigation

**Date:** 23 November 2026  
**Environment:** Home lab, VirtualSOC-style analyst workflow, offline RFC 5322 message review  
**Severity:** Medium (lab assessment)  
**Verdict:** Suspicious credential-phishing-style message; no recipient compromise established

## Alert and first look

I reviewed an email claiming that a Q4 supplier document had been shared with the finance team. The display name was "Microsoft 365 Documents", and the message asked the recipient to confirm access before 4 pm.

I started with the original message file rather than relying on what an email client displays. I checked the visible From address, Reply-To, Return-Path, Message-ID, Received header, recorded authentication results and both MIME body parts.

## What I checked

### 1. Sender identity

The visible sender was notice@file-access.test. The Return-Path was bounce@message-relay.test, and the Message-ID also used message-relay.test. A separate sending domain is not automatically malicious, but I wanted to see whether it was authorised to authenticate for the visible sender.

### 2. SPF, DKIM and DMARC

The Authentication-Results header in this exercise recorded:

- SPF pass for message-relay.test
- DKIM pass for message-relay.test
- DMARC fail for the visible From domain file-access.test

The key finding was **alignment**. Neither the domain reported for SPF nor the one reported for DKIM aligned with file-access.test. Passing SPF and DKIM for a different domain does not establish that the visible sender is legitimate.

This is a review of the results **recorded in the lab email**, not independent verification by a mail gateway or cryptographic validation of a DKIM signature.

### 3. Received path

The case message contained a Received line naming relay.message-relay.test and 192.0.2.57. I recorded it as an asserted relay hop, not a verified public sending IP. The address is documentation-only and must not be used as a live block indicator.

### 4. Plain text versus HTML

The text part included the destination directly. The HTML version displayed https://login.microsoftonline.com/ but the actual hyperlink pointed to https://review.file-access.test/verify?doc=Q4-SUPPLIER-REG.

I extracted the anchor text and href separately. That mismatch was a stronger signal than the message's urgent wording. I did not visit the URL.

### 5. Attachment check

I enumerated MIME attachments and found none. This was a link-based lure in the case evidence, not an attachment investigation.

### 6. Recipient exposure and scoping

No tenant message trace, Safe Links click records, Entra ID sign-ins or endpoint events were supplied for this exercise. I therefore cannot say the email reached a real inbox, that anyone clicked, or that credentials were submitted.

I prepared Defender XDR hunting queries to use in an environment with authorised data. Those queries are stored separately and were **not executed against a tenant** as part of the saved evidence.

## Decision

I assessed the content as a suspicious credential-phishing-style message and chose Medium severity for the lab triage. The decision came from three things together: Microsoft 365 branding, unaligned reported authentication, and a link whose displayed host differed from its destination.

I would isolate the message first, preserve the original .eml and message identifiers, and check delivery and click exposure before making any account-compromise claim. Where delivery was confirmed, I would search other recipients and quarantine matching messages. Password resets and session revocation would depend on evidence of a click followed by credential submission or suspicious authentication, not on the email alone.

## Detection and prevention notes

This case is a useful reminder that SPF or DKIM pass on its own does not prove an email is trustworthy. A mail control should assess DMARC alignment, impersonation, the real URL destination and user interaction as separate questions. A policy review would be justified if mail with failing alignment were shown to arrive unflagged, but there is no such delivery evidence here.

**MITRE ATT&CK:** T1566.002, Phishing: Spearphishing Link. This is a mapping of the attempted technique in the lab content, not evidence of a real-world campaign.

## Evidence and limits

- [Original case email](./evidence/message.eml)
- [Header and URL parser](./analysis.py)
- [Parser output](./evidence/analysis.txt)
- [Structured findings](./evidence/findings.json)
- [Visual evidence summary](./evidence/header-review.svg)
- [Hunting queries to run in an authorised tenant](./queries.kql)

The saved material supports email-content triage only. It does not establish a live attack, a mail security product failure, successful phishing, or completed containment in a customer environment.
