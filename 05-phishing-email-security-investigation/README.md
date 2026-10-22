# Phishing and Email Security Investigation

**Status:** Completed  
**Focus:** Email triage, header analysis, IOC extraction, attachment review, BEC analysis and SOC response planning

## Overview

This lab focused on investigating suspicious email reports from a SOC Analyst Level 1 perspective.

Five email cases were reviewed using a consistent workflow: sender and header review, URL/domain analysis, attachment inspection, IOC extraction, severity selection, verdict writing and response recommendations.

The evidence set is stored in the `evidence/` folder so the results can be reproduced from the same message files and attachment.

## Cases Reviewed

| # | Scenario | Severity | Analyst Verdict |
|---|---|---:|---|
| 1 | Microsoft 365 password expiration | Medium | Phishing / credential harvesting |
| 2 | Past-due invoice ZIP attachment | High | Phishing / suspicious attachment delivery |
| 3 | CEO "quick favor" | Medium | Business Email Compromise |
| 4 | Fake Okta security alert | Medium | Phishing / credential harvesting |
| 5 | Fake DocuSign document review | Medium | Phishing / credential harvesting |

## Evidence Files

The lab includes:

- five RFC-style `.eml` message files
- one ZIP attachment extracted from the invoice case
- the inner JavaScript file
- a CSV evidence manifest
- parsed header output
- attachment hash and extraction results
- static-analysis command output

[View the evidence folder](./evidence/)

## Investigation Workflow

For each email I reviewed:

1. Subject, display name and sender address
2. Reply-To and Return-Path
3. Message-ID domain
4. Received path and source IP
5. SPF / DKIM / DMARC results recorded in the message headers
6. URL and domain structure
7. Attachment type, archive contents and hashes
8. Social engineering indicators
9. Likely attacker objective
10. Final severity, verdict and response actions

## Header Findings

### Case 1 — Microsoft 365 Password Expiration

```text
From: IT Support <support@micros0ft-security.example>
Reply-To: support@micros0ft-security.example
Return-Path: <bounce@micros0ft-security.example>
Received IP: 198.51.100.24

SPF: fail
DKIM: none
DMARC: fail
```

The failed authentication results added weight to an already suspicious sender/domain pattern.

### Case 2 — Invoice ZIP

```text
From: Billing Department <billing@secure-invoices-payments.example>
Return-Path: <bounce@secure-invoices-payments.example>
Received IP: 203.0.113.44

SPF: pass
DKIM: pass
DMARC: pass
```

This case was useful because passing email authentication did not make the message trustworthy. Authentication proved domain alignment, not business legitimacy.

### Case 3 — CEO / BEC

```text
From: CEO <ceo.company.office@gmail.com>
Reply-To: ceo.company.office@gmail.com
Received IP: 209.85.220.41

SPF: pass
DKIM: pass
DMARC: pass
```

The message still presented BEC risk because the issue was executive impersonation, not sender-domain spoofing.

### Case 4 — Okta Security Alert

```text
From: Security Alert <alerts@okta-verification.example>
Received IP: 192.0.2.91

SPF: pass
DKIM: none
DMARC: pass
```

### Case 5 — DocuSign Review

```text
From: DocuSign Notification <notification@docusign-secure.example>
Received IP: 198.51.100.88

SPF: pass
DKIM: pass
DMARC: pass
```

The Okta and DocuSign examples reinforced that authentication success does not prove the sender is an authorised brand.

## Attachment Analysis

The invoice case contained:

```text
Filename: Invoice_INV-88421.zip
MIME type: application/zip
Size: 194 bytes

MD5:
d085fee01f400459915d1575bfac5dcc

SHA-1:
019b4bc678db084438020610a89ddaaff75633d6

SHA-256:
c422f08c2dd655422a10c07a7fc2003fd289d97c9c31a08529f126ff61ad5465
```

Archive contents:

```text
Invoice_INV-88421.js
Size: 54 bytes
```

Inner script hashes:

```text
MD5:
6b45fb571ec9c96ecc0599a5e40cfd60

SHA-1:
120c305e5f2383d59a2aa159f95fd189230e9571

SHA-256:
75e36eab35c99f782389aa577544849f27f5fa960c49c005152f8d0f6720bdae
```

Static strings review returned:

```text
WScript.Echo("Invoice INV-88421 - payment reminder");
```

The attachment type and archive/script combination justified caution, but the static content did not show network access, process creation, file writes, obfuscation or credential access.

## Key Findings

- Failed SPF/DKIM/DMARC can strengthen suspicion, but passing authentication does not make an email benign.
- BEC can use legitimate webmail infrastructure and still be malicious by impersonation and intent.
- Lookalike domains were the main indicator in the Microsoft, Okta and DocuSign cases.
- The invoice case demonstrated why attachment type and archive contents should be reviewed separately from message authentication.
- A suspicious ZIP or script extension increases risk, but the attachment still needs technical analysis before claiming malware execution.
- Display names are weak evidence compared with sender/domain/header data.
- HTTPS is transport encryption, not a trust signal.

## Detailed Analysis

- [Case investigations](./phishing-cases.md)
- [IOC and response summary](./ioc-summary.md)
- [Final incident report](./incident-report.md)
- [Evidence and analysis output](./evidence/)

## Response Actions Practised

- block malicious sender/domain/URL indicators
- search for additional recipients
- quarantine or remove matching messages
- determine whether users clicked, replied, opened attachments or entered credentials
- reset passwords and revoke sessions where credentials were submitted
- review identity-provider sign-in logs
- inspect endpoint telemetry when attachment execution is suspected
- escalate to incident response for confirmed compromise, malware execution or financial fraud
