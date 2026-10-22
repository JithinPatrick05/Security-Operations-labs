# Phishing Case Investigations

## Case 1 — Microsoft 365 Password Expiration

**Subject:** Urgent: Password Expiration Notice  
**Sender:** IT Support <support@micros0ft-security.example>  
**Received IP:** 198.51.100.24  
**Severity:** Medium  
**Verdict:** Phishing / credential harvesting

### Header Review

```text
Reply-To: support@micros0ft-security.example
Return-Path: <bounce@micros0ft-security.example>
Message-ID domain: micros0ft-security.example

SPF: fail
DKIM: none
DMARC: fail
```

### Analysis

The sender and linked domain used Microsoft-themed lookalike naming. The message created urgency by claiming the account would be suspended unless the user verified the password immediately.

The authentication failures supported the suspicious assessment, but the decisive indicators were the lookalike domain, account-pressure language and credential-verification theme.

### Recommended Actions

- Block sender/domain and URL indicators.
- Search for other recipients.
- Quarantine matching messages.
- Confirm whether the user clicked the link.
- Reset credentials and revoke sessions if credentials were entered.
- Review sign-in telemetry.

---

## Case 2 — Past-Due Invoice ZIP

**Subject:** Invoice INV-88421 Past Due  
**Sender:** Billing Department <billing@secure-invoices-payments.example>  
**Received IP:** 203.0.113.44  
**Severity:** High  
**Verdict:** Phishing / suspicious attachment delivery

### Header Review

```text
Return-Path: <bounce@secure-invoices-payments.example>
Message-ID domain: secure-invoices-payments.example

SPF: pass
DKIM: pass
DMARC: pass
```

### Attachment Evidence

```text
Attachment: Invoice_INV-88421.zip
MIME: application/zip
Size: 194 bytes
SHA-256: c422f08c2dd655422a10c07a7fc2003fd289d97c9c31a08529f126ff61ad5465
MD5: d085fee01f400459915d1575bfac5dcc
```

The hash extracted from the `.eml` attachment matched the standalone evidence file.

Archive listing:

```text
Invoice_INV-88421.js
54 bytes
```

Inner file:

```text
SHA-256: 75e36eab35c99f782389aa577544849f27f5fa960c49c005152f8d0f6720bdae
MD5: 6b45fb571ec9c96ecc0599a5e40cfd60
File type: ASCII text
```

Strings:

```text
WScript.Echo("Invoice INV-88421 - payment reminder");
```

### Analysis

The message used an invoice/payment theme, financial urgency and a compressed script attachment.

Email authentication passed, which demonstrated that SPF/DKIM/DMARC success alone is not enough to classify a message as legitimate.

The archive contained a JavaScript file, which is a high-risk attachment type. Static review did not identify network calls, process creation, file writes, obfuscation or credential-access behaviour in the script itself.

### Recommended Actions

- Quarantine the message and attachment.
- Search for other recipients.
- Block the sender/domain if the campaign is confirmed malicious.
- Compare attachment hashes across mailboxes/endpoints.
- Check endpoint telemetry for file extraction or script execution.
- Escalate if execution or additional suspicious behaviour is found.

---

## Case 3 — CEO / Executive Impersonation

**Subject:** Quick favor needed  
**Sender:** CEO <ceo.company.office@gmail.com>  
**Received IP:** 209.85.220.41  
**Severity:** Medium  
**Verdict:** Business Email Compromise / executive impersonation

### Header Review

```text
Reply-To: ceo.company.office@gmail.com
Return-Path: <ceo.company.office@gmail.com>
Message-ID domain: gmail.com

SPF: pass
DKIM: pass
DMARC: pass
```

### Analysis

The message passed authentication because it originated from a Gmail account. That did not establish that the sender was the company CEO.

The primary indicators were impersonation, urgency and the request to continue the conversation while the supposed executive was unavailable by phone. This matched a common BEC conversation-starter pattern.

### Recommended Actions

- Remove or quarantine the message.
- Search for similar messages and recipients.
- Warn the targeted user not to reply.
- Confirm whether any information or money was sent.
- Notify internal security and the impersonated executive where appropriate.

---

## Case 4 — Fake Okta Security Alert

**Subject:** Unusual Sign-In Attempt Blocked  
**Sender:** Security Alert <alerts@okta-verification.example>  
**Received IP:** 192.0.2.91  
**Severity:** Medium  
**Verdict:** Phishing / credential harvesting

### Header Review

```text
Return-Path: <alerts@okta-verification.example>

SPF: pass
DKIM: none
DMARC: pass
```

### Analysis

The domain was aligned enough to pass SPF/DMARC for itself, but it was not an authorised Okta domain. The message used a security-alert theme, urgency and account-lockout pressure to direct the user to an Okta-themed verification URL.

### Recommended Actions

- Block URL and sender-domain indicators.
- Search for other recipients.
- Quarantine matching messages.
- Confirm user interaction.
- Reset credentials/revoke sessions if credentials were entered.
- Review identity-provider logs.

---

## Case 5 — Fake DocuSign Document Review

**Subject:** Document Ready for Signature  
**Sender:** DocuSign Notification <notification@docusign-secure.example>  
**Received IP:** 198.51.100.88  
**Severity:** Medium  
**Verdict:** Phishing / credential harvesting

### Header Review

```text
Return-Path: <notification@docusign-secure.example>

SPF: pass
DKIM: pass
DMARC: pass
```

### Analysis

The message authenticated successfully for the sender domain, but the domain itself was a DocuSign-themed lookalike rather than an authorised DocuSign domain.

The body relied on trust in document-signing workflows and time pressure to drive the user to a review link.

### Recommended Actions

- Block sender/domain and URL indicators.
- Search for other recipients.
- Quarantine matching messages.
- Confirm whether users clicked or submitted credentials.
- Review sign-in activity if interaction occurred.
