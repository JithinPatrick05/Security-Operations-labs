# Final Phishing Incident Report

## Executive Summary

Five suspicious email cases were reviewed using a SOC triage workflow covering message headers, sender identity, URL/domain indicators, attachment evidence, social engineering, severity and response recommendations.

The cases represented credential phishing, suspicious attachment delivery and business email compromise patterns.

## Scope

Evidence reviewed:

- five `.eml` message files
- message header fields
- sender and return-path data
- Received source IPs
- SPF / DKIM / DMARC results recorded in the messages
- one ZIP attachment
- one extracted JavaScript file
- MD5 / SHA-1 / SHA-256 hashes
- archive listing and static strings output

## Key Findings

1. The Microsoft 365 case failed SPF and DMARC and used a lookalike sender/domain.
2. The invoice case passed SPF/DKIM/DMARC but still contained an unexpected ZIP with a JavaScript file.
3. The BEC case passed authentication because it used Gmail, but the sender identity did not match the claimed executive role.
4. The Okta case passed SPF/DMARC for its own lookalike domain, demonstrating that domain authentication does not prove brand legitimacy.
5. The DocuSign case passed all three checks for its own sender domain but remained suspicious because the sender/domain represented a lookalike identity.
6. The invoice ZIP SHA-256 extracted from the message matched the standalone ZIP evidence file.
7. Static review of the JavaScript found a single `WScript.Echo` statement and no network, process-creation, file-write, obfuscation or credential-access behaviour.

## Attachment Evidence

```text
Invoice_INV-88421.zip
Size: 194 bytes
SHA-256: c422f08c2dd655422a10c07a7fc2003fd289d97c9c31a08529f126ff61ad5465

Contains:
Invoice_INV-88421.js
Size: 54 bytes
SHA-256: 75e36eab35c99f782389aa577544849f27f5fa960c49c005152f8d0f6720bdae
```

Static strings:

```text
WScript.Echo("Invoice INV-88421 - payment reminder");
```

## Impact Assessment

No evidence in the reviewed files demonstrated credential submission, successful account takeover, malware execution, persistence or data exfiltration.

The risk came from the social-engineering patterns, lookalike identities and the potential for user interaction.

## Recommended SOC Actions

- quarantine confirmed suspicious messages
- search for additional recipients using sender, subject, URL, attachment name and hashes
- block confirmed malicious indicators
- determine whether users clicked, replied, opened attachments or submitted credentials
- reset passwords and revoke sessions where credentials were entered
- review identity logs
- review endpoint telemetry where attachment execution is suspected
- escalate to IR if compromise or malicious execution is confirmed

## Final Assessment

The investigation demonstrated how sender authentication, branding, user context and attachment evidence must be considered together.

Passing SPF/DKIM/DMARC was not treated as proof of legitimacy, and suspicious attachment types were not treated as proof of malware without technical evidence.
