# Phishing and Email Security Investigation

**Status:** Completed  
**Lab type:** Simulated phishing triage and incident reporting  
**Focus:** Email security, IOC extraction, verdict writing and SOC response planning

## Overview

This lab focused on one of the most common SOC queues: suspicious email reports.

Five simulated phishing cases were reviewed using a repeatable analyst workflow. Each case was assessed for sender/domain risk, URL or attachment indicators, impersonation, social engineering techniques, likely attacker objective, final verdict and recommended SOC action.

No production users or systems were affected. The email samples were intentionally simulated for safe investigation practice.

## Cases Reviewed

| # | Scenario | Severity | Verdict / Likely Goal |
|---|---|---|---|
| 1 | Microsoft 365 password expiration | Medium | Confirmed phishing / credential harvesting |
| 2 | Past-due invoice ZIP attachment | High | Suspected phishing / possible malware delivery |
| 3 | CEO "quick favor" | Medium | BEC / executive impersonation |
| 4 | Fake Okta security alert | Medium | Confirmed phishing / credential harvesting |
| 5 | Fake DocuSign document review | Medium | Confirmed phishing / credential harvesting |

[View detailed cases](./phishing-cases.md)

## Analyst Workflow

For each reported message:

1. Review subject, display name and sender address.
2. Compare sender and reply-to domains.
3. Inspect visible and actual link destinations.
4. Review attachment name/type without opening it.
5. Identify impersonated brand or person.
6. Identify urgency, fear, financial pressure or other social-engineering cues.
7. Extract IOCs.
8. Determine likely attacker objective.
9. Choose verdict and severity.
10. Recommend containment, user follow-up and escalation actions.

## IOC Summary

Examples extracted from the simulated cases:

```text
support@micros0ft-security[.]com
micros0ft-security[.]com
micros0ft-security-login[.]com
hxxps://micros0ft-security-login[.]com/verify

billing@secure-invoices-payments[.]com
secure-invoices-payments[.]com
Invoice_INV-88421.zip

ceo.company.office@gmail[.]com
Subject: Quick favor needed

alerts@okta-verification[.]com
okta-verification[.]com
hxxps://okta-verification[.]com/security-check

notification@docusign-secure[.]net
docusign-secure[.]net
hxxps://docusign-secure[.]net/document/review?id=88421
```

[View IOC and response summary](./ioc-summary.md)

## Key Findings

- Credential harvesting was the most common suspected objective.
- Lookalike domains were central to several cases.
- Brand impersonation was used against Microsoft 365, Okta and DocuSign themes.
- The invoice case relied on an attachment rather than a URL.
- The BEC case contained neither a link nor attachment but was still malicious by intent.
- HTTPS alone does not make a URL trustworthy.
- Display names are weaker evidence than the actual sender/domain.
- Analyst conclusions should distinguish confirmed evidence from likely attacker intent.

## Response Actions Practiced

- block malicious sender/domain/URL indicators
- search for additional recipients
- quarantine or remove matching messages
- ask whether the user clicked, replied, opened an attachment or submitted credentials
- reset password and revoke sessions if credentials were entered
- review identity sign-in logs
- review endpoint telemetry if an attachment was opened or executed
- escalate to incident response for malware execution, account compromise or financial fraud

## Evidence Limitation

These were simulated email scenarios, so the lab did not contain production message headers, real sender infrastructure or live reputation/sandbox results.

I therefore did not invent SPF, DKIM, DMARC, Message-ID, sending-IP or sandbox findings. In a real investigation those would be collected and added to the case before finalising the verdict.

## Incident Report

[View the final incident report](./incident-report.md)

## What I Learned

- Phishing can be malicious without a link.
- Phishing can be malicious without an attachment.
- HTTPS does not prove a site is safe.
- Lookalike domains and sender-domain mismatch are strong indicators.
- ZIP attachments deserve careful handling but are not automatically malicious.
- BEC often begins with a simple conversation starter before the financial request appears.
- SOC analysts should document evidence and qualified conclusions rather than assumptions.
