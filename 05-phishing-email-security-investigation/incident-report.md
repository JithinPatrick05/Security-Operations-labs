# Final Phishing Incident Report

## Executive Summary

Five simulated phishing reports were investigated using a SOC analyst workflow.

The cases covered:

1. Microsoft 365 credential phishing
2. Invoice-themed attachment delivery
3. CEO / executive impersonation BEC
4. Fake Okta security alert phishing
5. Fake DocuSign document-review phishing

The investigation focused on sender/domain analysis, URL and attachment indicators, impersonation, social-engineering technique, IOC extraction, likely attacker goal, verdict and response recommendations.

## Scope

The scope was limited to five simulated email reports. No production mailboxes, user accounts or endpoints were impacted.

## Findings

- Credential harvesting was the most common likely objective.
- Typosquatting and lookalike domains were used to appear legitimate.
- Urgency and fear appeared in several cases.
- The BEC case demonstrated that a malicious email does not require a link or attachment.
- The invoice case demonstrated attachment-based risk.
- Brand trust was abused in Microsoft 365, Okta and DocuSign themes.
- HTTPS was treated as transport encryption, not a trust indicator.

## Impact

No real-world impact occurred because the cases were simulations.

Potential production impact from similar cases could include:

- credential theft
- MFA/session theft
- account takeover
- malware execution
- initial access
- financial fraud
- vendor/payment fraud
- sensitive information disclosure

## Recommended SOC Response

- Block confirmed malicious sender/domain/URL indicators.
- Search the mail environment for additional recipients.
- Quarantine or remove matching messages.
- Determine whether users clicked, replied, opened attachments or entered credentials.
- Reset passwords and revoke sessions where credentials were submitted.
- Review sign-in telemetry.
- Review endpoint telemetry where attachments may have been executed.
- Escalate to incident response for confirmed execution, account compromise or financial loss.

## Final Assessment

The exercise demonstrated phishing triage, IOC extraction, credential-phishing analysis, attachment-risk assessment, BEC identification, analyst verdict writing and response planning.

The scenarios were simulated, so conclusions were limited to the evidence supplied in each scenario rather than invented email-header or reputation data.
