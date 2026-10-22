# IOC and Response Summary

## Indicators

| Case | Indicator | Type |
|---|---|---|
| Microsoft 365 | support@micros0ft-security[.]com | Sender |
| Microsoft 365 | micros0ft-security[.]com | Domain |
| Microsoft 365 | micros0ft-security-login[.]com | URL domain |
| Microsoft 365 | hxxps://micros0ft-security-login[.]com/verify | URL |
| Invoice | billing@secure-invoices-payments[.]com | Sender |
| Invoice | secure-invoices-payments[.]com | Domain |
| Invoice | Invoice_INV-88421.zip | Attachment filename |
| CEO/BEC | ceo.company.office@gmail[.]com | Sender |
| CEO/BEC | Quick favor needed | Subject |
| Okta | alerts@okta-verification[.]com | Sender |
| Okta | okta-verification[.]com | Domain |
| Okta | hxxps://okta-verification[.]com/security-check | URL |
| DocuSign | notification@docusign-secure[.]net | Sender |
| DocuSign | docusign-secure[.]net | Domain |
| DocuSign | hxxps://docusign-secure[.]net/document/review?id=88421 | URL |

## Response Matrix

| Finding | Immediate Action | Follow-up |
|---|---|---|
| Malicious sender/domain | Block/quarantine | Search other recipients |
| Credential-phishing link | Remove message, block URL | Confirm user interaction, review sign-ins |
| Credentials entered | Password reset | Revoke sessions, investigate account activity |
| ZIP attachment | Prevent opening / quarantine | Hash and sandbox safely |
| Attachment executed | Isolate/investigate endpoint | Escalate to IR |
| Executive impersonation | Remove/block sender | Notify target/executive/security |
| Financial action taken | Escalate immediately | Finance/fraud/IR process |

## Safe Handling

- Do not click suspicious links directly.
- Do not open suspicious attachments on the analyst workstation.
- Defang URLs in documentation.
- Use approved reputation and sandbox tooling when available.
- Preserve original message/header data in real cases.
