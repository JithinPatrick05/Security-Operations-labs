# IOC and Evidence Summary

## Message Evidence

| Case | Message SHA-256 | Received IP | SPF | DKIM | DMARC |
|---|---|---|---|---|---|
| Microsoft 365 | `611161189f5d913b0ceb3fef0c75dd952425c13b6200c5deba6996883807156b` | 198.51.100.24 | Fail | None | Fail |
| Invoice ZIP | `525ba4a691ad929e9594bc516bb706294074b16fd9b41c609db4f2dff37c53b0` | 203.0.113.44 | Pass | Pass | Pass |
| CEO / BEC | `82834891c9caa5b3bda07a698b568ec7c3ff59860e0e1c7b5a6e428627b5dec7` | 209.85.220.41 | Pass | Pass | Pass |
| Okta | `1c1d0d690eae8a8d3f970a0b2b78001acb138c7ec8d214c481814e991590cb43` | 192.0.2.91 | Pass | None | Pass |
| DocuSign | `5d2686ba242ca20adff77b28b9b8a3b3c074bc2263cbefc49d351f89ddf2f833` | 198.51.100.88 | Pass | Pass | Pass |

## Sender / URL Indicators

| Case | Indicator | Type |
|---|---|---|
| Microsoft 365 | support@micros0ft-security.example | Sender |
| Microsoft 365 | micros0ft-security.example | Domain |
| Microsoft 365 | micros0ft-security-login.example | URL domain |
| Invoice | billing@secure-invoices-payments.example | Sender |
| Invoice | secure-invoices-payments.example | Domain |
| CEO/BEC | ceo.company.office@gmail.com | Sender |
| CEO/BEC | Quick favor needed | Subject |
| Okta | alerts@okta-verification.example | Sender |
| Okta | okta-verification.example | Domain |
| DocuSign | notification@docusign-secure.example | Sender |
| DocuSign | docusign-secure.example | Domain |

## Attachment Indicators

```text
Invoice_INV-88421.zip
MD5: d085fee01f400459915d1575bfac5dcc
SHA-1: 019b4bc678db084438020610a89ddaaff75633d6
SHA-256: c422f08c2dd655422a10c07a7fc2003fd289d97c9c31a08529f126ff61ad5465

Invoice_INV-88421.js
MD5: 6b45fb571ec9c96ecc0599a5e40cfd60
SHA-1: 120c305e5f2383d59a2aa159f95fd189230e9571
SHA-256: 75e36eab35c99f782389aa577544849f27f5fa960c49c005152f8d0f6720bdae
```

## Response Matrix

| Finding | Immediate Action | Follow-up |
|---|---|---|
| Lookalike sender/domain | Quarantine/block indicator | Search additional recipients |
| Credential-phishing URL | Block URL | Confirm user interaction and review sign-ins |
| Credentials entered | Reset password | Revoke sessions and investigate account activity |
| ZIP/script attachment | Quarantine | Hash, inspect archive and check endpoint telemetry |
| Attachment executed | Investigate endpoint | Escalate to IR if suspicious activity follows |
| Executive impersonation | Remove message | Notify target/executive/security |
| Financial action taken | Escalate immediately | Finance/fraud/IR process |
