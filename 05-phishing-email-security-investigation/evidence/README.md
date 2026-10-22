# Evidence

This folder contains the message and attachment evidence used for the phishing investigation.

## Files

- `case1-microsoft365-password-expiration.eml`
- `case2-invoice-zip.eml`
- `case3-ceo-bec.eml`
- `case4-okta-security-alert.eml`
- `case5-docusign-review.eml`
- `Invoice_INV-88421.zip`
- `Invoice_INV-88421.js`
- `evidence-manifest.csv`
- `header-analysis.txt`
- `attachment-analysis.json`
- `attachment-static-analysis.txt`

## Attachment Verification

The ZIP extracted from `case2-invoice-zip.eml` produced:

```text
SHA-256:
c422f08c2dd655422a10c07a7fc2003fd289d97c9c31a08529f126ff61ad5465

MD5:
d085fee01f400459915d1575bfac5dcc
```

This matches the standalone `Invoice_INV-88421.zip` file in this folder.

## Static Analysis

`attachment-static-analysis.txt` records the workstation-style command output for:

- file type identification
- SHA-256
- SHA-1
- MD5
- ZIP archive listing
- strings review

`header-analysis.txt` contains parsed message metadata including:

- From
- Reply-To
- Return-Path
- Message-ID
- Received source IP
- Authentication-Results
