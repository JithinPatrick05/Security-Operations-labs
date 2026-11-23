# Evidence notes

The files in this folder belong to a controlled home-lab email review carried out on 23 November 2026.

- **message.eml** is the prepared case message, not an export from a real customer's inbox.
- **analysis.txt** and **findings.json** were produced by running analysis.py against message.eml.
- **header-review.svg** is a readable visual summary of those parser findings. It is not a screenshot of Microsoft Sentinel, Microsoft Defender or the VirtualSOC interface.
- The .test domain names and 192.0.2.57 are reserved lab identifiers. They are not live threat indicators.
- The authentication results are values supplied in the message header. No cryptographic DKIM verification, live SPF lookup or DMARC policy verification was performed.
- No URL was opened and no tenant telemetry, user click evidence, sign-in records or live email delivery actions were available.

Re-run from the case directory using Python 3: python3 analysis.py

SHA-256 of message.eml:
f9b86a0f7b655c23a5a7063ba22b15621af48ef5010ee2de36ea94502eb83982
