# Investigation 11 | Email authentication mismatch and disguised Microsoft 365 link

**23 November 2026** · **Home lab / VirtualSOC workflow** · **Medium** · **Email security triage**

## What triggered the review

The case email looked like a Microsoft 365 document notification. It was addressed to Finance, mentioned the Q4 supplier register and asked the recipient to act before 4 pm.

I wanted to know whether the sender was who it claimed to be and where the document link would actually take a user. I worked from the raw email rather than judging it by the display name.

## What stood out

1. The visible From address used file-access.test, but the Return-Path and Message-ID used message-relay.test.
2. The message recorded SPF pass and DKIM pass for message-relay.test. Neither authenticated domain aligned with the visible sender, and the recorded DMARC result was fail.
3. The HTML link displayed the Microsoft login URL but pointed to review.file-access.test.
4. No attachment was present.
5. There were no click, login or device events in the available case evidence, so I did not mark an account as compromised.

## My checks

I parsed the From, Reply-To, Return-Path, Message-ID, Received and Authentication-Results headers. I compared domains rather than simply treating a pass or fail value as the final verdict. I then extracted the real HTML href and compared it with the text a user would see. Finally, I checked the MIME parts and calculated a SHA-256 hash of the original message.

The local parser was executed against the case email. It returned SPF alignment false, DKIM alignment false, recorded DMARC fail, one disguised link and zero attachments.

## My assessment

**Verdict:** Suspicious link-based phishing attempt in the lab case  
**Priority:** Medium  
**Confirmed compromise:** None  
**Reason:** Sender authentication was reported for a different domain and the message hid a non-Microsoft destination behind a Microsoft login link.

I would preserve the .eml, check message trace and other recipients, and then review Safe Links and identity activity if I had access to an authorised Microsoft 365 environment. I wouldn't reset an account or claim data loss without evidence of user interaction and compromise.

This case does not contain genuine VirtualSOC console screenshots or production telemetry. The saved visual is a summary generated from the local parser output, and the Microsoft Defender queries are prepared for future validation, not presented as executed results.

## Evidence and files

- [Full investigation notes](./incident_report.md)
- [Original .eml](./evidence/message.eml)
- [Offline parser](./analysis.py)
- [Recorded parser output](./evidence/analysis.txt)
- [Structured findings](./evidence/findings.json)
- [Evidence summary visual](./evidence/header-review.svg)
- [Defender XDR hunting queries](./queries.kql)
- [Evidence provenance](./evidence/README.md)

Run the investigation again:

~~~bash
python3 analysis.py
~~~

The script requires Python 3 standard libraries only and does not connect to any external service.

**MITRE ATT&CK:** [T1566.002, Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/).

**References:** [Microsoft Defender EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table), [EmailUrlInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table), [UrlClickEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table).
