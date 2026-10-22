# Phishing Case Notes

All cases below were simulated for safe SOC investigation practice.

## Case 1 - Microsoft 365 Password Expiration

**Subject:** Urgent: Password Expiration Notice  
**Sender:** IT Support <support@micros0ft-security[.]com>  
**URL:** hxxps://micros0ft-security-login[.]com/verify  
**Attachment:** None  
**Severity:** Medium  
**Verdict:** Confirmed phishing / credential harvesting attempt

### Analysis

The sender and URL use Microsoft-themed lookalike domains, including `micros0ft` with a zero in place of the letter "o". The message creates urgency by claiming the password expires today and threatens account suspension.

The likely objective is credential harvesting, potentially including MFA/session information if the user submits credentials.

### SOC Actions

- Block sender domain and URL.
- Search for other recipients.
- Quarantine matching messages.
- Confirm whether the user clicked or entered credentials.
- Reset password and revoke sessions if credentials were submitted.
- Review identity sign-in activity.

---

## Case 2 - Past-Due Invoice ZIP

**Subject:** Invoice INV-88421 Past Due  
**Sender:** Billing Department <billing@secure-invoices-payments[.]com>  
**Attachment:** Invoice_INV-88421.zip  
**URL:** None  
**Severity:** High  
**Verdict:** Suspected phishing / possible malware delivery

### Analysis

The sender uses a generic invoice/payment-themed domain rather than a known vendor domain. The message uses financial urgency and directs the user toward a ZIP attachment.

No attachment hash was present in the source scenario, so the file was not claimed as confirmed malware.

### SOC Actions

- Instruct the user not to open the attachment.
- Quarantine/remove the message.
- Search for other recipients by sender, subject and attachment name.
- Hash/sandbox the file in an approved environment if available.
- Check endpoint telemetry for evidence of opening or execution.
- Escalate to IR if execution occurred.

---

## Case 3 - CEO / Executive Impersonation

**Subject:** Quick favor needed  
**Sender:** CEO <ceo.company.office@gmail[.]com>  
**URL:** None  
**Attachment:** None  
**Severity:** Medium  
**Verdict:** Business Email Compromise / executive impersonation attempt

### Analysis

The message claims to be from the CEO but originates from a Gmail address. It asks the recipient to reply quickly while stating the sender is unavailable to talk.

This is consistent with a BEC conversation starter where the financial or sensitive-data request may follow after the victim replies.

### SOC Actions

- Quarantine/remove the email.
- Search for other recipients and similar wording.
- Block sender address where appropriate.
- Ask whether the user replied or shared information.
- Notify the real executive/security team if impersonation is confirmed.
- Monitor for follow-up attempts.

---

## Case 4 - Fake Okta Security Alert

**Subject:** Unusual Sign-In Attempt Blocked  
**Sender:** Security Alert <alerts@okta-verification[.]com>  
**URL:** hxxps://okta-verification[.]com/security-check  
**Severity:** Medium  
**Verdict:** Confirmed phishing / credential harvesting

### Analysis

The sender and URL use an Okta-themed lookalike domain. The message uses fear and urgency by claiming an unusual sign-in and threatening lockout/suspension.

The likely objective is credential or MFA/session-token theft through a fake verification workflow.

### SOC Actions

- Block sender domain and URL.
- Search for additional recipients.
- Quarantine matching messages.
- Ask whether the user clicked or entered credentials.
- Reset credentials and revoke sessions if required.
- Review identity-provider sign-in logs.

---

## Case 5 - Fake DocuSign Document Review

**Subject:** Document Ready for Signature  
**Sender:** DocuSign Notification <notification@docusign-secure[.]net>  
**URL:** hxxps://docusign-secure[.]net/document/review?id=88421  
**Severity:** Medium  
**Verdict:** Confirmed phishing / credential harvesting

### Analysis

The sender and destination use a DocuSign-themed lookalike domain rather than a normal DocuSign domain. The message attempts to borrow trust from a document-signing service and pressures the user to review/sign before expiry.

The use of HTTPS would not make the destination trustworthy.

### SOC Actions

- Block sender domain and URL.
- Search for other recipients.
- Quarantine matching emails.
- Confirm whether the user interacted with the link.
- Reset credentials/revoke sessions if submitted.
- Review sign-in logs for anomalous activity.
