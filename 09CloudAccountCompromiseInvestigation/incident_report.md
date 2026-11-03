# SOC Incident Report | Case 009

## Summary

I investigated a high risk Entra ID sign in involving a finance mailbox.

The user normally authenticated from Sydney on `FINLT07`. A successful Amsterdam sign in occurred sixteen minutes after the last known Sydney session. Within minutes, the same source created an inbox forwarding rule and configured mailbox forwarding to an external recipient.

## Classification

**Incident type:** Cloud account compromise  
**Severity:** High  
**Confidence:** High  
**Affected user:** Finance Manager  
**Known device:** FINLT07  
**Suspicious source:** Public IP redacted  
**External forwarding destination:** Redacted

## Confirmed findings

1. I confirmed normal Sydney sign in activity before the alert.
2. I found two failed Amsterdam attempts before one successful authentication.
3. The successful Amsterdam session had no recognised device ID and was marked high risk.
4. The same source created an external inbox forwarding rule.
5. The same source configured mailbox forwarding to the same external destination.
6. The source attempted two additional finance accounts but did not authenticate successfully to either one.
7. I removed both forwarding mechanisms.
8. I revoked the user's active sessions.
9. I completed a password reset.
10. I validated a later sign in from the known Sydney device.

## Assessment

The timing, location change, device mismatch and mailbox audit activity support confirmed unauthorised account use.

I did not attribute the initial access method because the evidence did not prove whether the session resulted from a stolen password, token theft, social engineering or another method.

I also did not record confirmed data loss because message trace evidence was outside the dataset reviewed for this case.

## MITRE ATT&CK

**T1078 Valid Accounts**

**T1114.003 Email Forwarding Rule**

## Containment completed

1. Removed the suspicious inbox rule.
2. Cleared mailbox forwarding.
3. Revoked active sessions.
4. Forced a password reset.
5. Validated a new session from the user's known device.
6. Searched the available tenant evidence for the same source and forwarding destination.

## Handover

The active compromise was contained.

I left message trace, MFA registration review and endpoint review as follow up actions.

The same source attempted the AP Manager and Payroll accounts. Neither account showed a successful authentication in the evidence I reviewed.

