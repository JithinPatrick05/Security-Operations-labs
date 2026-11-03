# Investigation 09 | Entra ID Account Compromise and External Mailbox Forwarding

**Date:** 4 November 2026  
**Case:** SOC LAB 009  
**Severity:** High  
**Status:** Closed after containment and validation  
**Affected account:** finance.manager@lab.example  
**Primary tools:** Microsoft Sentinel, Entra ID sign-in logs, Microsoft 365 Unified Audit Log, KQL, Python, MITRE ATT&CK

## Alert

I received a high-priority identity alert for a finance user after a successful sign-in from an unfamiliar overseas location was followed by a new external mailbox forwarding rule.

The account normally authenticated from Sydney using the registered device `FINLT07`. At 08:21 UTC the same account successfully authenticated from `203.0.113.44` in Amsterdam with no recognised device ID. Three minutes later, the mailbox created an inbox rule called `InvoicesArchive` forwarding mail to `archive.notice@example.net`. A mailbox-level forwarding address was then added to the same external recipient.

I treated the alert as a possible account compromise but did not assume the conclusion from the alert alone. My investigation focused on confirming whether the sign-in was legitimate, linking the mailbox changes to the same session, checking whether other users were affected, and containing the account without losing the evidence trail.

## What I did

### 1. Built the account baseline

I started with seven days of Entra ID sign-in history for the user.

The normal pattern was consistent: Sydney-based sign-ins, the registered device `FINLT07`, and successful MFA. The last normal sign-in before the alert was at 08:05:41 UTC from `198.51.100.24`.

That gave me a known-good reference before reviewing the abnormal activity.

### 2. Reviewed the suspicious authentication

The first event from `203.0.113.44` occurred at 08:18:33 UTC and failed.

A second attempt at 08:19:11 UTC reached MFA and was denied.

At 08:21:02 UTC the same IP recorded a successful sign-in. The device ID was blank and Entra ID marked the sign-in risk as high.

The account had been used successfully from Sydney only sixteen minutes earlier. The timing and location made legitimate physical travel impossible, so I treated the Amsterdam session as unauthorised pending confirmation from the user.

I did not claim how the attacker obtained access because the available telemetry did not prove credential theft, token theft or social engineering.

### 3. Correlated Microsoft 365 audit activity

I pivoted from the successful sign-in into the Microsoft 365 audit log.

At 08:24:09 UTC the account created a new inbox rule named `InvoicesArchive`.

The rule forwarded mail externally to:

`archive.notice@example.net`

At 08:25:31 UTC the account also configured mailbox-level forwarding to the same address.

Both actions came from the same source IP as the suspicious sign-in. The timing and source correlation made the mailbox changes part of the same incident rather than unrelated configuration activity.

### 4. Checked whether the forwarding was legitimate

I reviewed the available change context and found no approved request for external forwarding on the finance mailbox.

The destination address was external to the organisation and had no business relationship recorded in the lab context.

I therefore classified both forwarding changes as unauthorised.

### 5. Scoped the suspicious source IP

I searched all sign-in records for `203.0.113.44`.

The same IP had also attempted:

- `ap.manager@lab.example`
- `payroll@lab.example`

Both attempts failed.

This changed the case from a single-user anomaly into a broader targeted identity event against finance accounts. I raised the priority of the investigation but did not mark the other two accounts as compromised because there was no successful authentication.

### 6. Scoped the forwarding destination

I searched the Microsoft 365 audit data for `archive.notice@example.net`.

The external address appeared only against the affected finance mailbox.

I also searched for other new inbox rules and mailbox forwarding changes created in the same period. No additional affected mailbox was identified.

### 7. Checked the known endpoint

The user's normal device was `FINLT07`.

The supplied endpoint context did not show evidence that the laptop itself generated the Amsterdam session or created the forwarding rules.

I kept endpoint compromise as unresolved instead of assuming the attack originated from the user's workstation.

### 8. Contained the account

Once the sign-in and mailbox changes were correlated, I completed the containment sequence:

1. Removed the `InvoicesArchive` inbox rule.
2. Cleared the mailbox-level forwarding address.
3. Revoked active sessions.
4. Forced a password reset.
5. Required the user to authenticate again from the known device.
6. Continued monitoring for the suspicious IP and forwarding address.

I preserved the timeline and audit events before closing the case.

### 9. Validated recovery

At 08:44:52 UTC the user authenticated again from the normal Sydney IP using `FINLT07`.

The reviewed period showed no further successful sign-in from `203.0.113.44`, no recreated forwarding rule, and no additional external forwarding configuration.

I closed the active containment phase after confirming the account had returned to its expected sign-in pattern.

## Timeline

| UTC | Event | Analyst significance |
|---|---|---|
| 08:05:41 | Normal Sydney sign-in | Known-good baseline |
| 08:18:33 | Failed Amsterdam sign-in | First abnormal authentication |
| 08:19:11 | MFA denied | Continued attempt from same IP |
| 08:21:02 | Successful Amsterdam sign-in | High-risk sign-in with unknown device |
| 08:22:18 | AP manager account attempted | Scope expanded to another finance account |
| 08:23:05 | Payroll account attempted | Same IP targets third finance account |
| 08:24:09 | New inbox rule created | External forwarding begins |
| 08:25:31 | Mailbox forwarding configured | Second persistence/collection path |
| 08:33:42 | Inbox rule removed | Containment |
| 08:34:15 | Mailbox forwarding cleared | Containment |
| 08:35:06 | Active sessions revoked | Identity containment |
| 08:38:27 | Password reset completed | Credential recovery |
| 08:44:52 | Known-device sign-in | Recovery validation |

## MITRE ATT&CK mapping

### T1078 | Valid Accounts

A legitimate user account was successfully used from an anomalous source and location.

The evidence proves unauthorised use of the account but does not prove how access was obtained.

### T1114.003 | Email Forwarding Rule

The suspicious session created both an inbox forwarding rule and mailbox-level forwarding to an external recipient.

This mapping is directly supported by the Microsoft 365 audit records.

## Analyst decision

**Verdict:** Confirmed unauthorised cloud account access with external mailbox forwarding.

**Severity:** High

I kept the severity high because the affected account belonged to finance, the successful sign-in was geographically inconsistent and high-risk, and the account immediately created two external forwarding mechanisms.

I did not classify this as confirmed data loss because the evidence available to me did not prove which messages, if any, were successfully forwarded before containment.

## Follow-up actions

- Review message trace to identify whether mail was forwarded externally.
- Review authentication method changes and registered MFA methods.
- Review the user's endpoint for browser/session theft or credential exposure.
- Continue tenant-wide hunting for `203.0.113.44` and `archive.notice@example.net`.
- Review the two additional finance accounts targeted by the same IP.
- Monitor the affected account for recurrence after session revocation and password reset.
- Consider alerting on new external forwarding rules for privileged or finance mailboxes.

## Evidence used

- [Entra ID sign-in evidence](./evidence/signins.csv)
- [Microsoft 365 audit evidence](./evidence/office_activity.csv)
- [Sentinel KQL](./queries.kql)
- [Python correlation script](./analysis.py)
- [Analysis output](./evidence/analysis.txt)
- [SOC incident report](./incident_report.md)

> Portfolio note: this investigation was completed in a controlled SOC lab using representative enterprise telemetry.
