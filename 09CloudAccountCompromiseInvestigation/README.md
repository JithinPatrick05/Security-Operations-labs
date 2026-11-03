# Investigation 09 | Entra ID Account Compromise and External Mailbox Forwarding

**Date:** 4 November 2026  
**Case:** 009  
**Severity:** High  
**Status:** Closed after containment and validation  
**Affected account:** Finance Manager  
**Primary tools:** Microsoft Sentinel, Entra ID sign in logs, Microsoft 365 Unified Audit Log, KQL, Python, MITRE ATT&CK

## Alert

I picked up a high priority identity alert involving a finance mailbox.

The user had a successful Entra ID sign in from Amsterdam shortly after a normal sign in from Sydney. The Amsterdam session had no recognised device ID and Entra ID marked the risk as high.

A few minutes after that session became successful, the same source created a new inbox rule called `InvoicesArchive` and configured mailbox forwarding to an external address.

I did not close the alert based on the impossible travel style signal alone. I checked the normal sign in pattern, the source activity, the mailbox audit trail, other accounts touched by the same source, and the recovery activity before making a decision.

## Investigation

### 1. I checked the user's normal sign in pattern

I reviewed seven days of Entra ID activity for the Finance Manager account.

The account normally signed in from Sydney using `FINLT07` with successful MFA. The last normal sign in before the alert was at 08:05:41 UTC.

That gave me a baseline for the user's usual location, device and authentication behaviour.

### 2. I reviewed the Amsterdam activity

The first Amsterdam attempt was recorded at 08:18:33 UTC and failed.

A second attempt at 08:19:11 UTC reached MFA and was denied.

At 08:21:02 UTC the same source recorded a successful sign in. The device ID was blank and the risk level was high.

The user had authenticated successfully from Sydney only sixteen minutes earlier. That made normal physical travel impossible.

At that point I treated the Amsterdam session as unauthorised pending user validation.

I did not claim how access was obtained because the evidence did not prove whether the initial access came from a stolen password, a session token, social engineering or another method.

### 3. I moved into the Microsoft 365 audit trail

I filtered the Unified Audit Log around the successful Amsterdam session.

At 08:24:09 UTC the Finance Manager account created an inbox rule called `InvoicesArchive`.

The rule forwarded messages to an external mailbox.

At 08:25:31 UTC mailbox forwarding was also configured to the same external destination.

The source matched the suspicious Entra ID session and the changes occurred within minutes of the successful sign in.

That correlation was the main reason I treated the mailbox changes as part of the same incident.

### 4. I checked whether the forwarding had a business reason

I reviewed the available change context and found no approved request for external forwarding on the mailbox.

I also checked whether the external destination appeared elsewhere in the audit evidence.

It only appeared against the affected finance mailbox.

That made a legitimate forwarding change unlikely.

### 5. I scoped the source across other users

I searched the Entra ID records for the same public source.

The source also attempted the AP Manager account and the Payroll account.

Both attempts failed.

This was important because it showed that the activity was not limited to one username.

I increased the priority of the case but did not mark the other accounts as compromised because there was no successful authentication for either one.

### 6. I checked for other forwarding changes

I searched Microsoft 365 audit events for new inbox rules, redirects and mailbox forwarding changes during the same period.

No second mailbox was identified in the evidence reviewed.

I also searched for the same external forwarding destination across the audit data and found no other user tied to it.

### 7. I checked the user's known device

The known device for the user was `FINLT07`.

The evidence I had did not show that the Amsterdam session came from that device.

It also did not prove the laptop itself was compromised.

I left endpoint compromise as unresolved and kept it as a follow up item instead of making an assumption that was not supported by the logs.

### 8. I contained the account

Once I had enough evidence to confirm the session and forwarding activity were connected, I moved to containment.

1. I removed the `InvoicesArchive` inbox rule.
2. I cleared the mailbox forwarding address.
3. I revoked the active sessions for the user.
4. I forced a password reset.
5. I required the user to authenticate again from the known device.
6. I continued monitoring the source and forwarding destination.

I preserved the relevant sign in and audit records before completing the clean up.

### 9. I validated the account after containment

At 08:44:52 UTC the user authenticated again from Sydney using `FINLT07`.

I checked the period after containment for another successful Amsterdam session, a recreated inbox rule and another mailbox forwarding change.

None were present in the reviewed evidence.

That was enough for me to close the active containment phase while leaving message trace, MFA registration review and endpoint review as follow up work.

## Timeline

**08:05:41 UTC**  
Normal Sydney sign in from the known device.

**08:18:33 UTC**  
First failed Amsterdam sign in.

**08:19:11 UTC**  
Second attempt reaches MFA and is denied.

**08:21:02 UTC**  
Successful Amsterdam sign in with no recognised device ID.

**08:22:18 UTC**  
The same source attempts the AP Manager account and fails.

**08:23:05 UTC**  
The same source attempts the Payroll account and fails.

**08:24:09 UTC**  
`InvoicesArchive` is created on the Finance Manager mailbox.

**08:25:31 UTC**  
Mailbox forwarding is configured to the same external destination.

**08:33:42 UTC**  
The inbox rule is removed.

**08:34:15 UTC**  
Mailbox forwarding is cleared.

**08:35:06 UTC**  
Active sessions are revoked.

**08:38:27 UTC**  
The password reset is completed.

**08:44:52 UTC**  
The user signs in again from Sydney using the known device.

## MITRE ATT&CK mapping

### T1078 | Valid Accounts

A legitimate user account was successfully used from an abnormal source and location.

The evidence supports unauthorised use of the account. It does not prove how access to the account was obtained.

### T1114.003 | Email Forwarding Rule

The suspicious session created an inbox forwarding rule and mailbox forwarding to an external recipient.

This mapping is directly supported by the Microsoft 365 audit activity.

## My decision

**Verdict:** Confirmed unauthorised cloud account access with external mailbox forwarding.

**Severity:** High

I kept the case at high severity because the affected user worked in finance, the successful sign in was high risk and geographically inconsistent, and the account immediately created two forwarding methods.

I did not record confirmed data loss because I did not have evidence showing which messages, if any, were delivered to the external mailbox before containment.

## Follow up work

1. Review message trace to determine whether mail was forwarded externally.
2. Review authentication method changes and registered MFA methods.
3. Review the user's endpoint for browser session theft or credential exposure.
4. Continue searching the tenant for the same source and forwarding destination.
5. Review the AP Manager and Payroll accounts in more detail.
6. Monitor the affected account for recurrence.
7. Review whether external forwarding should be restricted or alerted on for finance and privileged mailboxes.

## Evidence

[Entra ID sign in evidence](./evidence/signins.csv)  
[Microsoft 365 audit evidence](./evidence/office_activity.csv)  
[Sentinel KQL](./queries.kql)  
[Python correlation script](./analysis.py)  
[Analysis output](./evidence/analysis.txt)  
[SOC incident report](./incident_report.md)
