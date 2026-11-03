# SOC Incident Report | SOC LAB 009

## Summary

A high-risk Entra ID sign-in to `finance.manager@lab.example` was followed by unauthorised external mailbox forwarding.

The account normally authenticated from Sydney on `FINLT07`. A successful sign-in from `203.0.113.44` in Amsterdam occurred sixteen minutes after the last known-good Sydney sign-in. Within minutes, the same source IP created an inbox forwarding rule and configured mailbox-level forwarding to `archive.notice@example.net`.

## Classification

**Incident type:** Cloud account compromise  
**Severity:** High  
**Confidence:** High  
**Affected user:** finance.manager@lab.example  
**Suspicious IP:** 203.0.113.44  
**External destination:** archive.notice@example.net

## Confirmed findings

- Known-good Sydney sign-ins were present before the alert.
- The suspicious IP generated failed attempts before one successful sign-in.
- The successful overseas sign-in had no recognised device ID and was marked high risk.
- The same source IP created an external inbox forwarding rule.
- The same source IP configured mailbox-level forwarding to the same address.
- The source IP also attempted two other finance-related accounts, but neither successfully authenticated.
- The forwarding mechanisms were removed.
- Active sessions were revoked.
- The password was reset.
- A later sign-in from the known Sydney device was successful.

## Assessment

The location change, device mismatch, successful high-risk sign-in and immediate mailbox forwarding activity support confirmed unauthorised account use.

The available evidence does not identify the original access method, so I did not attribute the incident to password theft, token theft or MFA fatigue without supporting telemetry.

## MITRE ATT&CK

- T1078 Valid Accounts
- T1114.003 Email Forwarding Rule

## Containment

1. Removed the suspicious inbox rule.
2. Cleared mailbox-level forwarding.
3. Revoked active sessions.
4. Forced a password reset.
5. Validated reauthentication from the known user device.
6. Searched for the suspicious IP and external forwarding address across the available tenant evidence.

## Handover

The active compromise was contained. Follow-up should focus on message trace, MFA registration review, endpoint review, and additional tenant-wide hunting.

Two other finance accounts were targeted by the same source IP but did not show successful authentication in the evidence reviewed.

> Portfolio note: controlled SOC lab using representative enterprise telemetry.
