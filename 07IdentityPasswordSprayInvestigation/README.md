# Investigation 07 | Microsoft Entra ID Password Spray Alert

**Date:** 29 October 2026  
**Case:** SOC LAB 007  
**Status:** Completed lab investigation  
**Severity:** High priority for identity review, compromise not confirmed  
**Evidence:** Synthetic Entra sign in log export  
**Tools:** Python, CSV review, Microsoft Sentinel KQL, Entra sign in event field analysis

## Alert received

The alert showed repeated failed Microsoft 365 sign ins from one address against several accounts. I needed to determine whether these failures were isolated user mistakes or a wider authentication pattern.

I analysed a controlled training export shaped like Entra sign in logs. This case does not use a real tenant or customer records. All addresses and users are fictional or reserved examples.

## What I found

| Check | Result |
| :--- | :--- |
| Suspected source | `203.0.113.45` |
| First event | 09:02:10 UTC |
| Last event from suspect source | 09:10:05 UTC |
| Accounts targeted | 12 |
| Invalid password events | 24 |
| Failed MFA events | 1 |
| Successful events from suspect source | 0 |
| Separate success from another source | 1 |

## Investigation

### 1. Establish the scope

I started with the address rather than a single username. The log export showed 12 accounts receiving invalid password results, followed by a second pass against the same accounts.

The events were spread across multiple users, not concentrated on one person. That made a password spray hypothesis worth testing. I cannot prove the same password was used because password values are never present in the logs.

### 2. Read the result codes

All 24 password failures returned `50126`. At 09:10:05 UTC, the same IP generated `500121` for `maya@contoso.example`. That means the MFA step failed or was not completed.

I marked that account for extra review. A failed MFA step may warrant checking whether primary authentication succeeded, but the flat export is not enough to confirm credential disclosure or a successful session.

### 3. Search for access after the attempts

I specifically looked for sign in successes from the suspicious IP. There were none in the supplied data.

At 09:15:19 UTC, Maya had a successful sign in from `198.51.100.44`, a different source. I kept that event separate. A different address alone does not prove the activity was legitimate. I would need the user's confirmation, device details and the usual sign in history.

### 4. Reproduce the evidence

I used Python to count unique users, result codes and successful sign ins by source.

~~~bash
python3 analysis.py
~~~

The raw rows are in [signins.csv](./evidence/signins.csv), and the summary is in [analysis.txt](./evidence/analysis.txt). The script also prints the source file SHA256 digest to support evidence checking.

I wrote [Sentinel queries](./queries.kql) to repeat the same pivots in a live workspace if the data were ingested there. I did not run these queries against a real tenant.

## Evidence and notes

| File | Purpose |
| :--- | :--- |
| [Raw identity events](./evidence/signins.csv) | Complete training dataset |
| [Analysis output](./evidence/analysis.txt) | Observed counts and findings |
| [Analysis script](./analysis.py) | Repeatable review and file digest |
| [KQL investigations](./queries.kql) | Source scoping and wider account hunt |
| [Case note](./incident_report.md) | Timeline, verdict and handover |

## Analyst decision

**Verdict:** Activity consistent with password spraying. No successful session from the suspicious source was established by the supplied evidence.

**Escalation:** Identity team review required for the MFA event. I would keep the alert open while checking authentication details, later sign ins and account risk. I would not record a password reset, IP block or token revocation as completed because none occurred in the lab.

**MITRE ATT&CK:** T1110.003 Password Spraying is a relevant behaviour mapping. The logs do not show which passwords were attempted.

## Next actions

1. Retrieve detailed authentication steps and device context for the Maya MFA event.
2. Review all successful sign ins and session activity after the alert.
3. Expand the search to any other source targeting the same accounts.
4. Validate known VPN and company proxy addresses before recommending an IP block.
5. Recommend session revocation and a credential reset if exposure is established.
6. Carry the exact account, time and correlation IDs into the SOC ticket.

The key point for me was separating a suspicious sign in pattern from actual proof of compromise.
