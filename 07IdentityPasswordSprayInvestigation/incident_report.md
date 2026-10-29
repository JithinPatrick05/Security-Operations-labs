# SOC Case Note 007

**Review date:** 29 October 2026  
**Alert type:** Multiple user authentication failures  
**Source:** Controlled synthetic identity event export  
**Triage:** High priority  
**Status:** Analysis completed, response action not performed

## Timeline

| Time UTC | Recorded evidence | Analyst note |
| :--- | :--- | :--- |
| 09:02:10 | First `50126` from `203.0.113.45` | Start of suspicious sequence |
| 09:04:00 | Twelfth user receives a failure | Broad account scope |
| 09:08:10 | Second pass begins | Same users targeted again |
| 09:10:00 | Twenty fourth invalid password result | Repeated failure pattern |
| 09:10:05 | `500121` for Maya | MFA failure or incomplete challenge |
| 09:15:19 | Success from `198.51.100.44` | Different source, not attacker success |

## Evidence summary

I reviewed 26 sign in records. Of these, 25 were from the suspected source. There were 24 invalid password results across 12 separate accounts and one later MFA failure. There was no successful sign in from the suspected IP in the file.

The account spread suggests an automated password spray pattern. The MFA event is significant enough to escalate, but I cannot conclude that the attacker knew the password without the full authentication sequence.

## Evidence limitations

This is synthetic evidence, not a customer incident. The file does not contain full conditional access details, authentication steps, risk detections, device identity, session telemetry or user validation. The IP addresses belong to documentation networks and must not be treated as real threat indicators.

## Verdict and handover

**Verdict:** Suspected password spray, successful compromise unconfirmed.

**Response proposed:** Validate the affected account with identity operations, inspect MFA method details, review sign in activity after the event and confirm permitted source addresses. If compromise is subsequently supported, recommend credential reset, token revocation and source restrictions in line with the organisation's incident process.

**Handover:** Alert involves 12 accounts and 24 invalid password responses from one source, followed by a failed MFA challenge for one account. There is no observed success from that source. Identity owner review remains outstanding.
