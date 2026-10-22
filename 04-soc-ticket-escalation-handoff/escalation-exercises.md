# Escalation Writing Exercises

These exercises show how the same analyst evidence would be handed to L2 / IR if the surrounding production context increased the risk.

They are escalation-writing practice, not three additional confirmed malicious incidents.

## 1. Multiple Failed Logons from Unknown User

**Risk:** Medium to High depending on frequency, source, targeted account and follow-on success.

### Summary

Multiple failed logons on `DESKTOP-3JKM5O9` from an unknown or unexpected user could indicate password guessing, password spraying, account enumeration or unauthorised access attempts.

### Evidence to Review

- Windows Security Event ID 4625
- TargetUserName
- LogonType
- IpAddress
- WorkstationName
- Status / SubStatus
- FailureReason

### Recommended L2 Actions

- Confirm whether the attempted username is valid.
- Review source IP and logon type.
- Search whether the same source attempted additional usernames.
- Look for Event ID 4624 successful logons after the failures.
- Determine whether the target is privileged.
- Consider source blocking or account protection if brute-force behaviour is confirmed.

---

## 2. curl.exe Launched from PowerShell

**Risk:** Medium by default, High if suspicious content is downloaded or executed.

### Summary

`curl.exe` launched from PowerShell is not malicious by itself but can be used to retrieve payloads or contact external infrastructure.

### Evidence

```text
Host: DESKTOP-3JKM5O9
User: DESKTOP-3JKM5O9\mmajeed
Command: C:\Windows\system32\curl.exe https://github.com
Parent: powershell.exe
Sysmon Event ID: 1
```

### Recommended L2 Actions

- Validate user authorisation.
- Review execution frequency.
- Check destination reputation.
- Identify whether content was downloaded.
- Review file creation and follow-on execution.
- Correlate with Sysmon Event ID 3 network connections and Event ID 22 DNS queries.

---

## 3. Local Administrators Group Enumeration

**Risk:** Medium by default.

### Summary

A user executed a command to enumerate members of the local Administrators group.

### Evidence

```text
Command: net1.exe localgroup administrators
Parent: net.exe localgroup administrators
Host: DESKTOP-3JKM5O9
User: DESKTOP-3JKM5O9\mmajeed
Sysmon Event ID: 1
```

### Recommended L2 Actions

- Validate whether the user was expected to enumerate the group.
- Review frequency and surrounding discovery activity.
- Check Event ID 4720 for account creation.
- Check Event ID 4732 for additions to local groups.
- Review nearby successful logons and PowerShell activity.

### Escalate Further If

- new user creation follows
- a user is added to Administrators
- suspicious remote access is observed
- the activity comes from an unexpected account
- additional discovery or privilege-related behaviour follows
