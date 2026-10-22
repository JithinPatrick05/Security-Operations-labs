# Detection Notes

These are detection ideas taken from the completed JPtest1 investigation.

## 1. PowerShell executing from Public directories

Review PowerShell where the command line contains both a user-writable path and suspicious execution options.

Example conditions:

~~~text
Image ends with \powershell.exe
AND CommandLine contains \Users\Public\
AND CommandLine contains -ExecutionPolicy Bypass
~~~

This should be treated as a triage signal rather than a standalone malicious verdict.

## 2. PowerShell network activity

Look for Sysmon Event ID 3 where:

~~~text
Image = powershell.exe
Initiated = true
DestinationPort = 443
~~~

Prioritise cases where the destination is uncommon for the environment or where connections repeat at regular intervals.

## 3. Registry Run key modification

Review Event ID 13 affecting:

~~~text
\Software\Microsoft\Windows\CurrentVersion\Run\
~~~

Increase priority when the modifying process is a scripting engine such as PowerShell and the value points to a user-writable directory.

## 4. Correlated sequence

The highest-value detection idea from this lab is the sequence rather than one event:

~~~text
PowerShell process creation
        ->
DNS query
        ->
Outbound HTTPS connection
        ->
Run key modification
        ->
Repeated outbound connections
~~~

This is a better investigation lead than alerting on PowerShell execution alone.

## False-positive considerations

Legitimate activity can produce parts of the same pattern, including:

- software deployment scripts
- administrative PowerShell
- monitoring tools
- update agents
- logon scripts

Useful context includes:

- user and host role
- signer/reputation of the script
- parent process
- script location
- destination reputation
- frequency of connections
- whether the Run key is expected
