# SOC Incident Report

## Improved Initial Assessment

Between 09:12 and 09:16 UTC, five failed logon attempts were observed against the privileged account `svc_admin_backup` from source IP `185.203.118.44` targeting host `NBC-WIN-034`.

At 09:18 UTC, a successful RDP logon occurred using the same account, same source IP, and same host. At 09:19 UTC, special privileges were assigned to the session.

At 09:21 UTC, `powershell.exe` was executed with an `EncodedCommand` parameter. This was followed by reconnaissance commands including `whoami /groups`, `net user`, and `ipconfig /all`.

Based on the sequence of failed authentication attempts, successful privileged RDP access, special privileges, suspicious PowerShell execution, and discovery activity, this activity should be treated as a High Severity incident and escalated to Tier 2 SOC / Incident Response.

## Validation Steps

To validate whether this activity represents a true security incident, the following checks should be performed:

1. Confirm that the failed logons, successful RDP logon, special privileges event, encoded PowerShell execution, and reconnaissance commands are linked to the same account, source IP, host, and timeline.
2. Verify whether source IP `185.203.118.44` is expected or known for this environment.
3. Confirm whether account `svc_admin_backup` should be used interactively through RDP.
4. Check whether the RDP logon at `09:18 UTC` was approved or expected.
5. Review whether the PowerShell command with `EncodedCommand` can be explained as legitimate administrative activity.
6. Check for additional authentication attempts from the same source IP.
7. Search for related activity from the same account across other hosts.
8. Look for signs of lateral movement, persistence, or additional command execution.

## Containment and Blast Radius Reduction

If the activity is confirmed as suspicious or unauthorized, the following containment actions are recommended:

1. Reset or temporarily disable the affected account `svc_admin_backup`.
2. Revoke active sessions linked to the affected account.
3. Isolate host `NBC-WIN-034` from the network if malicious activity is confirmed.
4. Block source IP `185.203.118.44` at the firewall or relevant security control.
5. Review authentication activity from the same source IP across the environment.
6. Search for the same account activity on other hosts.
7. Check for lateral movement indicators.
8. Preserve relevant logs and evidence for Tier 2 SOC / Incident Response.
9. Escalate the case to Tier 2 SOC / Incident Response for deeper investigation.

---

# Splunk SPL Queries

## Failed Logons Against Privileged Account

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 Account_Name="svc_admin_backup"
| stats count min(_time) as first_seen max(_time) as last_seen by Account_Name, Source_Network_Address, host
| where count >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

## Successful RDP Logon After Failed Attempts

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10
| table _time, host, Account_Name, Source_Network_Address, Logon_Type
| sort _time
```

## Privileged Logon Events

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4672
| table _time, host, Account_Name, Privileges
| sort _time
```

## Suspicious PowerShell Execution

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| search New_Process_Name="*powershell.exe*" 
| search Process_Command_Line="*-enc*" OR Process_Command_Line="*EncodedCommand*" OR Process_Command_Line="*ExecutionPolicy Bypass*"
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
```

## Reconnaissance Commands

```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| search Process_Command_Line="*whoami*" OR Process_Command_Line="*net user*" OR Process_Command_Line="*net localgroup*" OR Process_Command_Line="*hostname*"
| table _time, host, Account_Name, New_Process_Name, Process_Command_Line
```

## Timeline Reconstruction

```spl
index=windows sourcetype=WinEventLog:Security host="NBC-WIN-034" Account_Name="svc_admin_backup"
| table _time, EventCode, host, Account_Name, Source_Network_Address, New_Process_Name, Process_Command_Line
| sort _time
```

---

## Query Output Evidence

This section was added after community feedback to show the query logic together with supporting output from the simulated dataset.

The project uses a simulated CSV dataset created for learning and portfolio practice. It is not based on real company data or confidential logs.

### Dataset Used

Dataset file: `simulated-security-events.csv`

The dataset contains fictional Windows-style security events used for SOC triage practice.

Included Event IDs:

- `4625` - Failed logon attempts
- `4624` - Successful RDP logon
- `4672` - Special privileges assigned
- `4688` - Process creation
- `4634` - Logoff

### Failed Logons - Event ID 4625

Command-line validation:

```bash
grep "4625" simulated-security-events.csv

```

Observed output:

```text
2026-06-04 09:12:03,4625,svc_admin_backup,185.203.118.44,NBC-WIN-034,10,,,Failed logon attempt against privileged service account,Medium
2026-06-04 09:13:11,4625,svc_admin_backup,185.203.118.44,NBC-WIN-034,10,,,Failed logon attempt against privileged service account,Medium
2026-06-04 09:14:27,4625,svc_admin_backup,185.203.118.44,NBC-WIN-034,10,,,Failed logon attempt against privileged service account,Medium
2026-06-04 09:15:42,4625,svc_admin_backup,185.203.118.44,NBC-WIN-034,10,,,Failed logon attempt against privileged service account,Medium
2026-06-04 09:16:58,4625,svc_admin_backup,185.203.118.44,NBC-WIN-034,10,,,Failed logon attempt against privileged service account,Medium
```

Analyst note:

Five failed logon attempts were observed between `09:12` and `09:16 UTC` against the privileged account `svc_admin_backup` from source IP `185.203.118.44` targeting host `NBC-WIN-034`.

### Successful RDP Logon - Event ID 4624

Command-line validation:

```bash
grep "4624" simulated-security-events.csv
```

Observed output:

```text
2026-06-04 09:18:21,4624,svc_admin_backup,185.203.118.44,NBC-WIN-034,10,,,Successful RDP logon after multiple failed attempts,High
```

Analyst note:

A successful RDP logon occurred at `09:18 UTC` using the same account, same source IP, and same host.

### Special Privileges Assigned - Event ID 4672

Command-line validation:

```bash
grep "4672" simulated-security-events.csv
```

Observed output:

```text
2026-06-04 09:19:06,4672,svc_admin_backup,185.203.118.44,NBC-WIN-034,,,,Special privileges assigned to new logon,High
```

Analyst note:

Special privileges were assigned shortly after the successful RDP logon.

### Encoded PowerShell Execution - Event ID 4688

Command-line validation:

```bash
grep -i "EncodedCommand" simulated-security-events.csv
```

Observed output:

```text
2026-06-04 09:21:44,4688,svc_admin_backup,185.203.118.44,NBC-WIN-034,,powershell.exe,"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",Encoded PowerShell execution observed,High
```

Analyst note:

PowerShell was executed with the `EncodedCommand` parameter after the successful RDP logon. This is suspicious because encoded PowerShell can be used to hide command activity.

### Reconnaissance Commands

Command-line validation:

```bash
grep -i "whoami\|net user\|ipconfig" simulated-security-events.csv
```

Observed output:

```text
2026-06-04 09:22:10,4688,svc_admin_backup,185.203.118.44,NBC-WIN-034,,cmd.exe,"cmd.exe /c whoami /groups",Reconnaissance command executed,High
2026-06-04 09:23:18,4688,svc_admin_backup,185.203.118.44,NBC-WIN-034,,cmd.exe,"cmd.exe /c net user",Local user enumeration command executed,High
2026-06-04 09:24:31,4688,svc_admin_backup,185.203.118.44,NBC-WIN-034,,cmd.exe,"cmd.exe /c ipconfig /all",Network reconnaissance command executed,Medium
```

Analyst note:

Reconnaissance commands were observed after the successful privileged logon. This supports escalation because the activity may indicate post-authentication discovery.

### Summary of Query Evidence

The evidence shows the following sequence:

1. Five failed logon attempts against `svc_admin_backup`
2. Successful RDP logon from the same source IP
3. Special privileges assigned to the session
4. Encoded PowerShell execution
5. Reconnaissance commands after logon

This sequence supports a High Severity decision and escalation to Tier 2 SOC / Incident Response.


