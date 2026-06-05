# MITRE ATT&CK Mapping

## Summary

The simulated activity maps to multiple MITRE ATT&CK techniques related to initial access attempts, valid account use, command execution, discovery, and possible preparation for lateral movement.

---

| Tactic | Technique | Technique ID | Evidence |
|---|---|---:|---|
| Credential Access / Initial Access | Brute Force | T1110 | Multiple failed logons against `svc_admin_backup` |
| Defense Evasion | Valid Accounts | T1078 | Successful logon using a privileged account |
| Lateral Movement | Remote Services: RDP | T1021.001 | Successful RDP logon, Logon Type 10 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell execution |
| Defense Evasion | Obfuscated Files or Information | T1027 | Encoded PowerShell command |
| Discovery | System Owner/User Discovery | T1033 | `whoami` command |
| Discovery | System Information Discovery | T1082 | `hostname` command |
| Discovery | Account Discovery | T1087 | `net user` command |
| Discovery | Permission Groups Discovery | T1069 | `net localgroup administrators` |

---

## Analyst Notes

The most concerning sequence is:

```text
failed logons → successful privileged RDP logon → special privileges → encoded PowerShell → discovery commands
```

This sequence may indicate successful credential compromise followed by post-compromise reconnaissance.
