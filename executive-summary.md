// Microsoft Sentinel / KQL Queries

// Failed Logons Against Privileged Account
SecurityEvent
| where EventID == 4625
| where Account has "svc_admin_backup"
| summarize FailedAttempts=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Account, IpAddress, Computer
| where FailedAttempts >= 5
| order by FailedAttempts desc

// Successful RDP Logons
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| order by TimeGenerated asc

// Privileged Logons
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Computer, Account, Activity
| order by TimeGenerated asc

// Suspicious PowerShell Execution
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine has_any ("-enc", "EncodedCommand", "ExecutionPolicy Bypass", "-NoProfile")
| project TimeGenerated, Computer, Account, Process, CommandLine
| order by TimeGenerated asc

// Reconnaissance Commands
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("whoami", "net user", "net localgroup", "hostname", "whoami /priv")
| project TimeGenerated, Computer, Account, Process, CommandLine
| order by TimeGenerated asc

// Timeline Reconstruction
SecurityEvent
| where Computer == "NBC-WIN-034"
| where Account has "svc_admin_backup"
| project TimeGenerated, EventID, Computer, Account, IpAddress, Process, CommandLine, Activity
| order by TimeGenerated asc
