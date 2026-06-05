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
