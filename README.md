Public Sector SOC Incident Triage & NCSC CAF Mapping Lab

Author: Miroslawa Chatys
Target role: Junior SOC Analyst / Cyber Security Analyst / Public Sector Cyber Security Support Analyst
Focus: Ticket triage, Windows Event Log analysis, suspicious authentication activity, incident reporting, MITRE ATT&CK mapping, NCSC CAF alignment, NIST CSF mapping, SPL/KQL-style queries, and SOC escalation documentation.

Project Summary

This GitHub-ready project demonstrates how a Junior SOC Analyst can triage a public sector security ticket involving suspicious authentication activity, privileged account use, and suspicious PowerShell execution on a Windows endpoint.

The project uses simulated logs and structured documentation to show a realistic SOC workflow: reviewing alert evidence, identifying suspicious behaviour, building a timeline, extracting indicators of compromise, mapping activity to security frameworks, documenting findings, and escalating the incident for deeper investigation.

The project is designed to demonstrate both technical investigation skills and an understanding of UK public sector cyber security expectations, including NCSC CAF and NIST CSF alignment.

Scenario Overview

A fictional UK local council receives a security alert showing repeated failed logon attempts against a privileged service account. Shortly afterwards, the same account successfully logs in through RDP from the same external source IP address.

After the successful logon, the logs show:

Special privileges assigned to the account.
Encoded PowerShell execution.
Reconnaissance commands.
Local administrator group enumeration.
Privilege discovery activity.

The activity is treated as suspicious and escalated as a possible privileged account compromise.

Skills Demonstrated
Skill Area	Evidence in This Project
Ticket triage	Ticket notes, severity assessment, evidence review, escalation decision
Windows log analysis	Event IDs 4624, 4625, 4672, 4688, and 4634
Incident investigation	Timeline analysis, IOC summary, risk assessment
Detection logic	SPL and KQL-style queries
Threat mapping	MITRE ATT&CK mapping
Public sector alignment	NCSC CAF and NIST CSF mapping
Reporting	SOC incident report and executive summary
Key Windows Event IDs
Event ID	Meaning	Investigation Value
4625	Failed logon	Identifies failed authentication attempts
4624	Successful logon	Confirms account access
4672	Special privileges assigned	Indicates privileged account activity
4688	New process created	Shows command and process execution
4634	Account logoff	Helps complete the user session timeline
Repository Structure
public-sector-soc-incident-triage-caf-lab/
├── README.md
├── scenario/
│   └── public-sector-incident-scenario.md
├── logs/
│   └── public-sector-security-events.csv
├── analysis/
│   ├── ticket-triage-notes.md
│   ├── timeline-analysis.md
│   ├── ioc-summary.md
│   └── risk-assessment.md
├── queries/
│   ├── splunk-queries.spl
│   └── kql-queries.kql
├── mapping/
│   ├── mitre-attack-mapping.md
│   ├── ncsc-caf-mapping.md
│   └── nist-csf-mapping.md
├── reports/
│   ├── soc-incident-report.md
│   └── executive-summary.md
└── screenshots/
    ├── ticket-triage-summary.png
    ├── incident-timeline.png
    ├── suspicious-powershell-evidence.png
    ├── ioc-summary.png
    ├── mitre-attack-mapping.png
    ├── ncsc-caf-mapping.png
    ├── nist-csf-mapping.png
    └── detection-queries.png
Investigation Workflow
Alert received
→ Ticket triage
→ Evidence review
→ Timeline creation
→ IOC identification
→ MITRE ATT&CK mapping
→ NCSC CAF / NIST CSF mapping
→ Risk assessment
→ Incident report
→ Escalation recommendation
Key Findings

The simulated evidence indicates:

Repeated failed logon attempts against a privileged account.
Successful RDP logon from the same suspicious source IP.
Special privileges assigned after logon.
Encoded PowerShell execution.
Reconnaissance commands executed after authentication.
Possible privileged account compromise.

The activity should be treated as suspicious and escalated for further investigation.

Screenshots
Ticket Triage Summary




Incident Timeline




Suspicious PowerShell Evidence




IOC Summary




MITRE ATT&CK Mapping




NCSC CAF Mapping




NIST CSF Mapping




Detection Query Evidence




Detection Queries

Detection logic is provided in:

queries/splunk-queries.spl
queries/kql-queries.kql

The queries cover:

Failed logon bursts.
Successful RDP logons.
Privileged account logons.
Suspicious PowerShell execution.
Reconnaissance command execution.
Timeline reconstruction.
Framework Mapping

This project includes mapping to:

MITRE ATT&CK
NCSC Cyber Assessment Framework
NIST Cybersecurity Framework

The purpose is to demonstrate both technical SOC investigation skills and awareness of governance, assurance, and public sector cyber security expectations.

Reports

The project includes two report formats:

reports/soc-incident-report.md
reports/executive-summary.md

The SOC incident report provides technical findings, evidence, MITRE mapping, recommended actions, and escalation rationale.

The executive summary provides a shorter business-level overview of the incident, business risk, key findings, and recommended management actions.

Portfolio Value

This project supports applications for roles such as:

Junior SOC Analyst
SOC Analyst Tier 1
Cyber Security Analyst
Security Monitoring Analyst
Cyber Security Consultant Graduate / Junior
Public Sector Cyber Security Support Analyst

It demonstrates practical investigation capability while also showing awareness of frameworks relevant to UK public sector cyber security work.

Disclaimer

This is a simulated, scenario-based lab created for learning and portfolio purposes. No real organisation, user, IP address, or incident is represented.
