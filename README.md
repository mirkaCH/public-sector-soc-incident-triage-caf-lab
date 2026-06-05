Public Sector SOC Incident Triage & NCSC CAF Mapping Lab

Author: Miroslawa Chatys
Project Type: Scenario-Based SOC Analyst / Public Sector Cyber Security Lab
Focus Areas: Ticket triage, Windows Event Log analysis, incident reporting, MITRE ATT&CK mapping, NCSC CAF alignment, NIST CSF mapping, SPL/KQL-style queries.

1. Project Overview

This project is a scenario-based SOC Analyst lab designed around a realistic public sector cyber security investigation.

The lab simulates a suspicious authentication and endpoint activity incident affecting a fictional UK public sector organisation. The goal is to demonstrate structured SOC investigation skills, including alert triage, evidence review, timeline analysis, IOC identification, detection logic, escalation, and reporting.

This project also includes mapping to frameworks commonly relevant to UK public sector cyber security work:

NCSC Cyber Assessment Framework (CAF)
NIST Cybersecurity Framework (CSF)
MITRE ATT&CK

2. Scenario Summary

A fictional local council receives a security alert indicating repeated failed logon attempts against a privileged account, followed by a successful remote logon and suspicious PowerShell execution.

The SOC analyst must review the available Windows Security logs, identify suspicious activity, document findings, assess risk, and recommend escalation and containment actions.

3. Skills Demonstrated
Skill Area	Evidence in This Project
Alert triage	Ticket notes, severity assessment, escalation decision
Windows log analysis	Event IDs 4624, 4625, 4672, 4688, 4634
Incident investigation	Timeline, IOC summary, evidence review
Detection engineering basics	SPL and KQL-style queries
Threat mapping	MITRE ATT&CK mapping
Public sector alignment	NCSC CAF and NIST CSF mapping
Reporting	SOC incident report and executive summary

5. Repository Structure
   
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
    
7. Investigation Workflow
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

9. Key Findings
The simulated evidence indicates:
Repeated failed logon attempts against a privileged account.
Successful remote logon from the same suspicious source IP.
Special privileges assigned to the account after logon.
Encoded PowerShell execution.
Reconnaissance commands executed from the compromised session.

The activity should be treated as suspicious and escalated for further investigation.

7. Screenshots
Ticket Triage Summary

Incident Timeline

Suspicious PowerShell Evidence

IOC Summary

MITRE ATT&CK Mapping

NCSC CAF Mapping

NIST CSF Mapping

Detection Query Evidence

8. Detection Queries

Detection logic is provided in:

queries/splunk-queries.spl

queries/kql-queries.kql

The queries cover:

Failed logon bursts

Successful RDP logons.
Privileged account logons.
Suspicious PowerShell execution.
Reconnaissance command execution.
Timeline reconstruction.

9. Framework Mapping
This project includes mapping to:
MITRE ATT&CK
NCSC Cyber Assessment Framework
NIST Cybersecurity Framework

The purpose is to demonstrate both technical SOC investigation skills and awareness of governance, assurance, and public sector cyber security expectations.

10. Reports

The project includes two report formats:

reports/soc-incident-report.md
reports/executive-summary.md

The SOC incident report provides technical findings, evidence, MITRE mapping, and recommended actions.

The executive summary provides a shorter business-level overview of the incident, risk, and recommended management actions.

11. Portfolio Value

This project supports applications for roles such as:

Junior SOC Analyst
SOC Analyst Tier 1
Cyber Security Analyst
Security Monitoring Analyst
Cyber Security Consultant Graduate / Junior
Public Sector Cyber Security Support Analyst

It demonstrates practical investigation capability while also showing awareness of frameworks relevant to UK public sector cyber security work.

12. Disclaimer

This is a simulated, scenario-based lab created for learning and portfolio purposes. No real organisation, user, IP address, or incident is represented.
