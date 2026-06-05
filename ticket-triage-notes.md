# Public Sector Incident Scenario

## Scenario Title

Suspicious Privileged Account Activity in a Public Sector Environment

---

## Background

A fictional UK local council uses Windows endpoints and Active Directory for staff authentication. The organisation has a small internal IT and security team responsible for monitoring authentication activity, endpoint alerts, and security events.

The SOC monitoring system generates an alert after several failed logon attempts are observed against a privileged account. Shortly afterwards, a successful remote logon occurs from the same external IP address. Additional events show special privileges assigned and suspicious PowerShell execution.

---

## Organisation Context

**Organisation:** Northbridge Local Council  
**Sector:** UK Public Sector  
**Environment:** Windows endpoint and authentication monitoring  
**Affected Host:** `NBC-WIN-034`  
**Affected Account:** `svc_admin_backup`  
**Suspicious Source IP:** `185.203.118.44`  
**Initial Alert Type:** Repeated failed logons followed by successful privileged logon

---

## Initial SOC Alert

**Ticket ID:** SOC-PS-2026-001  
**Alert Name:** Multiple Failed Logons Followed by Successful Privileged Logon  
**Severity:** High  
**Status:** Open  
**Assigned Analyst:** Miroslawa Chatys  
**Detection Source:** Windows Security Events  
**Time Window:** 09:12–09:42 UTC

---

## Analyst Objectives

1. Review authentication events.
2. Identify failed and successful logon patterns.
3. Check whether a privileged account was involved.
4. Review process creation activity.
5. Identify possible indicators of compromise.
6. Build a timeline.
7. Map relevant activity to MITRE ATT&CK.
8. Map security considerations to NCSC CAF and NIST CSF.
9. Write a structured SOC incident report.
10. Recommend containment and escalation actions.

---

## Evidence Provided

The simulated event dataset is located at:

```text
logs/public-sector-security-events.csv
```

The dataset includes Event ID 4625, 4624, 4672, 4688, and 4634.
