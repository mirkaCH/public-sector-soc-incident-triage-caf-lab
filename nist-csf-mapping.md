# NCSC CAF Mapping

## Overview

This section maps the simulated incident and recommended improvements to the UK NCSC Cyber Assessment Framework (CAF). The mapping is high-level and intended for portfolio / learning purposes.

---

## CAF Objective A — Managing Security Risk

The incident involves a privileged service account used for remote logon. This indicates a need to review identity governance, privileged access management, and risk ownership.

Suggested improvements:

- Maintain an inventory of privileged accounts.
- Assign clear ownership for service accounts.
- Review whether service accounts require interactive or RDP logon rights.
- Implement periodic access reviews.
- Document risk decisions for privileged account usage.

---

## CAF Objective B — Protecting Against Cyber Attack

The incident suggests the need for stronger protective controls around authentication, RDP, and privileged access.

Suggested improvements:

- Enforce MFA for privileged and remote access.
- Restrict RDP access through VPN or allowlisting.
- Disable interactive logon for service accounts unless required.
- Apply least privilege.
- Harden PowerShell execution controls.
- Use endpoint protection and attack surface reduction rules.

---

## CAF Objective C — Detecting Cyber Security Events

The incident demonstrates the need for effective monitoring of authentication activity, privileged access, and suspicious process execution.

Detection evidence:

- Event ID 4625 identified repeated failed logons.
- Event ID 4624 identified successful logon.
- Event ID 4672 identified privileged access.
- Event ID 4688 identified suspicious command execution.

Suggested improvements:

- Build SIEM rules for failed logon thresholds.
- Detect successful logon after repeated failures.
- Monitor privileged account logons.
- Alert on encoded PowerShell and execution policy bypass.
- Maintain documented triage playbooks.

---

## CAF Objective D — Minimising the Impact of Cyber Security Incidents

A structured response process is required to contain and investigate suspected account compromise.

Suggested improvements:

- Define account compromise response procedures.
- Maintain containment playbooks.
- Reset credentials and revoke active sessions.
- Search for lateral movement.
- Preserve endpoint evidence.
- Produce incident reports and lessons learned.
- Improve detection and prevention controls after review.
