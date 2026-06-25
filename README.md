# Incident Response Playbooks
 
A collection of professional-grade incident response playbooks and case studies built as part of a cybersecurity home lab portfolio. Each playbook follows the **NIST SP 800-61 Rev. 2** incident handling framework and includes a realistic simulated case study tied to a specific threat scenario and industry vertical.
 
> **Disclaimer:** All organizations, individuals, incidents, and data in these documents are entirely fictional and created for training and portfolio demonstration purposes only. No real classified, PHI, PII, or sensitive data is contained herein.
 
---
 
## Playbooks
 
| # | Playbook | Threat Type | Industry | Regulatory Framework |
|---|----------|-------------|----------|----------------------|
| 01 | [Phishing / Credential Theft](#01--phishing--credential-theft) | Spear-phishing, session hijack | Defense Contractor | DFARS 252.204-7012, CMMC |
| 02 | [Malware / Ransomware Precursor](#02--malware--ransomware-precursor) | Macro dropper, Cobalt Strike Beacon | Healthcare | HIPAA Breach Notification Rule |
| 03 | [Insider Threat / Data Exfiltration](#03--insider-threat--data-exfiltration) | Pre-resignation data theft, DLP evasion | Financial Services | SEC Reg S-P, FINRA Rule 4370 |
 
---
 
## 01 — Phishing / Credential Theft
 
**Document:** `playbooks/01_Phishing_IR_Playbook_and_Case_Study.pdf`  
**Fictional Org:** Meridian Defense Systems, LLC (defense contractor)  
**Case Study:** Operation Credential Harvest (INC-2024-0047)
 
### Scenario
A spear-phishing email impersonating the MDS IT Help Desk delivered a credential-harvesting page hosted on a lookalike domain. The victim entered credentials, triggering a session hijack from an Eastern European IP within 47 seconds. A custom Wazuh impossible-travel rule detected the anomalous login and the account was locked within 23 minutes of phish delivery.
 
### Key Technical Concepts Covered
- Email header analysis (SPF, DKIM, DMARC failures)
- Credential harvesting page anatomy and TLS certificate abuse
- Custom Wazuh detection rule for impossible travel (Rule 100201)
- Azure AD session revocation and account lockout procedures
- DFARS 252.204-7012 72-hour mandatory breach reporting
- CMMC incident handling obligations for defense industrial base (DIB) organizations
### Detection Rule Highlight
```xml
<rule id="100201" level="12">
  <if_sid>18127</if_sid>
  <field name="data.srcip" negate="yes">^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)</field>
  <field name="data.win.eventdata.logonType">3</field>
  <description>Impossible travel: O365 login from non-RFC1918 IP within 5 min of domestic session</description>
  <group>authentication_success,anomaly,credential_theft,</group>
</rule>
```
 
---
 
## 02 — Malware / Ransomware Precursor
 
**Document:** `playbooks/02_Malware_IR_Playbook_and_Case_Study.pdf`  
**Fictional Org:** Lakewood Regional Medical Center  
**Case Study:** Operation Phantom Script (INC-2024-0091)
 
### Scenario
A macro-enabled Excel attachment triggered a two-stage attack: a VBA macro dropped a PowerShell stager, which pulled a Cobalt Strike Beacon from a compromised WordPress redirector. The beacon established a C2 channel, executed a Mimikatz variant in memory, and began mapping network shares — reaching a file server and encrypting 14 files before EDR network isolation cut the connection. Wazuh detected the encoded PowerShell execution within 4 minutes.
 
### Key Technical Concepts Covered
- Two-stage malware delivery: macro dropper → drive-by second stage
- Cobalt Strike Beacon malleable C2 profiles and domain fronting
- Process hollowing into svchost.exe
- PowerShell encoded command detection (MITRE T1059.001)
- Ransomware file extension detection (MITRE T1486)
- HIPAA four-factor breach risk assessment
- HHS ransomware presumption-of-breach guidance (2016)
### Detection Rules Highlight
```xml
<rule id="100301" level="13">
  <if_sid>60612</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-e(nc|ncodedcommand)\s+[A-Za-z0-9+/]{20,}</field>
  <description>PowerShell encoded command execution detected — possible stager or obfuscation</description>
  <group>attack,execution,T1059.001,</group>
</rule>
 
<rule id="100302" level="15">
  <if_sid>60103</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">\.(locked|encrypted|enc|crypt)$</field>
  <description>Ransomware indicator: file renamed with known encryption extension</description>
  <group>attack,impact,ransomware,T1486,</group>
</rule>
```
 
---
 
## 03 — Insider Threat / Data Exfiltration
 
**Document:** `playbooks/03_Insider_Threat_IR_Playbook_and_Case_Study.pdf`  
**Fictional Org:** Crestline Capital Advisors, LLC (registered investment adviser)  
**Case Study:** Operation Silent Exit (INC-2024-0118)
 
### Scenario
A Senior Portfolio Analyst exfiltrated 847 files over 15 days prior to voluntary resignation, transferring proprietary equity factor models and client contact data to personal cloud storage and a USB drive. The activity went undetected in real time — a weekly DLP digest report surfaced the anomaly. UEBA retrospective analysis showed deviations of 1,240%+ above the subject's 90-day baseline. Legal coordinated a litigation hold and covert forensic imaging before a timed separation revoked all access simultaneously.
 
### Key Technical Concepts Covered
- DLP alert analysis and baseline deviation detection
- UEBA behavioral anomaly quantification
- USB mass storage detection with device serial number logging (MITRE T1025)
- Legal hold and chain of custody requirements for insider threat investigations
- Covert evidence collection and timed separation coordination
- SEC Regulation S-P safeguards rule and breach assessment
- FINRA SAR evaluation and 17 CFR §275.204-2 records retention (7 years)
- Principle of least privilege failure analysis
### Detection Rules Highlight
```xml
<rule id="100401" level="10">
  <if_sid>7200</if_sid>
  <field name="win.eventdata.driveName" type="pcre2">(?i)(removable|usb|mass storage)</field>
  <description>USB mass storage device connected to workstation</description>
  <group>policy_violation,data_loss,T1025,</group>
</rule>
 
<rule id="100402" level="12">
  <if_sid>100401</if_sid>
  <same_field>win.eventdata.driveLetter</same_field>
  <timeframe>600</timeframe>
  <frequency>50</frequency>
  <description>Bulk file copy to removable media: 50+ files within 10-minute window</description>
  <group>policy_violation,data_exfiltration,T1025,</group>
</rule>
```
 
---
 
## Framework Alignment
 
All playbooks follow the **NIST SP 800-61 Rev. 2** incident response lifecycle:
 
```
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident Activity
```
 
Detection rules are mapped to the **MITRE ATT&CK Framework** where applicable:
 
| Rule | Technique | Tactic |
|------|-----------|--------|
| 100201 | T1078 — Valid Accounts | Defense Evasion, Persistence |
| 100301 | T1059.001 — PowerShell | Execution |
| 100302 | T1486 — Data Encrypted for Impact | Impact |
| 100401/402 | T1025 — Data from Removable Media | Collection |
 
---
 
## Tools & Technologies Referenced
 
- **SIEM:** Wazuh 4.7.5 (all-in-one deployment on Ubuntu Server)
- **Endpoint Telemetry:** Sysmon with SwiftOnSecurity configuration
- **EDR:** CrowdStrike Falcon (referenced in scenarios)
- **DLP:** Microsoft Purview / email gateway DLP
- **Identity:** Azure Active Directory / Microsoft Entra ID
- **Email Security:** DMARC, DKIM, SPF; Microsoft Defender for Office 365
- **Forensics:** Memory acquisition, disk imaging, chain of custody
---
 
## Repository Structure
 
```
Incident-Response-Playbooks/
├── README.md
└── playbooks/
    ├── 01_Phishing_IR_Playbook_and_Case_Study.pdf
    ├── 02_Malware_IR_Playbook_and_Case_Study.pdf
    └── 03_Insider_Threat_IR_Playbook_and_Case_Study.pdf
```
 
---
 
## About
 
Built by **D. Taylor Jr.** as part of a cybersecurity home lab portfolio targeting SOC Analyst, Sysadmin, and cybersecurity roles. Background includes a B.S. in Computer Science (Cybersecurity concentration) and 8 years of service in the Louisiana Army National Guard.
 
**Other projects in this portfolio:**
- [Wazuh SIEM](https://github.com/dmtaylorjr/Wazuh-SIEM) — Full SIEM deployment with Windows agent, Sysmon, and custom detection rules
- [Network Traffic Analysis](https://github.com/dmtaylorjr/Network-Traffic-Analysis) — Wireshark + Suricata IDS with custom rulesets and real anomaly detection
- [Jellyfin Home Server](https://github.com/dmtaylorjr/Jellyfin-Home-Server) — Ubuntu media server with Tailscale VPN and multi-user remote access
 
