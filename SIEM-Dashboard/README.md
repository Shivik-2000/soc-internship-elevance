# 📊 Task 1 — Custom SIEM Dashboard (ELK Stack)

**Platform:** Elastic Cloud (Serverless Security Project)  
**Tool:** Kibana Lens  
**Date:** April 2026  

---

## Overview

Built 3 custom SIEM dashboards on Elastic Cloud (ELK Stack) visualizing critical security events across three threat categories — brute-force attacks, privilege escalations, and data exfiltration attempts.

Each dashboard was built by uploading realistic CSV log data to Elastic Cloud and creating Kibana visualizations using the Lens editor.

---

## Dashboard 1 — Brute-Force Attack SIEM Dashboard

**Index:** `ssh-brute-force`  
**Records:** 114 events  
**Panels:** 5 visualizations  

| Panel | Type | Finding |
|-------|------|---------|
| Failed Login Attempts Over Time | Bar chart | Spike on April 1 — 73 events |
| Top Attacking Source IPs | Bar chart | 203.0.113.55 is top attacker (26 attempts) |
| Most Targeted Usernames | Bar chart | root targeted 60 times |
| Failed vs Successful Logins | Pie chart | 93.86% failed, 6.14% success |
| Raw Attack Events Log | Table | 124 pages of event records |

### Screenshots

**Failed Logins Over Time + Top Attacking IPs**
![BF Dashboard Top](BF-Dashboard-Top.png)

**Most Targeted Usernames + Failed vs Successful**
![BF Dashboard Bottom](BF-Dashboard-Bottom.png)

**Raw Attack Events Log**
![BF Raw Events](BF-Raw-Events.png)

### Key Findings
- Coordinated brute-force campaign on April 1, 2026
- 203.0.113.55 is primary threat actor — 26 attempts
- Root account most targeted — credential enumeration pattern
- 7 successful logins detected — potential compromise

---

## Dashboard 2 — Privilege Escalation SIEM Dashboard

**Index:** `priv-escalation-logs`  
**Records:** 30 events  
**Panels:** 4 visualizations  

| Panel | Type | Finding |
|-------|------|---------|
| Escalation Events Over Time | Line chart | 30 events on April 1 |
| Escalation Methods Breakdown | Bar chart | sudo_abuse dominant (13 events) |
| Most Targeted Hosts | Bar chart | webserver hit 10 times |
| Successful vs Failed Escalations | Pie chart | 70% success rate — critical |

### Screenshots

**Timeline + Methods Breakdown**
![PrivEsc Top](screenshots/privilege-escalation/01_priv_esc_timeline_methods.png)

**Most Targeted Hosts + Success Rate**
![PrivEsc Bottom](screenshots/privilege-escalation/02_priv_esc_hosts_pie.png)

### Key Findings
- 70% escalation success rate — critical misconfiguration
- sudo_abuse is dominant technique — sudo rules need audit
- Webserver is highest risk host (10 events)
- 5 distinct escalation methods detected

---

## Dashboard 3 — Exfiltration Attempts SIEM Dashboard

**Index:** `exfiltration-logs`  
**Records:** 30 events  
**Panels:** 4 visualizations  

| Panel | Type | Finding |
|-------|------|---------|
| Exfiltration Events Over Time | Line chart | All on April 1 |
| Exfiltration Channels Used | Bar chart | TOR exit nodes dominant |
| Top Exfiltrating Source IPs | Bar chart | 10.0.2.33 most active |
| Successful vs Failed | Pie chart | 76.67% success rate |

### Screenshots

**Top Source IPs + Success Rate**
![Exfil Dashboard](screenshots/exfiltration/01_exfil_channels_success.png)

### Key Findings
- 76.67% exfiltration success — active data breach
- TOR exit nodes used — attacker anonymizing traffic
- DNS tunneling detected — data through port 53
- Internal host 10.0.2.33 is primary exfiltration source

---

## Tools Used

- **Platform:** Elastic Cloud (Serverless Security)
- **Visualization:** Kibana Lens
- **Data Ingestion:** Kibana Data Visualizer
- **Query Language:** KQL (Kibana Query Language)
- **Log Format:** CSV (structured fields)

---

## MITRE ATT&CK Coverage

| Dashboard | Technique | ID |
|-----------|-----------|-----|
| Brute-Force | Brute Force | T1110 |
| Brute-Force | Valid Accounts | T1078 |
| Privilege Escalation | Sudo Abuse | T1548.003 |
| Privilege Escalation | Create Account | T1136 |
| Exfiltration | Alt Protocol | T1048 |
| Exfiltration | DNS Tunneling | T1071.004 |
