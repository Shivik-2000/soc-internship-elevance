# 🧠 Phase 3 — Threat Intelligence & Mitigation

## Overview
YARA rules, Sigma rules, and MISP IoC export created based on Phase 1 attack findings. These files can be used to detect similar attacks in any environment.

---

## Files

| File | Type | Rules | Description |
|------|------|-------|-------------|
| [apt_detection.yar](apt_detection.yar) | YARA | 7 rules | File-based attack pattern detection |
| [apt_sigma_rules.yml](apt_sigma_rules.yml) | Sigma | 6 rules | Log-based SIEM detection |
| [misp_ioc_export.json](misp_ioc_export.json) | MISP | 12 IoCs | Threat intelligence sharing |

---

## YARA Rules

### How to use
```bash
# Install YARA
sudo apt install yara -y

# Scan auth log
yara apt_detection.yar /var/log/auth.log

# Scan entire /tmp directory
yara apt_detection.yar /tmp/

# Scan with all rules recursively
yara -r apt_detection.yar /
```

### Rules Included
| Rule | Detects | MITRE |
|------|---------|-------|
| APT_Backdoor_Account_Creation | useradd backdoor + NOPASSWD | T1136.001 |
| APT_SSH_BruteForce_Evidence | Multiple failed SSH logins | T1110.001 |
| APT_Sudo_PrivEsc | sudo su → root | T1548.003 |
| APT_HTTP_Exfiltration | python3 http.server + stolen files | T1048 |
| APT_Sensitive_File_Collection | /etc/shadow copied to /tmp | T1005 |
| APT_Nmap_Recon | Nmap scan evidence | T1595 |
| APT_Full_Attack_Chain | 3+ attack stages detected | Multiple |

---

## Sigma Rules

### How to use
```bash
# Install sigma CLI
pip3 install sigma-cli

# Convert to Kibana/Lucene format
sigma convert -t lucene apt_sigma_rules.yml

# Convert to Splunk format
sigma convert -t splunk apt_sigma_rules.yml

# Convert to QRadar format
sigma convert -t qradar apt_sigma_rules.yml
```

### Rules Included
| Rule | Detects | Level |
|------|---------|-------|
| SSH Brute Force | 5+ failed logins in 60s | High |
| SSH Login After Brute Force | Success after failures | Critical |
| Sudo Privilege Escalation | sudo to root | High |
| Backdoor Account Creation | useradd + usermod combo | High |
| Sensitive File Access | /etc/shadow access | Medium |
| HTTP Server Non-Standard Port | python3 http.server | High |

---

## MISP IoCs

### How to import
1. Go to your MISP instance
2. Events → Add Event
3. Populate from → JSON Import
4. Paste contents of `misp_ioc_export.json`

### IoCs Included
| Type | Value | Severity |
|------|-------|----------|
| ip-src | 172.16.207.3 (attacker) | Critical |
| ip-dst | 172.16.207.4 (victim) | Info |
| port | 8888 (exfil HTTP) | High |
| port | 22 (SSH brute-forced) | High |
| credentials | admin:admin123 | Critical |
| username | backdoor | Critical |
| filename | stolen_data.tar.gz | High |
| filename | credentials.txt | High |
| text | NOPASSWD:ALL sudoers entry | Critical |
| text | hydra brute-force command | High |

---

## Mitigation Plan

### Immediate Actions
```bash
# 1. Block attacker IP
sudo ufw deny from 172.16.207.3

# 2. Remove backdoor account
sudo userdel -r backdoor

# 3. Install fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban

# 4. Disable password auth SSH
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
sudo systemctl restart sshd

# 5. Fix sudoers
sudo visudo   # Remove NOPASSWD entries
```

### Long-term Actions
- Deploy IDS/IPS (Snort/Suricata)
- Implement egress firewall rules
- Enable auditd for comprehensive logging
- Regular vulnerability assessments
- Security awareness training
