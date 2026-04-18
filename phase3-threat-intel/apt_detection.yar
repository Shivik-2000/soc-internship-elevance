/*
    YARA Rules for APT Attack Detection
    Author: Vaishvik Kansara — SOC Intern
    Organization: Elevance Skills Technology Pvt. Ltd.
    Date: April 2026
    Description: Detection rules written based on Phase 1 red team
                 attack simulation findings. Covers brute-force,
                 persistence, privilege escalation and exfiltration.
*/

// ─── RULE 1: Backdoor Account Creation ──────────────────────────────────────
rule APT_Backdoor_Account_Creation
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects creation of backdoor user accounts with sudo privileges"
        mitre       = "T1136.001 - Create Local Account"
        severity    = "Critical"
        reference   = "Phase 1 Red Team simulation - ubuntu-victim"

    strings:
        $s1 = "useradd" ascii
        $s2 = "backdoor" ascii nocase
        $s3 = "NOPASSWD:ALL" ascii
        $s4 = "/bin/bash" ascii
        $s5 = "chpasswd" ascii
        $s6 = "usermod -aG sudo" ascii

    condition:
        ($s1 and $s2) or
        ($s3 and $s4) or
        ($s1 and $s6)
}

// ─── RULE 2: SSH Brute Force Evidence ───────────────────────────────────────
rule APT_SSH_BruteForce_Evidence
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects evidence of SSH brute-force attacks in auth logs"
        mitre       = "T1110.001 - Password Guessing via SSH"
        severity    = "High"
        reference   = "Phase 1 - Hydra brute-force against admin account"

    strings:
        $fail1 = "Failed password for" ascii
        $fail2 = "Failed password for invalid user" ascii
        $fail3 = "authentication failure" ascii nocase
        $tool1 = "hydra" ascii nocase
        $tool2 = "medusa" ascii nocase
        $tool3 = "ncrack" ascii nocase
        $user1 = "root" ascii
        $user2 = "admin" ascii
        $user3 = "ubuntu" ascii

    condition:
        (2 of ($fail*)) or
        (any of ($tool*)) or
        ($fail1 and any of ($user*))
}

// ─── RULE 3: Sudo Privilege Escalation ──────────────────────────────────────
rule APT_Sudo_PrivEsc
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects sudo privilege escalation to root"
        mitre       = "T1548.003 - Abuse Elevation Control - Sudo"
        severity    = "Critical"
        reference   = "Phase 1 - sudo su abuse to gain root"

    strings:
        $s1 = "sudo" ascii
        $s2 = "COMMAND=/usr/bin/su" ascii
        $s3 = "COMMAND=/bin/bash" ascii
        $s4 = "USER=root" ascii
        $s5 = "session opened for user root" ascii
        $s6 = "sudo su" ascii

    condition:
        ($s1 and $s4) or
        ($s2 or $s3) or
        $s5
}

// ─── RULE 4: Data Exfiltration via HTTP ─────────────────────────────────────
rule APT_HTTP_Exfiltration
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects data packaging and HTTP-based exfiltration"
        mitre       = "T1048 - Exfiltration Over Alternative Protocol"
        severity    = "Critical"
        reference   = "Phase 1 - python3 http.server + stolen_data.tar.gz"

    strings:
        $s1 = "stolen_data" ascii nocase
        $s2 = "http.server" ascii
        $s3 = "SimpleHTTPServer" ascii
        $s4 = "tar -czf" ascii
        $s5 = "/tmp/exfil" ascii
        $s6 = "credentials.txt" ascii nocase
        $s7 = "GET /stolen" ascii nocase

    condition:
        any of ($s*)
}

// ─── RULE 5: Suspicious File Collection ─────────────────────────────────────
rule APT_Sensitive_File_Collection
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects collection of sensitive system files for exfiltration"
        mitre       = "T1005 - Data from Local System"
        severity    = "High"
        reference   = "Phase 1 - /etc/passwd and /etc/shadow copied to /tmp"

    strings:
        $s1 = "/etc/shadow" ascii
        $s2 = "/etc/passwd" ascii
        $s3 = "/tmp/exfil" ascii
        $s4 = "cp /etc/passwd" ascii
        $s5 = "cp /etc/shadow" ascii
        $s6 = "cat /etc/shadow" ascii

    condition:
        ($s1 and $s3) or
        ($s4 or $s5 or $s6)
}

// ─── RULE 6: Nmap Reconnaissance ────────────────────────────────────────────
rule APT_Nmap_Recon
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects Nmap network reconnaissance activity"
        mitre       = "T1595 - Active Scanning"
        severity    = "Medium"
        reference   = "Phase 1 - nmap -sV -sC -O scan"

    strings:
        $s1 = "nmap" ascii nocase
        $s2 = "Nmap scan report" ascii
        $s3 = "Service detection performed" ascii
        $s4 = "-sV" ascii
        $s5 = "-sC" ascii
        $s6 = "OS detection" ascii

    condition:
        $s1 or $s2 or $s3 or
        ($s4 and $s5)
}

// ─── RULE 7: Full APT Attack Chain ──────────────────────────────────────────
rule APT_Full_Attack_Chain
{
    meta:
        author      = "Vaishvik Kansara"
        date        = "2026-04-05"
        description = "Detects multiple stages of APT attack chain in single artifact"
        mitre       = "Multiple - Full kill chain detection"
        severity    = "Critical"
        reference   = "Phase 1 complete attack simulation"

    strings:
        $recon    = "nmap" ascii nocase
        $brute    = "Failed password" ascii
        $access   = "Accepted password" ascii
        $privesc  = "session opened for user root" ascii
        $persist  = "useradd" ascii
        $exfil    = "stolen_data" ascii nocase

    condition:
        3 of them
}
