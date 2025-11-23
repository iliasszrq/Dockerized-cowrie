# Cowrie Honeypot & Custom Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![Cowrie](https://img.shields.io/badge/Honeypot-Cowrie-orange)
![ZeroTier](https://img.shields.io/badge/Network-ZeroTier-yellow)

## 📋 Project Overview
For this group project, we simulated an internal network breach scenario.

* **Attacker:** [@iliasszrq](https://github.com/iliasszrq)
* **Defender:** [@ZTMY0](https://github.com/ZTMY0)

**I** (the defender) deployed a **Cowrie SSH Honeypot** inside a Docker container and isolated it on a private **ZeroTier** network. My partner acted as the **Attacker** to breach the system, while I acted as the **Defender**, focusing on infrastructure, log ingestion, and forensic analysis.

**Note on Tool Selection:**
* **ELK Stack:** We initially attempted to use Elasticsearch for logging, but it consumed >4GB RAM. I replaced it with a custom **Python/Streamlit** parser.
*  We debated using **Wireshark** and **Fail2Ban** but deemed them unnecessary for this specific simulation but they can be a further addition in this project later on.

---

##  Defense Findings

### 1. Brute Force Analytics
The dashboard visualizing the volume of the dictionary attack. You can see the specific wordlists used against the `root` user.
![Dashboard Analytics](evidence/dashboard_analytics.png)

### 2. Executed Timeline
The honeypot successfully logged the commands the attacker ran *after* guessing the password (e.g., `whoami`, `wget`, `uname`).
![Forensics Commands](evidence/forensics_commands.png)


---

##  Attack Simulation
*Tools used: Nmap, Hydra*

**Step 1: Reconnaissance**
Scanning the private ZeroTier subnet to find the SSH port (mapped to 2222).
![Network Scan](evidence/red_team_network_scan.png)
![Port Scan](evidence/red_team_port_scan.png)

**Step 2: Exploitation**
Cracking the password using `rockyou.txt` and dropping payloads.
```bash
# Brute Force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.192.41 -s 2222

