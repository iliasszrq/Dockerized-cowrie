# Cowrie Honeypot & Custom Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![Cowrie](https://img.shields.io/badge/Honeypot-Cowrie-orange)
![ZeroTier](https://img.shields.io/badge/Network-ZeroTier-yellow)

## Project Overview
For this group project, we simulated an internal network breach scenario.

* **Attacker:** [@iliasszrq](https://github.com/iliasszrq)
* **Defender:** [@ZTMY0](https://github.com/ZTMY0)

I deployed a **Cowrie SSH Honeypot** inside a Docker container and isolated it on a private **ZeroTier** network. My partner acted as the **Attacker** to breach the system, while I acted as the **Defender**, focusing on infrastructure, log ingestion, and forensic analysis.

**Note on Tools:**
* **ELK Stack:** We initially tried using Elasticsearch and Kippo Graph but I had issues with configuration. I replaced it with a custom **Python/Streamlit** dashboard for lightweight visualization.
* **Scope:** We debated using **Wireshark** and **Fail2Ban** but decided to focus on the core honeypot for this specific simulation.

---

## Defense Findings

### 1. Brute Force Analytics
total number of attacks and a timeline graph that goes up when the attack attempts started.
![Dashboard Analytics](evidence/dashboard_analytics.png)

### 2. Forensic Timeline
The honeypot successfully logged the commands the attacker ran *after* guessing the password.
![Forensics Commands](evidence/dashboard_forensics.png)

---

## Attack Simulation (Red Team)
*Tools used: Nmap, Hydra*

### Step 1: Reconnaissance
Scanning the private ZeroTier subnet to find the open SSH port (mapped to 2222).
![Recon Scan](evidence/red_team_recon.png)

### Step 2: The Breach & Persistence
After cracking the password with Hydra, we logged in and attempted to change the root password.
* **The Deception:** Cowrie simulated a "success" message to fool the attacker, but the actual credentials remained unchanged.
![SSH Session](evidence/red_team_ssh_session.png)

### Step 3: Data Exfiltration
The attacker used `scp` to steal sensitive files (`/etc/passwd`) for offline cracking.
![Exfiltration](evidence/red_team_exfiltration.png)

---

## SysAdmin
We implemented security controls on the host machine in addition to Docker isolation.

**1. ACLs** : We configured specific permissions so our dedicated `auditor` user can read logs without being able to modify them.
```bash
ihab@ihab-VMware-VP:~/Desktop/honeypot$ getfacl cowrie.log
# file: cowrie.log
# owner: ihab
# group: ihab
user::rw-
user:auditor:r--
group::rw-			#effective:r--
group:cowrie-audit:r--
mask::r--
other::---

ihab@ihab-VMware-VP:~/Desktop/honeypot$ getfacl infrastructure/
# file: infrastructure/
# owner: ihab
# group: ihab
user::rwx
user:auditor:r-x
group::rwx
group:cowrie-audit:--x
mask::rwx
other::---
```

**2. Least Privilege (Sudo)** : We configured `/etc/sudoers` to allow the analyst to run `tail -f` on the logs without needing a root password.
```bash
ihab@ihab-VMware-VP:~/Desktop/honeypot$ sudo tail -f cowrie.log
[sudo] password for ihab: 
2025-11-25T22:01:18.950117Z bc0c80fbfa23 Command not found: ip addr
2025-11-25T22:01:28.035990Z bc0c80fbfa23 CMD: ip a
2025-11-25T22:01:28.037027Z bc0c80fbfa23 Command not found: ip a
2025-11-25T22:01:33.544221Z bc0c80fbfa23 CMD: sudo ip a
2025-11-25T22:01:49.147336Z bc0c80fbfa23 CMD: sudo apt install ip
2025-11-25T22:03:16.976876Z bc0c80fbfa23 CMD: touch iliass.txt
2025-11-25T22:03:21.879580Z bc0c80fbfa23 CMD: mkdir ihab
2025-11-25T22:03:25.688530Z bc0c80fbfa23 CMD: ls -la
2025-11-25T22:05:20.805524Z bc0c80fbfa23 Closing TTY Log: var/lib/cowrie/tty/e9dd234c1ba2bf14728d817dce23e8660a46f8d0d0fd6a94b34263b3b9abcd4e after 299.8 seconds
2025-11-25T22:05:20.806603Z bc0c80fbfa23 Connection lost after 302.5 seconds
```

**3. IPtables port redirection** : We applied a NAT rule to redirect traffic from standard SSH (Port 22) to the honeypot (Port 2222).
```bash
ihab@ihab-VMware-VP:~/Desktop/honeypot$ sudo iptables -t nat -L PREROUTING -n -v
Chain PREROUTING (policy ACCEPT 3404 packets, 1034K bytes)
 pkts bytes target     prot opt in     out     source               destination         
 2084  792K DOCKER     0    --  *      *       0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL
  101  6012 REDIRECT   6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 redir ports 2222
```
---

## Problems I Faced and How I Solved Them
 I ran into several real-world integration issues between Linux, Docker, and Python. Here is what I struggled with and how I fixed it.

### 1. Permission Crashes & Silent Logs
* **The Problem:** I needed to secure the log files using **ACLs** (Access Control Lists) for the assignment. However, applying these strict rules caused a conflict with Docker. The container would either crash with `(Errno 13) Permission Denied` or run silently without writing any logs because it lost access to the folder.
* **The Diagnostic:** I temporarily tested with `chmod -R 777` (allow everyone), and logs immediately appeared. This proved the issue was purely about Linux permissions blocking the Docker user.
* **How I Fixed It:**
    1. I moved the log file out of the sub-folder and into the main project root to avoid complex directory permission conflicts.
    2. I learned about Linux File IDs (UIDs) and used `chown` to explicitly give the container user (`UID 1000`) ownership of the file.
    3. Finally, I re-applied the ACLs strictly to give the auditor account read-only access without locking out the container.

### 2. Authentication Errors
* **The Problem:** I tried to force the honeypot to reject specific passwords using a `userdb.txt` file, but the Docker container kept ignoring my file and letting everyone in.
* **The Solution:** Instead of fighting the container image, I changed the strategy to a **"High-Interaction Honeypot."** By allowing attackers in easily, we actually gather *more* data (like the commands they type and files they download) than if we simply blocked them at the door.

### 3. The "Empty" Container
* **The Problem:** I tried to run `docker exec -it cowrie bash` to look inside the container and debug, but I got an error saying `exec file not found`.
* **The Lesson:** I learned the Cowrie image is **"Distroless"**—it has no shell, no `ls`, and no `cat` for security reasons. I had to learn by copying files *out* of the container (`docker cp`) to check them on my host machine instead.

## Installation & Usage

### Part 1: Infrastructure (Honeypot)
```bash
# Clone the repository
git clone [https://github.com/ZTMY0/Dockerized-cowrie.git](https://github.com/ZTMY0/Dockerized-cowrie.git)

# Install Docker Engine and the Compose Plugin
sudo apt install -y docker.io docker-compose-plugin

sudo systemctl enable --now docker # Enable docker service

sudo usermod -aG docker $USER # Restart VM after adding user to Docker group to apply permissions

# Start the container
docker-compose -f infrastructure/docker-compose.yml up -d

# Check Status
docker ps
```
### Part 2: Dashboard
```bash
# Create virtual environement to isolate dependencies
python3 -m venv myenv
source myenv/bin/activate 
pip install -r requirements.txt # Dashboard Reauirements
python3 -m streamlit run src/log_analyzer.py # Launch
