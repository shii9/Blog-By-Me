# 🛡️ Building a SOC Home Lab: Centralized Windows & Linux Security Monitoring with Splunk

[![Splunk Version](https://img.shields.io/badge/Splunk_Enterprise-10.4.2-FF0000?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![Windows 11](https://img.shields.io/badge/Host-Windows_11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Windows 10](https://img.shields.io/badge/VM-Windows_10-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Kali Linux](https://img.shields.io/badge/VM-Kali_Linux-557C93?style=for-the-badge&logo=kali-linux&logoColor=white)](https://www.kali.org/)

> A multi-OS Security Operations Center (SOC) laboratory implementing centralized log ingestion, security telemetry forwarding, index segregation, SPL detection engineering, and incident response workflows using **Splunk Enterprise 10.4.2** and **Splunk Universal Forwarders**.

🔗 **Source Repository:** [github.com/shii9/SOC_Lab_Setup_Splunk](https://github.com/shii9/SOC_Lab_Setup_Splunk)

---

## 📋 Table of Contents

1. [Introduction & Motivation](#1-introduction--motivation)
2. [Objectives & Project Scope](#2-objectives--project-scope)
3. [Lab Architecture & Data Flow](#3-lab-architecture--data-flow)
4. [Data Pipeline & Index Design](#4-data-pipeline--index-design)
5. [Step-by-Step Setup Guide](#5-step-by-step-setup-guide)
6. [Validation & Testing](#6-validation--testing)
7. [Detection Engineering — SPL Use Cases](#7-detection-engineering--spl-use-cases)
8. [Troubleshooting & Problem Resolution](#8-troubleshooting--problem-resolution)
9. [Security Hardening Best Practices](#9-security-hardening-best-practices)
10. [Future Enhancements](#10-future-enhancements)
11. [Conclusion](#11-conclusion)

---

## 1. Introduction & Motivation

Modern cybersecurity operations require centralized visibility across diverse operating systems and network boundaries. Traditional, decentralized log management—where system logs reside isolated on individual endpoints—fails to provide timely threat visibility, hinders forensic investigation, and increases **mean time to detect (MTTD)**.

This project details the design, deployment, configuration, and validation of a centralized **Security Information and Event Management (SIEM)** laboratory. Using **Splunk Enterprise 10.4.2** hosted on a Windows 11 platform as the central receiving, indexing, search, and alerting engine, security telemetry is collected near real-time over **TCP port 9997** from heterogeneous endpoints:

- A **Windows 10 Virtual Machine**
- A **Kali Linux Virtual Machine**
- Local **Windows 11 Host** logs

The laboratory successfully establishes:
- ✅ Segregated index storage (`windows11`, `windows10`, `sh-kali`)
- ✅ Custom Linux `auditd` noise reduction to prevent event flooding
- ✅ Inbound host firewall restrictions
- ✅ End-to-end telemetry ingestion with over **9,435+ events processed**
- ✅ Actionable SPL detection rules for brute-force, account tampering, privilege escalation, and file integrity breaches

### Why This Matters: Centralized vs. Decentralized SIEM

| Feature / Metric | Traditional Decentralized System | Centralized Splunk SIEM Lab | SOC Impact |
| :--- | :--- | :--- | :--- |
| **Log Storage** | Dispersed locally across endpoints | Centralized Indexer database | Instant search access; prevents log tampering |
| **Event Correlation** | Manual log collection per machine | Automated cross-platform SPL rules | Correlates Windows & Linux events simultaneously |
| **Search Speed** | Hours/Days manually parsing files | Seconds using indexed SPL queries | Drastically reduces MTTD |
| **Alerting** | None or local email/popups | Automated alerts & threshold triggers | Real-time notification of brute-force & privilege abuse |
| **Dashboards** | No visual aggregation | Real-time graphical UI & dashboards | Executive & operational situational awareness |
| **Audit Noise Control** | Raw unfiltered file logs | Filtered telemetry (`auditd` keys) | Prevents storage exhaustion and analyst burnout |

---

## 2. Objectives & Project Scope

- **Centralized SIEM Deployment**: Establish a single-instance Splunk Enterprise 10.4.2 server combining Indexer and Search Head capabilities on a Windows 11 host.
- **Cross-Platform Telemetry Collection**: Ingest Windows Event Logs (Security, System, Application, PowerShell, Defender) and Linux telemetry (`auth.log`, `auditd`, `kern.log`, `apt/dpkg`).
- **Data Pipeline Segregation**: Structure incoming data streams into dedicated indexes (`windows11`, `windows10`, `sh-kali`) for query performance and data hygiene.
- **Linux Audit Noise Optimization**: Fine-tune Linux `auditd` rules to eliminate excessive system call logs while capturing high-value File Integrity Monitoring (FIM) and credential modifications.
- **Detection Engineering**: Develop Splunk Processing Language (SPL) rules to detect brute-force logons, privilege escalation attempts, unauthorized account creation, and file integrity violations.

---

## 3. Lab Architecture & Data Flow

### 3.1 High-Level Topology

```
                       ┌──────────────────────────────────────┐
                       │          MONITORED ENDPOINTS         │
                       └──────────────────┬───────────────────┘
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
   │  Windows 10 VM  │           │  Kali Linux VM  │           │ Windows 11 Host │
   │ (Splunk UF)     │           │ (Splunk UF)     │           │ (Local Input)   │
   └────────┬────────┘           └────────┬────────┘           └────────┬────────┘
            │                             │                             │
            │ TCP 9997                    │ TCP 9997                    │ Direct Read
            └──────────────────────┬──────┴─────────────────────────────┘
                                   ▼
                   ┌──────────────────────────────────────┐
                   │  SPLUNK ENTERPRISE ON WINDOWS 11     │
                   │  • Receiving Layer (Port 9997)       │
                   │  • Indexer (Parsing & Storage)       │
                   │  • Search Head (Web UI Port 8000)    │
                   └──────────────────┬───────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
   ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
   │ index=windows10 │       │  index=sh-kali  │       │ index=windows11 │
   └────────┬────────┘       └────────┬────────┘       └────────┬────────┘
            └─────────────────────────┼─────────────────────────┘
                                      ▼
                           ┌─────────────────────┐
                           │   SPL Search Engine │
                           └──────────┬──────────┘
                                      ▼
                           ┌─────────────────────┐
                           │ SOC Analyst Triage  │
                           └─────────────────────┘
```

### 3.2 Network & Service Port Mapping

| Machine | OS | Role | Networking |
| :--- | :--- | :--- | :--- |
| **Splunk Server Host** | Windows 11 Pro | SIEM Receiver, Indexer & Search Head | Host Adapter / LAN |
| **Windows 10 Endpoint** | Windows 10 Enterprise VM | Monitored Windows Desktop | Hypervisor NAT Gateway |
| **Kali Linux Endpoint** | Kali Linux 2024.x | Monitored Linux Security VM | Virtual Subnet (Routed) |

**Service Ports:**
- `Port 8000 (TCP)` — Web UI browser access: `http://<Splunk_Server_IP>:8000`
- `Port 8089 (TCP)` — Splunk REST API and management service
- `Port 9997 (TCP)` — Encrypted Splunk-to-Splunk telemetry receiving listener

---

## 4. Data Pipeline & Index Design

### 4.1 Index Organization & Sourcetype Definitions

| Index Name | Source Host | Monitored Log Channels | Sourcetypes |
| :--- | :--- | :--- | :--- |
| `windows11` | Windows 11 Host | Security, System, Application, PowerShell | `WinEventLog:Security`, `WinEventLog:System`, etc. |
| `windows10` | Windows 10 VM | Security, System, Application, PowerShell, Defender | `WinEventLog:Security`, `XmlWinEventLog:Sysmon` |
| `sh-kali` | Kali Linux VM | `/var/log/auth.log`, `/var/log/audit/audit.log`, `kern.log`, `apt/dpkg` | `linux_secure`, `linux_audit`, `linux_kernel`, `dpkg`, `apt_history` |

### 4.2 High-Value Windows Security Event IDs

```
+----------+-------------------------------------------------------------+
| Event ID | Security Meaning & SOC Investigation Relevance              |
+----------+-------------------------------------------------------------+
|   4624   | Successful user logon authentication                        |
|   4625   | Failed user logon authentication (Brute-force indicator)    |
|   4648   | Logon attempted using explicit credentials (runas)          |
|   4672   | Special privileges assigned to new logon (Admin rights)     |
|   4688   | New process creation (Command line execution tracking)      |
|   4720   | User account created                                        |
|   4725   | User account disabled                                       |
|   4726   | User account deleted                                        |
|   4732   | Member added to local security group (Privilege escalation) |
|   4740   | User account locked out                                     |
|   7045   | New Windows service installed (Persistence mechanism)       |
+----------+-------------------------------------------------------------+
```

---

## 5. Step-by-Step Setup Guide

### 5.1 Central Splunk Server Installation (Windows 11)

1. Download and run `splunk-10.4.2-x64-release.msi`.
2. Complete setup and set Administrator credentials.
3. Access Splunk Web interface at `http://localhost:8000`.
4. Navigate to **Settings → Forwarding and receiving → Configure receiving**.
5. Click **New Receiving Port**, enter `9997`, and save.
6. Open PowerShell as **Administrator** and create the inbound firewall rule:

```powershell
New-NetFirewallRule -DisplayName "Splunk Forwarder 9997" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
Get-NetTCPConnection -LocalPort 9997 -State Listen
```

---

### 5.2 Local Windows 11 Log Ingestion Configuration

Define direct file inputs in `C:\Program Files\Splunk\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
index = windows11

[WinEventLog://System]
disabled = 0
index = windows11

[WinEventLog://Application]
disabled = 0
index = windows11

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows11
```

---

### 5.3 Windows 10 VM — Universal Forwarder Deployment

1. Install Splunk Universal Forwarder `splunkforwarder-10.4.2-x64-release.msi`.
2. Connect the agent to the central receiver:

```cmd
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe add forward-server <Splunk_Server_IP>:9997
.\splunk.exe list forward-server
```

3. Deploy `inputs.conf` to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
index = windows10

[WinEventLog://System]
disabled = 0
index = windows10

[WinEventLog://Application]
disabled = 0
index = windows10

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows10
```

---

### 5.4 Kali Linux VM — Forwarder Setup & Audit Tuning

#### Step 1: Install Universal Forwarder

```bash
wget -O splunkforwarder-10.4.2-linux-amd64.deb \
  "https://download.splunk.com/products/universalforwarder/releases/10.4.2/linux/splunkforwarder-10.4.2-33c3bf42cd73-linux-amd64.deb"
sudo dpkg -i splunkforwarder-10.4.2-linux-amd64.deb
```

#### Step 2: Start & Register Service

```bash
sudo /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk enable boot-start
sudo /opt/splunkforwarder/bin/splunk add forward-server <Splunk_Server_IP>:9997
```

#### Step 3: Configure rsyslog for Auth Telemetry

```bash
sudo apt update && sudo apt install rsyslog -y
sudo systemctl enable --now rsyslog
```

> **Why rsyslog?** Kali Linux defaults to `systemd-journald`, which does not create `/var/log/auth.log`. Installing `rsyslog` restores the traditional syslog-based auth log file that Splunk can monitor.

#### Step 4: Deploy Noise-Controlled auditd Rules

Broad syscall tracking (`-a always,exit -S execve`) floods logs with thousands of events per minute. Instead, use targeted file-watch rules in `/etc/audit/rules.d/splunk_soc.rules`:

```ini
# Account database changes
-w /etc/passwd -p wa -k account_changes
-w /etc/shadow -p wa -k account_changes
-w /etc/group -p wa -k account_changes
-w /etc/gshadow -p wa -k account_changes

# Privilege configuration
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes

# SSH and persistence monitoring
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes
-w /etc/crontab -p wa -k cron_changes

# Lab directory file integrity monitoring
-w /home/sh-kali/Desktop/ -p wa -k user_file_changes
```

Apply the rules:

```bash
sudo augenrules --load && sudo auditctl -l
```

#### Step 5: Configure inputs.conf on Kali

Set `/opt/splunkforwarder/etc/system/local/inputs.conf`:

```ini
[monitor:///var/log/auth.log]
disabled = false
index = sh-kali
sourcetype = linux_secure

[monitor:///var/log/audit/audit.log]
disabled = false
index = sh-kali
sourcetype = linux_audit

[monitor:///var/log/kern.log]
disabled = false
index = sh-kali
sourcetype = linux_kernel

[monitor:///var/log/dpkg.log]
disabled = false
index = sh-kali
sourcetype = dpkg

[monitor:///var/log/apt/history.log]
disabled = false
index = sh-kali
sourcetype = apt_history
```

Restart the forwarder:

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

---

## 6. Validation & Testing

Five formal test cases validated end-to-end functionality:

```
+---------+------------------------------+---------------------------------------+---------------------------------------+--------+
| Test ID | Test Scenario                | Input / Action                        | Expected Result                       | Status |
+---------+------------------------------+---------------------------------------+---------------------------------------+--------+
|  TC-01  | TCP Listener Check           | netstat / Get-NetTCPConnection        | Port 9997 listed in LISTEN state      | PASS   |
|  TC-02  | Forwarder Connectivity       | splunk list forward-server            | Active forward to <Splunk_IP>:9997    | PASS   |
|  TC-03  | Windows Event Ingestion      | Generate failed logon on Win 10 VM    | EventCode=4625 in index=windows10     | PASS   |
|  TC-04  | Kali Auth Log Ingestion      | Run invalid `sudo` command on Kali    | "authentication failure" in sh-kali   | PASS   |
|  TC-05  | Auditd FIM Verification      | touch /home/sh-kali/Desktop/test.txt  | key="user_file_changes" in sh-kali    | PASS   |
+---------+------------------------------+---------------------------------------+---------------------------------------+--------+
```

**Final Ingestion Verification SPL:**

```spl
index=* | stats count by host index
```

This confirmed **9,435 total ingested events** across all three hosts.

---

## 7. Detection Engineering — SPL Use Cases

### Use Case 1: Windows Brute Force Authentication Detection

**Objective:** Detect potential brute-force or password spraying attacks targeting Windows user accounts.

```spl
index=windows10 EventCode=4625 
| stats count by TargetUserName, WorkstationName, src_ip 
| where count >= 5
```

**Triage Workflow:** Verify if username is valid → Inspect source IP → Cross-reference Event Code 4624 for subsequent successful logon.

---

### Use Case 2: Linux Failed Sudo / Privilege Abuse Detection

**Objective:** Identify unauthorized privilege escalation attempts by non-root users on Kali Linux.

```spl
index=sh-kali sourcetype=linux_secure "authentication failure" 
| table _time, host, process, message
```

**Triage Workflow:** Correlate user ID (`auid`) with SSH logon session to determine if a compromised account is attempting escalation.

---

### Use Case 3: Linux Account Database Tampering

**Objective:** Detect unauthorized creation, modification, or deletion of local Linux accounts (`/etc/passwd`, `/etc/shadow`).

```spl
index=sh-kali sourcetype=linux_audit key="account_changes" 
| table _time, host, exe, name, auid
```

**Triage Workflow:** High Severity Alert. Validate binary (`exe`) executing write action — legitimate changes trace back to `/usr/sbin/useradd` or `/usr/bin/passwd` during approved maintenance windows.

---

### Use Case 4: Windows Local User Account Creation

**Objective:** Alert on newly created local administrator or backdoor accounts on Windows endpoints.

```spl
index=windows10 EventCode=4720 
| table _time, TargetUserName, SubjectUserName, host
```

**Triage Workflow:** Identify `SubjectUserName` (who created the account) and verify against approved change management records.

---

### Use Case 5: File Integrity Monitoring (FIM) on Desktop Directory

**Objective:** Monitor sensitive desktop directory modifications on the Linux workstation.

```spl
index=sh-kali sourcetype=linux_audit key="user_file_changes" 
| table _time, host, key, name, SYSCALL, auid
```

---

## 8. Troubleshooting & Problem Resolution

| Problem Scenario | Root Cause | Fix |
| :--- | :--- | :--- |
| **PowerShell "Access Denied"** | Command executed under standard user | Relaunch PowerShell as **Run as Administrator** |
| **Kali `nc` inverse host lookup warning** | Missing reverse DNS for `<Splunk_Server_IP>` | Benign — confirm output shows `open` on port 9997 |
| **Forwarder shows Inactive status** | Host firewall blocking port 9997 or service down | Verify `New-NetFirewallRule` and check service status |
| **Missing `/var/log/auth.log` on Kali** | Systemd journald default storage | Install `rsyslog`: `sudo apt install rsyslog -y` |
| **Audit log volume flooding** | Broad `-a always,exit -S execve` global rule | Remove global command tracking; deploy focused audit key rules |

---

## 9. Security Hardening Best Practices

1. **Network Segmentation**: Isolate laboratory VMs using Host-Only or NAT adapters to prevent external exposure.
2. **Firewall Scoping**: Restrict port 9997 inbound rules to explicit VM subnets (`192.168.X.X/24`), never `Any`.
3. **Credential Security**: Store Splunk credentials securely — never commit plain-text passwords to version control.
4. **Time Synchronization**: Keep all monitored machines NTP-synchronized to ensure accurate cross-platform event correlation timelines.

---

## 10. Future Enhancements

- **Microsoft Sysmon Integration**: Deploy Sysmon with Olaf Hartong modular XML configurations to capture process line parentage, DNS queries, and network connections.
- **Network Threat Detection (NIDS)**: Integrate Suricata or Zeek to ship packet metadata into Splunk.
- **Active Directory Domain Controller VM**: Introduce Windows Server 2022 to log Kerberos tickets and AD attack vectors (Kerberoasting).
- **MITRE ATT&CK Mapping**: Tag custom SPL alerts directly to MITRE ATT&CK technique IDs (e.g., T1078 — Valid Accounts, T1136 — Create Account, T1068 — Exploitation for Privilege Escalation).

---

## 11. Conclusion

This project successfully implemented a resilient, multi-OS centralized SOC Home Lab using **Splunk Enterprise 10.4.2**. By combining native Windows event logging, Linux `rsyslog`, and targeted `auditd` FIM telemetry, the lab achieved complete end-to-end visibility into security events across host and virtual environments.

The deployment of custom SPL detection rules proves that effective SIEM operations depend not only on log ingestion, but on **disciplined data filtering, index segregation, and actionable alert engineering**.

This lab demonstrates:
- Real-world SIEM architecture design
- Cross-platform telemetry collection pipeline
- Detection engineering using SPL
- Audit noise suppression for analyst efficiency
- Security hardening and operational best practices

---

*Author: Sourov Hossen | GitHub: [github.com/shii9](https://github.com/shii9) | LinkedIn: [linkedin.com/in/sourov-hossen-307655351](https://linkedin.com/in/sourov-hossen-307655351)*
