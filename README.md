# Threat-Detection-and-Correlation-Lab

A SOC-style threat detection and correlation lab built using Kali Linux, Windows 10, Ubuntu, Snort 3, and Sysmon. Includes a Python engine that correlates network and endpoint telemetry to identify reconnaissance, obfuscated PowerShell, and persistence attempts — generating automated incident reports with chronological timelines.

---

## Project Overview

This project simulates a centralized SOC (Security Operations Center) monitoring environment across three virtual machines. Snort 3 detects network reconnaissance via custom IDS rules. Sysmon collects Windows endpoint telemetry including process creation, command execution, and PowerShell activity. A Python correlation engine parses both sources, filters noise, decodes encoded PowerShell commands, reconstructs a chronological incident timeline, and generates a structured analysis report — replicating core Tier 1 SOC analyst workflow.

---

## Lab Architecture

```
Kali Linux VM                Windows 10 VM               Ubuntu VM
─────────────                ─────────────               ─────────
Attack Simulation     →      Sysmon Endpoint         →   SOC Monitoring Server
(Nmap SYN Scan)              Telemetry Collection        ├── Snort 3 IDS
                             ↓                           ├── Wireshark
                     VMware Shared Folder                ├── Python Correlation Engine
                     (PLACED_2026/)                      └── Automated Report Generator
                     ├── logs/
                     └── reports/
```

| Machine | OS | Role |
|---|---|---|
| Kali Linux | Kali Rolling | Attack simulation |
| Windows 10 VM | Windows 10 | Monitored endpoint |
| Ubuntu VM | Ubuntu 24 | SOC monitoring server |

---

## Tools & Technologies

| Tool | Purpose |
|---|---|
| Sysmon | Windows endpoint telemetry — process creation, PowerShell, command execution |
| Snort 3 | Network Intrusion Detection System with custom IDS rules |
| Wireshark | Packet capture and TCP traffic analysis |
| Nmap | Attack simulation — SYN reconnaissance scan |
| Python 3 | Log parsing, event correlation, report generation |
| VMware Workstation | Virtualized multi-machine lab environment |
| VMware Shared Folders | Centralized log storage accessible by all VMs |

---

## What the Correlation Engine Does

`soc_correlation_engine.py` automatically:

- Parses **Snort alert logs** to extract attacker IPs, target IPs, and SYN packet counts
- Parses **Sysmon endpoint logs** to extract process execution and command-line activity
- Filters out Windows system noise to surface only analyst-relevant events
- **Decodes base64-encoded PowerShell** (`-enc`) commands inline in the report
- Reconstructs a **chronological incident timeline** from Sysmon timestamps
- Generates **dynamic behavior analysis** based on what was actually detected — not hardcoded text
- Produces **dynamic recommendations** tied to specific findings
- Saves a timestamped report to the centralized shared folder

---

## Attack Simulation Performed

| Technique | Tool | What It Does |
|---|---|---|
| Network Reconnaissance | Nmap (`-sS`) | TCP SYN scan to discover open ports |
| Obfuscated Execution | PowerShell (`-enc`) | Base64-encoded command execution |
| System Enumeration | `whoami`, `ipconfig`, `tasklist` | Attacker maps the target environment |
| Persistence Attempt | `schtasks -create` | Scheduled task creation |
| File Deletion | `cmd /c del` | Cleanup of attacker artifacts |

---

## Detection Coverage

| Suspicious Behavior | Detected By |
|---|---|
| TCP SYN port scan | Snort 3 custom IDS rule |
| Encoded PowerShell execution | Sysmon Event ID 1 + Python decoder |
| System enumeration commands | Sysmon Event ID 1 |
| Scheduled task creation | Sysmon Event ID 1 |
| Suspicious process execution | Sysmon Event ID 1 |
| Multi-source event correlation | Python correlation engine |

---

## Snort Custom Rule

```
# Rule 1 — ICMP Ping Flood Detection
alert icmp any any -> <your-lab-subnet>/24 any
(itype:8; detection_filter:track by_src, count 20, seconds 5;
msg:"[Lab] ICMP Ping Flood Detected"; sid:1000001;)

# Rule 2 — SSH Attempt Detection
alert tcp any any -> <target-ip> 22
(msg:"[Lab] SSH Attempt Detected"; sid:1000002;)

# Rule 3 — TCP SYN Scan Detection
alert tcp any any -> <your-lab-subnet>/24 any
(flags:S; detection_filter:track by_src, count 20, seconds 10;
msg:"[Lab] SYN Scan"; sid:1000003;)
```

| Rule | What It Detects | Threshold |
|---|---|---|
| `sid:1000001` | ICMP ping flood — potential DoS or sweep activity | 20 ICMP type-8 packets from same source in 5 seconds |
| `sid:1000002` | SSH connection attempts to the monitored endpoint | Any TCP connection to port 22 |
| `sid:1000003` | TCP SYN scan — reconnaissance / port scanning | 20 SYN packets from same source in 10 seconds |

---

## Sample Report Output

```
====================================================
            SOC ACTIVITY ANALYSIS REPORT
====================================================
Report Generated: 2026-05-28 03:52:56
----------------------------------------------------
SUMMARY
----------------------------------------------------
  Attacker IPs Identified  : 1
  Target IPs Identified    : 1
  TCP SYN Packets Detected : 1971
  Suspicious Apps Found    : 8
  Suspicious Commands      : 10
  Timeline Events          : 22
----------------------------------------------------
INCIDENT TIMELINE:
- Network Activity Detected --> TCP SYN scanning activity detected
- 2026-05-27 19:07:59 --> powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQA
  [Decoded] --> echo test
- 2026-05-27 20:44:40 --> whoami
- 2026-05-27 20:45:03 --> tasklist
- 2026-05-27 20:50:15 --> schtasks.exe -create -tn
...
----------------------------------------------------
Behavior Analysis:
High-volume TCP SYN traffic indicates systematic port scanning
consistent with pre-attack reconnaissance activity.

Encoded PowerShell execution was observed. Attackers commonly use
base64 encoding to obfuscate malicious commands and evade detection.
...
====================================================
```

---

## Repository Structure

```
Threat-Detection-and-Correlation-Lab/
│
├── soc_correlation_engine.py       # Main correlation and reporting engine
├── README.md
│
├── rules/
│   └── local.rules                 # Custom Snort 3 IDS rules
│
├── screenshots/
│   ├── sysmon/                     # Sysmon Event Viewer captures
│   ├── snort/                      # Snort IDS alert output
│   ├── wireshark/                  # Packet capture screenshots
│   └── kali/                       # Nmap attack simulation
│
└── sample-report/
    └── soc_report_sample.txt       # Example generated report
```

---

## How to Run

### Prerequisites
- Ubuntu VM with Snort 3 installed
- Windows VM with Sysmon installed and configured
- VMware Shared Folder configured between host, Windows VM, and Ubuntu VM
  - In this lab the shared folder is named **`PLACED_2026`** — this is a VMware Workstation shared folder created on the host machine and mounted automatically on both VMs
  - Windows VM accesses it at: `\\vmware-host\Shared Folders\PLACED_2026\`
  - Ubuntu VM accesses it at: `/mnt/hgfs/PLACED_2026/` (mount with `sudo vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other`)
  - Inside it, create two subfolders: `logs/` and `reports/`

### Step 1 — Start Snort on Ubuntu
```bash
sudo snort -c /usr/local/etc/snort/snort.lua \
-R /usr/local/etc/snort/rules/local.rules \
-i ens33 -A alert_fast | tee /mnt/hgfs/PLACED_2026/logs/snort_alerts.txt
```

### Step 2 — Simulate Attack from Kali
```bash
nmap -sS <target-ip>
```

### Step 3 — Export Sysmon Logs from Windows
```powershell
$time = Get-Date -Format "yyyyMMdd_HHmmss"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Format-List > "\\vmware-host\Shared Folders\PLACED_2026\logs\sysmon_$time.txt"
```

### Step 4 — Convert Encoding on Ubuntu
```bash
iconv -f UTF-16 -t UTF-8 \
/mnt/hgfs/PLACED_2026/logs/sysmon_<timestamp>.txt \
-o /mnt/hgfs/PLACED_2026/logs/sysmon_utf8.txt
```

### Step 5 — Run the Correlation Engine
```bash
python3 soc_correlation_engine.py
```

The report is automatically saved to `/mnt/hgfs/PLACED_2026/reports/`.

---

## Key Learning Outcomes

- Built a multi-VM virtualized security monitoring environment from scratch
- Configured Sysmon with a custom XML config for detailed endpoint telemetry
- Wrote and validated a custom Snort 3 IDS rule with threshold-based detection
- Developed a Python log parser that correlates two independent telemetry sources
- Implemented automatic base64 PowerShell decoding for obfuscated command detection
- Reconstructed chronological incident timelines from raw Sysmon timestamps
- Produced structured, analyst-readable incident reports replicating SOC Tier 1 workflow

---

## Future Improvements

- Automated Sysmon log forwarding using **Winlogbeat** to eliminate manual export
- **Wazuh** or **ELK Stack** integration for real-time centralized log ingestion
- **MITRE ATT&CK** technique tagging per detected behavior
- Web-based report dashboard

---

*Built as part of a Master's-level cybersecurity lab project focused on SOC operations, threat detection, and incident analysis.*
