"""
SOC Correlation Engine v2.0
============================
Author  : Pranjali Mandavi
Purpose : Correlates Snort 3 IDS network alerts with Windows Sysmon
          endpoint telemetry to detect suspicious activity, reconstruct
          incident timelines, and generate automated SOC analysis reports.

Input Sources:
  - Snort 3 alert log     : snort_alerts.txt  (network telemetry)
  - Sysmon endpoint log   : sysmon_utf8.txt   (endpoint telemetry)
  Both files are read from a VMware Shared Folder (PLACED_2026/logs/)
  accessible by both the Windows VM and Ubuntu SOC server.

What It Does:
  1. Extracts attacker and target IPs from Snort alerts
  2. Counts TCP SYN packets to infer reconnaissance activity
  3. Parses Sysmon logs for suspicious process execution and commands
  4. Filters Windows system noise using a curated noise pattern list
  5. Automatically decodes base64-encoded PowerShell (-enc) commands
  6. Reconstructs a chronological incident timeline from Sysmon timestamps
  7. Generates dynamic behavior analysis based on detected activity
  8. Produces dynamic recommendations tied to specific findings
  9. Saves a timestamped report to PLACED_2026/reports/

Output:
  - Printed SOC Activity Analysis Report (console)
  - Timestamped .txt report saved to the centralized shared folder

Usage:
  python3 soc_correlation_engine.py

Requirements:
  - Python 3.x
  - Snort alerts saved to : /mnt/hgfs/PLACED_2026/logs/snort_alerts.txt
  - Sysmon logs (UTF-8)   : /mnt/hgfs/PLACED_2026/logs/sysmon_utf8.txt
  - VMware Shared Folder mounted at /mnt/hgfs/PLACED_2026/
"""

import re
import base64
from datetime import datetime

# ==========================================================
# SOC CORRELATION ENGINE v2.0
# Centralized Endpoint + Network Correlation
# With: Dynamic Timeline | PS Decoder | Stats | Behavior Analysis
# ==========================================================

# ----------------------------------------------------------
# File Paths
# ----------------------------------------------------------

SNORT_LOG  = "/mnt/hgfs/PLACED_2026/logs/snort_alerts.txt"
SYSMON_LOG = "/mnt/hgfs/PLACED_2026/logs/sysmon_utf8.txt"
REPORT_DIR = "/mnt/hgfs/PLACED_2026/reports/"

# ==========================================================
# Read Snort Alerts
# ==========================================================

with open(SNORT_LOG, "r", errors="ignore") as f:
    snort_data = f.read()

# ==========================================================
# Read Sysmon Logs
# ==========================================================

with open(SYSMON_LOG, "r", errors="ignore") as f:
    sysmon_data = f.read()

# ==========================================================
# Extract Network Information from Snort
# ==========================================================

ip_matches = re.findall(
    r'(\d+\.\d+\.\d+\.\d+):\d+\s*->\s*(\d+\.\d+\.\d+\.\d+):\d+',
    snort_data
)

attacker_ips = set()
target_ips   = set()

for src, dst in ip_matches:
    attacker_ips.add(src)
    target_ips.add(dst)

# ==========================================================
# Analyze Network Behavior
# ==========================================================

syn_count = len(re.findall(r'SYN', snort_data, re.IGNORECASE))

if syn_count > 100:
    network_behavior = "Possible reconnaissance / port scanning activity detected"
elif syn_count > 20:
    network_behavior = "Suspicious SYN packet activity observed"
else:
    network_behavior = "Low suspicious network activity observed"

# ==========================================================
# Extract Applications from Sysmon
# ==========================================================

process_matches = re.findall(r'Image:\s*(.+)', sysmon_data)

applications = set()
for process in process_matches:
    process  = process.strip()
    app_name = process.split("\\")[-1]
    if app_name:
        applications.add(app_name)

# Interesting binaries only
interesting_processes = [
    "powershell.exe", "cmd.exe", "whoami.exe", "ipconfig.exe",
    "tasklist.exe", "schtasks.exe", "rundll32.exe", "wmic.exe",
    "net.exe", "net1.exe", "certutil.exe", "reg.exe",
    "bitsadmin.exe", "mshta.exe", "cscript.exe",
    "wscript.exe", "nmap.exe", "taskkill.exe"
]

filtered_apps = sorted([
    app for app in applications
    if app.lower() in [x.lower() for x in interesting_processes]
])

# ==========================================================
# Extract All Command Lines
# ==========================================================

command_matches = re.findall(r'CommandLine:\s*(.+)', sysmon_data)

commands = []
seen     = set()
for command in command_matches:
    command = command.strip()
    if command and command not in seen:
        commands.append(command)
        seen.add(command)

# ==========================================================
# Detect Suspicious Commands
# ==========================================================

suspicious_keywords = [
    "powershell", "-enc", "cmd.exe", "whoami", "ipconfig",
    "tasklist", "net user", "schtasks",
    "rundll32", "nmap"
]

suspicious_activity = []
seen_suspicious     = set()

# Patterns that look suspicious by keyword but are known system/benign activity
command_noise_patterns = [
    "AppXDeploymentExtensions",
    "ShellRefresh",
    "acproxy.dll",
    "GeneralTel.dll",
    "SHCreateLocalServerRunDll",
    "EDGEHTML.dll",
    "qe Microsoft-Windows-Sysmon",
    "PerformAutochkOperations",
    "pushtoinstall registration",
    "wevtutil.exe install-manifest",
    "wevtutil.exe uninstall-manifest",
    "wevtutil install-manifest",
    "wevtutil uninstall-manifest",
    "protectionmanagement.dll",     # AV uninstall routine, not attack activity
    "ProgramData\\PLUG",            # lab setup artifact
    "ProgramData/PLUG",
    "C:\\ProgramData\\PLUG",
]

def is_bare_rundll32(cmd):
    """Returns True if rundll32 is called with no meaningful argument."""
    stripped = cmd.strip().strip('"')
    return stripped.lower().endswith("rundll32.exe")

for command in commands:
    for keyword in suspicious_keywords:
        if keyword.lower() in command.lower():
            is_noise = any(n.lower() in command.lower() for n in command_noise_patterns) \
                       or is_bare_rundll32(command)
            if not is_noise and command not in seen_suspicious:
                suspicious_activity.append(command)
                seen_suspicious.add(command)
            break

# ==========================================================
# PowerShell Decoder
# ==========================================================

def decode_powershell(command):
    """
    Attempts to decode a base64-encoded PowerShell -enc argument.
    Returns decoded string or None if decoding fails.
    """
    try:
        enc_match = re.search(r'-enc(?:odedCommand)?\s+([A-Za-z0-9+/=]+)', command, re.IGNORECASE)
        if enc_match:
            encoded = enc_match.group(1)
            # PowerShell encodes in UTF-16LE
            decoded = base64.b64decode(encoded).decode("utf-16-le")
            return decoded.strip()
    except Exception:
        pass
    return None

# ==========================================================
# INCIDENT TIMELINE — Fixed Parser
# ==========================================================
# Strategy: walk through sysmon_data line by line.
# Collect (UtcTime, CommandLine) pairs by tracking state.
# This avoids the fragile block-split approach.

timeline = []

lines         = sysmon_data.splitlines()
current_time  = None
current_cmd   = None

for line in lines:
    line = line.strip()

    utc_match = re.match(r'UtcTime:\s*(.+)', line)
    if utc_match:
        current_time = utc_match.group(1).strip()
        current_cmd  = None   # reset command for new event block
        continue

    cmd_match = re.match(r'CommandLine:\s*(.+)', line)
    if cmd_match and current_time:
        current_cmd = cmd_match.group(1).strip()

        # Only keep suspicious commands in the timeline
        for keyword in suspicious_keywords:
            if keyword.lower() in current_cmd.lower():

                # Filter out known system/benign noise
                noise_patterns = [
                    "AppXDeploymentExtensions",
                    "ShellRefresh",
                    "acproxy.dll",
                    "GeneralTel.dll",
                    "SHCreateLocalServerRunDll",
                    "EDGEHTML.dll",
                    "qe Microsoft-Windows-Sysmon",
                    "PerformAutochkOperations",
                    "wevtutil.exe install-manifest",
                    "wevtutil.exe uninstall-manifest",
                    "wevtutil install-manifest",
                    "wevtutil uninstall-manifest",
                ]
                is_noise = any(n.lower() in current_cmd.lower() for n in noise_patterns) \
                           or is_bare_rundll32(current_cmd)

                if not is_noise:
                    timeline.append((current_time, current_cmd))
                break

        current_time = None   # consumed; wait for next UtcTime
        current_cmd  = None

# Add network event at the front
if syn_count > 20:
    timeline.insert(0, ("Network Activity Detected", "TCP SYN scanning activity detected"))

# Sort by timestamp (network entry will sort to top naturally as it's non-numeric)
def sort_key(entry):
    ts = entry[0]
    try:
        return datetime.strptime(ts[:23], "%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        return datetime.min

timeline_sorted = sorted(
    [e for e in timeline if e[0] != "Network Activity Detected"],
    key=sort_key
)
# Put network event first if it exists
network_events = [e for e in timeline if e[0] == "Network Activity Detected"]
timeline_final = network_events + timeline_sorted

# ==========================================================
# Dynamic Behavior Analysis
# ==========================================================

behavior_notes = []
risk_factors   = []

# Network
if syn_count > 100:
    behavior_notes.append(
        "High-volume TCP SYN traffic indicates systematic port scanning "
        "consistent with pre-attack reconnaissance activity."
    )
    risk_factors.append("network_recon")

# Encoded PowerShell
enc_ps_found = any("-enc" in c.lower() for c in suspicious_activity)
if enc_ps_found:
    behavior_notes.append(
        "Encoded PowerShell execution was observed. Attackers commonly use "
        "base64 encoding to obfuscate malicious commands and evade basic detection."
    )
    risk_factors.append("obfuscated_execution")

# Log tampering
if any("wevtutil" in c.lower() for c in suspicious_activity):
    behavior_notes.append(
        "wevtutil.exe activity was detected, which is commonly associated with "
        "Windows event log manipulation or log clearing — a defensive evasion technique."
    )
    risk_factors.append("log_tampering")

# Persistence
if any("schtasks" in c.lower() for c in suspicious_activity):
    behavior_notes.append(
        "schtasks.exe was executed, which may indicate an attempt to establish "
        "persistence through scheduled task creation."
    )
    risk_factors.append("persistence_attempt")

# Enumeration
recon_commands = ["whoami", "ipconfig", "tasklist"]
recon_found = [kw for kw in recon_commands if any(kw in c.lower() for c in suspicious_activity)]
if recon_found:
    behavior_notes.append(
        f"System enumeration commands detected ({', '.join(recon_found)}). "
        "These are commonly used by attackers to map the target environment "
        "after initial access."
    )
    risk_factors.append("enumeration")

# rundll32 abuse
if any("rundll32" in c.lower() for c in suspicious_activity):
    behavior_notes.append(
        "rundll32.exe usage was flagged. This binary is frequently abused as a "
        "Living-off-the-Land (LOLBin) technique to execute malicious payloads "
        "while appearing legitimate."
    )
    risk_factors.append("lolbin_abuse")

# Fallback
if not behavior_notes:
    behavior_notes.append(
        "Endpoint and network telemetry suggest low-level suspicious activity. "
        "No high-confidence attack patterns were identified in this session."
    )

# ==========================================================
# Generate Timestamp + Filename
# ==========================================================

now          = datetime.now()
report_time  = now.strftime("%Y-%m-%d %H:%M:%S")
filename     = REPORT_DIR + f"soc_report_{now.strftime('%Y%m%d_%H%M%S')}.txt"

# ==========================================================
# Build Report
# ==========================================================

report = f"""
====================================================
            SOC ACTIVITY ANALYSIS REPORT
====================================================
Report Generated:
{report_time}
----------------------------------------------------
SUMMARY
----------------------------------------------------
  Attacker IPs Identified  : {len(attacker_ips)}
  Target IPs Identified    : {len(target_ips)}
  TCP SYN Packets Detected : {syn_count}
  Suspicious Apps Found    : {len(filtered_apps)}
  Suspicious Commands      : {len(suspicious_activity)}
  Timeline Events          : {len(timeline_final)}
----------------------------------------------------
Observed Attacker IPs:"""

for ip in attacker_ips:
    report += f"\n- {ip}"

report += "\n\nObserved Target IPs:"
for ip in target_ips:
    report += f"\n- {ip}"

report += f"""
----------------------------------------------------
Observed Network Activity:
- TCP SYN packets detected: {syn_count}
- {network_behavior}
----------------------------------------------------
Observed Suspicious Applications:"""

if filtered_apps:
    for app in filtered_apps:
        report += f"\n- {app}"
else:
    report += "\n- No suspicious applications identified"

report += """
----------------------------------------------------
Observed Suspicious Commands:"""

if suspicious_activity:
    for cmd in suspicious_activity[:15]:
        report += f"\n- {cmd}"

        # Inline PowerShell decode
        decoded = decode_powershell(cmd)
        if decoded:
            report += f"\n  [Decoded PowerShell] --> {decoded}"
else:
    report += "\n- No suspicious commands identified"

report += """
----------------------------------------------------
INCIDENT TIMELINE:"""

if timeline_final:
    for ts, event in timeline_final[:25]:
        report += f"\n- {ts} --> {event}"

        # Decode PowerShell inline in timeline too
        decoded = decode_powershell(event)
        if decoded:
            report += f"\n  [Decoded] --> {decoded}"
else:
    report += "\n- No timeline events generated"

report += """
----------------------------------------------------
Behavior Analysis:"""

for note in behavior_notes:
    report += f"\n{note}\n"

report += """
----------------------------------------------------
Recommendations:"""

# Dynamic recommendations based on what was actually found
if "network_recon" in risk_factors:
    report += "\n- Investigate repeated scanning activity from flagged source IP"
if "obfuscated_execution" in risk_factors:
    report += "\n- Review and decode all encoded PowerShell commands"
if "log_tampering" in risk_factors:
    report += "\n- Urgently review wevtutil activity — possible log clearing attempt"
if "persistence_attempt" in risk_factors:
    report += "\n- Audit scheduled tasks for unauthorized entries"
if "enumeration" in risk_factors:
    report += "\n- Investigate system enumeration — may indicate post-access recon"
if "lolbin_abuse" in risk_factors:
    report += "\n- Review rundll32.exe execution context and loaded DLLs"

# Always include these
report += """
- Correlate endpoint and network telemetry across sessions
- Archive logs for forensic retention
----------------------------------------------------
Conclusion:
The SOC monitoring environment successfully
correlated endpoint telemetry and network alerts
to identify suspicious activity patterns.

The project demonstrated:
- Endpoint monitoring using Sysmon
- Intrusion detection using Snort 3
- Packet analysis using Wireshark
- Event correlation and automated reporting
- Chronological incident reconstruction
- Encoded PowerShell detection and decoding
- Dynamic behavior analysis
====================================================
"""

# ==========================================================
# Save Report
# ==========================================================

import os
os.makedirs(os.path.dirname(filename), exist_ok=True)

with open(filename, "w") as report_file:
    report_file.write(report)

# ==========================================================
# Display Report
# ==========================================================

print(report)
print(f"\n[+] SOC analysis report saved as:\n{filename}")
