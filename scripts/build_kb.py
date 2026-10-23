#!/usr/bin/env python3
"""Build the offline knowledge base (data/*.json) for the planner.

The knowledge base is *curated reference data*, not synthetic sample data: it
encodes a slice of the public MITRE ATT&CK Enterprise matrix (technique id,
name, tactic, a short plain-language description, the ATT&CK data sources, and
the common Windows/Sysmon log events that carry the telemetry), six
threat-actor archetypes modelled on public reporting (generic names, no claims
about specific named groups), a technique -> Atomic Red Team *test identifier*
map (IDs and titles only, never commands or payloads), and a technique ->
detection-idea map (Sigma rule titles, Splunk/KQL pseudo-logic, and references
to the owner's own detection repositories).

Run ``python scripts/build_kb.py`` to regenerate ``data/techniques.json``,
``data/actor_profiles.json``, ``data/atomic_map.json`` and
``data/detections.json``. The planner never needs this script at runtime; the
JSON files are the committed source of truth. Keeping the builder in the repo
makes the KB reviewable and reproducible.
"""

from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Canonical ATT&CK tactic order used everywhere in the project.
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Each tuple: (id, name, tactic, description, data_sources, log_events)
T = [
    # ------------------------------------------------------------------ recon
    ("T1595", "Active Scanning", "reconnaissance",
     "Adversary probes victim infrastructure (ports, vulnerabilities) before access.",
     ["Network Traffic"], ["Firewall/NetFlow connection logs", "Zeek conn.log"]),
    ("T1592", "Gather Victim Host Information", "reconnaissance",
     "Collecting details about victim hosts (OS, hardware) from open sources.",
     ["Internet Scan"], ["Web server access logs"]),
    ("T1589", "Gather Victim Identity Information", "reconnaissance",
     "Harvesting employee names, emails and credentials from public sources.",
     ["Internet Scan"], ["External OSINT (no internal telemetry)"]),
    ("T1598", "Phishing for Information", "reconnaissance",
     "Soliciting information from targets via deceptive messages.",
     ["Application Log"], ["Email gateway logs", "Message trace"]),
    # ------------------------------------------------------------- resource-dev
    ("T1583", "Acquire Infrastructure", "resource-development",
     "Buying or leasing domains, servers or services used to stage operations.",
     ["Internet Scan"], ["Passive DNS", "Certificate transparency"]),
    ("T1585", "Establish Accounts", "resource-development",
     "Creating social-media or email accounts to support targeting.",
     ["Persona"], ["(external, no internal telemetry)"]),
    ("T1588", "Obtain Capabilities", "resource-development",
     "Acquiring tooling, exploits or certificates rather than developing them.",
     ["Malware Repository"], ["Threat-intel feeds"]),
    # -------------------------------------------------------------- initial-access
    ("T1566", "Phishing", "initial-access",
     "Sending deceptive messages to induce execution or credential entry.",
     ["Application Log", "Network Traffic"], ["Email gateway logs", "Proxy logs"]),
    ("T1566.001", "Spearphishing Attachment", "initial-access",
     "Targeted email carrying a malicious attachment to be opened by the user.",
     ["Application Log", "File"], ["Email gateway logs", "Sysmon 11 (file create)"]),
    ("T1566.002", "Spearphishing Link", "initial-access",
     "Targeted email with a link to a credential-harvest or malware page.",
     ["Application Log", "Network Traffic"], ["Email gateway logs", "Proxy/URL logs"]),
    ("T1190", "Exploit Public-Facing Application", "initial-access",
     "Exploiting an internet-exposed application to gain a foothold.",
     ["Application Log", "Network Traffic"], ["Web/WAF logs", "Sysmon 1 (web app child process)"]),
    ("T1133", "External Remote Services", "initial-access",
     "Using exposed remote services (VPN, RDP gateway, Citrix) to enter.",
     ["Logon Session", "Network Traffic"], ["VPN logs", "Security 4624 (type 10)"]),
    ("T1078", "Valid Accounts", "initial-access",
     "Using legitimate credentials to access systems and blend in.",
     ["Logon Session"], ["Security 4624", "SigninLogs"]),
    ("T1078.002", "Valid Accounts: Domain Accounts", "initial-access",
     "Using compromised domain credentials across the environment.",
     ["Logon Session"], ["Security 4624", "Security 4768/4769 (TGT/TGS)"]),
    ("T1199", "Trusted Relationship", "initial-access",
     "Abusing a trusted third-party or MSP connection to reach the target.",
     ["Logon Session"], ["VPN logs", "Security 4624"]),
    ("T1189", "Drive-by Compromise", "initial-access",
     "User's browser is compromised by visiting a malicious or watering-hole site.",
     ["Network Traffic", "Process"], ["Proxy logs", "Sysmon 1 (browser child)"]),
    # ------------------------------------------------------------------ execution
    ("T1059", "Command and Scripting Interpreter", "execution",
     "Abusing command and script interpreters to run adversary code.",
     ["Process", "Command"], ["Security 4688", "Sysmon 1"]),
    ("T1059.001", "PowerShell", "execution",
     "Using PowerShell for execution, often encoded or with download cradles.",
     ["Process", "Command", "Script"], ["Security 4688", "Sysmon 1", "PowerShell 4104 (script block)"]),
    ("T1059.003", "Windows Command Shell", "execution",
     "Using cmd.exe to run commands, chain tools and batch scripts.",
     ["Process", "Command"], ["Security 4688", "Sysmon 1"]),
    ("T1059.005", "Visual Basic", "execution",
     "Executing VBScript/VBA, frequently from Office macros.",
     ["Process", "Script"], ["Sysmon 1", "Security 4688"]),
    ("T1059.006", "Python", "execution",
     "Using a Python interpreter to execute cross-platform tooling.",
     ["Process", "Command"], ["Security 4688", "auditd execve"]),
    ("T1204.002", "User Execution: Malicious File", "execution",
     "User opens a delivered file (document, LNK, ISO) that runs code.",
     ["Process", "File"], ["Sysmon 1", "Sysmon 11"]),
    ("T1047", "Windows Management Instrumentation", "execution",
     "Using WMI to execute commands locally or on remote hosts.",
     ["Process", "Command"], ["Sysmon 1 (WmiPrvSE child)", "Security 4688"]),
    ("T1569.002", "System Services: Service Execution", "execution",
     "Running a binary by creating/starting a Windows service.",
     ["Process", "Service"], ["Security 7045", "Security 4697", "Sysmon 1"]),
    ("T1106", "Native API", "execution",
     "Executing via direct OS API calls to avoid spawning command-line tools.",
     ["Process", "Module"], ["Sysmon 1", "ETW"]),
    # ---------------------------------------------------------------- persistence
    ("T1136.001", "Create Account: Local Account", "persistence",
     "Creating a local account to retain access to a host.",
     ["User Account"], ["Security 4720"]),
    ("T1098", "Account Manipulation", "persistence",
     "Modifying accounts (group membership, credentials) to keep access.",
     ["User Account", "Group"], ["Security 4728/4732/4756", "Security 4738"]),
    ("T1547.001", "Registry Run Keys / Startup Folder", "persistence",
     "Adding a program to Run keys or the Startup folder for autostart.",
     ["Windows Registry", "File"], ["Sysmon 13 (registry set)", "Sysmon 11 (startup file)"]),
    ("T1543.003", "Create or Modify System Process: Windows Service", "persistence",
     "Installing or altering a Windows service for persistence/SYSTEM.",
     ["Service", "Process"], ["Security 7045", "Security 4697", "Sysmon 13"]),
    ("T1053.005", "Scheduled Task", "persistence",
     "Creating a scheduled task that re-launches payloads.",
     ["Scheduled Job", "Process"], ["Security 4698", "Sysmon 1 (schtasks)"]),
    ("T1505.003", "Server Software Component: Web Shell", "persistence",
     "Planting a web shell on a server for remote command execution.",
     ["File", "Network Traffic"], ["Web server logs", "Sysmon 11", "Sysmon 1 (w3wp child)"]),
    ("T1574.002", "Hijack Execution Flow: DLL Side-Loading", "persistence",
     "Placing a malicious DLL next to a signed binary that loads it.",
     ["Module", "File"], ["Sysmon 7 (image load)", "Sysmon 11"]),
    ("T1197", "BITS Jobs", "persistence",
     "Using the BITS service to download and persist payloads stealthily.",
     ["Process", "Network Traffic"], ["Sysmon 1 (bitsadmin)", "BITS-Client 4104"]),
    ("T1546.003", "WMI Event Subscription", "persistence",
     "Registering a permanent WMI event consumer to trigger code.",
     ["WMI", "Process"], ["Sysmon 19/20/21 (WMI event)"]),
    # --------------------------------------------------------- privilege-escalation
    ("T1548.002", "Abuse Elevation Control: Bypass UAC", "privilege-escalation",
     "Bypassing User Account Control to elevate without a prompt.",
     ["Process", "Windows Registry"], ["Sysmon 1", "Sysmon 13"]),
    ("T1134", "Access Token Manipulation", "privilege-escalation",
     "Manipulating access tokens to run code in another security context.",
     ["Process"], ["Security 4624 (type 9)", "Sysmon 1"]),
    ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
     "Exploiting a software/kernel flaw to gain higher privileges.",
     ["Process", "Driver"], ["Sysmon 1", "Sysmon 6 (driver load)"]),
    ("T1055", "Process Injection", "privilege-escalation",
     "Injecting code into another process to evade defenses and elevate.",
     ["Process", "Module"], ["Sysmon 8 (CreateRemoteThread)", "Sysmon 10 (process access)"]),
    ("T1484.001", "Domain Policy Modification: Group Policy", "privilege-escalation",
     "Altering Group Policy to push privileged changes domain-wide.",
     ["Active Directory", "Command"], ["Security 5136 (DS object modified)"]),
    # ------------------------------------------------------------- defense-evasion
    ("T1070.001", "Indicator Removal: Clear Windows Event Logs", "defense-evasion",
     "Clearing event logs to remove traces of activity.",
     ["Windows Registry", "Command"], ["Security 1102", "System 104"]),
    ("T1070.004", "Indicator Removal: File Deletion", "defense-evasion",
     "Deleting files dropped during the operation.",
     ["File", "Command"], ["Sysmon 23 (file delete)", "Security 4688"]),
    ("T1027", "Obfuscated Files or Information", "defense-evasion",
     "Encoding or packing files and commands to hinder analysis.",
     ["File", "Command"], ["Sysmon 1", "PowerShell 4104"]),
    ("T1027.010", "Command Obfuscation", "defense-evasion",
     "Obscuring command-line content (encoding, concatenation).",
     ["Command"], ["Security 4688", "PowerShell 4104"]),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion",
     "Disabling or tampering with security software.",
     ["Windows Registry", "Service", "Command"], ["Security 4688", "Defender 5001", "Sysmon 13"]),
    ("T1562.002", "Impair Defenses: Disable Windows Event Logging", "defense-evasion",
     "Turning off or weakening Windows audit logging.",
     ["Windows Registry", "Command"], ["Security 4719", "Security 4688"]),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", "defense-evasion",
     "Using rundll32.exe to proxy execution of code.",
     ["Process", "Command"], ["Sysmon 1", "Security 4688"]),
    ("T1218.005", "System Binary Proxy Execution: Mshta", "defense-evasion",
     "Using mshta.exe to execute HTA/script content.",
     ["Process", "Command"], ["Sysmon 1", "Security 4688"]),
    ("T1036", "Masquerading", "defense-evasion",
     "Naming/placing tools to look legitimate (e.g. svchost in user path).",
     ["Process", "File"], ["Sysmon 1", "Security 4688"]),
    ("T1112", "Modify Registry", "defense-evasion",
     "Changing registry keys to evade defenses or hide configuration.",
     ["Windows Registry"], ["Sysmon 13", "Security 4657"]),
    ("T1140", "Deobfuscate/Decode Files or Information", "defense-evasion",
     "Decoding staged payloads on the host (certutil, base64).",
     ["Process", "Command"], ["Sysmon 1 (certutil)", "Security 4688"]),
    # ------------------------------------------------------------- credential-access
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access",
     "Reading LSASS memory to extract credentials.",
     ["Process", "Command"], ["Sysmon 10 (lsass access)", "Security 4688"]),
    ("T1003.002", "OS Credential Dumping: SAM", "credential-access",
     "Extracting the local SAM database for password hashes.",
     ["Windows Registry", "File", "Command"], ["Sysmon 1 (reg save)", "Security 4688"]),
    ("T1003.003", "OS Credential Dumping: NTDS", "credential-access",
     "Copying NTDS.dit from a domain controller for all domain hashes.",
     ["File", "Command"], ["Sysmon 1 (ntdsutil/vssadmin)", "Security 4688"]),
    ("T1110.003", "Brute Force: Password Spraying", "credential-access",
     "Trying one/few passwords across many accounts to avoid lockout.",
     ["Logon Session", "User Account"], ["Security 4625", "Security 4771", "SigninLogs"]),
    ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "credential-access",
     "Requesting service tickets to crack SPN account passwords offline.",
     ["Logon Session"], ["Security 4769 (RC4/0x17)"]),
    ("T1555", "Credentials from Password Stores", "credential-access",
     "Extracting credentials from browsers, vaults and credential managers.",
     ["Process", "File"], ["Sysmon 10", "Sysmon 11"]),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access",
     "Searching files/scripts for plaintext credentials.",
     ["File", "Command"], ["Sysmon 1 (findstr)", "Security 4688"]),
    ("T1056.001", "Input Capture: Keylogging", "credential-access",
     "Recording keystrokes to capture credentials and data.",
     ["Process"], ["Sysmon 1", "Sysmon 10"]),
    # ------------------------------------------------------------------- discovery
    ("T1087.002", "Account Discovery: Domain Account", "discovery",
     "Enumerating domain accounts and groups.",
     ["Process", "Command"], ["Security 4688 (net/dsquery)", "Security 4661"]),
    ("T1082", "System Information Discovery", "discovery",
     "Collecting host OS, hardware and configuration details.",
     ["Process", "Command"], ["Security 4688 (systeminfo)", "Sysmon 1"]),
    ("T1083", "File and Directory Discovery", "discovery",
     "Enumerating files and directories of interest.",
     ["Process", "Command"], ["Sysmon 1", "Security 4688"]),
    ("T1018", "Remote System Discovery", "discovery",
     "Discovering other hosts on the network.",
     ["Process", "Command", "Network Traffic"], ["Security 4688 (net view/ping)", "Sysmon 3"]),
    ("T1057", "Process Discovery", "discovery",
     "Listing running processes to understand the host.",
     ["Process", "Command"], ["Security 4688 (tasklist)", "Sysmon 1"]),
    ("T1016", "System Network Configuration Discovery", "discovery",
     "Enumerating local network configuration and connections.",
     ["Process", "Command"], ["Security 4688 (ipconfig/netstat)", "Sysmon 1"]),
    ("T1046", "Network Service Discovery", "discovery",
     "Scanning for reachable services on internal hosts.",
     ["Network Traffic", "Process"], ["Sysmon 3", "Firewall/NetFlow"]),
    ("T1482", "Domain Trust Discovery", "discovery",
     "Enumerating domain trust relationships for lateral paths.",
     ["Process", "Command"], ["Security 4688 (nltest)", "Sysmon 1"]),
    ("T1069.002", "Permission Groups Discovery: Domain Groups", "discovery",
     "Enumerating domain groups (e.g. Domain Admins).",
     ["Process", "Command"], ["Security 4688 (net group)", "Security 4661"]),
    # ------------------------------------------------------------- lateral-movement
    ("T1021.001", "Remote Services: RDP", "lateral-movement",
     "Moving between hosts via Remote Desktop.",
     ["Logon Session", "Network Traffic"], ["Security 4624 (type 10)", "Security 4778"]),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement",
     "Using admin shares (C$, ADMIN$) to move and execute.",
     ["Logon Session", "Network Share"], ["Security 4624 (type 3)", "Security 5140", "Sysmon 1 (psexec)"]),
    ("T1021.006", "Remote Services: Windows Remote Management", "lateral-movement",
     "Using WinRM/PowerShell Remoting to run commands remotely.",
     ["Logon Session", "Process"], ["Security 4624", "Sysmon 1 (wsmprovhost child)"]),
    ("T1570", "Lateral Tool Transfer", "lateral-movement",
     "Copying tools between hosts inside the network.",
     ["Network Share", "File"], ["Security 5145", "Sysmon 11"]),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "lateral-movement",
     "Authenticating with a stolen NTLM hash instead of a password.",
     ["Logon Session"], ["Security 4624 (type 3, NTLM)", "Security 4776"]),
    ("T1210", "Exploitation of Remote Services", "lateral-movement",
     "Exploiting a vulnerable internal service to move laterally.",
     ["Network Traffic", "Process"], ["IDS alerts", "Sysmon 1"]),
    # ------------------------------------------------------------------ collection
    ("T1005", "Data from Local System", "collection",
     "Collecting files of interest from a compromised host.",
     ["File", "Command"], ["Sysmon 1", "Security 4663"]),
    ("T1039", "Data from Network Shared Drive", "collection",
     "Collecting data from accessible network shares.",
     ["Network Share", "File"], ["Security 5140/5145", "Sysmon 11"]),
    ("T1560.001", "Archive Collected Data: Archive via Utility", "collection",
     "Compressing/encrypting staged data with an archiver before exfil.",
     ["Process", "Command", "File"], ["Sysmon 1 (rar/7z/tar)", "Sysmon 11"]),
    ("T1114", "Email Collection", "collection",
     "Collecting email content from local or server mailboxes.",
     ["Application Log", "File"], ["OfficeActivity", "Exchange logs"]),
    ("T1113", "Screen Capture", "collection",
     "Capturing screenshots of the victim desktop.",
     ["Process"], ["Sysmon 1", "ETW"]),
    # --------------------------------------------------------------- command-and-control
    ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control",
     "C2 over HTTP/HTTPS blending with normal web traffic.",
     ["Network Traffic"], ["Proxy logs", "Zeek http.log", "Sysmon 3"]),
    ("T1071.004", "Application Layer Protocol: DNS", "command-and-control",
     "C2 or exfil tunnelled over DNS queries.",
     ["Network Traffic"], ["DNS logs", "Zeek dns.log"]),
    ("T1105", "Ingress Tool Transfer", "command-and-control",
     "Downloading additional tools from external infrastructure.",
     ["Network Traffic", "File"], ["Proxy logs", "Sysmon 1/3/11"]),
    ("T1572", "Protocol Tunneling", "command-and-control",
     "Tunnelling traffic within another protocol to bypass controls.",
     ["Network Traffic"], ["Firewall/NetFlow", "Zeek conn.log"]),
    ("T1090", "Proxy", "command-and-control",
     "Routing C2 through intermediary proxies/relays.",
     ["Network Traffic"], ["Proxy logs", "Firewall logs"]),
    ("T1573", "Encrypted Channel", "command-and-control",
     "Encrypting C2 traffic to hide its content.",
     ["Network Traffic"], ["TLS/JA3 logs", "Zeek ssl.log"]),
    # ----------------------------------------------------------------- exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration",
     "Sending stolen data out over the existing C2 channel.",
     ["Network Traffic"], ["Proxy logs", "NetFlow byte counts"]),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration",
     "Exfiltrating over a protocol different from the C2 channel.",
     ["Network Traffic"], ["DNS/FTP/SMTP logs", "NetFlow"]),
    ("T1567.002", "Exfiltration to Cloud Storage", "exfiltration",
     "Uploading data to a cloud storage service.",
     ["Network Traffic"], ["Proxy logs", "CASB logs"]),
    ("T1020", "Automated Exfiltration", "exfiltration",
     "Automatically transferring collected data on a schedule.",
     ["Network Traffic", "Command"], ["NetFlow", "Sysmon 3"]),
    # ----------------------------------------------------------------------- impact
    ("T1486", "Data Encrypted for Impact", "impact",
     "Encrypting data to disrupt operations and demand ransom.",
     ["File", "Process", "Command"], ["Sysmon 11 (mass writes)", "Security 4663"]),
    ("T1490", "Inhibit System Recovery", "impact",
     "Deleting shadow copies/backups to prevent recovery.",
     ["Process", "Command"], ["Sysmon 1 (vssadmin/wbadmin/bcdedit)", "Security 4688"]),
    ("T1489", "Service Stop", "impact",
     "Stopping services (databases, security) before encryption.",
     ["Service", "Process"], ["Security 7036", "Security 4688 (net stop)"]),
    ("T1485", "Data Destruction", "impact",
     "Destroying data/files to disrupt availability.",
     ["File", "Command"], ["Sysmon 23", "Security 4663"]),
    ("T1529", "System Shutdown/Reboot", "impact",
     "Shutting down or rebooting systems to disrupt or complete impact.",
     ["Process", "Command"], ["System 1074", "Security 4688 (shutdown)"]),
]


def build_techniques() -> list[dict]:
    rows = []
    for tid, name, tactic, desc, ds, logs in T:
        rows.append({
            "id": tid,
            "name": name,
            "tactic": tactic,
            "description": desc,
            "data_sources": ds,
            "log_events": logs,
        })
    return rows


# Technique -> list of Atomic Red Team test *identifiers* (id + title only).
# Titles describe the intent of each public atomic test; no commands here.
ATOMIC = {
    "T1059.001": [("T1059.001-1", "Mshta/PowerShell download cradle"),
                  ("T1059.001-2", "PowerShell -EncodedCommand execution"),
                  ("T1059.001-5", "PowerShell invoke known malicious cmdlet name")],
    "T1059.003": [("T1059.003-1", "Create and execute a batch script"),
                  ("T1059.003-4", "Simulate a common command-shell recon one-liner")],
    "T1047": [("T1047-1", "WMI reconnaissance of users/processes"),
              ("T1047-4", "WMI process creation locally")],
    "T1053.005": [("T1053.005-1", "Scheduled task via schtasks"),
                  ("T1053.005-6", "Scheduled task that re-runs at logon")],
    "T1543.003": [("T1543.003-1", "Create a Windows service (sc create)"),
                  ("T1543.003-4", "Modify an existing service binary path")],
    "T1136.001": [("T1136.001-1", "Create a local user account"),
                  ("T1136.001-3", "Create a local account and add to a group")],
    "T1098": [("T1098-2", "Add user to a privileged local group")],
    "T1547.001": [("T1547.001-1", "Add a Run key for persistence"),
                  ("T1547.001-7", "Drop a shortcut in the Startup folder")],
    "T1548.002": [("T1548.002-1", "Bypass UAC using a known auto-elevate path")],
    "T1070.001": [("T1070.001-1", "Clear the Windows Security event log"),
                  ("T1070.001-2", "Clear all event logs via wevtutil")],
    "T1562.001": [("T1562.001-1", "Disable a security product service"),
                  ("T1562.001-7", "Add a tampering exclusion")],
    "T1562.002": [("T1562.002-1", "Disable Windows event logging service")],
    "T1218.011": [("T1218.011-1", "Rundll32 executing a DLL export")],
    "T1218.005": [("T1218.005-1", "Mshta executing a local HTA")],
    "T1003.001": [("T1003.001-1", "Dump LSASS via a known tool"),
                  ("T1003.001-2", "Create a LSASS minidump with comsvcs.dll")],
    "T1003.002": [("T1003.002-1", "Save SAM/SYSTEM registry hives")],
    "T1003.003": [("T1003.003-1", "Copy NTDS.dit via volume shadow copy"),
                  ("T1003.003-4", "ntdsutil IFM database dump")],
    "T1110.003": [("T1110.003-1", "Password spray against local accounts"),
                  ("T1110.003-2", "Domain password spray simulation")],
    "T1558.003": [("T1558.003-1", "Request RC4 service tickets (kerberoast)")],
    "T1552.001": [("T1552.001-1", "Search files for plaintext credentials")],
    "T1087.002": [("T1087.002-1", "Enumerate domain accounts with net/dsquery")],
    "T1082": [("T1082-1", "Collect system information")],
    "T1018": [("T1018-1", "Remote system discovery via net view")],
    "T1057": [("T1057-1", "Process discovery via tasklist")],
    "T1016": [("T1016-1", "Network configuration discovery")],
    "T1482": [("T1482-1", "Domain trust discovery via nltest")],
    "T1069.002": [("T1069.002-1", "Enumerate domain groups")],
    "T1021.001": [("T1021.001-1", "RDP session to a remote host")],
    "T1021.002": [("T1021.002-1", "Copy and execute via admin share"),
                  ("T1021.002-3", "PsExec-style remote service execution")],
    "T1021.006": [("T1021.006-1", "Execute a command via WinRM")],
    "T1550.002": [("T1550.002-1", "Pass-the-hash simulation with a test tool")],
    "T1560.001": [("T1560.001-1", "Archive data with a command-line utility")],
    "T1071.001": [("T1071.001-1", "Beacon-like HTTP requests to a test server")],
    "T1071.004": [("T1071.004-1", "DNS queries with encoded subdomains")],
    "T1105": [("T1105-1", "Download a file with certutil"),
              ("T1105-6", "Download a file with PowerShell")],
    "T1041": [("T1041-1", "Exfiltrate a file over the C2 HTTP channel")],
    "T1048": [("T1048-1", "Exfiltrate over DNS"),
              ("T1048-2", "Exfiltrate over unencrypted protocol")],
    "T1567.002": [("T1567.002-1", "Upload a file to cloud storage")],
    "T1486": [("T1486-1", "Encrypt files in a test directory (reversible)")],
    "T1490": [("T1490-1", "Delete volume shadow copies with vssadmin"),
              ("T1490-3", "Disable recovery with bcdedit")],
    "T1489": [("T1489-1", "Stop a service with net stop")],
    "T1140": [("T1140-1", "Decode a base64 payload with certutil")],
    "T1036": [("T1036-1", "Rename a tool to masquerade as a system binary")],
    "T1055": [("T1055-1", "Process injection into a benign test process")],
    "T1497": [],  # placeholder guard (not in KB) - intentionally empty, dropped below
}


# Technique -> detection ideas. Each idea: type, title, logic (pseudo), repo.
REPO_SENTINEL = "microsoft-sentinel-detection-engineering"
REPO_SPLUNK = "splunk-threat-detection-lab"
REPO_SIEM = "siem-from-scratch"

DETECTIONS = {
    "T1059.001": [
        {"type": "sigma", "title": "Encoded PowerShell Command Line",
         "logic": "process == powershell AND command_line contains '-enc'/'-encodedcommand'",
         "repo": REPO_SPLUNK},
        {"type": "kql", "title": "sec-4688-encoded-powershell",
         "logic": "SecurityEvent | where NewProcessName endswith 'powershell.exe' and CommandLine matches regex '-e[ncodema]* [A-Za-z0-9+/=]{30,}'",
         "repo": REPO_SENTINEL},
    ],
    "T1059.003": [
        {"type": "splunk", "title": "Suspicious cmd.exe child of Office",
         "logic": "index=win EventCode=1 ParentImage=*winword.exe Image=*cmd.exe | stats count by host,User",
         "repo": REPO_SPLUNK},
    ],
    "T1566.001": [
        {"type": "sigma", "title": "Office Application Spawning Script Host",
         "logic": "parent in (winword,excel,outlook) AND child in (cmd,powershell,wscript,mshta)",
         "repo": REPO_SPLUNK},
    ],
    "T1047": [
        {"type": "kql", "title": "WmiPrvSE spawning shells",
         "logic": "Sysmon 1 | where ParentImage endswith 'WmiPrvSE.exe' and Image has_any ('cmd.exe','powershell.exe')",
         "repo": REPO_SENTINEL},
    ],
    "T1053.005": [
        {"type": "kql", "title": "sec-4698-scheduled-task-created",
         "logic": "SecurityEvent EventID==4698 | parse task XML for Command/Arguments; flag scripting hosts & user-writable paths",
         "repo": REPO_SENTINEL},
    ],
    "T1543.003": [
        {"type": "kql", "title": "sec-7045-new-service-installed",
         "logic": "union SecurityEvent(4697), Event(System 7045) | where ImagePath suspicious or random 8-16 char name",
         "repo": REPO_SENTINEL},
    ],
    "T1136.001": [
        {"type": "kql", "title": "sec-4720-local-account-created",
         "logic": "SecurityEvent EventID==4720 where SubjectUserName !endswith '$'",
         "repo": REPO_SENTINEL},
    ],
    "T1098": [
        {"type": "kql", "title": "sec-4728-4732-privileged-group-add",
         "logic": "SecurityEvent EventID in (4728,4732,4756) and GroupName in tier0 list",
         "repo": REPO_SENTINEL},
    ],
    "T1547.001": [
        {"type": "sigma", "title": "Run Key Persistence Set",
         "logic": "Sysmon 13 TargetObject contains '\\CurrentVersion\\Run'",
         "repo": REPO_SIEM},
    ],
    "T1070.001": [
        {"type": "kql", "title": "sec-1102-security-log-cleared",
         "logic": "SecurityEvent EventID==1102 (any)",
         "repo": REPO_SENTINEL},
        {"type": "splunk", "title": "Windows Event Log Cleared (1102/104)",
         "logic": "index=win (EventCode=1102 OR EventCode=104) | stats count by host,user",
         "repo": REPO_SPLUNK},
    ],
    "T1562.002": [
        {"type": "kql", "title": "sec-4719-audit-policy-changed",
         "logic": "SecurityEvent EventID==4719 removing success/failure auditing by human account",
         "repo": REPO_SENTINEL},
    ],
    "T1003.001": [
        {"type": "kql", "title": "mde-lsass-memory-dump",
         "logic": "DeviceProcessEvents | procdump/comsvcs MiniDump/known dumpers targeting lsass",
         "repo": REPO_SENTINEL},
        {"type": "sigma", "title": "LSASS Access by Non-Allowlisted Process",
         "logic": "Sysmon 10 TargetImage=lsass.exe AND SourceImage NOT in allowlist AND GrantedAccess in (0x1010,0x1410,0x1fffff)",
         "repo": REPO_SPLUNK},
    ],
    "T1003.003": [
        {"type": "splunk", "title": "NTDS.dit Extraction Indicators",
         "logic": "EventCode=1 (Image=*ntdsutil.exe OR CommandLine=*ntds* OR CommandLine=*vssadmin*create*)",
         "repo": REPO_SPLUNK},
    ],
    "T1110.003": [
        {"type": "kql", "title": "signin-password-spray-by-ip / sec-4776-ntlm-password-spray",
         "logic": "group failures by source; DistinctUsers>=10 AND AttemptsPerAccount<=3 within 1h",
         "repo": REPO_SENTINEL},
        {"type": "splunk", "title": "Password Spraying - One Source Many Accounts",
         "logic": "EventCode=4625 | stats dc(Account_Name) as users by src | where users>=10",
         "repo": REPO_SPLUNK},
    ],
    "T1558.003": [
        {"type": "sigma", "title": "Kerberoasting - RC4 Service Ticket Requests",
         "logic": "Security 4769 TicketEncryptionType=0x17 AND ServiceName != krbtgt | stats by Account",
         "repo": REPO_SIEM},
    ],
    "T1021.001": [
        {"type": "kql", "title": "tdl-005 RDP to multiple hosts by one user",
         "logic": "Security 4624 LogonType==10 | summarize dc(Computer) by Account within 1h >= N",
         "repo": REPO_SPLUNK},
    ],
    "T1021.002": [
        {"type": "splunk", "title": "SMB Admin Share Fan-Out",
         "logic": "EventCode=5140 ShareName in (ADMIN$,C$) | stats dc(dest) by src_user",
         "repo": REPO_SPLUNK},
    ],
    "T1550.002": [
        {"type": "sigma", "title": "Pass-the-Hash NTLM Logon",
         "logic": "Security 4624 LogonType=3 AuthenticationPackage=NTLM AND KeyLength=0 (and 4776)",
         "repo": REPO_SIEM},
    ],
    "T1071.001": [
        {"type": "kql", "title": "csl-firewall-beaconing",
         "logic": "CommonSecurityLog | inter-arrival via prev(); >=20 conns, jitter<10%, period 30s-1h",
         "repo": REPO_SENTINEL},
        {"type": "splunk", "title": "tdl-011 Beaconing Regular Interval",
         "logic": "compute delta between outbound conns per src,dst,port; low stdev/mean",
         "repo": REPO_SPLUNK},
    ],
    "T1071.004": [
        {"type": "splunk", "title": "tdl-009/010 DNS Tunneling",
         "logic": "dns | eval len=len(query) | stats avg(len) dc(subdomain) by domain | where long names / many subdomains",
         "repo": REPO_SPLUNK},
    ],
    "T1105": [
        {"type": "sigma", "title": "Certutil/BITS/PowerShell Download Cradle",
         "logic": "process in (certutil,bitsadmin,powershell) AND command_line contains url / '-urlcache' / 'DownloadString'",
         "repo": REPO_SIEM},
    ],
    "T1486": [
        {"type": "sigma", "title": "Mass File Modification (Ransomware)",
         "logic": "Sysmon 11 | high rate of writes/renames with uncommon extension by one process",
         "repo": REPO_SIEM},
    ],
    "T1490": [
        {"type": "splunk", "title": "Shadow Copy / Backup Deletion",
         "logic": "EventCode=1 (Image=*vssadmin* delete shadows OR *wbadmin* delete OR *bcdedit* recoveryenabled no)",
         "repo": REPO_SPLUNK},
    ],
    "T1489": [
        {"type": "sigma", "title": "Service Stop Before Impact",
         "logic": "process=net.exe/sc.exe 'stop' targeting DB/security/backup services",
         "repo": REPO_SIEM},
    ],
    "T1190": [
        {"type": "sigma", "title": "Web Server Spawning Shell",
         "logic": "parent in (w3wp,httpd,tomcat) AND child in (cmd,powershell,bash,whoami)",
         "repo": REPO_SPLUNK},
    ],
    "T1078": [
        {"type": "kql", "title": "signin-high-risk-successful / impossible-travel",
         "logic": "SigninLogs RiskLevelDuringSignIn=high ResultType=0; or geo-velocity > threshold",
         "repo": REPO_SENTINEL},
    ],
}


def build_atomic(techniques: list[dict]) -> dict:
    valid_ids = {t["id"] for t in techniques}
    out = {}
    for tid, tests in ATOMIC.items():
        if tid not in valid_ids:
            continue  # drop refs to techniques not in the KB
        if not tests:
            continue
        out[tid] = [{"test_id": a, "title": b} for a, b in tests]
    return out


def build_detections(techniques: list[dict]) -> dict:
    valid_ids = {t["id"] for t in techniques}
    out = {}
    for tid, ideas in DETECTIONS.items():
        if tid not in valid_ids:
            continue
        out[tid] = ideas
    return out


# Six threat-actor archetypes modelled on *public reporting patterns*.
# Generic names only; no claims about specific real-world named groups.
PROFILES = [
    {
        "id": "ransomware-affiliate",
        "name": "Group A - Ransomware Affiliate (healthcare/finance)",
        "summary": "Financially motivated affiliate of a ransomware-as-a-service "
                   "operation. Phishing or exposed remote services for access, "
                   "hands-on-keyboard escalation, double extortion (exfil then encrypt).",
        "motivation": "financial",
        "typical_targets": ["healthcare", "finance", "manufacturing"],
        "techniques": [
            "T1566.001", "T1133", "T1078", "T1059.001", "T1569.002", "T1053.005",
            "T1543.003", "T1548.002", "T1134", "T1562.001", "T1070.001",
            "T1003.001", "T1558.003", "T1110.003", "T1087.002", "T1018", "T1482",
            "T1021.001", "T1021.002", "T1550.002", "T1570", "T1560.001", "T1005",
            "T1567.002", "T1041", "T1071.001", "T1105", "T1489", "T1490", "T1486",
        ],
    },
    {
        "id": "state-espionage",
        "name": "Group B - State-Nexus Espionage",
        "summary": "Stealthy, long-dwell intrusion set focused on intellectual "
                   "property and sensitive data. Spearphishing and edge exploitation, "
                   "living-off-the-land, encrypted C2, slow and careful collection.",
        "motivation": "espionage",
        "typical_targets": ["government", "defense", "technology", "ngo"],
        "techniques": [
            "T1566.002", "T1190", "T1133", "T1059.001", "T1047", "T1505.003",
            "T1574.002", "T1546.003", "T1055", "T1036", "T1027", "T1070.004",
            "T1003.001", "T1558.003", "T1555", "T1087.002", "T1482", "T1069.002",
            "T1021.006", "T1550.002", "T1005", "T1039", "T1114", "T1560.001",
            "T1071.001", "T1573", "T1090", "T1105", "T1041", "T1567.002",
        ],
    },
    {
        "id": "ecrime-loader",
        "name": "Group C - eCrime Loader / Access Broker",
        "summary": "Commodity-malware crew that gains and sells access. Malicious "
                   "attachments and malvertising, loaders that pull follow-on tooling, "
                   "credential theft for resale to ransomware affiliates.",
        "motivation": "financial",
        "typical_targets": ["any opportunistic"],
        "techniques": [
            "T1566.001", "T1189", "T1204.002", "T1059.005", "T1059.001", "T1218.011",
            "T1218.005", "T1547.001", "T1053.005", "T1055", "T1027.010", "T1140",
            "T1003.001", "T1555", "T1552.001", "T1082", "T1057", "T1016",
            "T1071.001", "T1105", "T1572", "T1041",
        ],
    },
    {
        "id": "insider-threat",
        "name": "Group D - Malicious Insider",
        "summary": "Authorized user abusing legitimate access to collect and "
                   "exfiltrate data. Little or no malware; detection relies on "
                   "behaviour, data access and egress anomalies.",
        "motivation": "data theft",
        "typical_targets": ["own employer"],
        "techniques": [
            "T1078", "T1087.002", "T1083", "T1005", "T1039", "T1114", "T1552.001",
            "T1560.001", "T1048", "T1567.002", "T1020",
        ],
    },
    {
        "id": "hacktivist",
        "name": "Group E - Hacktivist / Disruption",
        "summary": "Ideologically motivated actor seeking visible disruption. "
                   "Public-facing exploitation and valid accounts, defacement and "
                   "destructive impact over stealth.",
        "motivation": "ideological",
        "typical_targets": ["government", "media", "high-profile brands"],
        "techniques": [
            "T1190", "T1078", "T1505.003", "T1059.003", "T1136.001", "T1098",
            "T1070.001", "T1562.001", "T1046", "T1018", "T1491" if False else "T1485",
            "T1489", "T1529",
        ],
    },
    {
        "id": "scattered-social-eng",
        "name": "Group F - Social-Engineering Intrusion Set",
        "summary": "Native-English social engineers who abuse help desks and MFA "
                   "fatigue for identity-based access, then move fast in cloud and "
                   "on-prem using legitimate tooling.",
        "motivation": "financial",
        "typical_targets": ["telecom", "technology", "business process outsourcing"],
        "techniques": [
            "T1566.002", "T1078", "T1133", "T1098", "T1136.001", "T1059.001",
            "T1555", "T1552.001", "T1087.002", "T1018", "T1021.001", "T1021.006",
            "T1005", "T1567.002", "T1071.001", "T1105",
        ],
    },
]


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    techniques = build_techniques()
    atomic = build_atomic(techniques)
    detections = build_detections(techniques)

    # Integrity guard: every profile technique must exist in the KB.
    valid = {t["id"] for t in techniques}
    for p in PROFILES:
        missing = [t for t in p["techniques"] if t not in valid]
        if missing:
            raise SystemExit(f"profile {p['id']} references unknown techniques: {missing}")

    (DATA_DIR / "techniques.json").write_text(
        json.dumps({"version": "1.0", "source": "MITRE ATT&CK Enterprise (public)",
                    "tactic_order": TACTIC_ORDER, "techniques": techniques}, indent=2) + "\n")
    (DATA_DIR / "actor_profiles.json").write_text(
        json.dumps({"version": "1.0", "profiles": PROFILES}, indent=2) + "\n")
    (DATA_DIR / "atomic_map.json").write_text(
        json.dumps({"version": "1.0",
                    "note": "Atomic Red Team test identifiers and titles only - no commands or payloads.",
                    "map": atomic}, indent=2) + "\n")
    (DATA_DIR / "detections.json").write_text(
        json.dumps({"version": "1.0", "map": detections}, indent=2) + "\n")

    print(f"techniques: {len(techniques)}")
    print(f"tactics:    {len(set(t['tactic'] for t in techniques))}")
    print(f"atomic map: {len(atomic)} techniques, {sum(len(v) for v in atomic.values())} tests")
    print(f"detections: {len(detections)} techniques, {sum(len(v) for v in detections.values())} ideas")
    print(f"profiles:   {len(PROFILES)}")


if __name__ == "__main__":
    main()
