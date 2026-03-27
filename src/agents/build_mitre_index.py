#!/usr/bin/env python3
"""
Build MITRE ATT&CK keyword index for LangMal.
No external dependencies — built from ATT&CK v14 Windows techniques.

Output: artifacts/mitre_index.json
"""
import json
from pathlib import Path

# ── MITRE ATT&CK v14 Windows technique definitions ────────────────────────────
# Format: technique_id → {name, keywords, stages}
# keywords: terms likely to appear in behavioral_goal
# stages:   LangMal stage names where this technique is valid

TECHNIQUES = {
    # ══════════════════════════════════════════════════════════════════════════
    # DISCOVERY
    # ══════════════════════════════════════════════════════════════════════════
    "T1082": {
        "name": "System Information Discovery",
        "keywords": [
            "os version", "system info", "architecture", "hostname", "platform",
            "cpu", "ram", "memory", "hardware", "gather os", "collect os",
            "system information", "windows version", "os build", "system architecture",
            "gather system", "collect system", "enumerate system", "machine info",
            "environment info", "system details", "os details", "computer name",
            "bios version", "system manufacturer",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "keywords": [
            "current user", "username", "whoami", "logged in user", "user identity",
            "user account", "admin status", "is_admin", "user info", "collect user",
            "retrieve user", "user information", "logged on user", "user context",
            "current username", "user privilege", "check admin",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "keywords": [
            "locate files", "find files", "enumerate files", "list files", "file paths",
            "directory", "folder", "glob", "search files", "identify files",
            "scan files", "enumerate target", "list all", "list documents",
            "list .txt", "list .docx", "find .txt", "find .docx", "find documents",
            "locate documents", "locate target", "walk directory", "scan directory",
            "search directory", "find .pdf", "find .xls", "list .pdf",
            "enumerate directory", "directory listing", "file enumeration",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1057": {
        "name": "Process Discovery",
        "keywords": [
            "process list", "running processes", "enumerate processes", "tasklist",
            "process id", "pid", "list processes", "check process", "process name",
            "running program", "active process",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1518": {
        "name": "Software Discovery",
        "keywords": [
            "installed software", "installed applications", "enumerate software",
            "software list", "wmic product", "installed programs", "software inventory",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "keywords": [
            "network connections", "active connections", "netstat", "open ports", "socket",
            "tcp connections", "udp connections", "listening ports",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1217": {
        "name": "Browser Information Discovery",
        "keywords": [
            "browser history", "browsing history", "browser bookmarks", "browser profile",
            "browser data", "visited urls",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "keywords": [
            "ip address", "network config", "ipconfig", "network interface", "dns",
            "gateway", "subnet mask", "mac address", "arp table", "routing table",
            "network settings",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1010": {
        "name": "Application Window Discovery",
        "keywords": [
            "enumerate windows", "list windows", "active windows", "foreground window",
            "window title", "getforegroundwindow", "enumwindows",
        ],
        "stages": ["discovery", "recon"],
    },
    "T1124": {
        "name": "System Time Discovery",
        "keywords": [
            "system time", "current time", "system clock", "timestamp", "local time",
            "get time", "datetime now",
        ],
        "stages": ["discovery", "recon"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CREDENTIAL ACCESS
    # ══════════════════════════════════════════════════════════════════════════
    "T1555.003": {
        "name": "Credentials from Web Browsers",
        "keywords": [
            "browser password", "saved password", "chrome password", "firefox password",
            "browser credential", "login data", "browser database", "sqlite", "dpapi",
            "browser login", "edge password", "browser saved", "credential database",
            "decrypt browser", "browser vault",
        ],
        "stages": ["credential-access"],
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "keywords": [
            "browser cookie", "session cookie", "steal cookie", "chrome cookie",
            "firefox cookie", "web cookie", "cookie database", "cookie jar",
            "authentication cookie", "cookie theft",
        ],
        "stages": ["credential-access"],
    },
    "T1552.001": {
        "name": "Credentials in Files",
        "keywords": [
            "credentials in files", "password file", "config file credentials",
            "plaintext password", "credential file", "password in config",
            "hardcoded password", "password txt", "find credentials",
        ],
        "stages": ["credential-access"],
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "keywords": [
            "lsass", "dump credentials", "memory dump", "credential dump", "mimikatz",
            "lsass dump", "process dump", "dump lsass", "ntds",
        ],
        "stages": ["credential-access"],
    },
    "T1056.001": {
        "name": "Keylogging",
        "keywords": [
            "keylogger", "keystroke", "keyboard hook", "key capture", "keyboard input",
            "log keystrokes", "hook keyboard", "low-level keyboard", "keyboard listener",
            "capture keystrokes", "record keystrokes", "keyboard monitoring",
            "setwindowshookex", "wh_keyboard", "keyboard event", "key press",
            "capture key press",
        ],
        "stages": ["execution", "collection"],
    },
    "T1552.002": {
        "name": "Credentials in Registry",
        "keywords": [
            "registry credential", "registry password", "winlogon password",
            "autologon credential", "credential registry", "stored credential registry",
        ],
        "stages": ["credential-access"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # EXECUTION
    # ══════════════════════════════════════════════════════════════════════════
    "T1059.001": {
        "name": "PowerShell",
        "keywords": [
            "powershell", "ps1", "invoke-expression", "iex", "powershell script",
            "invoke-command", "powershell execution",
        ],
        "stages": ["execution"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "keywords": [
            "cmd", "command shell", "batch script", "command prompt", "cmd.exe",
            "batch file", "shell command", "os.system",
        ],
        "stages": ["execution"],
    },
    "T1059.006": {
        "name": "Python",
        "keywords": [
            "python script", "exec(", "subprocess", "python execution", "run python",
            "python payload", "python interpreter",
        ],
        "stages": ["execution"],
    },
    "T1106": {
        "name": "Native API",
        "keywords": [
            "winapi", "createprocess", "shellexecute", "native api", "windows api",
            "ctypes", "win32api", "virtualalloc", "createthread", "loadlibrary",
        ],
        "stages": ["execution"],
    },
    "T1204.002": {
        "name": "Malicious File",
        "keywords": [
            "user execute", "lure user", "double click", "malicious file execution",
            "trick user", "social engineering execute",
        ],
        "stages": ["execution", "initial-access"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "keywords": [
            "encrypt files", "ransomware", "file encryption", "encrypt documents",
            "encrypt victim", "lock files", "encrypt target", "aes encrypt file",
            "encrypt all", "encrypt each", "encrypt identified", "aes-256 file",
            "encrypt user files", "encrypt victim files", "encrypt in-place",
            "append .locked", "encrypt target file", "encrypt document",
            "encrypt every file", "file in-place", ".locked extension",
            "encrypt user document", "ransom encrypt", "encrypt and lock",
        ],
        "stages": ["execution", "impact"],
    },
    "T1491.001": {
        "name": "Internal Defacement / Ransom Note",
        "keywords": [
            "ransom note", "drop note", "defacement", "leave message", "readme ransom",
            "ransom message", "create ransom", "write ransom", "ransom html",
            "ransom txt", "drop ransom", "ransom demand", "payment instruction",
            "ransom file", "ransom desktop", "write note", "create note",
            "ransom readme", "how to decrypt", "bitcoin ransom", "payment address",
        ],
        "stages": ["execution", "impact"],
    },
    "T1489": {
        "name": "Service Stop",
        "keywords": [
            "stop service", "kill service", "disable service", "terminate service",
            "stop database", "stop backup", "kill antivirus process",
        ],
        "stages": ["impact", "defense-evasion"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # COLLECTION
    # ══════════════════════════════════════════════════════════════════════════
    "T1005": {
        "name": "Data from Local System",
        "keywords": [
            "read file", "open file", "file content", "read document", "collect file content",
            "access file", "read text file", "read victim file", "extract content",
            "file data", "read file content", "collect data from file", "file read",
            "gather file content", "retrieve file content", "read local file",
            "access local data", "local file content", "extract file data",
        ],
        "stages": ["collection"],
    },
    "T1115": {
        "name": "Clipboard Data",
        "keywords": [
            "clipboard", "copy paste", "clipboard monitor", "clipboard data",
            "clipboard capture", "pyperclip", "getclipboarddata", "clipboard content",
            "monitor clipboard",
        ],
        "stages": ["execution", "collection"],
    },
    "T1113": {
        "name": "Screen Capture",
        "keywords": [
            "screenshot", "screen capture", "screen grab", "printscreen",
            "capture screen", "desktop screenshot", "take screenshot",
            "screen recording", "pil screenshot",
        ],
        "stages": ["execution", "collection"],
    },
    "T1123": {
        "name": "Audio Capture",
        "keywords": [
            "microphone", "audio capture", "record audio", "sound capture",
            "audio recording", "mic capture", "pyaudio",
        ],
        "stages": ["execution", "collection"],
    },
    "T1125": {
        "name": "Video Capture",
        "keywords": [
            "webcam", "camera capture", "video capture", "record webcam",
            "cv2 capture", "camera record",
        ],
        "stages": ["collection"],
    },
    "T1560.001": {
        "name": "Archive Collected Data",
        "keywords": [
            "zip files", "compress data", "archive before", "tar files", "create zip",
            "compress collected", "zip archive", "zipfile", "compress files",
            "archive data", "pack files", "compress before send",
        ],
        "stages": ["collection", "exfiltration"],
    },
    "T1074.001": {
        "name": "Local Data Staging",
        "keywords": [
            "staging directory", "temp folder", "collect to folder", "aggregate files",
            "stage data", "temporary staging", "dump to folder", "staging area",
            "collect into directory", "gather to temp", "save to temp",
            "write to staging", "staging path", "stage collected", "stage to",
            "collected data to", "store collected", "temp directory", "temporary directory",
        ],
        "stages": ["collection"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION
    # ══════════════════════════════════════════════════════════════════════════
    "T1548.002": {
        "name": "Bypass User Account Control",
        "keywords": [
            "uac bypass", "bypass uac", "user account control", "fodhelper",
            "eventvwr", "elevate privilege", "admin bypass", "uac elevation",
            "bypass admin", "gain admin",
        ],
        "stages": ["privilege-escalation"],
    },
    "T1134.001": {
        "name": "Token Impersonation",
        "keywords": [
            "token impersonation", "impersonate token", "steal token", "access token",
            "duplicatetoken", "impersonation", "token theft",
        ],
        "stages": ["privilege-escalation"],
    },
    "T1055": {
        "name": "Process Injection",
        "keywords": [
            "inject code", "process injection", "shellcode inject", "dll inject",
            "inject into process", "code injection", "remote thread injection",
            "writeprocessmemory", "createremotethread",
        ],
        "stages": ["privilege-escalation", "defense-evasion"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ══════════════════════════════════════════════════════════════════════════
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "keywords": [
            "registry run", "run key", "startup", "hkcu run", "hklm run",
            "registry persistence", "autorun", "survive reboot", "persist reboot",
            "winreg", "add to registry", "registry key", "run on startup",
            "launch on boot", "auto-start", "autostart", "run at boot",
            "hkey_current_user", "hkey_local_machine", "startup folder",
            "start menu startup", "persist via registry",
        ],
        "stages": ["persistence"],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "keywords": [
            "scheduled task", "schtasks", "task scheduler", "cron",
            "schedule execution", "create task", "periodic task", "task schedule",
        ],
        "stages": ["persistence"],
    },
    "T1543.003": {
        "name": "Windows Service",
        "keywords": [
            "windows service", "create service", "sc create", "install service",
            "service persistence", "register service", "service installation",
        ],
        "stages": ["persistence"],
    },
    "T1547.009": {
        "name": "Shortcut Modification",
        "keywords": [
            "lnk file", "shortcut modification", "modify shortcut", "desktop shortcut",
            "lnk persistence", "create shortcut", "shortcut payload",
        ],
        "stages": ["persistence"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # DEFENSE EVASION
    # ══════════════════════════════════════════════════════════════════════════
    "T1027": {
        "name": "Obfuscated Files or Information",
        "keywords": [
            "obfuscate code", "obfuscate payload", "encode payload", "base64 encode",
            "payload obfuscation", "encrypt payload", "encrypt buffer",
            "encrypt logs", "encrypt collected", "encrypt aggregated",
            "aes-256 to prevent", "prevent network inspection",
            "encrypt before transmission", "encrypt for transmission",
            "aes encrypt payload", "encrypt keystroke", "encrypt dump",
            "xor encode", "obfuscate string", "string obfuscation",
        ],
        "stages": ["defense-evasion"],
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "keywords": [
            "decode payload", "decrypt payload", "base64 decode", "decompress payload",
            "deobfuscate", "decrypt shellcode", "decode config", "decode string",
            "xor decode", "decrypt config", "base64-encoded", "encoded shellcode",
            "decode at runtime", "decode shellcode", "base64 encoded shellcode",
        ],
        "stages": ["defense-evasion", "execution"],
    },
    "T1070.004": {
        "name": "File Deletion",
        "keywords": [
            "delete file", "cleanup", "remove traces", "remove file", "clean up",
            "wipe", "delete logs", "remove artifacts", "securely delete",
            "delete after", "wipe after", "delete dump", "remove dump",
            "cleanup after", "delete evidence", "shred file", "overwrite file",
            "secure erase", "self delete", "delete self", "remove original",
        ],
        "stages": ["defense-evasion"],
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "keywords": [
            "masquerade", "fake name", "legitimate name", "disguise process",
            "mimic system", "fake process name", "impersonate process",
            "disguise as system",
        ],
        "stages": ["defense-evasion"],
    },
    "T1055.001": {
        "name": "Process Hollowing",
        "keywords": [
            "process hollowing", "hollow process", "inject hollow",
            "process injection hollowing", "unmapping", "ntunmapviewofsection",
        ],
        "stages": ["defense-evasion"],
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "keywords": [
            "disable antivirus", "disable defender", "kill av", "disable security",
            "amsi bypass", "disable monitoring", "kill antivirus", "stop av",
            "bypass amsi", "disable windows defender", "tamper protection",
        ],
        "stages": ["defense-evasion"],
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "keywords": [
            "sandbox detection", "vm check", "sleep evasion", "anti-debug",
            "detect sandbox", "check vm", "virtual machine detection",
            "sandbox evasion", "vmware detect", "virtualbox detect",
            "anti-analysis", "anti-vm", "environment check", "is virtual",
            "detect analysis", "check environment", "sleep to evade",
            "long sleep", "time delay evasion", "detect debugger",
            "check sandbox", "sandbox aware", "anti-sandbox",
            "running inside", "inside a vm", "inside vm", "running in vm",
            "detect virtual", "virtual environment", "vm detection",
        ],
        "stages": ["defense-evasion"],
    },
    "T1622": {
        "name": "Debugger Evasion",
        "keywords": [
            "isdebuggerpresent", "timing check", "detect debugger",
            "anti-debug", "debugger detection", "checkremotedebuggerpresent",
            "debug flag", "heap flag", "ntglobalflag",
        ],
        "stages": ["defense-evasion"],
    },
    "T1112": {
        "name": "Modify Registry",
        "keywords": [
            "modify registry", "delete registry key", "registry modification",
            "registry edit", "set registry", "winreg modify", "registry value",
            "change registry", "update registry",
        ],
        "stages": ["defense-evasion", "persistence"],
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "keywords": [
            "clear event log", "delete event log", "wipe event log",
            "clear logs", "event log deletion", "clear security log",
            "clear system log", "wevtutil", "windows event logs",
            "clear windows event", "remove event log", "erase event log",
            "event logs to remove",
        ],
        "stages": ["defense-evasion"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # EXFILTRATION
    # ══════════════════════════════════════════════════════════════════════════
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "keywords": [
            "send to c2", "exfiltrate c2", "transmit c2", "upload c2",
            "send data server", "remote server", "command and control", "c2 server",
            "upload to c2", "send encrypted", "transmit encrypted", "exfiltrate to",
            "upload encrypted", "send key to", "upload key", "upload rsa",
            "key to c2", "upload to server", "send to server", "exfil to c2",
            "transmit to c2", "send collected", "upload collected", "exfil data",
        ],
        "stages": ["exfiltration"],
    },
    "T1071.001": {
        "name": "Web Protocols (HTTP/HTTPS)",
        "keywords": [
            "https post", "http post", "https request", "web protocol",
            "requests.post", "http upload", "https upload", "https transmission",
            "http transmission", "via https", "via http", "https endpoint",
            "post to c2", "post encrypted", "upload via https",
            "https post to c2", "c2 via https", "c2 endpoint",
            "http request", "send via http",
        ],
        "stages": ["exfiltration", "c2-setup"],
    },
    "T1071.003": {
        "name": "Mail Protocols",
        "keywords": [
            "email", "smtp", "send mail", "mail exfil", "email attachment",
            "send via email", "smtp server", "email data",
        ],
        "stages": ["exfiltration"],
    },
    "T1048.003": {
        "name": "Exfiltration Over Unencrypted Protocol",
        "keywords": [
            "ftp", "unencrypted exfil", "plain http exfil", "ftp upload",
            "plaintext transfer",
        ],
        "stages": ["exfiltration"],
    },
    "T1020": {
        "name": "Automated Exfiltration",
        "keywords": [
            "auto upload", "automatically send", "auto exfil", "automated transfer",
            "send automatically", "periodic upload", "auto transmit",
            "background upload", "continuously send",
        ],
        "stages": ["exfiltration"],
    },
    "T1030": {
        "name": "Data Transfer Size Limits",
        "keywords": [
            "chunk data", "split before send", "chunked upload", "data chunk",
            "split data", "chunk size", "send in chunks", "transfer in parts",
            "batch upload", "chunks of", "in chunks", "chunk transfer",
            "size limit", "transfer limit", "split transfer",
        ],
        "stages": ["exfiltration"],
    },
    "T1029": {
        "name": "Scheduled Transfer",
        "keywords": [
            "send periodically", "scheduled exfil", "interval upload",
            "periodic send", "timed transfer", "send every", "transfer interval",
        ],
        "stages": ["exfiltration"],
    },
    "T1573.001": {
        "name": "Symmetric Cryptography (C2 Channel)",
        "keywords": [
            "encrypted c2 channel", "symmetric c2", "aes c2 channel",
            "encrypt c2 communication", "aes channel", "symmetric encryption c2",
        ],
        "stages": ["c2-setup", "exfiltration"],
    },
    "T1573.002": {
        "name": "Asymmetric Cryptography (C2 / Key Protection)",
        "keywords": [
            "rsa encrypt key", "rsa key", "asymmetric encrypt", "public key encrypt",
            "rsa transmission", "encrypt encryption key", "protect key rsa",
            "rsa for secure", "using rsa", "rsa public", "secure transmission rsa",
            "encrypt key using rsa", "rsa-encrypt", "rsa-encrypted",
            "rsa encrypt the", "protect encryption key", "only c2 can recover",
            "key so only", "public key encryption", "rsa 2048",
        ],
        "stages": ["defense-evasion", "exfiltration", "c2-setup"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT
    # ══════════════════════════════════════════════════════════════════════════
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "keywords": ["rdp", "remote desktop", "mstsc"],
        "stages": ["lateral-movement"],
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "keywords": [
            "smb", "admin share", "network share", "unc path", "ipc$",
            "lateral smb", "copy via smb", "move via smb",
        ],
        "stages": ["lateral-movement"],
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "keywords": [
            "copy to remote", "transfer tool", "move payload lateral",
            "spread to host", "copy payload to",
        ],
        "stages": ["lateral-movement"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # INITIAL ACCESS
    # ══════════════════════════════════════════════════════════════════════════
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "keywords": [
            "phishing", "malicious attachment", "spearphishing", "email attachment",
            "phishing email", "lure email", "phishing document",
        ],
        "stages": ["initial-access"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "keywords": [
            "download payload", "download file", "fetch payload", "retrieve payload",
            "drop file", "download executable", "download binary", "pull payload",
            "download additional", "fetch from url", "download from server",
        ],
        "stages": ["execution", "initial-access"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "keywords": [
            "use stolen credentials", "login with harvested", "valid account",
            "use credential", "authenticate with", "stolen account", "credential reuse",
        ],
        "stages": ["initial-access", "lateral-movement"],
    },

    # ══════════════════════════════════════════════════════════════════════════
    # C2 SETUP
    # ══════════════════════════════════════════════════════════════════════════
    "T1571": {
        "name": "Non-Standard Port",
        "keywords": [
            "custom port", "non-standard port", "port 4444", "port 8888",
            "unusual port", "backdoor port", "listen on port",
        ],
        "stages": ["c2-setup"],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "keywords": [
            "tunnel traffic", "dns tunnel", "icmp tunnel", "protocol tunneling",
            "encapsulate traffic", "covert channel",
        ],
        "stages": ["c2-setup", "exfiltration"],
    },
}


def build_index() -> dict:
    """
    Build inverted keyword → [technique_id] index.
    Also keeps forward index: technique_id → metadata.
    """
    keyword_index: dict[str, list[str]] = {}
    forward_index: dict[str, dict] = {}

    for tid, meta in TECHNIQUES.items():
        forward_index[tid] = {
            "name":   meta["name"],
            "stages": meta["stages"],
        }
        for kw in meta["keywords"]:
            keyword_index.setdefault(kw.lower(), [])
            if tid not in keyword_index[kw.lower()]:
                keyword_index[kw.lower()].append(tid)

    return {
        "version":         "ATT&CK v14 (Windows) — LangMal Extended",
        "technique_count": len(TECHNIQUES),
        "keyword_count":   len(keyword_index),
        "keyword_index":   keyword_index,
        "forward_index":   forward_index,
    }


def lookup(behavioral_goal: str, stage: str, index: dict, top_n: int = 3) -> list[str]:
    """
    Lookup best matching techniques for a behavioral_goal + stage.

    Scoring:
      +2  keyword match AND stage match
      +1  keyword match only (stage mismatch)
    Longer keyword phrases score higher (weighted by word count) to prefer
    specific matches over short substring hits.

    Returns list of technique IDs sorted by match score.
    """
    goal_lower  = behavioral_goal.lower()
    stage_lower = stage.lower()
    kw_index    = index["keyword_index"]
    fwd_index   = index["forward_index"]

    scores: dict[str, float] = {}

    for kw, tids in kw_index.items():
        if kw in goal_lower:
            weight = len(kw.split())          # prefer longer / more specific keywords
            for tid in tids:
                meta = fwd_index.get(tid, {})
                stage_match = stage_lower in meta.get("stages", [])
                bonus = 2 if stage_match else 1
                scores[tid] = scores.get(tid, 0) + weight * bonus

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return [tid for tid, score in ranked[:top_n] if score > 0]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build MITRE ATT&CK keyword index")
    parser.add_argument("--out", default="artifacts/mitre_index.json")
    parser.add_argument("--test", action="store_true", help="Run lookup tests")
    args = parser.parse_args()

    index = build_index()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(f"✅ Index built: {index['keyword_count']} keywords, {index['technique_count']} techniques")
    print(f"💾 Saved: {out_path}")

    if args.test:
        print("\n── Lookup tests ──")
        tests = [
            # Original tests
            ("Encrypt each identified file using AES-256",              "execution"),
            ("Register low-level keyboard hook to capture all keystrokes", "execution"),
            ("Create a ransom note in the Documents folder",            "execution"),
            ("Transmit encrypted payload via HTTPS POST to C2",        "exfiltration"),
            ("Add to registry Run key to survive reboot",              "persistence"),
            ("Retrieve saved passwords and cookies from browser databases", "credential-access"),
            ("Encrypt the encryption key using RSA for secure transmission", "defense-evasion"),
            ("Remove traces of extracted data after upload",           "defense-evasion"),
            ("Identify all .txt and .docx files in user Documents folder", "discovery"),
            # New tests
            ("Read file content and collect all document data",        "collection"),
            ("Compress collected files into zip archive before sending", "collection"),
            ("Detect if running inside a virtual machine or sandbox",  "defense-evasion"),
            ("Check if a debugger is present using IsDebuggerPresent", "defense-evasion"),
            ("Decode base64-encoded shellcode at runtime",             "defense-evasion"),
            ("Stage collected data to a temporary directory",          "collection"),
            ("Automatically send data to server every 60 seconds",     "exfiltration"),
            ("Send data in chunks of 1MB to avoid detection",         "exfiltration"),
            ("Clear Windows event logs to remove evidence",            "defense-evasion"),
        ]
        width = max(len(g) for g, _ in tests)
        for goal, stage in tests:
            results = lookup(goal, stage, index)
            names = [index["forward_index"][t]["name"] for t in results]
            print(f"\n  Goal : {goal}")
            print(f"  Stage: {stage}")
            print(f"  Match: {list(zip(results, names))}")