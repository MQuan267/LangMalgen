from __future__ import annotations
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from openai import OpenAI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_STAGES = frozenset({
    "recon", "discovery", "initial-access", "execution",
    "privilege-escalation", "persistence", "defense-evasion",
    "exfiltration", "lateral-movement", "credential-access",
    "weaponization", "c2-setup", "data-processing",
})

ADVERSARIAL_STAGES = frozenset({
    "discovery", "credential-access", "persistence",
    "defense-evasion", "exfiltration", "execution",
    "privilege-escalation", "lateral-movement",
})

MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
WORD_RE = re.compile(r"[a-z0-9_\-\.]+")

INTENT_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["keylog", "keystroke", "keyboard", "monitor input", "capture key"], "keylogger"),
    (["lsass", "credential", "password", "hash dump", "ntlm", "dump cred"], "credential_dumper"),
    (["ransom", "encrypt file", "lock file", "decrypt", "bitcoin", "wanna"], "ransomware"),
    (["rat", "remote access", "remote shell", "reverse shell", "c2 shell"], "rat"),
    (["inject", "dll inject", "process hollow", "shellcode", "reflective"], "injector"),
    (["backdoor", "persist shell", "hidden shell"], "rat"),
    (["screenshot", "screen capture", "screengrab"], "screenshotter"),
]

_TEMPERATURE_MAP = {
    "keylogger": 0.35,
    "credential_dumper": 0.25,
    "ransomware": 0.30,
    "rat": 0.35,
    "injector": 0.30,
    "screenshotter": 0.30,
    "unknown": 0.30,
}

EXAMPLE_INTENT_HINTS: Dict[str, str] = {
    "info_stealer": "collect system information aggregate data encrypt payload exfiltrate over https",
    "keylogger": "capture keyboard input buffer logs encrypt logs exfiltrate logs registry persistence",
    "credential_dumper": "check privileges access lsass dump credentials encrypt dump exfiltrate cleanup",
    "ransomware": "enumerate files encrypt files protect key exfiltrate recovery key drop ransom note",
    "rat": "establish command and control receive commands execute operator actions persistence defense evasion",
    "injector": "find target process escalate privileges inject shellcode execute remote thread",
    "screenshotter": "capture screenshots compress image encrypt screenshot exfiltrate image",
}

ATTACK_KB: List[Dict[str, Any]] = [
    # ── DISCOVERY ──────────────────────────────────────────────────────────
    {"id": "T1082", "stage": "discovery", "name": "System Information Discovery",
     "keywords": ["os", "hostname", "architecture", "system information", "system version", "computer name", "environment info"]},

    {"id": "T1033", "stage": "discovery", "name": "System Owner/User Discovery",
     "keywords": ["user", "username", "current user", "account", "logged in", "whoami"]},

    {"id": "T1083", "stage": "discovery", "name": "File and Directory Discovery",
     "keywords": ["file", "directory", "document", "path", "enumerate files", "list files", "file system"]},

    {"id": "T1057", "stage": "discovery", "name": "Process Discovery",
     "keywords": ["process", "pid", "running process", "target process", "enumerate process", "tasklist"]},

    {"id": "T1012", "stage": "discovery", "name": "Query Registry",
     "keywords": ["query registry", "read registry", "registry key", "registry value", "regedit"]},

    {"id": "T1047", "stage": "discovery", "name": "Windows Management Instrumentation",
     "keywords": ["wmi", "wmic", "windows management", "impacket", "wmi query"]},

    {"id": "T1518.001", "stage": "discovery", "name": "Security Software Discovery",
     "keywords": ["security software", "antivirus", "edr", "defender", "discover security tool"]},

    # ── CREDENTIAL ACCESS ───────────────────────────────────────────────────
    {"id": "T1003.001", "stage": "credential-access", "name": "LSASS Memory",
     "keywords": ["lsass", "credential", "password", "ntlm", "hash", "dump memory", "minidump", "mimikatz", "comsvcs"]},

    {"id": "T1552.001", "stage": "credential-access", "name": "Credentials In Files",
     "keywords": ["credential file", "password file", "config file credential", "plaintext password", "stored credential"]},

    {"id": "T1110", "stage": "credential-access", "name": "Brute Force",
     "keywords": ["brute force", "password spray", "credential stuffing", "guess password"]},

    {"id": "T1557.001", "stage": "credential-access", "name": "LLMNR/NBT-NS Poisoning",
     "keywords": ["llmnr", "nbt-ns", "responder", "poisoning", "credential intercept"]},

    # ── EXECUTION ───────────────────────────────────────────────────────────
    {"id": "T1056.001", "stage": "execution", "name": "Keylogging",
     "keywords": ["keyboard", "keystroke", "keylog", "input capture", "hook keyboard", "pynput"]},

    {"id": "T1113", "stage": "execution", "name": "Screen Capture",
     "keywords": ["screenshot", "screen", "desktop capture", "bitmap", "capture screen", "screengrab"]},

    {"id": "T1059.003", "stage": "execution", "name": "Windows Command Shell",
     "keywords": ["cmd", "command shell", "cmd.exe", "batch", "windows command", "run command"]},

    {"id": "T1106", "stage": "execution", "name": "Native API",
     "keywords": ["native api", "win32api", "ctypes", "winapi", "system call", "windows api"]},

    {"id": "T1055", "stage": "execution", "name": "Process Injection",
     "keywords": ["inject", "shellcode", "remote thread", "writeprocessmemory", "process injection", "dll inject", "reflective"]},

    {"id": "T1486", "stage": "execution", "name": "Data Encrypted for Impact",
     "keywords": ["encrypt files", "ransom", "locked extension", "encrypt document", "data encrypted", "aes encrypt file"]},

    {"id": "T1204.002", "stage": "execution", "name": "User Execution: Malicious File",
     "keywords": ["user execution", "malicious file", "open attachment", "run file", "execute payload"]},

    {"id": "T1569.002", "stage": "execution", "name": "Service Execution",
     "keywords": ["service execution", "windows service", "start service", "psexec", "service run"]},

    {"id": "T1047", "stage": "execution", "name": "Windows Management Instrumentation",
     "keywords": ["wmi", "wmic", "windows management instrumentation", "wmi execute"]},

    # ── PRIVILEGE ESCALATION ────────────────────────────────────────────────
    {"id": "T1548", "stage": "privilege-escalation", "name": "Abuse Elevation Control Mechanism",
     "keywords": ["elevate", "uac", "admin", "integrity", "elevated privileges", "bypass uac"]},

    {"id": "T1068", "stage": "privilege-escalation", "name": "Exploitation for Privilege Escalation",
     "keywords": ["exploit privilege", "kernel exploit", "local exploit", "privilege escalation exploit", "cve privilege"]},

    {"id": "T1548.002", "stage": "privilege-escalation", "name": "Bypass User Account Control",
     "keywords": ["bypass uac", "uac bypass", "user account control", "elevated token"]},

    # ── PERSISTENCE ─────────────────────────────────────────────────────────
    {"id": "T1547.001", "stage": "persistence", "name": "Registry Run Keys / Startup Folder",
     "keywords": ["registry run key", "autorun", "startup", "logon", "run key", "hkcu run", "hklm run"]},

    {"id": "T1053.005", "stage": "persistence", "name": "Scheduled Task",
     "keywords": ["scheduled task", "task scheduler", "schtasks", "cron", "at command"]},

    {"id": "T1543.003", "stage": "persistence", "name": "Windows Service",
     "keywords": ["windows service", "create service", "sc create", "service install", "service persist"]},

    {"id": "T1574.002", "stage": "persistence", "name": "DLL Side-Loading",
     "keywords": ["dll side-load", "dll hijack", "side loading", "hijack dll", "phantom dll"]},

    # ── DEFENSE EVASION ─────────────────────────────────────────────────────
    {"id": "T1027", "stage": "defense-evasion", "name": "Obfuscated Files or Information",
     "keywords": ["encrypt payload", "obfuscate", "compress", "encrypted logs", "base64 encode", "packed", "obfuscated"]},

    {"id": "T1140", "stage": "defense-evasion", "name": "Deobfuscate/Decode Files",
     "keywords": ["decode", "decrypt payload", "deobfuscate", "base64 decode", "unpack", "decompress", "decrypt config"]},

    {"id": "T1070.004", "stage": "defense-evasion", "name": "File Deletion",
     "keywords": ["cleanup", "delete file", "remove file", "securely delete", "wipe file", "erase artifact"]},

    {"id": "T1112", "stage": "defense-evasion", "name": "Modify Registry",
     "keywords": ["modify registry", "registry value", "registry key", "write registry", "reg add", "regedit modify"]},

    {"id": "T1562.001", "stage": "defense-evasion", "name": "Disable or Modify Tools",
     "keywords": ["disable defender", "disable antivirus", "turn off security", "kill edr", "stop security service", "disable logging"]},

    {"id": "T1036.005", "stage": "defense-evasion", "name": "Masquerading",
     "keywords": ["masquerade", "rename process", "legitimate name", "hide identity", "spoof process name"]},

    {"id": "T1055", "stage": "defense-evasion", "name": "Process Injection",
     "keywords": ["process hollow", "inject code", "memory injection", "reflective load"]},

    {"id": "T1078", "stage": "defense-evasion", "name": "Valid Accounts",
     "keywords": ["valid account", "stolen credential", "legitimate account", "compromised account", "reuse credential"]},

    {"id": "T1218.011", "stage": "defense-evasion", "name": "Rundll32",
     "keywords": ["rundll32", "comsvcs.dll", "dll execution", "lolbin", "living off the land"]},

    {"id": "T1564.001", "stage": "defense-evasion", "name": "Hidden Files and Directories",
     "keywords": ["hidden file", "hidden directory", "attrib hidden", "hide file", "conceal file"]},

    # ── EXFILTRATION ────────────────────────────────────────────────────────
    {"id": "T1041", "stage": "exfiltration", "name": "Exfiltration Over C2 Channel",
     "keywords": ["exfiltrate", "send data", "upload", "transmit", "send to c2", "data out"]},

    {"id": "T1071.001", "stage": "exfiltration", "name": "Web Protocols",
     "keywords": ["https", "http", "web protocol", "post request", "remote endpoint", "c2 over https", "beacon"]},

    {"id": "T1105", "stage": "exfiltration", "name": "Ingress Tool Transfer",
     "keywords": ["download payload", "fetch tool", "transfer tool", "retrieve from c2", "drop tool", "download file"]},

    {"id": "T1074.001", "stage": "exfiltration", "name": "Local Data Staging",
     "keywords": ["stage data", "collect data", "aggregate files", "local staging", "gather before exfil"]},

    # ── LATERAL MOVEMENT ────────────────────────────────────────────────────
    {"id": "T1021.001", "stage": "lateral-movement", "name": "Remote Desktop Protocol",
     "keywords": ["rdp", "remote desktop", "mstsc", "remote desktop connection", "rdp session"]},

    {"id": "T1570", "stage": "lateral-movement", "name": "Lateral Tool Transfer",
     "keywords": ["lateral movement", "move to system", "copy tool", "spread tool", "remote copy", "psexec lateral"]},

    {"id": "T1090", "stage": "lateral-movement", "name": "Proxy",
     "keywords": ["proxy", "proxychains", "redirect traffic", "c2 proxy", "network proxy", "tunnel traffic"]},

    # ── COMMAND AND CONTROL ─────────────────────────────────────────────────
    {"id": "T1071.001", "stage": "c2-setup", "name": "Web Protocols",
     "keywords": ["https c2", "http beacon", "web c2", "c2 channel", "command control https"]},

    {"id": "T1090", "stage": "c2-setup", "name": "Proxy",
     "keywords": ["c2 proxy", "proxy chain", "redirect c2", "proxy c2 traffic"]},

    {"id": "T1095", "stage": "c2-setup", "name": "Non-Application Layer Protocol",
     "keywords": ["raw socket", "tcp c2", "udp c2", "non-http", "custom protocol", "icmp tunnel"]},

    {"id": "T1219", "stage": "c2-setup", "name": "Remote Access Software",
     "keywords": ["screenconnect", "anydesk", "remote utilities", 
              "ehorus", "teamviewer", "commercial rat", "remote monitoring"]},

    # ── INITIAL ACCESS ──────────────────────────────────────────────────────
    {"id": "T1566.001", "stage": "initial-access", "name": "Spearphishing Attachment",
     "keywords": ["spearphish", "phishing", "malicious attachment", "phishing email", "lure document"]},

    {"id": "T1190", "stage": "initial-access", "name": "Exploit Public-Facing Application",
     "keywords": ["exploit", "vulnerability", "cve", "public facing", "web shell", "rce", "remote code execution"]},

    {"id": "T1078", "stage": "initial-access", "name": "Valid Accounts",
     "keywords": ["stolen credential login", "valid account access", "credential reuse login"]},
]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PolicyFlags:
    network: str = "allowed"
    os_introspection: str = "no mock"


@dataclass
class OutputContract:
    schema: str
    fields: Dict[str, str]
    properties: Optional[Dict[str, Any]] = None


@dataclass
class InputContract:
    sources: List[Dict[str, str]]


@dataclass
class ErrorContract:
    on_failure: str = "return_partial"
    required_fields: List[str] = field(default_factory=list)
    fallback_value: Optional[Dict[str, Any]] = None


@dataclass
class MitreCandidate:
    id: str
    reason: str = ""
    score: Optional[float] = None
    source: str = "unknown"


@dataclass
class Task:
    task_id: str
    stage: str
    intent: str
    behavioral_goal: str
    output_contract: OutputContract
    input_contract: Optional[InputContract] = None
    error_contract: ErrorContract = field(default_factory=ErrorContract)
    mitre_candidates: List[MitreCandidate] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_status: str = "needs_verification"
    mapping_confidence: str = "medium"
    ambiguity_notes: str = ""


@dataclass
class DataFlow:
    from_task: str
    to_task: str
    data_schema: str
    required: bool = True
    transform: Optional[str] = None


@dataclass
class GlobalConstraints:
    target_os_family: str = "windows"
    language_target: str = "python"
    stealth_level: str = "high"
    execution_model: str = "modular"
    forbidden_capabilities: List[str] = field(default_factory=lambda: ["self_propagation"])


@dataclass
class ValidationRules:
    max_execution_time_seconds: int = 60
    max_memory_mb: int = 150
    allowed_modules: List[str] = field(default_factory=lambda: [
        "os", "platform", "ctypes", "winreg", "subprocess",
        "win32api", "win32security", "win32process", "win32con",
        "wmi", "psutil", "Crypto.Cipher", "cryptography", "hashlib",
        "requests", "socket", "json", "base64", "time", "datetime",
    ])
    forbidden_patterns: List[str] = field(default_factory=lambda: [
        r"eval\(", r"exec\(", r"__import__\(",
    ])


# ---------------------------------------------------------------------------
# Few-shot examples
# ---------------------------------------------------------------------------

_EXAMPLES: Dict[str, str] = {
    "info_stealer": '''{
  "mission_id": "sysinfo_exfil",
  "intent": "Collect system information and send to C2",
  "malware_type": "stealer",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"medium","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":60,"max_memory_mb":150,"allowed_modules":["os","platform","wmi","json","Crypto.Cipher","requests"],"forbidden_patterns":["eval\\(","exec\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Collect OS Info","behavioral_goal":"Gather OS version, hostname, architecture","input_contract":null,"output_contract":{"schema":"OSInfo","fields":{"os_version":"string","hostname":"string","architecture":"string"}},"error_contract":{"on_failure":"abort_mission","required_fields":["os_version"],"fallback_value":null},"mitre_candidates":[{"id":"T1082","reason":"system information discovery","score":0.92,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"discovery","intent":"Collect User Info","behavioral_goal":"Retrieve current username and admin status","input_contract":null,"output_contract":{"schema":"UserInfo","fields":{"username":"string","is_admin":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":["username"],"fallback_value":{"is_admin":false}},"mitre_candidates":[{"id":"T1033","reason":"current user discovery","score":0.88,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"data-processing","intent":"Aggregate Data","behavioral_goal":"Combine all collected information into a single JSON payload","input_contract":{"sources":[{"task_id":"T1","schema":"OSInfo"},{"task_id":"T2","schema":"UserInfo"}]},"output_contract":{"schema":"AggregatedPayload","fields":{"payload":"string_json"}},"error_contract":{"on_failure":"abort_mission","required_fields":["payload"],"fallback_value":null},"mitre_candidates":[],"mitre_techniques":[],"mitre_status":"not_applicable","mapping_confidence":"high","ambiguity_notes":"data-processing task"},
    {"task_id":"T4","stage":"defense-evasion","intent":"Encrypt Payload","behavioral_goal":"Encrypt aggregated data using AES-256 before network transmission","input_contract":{"sources":[{"task_id":"T3","schema":"AggregatedPayload"}]},"output_contract":{"schema":"EncryptedPayload","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted or obfuscated payload","score":0.84,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"exfiltration","intent":"Send to C2","behavioral_goal":"Transmit encrypted payload via HTTPS POST to a remote server","input_contract":{"sources":[{"task_id":"T4","schema":"EncryptedPayload"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean","status_code":"integer"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data sent out of the victim environment","score":0.82,"source":"llm"},{"id":"T1071.001","reason":"web protocol command-and-control channel","score":0.79,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":"protocol details may vary"}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T3","data_schema":"OSInfo","required":true,"transform":null},
    {"from_task":"T2","to_task":"T3","data_schema":"UserInfo","required":true,"transform":null},
    {"from_task":"T3","to_task":"T4","data_schema":"AggregatedPayload","required":true,"transform":null},
    {"from_task":"T4","to_task":"T5","data_schema":"EncryptedPayload","required":true,"transform":null}
  ]
}''',
    "keylogger": '''{
  "mission_id": "keylogger_hourly",
  "intent": "Monitor keyboard input and send logs hourly",
  "malware_type": "keylogger",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":3600,"max_memory_mb":100,"allowed_modules":["ctypes","win32api","time","json","Crypto.Cipher","requests"],"forbidden_patterns":["eval\\(","exec\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"execution","intent":"Hook Keyboard","behavioral_goal":"Register a low-level keyboard hook to capture keystrokes","input_contract":null,"output_contract":{"schema":"KeyboardHook","fields":{"hook_id":"integer","active":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["hook_id"],"fallback_value":null},"mitre_candidates":[{"id":"T1056.001","reason":"keylogging via input capture","score":0.95,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"data-processing","intent":"Buffer Keystrokes","behavioral_goal":"Store captured keystrokes with timestamps and window context","input_contract":{"sources":[{"task_id":"T1","schema":"KeyboardHook"}]},"output_contract":{"schema":"KeystrokeBuffer","fields":{"entries":"array","count":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["entries"],"fallback_value":{"entries":[]}},"mitre_candidates":[],"mitre_techniques":[],"mitre_status":"not_applicable","mapping_confidence":"high","ambiguity_notes":"data-processing task"},
    {"task_id":"T3","stage":"defense-evasion","intent":"Encrypt Logs","behavioral_goal":"Encrypt buffered keystroke data before transmission","input_contract":{"sources":[{"task_id":"T2","schema":"KeystrokeBuffer"}]},"output_contract":{"schema":"EncryptedLogs","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload before exfiltration","score":0.82,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T4","stage":"exfiltration","intent":"Upload Logs","behavioral_goal":"Send encrypted keystroke logs to a remote server via HTTPS POST","input_contract":{"sources":[{"task_id":"T3","schema":"EncryptedLogs"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.80,"source":"llm"},{"id":"T1071.001","reason":"web protocol channel","score":0.78,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"persistence","intent":"Registry Persistence","behavioral_goal":"Establish automatic execution by writing to the registry Run key","input_contract":null,"output_contract":{"schema":"PersistenceStatus","fields":{"persisted":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"persisted":false}},"mitre_candidates":[{"id":"T1547.001","reason":"registry autorun persistence","score":0.93,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"KeyboardHook","required":true,"transform":null},
    {"from_task":"T2","to_task":"T3","data_schema":"KeystrokeBuffer","required":true,"transform":null},
    {"from_task":"T3","to_task":"T4","data_schema":"EncryptedLogs","required":true,"transform":null}
  ]
}''',
    "credential_dumper": '''{
  "mission_id": "lsass_dump",
  "intent": "Extract credentials from LSASS memory",
  "malware_type": "dumper",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":120,"max_memory_mb":200,"allowed_modules":["ctypes","win32api","win32security","Crypto.Cipher","requests","os"],"forbidden_patterns":["eval\\(","exec\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Check Privileges","behavioral_goal":"Verify administrative privileges and required debug capabilities","input_contract":null,"output_contract":{"schema":"PrivilegeCheck","fields":{"is_admin":"boolean","has_debug":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["is_admin"],"fallback_value":null},"mitre_candidates":[{"id":"T1033","reason":"discover current user or current context","score":0.58,"source":"llm"},{"id":"T1548","reason":"may require elevation or privilege changes before protected access","score":0.55,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"low","ambiguity_notes":"privilege check itself may map weakly or remain unmapped"},
    {"task_id":"T2","stage":"credential-access","intent":"Access LSASS","behavioral_goal":"Obtain access to the LSASS process for credential extraction","input_contract":{"sources":[{"task_id":"T1","schema":"PrivilegeCheck"}]},"output_contract":{"schema":"ProcessHandle","fields":{"handle":"integer","pid":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["handle"],"fallback_value":null},"mitre_candidates":[{"id":"T1003.001","reason":"LSASS memory credential dumping","score":0.94,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"credential-access","intent":"Dump Memory","behavioral_goal":"Create a memory dump of LSASS for offline credential extraction","input_contract":{"sources":[{"task_id":"T2","schema":"ProcessHandle"}]},"output_contract":{"schema":"MemoryDump","fields":{"path":"string","size":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["path"],"fallback_value":null},"mitre_candidates":[{"id":"T1003.001","reason":"OS credential dumping from LSASS memory","score":0.96,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T4","stage":"defense-evasion","intent":"Encrypt Dump","behavioral_goal":"Encrypt the memory dump before transmission or storage","input_contract":{"sources":[{"task_id":"T3","schema":"MemoryDump"}]},"output_contract":{"schema":"EncryptedDump","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted or obfuscated payload","score":0.77,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"exfiltration","intent":"Exfiltrate Dump","behavioral_goal":"Send encrypted credential dump to a remote endpoint via HTTPS POST","input_contract":{"sources":[{"task_id":"T4","schema":"EncryptedDump"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.80,"source":"llm"},{"id":"T1071.001","reason":"web protocol channel","score":0.76,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"PrivilegeCheck","required":true,"transform":null},
    {"from_task":"T2","to_task":"T3","data_schema":"ProcessHandle","required":true,"transform":null},
    {"from_task":"T3","to_task":"T4","data_schema":"MemoryDump","required":true,"transform":null},
    {"from_task":"T4","to_task":"T5","data_schema":"EncryptedDump","required":true,"transform":null}
  ]
}''',
    "ransomware": '''{
  "mission_id": "ransomware_encrypt",
  "intent": "Encrypt user files and demand ransom",
  "malware_type": "ransomware",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"medium","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":300,"max_memory_mb":200,"allowed_modules":["os","Crypto.Cipher","cryptography","requests","winreg","pathlib"],"forbidden_patterns":["eval\\(","exec\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Enumerate Target Files","behavioral_goal":"List target user documents and media files on disk","input_contract":null,"output_contract":{"schema":"FileList","fields":{"paths":"array","total_size":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["paths"],"fallback_value":null},"mitre_candidates":[{"id":"T1083","reason":"file and directory discovery","score":0.94,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"execution","intent":"Encrypt Files","behavioral_goal":"Encrypt each target file in place and mark it as unavailable to the user","input_contract":{"sources":[{"task_id":"T1","schema":"FileList"}]},"output_contract":{"schema":"EncryptionResult","fields":{"encrypted_count":"integer","encryption_key":"bytes"}},"error_contract":{"on_failure":"return_partial","required_fields":["encrypted_count"],"fallback_value":{"encrypted_count":0}},"mitre_candidates":[{"id":"T1486","reason":"data encrypted for impact","score":0.97,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"defense-evasion","intent":"Protect Encryption Key","behavioral_goal":"Protect the encryption key before transmission by wrapping it with another cryptographic mechanism","input_contract":{"sources":[{"task_id":"T2","schema":"EncryptionResult"}]},"output_contract":{"schema":"ProtectedKey","fields":{"encrypted_key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["encrypted_key"],"fallback_value":null},"mitre_candidates":[{"id":"T1573.002","reason":"asymmetric cryptography used to protect communications or data","score":0.73,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T4","stage":"exfiltration","intent":"Send Recovery Material","behavioral_goal":"Upload the protected key or victim recovery material to a remote server over HTTPS","input_contract":{"sources":[{"task_id":"T3","schema":"ProtectedKey"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean","victim_id":"string"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false,"victim_id":""}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.78,"source":"llm"},{"id":"T1071.001","reason":"web protocol channel","score":0.76,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"execution","intent":"Drop Ransom Note","behavioral_goal":"Write a ransom note to victim-visible locations after encryption","input_contract":{"sources":[{"task_id":"T4","schema":"TransmissionStatus"}]},"output_contract":{"schema":"RansomNoteStatus","fields":{"dropped":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"dropped":false}},"mitre_candidates":[{"id":"T1491.001","reason":"internal defacement or note-dropping visible to the user","score":0.61,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"low","ambiguity_notes":"ransom note behavior may be represented differently depending on ontology interpretation"}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"FileList","required":true,"transform":null},
    {"from_task":"T2","to_task":"T3","data_schema":"EncryptionResult","required":true,"transform":null},
    {"from_task":"T3","to_task":"T4","data_schema":"ProtectedKey","required":true,"transform":null},
    {"from_task":"T4","to_task":"T5","data_schema":"TransmissionStatus","required":true,"transform":null}
  ]
}''',
    "rat": '''{ "mission_id": "rat_c2", "intent": "Establish persistent remote access with command execution", "malware_type": "rat", "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]}, "validation_rules": {"max_execution_time_seconds":86400,"max_memory_mb":150,"allowed_modules":["socket","subprocess","ctypes","Crypto.Cipher","requests","winreg","os","threading"],"forbidden_patterns":["eval\\(","exec\\("]}, "execution_graph": [{"task_id":"T1","stage":"c2-setup","intent":"Establish C2 Channel","behavioral_goal":"Open an encrypted command-and-control channel to a remote server","input_contract":null,"output_contract":{"schema":"C2Channel","fields":{"session_id":"string","connected":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["connected"],"fallback_value":{"connected":false,"session_id":""}},"mitre_candidates":[{"id":"T1071.001","reason":"web protocol or HTTPS-based C2","score":0.89,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},{"task_id":"T2","stage":"execution","intent":"Command Dispatcher","behavioral_goal":"Receive and dispatch operator commands such as shell execution or file transfer","input_contract":{"sources":[{"task_id":"T1","schema":"C2Channel"}]},"output_contract":{"schema":"CommandResult","fields":{"command":"string","output":"string","exit_code":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["command"],"fallback_value":{"command":"","output":"","exit_code":-1}},"mitre_candidates":[{"id":"T1059.003","reason":"command shell execution","score":0.76,"source":"llm"},{"id":"T1106","reason":"native API used to carry out execution-related behavior","score":0.52,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":"API-level mapping depends on downstream implementation"},{"task_id":"T3","stage":"persistence","intent":"Install Persistence","behavioral_goal":"Ensure automatic execution on reboot by creating registry or scheduled task persistence","input_contract":null,"output_contract":{"schema":"PersistenceStatus","fields":{"registry":"boolean","scheduled_task":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"registry":false,"scheduled_task":false}},"mitre_candidates":[{"id":"T1547.001","reason":"registry autorun persistence","score":0.86,"source":"llm"},{"id":"T1053.005","reason":"scheduled task persistence","score":0.72,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":"final technique depends on chosen persistence mechanism"},{"task_id":"T4","stage":"defense-evasion","intent":"Hide Process Identity","behavioral_goal":"Masquerade the process to reduce operator-facing detection","input_contract":null,"output_contract":{"schema":"EvasionStatus","fields":{"hidden":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"hidden":false}},"mitre_candidates":[{"id":"T1036.005","reason":"match or imitate a legitimate process identity","score":0.74,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}], "dataflow": [{"from_task":"T1","to_task":"T2","data_schema":"C2Channel","required":true,"transform":null}] }''',
    "injector": '''{ "mission_id": "dll_injector", "intent": "Inject shellcode into a target process", "malware_type": "injector", "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]}, "validation_rules": {"max_execution_time_seconds":30,"max_memory_mb":100,"allowed_modules":["ctypes","win32api","win32process","win32security","win32con","os"],"forbidden_patterns":["eval\\(","exec\\("]}, "execution_graph": [{"task_id":"T1","stage":"discovery","intent":"Find Target Process","behavioral_goal":"Locate a suitable host process by name for code injection","input_contract":null,"output_contract":{"schema":"TargetProcess","fields":{"pid":"integer","name":"string"}},"error_contract":{"on_failure":"abort_mission","required_fields":["pid"],"fallback_value":null},"mitre_candidates":[{"id":"T1057","reason":"process discovery","score":0.90,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},{"task_id":"T2","stage":"privilege-escalation","intent":"Acquire Required Privileges","behavioral_goal":"Obtain elevated or debug privileges required for cross-process memory access","input_contract":{"sources":[{"task_id":"T1","schema":"TargetProcess"}]},"output_contract":{"schema":"PrivilegeStatus","fields":{"has_debug":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["has_debug"],"fallback_value":null},"mitre_candidates":[{"id":"T1548","reason":"abuse of elevation control or elevation path","score":0.63,"source":"llm"},{"id":"T1134.001","reason":"token or privilege manipulation for elevated access","score":0.67,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":"candidate depends on exact escalation mechanism"},{"task_id":"T3","stage":"execution","intent":"Inject Payload","behavioral_goal":"Write shellcode into memory of the target process","input_contract":{"sources":[{"task_id":"T1","schema":"TargetProcess"},{"task_id":"T2","schema":"PrivilegeStatus"}]},"output_contract":{"schema":"InjectionResult","fields":{"remote_addr":"integer","success":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["success"],"fallback_value":null},"mitre_candidates":[{"id":"T1055.001","reason":"dynamic-link-library or process injection-related memory manipulation","score":0.89,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},{"task_id":"T4","stage":"execution","intent":"Start Injected Payload","behavioral_goal":"Trigger execution of the injected shellcode within the target process context","input_contract":{"sources":[{"task_id":"T3","schema":"InjectionResult"}]},"output_contract":{"schema":"ExecutionStatus","fields":{"thread_id":"integer","running":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["running"],"fallback_value":null},"mitre_candidates":[{"id":"T1055.001","reason":"process injection execution in remote process","score":0.87,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}], "dataflow": [{"from_task":"T1","to_task":"T2","data_schema":"TargetProcess","required":true,"transform":null},{"from_task":"T1","to_task":"T3","data_schema":"TargetProcess","required":true,"transform":null},{"from_task":"T2","to_task":"T3","data_schema":"PrivilegeStatus","required":true,"transform":null},{"from_task":"T3","to_task":"T4","data_schema":"InjectionResult","required":true,"transform":null}] }''',
    "screenshotter": '''{ "mission_id": "screen_capture", "intent": "Periodically capture screenshots and exfiltrate", "malware_type": "stealer", "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"medium","execution_model":"modular","forbidden_capabilities":["self_propagation"]}, "validation_rules": {"max_execution_time_seconds":86400,"max_memory_mb":200,"allowed_modules":["ctypes","PIL","win32api","Crypto.Cipher","requests","io","time"],"forbidden_patterns":["eval\\(","exec\\("]}, "execution_graph": [{"task_id":"T1","stage":"execution","intent":"Capture Screen","behavioral_goal":"Capture a screenshot of the user desktop at an interval","input_contract":null,"output_contract":{"schema":"Screenshot","fields":{"image_bytes":"bytes","timestamp":"string"}},"error_contract":{"on_failure":"return_partial","required_fields":["image_bytes"],"fallback_value":null},"mitre_candidates":[{"id":"T1113","reason":"screen capture","score":0.95,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},{"task_id":"T2","stage":"data-processing","intent":"Compress Image","behavioral_goal":"Compress screenshot data to reduce transmission size","input_contract":{"sources":[{"task_id":"T1","schema":"Screenshot"}]},"output_contract":{"schema":"CompressedImage","fields":{"data":"bytes","quality":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["data"],"fallback_value":null},"mitre_candidates":[],"mitre_techniques":[],"mitre_status":"not_applicable","mapping_confidence":"high","ambiguity_notes":"data-processing task"},{"task_id":"T3","stage":"defense-evasion","intent":"Encrypt Image","behavioral_goal":"Encrypt compressed screenshot data before transmission","input_contract":{"sources":[{"task_id":"T2","schema":"CompressedImage"}]},"output_contract":{"schema":"EncryptedImage","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload before exfiltration","score":0.81,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},{"task_id":"T4","stage":"exfiltration","intent":"Upload Screenshot","behavioral_goal":"Send encrypted screenshot data to a remote endpoint over HTTPS","input_contract":{"sources":[{"task_id":"T3","schema":"EncryptedImage"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.80,"source":"llm"},{"id":"T1071.001","reason":"web protocol channel","score":0.78,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}], "dataflow": [{"from_task":"T1","to_task":"T2","data_schema":"Screenshot","required":true,"transform":null},{"from_task":"T2","to_task":"T3","data_schema":"CompressedImage","required":true,"transform":null},{"from_task":"T3","to_task":"T4","data_schema":"EncryptedImage","required":true,"transform":null}] }''',
}

_TASK_PATTERNS = """
TASK PATTERN EXAMPLES

Privilege escalation pattern:
stage: privilege-escalation
behavior: obtain elevated privileges required for protected resource access
candidate techniques: T1548, T1134, T1134.001

Persistence pattern:
stage: persistence
behavior: establish automatic execution at system startup
candidate technique: T1547.001

Exfiltration pattern:
stage: exfiltration
behavior: transmit data outside the victim environment using web protocols
candidate techniques: T1041, T1071.001

Credential dumping pattern:
stage: credential-access
behavior: extract credentials or access protected process memory such as LSASS
candidate technique: T1003.001
"""

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tokenize(text: str) -> set[str]:
    return {tok for tok in WORD_RE.findall(text.lower()) if len(tok) > 2}


def _detect_example_key(intent: str) -> str:
    lower = intent.lower()
    for keywords, key in INTENT_KEYWORD_MAP:
        if any(kw in lower for kw in keywords):
            return key
    return "info_stealer"


def _score_example(intent: str, key: str) -> float:
    intent_lower = intent.lower()
    score = 0.0
    for keywords, mapped_key in INTENT_KEYWORD_MAP:
        if mapped_key != key:
            continue
        for kw in keywords:
            if kw in intent_lower:
                score += 4.0 if " " in kw else 2.0
    intent_tokens = _tokenize(intent)
    hint_tokens = _tokenize(EXAMPLE_INTENT_HINTS.get(key, ""))
    overlap = len(intent_tokens & hint_tokens)
    if intent_tokens and hint_tokens:
        score += overlap * 1.25
        score += overlap / max(len(hint_tokens), 1)
        if overlap == 0:
            score -= 1.5
    if key == "info_stealer":
        score += 0.10
    return score


def _mission_retrieval_hints(intent: str, top_k: int = 6) -> List[Dict[str, Any]]:
    text = intent.lower()
    tokens = _tokenize(text)
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for item in ATTACK_KB:
        score = 0.0
        for kw in item["keywords"]:
            kw_lower = kw.lower()
            if kw_lower in text:
                score += 3.0 if " " in kw_lower else 1.5
            kw_tokens = _tokenize(kw_lower)
            if kw_tokens:
                score += 0.8 * len(tokens & kw_tokens)
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda x: (x[0], x[1]["id"]), reverse=True)
    out = []
    for score, item in scored[:top_k]:
        out.append({"id": item["id"], "stage": item["stage"], "name": item["name"], "score": round(min(1.0, score / 8.0), 2)})
    return out


def _related_stages_for(stage: str) -> set[str]:
    related = {
        "discovery": {"credential-access", "privilege-escalation"},
        "credential-access": {"discovery", "privilege-escalation"},
        "execution": {"privilege-escalation", "defense-evasion"},
        "defense-evasion": {"execution", "exfiltration", "persistence"},
        "exfiltration": {"defense-evasion", "c2-setup"},
        "persistence": {"defense-evasion", "execution"},
        "c2-setup": {"exfiltration", "execution"},
    }
    return related.get(stage, set())


def _retrieve_task_candidates(text: str, stage: str, top_k: int = 3) -> List[MitreCandidate]:
    lowered = text.lower()
    tokens = _tokenize(lowered)

    def score_items(allow_related: bool) -> List[Tuple[float, Dict[str, Any]]]:
        scored: List[Tuple[float, Dict[str, Any]]] = []
        related = _related_stages_for(stage)
        for item in ATTACK_KB:
            item_stage = item["stage"]
            allowed = False
            if item_stage == stage:
                allowed = True
            elif stage == "exfiltration" and item["id"] in {"T1041", "T1071.001"}:
                allowed = True
            elif stage == "privilege-escalation" and item["id"] in {"T1548", "T1134.001"}:
                allowed = True
            elif allow_related and item_stage in related:
                allowed = True
            if not allowed:
                continue

            score = 0.0
            if item_stage == stage:
                score += 2.0
            elif allow_related and item_stage in related:
                score += 0.75

            for kw in item["keywords"]:
                kw_lower = kw.lower()
                if kw_lower in lowered:
                    score += 3.0 if " " in kw_lower else 1.5
                kw_tokens = _tokenize(kw_lower)
                if kw_tokens:
                    score += 0.7 * len(tokens & kw_tokens)

            if stage == "exfiltration" and item["id"] == "T1027":
                score -= 2.0
            if stage == "defense-evasion" and item["id"] == "T1486":
                score -= 2.5
            if stage == "discovery" and item["id"] == "T1548":
                score -= 2.0

            if score >= 0.5:
                scored.append((score, item))
        scored.sort(key=lambda x: (x[0], x[1]["id"]), reverse=True)
        return scored

    scored = score_items(allow_related=False)
    if not scored:
        scored = score_items(allow_related=True)

    results: List[MitreCandidate] = []
    for score, item in scored[:top_k]:
        results.append(MitreCandidate(
            id=item["id"],
            reason=f"retrieval match: {item['name']}",
            score=round(min(1.0, score / 8.0), 2),
            source="retrieval",
        ))
    return results


def _select_example_keys(intent: str, k: int = 3) -> List[str]:
    scored = sorted(
        ((key, _score_example(intent, key)) for key in _EXAMPLES.keys()),
        key=lambda x: (x[1], x[0]),
        reverse=True,
    )
    chosen = [key for key, _ in scored[:k]]
    fallback_order = ["info_stealer", "keylogger", "ransomware", "rat", "credential_dumper", "injector", "screenshotter"]
    for key in fallback_order:
        if key not in chosen and len(chosen) < k:
            chosen.append(key)
    return chosen[:k]


def _clamp_score(value: Any) -> Optional[float]:
    try:
        x = float(value)
    except Exception:
        return None
    return max(0.0, min(1.0, x))


def _validate_mitre_list(techniques: Any) -> List[str]:
    if not isinstance(techniques, list):
        return []
    return [t for t in techniques if isinstance(t, str) and MITRE_PATTERN.match(t)]


def _parse_mitre_candidates(value: Any) -> List[MitreCandidate]:
    candidates: List[MitreCandidate] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and MITRE_PATTERN.match(item):
                candidates.append(MitreCandidate(id=item, source="llm"))
            elif isinstance(item, dict):
                cid = item.get("id")
                if isinstance(cid, str) and MITRE_PATTERN.match(cid):
                    candidates.append(MitreCandidate(
                        id=cid,
                        reason=str(item.get("reason", "")),
                        score=_clamp_score(item.get("score")),
                        source=str(item.get("source", "llm")),
                    ))
    return candidates


def _merge_candidates(llm_candidates: List[MitreCandidate], retrieved: List[MitreCandidate], stage: str) -> Tuple[List[MitreCandidate], str, str]:
    merged: Dict[str, MitreCandidate] = {}
    for cand in llm_candidates + retrieved:
        existing = merged.get(cand.id)
        if existing is None:
            merged[cand.id] = MitreCandidate(id=cand.id, reason=cand.reason, score=cand.score, source=cand.source)
            continue
        if cand.score is not None and (existing.score is None or cand.score > existing.score):
            existing.score = cand.score
        if cand.reason and cand.reason not in existing.reason:
            existing.reason = (existing.reason + " | " + cand.reason).strip(" |")
        existing_sources = set(filter(None, existing.source.split("+")))
        existing_sources.update(filter(None, cand.source.split("+")))
        existing.source = "+".join(sorted(existing_sources)) if existing_sources else "unknown"

    ordered = sorted(merged.values(), key=lambda c: ((c.score or 0.0), c.id), reverse=True)
    ordered = [c for c in ordered if (c.score or 0.0) >= 0.35][:3]

    if stage == "data-processing":
        return [], "not_applicable", "high"
    if not ordered:
        return [], "needs_verification", "low"

    top1 = ordered[0].score or 0.0
    top2 = ordered[1].score or 0.0 if len(ordered) > 1 else 0.0
    gap = top1 - top2
    if top1 >= 0.85 and gap >= 0.20:
        confidence = "high"
    elif top1 >= 0.65 and gap >= 0.08:
        confidence = "medium"
    else:
        confidence = "low"
    return ordered, "needs_verification", confidence


def _parse_task(item: dict) -> Optional[Task]:
    try:
        required_keys = {"task_id", "stage", "intent", "behavioral_goal", "output_contract"}
        if not required_keys.issubset(item):
            return None

        stage = str(item["stage"]).lower().strip()
        if stage not in VALID_STAGES:
            return None

        out = item["output_contract"]
        output_contract = OutputContract(schema=out["schema"], fields=out["fields"], properties=out.get("properties"))

        input_contract = None
        if ic := item.get("input_contract"):
            input_contract = InputContract(sources=ic.get("sources", []))

        ec_data = item.get("error_contract", {})
        error_contract = ErrorContract(
            on_failure=ec_data.get("on_failure", "return_partial"),
            required_fields=ec_data.get("required_fields", []),
            fallback_value=ec_data.get("fallback_value"),
        )

        candidates = _parse_mitre_candidates(item.get("mitre_candidates", []))
        techniques = _validate_mitre_list(item.get("mitre_techniques", []))
        if not candidates and techniques:
            candidates = [MitreCandidate(id=t, reason="backfilled from mitre_techniques", source="legacy") for t in techniques]

        return Task(
            task_id=str(item["task_id"]),
            stage=stage,
            intent=str(item["intent"]),
            behavioral_goal=str(item["behavioral_goal"]),
            output_contract=output_contract,
            input_contract=input_contract,
            error_contract=error_contract,
            mitre_candidates=candidates,
            mitre_techniques=techniques,
            mitre_status=str(item.get("mitre_status", "needs_verification")),
            mapping_confidence=str(item.get("mapping_confidence", "medium")),
            ambiguity_notes=str(item.get("ambiguity_notes", "")),
        )
    except Exception as exc:
        print(f"  [task parse error] {exc}")
        return None


def _parse_dataflow(item: dict) -> Optional[DataFlow]:
    try:
        from_task = item.get("from_task") or item.get("from")
        to_task = item.get("to_task") or item.get("to")
        schema = item.get("data_schema") or item.get("data")
        if not (from_task and to_task and schema):
            return None
        return DataFlow(from_task=str(from_task), to_task=str(to_task), data_schema=str(schema), required=bool(item.get("required", True)), transform=item.get("transform"))
    except Exception as exc:
        print(f"  [dataflow parse error] {exc}")
        return None


def _warn_mitre_gaps(execution_graph: List[dict]) -> None:
    missing = [t for t in execution_graph if t["stage"] in ADVERSARIAL_STAGES and not t.get("mitre_candidates")]
    if missing:
        print(f"\n⚠️  {len(missing)} adversarial tasks without MITRE candidates")
        for t in missing:
            print(f"   • {t['task_id']} ({t['stage']}: {t['intent']})")
        print()


def _looks_non_atomic(task: dict) -> bool:
    text = f"{task.get('intent', '')} {task.get('behavioral_goal', '')}".lower()
    strong_verbs = ["collect", "aggregate", "encrypt", "exfil", "upload", "send", "dump", "capture", "inject", "execute", "persist", "establish", "discover", "enumerate"]
    hits = sum(1 for verb in strong_verbs if verb in text)
    return hits >= 3 and task.get("stage") != "data-processing"


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

class WindowsPythonPlanner:
    _SYSTEM_PROMPT = (
        "You are a Windows malware mission planner for security research.\n"
        "Convert a natural language intent into a structured mission plan.\n\n"
        "The mission must contain 4-8 atomic behavioral tasks.\n"
        "Each task must represent ONE behavioral objective only.\n"
        "Do not combine collection, encryption, exfiltration, persistence, or execution into a single task.\n"
        "Describe WHAT behavior happens, not HOW it is implemented.\n\n"
        "Each task must contain: task_id, stage, intent, behavioral_goal, input_contract, output_contract, error_contract, mitre_candidates, mitre_techniques, mitre_status, mapping_confidence, ambiguity_notes.\n"
        "Use 'from_task'/'to_task'/'data_schema' keys in dataflow.\n\n"
        "Valid stages: discovery, execution, credential-access, defense-evasion, exfiltration, persistence, c2-setup, data-processing, privilege-escalation, weaponization.\n\n"
        "ATT&CK rules:\n"
        "- data-processing tasks -> mitre_candidates: [] and mitre_techniques: []\n"
        "- ransomware file encryption -> candidate T1486, stage execution\n"
        "- file or directory enumeration -> candidate T1083, stage discovery\n"
        "- encrypted payload before transmission -> candidate T1027, stage defense-evasion\n"
        "- exfiltration over HTTPS -> candidates T1041 and T1071.001\n"
        "- keyboard capture -> candidate T1056.001\n"
        "- screenshot capture -> candidate T1113\n"
        "- registry Run key persistence -> candidate T1547.001\n"
        "- LSASS credential dumping -> candidate T1003.001\n\n"
        "Do NOT finalize ATT&CK mappings. mitre_techniques should stay [] unless the behavior is extremely explicit. Prefer mitre_candidates and let the verifier finalize.\n"
        "Use mapping_confidence: high, medium, or low.\n"
        "Use ambiguity_notes when multiple techniques are plausible.\n\n"
        "Field types: string, string_json, integer, boolean, bytes, array, dict, float.\n"
        "Tasks serializing data should output string_json. AES encryption tasks should include key: bytes.\n\n"
        "Output ONLY valid JSON. No markdown. No explanations.\n"
    )

    def __init__(self, policy: Optional[PolicyFlags] = None, stack_name: str = "openai", out_dir: str = "artifacts/missions") -> None:
        load_dotenv(override=True)
        self.policy = policy or PolicyFlags()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        self.client = OpenAI()
        self.stack = stack_name
        self.out_dir = Path(out_dir)

    def _normalize_intent(self, intent: str) -> str:
        prompt = (
            "Rewrite the following malware intent into one concise, clear behavioral objective. "
            "Do not add new capabilities or steps. Clarify only what is already implied. "
            "Keep it to one sentence.\n\n"
            f"Intent: {intent}"
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=120,
            )
            normalized = (response.choices[0].message.content or "").strip()
            return normalized or intent
        except Exception:
            return intent

    def plan(self, intent: str) -> Dict[str, Any]:
        normalized_intent = self._normalize_intent(intent)
        mission = self._generate_with_retry(normalized_intent)
        _warn_mitre_gaps(mission["execution_graph"])
        mission.update(
            ts_utc=_utc_now(),
            model_used=self.model,
            task_count=len(mission["execution_graph"]),
            original_intent=intent,
            normalized_intent=normalized_intent,
        )
        if "planner_summary" in mission:
            mission["planner_summary"]["normalized_intent"] = normalized_intent
            mission["planner_summary"]["mitre_selection_mode"] = "retrieval_constrained_candidate_generation"
        path = self._persist(mission)
        mission["mission_path"] = str(path)
        return mission

    def _build_user_prompt(self, intent: str) -> Tuple[str, List[str], float, List[Dict[str, Any]]]:
        selected = _select_example_keys(intent, k=3)
        sections: List[str] = []
        for idx, key in enumerate(selected, start=1):
            sections.append(f"EXAMPLE {idx} ({key.replace('_', ' ').title()}):\n{_EXAMPLES[key]}")
        primary = selected[0] if selected else _detect_example_key(intent)
        temperature = _TEMPERATURE_MAP.get(primary, 0.3)
        retrieval_hints = _mission_retrieval_hints(intent, top_k=6)
        retrieval_block = "\n".join(f"- {item['id']} [{item['stage']}] {item['name']} (score={item['score']})" for item in retrieval_hints) or "- none"
        prompt = (
            "\n\n".join(sections)
            + "\n\n"
            + _TASK_PATTERNS
            + "\n\nRETRIEVAL HINTS FOR THIS INTENT:\n"
            + retrieval_block
            + "\n\n─────────────────────────────────────────\n\n"
            + f'Generate a mission plan for:\nIntent: "{intent}"\n\n'
            + "Use the examples only as structural guidance. Do not blindly copy them. "
              "Choose the pattern most relevant to the intent. Decompose into 4-8 atomic tasks. "
              "Prefer mitre_candidates over final mitre_techniques. Return ONLY valid JSON."
        )
        return prompt, selected, temperature, retrieval_hints

    def _generate_with_retry(self, intent: str, max_retries: int = 3) -> Dict[str, Any]:
        user_prompt, selected_examples, temperature, retrieval_hints = self._build_user_prompt(intent)
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self._SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=temperature,
                    max_tokens=3500,
                )
                raw = (response.choices[0].message.content or "{}").strip()
                mission = self._parse_and_validate(raw, intent)
                mission["planner_summary"] = {
                    "selected_examples": selected_examples,
                    "selection_mode": "dynamic_few_shot_top3",
                    "planner_temperature": temperature,
                    "intent_retrieval_hints": retrieval_hints,
                }
                return mission
            except Exception as exc:
                msg = str(exc)
                print(f"Attempt {attempt + 1}/{max_retries}: {type(exc).__name__} — {msg[:120]}")
                if "rate_limit" in msg.lower() or "429" in msg:
                    wait = 30 * (2 ** attempt)
                    print(f"Rate limited — waiting {wait}s …")
                    if attempt < max_retries - 1:
                        time.sleep(wait)
                elif attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        print("All attempts failed — using fallback plan.")
        return self._fallback_plan(intent)

    def _parse_and_validate(self, raw: str, intent: str) -> Dict[str, Any]:
        for fence in ("```json", "```"):
            raw = raw.replace(fence, "")
        raw = raw.strip()
        data: Dict[str, Any] = json.loads(raw)
        required_keys = {"mission_id", "intent", "global_constraints", "execution_graph", "dataflow"}
        if not required_keys.issubset(data):
            raise ValueError(f"Missing keys: {required_keys - data.keys()}")
        data.setdefault("global_constraints", {})
        data["global_constraints"]["target_os_family"] = "windows"
        data["global_constraints"]["language_target"] = "python"
        data.setdefault("malware_type", "generic")
        data.setdefault("validation_rules", asdict(ValidationRules()))

        tasks = [t for item in data["execution_graph"] if (t := _parse_task(item))]
        if len(tasks) < 2:
            raise ValueError(f"Only {len(tasks)} valid tasks parsed (need ≥2)")
        ids = [t.task_id for t in tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate task_id values detected")

        flows = [f for item in data["dataflow"] if (f := _parse_dataflow(item))]
        task_by_id = {t.task_id: t for t in tasks}
        planner_warnings: List[str] = []
        for flow in flows:
            if flow.from_task not in task_by_id:
                raise ValueError(f"dataflow source does not exist: {flow.from_task}")
            if flow.to_task not in task_by_id:
                raise ValueError(f"dataflow target does not exist: {flow.to_task}")
            source_schema = task_by_id[flow.from_task].output_contract.schema
            if source_schema != flow.data_schema:
                planner_warnings.append(f"dataflow schema mismatch: {flow.from_task} outputs {source_schema} but edge declares {flow.data_schema}")

        incoming: Dict[str, set[Tuple[str, str]]] = {}
        for flow in flows:
            incoming.setdefault(flow.to_task, set()).add((flow.from_task, flow.data_schema))

        for task in tasks:
            if _looks_non_atomic(asdict(task)):
                planner_warnings.append(f"task {task.task_id} may not be atomic")

            retrieved = _retrieve_task_candidates(f"{task.intent}. {task.behavioral_goal}", task.stage, top_k=3)
            merged_candidates, merged_status, merged_confidence = _merge_candidates(task.mitre_candidates, retrieved, task.stage)
            if retrieved and not task.mitre_candidates and task.stage != "data-processing":
                planner_warnings.append(f"task {task.task_id} had no LLM MITRE candidates; retrieval backfilled candidates")
            task.mitre_candidates = merged_candidates
            task.mitre_status = merged_status
            task.mapping_confidence = merged_confidence

            if task.stage == "data-processing" and task.mitre_candidates:
                planner_warnings.append(f"task {task.task_id} is data-processing but has MITRE candidates")
                task.mitre_candidates = []
                task.mitre_status = "not_applicable"
                task.mapping_confidence = "high"

            if task.stage != "data-processing" and len(task.mitre_candidates) >= 2:
                s1 = task.mitre_candidates[0].score or 0.0
                s2 = task.mitre_candidates[1].score or 0.0
                if abs(s1 - s2) <= 0.08 and not task.ambiguity_notes:
                    task.ambiguity_notes = f"candidate scores are close ({task.mitre_candidates[0].id} vs {task.mitre_candidates[1].id})"

            if task.input_contract:
                expected = {(str(src.get("task_id")), str(src.get("schema"))) for src in task.input_contract.sources}
                actual = incoming.get(task.task_id, set())
                missing = expected - actual
                if missing:
                    planner_warnings.append(f"task {task.task_id} missing dataflow edges for inputs: {sorted(missing)}")
                for src in task.input_contract.sources:
                    upstream_id = str(src.get("task_id"))
                    upstream_schema = str(src.get("schema"))
                    upstream_task = task_by_id.get(upstream_id)
                    if upstream_task and upstream_task.output_contract.schema != upstream_schema:
                        planner_warnings.append(f"task {task.task_id} expects {upstream_schema} from {upstream_id}, but upstream outputs {upstream_task.output_contract.schema}")

        data["execution_graph"] = [asdict(t) for t in tasks]
        data["dataflow"] = [asdict(f) for f in flows]
        data["planner_warnings"] = planner_warnings
        return data

    def _fallback_plan(self, intent: str) -> Dict[str, Any]:
        normalized_intent = intent
        return {
            "mission_id": f"fallback_{uuid.uuid4().hex[:8]}",
            "intent": intent,
            "malware_type": "generic",
            "global_constraints": asdict(GlobalConstraints()),
            "validation_rules": asdict(ValidationRules()),
            "execution_graph": [
                asdict(Task(
                    task_id="T1", stage="discovery", intent="Environment Check", behavioral_goal="Identify basic Windows environment information",
                    output_contract=OutputContract(schema="WindowsEnvironment", fields={"os_version": "string"}),
                    error_contract=ErrorContract(on_failure="abort_mission", required_fields=["os_version"]),
                    mitre_candidates=[MitreCandidate(id="T1082", reason="system information discovery", score=0.85, source="fallback")],
                    mitre_techniques=[], mitre_status="needs_verification", mapping_confidence="medium", ambiguity_notes="",
                )),
                asdict(Task(
                    task_id="T2", stage="execution", intent="Execute Objective", behavioral_goal=f"Accomplish the primary mission objective derived from the intent: {intent[:100]}",
                    input_contract=InputContract(sources=[{"task_id": "T1", "schema": "WindowsEnvironment"}]),
                    output_contract=OutputContract(schema="ExecutionResult", fields={"status": "string"}),
                    error_contract=ErrorContract(on_failure="abort_mission", required_fields=["status"]),
                    mitre_candidates=[], mitre_techniques=[], mitre_status="needs_verification", mapping_confidence="low", ambiguity_notes="fallback mission requires verifier refinement",
                )),
            ],
            "dataflow": [asdict(DataFlow(from_task="T1", to_task="T2", data_schema="WindowsEnvironment"))],
            "planner_summary": {
                "selected_examples": ["fallback"],
                "selection_mode": "fallback",
                "planner_temperature": 0.0,
                "mitre_selection_mode": "retrieval_constrained_candidate_generation",
                "normalized_intent": normalized_intent,
            },
            "planner_warnings": ["fallback plan used after repeated generation failures"],
        }

    def _persist(self, mission: Dict[str, Any]) -> Path:
        self.out_dir.mkdir(parents=True, exist_ok=True)

        malware_type = str(mission.get("malware_type", "generic"))
        mission_id = str(mission.get("mission_id", "mission"))

        def _safe_name(x: str) -> str:
            import re
            x = x.strip().lower()
            x = re.sub(r"[\\/:\*\?\"<>\|]+", "_", x)   # thay / \ : * ? " < > |
            x = re.sub(r"\s+", "_", x)                 # thay khoảng trắng
            x = re.sub(r"_+", "_", x)                  # gộp nhiều _
            return x.strip("_") or "generic"

        safe_malware_type = _safe_name(malware_type)
        safe_mission_id = _safe_name(mission_id)

        uid = uuid.uuid4().hex[:8]
        fname = f"{self.stack}_{safe_malware_type}_{uid}_{safe_mission_id}.json"
        fpath = self.out_dir / fname

        fpath.write_text(
            json.dumps(mission, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        print(f"✓ Mission saved → {fpath}")
        return fpath

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Windows Python Mission Planner")
    parser.add_argument("--intent", required=True)
    parser.add_argument("--policy-network", default="blocked", choices=["blocked", "localhost-only", "full"])
    parser.add_argument("--out-dir", default="artifacts/missions")
    args = parser.parse_args()
    planner = WindowsPythonPlanner(policy=PolicyFlags(network=args.policy_network), out_dir=args.out_dir)
    result = planner.plan(args.intent)
    print(json.dumps(result, indent=2, ensure_ascii=False))
