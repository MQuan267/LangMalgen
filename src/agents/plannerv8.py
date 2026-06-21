"""
planner_v9.py – Windows Python Mission Planner (v9)
====================================================
Patches applied on top of v8:

  PATCH 1: T1071.001 duplicate in ATTACK_KB → merged into single entry
           Added "beacon", "callback" keywords
  PATCH 2: FALLBACK_STAGE_BY_TYPE constant + _fallback_plan uses it
  PATCH 3: IntentNormalizer._CAPABILITY_GROUPS (class variable, pre-__init__)
           + _introduced_new_capability() capability injection guard
           + expanded keywords: beacon/callback, network configuration, encode/packed/compressed
  PATCH 4: _EXAMPLE_META completed for browser_stealer/clipper/rootkit/loader/screenshotter
           clipper family = "collection" (not "impact")
  PATCH 5: _EXAMPLE_SUMMARIES completed, MITRE IDs removed (replaced with behavioral desc)
  PATCH 6: _is_legitimate_prerequisite discovery branch → 3-condition check
           (goal verb + goal object + intent object)
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
try:
    import fcntl
except ImportError:
    # Nếu chạy trên Windows, fcntl không tồn tại, ta dùng portalocker
    import portalocker 
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from dotenv import load_dotenv
from openai import OpenAI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_STAGES = frozenset({
    "recon", "discovery", "initial-access", "execution",
    "privilege-escalation", "persistence", "defense-evasion",
    "exfiltration", "lateral-movement", "credential-access",
    "weaponization", "c2-setup", "data-processing", "collection",
})

ADVERSARIAL_STAGES = frozenset({
    "discovery", "credential-access", "persistence",
    "defense-evasion", "exfiltration", "execution",
    "privilege-escalation", "lateral-movement",
    "c2-setup", "initial-access",
})

VALID_ON_FAILURE = frozenset({
    "abort_mission", "return_partial", "retry", "skip",
})

MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
WORD_RE = re.compile(r"[a-z0-9_\-\.]+")
MIN_TOKEN_LEN = 2

INTENT_KEYWORD_MAP: list[tuple[list[str], str]] = [
    (["keylog", "keystroke", "keyboard", "monitor input", "capture key"], "keylogger"),
    (["lsass", "credential dump", "password dump", "hash dump", "ntlm dump", "dump cred", "mimikatz"], "credential_dumper"),
    (["info steal", "system info", "collect system", "gather system", "sysinfo",
      "collect host information", "gather host information", "host profiling"], "info_stealer"),
    (["collect sensitive", "collect local files", "gather sensitive", "harvest files",
      "retrieve local files", "copy files from", "local file collection"], "file_collector"),
    (["ransom", "encrypt file", "lock file", "decrypt demand", "bitcoin ransom", "wanna"], "ransomware"),
    (["rat ", "remote access trojan", "remote shell", "reverse shell", "c2 shell", "backdoor shell"], "rat"),
    (["inject", "dll inject", "process hollow", "shellcode inject", "reflective load"], "injector"),
    (["backdoor", "persist shell", "hidden shell", "covert access"], "rat"),
    (["screenshot", "screen capture", "screengrab", "desktop capture"], "screenshotter"),
    (["wipe", "wiper", "destroy data", "overwrite file", "destructive"], "wiper"),
    (["loader", "dropper", "stage payload", "download execute", "fetch payload"], "loader"),
    (["browser steal", "cookie steal", "browser credential", "autofill"], "browser_stealer"),
    (["clipboard", "clipper", "crypto address", "wallet address"], "clipper"),
    (["rootkit", "hide process", "kernel hook", "ssdt"], "rootkit"),
]

_TEMPERATURE_MAP = {
    "keylogger": 0.35,
    "credential_dumper": 0.25,
    "ransomware": 0.30,
    "rat": 0.35,
    "injector": 0.30,
    "screenshotter": 0.30,
    "wiper": 0.30,
    "loader": 0.30,
    "browser_stealer": 0.30,
    "clipper": 0.30,
    "rootkit": 0.25,
    "file_collector": 0.30,
    "unknown": 0.30,
}

# PATCH 2: fallback stage map
FALLBACK_STAGE_BY_TYPE: Dict[str, str] = {
    "credential_dumper": "credential-access",
    "browser_stealer":   "credential-access",

    "rat":               "c2-setup",

    "rootkit":           "defense-evasion",

    "file_collector":    "collection",

    "keylogger":         "execution",
    "injector":          "execution",
    "ransomware":        "execution",
    "wiper":             "execution",
    "loader":            "execution",
    "clipper":           "execution",
    "screenshotter":     "execution",
    "info_stealer":      "execution",

    "unknown":           "execution",
}

EXAMPLE_INTENT_HINTS: Dict[str, str] = {
    "info_stealer": "collect system information aggregate data encrypt payload exfiltrate over https",
    "keylogger": "capture keyboard input buffer logs encrypt logs exfiltrate logs registry persistence",
    "credential_dumper": "check privileges access lsass dump credentials encrypt dump exfiltrate cleanup",
    "ransomware": "enumerate files encrypt files protect key exfiltrate recovery key drop ransom note",
    "rat": "establish command and control receive commands execute operator actions persistence defense evasion",
    "injector": "find target process escalate privileges inject shellcode execute remote thread",
    "screenshotter": "capture screenshots compress image encrypt screenshot exfiltrate image",
    "wiper": "enumerate target files overwrite data destroy recovery remove traces",
    "loader": "download payload decrypt stage execute payload establish persistence",
    "browser_stealer": "locate browser data extract cookies extract credentials encrypt exfiltrate",
    "clipper": "monitor clipboard detect crypto address replace address maintain persistence",
    "rootkit": "escalate privileges hook system calls hide process kernel manipulation persist stealthily",
    "file_collector": "collect sensitive files local filesystem obfuscate encode payload download transfer tools remote server",
}

# ---------------------------------------------------------------------------
# PATCH 4: _EXAMPLE_META — completed for all supported types
# ---------------------------------------------------------------------------

_EXAMPLE_META: Dict[str, Dict[str, str]] = {
    "info_stealer":      {"shape": "collect_protect_exfil",                     "family": "collection"},
    "keylogger":         {"shape": "hook_buffer_protect_exfil_persist",          "family": "input_capture"},
    "credential_dumper": {"shape": "escalate_access_dump_protect_exfil_cleanup", "family": "credential_access"},
    "ransomware":        {"shape": "discover_encrypt_protect_exfil",             "family": "impact"},
    "injector":          {"shape": "escalate_inject_execute",                    "family": "execution"},
    "wiper":             {"shape": "discover_destroy_cleanup",                   "family": "impact"},
    "rat":               {"shape": "c2_execute_persist_evade",                   "family": "c2"},
    # PATCH 4: new entries — clipper family = "collection" not "impact"
    "browser_stealer":   {"shape": "locate_extract_protect_exfil",               "family": "credential_access"},
    "clipper":           {"shape": "monitor_intercept_replace_persist",          "family": "collection"},
    "rootkit":           {"shape": "escalate_hook_hide_persist",                 "family": "defense_evasion"},
    "loader":            {"shape": "fetch_decrypt_stage_execute",                "family": "execution"},
    "screenshotter":     {"shape": "capture_compress_protect_exfil",             "family": "collection"},
    # PATCH file_collector
    "file_collector":    {"shape": "collect_encode_transfer",                    "family": "collection"},
}

# ---------------------------------------------------------------------------
# PATCH 5: _EXAMPLE_SUMMARIES — completed, MITRE IDs removed
# ---------------------------------------------------------------------------

_EXAMPLE_SUMMARIES: Dict[str, str] = {
    "info_stealer": (
        "Shape: collect → protect → exfil\n"
        "Core stages: discovery, data-processing, defense-evasion, exfiltration\n"
        "Behavior: collect system info, encrypt, send to remote\n"
        "Has exfiltration. No persistence."
    ),
    "keylogger": (
        "Shape: hook → buffer → protect → exfil → persist\n"
        "Core stages: execution, data-processing, defense-evasion, exfiltration, persistence\n"
        "Behavior: capture keystrokes, encrypt logs, exfiltrate, persist via registry\n"
        "Has exfiltration. Has persistence."
    ),
    "credential_dumper": (
        "Shape: escalate → access → dump → protect → exfil → cleanup\n"
        "Core stages: privilege-escalation, credential-access, defense-evasion, exfiltration\n"
        "Behavior: escalate privileges, dump LSASS, encrypt dump, exfiltrate, cleanup\n"
        "Has exfiltration. Has cleanup."
    ),
    "ransomware": (
        "Shape: discover → encrypt → protect → exfil\n"
        "Core stages: discovery, execution, defense-evasion, exfiltration\n"
        "Behavior: enumerate files, encrypt in place, protect key, send key to remote\n"
        "Has exfiltration. No persistence."
    ),
    "injector": (
        "Shape: escalate → inject → execute\n"
        "Core stages: privilege-escalation, execution\n"
        "Behavior: acquire debug privilege, inject shellcode, trigger remote thread\n"
        "No exfiltration. No persistence."
    ),
    "wiper": (
        "Shape: discover → destroy → cleanup\n"
        "Core stages: discovery, execution, defense-evasion\n"
        "Behavior: enumerate target files, overwrite with random data, remove traces\n"
        "No exfiltration. No persistence."
    ),
    "rat": (
        "Shape: c2 → execute → persist → evade\n"
        "Core stages: c2-setup, execution, persistence, defense-evasion\n"
        "Behavior: establish C2 channel, dispatch commands, persist, masquerade process\n"
        "No exfiltration. Has persistence."
    ),
    # PATCH 5: new summaries — no MITRE IDs, behavioral descriptions only
    "browser_stealer": (
        "Shape: locate → extract → protect → exfil\n"
        "Core stages: discovery, credential-access, defense-evasion, exfiltration\n"
        "Behavior: steal browser-stored credentials and cookies, encrypt, send to remote\n"
        "Has exfiltration. No persistence."
    ),
    "clipper": (
        "Shape: monitor → intercept → replace → persist\n"
        "Core stages: execution, defense-evasion, persistence\n"
        "Behavior: intercept clipboard data, replace crypto addresses, maintain persistence\n"
        "No exfiltration. Has persistence."
    ),
    "rootkit": (
        "Shape: escalate → hook → hide → persist\n"
        "Core stages: privilege-escalation, defense-evasion, persistence\n"
        "Behavior: escalate privileges, hook system calls, hide presence, persist stealthily\n"
        "No exfiltration. Has persistence."
    ),
    "loader": (
        "Shape: fetch → decrypt → stage → execute\n"
        "Core stages: execution, defense-evasion\n"
        "Behavior: download and execute staged payload, decrypt before execution\n"
        "No exfiltration. No persistence."
    ),
    "screenshotter": (
        "Shape: capture → compress → protect → exfil\n"
        "Core stages: execution, data-processing, defense-evasion, exfiltration\n"
        "Behavior: capture screen data, compress, encrypt, send to remote\n"
        "Has exfiltration. No persistence."
    ),
    "file_collector": (
        "Shape: collect → encode → transfer\n"
        "Core stages: collection, defense-evasion, exfiltration\n"
        "Behavior: collect sensitive local files, obfuscate/encode payload, download or transfer tools from remote\n"
        "Has exfiltration. No persistence."
    ),
}

# ---------------------------------------------------------------------------
# ATTACK_KB with keyword weights
# PATCH 1: T1071.001 — single entry, stage=c2-setup, cross_stages=["exfiltration"]
#          Added "beacon", "callback" keywords
# ---------------------------------------------------------------------------

@dataclass
class AttackEntry:
    id: str
    stage: str
    name: str
    keywords: List[Dict[str, str]]
    cross_stages: List[str] = field(default_factory=list)


def _kw(word: str, weight: str = "strong") -> Dict[str, str]:
    return {"kw": word, "weight": weight}


ATTACK_KB: List[AttackEntry] = [
    # ── DISCOVERY ──
    AttackEntry("T1082", "discovery", "System Information Discovery",
        [_kw("system information"), _kw("os version"), _kw("hostname"), _kw("architecture"),
         _kw("computer name"), _kw("environment info"),
         _kw("os", "weak"), _kw("system", "weak")]),

    AttackEntry("T1016", "discovery", "System Network Configuration Discovery",
        [_kw("network configuration"), _kw("ip address"), _kw("ip addresses"),
        _kw("subnet mask"), _kw("subnet masks"), _kw("dns server"),
        _kw("default gateway"), _kw("network adapter"),
        _kw("interface configuration"), _kw("routing table"),
        _kw("ipconfig"), _kw("network", "weak"), _kw("ip", "weak")]),

    AttackEntry("T1033", "discovery", "System Owner/User Discovery",
        [_kw("current user"), _kw("whoami"), _kw("username discovery"),
         _kw("logged in user"), _kw("account discovery"),
         _kw("user", "weak"), _kw("account", "weak")]),

    AttackEntry("T1083", "discovery", "File and Directory Discovery",
        [_kw("enumerate files"), _kw("list files"), _kw("file discovery"),
         _kw("directory discovery"), _kw("file system scan"),
         _kw("file", "weak"), _kw("directory", "weak"), _kw("path", "weak")]),

    AttackEntry("T1057", "discovery", "Process Discovery",
        [_kw("process discovery"), _kw("enumerate process"), _kw("tasklist"),
         _kw("running process"), _kw("target process"),
         _kw("process", "weak"), _kw("pid", "weak")]),

    AttackEntry("T1012", "discovery", "Query Registry",
        [_kw("query registry"), _kw("read registry"), _kw("registry key"),
         _kw("registry value"), _kw("regedit")]),

    AttackEntry("T1047", "discovery", "Windows Management Instrumentation",
        [_kw("wmi query"), _kw("wmic discovery"),
         _kw("wmi", "weak"), _kw("wmic", "weak")],
        cross_stages=["execution"]),

    AttackEntry("T1518.001", "discovery", "Security Software Discovery",
        [_kw("security software"), _kw("antivirus discovery"), _kw("edr discovery"),
         _kw("defender discovery"), _kw("discover security tool")]),

    # ── CREDENTIAL ACCESS ──
    AttackEntry("T1003.001", "credential-access", "LSASS Memory",
        [_kw("lsass"), _kw("mimikatz"), _kw("minidump lsass"), _kw("comsvcs dump"),
         _kw("credential dump"), _kw("dump memory credential"),
         _kw("credential", "weak"), _kw("password", "weak"), _kw("ntlm", "weak"), _kw("hash", "weak")]),

    AttackEntry("T1552.001", "credential-access", "Credentials In Files",
        [_kw("credential file"), _kw("password file"), _kw("plaintext password"),
         _kw("stored credential"), _kw("config file credential")]),

    AttackEntry("T1110", "credential-access", "Brute Force",
        [_kw("brute force"), _kw("password spray"), _kw("credential stuffing"),
         _kw("guess password")]),

    AttackEntry("T1557.001", "credential-access", "LLMNR/NBT-NS Poisoning",
        [_kw("llmnr"), _kw("nbt-ns"), _kw("responder poisoning"),
         _kw("credential intercept")]),

    # ── EXECUTION ──
    AttackEntry("T1056.001", "execution", "Keylogging",
        [_kw("keylog"), _kw("keystroke"), _kw("keyboard hook"), _kw("input capture"),
         _kw("pynput keyboard"), _kw("capture key")]),

    AttackEntry("T1113", "execution", "Screen Capture",
        [_kw("screenshot"), _kw("screen capture"), _kw("desktop capture"),
         _kw("screengrab"), _kw("capture screen"), _kw("bitmap capture")]),

    AttackEntry("T1059.003", "execution", "Windows Command Shell",
        [_kw("cmd.exe"), _kw("command shell"), _kw("batch command"),
         _kw("windows command"), _kw("run command"),
         _kw("cmd", "weak")]),

    AttackEntry("T1106", "execution", "Native API",
        [_kw("native api"), _kw("win32api"), _kw("ctypes call"), _kw("winapi"),
         _kw("windows api call"), _kw("system call")]),

    AttackEntry("T1055", "execution", "Process Injection",
        [_kw("process injection"), _kw("shellcode inject"), _kw("remote thread"),
         _kw("writeprocessmemory"), _kw("dll inject"), _kw("reflective load"),
         _kw("inject", "weak")],
        cross_stages=["defense-evasion"]),

    AttackEntry("T1486", "execution", "Data Encrypted for Impact",
        [_kw("encrypt files"), _kw("ransom encrypt"), _kw("data encrypted for impact"),
         _kw("locked extension"), _kw("aes encrypt file"),
         _kw("ransom", "weak")]),

    AttackEntry("T1204.002", "execution", "User Execution: Malicious File",
        [_kw("user execution"), _kw("malicious file"), _kw("open attachment"),
         _kw("execute payload"), _kw("run file")]),

    AttackEntry("T1569.002", "execution", "Service Execution",
        [_kw("service execution"), _kw("psexec service"), _kw("start service"),
         _kw("windows service run")]),

    AttackEntry("T1485", "execution", "Data Destruction",
        [_kw("destroy data"), _kw("wipe data"), _kw("overwrite file"),
        _kw("data destruction"), _kw("corrupt file"),
        _kw("wiper", "weak"), _kw("destructive", "weak")]),

    # ── PRIVILEGE ESCALATION ──
    AttackEntry("T1548", "privilege-escalation", "Abuse Elevation Control Mechanism",
        [_kw("elevate privilege"), _kw("bypass uac"), _kw("uac bypass"),
         _kw("elevated privileges"), _kw("admin privilege"),
         _kw("uac", "weak"), _kw("elevate", "weak")],
        cross_stages=["execution"]),

    AttackEntry("T1068", "privilege-escalation", "Exploitation for Privilege Escalation",
        [_kw("kernel exploit"), _kw("local exploit"), _kw("privilege escalation exploit"),
         _kw("cve privilege")]),

    AttackEntry("T1548.002", "privilege-escalation", "Bypass User Account Control",
        [_kw("bypass uac"), _kw("uac bypass"), _kw("user account control bypass"),
         _kw("elevated token")]),

    AttackEntry("T1134.001", "privilege-escalation", "Access Token Manipulation",
        [_kw("token manipulation"), _kw("token impersonation"), _kw("access token"),
         _kw("privilege token"), _kw("impersonate token")]),

    # ── PERSISTENCE ──
    AttackEntry("T1547.001", "persistence", "Registry Run Keys / Startup Folder",
        [_kw("registry run key"), _kw("autorun"), _kw("startup folder"),
         _kw("hkcu run"), _kw("hklm run"), _kw("logon persistence"),
         _kw("startup", "weak")]),

    AttackEntry("T1053.005", "persistence", "Scheduled Task",
        [_kw("scheduled task"), _kw("schtasks"), _kw("task scheduler"),
         _kw("cron job"), _kw("at command")]),

    AttackEntry("T1543.003", "persistence", "Windows Service",
        [_kw("create service"), _kw("sc create"), _kw("service install"),
         _kw("service persist"), _kw("windows service persist")]),

    AttackEntry("T1574.002", "persistence", "DLL Side-Loading",
        [_kw("dll side-load"), _kw("dll hijack"), _kw("phantom dll"),
         _kw("side loading"), _kw("dll search order"), _kw("hijack dll"),
         _kw("load malicious dll"), _kw("dll hijacking")],
        cross_stages=["execution", "defense-evasion"]),

    # ── DEFENSE EVASION ──
    AttackEntry("T1027", "defense-evasion", "Obfuscated Files or Information",
        [_kw("encrypt payload"), _kw("obfuscate"), _kw("encrypted logs"),
         _kw("base64 encode payload"), _kw("packed binary"), _kw("obfuscated code"),
         _kw("compress", "weak")]),

    AttackEntry("T1140", "defense-evasion", "Deobfuscate/Decode Files",
        [_kw("decode payload"), _kw("decrypt payload"), _kw("deobfuscate"),
         _kw("base64 decode"), _kw("unpack payload"), _kw("decrypt config")]),

    AttackEntry("T1070.004", "defense-evasion", "File Deletion",
        [_kw("delete file"), _kw("cleanup artifact"), _kw("securely delete"),
         _kw("wipe file"), _kw("erase artifact"), _kw("remove traces"),
         _kw("cleanup", "weak")]),

    AttackEntry("T1112", "defense-evasion", "Modify Registry",
        [_kw("modify registry"), _kw("write registry"), _kw("reg add"),
         _kw("registry modify")]),

    AttackEntry("T1562.001", "defense-evasion", "Disable or Modify Tools",
        [_kw("disable defender"), _kw("disable antivirus"), _kw("kill edr"),
         _kw("stop security service"), _kw("disable logging"),
         _kw("turn off security")]),

    AttackEntry("T1036.005", "defense-evasion", "Masquerading",
        [_kw("masquerade"), _kw("rename process"), _kw("spoof process name"),
         _kw("legitimate name"), _kw("hide identity")]),

    AttackEntry("T1078", "defense-evasion", "Valid Accounts",
        [_kw("valid account"), _kw("stolen credential login"), _kw("compromised account"),
         _kw("reuse credential"), _kw("valid account access"),
         _kw("credential reuse login")],
        cross_stages=["initial-access"]),

    AttackEntry("T1218.011", "defense-evasion", "Rundll32",
        [_kw("rundll32"), _kw("comsvcs.dll"), _kw("lolbin"),
         _kw("living off the land")]),

    AttackEntry("T1564.001", "defense-evasion", "Hidden Files and Directories",
        [_kw("hidden file"), _kw("attrib hidden"), _kw("conceal file"),
         _kw("hide file")]),

    # ── EXFILTRATION ──
    AttackEntry("T1041", "exfiltration", "Exfiltration Over C2 Channel",
        [_kw("exfiltrate"), _kw("send data out"), _kw("upload stolen"),
         _kw("transmit data"), _kw("data exfiltration"), _kw("send to c2")],
        cross_stages=["c2-setup"]),

    # PATCH 1: T1071.001 — single entry, merged keywords, beacon/callback added
    AttackEntry("T1071.001", "c2-setup", "Web Protocols",
        [_kw("https c2"), _kw("http beacon"), _kw("web c2"),
         _kw("c2 channel"), _kw("command control https"),
         _kw("https exfil"), _kw("http post exfil"), _kw("web protocol c2"),
         _kw("c2 over https"), _kw("beacon https"),
         _kw("beacon"), _kw("callback"),
         _kw("https", "weak"), _kw("http", "weak")],
        cross_stages=["exfiltration"]),

    AttackEntry("T1105", "exfiltration", "Ingress Tool Transfer",
        [_kw("download payload"), _kw("fetch tool"), _kw("retrieve from c2"),
         _kw("drop tool"), _kw("download file"), _kw("transfer tool"),
         _kw("download additional tools"), _kw("download tool from"),
         _kw("fetch from remote server"), _kw("retrieve tool from server"),
         _kw("remote download"), _kw("download", "weak")],
        cross_stages=["collection"]),

    # PATCH: T1005 — Data from Local System
    AttackEntry("T1005", "collection", "Data from Local System",
        [_kw("collect sensitive files"), _kw("collect files"), _kw("gather files"),
         _kw("gather sensitive data"), _kw("retrieve local files"), _kw("copy files"),
         _kw("harvest files"), _kw("local file collection"), _kw("sensitive files"),
         _kw("data collection from system"), _kw("collect local data"),
         _kw("collect", "weak"), _kw("harvest", "weak")],
        cross_stages=["discovery", "exfiltration"]),

    AttackEntry("T1074.001", "exfiltration", "Local Data Staging",
        [_kw("stage data"), _kw("collect data"), _kw("aggregate files"),
         _kw("local staging"), _kw("gather before exfil")]),

    # ── LATERAL MOVEMENT ──
    AttackEntry("T1021.001", "lateral-movement", "Remote Desktop Protocol",
        [_kw("rdp"), _kw("remote desktop"), _kw("mstsc"),
         _kw("rdp session")]),

    AttackEntry("T1570", "lateral-movement", "Lateral Tool Transfer",
        [_kw("lateral movement"), _kw("spread tool"), _kw("remote copy"),
         _kw("psexec lateral"), _kw("move to system")]),

    AttackEntry("T1090", "lateral-movement", "Proxy",
        [_kw("proxy"), _kw("proxychains"), _kw("tunnel traffic"),
         _kw("redirect traffic"), _kw("network proxy")],
        cross_stages=["c2-setup"]),

    # ── COMMAND AND CONTROL ──
    # PATCH FIX3: T1573.001 — Encrypted Channel
    AttackEntry("T1573.001", "c2-setup", "Encrypted Channel: Symmetric Cryptography",
        [_kw("encrypt c2 channel"), _kw("tls encryption"), _kw("ssl tls"),
         _kw("encrypt traffic"), _kw("encrypted channel"), _kw("secure channel"),
         _kw("secure communication"), _kw("tls c2"), _kw("encrypt communication"),
         _kw("tls", "weak"), _kw("ssl", "weak"), _kw("encrypt", "weak")],
        cross_stages=["exfiltration"]),
    AttackEntry("T1095", "c2-setup", "Non-Application Layer Protocol",
        [_kw("raw socket"), _kw("tcp c2"), _kw("udp c2"),
         _kw("custom protocol"), _kw("icmp tunnel"),
         _kw("non-http", "weak")]),

    AttackEntry("T1219", "c2-setup", "Remote Access Software",
        [_kw("screenconnect"), _kw("anydesk"), _kw("teamviewer"),
         _kw("remote monitoring"), _kw("commercial rat"),
         _kw("remote utilities")]),

    # ── INITIAL ACCESS ──
    AttackEntry("T1566.001", "initial-access", "Spearphishing Attachment",
        [_kw("spearphish"), _kw("phishing email"), _kw("malicious attachment"),
         _kw("lure document"), _kw("phishing", "weak")]),

    AttackEntry("T1190", "initial-access", "Exploit Public-Facing Application",
        [_kw("exploit public"), _kw("web shell"), _kw("remote code execution"),
         _kw("rce exploit"), _kw("vulnerability exploit"),
         _kw("cve", "weak")]),


]

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PolicyFlags:
    network: str = "allowed"
    os_introspection: str = "no mock"
    max_tasks: int = 8
    min_tasks: int = 2


@dataclass
class OutputContract:
    schema: str
    fields: Dict[str, str]


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
  "validation_rules": {"max_execution_time_seconds":60,"max_memory_mb":150,"allowed_modules":["os","platform","wmi","json","Crypto.Cipher","requests"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Collect OS Info","behavioral_goal":"Gather OS version, hostname, architecture","input_contract":null,"output_contract":{"schema":"OSInfo","fields":{"os_version":"string","hostname":"string","architecture":"string"}},"error_contract":{"on_failure":"abort_mission","required_fields":["os_version"],"fallback_value":null},"mitre_candidates":[{"id":"T1082","reason":"system information discovery","score":0.92,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"discovery","intent":"Collect User Info","behavioral_goal":"Retrieve current username and admin status","input_contract":null,"output_contract":{"schema":"UserInfo","fields":{"username":"string","is_admin":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":["username"],"fallback_value":{"is_admin":false}},"mitre_candidates":[{"id":"T1033","reason":"current user discovery","score":0.88,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"data-processing","intent":"Aggregate Data","behavioral_goal":"Combine all collected information into a single JSON payload","input_contract":{"sources":[{"task_id":"T1","schema":"OSInfo"},{"task_id":"T2","schema":"UserInfo"}]},"output_contract":{"schema":"AggregatedPayload","fields":{"payload":"string_json"}},"error_contract":{"on_failure":"abort_mission","required_fields":["payload"],"fallback_value":null},"mitre_candidates":[],"mitre_techniques":[],"mitre_status":"not_applicable","mapping_confidence":"high","ambiguity_notes":"data-processing task"},
    {"task_id":"T4","stage":"defense-evasion","intent":"Encrypt Payload","behavioral_goal":"Encrypt aggregated data using AES-256 before network transmission","input_contract":{"sources":[{"task_id":"T3","schema":"AggregatedPayload"}]},"output_contract":{"schema":"EncryptedPayload","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload","score":0.84,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"exfiltration","intent":"Send to C2","behavioral_goal":"Transmit encrypted payload via HTTPS POST to a remote server","input_contract":{"sources":[{"task_id":"T4","schema":"EncryptedPayload"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean","status_code":"integer"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.82,"source":"llm"},{"id":"T1071.001","reason":"web protocol channel","score":0.79,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T3","data_schema":"OSInfo","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"UserInfo","required":true},
    {"from_task":"T3","to_task":"T4","data_schema":"AggregatedPayload","required":true},
    {"from_task":"T4","to_task":"T5","data_schema":"EncryptedPayload","required":true}
  ]
}''',

    "keylogger": '''{
  "mission_id": "keylogger_hourly",
  "intent": "Monitor keyboard input and send logs hourly",
  "malware_type": "keylogger",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":3600,"max_memory_mb":100,"allowed_modules":["ctypes","win32api","time","json","Crypto.Cipher","requests"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"execution","intent":"Hook Keyboard","behavioral_goal":"Register a low-level keyboard hook to capture keystrokes","input_contract":null,"output_contract":{"schema":"KeyboardHook","fields":{"hook_id":"integer","active":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["hook_id"],"fallback_value":null},"mitre_candidates":[{"id":"T1056.001","reason":"keylogging via input capture","score":0.95,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"data-processing","intent":"Buffer Keystrokes","behavioral_goal":"Store captured keystrokes with timestamps and window context","input_contract":{"sources":[{"task_id":"T1","schema":"KeyboardHook"}]},"output_contract":{"schema":"KeystrokeBuffer","fields":{"entries":"array","count":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["entries"],"fallback_value":{"entries":[]}},"mitre_candidates":[],"mitre_techniques":[],"mitre_status":"not_applicable","mapping_confidence":"high","ambiguity_notes":"data-processing task"},
    {"task_id":"T3","stage":"defense-evasion","intent":"Encrypt Logs","behavioral_goal":"Encrypt buffered keystroke data before transmission","input_contract":{"sources":[{"task_id":"T2","schema":"KeystrokeBuffer"}]},"output_contract":{"schema":"EncryptedLogs","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload before exfiltration","score":0.82,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T4","stage":"exfiltration","intent":"Upload Logs","behavioral_goal":"Send encrypted keystroke logs to remote server via HTTPS POST","input_contract":{"sources":[{"task_id":"T3","schema":"EncryptedLogs"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.80,"source":"llm"},{"id":"T1071.001","reason":"web protocol channel","score":0.78,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"persistence","intent":"Registry Persistence","behavioral_goal":"Write to registry Run key for automatic execution on logon","input_contract":null,"output_contract":{"schema":"PersistenceStatus","fields":{"persisted":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"persisted":false}},"mitre_candidates":[{"id":"T1547.001","reason":"registry autorun","score":0.93,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"KeyboardHook","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"KeystrokeBuffer","required":true},
    {"from_task":"T3","to_task":"T4","data_schema":"EncryptedLogs","required":true}
  ]
}''',

    "credential_dumper": '''{
  "mission_id": "lsass_dump",
  "intent": "Extract credentials from LSASS memory",
  "malware_type": "dumper",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":120,"max_memory_mb":200,"allowed_modules":["ctypes","win32api","win32security","Crypto.Cipher","requests","os"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"privilege-escalation","intent":"Acquire Debug Privileges","behavioral_goal":"Obtain SeDebugPrivilege required for LSASS access","input_contract":null,"output_contract":{"schema":"PrivilegeStatus","fields":{"is_admin":"boolean","has_debug":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["has_debug"],"fallback_value":null},"mitre_candidates":[{"id":"T1134.001","reason":"token manipulation for debug privilege","score":0.72,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":"may also map to T1548 depending on elevation method"},
    {"task_id":"T2","stage":"credential-access","intent":"Access LSASS","behavioral_goal":"Open handle to LSASS process for credential extraction","input_contract":{"sources":[{"task_id":"T1","schema":"PrivilegeStatus"}]},"output_contract":{"schema":"ProcessHandle","fields":{"handle":"integer","pid":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["handle"],"fallback_value":null},"mitre_candidates":[{"id":"T1003.001","reason":"LSASS memory credential dumping","score":0.94,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"credential-access","intent":"Dump Memory","behavioral_goal":"Create memory dump of LSASS for offline credential extraction","input_contract":{"sources":[{"task_id":"T2","schema":"ProcessHandle"}]},"output_contract":{"schema":"MemoryDump","fields":{"path":"string","size":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["path"],"fallback_value":null},"mitre_candidates":[{"id":"T1003.001","reason":"OS credential dumping","score":0.96,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T4","stage":"defense-evasion","intent":"Encrypt Dump","behavioral_goal":"Encrypt the memory dump before transmission","input_contract":{"sources":[{"task_id":"T3","schema":"MemoryDump"}]},"output_contract":{"schema":"EncryptedDump","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload","score":0.77,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"exfiltration","intent":"Exfiltrate Dump","behavioral_goal":"Send encrypted credential dump via HTTPS POST","input_contract":{"sources":[{"task_id":"T4","schema":"EncryptedDump"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.80,"source":"llm"},{"id":"T1071.001","reason":"web protocol","score":0.76,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T6","stage":"defense-evasion","intent":"Cleanup Artifacts","behavioral_goal":"Delete dump file and clear traces from disk","input_contract":{"sources":[{"task_id":"T5","schema":"TransmissionStatus"}]},"output_contract":{"schema":"CleanupStatus","fields":{"cleaned":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"cleaned":false}},"mitre_candidates":[{"id":"T1070.004","reason":"file deletion to remove evidence","score":0.85,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"PrivilegeStatus","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"ProcessHandle","required":true},
    {"from_task":"T3","to_task":"T4","data_schema":"MemoryDump","required":true},
    {"from_task":"T4","to_task":"T5","data_schema":"EncryptedDump","required":true},
    {"from_task":"T5","to_task":"T6","data_schema":"TransmissionStatus","required":true}
  ]
}''',

    "ransomware": '''{
  "mission_id": "ransomware_encrypt",
  "intent": "Encrypt user files and demand ransom",
  "malware_type": "ransomware",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"medium","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":300,"max_memory_mb":200,"allowed_modules":["os","Crypto.Cipher","cryptography","requests","winreg","pathlib"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Enumerate Target Files","behavioral_goal":"List target user documents and media files on disk","input_contract":null,"output_contract":{"schema":"FileList","fields":{"paths":"array","total_size":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["paths"],"fallback_value":null},"mitre_candidates":[{"id":"T1083","reason":"file and directory discovery","score":0.94,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"execution","intent":"Encrypt Files","behavioral_goal":"Encrypt each target file in place using AES","input_contract":{"sources":[{"task_id":"T1","schema":"FileList"}]},"output_contract":{"schema":"EncryptionResult","fields":{"encrypted_count":"integer","encryption_key":"bytes"}},"error_contract":{"on_failure":"return_partial","required_fields":["encrypted_count"],"fallback_value":{"encrypted_count":0}},"mitre_candidates":[{"id":"T1486","reason":"data encrypted for impact","score":0.97,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"defense-evasion","intent":"Protect Encryption Key","behavioral_goal":"Wrap encryption key with RSA public key before transmission","input_contract":{"sources":[{"task_id":"T2","schema":"EncryptionResult"}]},"output_contract":{"schema":"ProtectedKey","fields":{"encrypted_key":"bytes"}},"error_contract":{"on_failure":"abort_mission","required_fields":["encrypted_key"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"cryptographic protection of sensitive material","score":0.73,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T4","stage":"exfiltration","intent":"Send Recovery Material","behavioral_goal":"Upload protected key to remote server over HTTPS","input_contract":{"sources":[{"task_id":"T3","schema":"ProtectedKey"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean","victim_id":"string"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false,"victim_id":""}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.78,"source":"llm"},{"id":"T1071.001","reason":"web protocol","score":0.76,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T5","stage":"execution","intent":"Drop Ransom Note","behavioral_goal":"Write ransom note to victim-visible locations","input_contract":{"sources":[{"task_id":"T4","schema":"TransmissionStatus"}]},"output_contract":{"schema":"RansomNoteStatus","fields":{"dropped":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"dropped":false}},"mitre_candidates":[{"id":"T1491.001","reason":"note-dropping visible to user","score":0.61,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"low","ambiguity_notes":"ransom note may map differently depending on ontology"}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"FileList","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"EncryptionResult","required":true},
    {"from_task":"T3","to_task":"T4","data_schema":"ProtectedKey","required":true},
    {"from_task":"T4","to_task":"T5","data_schema":"TransmissionStatus","required":true}
  ]
}''',

    "injector": '''{
  "mission_id": "dll_injector",
  "intent": "Inject shellcode into a running process",
  "malware_type": "injector",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":30,"max_memory_mb":100,"allowed_modules":["ctypes","win32api","win32process","win32security","win32con","os"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"privilege-escalation","intent":"Acquire Debug Privileges","behavioral_goal":"Obtain debug privileges required for cross-process memory write","input_contract":null,"output_contract":{"schema":"PrivilegeStatus","fields":{"has_debug":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["has_debug"],"fallback_value":null},"mitre_candidates":[{"id":"T1134.001","reason":"token manipulation","score":0.67,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T2","stage":"execution","intent":"Inject Payload","behavioral_goal":"Write shellcode into target process memory via VirtualAllocEx + WriteProcessMemory","input_contract":{"sources":[{"task_id":"T1","schema":"PrivilegeStatus"}]},"output_contract":{"schema":"InjectionResult","fields":{"remote_addr":"integer","success":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["success"],"fallback_value":null},"mitre_candidates":[{"id":"T1055","reason":"process injection","score":0.89,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"execution","intent":"Execute Injected Code","behavioral_goal":"Trigger execution via CreateRemoteThread in target process","input_contract":{"sources":[{"task_id":"T2","schema":"InjectionResult"}]},"output_contract":{"schema":"ExecutionStatus","fields":{"thread_id":"integer","running":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["running"],"fallback_value":null},"mitre_candidates":[{"id":"T1055","reason":"remote thread execution","score":0.87,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"PrivilegeStatus","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"InjectionResult","required":true}
  ]
}''',

    "wiper": '''{
  "mission_id": "disk_wiper",
  "intent": "Overwrite and destroy target files to make them unrecoverable",
  "malware_type": "wiper",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"low","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":600,"max_memory_mb":200,"allowed_modules":["os","pathlib","ctypes","winreg"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Enumerate Target Files","behavioral_goal":"List critical user and system files for destruction","input_contract":null,"output_contract":{"schema":"FileList","fields":{"paths":"array","total_size":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["paths"],"fallback_value":null},"mitre_candidates":[{"id":"T1083","reason":"file and directory discovery","score":0.92,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"execution","intent":"Overwrite File Contents","behavioral_goal":"Overwrite each target file with random data multiple passes","input_contract":{"sources":[{"task_id":"T1","schema":"FileList"}]},"output_contract":{"schema":"WipeResult","fields":{"wiped_count":"integer","failed_count":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["wiped_count"],"fallback_value":{"wiped_count":0}},"mitre_candidates":[{"id":"T1485","reason":"data destruction","score":0.95,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"defense-evasion","intent":"Remove Traces","behavioral_goal":"Delete wiped files and clear event logs","input_contract":{"sources":[{"task_id":"T2","schema":"WipeResult"}]},"output_contract":{"schema":"CleanupStatus","fields":{"cleaned":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"cleaned":false}},"mitre_candidates":[{"id":"T1070.004","reason":"file deletion","score":0.88,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"FileList","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"WipeResult","required":true}
  ]
}''',

    "rat": '''{
  "mission_id": "rat_c2",
  "intent": "Establish persistent remote access with command execution",
  "malware_type": "rat",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":86400,"max_memory_mb":150,"allowed_modules":["socket","subprocess","ctypes","Crypto.Cipher","requests","winreg","os","threading"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"c2-setup","intent":"Establish C2 Channel","behavioral_goal":"Open encrypted command-and-control channel to remote server","input_contract":null,"output_contract":{"schema":"C2Channel","fields":{"session_id":"string","connected":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["connected"],"fallback_value":{"connected":false}},"mitre_candidates":[{"id":"T1071.001","reason":"web protocol C2","score":0.89,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"execution","intent":"Command Dispatcher","behavioral_goal":"Receive and dispatch operator commands","input_contract":{"sources":[{"task_id":"T1","schema":"C2Channel"}]},"output_contract":{"schema":"CommandResult","fields":{"command":"string","output":"string","exit_code":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["command"],"fallback_value":{"command":"","output":"","exit_code":-1}},"mitre_candidates":[{"id":"T1059.003","reason":"command shell execution","score":0.76,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T3","stage":"persistence","intent":"Install Persistence","behavioral_goal":"Create registry or scheduled task for auto-execution on reboot","input_contract":null,"output_contract":{"schema":"PersistenceStatus","fields":{"registry":"boolean","scheduled_task":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"registry":false,"scheduled_task":false}},"mitre_candidates":[{"id":"T1547.001","reason":"registry autorun","score":0.86,"source":"llm"},{"id":"T1053.005","reason":"scheduled task","score":0.72,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":"depends on chosen persistence mechanism"},
    {"task_id":"T4","stage":"defense-evasion","intent":"Hide Process","behavioral_goal":"Masquerade process to look like a legitimate system process","input_contract":null,"output_contract":{"schema":"EvasionStatus","fields":{"hidden":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"hidden":false}},"mitre_candidates":[{"id":"T1036.005","reason":"process masquerading","score":0.74,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"C2Channel","required":true}
  ]
}''',

    "file_collector": '''{
  "mission_id": "file_collect_encode_transfer",
  "intent": "Collect sensitive files from local filesystem, obfuscate payload, and download additional tools from remote server",
  "malware_type": "file_collector",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":120,"max_memory_mb":150,"allowed_modules":["os","pathlib","Crypto.Cipher","requests","base64","json"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"collection","intent":"Collect Sensitive Files","behavioral_goal":"Enumerate and copy sensitive files from local filesystem to staging location","input_contract":null,"output_contract":{"schema":"CollectedFiles","fields":{"file_paths":"array","total_size":"integer"}},"error_contract":{"on_failure":"abort_mission","required_fields":["file_paths"],"fallback_value":null},"mitre_candidates":[{"id":"T1005","reason":"data from local system","score":0.92,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"defense-evasion","intent":"Obfuscate and Encode Payload","behavioral_goal":"Encode collected file data to evade detection during transfer","input_contract":{"sources":[{"task_id":"T1","schema":"CollectedFiles"}]},"output_contract":{"schema":"EncodedPayload","fields":{"encoded_data":"bytes","encoding":"string"}},"error_contract":{"on_failure":"abort_mission","required_fields":["encoded_data"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"obfuscated files or information","score":0.85,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"exfiltration","intent":"Download Additional Tools","behavioral_goal":"Download and transfer additional tools from remote server for follow-on operations","input_contract":null,"output_contract":{"schema":"ToolTransferStatus","fields":{"success":"boolean","tool_path":"string"}},"error_contract":{"on_failure":"return_partial","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1105","reason":"ingress tool transfer from remote server","score":0.88,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"CollectedFiles","required":true}
  ]
}''',
"screenshotter": '''{
  "mission_id": "screenshot_exfil",
  "intent": "Capture screenshots and send to remote server",
  "malware_type": "screenshotter",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"medium","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":60,"max_memory_mb":100,"allowed_modules":["PIL","mss","Crypto.Cipher","requests","base64","os"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"execution","intent":"Capture Screenshot","behavioral_goal":"Capture current desktop screen as image","input_contract":null,"output_contract":{"schema":"Screenshot","fields":{"image_data":"string","format":"string"}},"error_contract":{"on_failure":"return_partial","required_fields":["image_data"],"fallback_value":null},"mitre_candidates":[{"id":"T1113","reason":"screen capture","score":0.95,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"defense-evasion","intent":"Encrypt Screenshot","behavioral_goal":"Encrypt captured image data before transmission","input_contract":{"sources":[{"task_id":"T1","schema":"Screenshot"}]},"output_contract":{"schema":"EncryptedScreenshot","fields":{"ciphertext":"bytes","iv":"bytes","key":"bytes"}},"error_contract":{"on_failure":"return_partial","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload","score":0.82,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T3","stage":"exfiltration","intent":"Send Screenshot","behavioral_goal":"Transmit encrypted screenshot to remote server via HTTPS POST","input_contract":{"sources":[{"task_id":"T2","schema":"EncryptedScreenshot"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.80,"source":"llm"},{"id":"T1071.001","reason":"web protocol","score":0.78,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"Screenshot","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"EncryptedScreenshot","required":true}
  ]
}''',

    "loader": '''{
  "mission_id": "payload_loader",
  "intent": "Download and execute a staged payload",
  "malware_type": "loader",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":60,"max_memory_mb":100,"allowed_modules":["requests","Crypto.Cipher","os","subprocess","base64"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"exfiltration","intent":"Download Payload","behavioral_goal":"Download encrypted payload from remote server","input_contract":null,"output_contract":{"schema":"EncryptedPayload","fields":{"data":"bytes","url":"string"}},"error_contract":{"on_failure":"retry","required_fields":["data"],"fallback_value":null},"mitre_candidates":[{"id":"T1105","reason":"ingress tool transfer","score":0.92,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"defense-evasion","intent":"Decrypt Payload","behavioral_goal":"Decrypt downloaded payload before execution","input_contract":{"sources":[{"task_id":"T1","schema":"EncryptedPayload"}]},"output_contract":{"schema":"DecryptedPayload","fields":{"executable":"bytes","path":"string"}},"error_contract":{"on_failure":"abort_mission","required_fields":["executable"],"fallback_value":null},"mitre_candidates":[{"id":"T1140","reason":"deobfuscate payload","score":0.88,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"execution","intent":"Execute Payload","behavioral_goal":"Execute decrypted payload on target system","input_contract":{"sources":[{"task_id":"T2","schema":"DecryptedPayload"}]},"output_contract":{"schema":"ExecutionStatus","fields":{"pid":"integer","running":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":["running"],"fallback_value":{"running":false}},"mitre_candidates":[{"id":"T1204.002","reason":"user execution malicious file","score":0.75,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"EncryptedPayload","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"DecryptedPayload","required":true}
  ]
}''',

    "browser_stealer": '''{
  "mission_id": "browser_credential_steal",
  "intent": "Steal browser credentials and cookies and exfiltrate",
  "malware_type": "browser_stealer",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":60,"max_memory_mb":100,"allowed_modules":["os","pathlib","Crypto.Cipher","requests","json","sqlite3"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"discovery","intent":"Locate Browser Data","behavioral_goal":"Find browser profile directories containing credentials and cookies","input_contract":null,"output_contract":{"schema":"BrowserPaths","fields":{"paths":"array","browser":"string"}},"error_contract":{"on_failure":"abort_mission","required_fields":["paths"],"fallback_value":null},"mitre_candidates":[{"id":"T1083","reason":"file and directory discovery","score":0.85,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"credential-access","intent":"Extract Credentials","behavioral_goal":"Extract stored credentials and cookies from browser database","input_contract":{"sources":[{"task_id":"T1","schema":"BrowserPaths"}]},"output_contract":{"schema":"StolenData","fields":{"credentials":"array","cookies":"array"}},"error_contract":{"on_failure":"return_partial","required_fields":["credentials"],"fallback_value":{"credentials":[]}},"mitre_candidates":[{"id":"T1552.001","reason":"credentials in files","score":0.88,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T3","stage":"defense-evasion","intent":"Encrypt Stolen Data","behavioral_goal":"Encrypt credentials and cookies before transmission","input_contract":{"sources":[{"task_id":"T2","schema":"StolenData"}]},"output_contract":{"schema":"EncryptedData","fields":{"ciphertext":"bytes","iv":"bytes"}},"error_contract":{"on_failure":"return_partial","required_fields":["ciphertext"],"fallback_value":null},"mitre_candidates":[{"id":"T1027","reason":"encrypted payload","score":0.80,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T4","stage":"exfiltration","intent":"Exfiltrate Stolen Data","behavioral_goal":"Send encrypted credentials to remote server via HTTPS","input_contract":{"sources":[{"task_id":"T3","schema":"EncryptedData"}]},"output_contract":{"schema":"TransmissionStatus","fields":{"success":"boolean"}},"error_contract":{"on_failure":"retry","required_fields":["success"],"fallback_value":{"success":false}},"mitre_candidates":[{"id":"T1041","reason":"data exfiltration","score":0.82,"source":"llm"},{"id":"T1071.001","reason":"web protocol","score":0.79,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"BrowserPaths","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"StolenData","required":true},
    {"from_task":"T3","to_task":"T4","data_schema":"EncryptedData","required":true}
  ]
}''',

    "clipper": '''{
  "mission_id": "clipboard_clipper",
  "intent": "Monitor clipboard and replace crypto addresses",
  "malware_type": "clipper",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":86400,"max_memory_mb":50,"allowed_modules":["ctypes","win32api","winreg","time","re","os"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"execution","intent":"Monitor Clipboard","behavioral_goal":"Continuously monitor clipboard for cryptocurrency address patterns","input_contract":null,"output_contract":{"schema":"ClipboardContent","fields":{"content":"string","is_crypto":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":["content"],"fallback_value":{"content":"","is_crypto":false}},"mitre_candidates":[{"id":"T1115","reason":"clipboard data collection","score":0.90,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""},
    {"task_id":"T2","stage":"defense-evasion","intent":"Replace Crypto Address","behavioral_goal":"Replace detected cryptocurrency address with attacker-controlled address","input_contract":{"sources":[{"task_id":"T1","schema":"ClipboardContent"}]},"output_contract":{"schema":"ReplacementStatus","fields":{"replaced":"boolean","original":"string","replacement":"string"}},"error_contract":{"on_failure":"return_partial","required_fields":["replaced"],"fallback_value":{"replaced":false}},"mitre_candidates":[{"id":"T1036.005","reason":"masquerading address","score":0.72,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T3","stage":"persistence","intent":"Registry Persistence","behavioral_goal":"Write to registry Run key for automatic execution on logon","input_contract":null,"output_contract":{"schema":"PersistenceStatus","fields":{"persisted":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"persisted":false}},"mitre_candidates":[{"id":"T1547.001","reason":"registry autorun","score":0.90,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"high","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"ClipboardContent","required":true}
  ]
}''',

    "rootkit": '''{
  "mission_id": "rootkit_hide",
  "intent": "Escalate privileges, hook system calls and hide presence",
  "malware_type": "rootkit",
  "global_constraints": {"target_os_family":"windows","language_target":"python","stealth_level":"high","execution_model":"modular","forbidden_capabilities":["self_propagation"]},
  "validation_rules": {"max_execution_time_seconds":60,"max_memory_mb":150,"allowed_modules":["ctypes","win32api","win32security","win32process","os"],"forbidden_patterns":["eval\\\\(","exec\\\\("]},
  "execution_graph": [
    {"task_id":"T1","stage":"privilege-escalation","intent":"Escalate Privileges","behavioral_goal":"Obtain elevated privileges required for kernel-level operations","input_contract":null,"output_contract":{"schema":"PrivilegeStatus","fields":{"elevated":"boolean","has_debug":"boolean"}},"error_contract":{"on_failure":"abort_mission","required_fields":["elevated"],"fallback_value":null},"mitre_candidates":[{"id":"T1134.001","reason":"token manipulation","score":0.75,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T2","stage":"defense-evasion","intent":"Hook System Calls","behavioral_goal":"Hook kernel-level system calls to intercept and manipulate process visibility","input_contract":{"sources":[{"task_id":"T1","schema":"PrivilegeStatus"}]},"output_contract":{"schema":"HookStatus","fields":{"hooked":"boolean","hook_count":"integer"}},"error_contract":{"on_failure":"return_partial","required_fields":["hooked"],"fallback_value":{"hooked":false}},"mitre_candidates":[{"id":"T1055","reason":"process injection for hooking","score":0.78,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T3","stage":"defense-evasion","intent":"Hide Process","behavioral_goal":"Conceal malicious process from system process listings","input_contract":{"sources":[{"task_id":"T2","schema":"HookStatus"}]},"output_contract":{"schema":"HideStatus","fields":{"hidden":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"hidden":false}},"mitre_candidates":[{"id":"T1564.001","reason":"hidden files and directories","score":0.80,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""},
    {"task_id":"T4","stage":"persistence","intent":"Persist Stealthily","behavioral_goal":"Establish persistence without visible registry or scheduled task entries","input_contract":null,"output_contract":{"schema":"PersistenceStatus","fields":{"persisted":"boolean"}},"error_contract":{"on_failure":"return_partial","required_fields":[],"fallback_value":{"persisted":false}},"mitre_candidates":[{"id":"T1547.001","reason":"registry autorun","score":0.75,"source":"llm"}],"mitre_techniques":[],"mitre_status":"needs_verification","mapping_confidence":"medium","ambiguity_notes":""}
  ],
  "dataflow": [
    {"from_task":"T1","to_task":"T2","data_schema":"PrivilegeStatus","required":true},
    {"from_task":"T2","to_task":"T3","data_schema":"HookStatus","required":true}
  ]
}''',
}

_TASK_PATTERNS = """
TASK PATTERN REFERENCE

Privilege escalation pattern:
  stage: privilege-escalation
  input_contract: usually null (unless needs specific process handle from upstream)
  behavior: obtain elevated privileges for protected resource access
  candidates: T1548, T1134.001

Persistence pattern:
  stage: persistence
  input_contract: usually null (unless needs path/exe from upstream)
  behavior: establish automatic execution at startup or logon
  candidates: T1547.001, T1053.005

Exfiltration pattern:
  stage: exfiltration
  input_contract: from upstream data collection or encryption task
  behavior: transmit data outside victim environment via web protocols
  candidates: T1041, T1071.001

Collection pattern:
  stage: collection
  input_contract: usually null
  behavior: collect or copy sensitive files from local filesystem
  candidates: T1005

Tool transfer pattern:
  stage: exfiltration
  input_contract: usually null
  behavior: download or transfer additional tools from remote server
  candidates: T1105

Discovery pattern:
  stage: discovery
  input_contract: usually null (unless needs target/handle from upstream)
  behavior: enumerate files, processes, users, or system information
  candidates: T1083, T1057, T1082, T1033

Defense evasion pattern:
  stage: defense-evasion
  input_contract: depends — null if standalone obfuscation, upstream if operating on prior artifacts
  behavior: encrypt, obfuscate, or conceal malicious artifacts
  candidates: T1027, T1070.004, T1036.005

C2 setup pattern:
  stage: c2-setup
  input_contract: usually null
  behavior: establish remote command-and-control communication
  candidates: T1071.001, T1095

Execution pattern:
  stage: execution
  input_contract: depends — null if standalone, upstream if needs prior data
  behavior: run commands, inject code, or perform primary malicious action
  candidates: T1059.003, T1055, T1486, T1056.001
"""
# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tokenize(text: str) -> Set[str]:
    return {tok for tok in WORD_RE.findall(text.lower()) if len(tok) >= MIN_TOKEN_LEN}


def _detect_example_key(intent: str) -> str:
    lower = intent.lower()
    for keywords, key in INTENT_KEYWORD_MAP:
        if any(kw in lower for kw in keywords):
            return key
    return "unknown"


def _safe_filename(x: str) -> str:
    x = x.strip().lower()
    x = re.sub(r"[\\/:\*\?\"<>\|]+", "_", x)
    x = re.sub(r"\s+", "_", x)
    x = re.sub(r"_+", "_", x)
    return x.strip("_") or "generic"


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

class ExampleSelector:
    def score_example(self, intent: str, key: str) -> float:
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
        if intent_tokens and hint_tokens:
            overlap = len(intent_tokens & hint_tokens)
            score += overlap * 1.25
            score += overlap / max(len(hint_tokens), 1)
            if overlap == 0:
                score -= 1.5
        # Boost file_collector when intent has both collection + transfer signals
        if key == "file_collector":
            has_collect = any(w in intent_lower for w in [
                "collect", "gather", "harvest", "sensitive files", "local files"
            ])
            has_transfer = any(w in intent_lower for w in [
                "download", "transfer", "fetch tool", "remote server", "additional tools"
            ])
            if has_collect and has_transfer:
                score += 3.0
            elif has_collect or has_transfer:
                score += 1.0
        return score

    def select(self, intent: str, k: int = 3) -> List[str]:
        scored = sorted(
            ((key, self.score_example(intent, key)) for key in _EXAMPLES),
            key=lambda x: (x[1], x[0]),
            reverse=True,
        )

        chosen: List[str] = []
        best_key    = scored[0][0]
        chosen.append(best_key)
        best_shape  = _EXAMPLE_META.get(best_key, {}).get("shape",  "")
        best_family = _EXAMPLE_META.get(best_key, {}).get("family", "")

        for key, _ in scored[1:]:
            if key not in chosen:
                if _EXAMPLE_META.get(key, {}).get("shape", "") != best_shape:
                    chosen.append(key)
                    break

        for key, _ in scored[1:]:
            if key not in chosen:
                if _EXAMPLE_META.get(key, {}).get("family", "") != best_family:
                    chosen.append(key)
                    break

        fallback_order = ["injector", "wiper", "rat", "ransomware",
                          "credential_dumper", "keylogger", "info_stealer"]
        for key in fallback_order:
            if len(chosen) >= k:
                break
            if key not in chosen:
                chosen.append(key)

        return chosen[:k]

    def get_temperature(self, selected: List[str]) -> float:
        if not selected:
            return 0.30
        return _TEMPERATURE_MAP.get(selected[0], 0.30)


class MitreRetriever:
    RETRIEVAL_MIN_SCORE = 0.25
    MERGE_MIN_SCORE = 0.40

    def _score_entry(self, entry: AttackEntry, text: str, tokens: Set[str],
                     target_stage: str, allow_cross: bool) -> float:
        allowed = False
        if entry.stage == target_stage:
            allowed = True
        elif target_stage in entry.cross_stages:
            allowed = True
        elif allow_cross and entry.stage in self._related_stages(target_stage):
            allowed = True
        if not allowed:
            return -1.0

        score = 0.0
        if entry.stage == target_stage:
            score += 2.0
        elif allow_cross:
            score += 0.75

        for kw_entry in entry.keywords:
            kw = kw_entry["kw"].lower()
            weight = kw_entry["weight"]
            phrase_bonus = 4.0 if weight == "strong" else 2.0
            word_bonus = 3.0 if weight == "strong" else 1.0
            if " " in kw and kw in text:
                score += phrase_bonus
            elif " " not in kw and kw in text:
                score += word_bonus
            kw_tokens = _tokenize(kw)
            if kw_tokens:
                overlap = len(tokens & kw_tokens)
                token_weight = 0.8 if weight == "strong" else 0.4
                score += token_weight * overlap

        return score

    def _related_stages(self, stage: str) -> Set[str]:
        related: Dict[str, Set[str]] = {
            "discovery": {"credential-access", "privilege-escalation", "execution"},
            "credential-access": {"discovery", "privilege-escalation"},
            "execution": {"privilege-escalation", "defense-evasion", "discovery"},
            "defense-evasion": {"execution", "exfiltration", "persistence"},
            "exfiltration": {"defense-evasion", "c2-setup"},
            "persistence": {"defense-evasion", "execution"},
            "c2-setup": {"exfiltration", "execution"},
            "initial-access": {"execution", "credential-access"},
            "privilege-escalation": {"execution", "discovery", "credential-access"},
            "lateral-movement": {"credential-access", "execution", "c2-setup"},
        }
        return related.get(stage, set())

    def mission_hints(self, intent: str, top_k: int = 6) -> List[Dict[str, Any]]:
        text = intent.lower()
        tokens = _tokenize(text)
        scored: List[Tuple[float, AttackEntry]] = []
        for entry in ATTACK_KB:
            score = 0.0
            for kw_entry in entry.keywords:
                kw = kw_entry["kw"].lower()
                weight = kw_entry["weight"]
                if " " in kw and kw in text:
                    score += 4.0 if weight == "strong" else 2.0
                elif " " not in kw and kw in text:
                    score += 3.0 if weight == "strong" else 1.0
                kw_tokens = _tokenize(kw)
                if kw_tokens:
                    tw = 0.8 if weight == "strong" else 0.4
                    score += tw * len(tokens & kw_tokens)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: (x[0], x[1].id), reverse=True)

        seen_ids: Set[str] = set()
        out: List[Dict[str, Any]] = []
        for raw_score, entry in scored:
            norm_score = round(min(1.0, raw_score / 8.0), 2)
            if norm_score < self.RETRIEVAL_MIN_SCORE:
                continue
            if entry.id in seen_ids:
                continue
            seen_ids.add(entry.id)
            out.append({
                "id": entry.id, "stage": entry.stage,
                "name": entry.name, "score": norm_score,
            })
            if len(out) >= top_k:
                break
        return out

    def task_candidates(self, text: str, stage: str, top_k: int = 3) -> List[MitreCandidate]:
        lowered = text.lower()
        tokens = _tokenize(lowered)

        for allow_cross in (False, True):
            scored: List[Tuple[float, AttackEntry]] = []
            for entry in ATTACK_KB:
                s = self._score_entry(entry, lowered, tokens, stage, allow_cross)
                if s >= 0.5:
                    scored.append((s, entry))
            if scored:
                break

        scored.sort(key=lambda x: (x[0], x[1].id), reverse=True)

        seen: Set[str] = set()
        results: List[MitreCandidate] = []
        for score, entry in scored:
            if entry.id in seen:
                continue
            seen.add(entry.id)
            results.append(MitreCandidate(
                id=entry.id,
                reason=f"retrieval match: {entry.name}",
                score=round(min(1.0, score / 8.0), 2),
                source="retrieval",
            ))
            if len(results) >= top_k:
                break
        return results

    def merge_candidates(self, llm_candidates: List[MitreCandidate],
                     retrieved: List[MitreCandidate],
                     stage: str,
                     text: str) -> Tuple[List[MitreCandidate], str, str]:
        if stage == "data-processing":
            return [], "not_applicable", "high"

        merged: Dict[str, MitreCandidate] = {}
        for cand in llm_candidates + retrieved:
            existing = merged.get(cand.id)
            if existing is None:
                merged[cand.id] = MitreCandidate(
                    id=cand.id, reason=cand.reason,
                    score=cand.score, source=cand.source,
                )
                continue
            if cand.score is not None and (existing.score is None or cand.score > existing.score):
                existing.score = cand.score
            if cand.reason and cand.reason not in existing.reason:
                existing.reason = (existing.reason + " | " + cand.reason).strip(" |")
            src_set = set(filter(None, existing.source.split("+")))
            src_set.update(filter(None, cand.source.split("+")))
            existing.source = "+".join(sorted(src_set)) if src_set else "unknown"

        ordered = sorted(merged.values(), key=lambda c: ((c.score or 0.0), c.id), reverse=True)
        ordered = [c for c in ordered if (c.score or 0.0) >= self.MERGE_MIN_SCORE]
        ordered = self._post_filter_candidates(text, stage, ordered)[:3]

        if not ordered:
            return [], "needs_verification", "low"

        top1 = ordered[0].score or 0.0
        top2 = ordered[1].score or 0.0 if len(ordered) > 1 else 0.0
        gap = top1 - top2

        if len(ordered) == 1:
            confidence = "high" if top1 >= 0.90 else ("medium" if top1 >= 0.70 else "low")
        elif top1 >= 0.85 and gap >= 0.20:
            confidence = "high"
        elif top1 >= 0.65 and gap >= 0.08:
            confidence = "medium"
        else:
            confidence = "low"

        return ordered, "needs_verification", confidence

    def _post_filter_candidates(self, text: str, stage: str,
                            candidates: List[MitreCandidate]) -> List[MitreCandidate]:
        lowered = text.lower()
        filtered: List[MitreCandidate] = []

        for cand in candidates:
            cid = cand.id
            if cid == "T1113" and any(x in lowered for x in ["keylog", "keystroke", "keyboard"]):
                continue
            if cid == "T1204.002" and any(x in lowered for x in [
                "inject", "shellcode", "virtualallocex",
                "writeprocessmemory", "createremotethread"
            ]):
                continue
            if cid == "T1140" and any(x in lowered for x in [
                "cleanup", "remove traces", "delete", "erase"
            ]):
                continue
            if stage == "exfiltration" and cid == "T1074.001":
                continue
            filtered.append(cand)

        ids = {c.id for c in filtered}
        if "T1548.002" in ids and "T1548" in ids:
            filtered = [c for c in filtered if c.id != "T1548"]

        return filtered


class IntentNormalizer:
    """PATCH 3: _CAPABILITY_GROUPS as class variable + _introduced_new_capability guard."""

    # PATCH 3: class variable — must be here, before __init__
    _CAPABILITY_GROUPS: Dict[str, List[str]] = {
        "exfil": [
            "exfil", "send", "upload", "transmit", "remote server",
            "c2", "https post", "http post", "beacon", "callback",
        ],
        "persist": [
            "persist", "persistence", "startup", "autorun",
            "registry run", "scheduled task", "logon",
        ],
        "discover": [
            "discover", "enumerate", "scan", "list process",
            "system information", "file discovery", "network configuration",
        ],
        "protect": [
            "encrypt payload", "obfuscate", "protect payload",
            "conceal", "hide payload", "encode", "packed", "compressed",
        ],
        "lateral": [
            "lateral", "spread", "move to", "remote copy",
        ],
    }

    def __init__(self, client: OpenAI, model: str):
        self.client = client
        self.model = model

    @staticmethod
    def _introduced_new_capability(original: str, rewritten: str) -> bool:
        orig = original.lower()
        new  = rewritten.lower()
        for _, kws in IntentNormalizer._CAPABILITY_GROUPS.items():
            had = any(k in orig for k in kws)
            now = any(k in new  for k in kws)
            if now and not had:
                return True
        return False

    def normalize(self, intent: str) -> str:
        prompt = (
            "Rewrite the following malware intent into one concise, clear behavioral objective.\n"
            "RULES:\n"
            "- Do NOT add new capabilities, steps, or behaviors not present in the original.\n"
            "- Do NOT expand scope (e.g., do not add exfiltration if not mentioned).\n"
            "- Do NOT add discovery/recon if not mentioned.\n"
            "- Only clarify ambiguous wording. Keep the same scope.\n"
            "- Keep it to ONE sentence.\n\n"
            f"Original intent: {intent}\n"
            "Rewritten intent:"
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=120,
            )
            normalized = (response.choices[0].message.content or "").strip()
            if not normalized:
                return intent
            # word count guard
            if len(normalized.split()) > len(intent.split()) * 2:
                return intent
            # PATCH 3: capability injection guard
            if self._introduced_new_capability(intent, normalized):
                return intent
            return normalized
        except Exception:
            return intent


class PromptBuilder:
    SYSTEM_PROMPT = (
        "You are a Windows malware mission planner for security research.\n"
        "Convert a natural language intent into a structured mission plan.\n\n"

        "CRITICAL RULES:\n"
        "1. Each task must represent ONE atomic behavioral objective only.\n"
        "2. Do NOT combine collection, encryption, exfiltration, persistence into a single task.\n"
        "3. Describe WHAT behavior happens, not HOW it is implemented.\n"
        "4. The number of tasks should match the complexity of the intent (1-8 tasks).\n"
        "5. Single-action intents may be represented by a single task if that task fully captures the behavior.\n\n"

        "NEGATIVE CONSTRAINTS — DO NOT VIOLATE:\n"
        "- Do NOT add discovery/recon tasks unless the intent explicitly requires gathering system or environment information.\n"
        "- Do NOT add exfiltration tasks unless the intent explicitly involves sending data out.\n"
        "- Do NOT add encryption/defense-evasion tasks unless the intent requires data protection or stealth.\n"
        "- Do NOT pad tasks to reach a minimum count. 3 tasks is fine if 3 tasks are sufficient.\n"
        "- Do NOT copy example structure blindly. Adapt to the specific intent.\n\n"
        "DATAFLOW RULES (critical):\n"
        "- Only add dataflow edge A → B if B genuinely requires data produced by A.\n"
        "- Do NOT add dataflow edges just because tasks are sequential.\n"
        "- Persistence and discovery tasks are often independent — use input_contract: null unless behavioral_goal explicitly requires upstream data.\n"
        "- Cleanup/artifact-removal tasks may depend on outputs from prior tasks if they operate on files, paths, or artifacts created earlier.\n"
        "- A task with input_contract: null must be executable independently of other task results.\n\n"

        "TASK SCHEMA (each task must contain all fields):\n"
        "task_id, stage, intent, behavioral_goal, input_contract, output_contract, "
        "error_contract, mitre_candidates, mitre_techniques, mitre_status, "
        "mapping_confidence, ambiguity_notes.\n\n"

        "VALID STAGES: discovery, execution, credential-access, defense-evasion, "
        "exfiltration, persistence, c2-setup, data-processing, privilege-escalation, "
        "weaponization, initial-access, lateral-movement.\n\n"

        "ATT&CK MAPPING RULES:\n"
        "- data-processing tasks → mitre_candidates: [] and mitre_techniques: []\n"
        "- mitre_techniques should stay [] (let the verifier finalize)\n"
        "- Prefer mitre_candidates with id, reason, score (0.0-1.0), source='llm'\n"
        "- Use mapping_confidence: high | medium | low\n"
        "- Use ambiguity_notes when multiple techniques are plausible\n\n"

        "COMMON MAPPINGS:\n"
        "- ransomware file encryption → T1486, stage execution\n"
        "- file/directory enumeration → T1083, stage discovery\n"
        "- encrypted payload → T1027, stage defense-evasion\n"
        "- exfiltration over HTTPS → T1041 + T1071.001\n"
        "- keyboard capture → T1056.001\n"
        "- screenshot capture → T1113\n"
        "- registry Run key persistence → T1547.001\n"
        "- LSASS credential dumping → T1003.001\n"
        "- process injection → T1055\n\n"

        "FIELD TYPES: string, string_json, integer, boolean, bytes, array, dict, float.\n"
        "DATAFLOW: use from_task/to_task/data_schema keys.\n"
        "on_failure: must be one of: abort_mission, return_partial, retry, skip.\n"
        "ON_FAILURE RULES:\n"
        "- execution tasks → on_failure: return_partial\n"
        "- persistence tasks → on_failure: return_partial\n"
        "- discovery tasks → on_failure: return_partial\n"
        "- defense-evasion tasks → on_failure: return_partial\n"
        "- exfiltration/c2 tasks → on_failure: retry\n"
        "- abort_mission only when task is absolute prerequisite (e.g. decrypt before execute)\n\n"
        "Output ONLY valid JSON. No markdown. No explanations.\n"
    )

    def build(self, intent: str, selected_examples: List[str],
              retrieval_hints: List[Dict[str, Any]],
              policy: PolicyFlags) -> str:
        parts: List[str] = []

        parts.append(f'TARGET INTENT: "{intent}"')
        parts.append("")

        policy_notes: List[str] = []
        if policy.network == "blocked":
            policy_notes.append(
                "POLICY: Network access is BLOCKED. Do NOT create exfiltration or C2 tasks."
            )
        elif policy.network == "localhost-only":
            policy_notes.append(
                "POLICY: Network access is localhost-only."
            )
        if policy_notes:
            parts.append("\n".join(policy_notes))
            parts.append("")

        parts.append(
            "IMPORTANT: The TARGET INTENT above has absolute priority over all examples below. "
            "Later examples show different structural shapes only — they may contain stages "
            "(exfiltration, persistence, discovery) that are NOT needed for the target intent. "
            "Treat them as shape references only. Prefer fewer tasks when uncertain."
        )
        parts.append("")

        parts.append("REFERENCE EXAMPLES:")
        for idx, key in enumerate(selected_examples, start=1):
            label = key.replace("_", " ").title()
            if idx == 1:
                parts.append(f"\nEXAMPLE {idx} — {label} (full reference):")
                parts.append(_EXAMPLES[key])
            else:
                parts.append(f"\nEXAMPLE {idx} — {label} (shape reference only):")
                parts.append(_EXAMPLE_SUMMARIES.get(key, ""))

        parts.append("")
        parts.append(_TASK_PATTERNS)

        if retrieval_hints:
            hint_lines = [
                f"- {h['id']} [{h['stage']}] {h['name']} (score={h['score']})"
                for h in retrieval_hints
            ]
            parts.append("\nRETRIEVAL HINTS (relevant MITRE techniques for this intent):")
            parts.append("\n".join(hint_lines))
        parts.append("")

        parts.append(
            "Generate a mission plan for the TARGET INTENT above. "
            "Adapt task count and structure to the intent. "
            "Return ONLY valid JSON."
        )

        return "\n".join(parts)


class PlanValidator:
    def __init__(self, retriever: MitreRetriever, policy: PolicyFlags):
        self.retriever = retriever
        self.policy = policy

    def _allow_single_task_plan(self, intent: str, tasks: list) -> bool:
        if len(tasks) != 1:
            return False
        t = tasks[0]
        if t.stage not in {"persistence", "privilege-escalation", "execution", "defense-evasion"}:
            return False
        if not t.mitre_candidates:
            return False
        top_score = max((c.score or 0.0) for c in t.mitre_candidates)
        return top_score >= 0.65

    def _is_legitimate_prerequisite(self, task: Task, intent: str) -> bool:
        """PATCH 6: 3-condition check for discovery prerequisite."""
        intent_text = intent.lower()
        goal = (task.behavioral_goal or "").lower()

        if task.stage == "privilege-escalation":
            trigger_terms = [
                "inject", "shellcode", "running process", "lsass",
                "credential", "protected", "cross-process"
            ]
            if any(t in intent_text for t in trigger_terms):
                return True

        if task.stage == "discovery":
            # Condition 1: goal must have a discovery verb
            discovery_verbs = ["discover", "enumerate", "list", "identify", "locate", "scan"]
            if not any(v in goal for v in discovery_verbs):
                return False

            # Condition 2: goal must have a discovery object
            goal_objects = [
                "file", "directory", "process", "network",
                "configuration", "user", "hostname",
            ]
            if not any(obj in goal for obj in goal_objects):
                return False

            # Condition 3: intent must have a related object
            intent_objects = [
                "file", "directory", "process", "network",
                "configuration", "collect", "discover", "enumerate",
            ]
            if any(obj in intent_text for obj in intent_objects):
                return True

            return False

        if any(x in goal for x in ["required for", "needed for", "in order to"]):
            return True

        return False

    def validate(self, raw: str, intent: str, prev_errors: List[str] | None = None) -> Dict[str, Any]:
        for fence in ("```json", "```"):
            raw = raw.replace(fence, "")
        raw = raw.strip()
        data: Dict[str, Any] = json.loads(raw)

        required_keys = {"mission_id", "intent", "execution_graph", "dataflow"}
        missing = required_keys - data.keys()
        if missing:
            raise ValueError(f"Missing top-level keys: {missing}")

        data.setdefault("global_constraints", {})
        data["global_constraints"]["target_os_family"] = "windows"
        data["global_constraints"]["language_target"] = "python"
        data.setdefault("malware_type", "generic")
        data.setdefault("validation_rules", asdict(ValidationRules()))

        tasks: List[Task] = []
        dropped_tasks: List[str] = []
        for item in data["execution_graph"]:
            t = self._parse_task(item)
            if t:
                tasks.append(t)
            else:
                dropped_tasks.append(str(item.get("task_id", "unknown")))

        valid_task_count = len(tasks)

        if valid_task_count < self.policy.min_tasks:
            if not self._allow_single_task_plan(intent, tasks):
                raise ValueError(
                    f"Only {valid_task_count} valid tasks (need ≥{self.policy.min_tasks})"
                )

        ids = [t.task_id for t in tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate task_id values detected")

        flows: List[DataFlow] = []
        for item in data["dataflow"]:
            f = self._parse_dataflow(item)
            if f:
                flows.append(f)

        task_by_id = {t.task_id: t for t in tasks}
        warnings: List[str] = []

        if dropped_tasks:
            warnings.append(f"Dropped {len(dropped_tasks)} invalid tasks: {dropped_tasks}")

        for task in tasks:
            if task.error_contract.on_failure not in VALID_ON_FAILURE:
                warnings.append(
                    f"task {task.task_id}: invalid on_failure='{task.error_contract.on_failure}', "
                    f"defaulting to 'return_partial'"
                )
                task.error_contract.on_failure = "return_partial"
        # Override abort_mission cho non-critical stages
        NON_ABORT_STAGES = {"discovery", "execution", "persistence", "defense-evasion"}
        for task in tasks:
            if (task.error_contract.on_failure == "abort_mission"
                    and task.stage in NON_ABORT_STAGES):
                task.error_contract.on_failure = "return_partial"
                warnings.append(
                    f"task {task.task_id}: override abort_mission → return_partial "
                    f"for stage={task.stage}"
                )

        for flow in flows:
            if flow.from_task not in task_by_id:
                raise ValueError(f"dataflow source missing: {flow.from_task}")
            if flow.to_task not in task_by_id:
                raise ValueError(f"dataflow target missing: {flow.to_task}")
            source_schema = task_by_id[flow.from_task].output_contract.schema
            if source_schema != flow.data_schema:
                warnings.append(
                    f"dataflow schema mismatch: {flow.from_task} outputs "
                    f"{source_schema} but edge declares {flow.data_schema}"
                )

        adj: Dict[str, List[str]] = defaultdict(list)
        in_degree: Dict[str, int] = {t.task_id: 0 for t in tasks}
        for flow in flows:
            adj[flow.from_task].append(flow.to_task)
            in_degree[flow.to_task] = in_degree.get(flow.to_task, 0) + 1

        queue: deque[str] = deque(tid for tid, deg in in_degree.items() if deg == 0)
        topo_order: List[str] = []
        while queue:
            node = queue.popleft()
            topo_order.append(node)
            for neighbor in adj[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(topo_order) != len(tasks):
            cycle_nodes = set(t.task_id for t in tasks) - set(topo_order)
            raise ValueError(f"Cycle detected in dataflow involving: {cycle_nodes}")

        for task in tasks:
            if task.input_contract and task.input_contract.sources:
                has_incoming = any(f.to_task == task.task_id for f in flows)
                if not has_incoming:
                    warnings.append(f"task {task.task_id} has input_contract but no incoming dataflow edges")

        task_order_map = {tid: idx for idx, tid in enumerate(topo_order)}
        for task in tasks:
            if task.task_id not in task_order_map:
                task_order_map[task.task_id] = len(topo_order)
        tasks.sort(key=lambda t: task_order_map.get(t.task_id, 999))

        incoming: Dict[str, Set[Tuple[str, str]]] = {}
        for flow in flows:
            incoming.setdefault(flow.to_task, set()).add((flow.from_task, flow.data_schema))

        for task in tasks:
            if self._looks_non_atomic(task):
                warnings.append(f"task {task.task_id} may not be atomic")

            retrieved = self.retriever.task_candidates(
                f"{task.intent}. {task.behavioral_goal}", task.stage, top_k=3
            )
            merged, status, confidence = self.retriever.merge_candidates(
                task.mitre_candidates, retrieved, task.stage,
                f"{task.intent}. {task.behavioral_goal}"
            )

            if retrieved and not task.mitre_candidates and task.stage != "data-processing":
                warnings.append(f"task {task.task_id}: no LLM candidates, retrieval backfilled")

            task.mitre_candidates = merged
            task.mitre_status = status
            task.mapping_confidence = confidence

            if task.stage == "data-processing" and task.mitre_candidates:
                warnings.append(f"task {task.task_id}: data-processing with MITRE candidates, clearing")
                task.mitre_candidates = []
                task.mitre_status = "not_applicable"
                task.mapping_confidence = "high"

            if task.stage != "data-processing" and len(task.mitre_candidates) >= 2:
                s1 = task.mitre_candidates[0].score or 0.0
                s2 = task.mitre_candidates[1].score or 0.0
                if abs(s1 - s2) <= 0.08 and not task.ambiguity_notes:
                    task.ambiguity_notes = (
                        f"close scores: {task.mitre_candidates[0].id} vs {task.mitre_candidates[1].id}"
                    )

            if task.input_contract:
                expected = {
                    (str(src.get("task_id")), str(src.get("schema")))
                    for src in task.input_contract.sources
                }
                actual = incoming.get(task.task_id, set())
                missing_edges = expected - actual
                if missing_edges:
                    warnings.append(f"task {task.task_id}: missing dataflow for: {sorted(missing_edges)}")

                for src in task.input_contract.sources:
                    up_id = str(src.get("task_id"))
                    up_schema = str(src.get("schema"))
                    up_task = task_by_id.get(up_id)
                    if up_task and up_task.output_contract.schema != up_schema:
                        warnings.append(
                            f"task {task.task_id}: expects {up_schema} from {up_id}, "
                            f"but upstream outputs {up_task.output_contract.schema}"
                        )

        if self.policy.network == "blocked":
            blocked_stages = {"exfiltration", "c2-setup"}
            exfil_tasks = [t for t in tasks if t.stage in blocked_stages]
            if exfil_tasks:
                warnings.append(
                    f"Policy network=blocked but plan contains {[t.task_id for t in exfil_tasks]} "
                    f"with stages {[t.stage for t in exfil_tasks]}. Consider removing these tasks."
                )

        forbidden = set(data.get("global_constraints", {}).get("forbidden_capabilities", []))
        if "self_propagation" in forbidden:
            spread_tasks = [t for t in tasks if t.stage == "lateral-movement"]
            if spread_tasks:
                warnings.append(
                    f"forbidden self_propagation but lateral-movement tasks present: "
                    f"{[t.task_id for t in spread_tasks]}"
                )

        intent_tokens = _tokenize(intent)
        for task in tasks:
            task_tokens = _tokenize(f"{task.intent} {task.behavioral_goal}")
            overlap = len(intent_tokens & task_tokens)
            if overlap == 0 and task.stage in ADVERSARIAL_STAGES:
                if not self._is_legitimate_prerequisite(task, intent):
                    warnings.append(
                        f"task {task.task_id} ({task.stage}: {task.intent}) "
                        f"has zero token overlap with intent — may be irrelevant"
                    )

        intent_lower = intent.lower()

        _EXFIL_SIGNALS   = {"exfil", "send", "upload", "transmit", "remote server", "c2", "https", "http", "post"}
        _PERSIST_SIGNALS = {"persist", "persistence", "startup", "autorun", "registry", "scheduled task", "logon","logs in", "log in", "login", "boot", "reboot",
                            "automatically", "auto-start", "autostart",
                            "execute automatically", "run automatically",
                            "survive reboot", "on startup", "on logon",}
        _PROTECT_SIGNALS = {"encrypt", "encrypted", "obfuscate", "protect", "stealth", "hide", "conceal"}
        _CLEANUP_SIGNALS = {"cleanup", "delete", "remove traces", "erase", "wipe artifact", "wipe artifacts"}
        _DISC_SIGNALS    = {"discover", "discovery", "enumerate", "scan", "list files", "list processes",
                            "system information", "process discovery", "file discovery",
                            "directory discovery", "user discovery", "hostname",
                            "collect", "gather", "os info", "user info", "user information",
                            "os version", "operating system", "host info", "environment info",
                            "system info", "machine info",}
        def _has(signals: set, text: str) -> bool:
            return any(s in text for s in signals)

        has_exfil_intent   = _has(_EXFIL_SIGNALS, intent_lower)
        has_persist_intent = _has(_PERSIST_SIGNALS, intent_lower)
        has_protect_intent = _has(_PROTECT_SIGNALS, intent_lower)
        has_cleanup_intent = _has(_CLEANUP_SIGNALS, intent_lower)
        has_disc_intent    = _has(_DISC_SIGNALS, intent_lower)

        severe_padding: list[str] = []
        moderate_padding: list[str] = []
        discovery_tasks = [t for t in tasks if t.stage == "discovery"]

        for idx, task in enumerate(tasks):
            goal  = (task.behavioral_goal or "").lower()
            stage = task.stage

            if stage == "exfiltration" and not has_exfil_intent:
                severe_padding.append(
                    f"{task.task_id}: exfiltration task but intent has no exfiltration signal"
                )
            if stage == "persistence" and not has_persist_intent:
                severe_padding.append(
                    f"{task.task_id}: persistence task but intent has no persistence signal"
                )

            if stage == "discovery" and not has_disc_intent:
                suspicious = False
                if len(discovery_tasks) > 1:
                    suspicious = True
                if idx > 0:
                    suspicious = True
                generic_phrases = [
                    "collect system information", "gather environment",
                    "enumerate files", "list processes", "discover security software",
                ]
                if any(p in goal for p in generic_phrases):
                    suspicious = True
                if suspicious:
                    moderate_padding.append(
                        f"{task.task_id}: discovery task may be padding for this intent"
                    )

            if stage == "defense-evasion" and not (has_protect_intent or has_exfil_intent):
                if any(x in goal for x in ["encrypt", "obfuscate", "protect", "conceal", "hide"]):
                    moderate_padding.append(
                        f"{task.task_id}: protection task may be unnecessary for this intent"
                    )

            if stage == "defense-evasion" and not (has_cleanup_intent or has_protect_intent):
                if any(x in goal for x in ["cleanup", "delete", "remove traces", "erase", "wipe artifact"]):
                    moderate_padding.append(
                        f"{task.task_id}: cleanup task may be padding for this intent"
                    )

        intent_word_count = len(intent.split())
        if len(tasks) > 6 and intent_word_count < 15:
            moderate_padding.append(
                f"plan has {len(tasks)} tasks but intent is short ({intent_word_count} words)"
            )

        warnings.extend(severe_padding)
        warnings.extend(moderate_padding)

        if severe_padding:
            raise ValueError(
                "Plan likely over-generated (severe): " + " | ".join(severe_padding)
            )
        if len(moderate_padding) >= 2:
            raise ValueError(
                "Plan likely over-generated (moderate): " + " | ".join(moderate_padding)
            )

        data["execution_graph"] = [asdict(t) for t in tasks]
        data["dataflow"] = [asdict(f) for f in flows]
        data["planner_warnings"] = warnings
        return data

    def _parse_task(self, item: dict) -> Optional[Task]:
        try:
            required = {"task_id", "stage", "intent", "behavioral_goal", "output_contract"}
            if not required.issubset(item):
                return None
            stage = str(item["stage"]).lower().strip()
            if stage not in VALID_STAGES:
                return None

            out = item["output_contract"]
            oc = OutputContract(schema=out["schema"], fields=out["fields"])

            ic = None
            if item.get("input_contract"):
                ic = InputContract(sources=item["input_contract"].get("sources", []))

            ec_data = item.get("error_contract", {})
            ec = ErrorContract(
                on_failure=ec_data.get("on_failure", "return_partial"),
                required_fields=ec_data.get("required_fields", []),
                fallback_value=ec_data.get("fallback_value"),
            )

            candidates = self._parse_mitre_candidates(item.get("mitre_candidates", []))
            techniques = self._validate_mitre_list(item.get("mitre_techniques", []))
            if not candidates and techniques:
                candidates = [
                    MitreCandidate(id=t, reason="backfilled from mitre_techniques", source="legacy")
                    for t in techniques
                ]

            return Task(
                task_id=str(item["task_id"]),
                stage=stage,
                intent=str(item["intent"]),
                behavioral_goal=str(item["behavioral_goal"]),
                output_contract=oc,
                input_contract=ic,
                error_contract=ec,
                mitre_candidates=candidates,
                mitre_techniques=techniques,
                mitre_status=str(item.get("mitre_status", "needs_verification")),
                mapping_confidence=str(item.get("mapping_confidence", "medium")),
                ambiguity_notes=str(item.get("ambiguity_notes", "")),
            )
        except Exception as exc:
            print(f"  [task parse error] {exc}")
            return None

    def _parse_dataflow(self, item: dict) -> Optional[DataFlow]:
        try:
            from_t = item.get("from_task") or item.get("from")
            to_t = item.get("to_task") or item.get("to")
            schema = item.get("data_schema") or item.get("data")
            if not (from_t and to_t and schema):
                return None
            return DataFlow(
                from_task=str(from_t), to_task=str(to_t),
                data_schema=str(schema), required=bool(item.get("required", True)),
                transform=item.get("transform"),
            )
        except Exception as exc:
            print(f"  [dataflow parse error] {exc}")
            return None

    def _parse_mitre_candidates(self, value: Any) -> List[MitreCandidate]:
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
                            score=self._clamp_score(item.get("score")),
                            source=str(item.get("source", "llm")),
                        ))
        return candidates

    @staticmethod
    def _validate_mitre_list(techniques: Any) -> List[str]:
        if not isinstance(techniques, list):
            return []
        return [t for t in techniques if isinstance(t, str) and MITRE_PATTERN.match(t)]

    @staticmethod
    def _clamp_score(value: Any) -> Optional[float]:
        if value is None:
            return None
        try:
            x = float(value)
            return max(0.0, min(1.0, x))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _looks_non_atomic(task: Task) -> bool:
        text = f"{task.intent} {task.behavioral_goal}".lower()
        if task.stage == "data-processing":
            return False
        strong_verbs = [
            "collect", "aggregate", "encrypt", "exfil", "upload", "send",
            "dump", "capture", "inject", "execute", "persist", "establish",
            "discover", "enumerate", "download", "decode",
        ]
        hits = sum(1 for verb in strong_verbs if verb in text)
        conjunction_patterns = [" and ", " then ", ", then ", " followed by "]
        has_conjunction = any(p in text for p in conjunction_patterns)
        return hits >= 3 or (hits >= 2 and has_conjunction)


class PlanPersister:
    def __init__(self, out_dir: str, stack_name: str):
        self.out_dir = Path(out_dir)
        self.stack = stack_name

    def save(self, mission: Dict[str, Any]) -> Path:
        self.out_dir.mkdir(parents=True, exist_ok=True)

        malware_type = _safe_filename(str(mission.get("malware_type", "generic")))
        mission_id = _safe_filename(str(mission.get("mission_id", "mission")))
        uid = uuid.uuid4().hex[:12]
        fname = f"{self.stack}_{malware_type}_{uid}_{mission_id}.json"
        fpath = self.out_dir / fname

        content = json.dumps(mission, ensure_ascii=False, indent=2)

        tmp_path = fpath.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                if 'fcntl' in globals():
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                else:
                    portalocker.lock(f, portalocker.LOCK_EX)
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
                if 'fcntl' in globals():
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                else:
                    portalocker.unlock(f)
            tmp_path.rename(fpath)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

        print(f"✓ Mission saved → {fpath}")
        return fpath


# ---------------------------------------------------------------------------
# Planner (orchestrator)
# ---------------------------------------------------------------------------

class WindowsPythonPlanner:
    def __init__(self, policy: Optional[PolicyFlags] = None,
                 stack_name: str = "openai",
                 out_dir: str = "artifacts/missions") -> None:
        load_dotenv(override=True)
        self.policy = policy or PolicyFlags()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o")
        self.client = OpenAI()
        self.stack = stack_name

        self.normalizer = IntentNormalizer(self.client, self.model)
        self.selector = ExampleSelector()
        self.retriever = MitreRetriever()
        self.prompt_builder = PromptBuilder()
        self.validator = PlanValidator(self.retriever, self.policy)
        self.persister = PlanPersister(out_dir, stack_name)

    def plan(self, intent: str) -> Dict[str, Any]:
        normalized = self.normalizer.normalize(intent)
        mission = self._generate_with_retry(normalized, intent)

        self._warn_mitre_gaps(mission["execution_graph"])

        mission.update(
            ts_utc=_utc_now(),
            model_used=self.model,
            task_count=len(mission["execution_graph"]),
            original_intent=intent,
            normalized_intent=normalized,
        )

        if "planner_summary" in mission:
            mission["planner_summary"]["normalized_intent"] = normalized
            mission["planner_summary"]["mitre_selection_mode"] = "retrieval_constrained_candidate_generation"

        path = self.persister.save(mission)
        mission["mission_path"] = str(path)
        return mission

    def _generate_with_retry(self, intent: str, original_intent: str,
                             max_retries: int = 3) -> Dict[str, Any]:
        selected = self.selector.select(intent)
        temperature = self.selector.get_temperature(selected)
        hints = self.retriever.mission_hints(intent, top_k=6)

        prev_errors: List[str] = []
        total_prompt_tokens = 0
        total_completion_tokens = 0

        for attempt in range(max_retries):
            try:
                user_prompt = self.prompt_builder.build(
                    intent, selected, hints, self.policy
                )

                if prev_errors:
                    error_block = (
                        "\n\nPREVIOUS ATTEMPT FAILED. Errors:\n"
                        + "\n".join(f"- {e}" for e in prev_errors[-3:])
                        + "\nPlease fix these issues in your output.\n"
                    )
                    user_prompt += error_block

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": PromptBuilder.SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=temperature,
                    max_tokens=4500,
                )

                if response.usage:
                    total_prompt_tokens += response.usage.prompt_tokens
                    total_completion_tokens += response.usage.completion_tokens

                raw = (response.choices[0].message.content or "{}").strip()
                mission = self.validator.validate(raw, original_intent)
                mission["planner_summary"] = {
                    "selected_examples": selected,
                    "selection_mode": "dynamic_few_shot_top3",
                    "planner_temperature": temperature,
                    "intent_retrieval_hints": hints,
                    "token_usage": {
                        "prompt_tokens": total_prompt_tokens,
                        "completion_tokens": total_completion_tokens,
                        "total_tokens": total_prompt_tokens + total_completion_tokens,
                        "attempts": attempt + 1,
                    },
                }
                return mission

            except json.JSONDecodeError as exc:
                msg = f"Invalid JSON: {str(exc)[:100]}"
                print(f"Attempt {attempt + 1}/{max_retries}: {msg}")
                prev_errors.append(msg)
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)

            except ValueError as exc:
                msg = f"Validation error: {str(exc)[:150]}"
                print(f"Attempt {attempt + 1}/{max_retries}: {msg}")
                prev_errors.append(msg)
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)

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
                prev_errors.append(f"{type(exc).__name__}: {msg[:100]}")

        print("All attempts failed — using fallback plan.")
        return self._fallback_plan(intent, original_intent, prev_errors,
                                    total_prompt_tokens, total_completion_tokens)

    def _fallback_plan(self, intent: str, original_intent: str,
                       errors: List[str],
                       prompt_tokens: int, completion_tokens: int) -> Dict[str, Any]:
        """PATCH 2: core_stage driven by FALLBACK_STAGE_BY_TYPE."""
        detected_type = _detect_example_key(original_intent)
        hints = self.retriever.mission_hints(original_intent, top_k=3)

        tasks: List[Dict[str, Any]] = []

        intent_lower = original_intent.lower()
        needs_discovery = any(kw in intent_lower for kw in [
            "discover", "enumerate", "scan", "collect info", "gather info",
            "system info", "list file", "find process",
        ])

        if needs_discovery:
            tasks.append(asdict(Task(
                task_id="T1", stage="discovery",
                intent="Environment Discovery",
                behavioral_goal="Gather required environmental information",
                output_contract=OutputContract(
                    schema="EnvironmentInfo",
                    fields={"info": "string_json"}
                ),
                error_contract=ErrorContract(on_failure="abort_mission", required_fields=["info"]),
                mitre_candidates=[MitreCandidate(id="T1082", reason="system discovery", score=0.75, source="fallback")],
                mitre_status="needs_verification", mapping_confidence="medium",
            )))

        core_task_id = f"T{len(tasks) + 1}"
        core_candidates = [
            MitreCandidate(id=h["id"], reason=h["name"], score=h["score"], source="fallback")
            for h in hints[:2]
        ]

        # PATCH 2: use type-aware stage
        core_stage = FALLBACK_STAGE_BY_TYPE.get(detected_type, "execution")

        tasks.append(asdict(Task(
            task_id=core_task_id,
            stage=core_stage,
            intent="Core Objective",
            behavioral_goal=f"Execute primary objective: {original_intent[:120]}",
            input_contract=InputContract(
                sources=[{"task_id": "T1", "schema": "EnvironmentInfo"}]
            ) if needs_discovery else None,
            output_contract=OutputContract(
                schema="ExecutionResult", fields={"status": "string", "result": "string_json"}
            ),
            error_contract=ErrorContract(on_failure="abort_mission", required_fields=["status"]),
            mitre_candidates=core_candidates,
            mitre_status="needs_verification",
            mapping_confidence="low",
            ambiguity_notes="fallback plan — verifier must refine",
        )))

        dataflows = []
        if needs_discovery:
            dataflows.append(asdict(DataFlow(
                from_task="T1", to_task=core_task_id, data_schema="EnvironmentInfo"
            )))

        return {
            "mission_id": f"fallback_{uuid.uuid4().hex[:8]}",
            "intent": original_intent,
            "malware_type": detected_type if detected_type != "unknown" else "generic",
            "global_constraints": asdict(GlobalConstraints()),
            "validation_rules": asdict(ValidationRules()),
            "execution_graph": tasks,
            "dataflow": dataflows,
            "planner_summary": {
                "selected_examples": ["fallback"],
                "selection_mode": "fallback",
                "planner_temperature": 0.0,
                "mitre_selection_mode": "retrieval_constrained_candidate_generation",
                "normalized_intent": intent,
                "token_usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                    "attempts": 3,
                },
                "fallback_errors": errors,
            },
            "planner_warnings": [
                "fallback plan used after repeated generation failures",
                f"generation errors: {errors}",
            ],
        }

    @staticmethod
    def _warn_mitre_gaps(execution_graph: List[dict]) -> None:
        missing = [
            t for t in execution_graph
            if t["stage"] in ADVERSARIAL_STAGES and not t.get("mitre_candidates")
        ]
        if missing:
            print(f"\n⚠️  {len(missing)} adversarial tasks without MITRE candidates:")
            for t in missing:
                print(f"   • {t['task_id']} ({t['stage']}: {t['intent']})")
            print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Windows Python Mission Planner v9")
    parser.add_argument("--intent", required=True)
    parser.add_argument("--policy-network", default="allowed",
                        choices=["blocked", "localhost-only", "allowed", "full"])
    parser.add_argument("--out-dir", default="artifacts/missions")
    parser.add_argument("--max-tasks", type=int, default=8)
    parser.add_argument("--min-tasks", type=int, default=2)
    args = parser.parse_args()

    policy = PolicyFlags(
        network=args.policy_network,
        max_tasks=args.max_tasks,
        min_tasks=args.min_tasks,
    )
    planner = WindowsPythonPlanner(policy=policy, out_dir=args.out_dir)
    result = planner.plan(args.intent)
    print(json.dumps(result, indent=2, ensure_ascii=False))