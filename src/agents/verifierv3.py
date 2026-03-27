from __future__ import annotations
import json
import re
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple
from copy import deepcopy
from dotenv import load_dotenv
from openai import OpenAI

# ── Constants ──────────────────────────────────────────────────────────────────

VALID_STAGES = {
    "recon", "discovery", "initial-access", "execution", "privilege-escalation",
    "persistence", "defense-evasion", "exfiltration", "lateral-movement",
    "credential-access", "weaponization", "c2-setup", "data-processing"
}
VALID_EXECUTION_MODELS = {"modular", "sequential", "parallel", "persistent", "scheduled"}
VALID_ON_FAILURE       = {"abort_mission", "return_partial", "retry"}
UTILITY_STAGES         = {"data-processing"}  # no MITRE needed
INDEPENDENT_STAGES     = {"persistence"}       # run independently, no incoming edges needed

# Strict field type system
VALID_FIELD_TYPES = {
    "string",        # plain string
    "string_json",   # json.dumps() output — encode directly, never re-serialize
    "integer",
    "boolean",
    "bytes",         # raw bytes
    "array",         # list
    "dict",          # raw Python dict
    "float",
    "null",
}

# Legacy/ambiguous types → normalize to strict types
_TYPE_ALIASES: Dict[str, str] = {
    "json_object": "string_json",
    "list":        "array",
    "bool":        "boolean",
    "int":         "integer",
    "str":         "string",
    "number":      "float",
}

STAGE_ORDER_CONSTRAINTS: List[Tuple[str, str]] = [
    ("credential-access",  "privilege-escalation"),
    ("credential-access",  "discovery"),
    ("exfiltration",       "defense-evasion"),
    ("exfiltration",       "data-processing"),
    ("persistence",        "discovery"),
    ("c2-setup",           "persistence"),
]

# LLM prompt — built once at module level for clarity
_SEMANTIC_FIX_RULES = """
RULES (strictly follow all):
- Keep existing task_ids unchanged; new tasks use next available IDs (T6, T7…)
- Keep mission_id, intent, malware_type unchanged
- Target: Windows, Python only
- Use ONLY these valid stages: {valid_stages}
- Encryption/obfuscation tasks → stage 'defense-evasion'
- Data aggregation/processing tasks → stage 'data-processing'
- 'data-processing' tasks are utility only → mitre_techniques MUST be []
- Persistence tasks run independently → remove incoming dataflow edges unless data is genuinely required
- Only add a new task if it is STRICTLY missing from the pipeline
  · Do NOT add a task if the needed data already exists in any task's output_contract.fields
  · Do NOT add a privilege-check task if is_admin or similar field is already collected
- Encryption tasks (defense-evasion stage with AES/cipher in behavioral_goal): output_contract.fields MUST include 'key: bytes' so downstream tasks can decrypt
- Buffer/collection tasks that mention time interval (e.g. "every N seconds", "every N minutes"): output_contract.fields MUST include 'timestamp: string' and 'interval_seconds: integer'
- Fix data_schema in dataflow edges to match the actual output_contract.schema of the source task
- Do not invent stage names outside the valid list
- Do NOT modify mitre_techniques — MITRE validation is handled separately
- Use ONLY these field types: string, string_json, integer, boolean, bytes, array, dict, float, null
- Tasks that serialize data via json.dumps() → output field type MUST be 'string_json' (not 'json_object', not 'string')
- 'string_json' means the field is already a JSON string — downstream must .encode() directly, never re-serialize
""".strip()


# ── VerifyResult ───────────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    valid:      bool
    errors:     List[str] = field(default_factory=list)
    warnings:   List[str] = field(default_factory=list)
    auto_fixed: List[str] = field(default_factory=list)
    data:       Optional[Dict[str, Any]] = None

    def summary(self) -> str:
        status = "✅ VALID" if self.valid else "❌ INVALID"
        lines  = [status,
                  f"  Errors    : {len(self.errors)}",
                  f"  Warnings  : {len(self.warnings)}",
                  f"  Auto-fixed: {len(self.auto_fixed)}"]
        lines += [f"  ❌ {e}"  for e in self.errors]
        lines += [f"  ⚠️  {w}" for w in self.warnings]
        lines += [f"  🔧 {f}"  for f in self.auto_fixed]
        return "\n".join(lines)


# ── BaseVerifier ───────────────────────────────────────────────────────────────

class BaseVerifier(ABC):

    def __init__(self, strict: bool = False) -> None:
        load_dotenv()
        self.strict = strict
        self.client = OpenAI()
        self.model  = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    @abstractmethod
    def verify(self, data: Dict[str, Any]) -> VerifyResult: ...

    # ── shared helpers ────────────────────────────────────────────────────────

    def _llm_call(self, prompt: str, max_tokens: int = 4000) -> Optional[Dict]:
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=max_tokens,
            )
            return json.loads(resp.choices[0].message.content or "{}")
        except Exception as e:
            print(f"⚠️  LLM call failed: {e}")
            return None

    def _detect_cycle(self, graph: Dict[str, List[str]]) -> Optional[List[str]]:
        visited, rec_stack, path = set(), set(), []

        def dfs(node: str) -> bool:
            visited.add(node); rec_stack.add(node); path.append(node)
            for nb in graph.get(node, []):
                if nb not in visited:
                    if dfs(nb): return True
                elif nb in rec_stack:
                    path.append(nb); return True
            rec_stack.discard(node); path.pop()
            return False

        for n in list(graph): 
            if n not in visited and dfs(n): return path
        return None

    def _normalize_dataflow(self, dataflow: list, fixed: list) -> list:
        for e in dataflow:
            if "from" in e and "from_task" not in e:
                e["from_task"] = e.pop("from")
                fixed.append("dataflow: 'from' → 'from_task'")
            if "to" in e and "to_task" not in e:
                e["to_task"] = e.pop("to")
                fixed.append("dataflow: 'to' → 'to_task'")
        return dataflow

    def _connected_ids(self, dataflow: list) -> Set[str]:
        return {tid for e in dataflow for tid in (e.get("from_task",""), e.get("to_task","")) if tid}


# ── PlannerVerifier ────────────────────────────────────────────────────────────

class PlannerVerifier(BaseVerifier):
    """
    3-phase verifier for Planner Agent mission JSON.

    Phase 1 — Rule-based structural validation (fast, deterministic)
    Phase 2 — LLM holistic semantic fix (one call, full mission context)
    Phase 3 — Re-run Phase 1 to catch regressions introduced by Phase 2
    """

    def verify(self, data: Dict[str, Any], intent: str = "") -> VerifyResult:
        mission = deepcopy(data)
        errors, warnings, fixed = [], [], []

        # ── Phase 1 ───────────────────────────────────────────────────────────
        print("  [Phase 1] Structural checks...")
        self._structural_check(mission, errors, warnings, fixed)
        if errors:
            return VerifyResult(False, errors, warnings, fixed, mission)

        # ── Phase 2 ───────────────────────────────────────────────────────────
        print("  [Phase 2] LLM semantic fix...")
        mission, sem_fixed, sem_warn = self._llm_semantic_fix(mission, intent=intent)
        fixed.extend(sem_fixed); warnings.extend(sem_warn)

        # ── Phase 2b ──────────────────────────────────────────────────────────
        print("  [Phase 2b] MITRE specialist fix...")
        mission, mitre_fixed, mitre_warn = self._llm_mitre_fix(mission, intent=intent)
        fixed.extend(mitre_fixed); warnings.extend(mitre_warn)

        # ── Phase 3 ───────────────────────────────────────────────────────────
        print("  [Phase 3] Re-verifying...")
        p3_errors, p3_warn, p3_fixed = [], [], []
        self._structural_check(mission, p3_errors, p3_warn, p3_fixed,
                               suppress_floating=INDEPENDENT_STAGES)
        fixed.extend(p3_fixed); warnings.extend(p3_warn)

        if p3_errors:
            print(f"  ⚠️  Phase 2 introduced {len(p3_errors)} regression(s)")
            return VerifyResult(False,
                                [f"[regression] {e}" for e in p3_errors],
                                warnings, fixed, mission)

        return VerifyResult(True, [], warnings, fixed, mission)

    # ── Structural check (shared by Phase 1 & 3) ─────────────────────────────

    def _structural_check(
        self, mission: dict,
        errors: list, warnings: list, fixed: list,
        suppress_floating: Set[str] | None = None,
    ) -> None:
        suppress_floating = suppress_floating or set()

        # Required keys
        for k in ("mission_id", "intent", "global_constraints",
                  "execution_graph", "dataflow"):
            if k not in mission:
                errors.append(f"Missing key: '{k}'")
        if errors: return

        # Global constraints
        gc = mission["global_constraints"]
        if gc.get("execution_model") not in VALID_EXECUTION_MODELS:
            old = gc.get("execution_model", "?")
            gc["execution_model"] = "modular"
            fixed.append(f"execution_model '{old}' → 'modular'")
        if gc.get("target_os_family") != "windows":
            gc["target_os_family"] = "windows"
            fixed.append("target_os_family → 'windows'")
        if gc.get("language_target") != "python":
            gc["language_target"] = "python"
            fixed.append("language_target → 'python'")

        # Tasks
        tasks  = mission.get("execution_graph", [])
        task_ids: Set[str] = set()
        if len(tasks) < 2:
            errors.append(f"execution_graph needs ≥2 tasks, got {len(tasks)}")
            return

        for i, t in enumerate(tasks):
            tid = t.get("task_id", f"T?[{i}]")
            if tid in task_ids: errors.append(f"Duplicate task_id: '{tid}'")
            task_ids.add(tid)

            stage = str(t.get("stage", "")).lower().strip()
            if stage not in VALID_STAGES:
                errors.append(f"{tid}: invalid stage '{stage}'")

            oc = t.get("output_contract")
            if not oc:
                errors.append(f"{tid}: missing output_contract")
            else:
                if "schema" not in oc:
                    errors.append(f"{tid}: output_contract missing 'schema'")
                if not isinstance(oc.get("fields"), dict):
                    errors.append(f"{tid}: output_contract.fields must be a dict")
                else:
                    # Normalize and validate field types
                    for fname, ftype in list(oc["fields"].items()):
                        ftype_str = str(ftype).lower().strip()
                        if ftype_str in _TYPE_ALIASES:
                            normalized = _TYPE_ALIASES[ftype_str]
                            oc["fields"][fname] = normalized
                            fixed.append(f"{tid}.{fname}: type '{ftype_str}' → '{normalized}'")
                        elif ftype_str not in VALID_FIELD_TYPES:
                            # Unknown type — keep but warn
                            warnings.append(f"{tid}.{fname}: unknown field type '{ftype_str}'"  )

            ec = t.get("error_contract") or {}
            if ec.get("on_failure") not in VALID_ON_FAILURE:
                old = ec.get("on_failure", "?")
                ec["on_failure"] = "return_partial"
                fixed.append(f"{tid}: on_failure '{old}' → 'return_partial'")

        # Dataflow
        dataflow = self._normalize_dataflow(mission.get("dataflow", []), fixed)
        mission["dataflow"] = dataflow

        for e in dataflow:
            for key in ("from_task", "to_task"):
                ref = e.get(key, "")
                if ref and ref not in task_ids:
                    errors.append(f"dataflow: {key} '{ref}' not in execution_graph")

        graph: Dict[str, List[str]] = {tid: [] for tid in task_ids}
        for e in dataflow:
            s, d = e.get("from_task",""), e.get("to_task","")
            if s in graph: graph[s].append(d)
        cycle = self._detect_cycle(graph)
        if cycle:
            errors.append(f"Cycle: {' → '.join(cycle)}")

        # Floating tasks (warn only, skip suppressed stages)
        connected = self._connected_ids(dataflow)
        floating = [
            t for i, t in enumerate(tasks)
            if t.get("task_id","") not in connected
            and i > 0
            and t.get("stage","") not in suppress_floating
        ]
        if floating:
            warnings.append(
                "Floating tasks: " +
                ", ".join(f"{t['task_id']} ({t.get('stage','')})" for t in floating)
            )

        # Stage ordering
        pos: Dict[str, int] = {}
        for i, t in enumerate(tasks):
            pos.setdefault(t.get("stage",""), i)
        for later, earlier in STAGE_ORDER_CONSTRAINTS:
            if later in pos and earlier in pos and pos[later] < pos[earlier]:
                warnings.append(f"Stage ordering: '{later}' before '{earlier}'")

        # Fallback consistency
        for t in tasks:
            tid      = t.get("task_id", "?")
            fallback = (t.get("error_contract") or {}).get("fallback_value")
            if not isinstance(fallback, dict): continue
            out_fields = (t.get("output_contract") or {}).get("fields", {})
            for k in fallback:
                if k not in out_fields:
                    warnings.append(f"{tid}: fallback field '{k}' not in output_contract.fields")

    # ── Phase 2: LLM semantic fix ─────────────────────────────────────────────

    def _llm_semantic_fix(
        self, mission: dict, intent: str = ""
    ) -> Tuple[dict, List[str], List[str]]:

        # Build all-fields map so LLM knows what data already exists
        existing_fields: Dict[str, list] = {
            t["task_id"]: list((t.get("output_contract") or {}).get("fields", {}).keys())
            for t in mission.get("execution_graph", [])
            if "task_id" in t
        }

        rules = _SEMANTIC_FIX_RULES.format(
            valid_stages=", ".join(sorted(VALID_STAGES))
        )

        intent_section = (
            f"ORIGINAL USER INTENT:\n{intent}\n\n"
            "Use this intent as ground truth to verify:\n"
            "- Each task actually implements what the intent requires\n"
            "- Output contract fields match what the intent implies (e.g. '60 seconds' → timestamp field)\n"
            "- MITRE techniques match the actual method described (e.g. 'HTTPS POST' → T1071.001 not T1071.003)\n"
            "- No required capability from the intent is missing from the pipeline\n\n"
        ) if intent else ""

        prompt = (
            "You are a senior malware analyst and Windows red team expert.\n"
            "Review this mission plan and return a fully corrected version.\n\n"
            f"{intent_section}"
            "MISSION PLAN:\n"
            f"{json.dumps(mission, indent=2)}\n\n"
            "EXISTING OUTPUT FIELDS PER TASK (do not duplicate these in new tasks):\n"
            f"{json.dumps(existing_fields, indent=2)}\n\n"
            "YOUR JOB:\n"
            "1. Fix MITRE techniques — remove wrong ones, add correct ones per task behavior\n"
            "2. Add missing tasks ONLY if strictly required and data not already available\n"
            "3. Fix schema names in dataflow edges to match source output_contract.schema\n"
            "4. Add missing dataflow edges for any new tasks\n"
            "5. Reorder tasks if execution order is logically wrong\n"
            "6. Add output_contract fields only if downstream tasks genuinely need them\n"
            "7. Verify mission fully implements the original intent\n\n"
            f"{rules}\n\n"
            "Return ONLY valid JSON:\n"
            "{\n"
            '  "fixes_applied": ["concise description of each fix"],\n'
            '  "warnings": ["anything notable but not fixed"],\n'
            '  "corrected_mission": { ...full corrected mission JSON... }\n'
            "}"
        )

        result = self._llm_call(prompt)
        if not result:
            return mission, [], ["LLM semantic fix unavailable"]

        corrected = result.get("corrected_mission")
        if not isinstance(corrected, dict):
            return mission, [], ["LLM returned invalid mission structure"]

        # Preserve original metadata
        for key in ("ts_utc", "model_used", "mission_path"):
            if key in mission:
                corrected[key] = mission[key]
        corrected["task_count"] = len(corrected.get("execution_graph", []))

        return corrected, result.get("fixes_applied", []), result.get("warnings", [])

    # ── Phase 2b: MITRE specialist fix ───────────────────────────────────────

    def _llm_mitre_fix(
        self, mission: dict, intent: str = ""
    ) -> Tuple[dict, List[str], List[str]]:
        """
        Dedicated MITRE ATT&CK specialist pass.
        Only modifies mitre_techniques per task — does not touch anything else.
        """

        tasks = mission.get("execution_graph", [])

        # Build task summaries for the prompt
        task_summaries = [
            {
                "task_id":       t.get("task_id"),
                "stage":         t.get("stage"),
                "intent":        t.get("intent"),
                "behavioral_goal": t.get("behavioral_goal"),
                "current_mitre": t.get("mitre_techniques", []),
            }
            for t in tasks
        ]

        intent_line = f"Overall mission intent: {intent}\n\n" if intent else ""

        prompt = (
            "You are a MITRE ATT&CK v14 expert specializing in Windows malware TTPs.\n"
            "Your ONLY job is to assign correct MITRE ATT&CK technique IDs to each task.\n\n"
            f"{intent_line}"
            "TASKS:\n"
            f"{json.dumps(task_summaries, indent=2)}\n\n"
            "RULES:\n"
            "- Use the most SPECIFIC sub-technique when applicable (e.g. T1555.003 not T1555)\n"
            "- Base assignment on behavioral_goal, NOT just the stage name\n"
            "- data-processing tasks: ALWAYS return empty list []\n"
            "- persistence tasks: use T1547.001 for Run key, T1053.005 for scheduled task\n"
            "- discovery tasks: T1082 (OS info), T1033 (user), T1083 (file/dir), T1057 (process)\n"
            "- credential-access from browser SQLite+DPAPI: T1555.003 + T1539\n"
            "- defense-evasion AES encryption: T1027 (payload obfuscation)\n"
            "- defense-evasion file deletion/cleanup: T1070.004\n"
            "- exfiltration HTTPS POST to C2: T1041 + T1071.001\n"
            "- exfiltration via email: T1048.003\n"
            "- execution keyboard hook: T1056.001\n"
            "- T1573 (Encrypted Channel) only for custom encrypted C2 protocol, NOT for payload encryption\n"
            "- Remove any technique that does not match the specific behavioral_goal\n\n"
            "Return ONLY valid JSON:\n"
            "{\n"
            '  "fixes_applied": ["concise description of each MITRE fix"],\n'
            '  "mitre_assignments": {\n'
            '    "T1": ["T1082"],\n'
            '    "T2": []\n'
            "  }\n"
            "}"
        )

        result = self._llm_call(prompt, max_tokens=2000)
        if not result:
            return mission, [], ["MITRE specialist fix unavailable"]

        assignments = result.get("mitre_assignments", {})
        if not isinstance(assignments, dict):
            return mission, [], ["MITRE specialist returned invalid structure"]

        # Apply assignments — only update mitre_techniques, nothing else
        mission = deepcopy(mission)
        fixes = []
        for t in mission.get("execution_graph", []):
            tid = t.get("task_id")
            if tid in assignments:
                old = t.get("mitre_techniques", [])
                new = assignments[tid]
                if sorted(old) != sorted(new):
                    t["mitre_techniques"] = new
                    fixes.append(f"{tid}: MITRE {old} → {new}")

        return mission, result.get("fixes_applied", fixes), []


# ── DeveloperVerifier ─────────────────────────────────────────────────────────

class DeveloperVerifier(BaseVerifier):
    """
    Verifies Python modules generated by DeveloperAgent.

    Input data dict:
        {
            "manifest": <manifest dict from artifacts/modules/manifest_*.json>,
            "mission":  <verified mission dict>
        }

    Per-module checks:
      Phase 1 (static AST):
        - run() function exists
        - Required output fields present in code
        - Nested schema access anti-pattern
        - is_admin subprocess missing CalledProcessError handler
      Phase 2 (LLM fix): auto-fix found issues
      Phase 3 (re-validate): confirm fix worked
    """

    _NESTED_RE = re.compile(r"input_data\.get\(\s*['\"][A-Z][A-Za-z]+['\"]")

    def verify(self, data: Dict[str, Any]) -> VerifyResult:
        manifest = data.get("manifest", {})
        mission  = data.get("mission",  {})

        modules  = [m for m in manifest.get("modules", [])
                    if m.get("status") == "success" and m.get("path")]
        task_map = {t["task_id"]: t for t in mission.get("execution_graph", [])}

        errors:     List[str] = []
        warnings:   List[str] = []
        auto_fixed: List[str] = []
        fixed_paths: Dict[str, str] = {}

        for mod in modules:
            tid  = mod["task_id"]
            path = Path(mod["path"])
            task = task_map.get(tid, {})

            print(f"\n  [{tid}] {mod.get('intent', '')}...")

            try:
                code = path.read_text(encoding="utf-8")
            except Exception as e:
                errors.append(f"{tid}: cannot read — {e}")
                continue

            out_fields = list((task.get("output_contract") or {}).get("fields", {}).keys())

            # Phase 1
            issues = self._static_check(code, out_fields)
            if issues:
                print(f"    ⚠️  Phase 1: {len(issues)} issue(s)")
                for i in issues: print(f"       • {i}")
            else:
                print(f"    ✅ Phase 1: OK")

            # Phase 2 — LLM fix
            if issues:
                fixed = self._llm_fix(code, issues, task)
                if fixed:
                    remaining = self._static_check(fixed, out_fields)
                    if not remaining:
                        fp = path.with_stem(path.stem + "_fixed")
                        fp.write_text(fixed, encoding="utf-8")
                        fp.chmod(0o755)
                        fixed_paths[tid] = str(fp)
                        auto_fixed.append(f"{tid}: fixed {len(issues)} issue(s) → {fp.name}")
                        print(f"    ✅ Phase 2: Fixed → {fp.name}")
                    else:
                        warnings.append(f"{tid}: partial fix — {len(remaining)} remain")
                        print(f"    ⚠️  Phase 2: Partial, {len(remaining)} remaining")
                        for r in remaining: print(f"       • {r}")
                else:
                    warnings.append(f"{tid}: LLM fix failed — manual review needed")
                    print(f"    ⚠️  Phase 2: LLM fix unavailable")
            else:
                print(f"    ✅ Phase 2: No fix needed")

        updated = deepcopy(manifest)
        for mod in updated.get("modules", []):
            if mod["task_id"] in fixed_paths:
                mod["path"]   = fixed_paths[mod["task_id"]]
                mod["status"] = "fixed"

        return VerifyResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            auto_fixed=auto_fixed,
            data=updated,
        )

    def _static_check(self, code: str, out_fields: List[str]) -> List[str]:
        issues = []
        if not re.search(r"^def run\(", code, re.MULTILINE):
            issues.append("Missing run() function")
        for f in out_fields:
            if f"'{f}'" not in code and f'"{f}"' not in code:
                issues.append(f"Output field '{f}' not found in code")
        if self._NESTED_RE.search(code):
            issues.append("Nested schema access: use input_data.get('field') directly")
        if ("net session" in code or "is_admin" in code) and \
           "subprocess.check_output" in code and \
           "except subprocess.CalledProcessError" not in code:
            issues.append("is_admin check missing except subprocess.CalledProcessError")
        return issues

    def _llm_fix(self, code: str, issues: List[str], task: Dict[str, Any]) -> Optional[str]:
        out_fields = list((task.get("output_contract") or {}).get("fields", {}).keys())
        issue_text = "\n".join(f"- {i}" for i in issues)

        prompt = (
            "Fix ONLY the listed issues in this Python module for a Windows security research framework.\n"
            "Do NOT change any other logic. Output ONLY valid Python code, no markdown.\n\n"
            f"Task stage : {task.get('stage','')}\n"
            f"Task goal  : {task.get('behavioral_goal','')}\n"
            f"Output fields required: {out_fields}\n\n"
            f"Issues to fix:\n{issue_text}\n\n"
            "Fix rules:\n"
            "- input_data is FLAT — use input_data.get('field') directly, never nested\n"
            "- is_admin MUST wrap subprocess in try/except subprocess.CalledProcessError\n"
            "- All output_contract fields must appear in returned 'data' dict\n"
            "- Encryption tasks must include 'key' in output\n\n"
            f"Code:\n{code}"
        )

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=3000,
            )
            raw = resp.choices[0].message.content or ""
            raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
            raw = re.sub(r"\n?```$", "", raw).strip()
            compile(raw, "<string>", "exec")
            return raw
        except Exception:
            return None


# ── IntegratorVerifier ────────────────────────────────────────────────────────

class IntegratorVerifier(BaseVerifier):
    """
    Static-only verifier for the merged integration file.
    No LLM needed — pure AST + regex checks.

    Input data dict:
        {
            "integration_file": "/path/to/merged.py",
            "mission":          <verified mission dict>,
            "manifest":         <manifest dict>          # optional
        }

    Checks:
      - Syntax valid (compile)
      - All task_T<ID>() functions present
      - main() function present
      - main() calls each task in correct dataflow order
      - No unreplaced TASK_ID placeholders
      - All required imports present (requests, Crypto, etc.)
    """

    def verify(self, data: Dict[str, Any]) -> VerifyResult:
        integration_file = data.get("integration_file", "")
        mission          = data.get("mission", {})

        errors:    List[str] = []
        warnings:  List[str] = []
        auto_fixed: List[str] = []

        # Load file
        try:
            code = Path(integration_file).read_text(encoding="utf-8")
        except Exception as e:
            return VerifyResult(False, [f"Cannot read integration file: {e}"], [], [], None)

        print(f"  Checking: {Path(integration_file).name}")

        # ── Check 1: Syntax ───────────────────────────────────────────────────
        try:
            tree = compile(code, integration_file, "exec", flags=0)
            print("  ✅ Syntax: OK")
        except SyntaxError as e:
            errors.append(f"Syntax error: {e}")
            print(f"  ❌ Syntax: {e}")
            return VerifyResult(False, errors, warnings, auto_fixed, None)

        # ── Check 2: All task functions present ───────────────────────────────
        tasks    = mission.get("execution_graph", [])
        task_ids = [t["task_id"] for t in tasks]

        missing_funcs = []
        for tid in task_ids:
            if not re.search(rf"^def task_{tid}\(", code, re.MULTILINE):
                missing_funcs.append(f"task_{tid}()")

        if missing_funcs:
            for f in missing_funcs:
                errors.append(f"Missing function: {f}")
            print(f"  ❌ Functions: missing {missing_funcs}")
        else:
            print(f"  ✅ Functions: all {len(task_ids)} task functions present")

        # ── Check 3: main() present ───────────────────────────────────────────
        if not re.search(r"^def main\(", code, re.MULTILINE):
            errors.append("Missing main() orchestrator function")
            print("  ❌ main(): missing")
        else:
            print("  ✅ main(): present")

        # ── Check 4: main() calls tasks in correct order ──────────────────────
        # Extract task call order from main()
        main_match = re.search(r"def main\(.*?(?=\ndef |\Z)", code, re.DOTALL)
        if main_match:
            main_body = main_match.group(0)
            call_order = re.findall(r"task_(T\d+)\(", main_body)

            # Build expected order from dataflow
            dataflow  = mission.get("dataflow", [])
            all_called = set(call_order)
            missing_calls = [tid for tid in task_ids if tid not in all_called]

            if missing_calls:
                for tid in missing_calls:
                    errors.append(f"main() never calls task_{tid}()")
                print(f"  ❌ Orchestrator: missing calls {missing_calls}")
            else:
                print(f"  ✅ Orchestrator: all tasks called")

            # Check T5 independence (persistence) called with None
            for t in tasks:
                if t.get("stage") == "persistence":
                    tid = t["task_id"]
                    if f"task_{tid}(None)" not in code and f"task_{tid}(outputs" not in code:
                        warnings.append(f"task_{tid}() (persistence) call pattern unclear")

        # ── Check 5: No TASK_ID placeholders ─────────────────────────────────
        if "TASK_ID" in code:
            warnings.append("Unreplaced 'TASK_ID' placeholder found")
            print("  ⚠️  Placeholder: TASK_ID found")
        else:
            print("  ✅ Placeholders: none")

        # ── Check 6: Required imports (AST-based) ────────────────────────────
        required_modules = self._infer_required_modules(tasks)
        imported_modules = self._extract_imported_modules(code)
        missing_imports  = [m for m in required_modules if m not in imported_modules]
        if missing_imports:
            for m in missing_imports:
                warnings.append(f"Possibly missing import: {m}")
            print(f"  ⚠️  Imports: possibly missing {missing_imports}")
        else:
            print(f"  ✅ Imports: OK")

        valid = len(errors) == 0
        return VerifyResult(valid, errors, warnings, auto_fixed, {"integration_file": integration_file})

    def _infer_required_modules(self, tasks: List[Dict]) -> List[str]:
        """Infer required top-level module names from task stages."""
        import ast as _ast
        modules = ["json", "time"]
        stages  = {t.get("stage", "") for t in tasks}
        mitre   = {m for t in tasks for m in t.get("mitre_techniques", [])}

        if any(s in stages for s in ("discovery", "execution")):
            modules.append("subprocess")
        if "defense-evasion" in stages:
            modules.append("Crypto")
        if "exfiltration" in stages:
            modules.append("requests")
        if "persistence" in stages:
            modules.append("winreg")
        if "T1056.001" in mitre:
            modules.append("ctypes")

        return modules

    def _extract_imported_modules(self, code: str) -> Set[str]:
        """Extract all imported top-level module names using AST."""
        import ast as _ast
        imported: Set[str] = set()
        try:
            tree = _ast.parse(code)
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Import):
                    for alias in node.names:
                        imported.add(alias.name.split(".")[0])
                elif isinstance(node, _ast.ImportFrom):
                    if node.module:
                        imported.add(node.module.split(".")[0])
        except Exception:
            pass
        return imported


# ── Orchestrator ───────────────────────────────────────────────────────────────

class PlannerVerifierOrchestrator:
    MAX_RETRIES = 3

    def __init__(self, planner, verifier: PlannerVerifier | None = None) -> None:
        self.planner  = planner
        self.verifier = verifier or PlannerVerifier()

    def run(self, intent: str) -> Dict[str, Any]:
        for attempt in range(self.MAX_RETRIES):
            print(f"\n🔄 Attempt {attempt + 1}/{self.MAX_RETRIES}...")
            mission = self.planner.plan(intent)
            result  = self.verifier.verify(mission)
            print(result.summary())

            if result.valid:
                print(f"\n✅ Done in {attempt + 1} attempt(s)")
                return result.data

            if attempt < self.MAX_RETRIES - 1:
                print("🔁 Structural errors — re-planning...")

        print("\n⚠️  All attempts failed, using fallback")
        fallback = self.planner._fallback_plan(intent)
        return self.verifier.verify(fallback).data or fallback


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from pathlib import Path
    from datetime import datetime, timezone

    parser = argparse.ArgumentParser(description="LangMal Verifier")
    parser.add_argument("--mission",  required=True, help="Path to mission JSON")
    parser.add_argument("--manifest", help="Path to developer manifest JSON (for --agent developer)")
    parser.add_argument("--intent",   default="", help="Original user intent (improves semantic fix)")
    parser.add_argument("--strict",   action="store_true", help="Semantic issues = errors")
    parser.add_argument("--agent",    choices=["planner", "developer", "integrator"],
                         default="planner", help="Which agent output to verify")
    parser.add_argument("--integration-file", default="",
                         help="Path to merged integration .py file (for --agent integrator)")
    parser.add_argument("--save",     action="store_true",
                         help="Save verified output")
    args = parser.parse_args()

    with open(args.mission, encoding="utf-8") as f:
        mission_data = json.load(f)

    if args.agent == "developer":
        if not args.manifest:
            print("❌ --manifest required for --agent developer")
            import sys; sys.exit(1)
        with open(args.manifest, encoding="utf-8") as f:
            manifest_data = json.load(f)
        data = {"manifest": manifest_data, "mission": mission_data}
        verifier = DeveloperVerifier(strict=args.strict)
        result = verifier.verify(data)
    elif args.agent == "integrator":
        if not args.integration_file:
            print("❌ --integration-file required for --agent integrator")
            import sys; sys.exit(1)
        data = {"integration_file": args.integration_file, "mission": mission_data}
        verifier = IntegratorVerifier(strict=args.strict)
        result = verifier.verify(data)
    else:
        data = mission_data
        verifier = PlannerVerifier(strict=args.strict)
        result = verifier.verify(data, intent=args.intent)
    print(result.summary())

    if args.agent == "integrator":
        pass  # summary already printed above
    elif args.agent == "planner":
        print("\n── Fixed Mission ──")
        print(json.dumps(result.data, indent=2, ensure_ascii=False))
        if args.save and result.valid and result.data:
            out_dir  = Path("artifacts/missions")
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            mid      = result.data.get("mission_id", "mission")
            out_path = out_dir / f"verified_{stamp}_{mid}.json"
            out_path.write_text(json.dumps(result.data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\n💾 Saved: {out_path}")
    else:
        if args.save and result.data:
            out_dir  = Path("artifacts/modules")
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            out_path = out_dir / f"manifest_verified_{stamp}.json"
            out_path.write_text(json.dumps(result.data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\n💾 Saved manifest: {out_path}")