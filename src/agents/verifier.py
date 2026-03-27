from __future__ import annotations
import json
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
- MITRE: match techniques to the SPECIFIC behavior, not just the stage; use sub-techniques when applicable
- Exfiltration via email → T1048.003 or T1071.003 (NOT T1041)
- WiFi credential extraction → T1552.001; browser history → T1217 or T1539
- Fix data_schema in dataflow edges to match the actual output_contract.schema of the source task
- Do not invent stage names outside the valid list
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

    def verify(self, data: Dict[str, Any]) -> VerifyResult:
        mission = deepcopy(data)
        errors, warnings, fixed = [], [], []

        # ── Phase 1 ───────────────────────────────────────────────────────────
        print("  [Phase 1] Structural checks...")
        self._structural_check(mission, errors, warnings, fixed)
        if errors:
            return VerifyResult(False, errors, warnings, fixed, mission)

        # ── Phase 2 ───────────────────────────────────────────────────────────
        print("  [Phase 2] LLM semantic fix...")
        mission, sem_fixed, sem_warn = self._llm_semantic_fix(mission)
        fixed.extend(sem_fixed); warnings.extend(sem_warn)

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
        self, mission: dict
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

        prompt = (
            "You are a senior malware analyst and Windows red team expert.\n"
            "Review this mission plan and return a fully corrected version.\n\n"
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
            "6. Add output_contract fields only if downstream tasks genuinely need them\n\n"
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


# ── DeveloperVerifier (placeholder) ───────────────────────────────────────────

class DeveloperVerifier(BaseVerifier):
    def verify(self, data: Dict[str, Any]) -> VerifyResult:
        raise NotImplementedError("DeveloperVerifier — coming after Developer Agent")


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

    parser = argparse.ArgumentParser(description="LangMal Mission Verifier")
    parser.add_argument("--mission", required=True, help="Path to mission JSON")
    parser.add_argument("--strict",  action="store_true", help="Semantic issues = errors")
    parser.add_argument("--agent",   choices=["planner", "developer"],
                        default="planner", help="Which agent output to verify")
    parser.add_argument("--save",    action="store_true",
                        help="Save verified mission to artifacts/missions/verified_*.json")
    args = parser.parse_args()

    with open(args.mission, encoding="utf-8") as f:
        data = json.load(f)

    verifier = {"planner": PlannerVerifier, "developer": DeveloperVerifier}[args.agent](
        strict=args.strict
    )
    result = verifier.verify(data)

    print(result.summary())
    print("\n── Fixed Mission ──")
    print(json.dumps(result.data, indent=2, ensure_ascii=False))

    if args.save and result.valid and result.data:
        from datetime import datetime, timezone
        from pathlib import Path
        out_dir  = Path("artifacts/missions")
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        mid      = result.data.get("mission_id", "mission")
        out_path = out_dir / f"verified_{stamp}_{mid}.json"
        out_path.write_text(json.dumps(result.data, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n💾 Saved: {out_path}")