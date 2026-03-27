from __future__ import annotations
import os, json, time, ast, traceback
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

# ── Helpers ────────────────────────────────────────────────────────────────────

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")


def _safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in s.lower().replace("-", "_"))


# ── Validation result ──────────────────────────────────────────────────────────

from dataclasses import dataclass, field as dc_field

@dataclass
class ValidationResult:
    valid:    bool
    errors:   List[str] = dc_field(default_factory=list)
    warnings: List[str] = dc_field(default_factory=list)
    metrics:  Dict[str, Any] = dc_field(default_factory=dict)


# ── Developer Agent ────────────────────────────────────────────────────────────

class DeveloperAgent:
    """
    Reads a verified mission JSON (execution_graph + dataflow),
    generates one Python module per task with correct input/output contracts.
    """

    DANGEROUS = {"eval(", "exec(", "compile(", "__import__("}

    def __init__(self) -> None:
        load_dotenv()
        self.model      = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.client     = OpenAI()
        self.max_retry  = 3
        self.out_dir    = Path("artifacts/modules")
        self.out_dir.mkdir(parents=True, exist_ok=True)

    # ── LLM ───────────────────────────────────────────────────────────────────

    def _llm(self, system: str, user: str) -> str:
        for attempt in range(self.max_retry):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    temperature=0.2,
                    max_tokens=2500,
                )
                return resp.choices[0].message.content or ""
            except RateLimitError:
                if attempt == self.max_retry - 1: raise
                wait = 5 * (attempt + 1)
                print(f"  ⏳ Rate limit, retry in {wait}s...")
                time.sleep(wait)
        raise RuntimeError("LLM max retries exceeded")

    # ── Code generation ───────────────────────────────────────────────────────

    def _build_system_prompt(self) -> str:
        return """You are a senior Python developer generating production modules for a Windows malware research framework.

CONTRACT (non-negotiable):
  def run(input_data: dict = None) -> dict
  Return: {'success': bool, 'data': dict, 'metadata': {'task_id': str, 'execution_time': float}}

CODING RULES:
  - Implement the REAL logic — no stubs, no placeholders
  - ONE try/except around the main block
  - Use the input_contract fields from input_data when available
  - Output fields must match output_contract exactly
  - Use subprocess.run(timeout=...) for shell commands
  - Use requests with timeout= for HTTP calls
  - NO eval(), exec(), compile(), __import__()
  - NO excessive defensive checks — trust the caller
  - Clear variable names, comments only for complex parts
  - Type hints on function signatures

REQUIRED STRUCTURE:
#!/usr/bin/env python3
\"\"\"<task intent>\"\"\"
import sys, json, time
from typing import Dict, Any
# ... other imports

def run(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    input_data = input_data or {}
    try:
        # Access upstream fields DIRECTLY — input_data is a flat dict:
        # e.g. ciphertext = input_data.get('ciphertext')   ← CORRECT
        # e.g. input_data.get('EncryptedPayload', {}).get('ciphertext')  ← WRONG
        ...
        return {'success': True, 'data': result,
                'metadata': {'task_id': 'TASK_ID', 'execution_time': time.time()-start}}
    except Exception as e:
        return {'success': False, 'error': f'{type(e).__name__}: {e}',
                'metadata': {'task_id': 'TASK_ID', 'execution_time': time.time()-start}}

if __name__ == '__main__':
    result = run()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get('success') else 1)

Output ONLY Python code. No markdown fences."""

    def _build_user_prompt(
        self,
        task:      Dict[str, Any],
        upstream:  Dict[str, Dict],   # task_id → task dict for input sources
    ) -> str:
        tid   = task["task_id"]
        stage = task.get("stage", "")
        intent = task.get("intent", "")
        goal   = task.get("behavioral_goal", "")
        mitre  = task.get("mitre_techniques", [])

        ic = task.get("input_contract")
        oc = task.get("output_contract", {})
        ec = task.get("error_contract", {})

        # Describe what input_data will contain
        input_desc = "None (this task takes no inputs)"
        if ic and ic.get("sources"):
            parts = []
            for src in ic["sources"]:
                src_task = upstream.get(src["task_id"], {})
                src_fields = (src_task.get("output_contract") or {}).get("fields", {})
                parts.append(
                    f"  From {src['task_id']} ({src['schema']}): "
                    + ", ".join(f"{k}: {v}" for k, v in src_fields.items())
                )
            input_desc = "\n".join(parts)

        output_fields = oc.get("fields", {})
        required_out  = ec.get("required_fields", [])
        fallback      = ec.get("fallback_value")
        on_failure    = ec.get("on_failure", "return_partial")

        return f"""Task ID    : {tid}
Stage      : {stage}
Intent     : {intent}
Goal       : {goal}
MITRE      : {', '.join(mitre) if mitre else 'N/A'}

INPUT DATA (available in input_data dict):
{input_desc}

OUTPUT CONTRACT (your 'data' dict must contain these fields):
{json.dumps(output_fields, indent=2)}

Required output fields (must always be present): {required_out}
On failure behavior : {on_failure}
Fallback value      : {fallback}

IMPLEMENTATION NOTES:
- Replace all 'TASK_ID' placeholders with '{tid}'
- input_data is a FLAT dict — access fields directly:
  ✅ CORRECT: input_data.get('ciphertext')
  ❌ WRONG:   input_data.get('EncryptedPayload', {{}}).get('ciphertext')
- Your data dict MUST include ALL these output fields: {list(output_fields.keys())}
  Every field in output_contract must appear in the returned 'data' dict
- Encryption tasks (defense-evasion stage with AES/cipher): ALWAYS include the encryption key in output so downstream tasks can decrypt
- For Windows-specific operations, use subprocess or ctypes as appropriate
- Stage '{stage}' context: {"use subprocess for shell commands" if stage in ("discovery","execution") else "use Python crypto libs" if stage == "defense-evasion" else "use requests/ftplib/smtplib" if stage == "exfiltration" else "use winreg/schtasks" if stage == "persistence" else "implement accordingly"}

FIELD TYPE CODING RULES (based on output_contract field types):
- 'string'      → plain str value
- 'string_json' → already serialized JSON string; use json.dumps(data) to produce it
                  downstream will .encode('utf-8') directly — NEVER call json.dumps() on a string_json field
- 'bytes'       → raw bytes; use .hex() or base64.b64encode() for transmission
- 'array'       → Python list
- 'dict'        → Python dict (not serialized)
- 'boolean'     → bool (True/False)
- 'integer'     → int

CRITICAL: If you receive a 'string_json' field as INPUT, use field.encode('utf-8') directly to get bytes.
          NEVER wrap it with json.dumps() again — it is already a JSON string.

Generate the complete Python module now."""

    def _generate(self, task: Dict, upstream: Dict[str, Dict]) -> str:
        system = self._build_system_prompt()
        user   = self._build_user_prompt(task, upstream)
        code   = self._llm(system, user).strip()

        # Strip markdown fences if present
        for fence in ("```python", "```"):
            code = code.replace(fence, "")
        code = code.strip()

        # Detect refusal
        if len(code) < 150 or any(
            r in code[:300].lower()
            for r in ("i'm sorry", "i can't", "i cannot", "i apologize", "i'm unable")
        ):
            print("  ⚠️  LLM refused — using fallback stub")
            return self._fallback(task)

        # Ensure shebang
        if not code.startswith("#!"):
            code = f"#!/usr/bin/env python3\n\"\"\"{task.get('intent','')}\"\"\"\n\n{code}"

        return code

    def _fallback(self, task: Dict) -> str:
        tid   = task["task_id"]
        intent = task.get("intent", "Unknown")
        oc_fields = (task.get("output_contract") or {}).get("fields", {})
        stub_data = {k: f"<{v}>" for k, v in oc_fields.items()}

        return f'''#!/usr/bin/env python3
"""{intent} — STUB (generation failed)"""
import sys, json, time
from typing import Dict, Any

def run(input_data: Dict[str, Any] = None) -> Dict[str, Any]:
    start = time.time()
    try:
        # TODO: implement real logic
        result = {json.dumps(stub_data, indent=8)}
        return {{"success": True, "data": result,
                "metadata": {{"task_id": "{tid}", "execution_time": time.time()-start, "is_stub": True}}}}
    except Exception as e:
        return {{"success": False, "error": f"{{type(e).__name__}}: {{e}}",
                "metadata": {{"task_id": "{tid}", "execution_time": time.time()-start}}}}

if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("success") else 1)
'''

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate(self, code: str, task: Dict, filepath: Path) -> ValidationResult:
        errors:   List[str] = []
        warnings: List[str] = []
        metrics:  Dict[str, Any] = {}

        # 1. Syntax
        try:
            compile(code, str(filepath), "exec")
            metrics["syntax_valid"] = True
        except SyntaxError as e:
            errors.append(f"SyntaxError line {e.lineno}: {e.msg}")
            return ValidationResult(False, errors, warnings, metrics)

        # 2. AST checks
        tree = ast.parse(code)
        fn_names    = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
        has_main    = any(
            isinstance(n, ast.If) and any(
                isinstance(c, ast.Name) and c.id == "__name__"
                for c in ast.walk(n.test)
            )
            for n in ast.walk(tree)
        )

        if "run" not in fn_names:
            errors.append("Missing run() function")
        if not has_main:
            warnings.append("Missing if __name__ == '__main__' block")

        # 3. Return contract
        if "'success'" not in code and '"success"' not in code:
            errors.append("return dict missing 'success' key")
        if "return {" not in code and "return{" not in code:
            errors.append("No dict return statement found")

        # 4. Required output fields
        required = (task.get("error_contract") or {}).get("required_fields", [])
        for field in required:
            if f'"{field}"' not in code and f"'{field}'" not in code:
                warnings.append(f"Required output field '{field}' not found in code")

        # 5. Dangerous patterns
        for pat in self.DANGEROUS:
            if pat in code:
                errors.append(f"Dangerous pattern: {pat}")

        # 6. task_id placeholder
        tid = task["task_id"]
        if "TASK_ID" in code:
            warnings.append(f"Unreplaced TASK_ID placeholder (should be '{tid}')")

        # 7. Metrics
        lines = code.splitlines()
        metrics.update({
            "lines":        len(lines),
            "has_main":     has_main,
            "has_typing":   "->" in code or ": Dict" in code,
            "has_timeout":  "timeout=" in code,
            "has_try":      "try:" in code,
            "import_count": sum(1 for l in lines if l.strip().startswith("import") or l.strip().startswith("from")),
        })

        # Quality score
        score = 10 - len(errors) * 3
        if has_main:          score += 1
        if metrics["has_typing"]:   score += 1
        if metrics["has_timeout"]:  score += 1
        metrics["quality"] = max(0, min(10, score))

        return ValidationResult(len(errors) == 0, errors, warnings, metrics)

    # ── Main entry ────────────────────────────────────────────────────────────

    def develop(self, mission_path: str) -> Dict[str, Any]:
        with open(mission_path, encoding="utf-8") as f:
            mission = json.load(f)

        tasks    = mission.get("execution_graph", [])
        dataflow = mission.get("dataflow", [])

        if not tasks:
            raise ValueError("No tasks in execution_graph")

        # Build task map for upstream lookup
        task_map: Dict[str, Dict] = {t["task_id"]: t for t in tasks}

        # Build upstream map: task_id → {src_task_id → task_dict}
        upstream_map: Dict[str, Dict[str, Dict]] = {t["task_id"]: {} for t in tasks}
        for edge in dataflow:
            src = edge.get("from_task", "")
            dst = edge.get("to_task", "")
            if src in task_map and dst in upstream_map:
                upstream_map[dst][src] = task_map[src]

        mid = mission.get("mission_id", "unknown")
        print(f"\n{'='*65}")
        print(f"  DEVELOPER AGENT — {mid} ({len(tasks)} tasks)")
        print(f"{'='*65}\n")

        results   = []
        n_success = 0
        stamp     = _stamp()

        for idx, task in enumerate(tasks, 1):
            tid    = task["task_id"]
            intent = task.get("intent", f"task_{idx}")
            stage  = task.get("stage", "execution")

            print(f"  [{idx}/{len(tasks)}] {tid} · {intent}...", end=" ", flush=True)

            try:
                code = self._generate(task, upstream_map[tid])

                fname    = f"{stamp}_{idx:02d}_{tid}_{_safe_name(stage)}.py"
                filepath = self.out_dir / fname

                vr = self._validate(code, task, filepath)

                if not vr.valid:
                    print(f"❌ validation failed")
                    for e in vr.errors:
                        print(f"       ✗ {e}")
                    results.append({"task_id": tid, "intent": intent,
                                    "status": "failed", "errors": vr.errors})
                    continue

                filepath.write_text(code, encoding="utf-8")
                filepath.chmod(0o755)

                q   = vr.metrics.get("quality", 0)
                loc = vr.metrics.get("lines", 0)
                print(f"✅  Q:{q}/10  {loc}L"
                      + ("  ⚠ " + vr.warnings[0][:40] if vr.warnings else ""))

                n_success += 1
                results.append({
                    "task_id":  tid,
                    "intent":   intent,
                    "stage":    stage,
                    "status":   "success",
                    "path":     str(filepath),
                    "metrics":  vr.metrics,
                    "warnings": vr.warnings,
                })

            except Exception as e:
                print(f"❌ {e}")
                results.append({"task_id": tid, "intent": intent,
                                 "status": "error", "error": str(e),
                                 "traceback": traceback.format_exc()[-400:]})

        # Summary
        total = len(tasks)
        print(f"\n{'='*65}")
        print(f"  ✅ {n_success}/{total} modules generated successfully")

        ok = [r for r in results if r["status"] == "success"]
        if ok:
            avg_q   = sum(r["metrics"]["quality"] for r in ok) / len(ok)
            avg_loc = sum(r["metrics"]["lines"]   for r in ok) / len(ok)
            print(f"  📊 avg quality {avg_q:.1f}/10  |  avg {avg_loc:.0f} lines")
        print(f"{'='*65}\n")

        # Save manifest
        manifest = {
            "agent":      "DeveloperAgent",
            "mission_id": mid,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "total":      total,
            "successful": n_success,
            "failed":     total - n_success,
            "modules":    results,
        }
        mfile = self.out_dir / f"manifest_{stamp}.json"
        mfile.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"  📄 Manifest: {mfile}")

        return manifest


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LangMal Developer Agent")
    parser.add_argument("--mission", required=True,
                        help="Path to verified mission JSON (from verifier output)")
    args = parser.parse_args()

    agent = DeveloperAgent()
    agent.develop(args.mission)