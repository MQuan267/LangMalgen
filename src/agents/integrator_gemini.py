from __future__ import annotations
import json, os, ast
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path

from dotenv import load_dotenv
from google import genai

PIPELINE_TEMPLATE = '''"""
SAFE integrated pipeline.
This script stitches SAFE modules (mock-only) into a coherent flow.
"""
from typing import Dict, Any

{imports}

def main() -> Dict[str, Any]:
    state: Dict[str, Any] = {{}}
{calls}
    return state

if __name__ == "__main__":
    out = main()
    # Optional: print or write combined result
    # print(out)
'''

@dataclass
class PolicyFlags:
    network: str = "blocked"            # blocked | localhost-only
    os_introspection: str = "mock_only" # mock_only | none

class IntegrationAgentGemini:
    """
    SAFE Code Integration:
      - Nhận dev_specs + modules từ Developer.
      - Sinh execution plan: order, data_flow, imports, constraints, naming (LLM).
      - Ghép các module thành pipeline.py (hợp lệ cú pháp).
    """
    def __init__(self, policy: PolicyFlags | None = None) -> None:
        load_dotenv()
        self.policy = policy or PolicyFlags()
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("Missing GOOGLE_API_KEY")
        self.model = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash-latest")
        self.client = genai.Client(api_key=api_key)

    # ---------- LLM: tạo plan JSON ----------
    def _llm_plan(self, dev_specs: List[Dict[str, Any]]) -> Dict[str, Any]:
        system = (
            "You are a SAFE code integration planner for a defensive simulation. "
            "Produce ONLY a harmless execution plan JSON. No code. No commands. "
            "All providers must be adapters.data_provider.Mock*, sink must be adapters.sink.LocalJsonWriter. "
            "Return STRICT JSON object with keys:\n"
            "{\n"
            '  "order": ["subtask_id", ...],\n'
            '  "data_flow": { "st1.output": ["st3.input.host"], "st2.output": ["st3.input.user"] },\n'
            '  "imports": ["adapters.data_provider","adapters.sink"],\n'
            '  "constraints": {"network":"blocked|localhost-only","no_syscalls":true},\n'
            '  "naming": {"artifact_prefix":"safe_sim","var_case":"snake"}\n'
            "}\n"
        )
        user = (
            f"Policy: network={self.policy.network}, os_introspection={self.policy.os_introspection}\n"
            f"Developer dev_specs JSON:\n{json.dumps(dev_specs, ensure_ascii=False)}\n"
            "Constraints: mock-only; local JSON sink; produce a sensible order and data_flow mapping."
        )
        resp = self.client.models.generate_content(
            model=self.model,
            contents=[system, user],
            config={"response_mime_type": "application/json"}
        )
        text = resp.text or "{}"
        data = json.loads(text)

        # Fallbacks an toàn
        data.setdefault("imports", ["adapters.data_provider","adapters.sink"])
        data.setdefault("constraints", {"network": self.policy.network, "no_syscalls": True})
        data.setdefault("naming", {"artifact_prefix":"safe_sim","var_case":"snake"})
        if not data.get("order"):
            data["order"] = [ str(x.get("subtask_id")) for x in dev_specs ]
        if not data.get("data_flow"):
            df = {}
            ids = [str(x.get("subtask_id")) for x in dev_specs]
            if len(ids) >= 3:
                df[f"{ids[0]}.output"] = [f"{ids[-1]}.input.host"]
                df[f"{ids[1]}.output"] = [f"{ids[-1]}.input.user"]
            data["data_flow"] = df
        return data

    # ---------- Emit pipeline.py từ modules + plan ----------
    def _emit_pipeline(self, modules: List[Dict[str, Any]], plan: Dict[str, Any]) -> str:
        # map subtask_id -> module path
        id2mod = {str(m["subtask_id"]): m["path"] for m in modules if "subtask_id" in m and "path" in m}
        order = [str(x) for x in plan.get("order", []) if str(x) in id2mod] or [str(m["subtask_id"]) for m in modules]

        # tạo import alias an toàn (de-dup)
        imports_lines: List[str] = []
        alias_names: Dict[str, str] = {}
        seen_mods: set[str] = set()

        for idx, sid in enumerate(order, 1):
            rel = Path(id2mod[sid]).with_suffix("")      # artifacts/modules/st1_xxx
            mod_path = str(rel).replace(os.sep, ".")     # chuẩn hoá 'a/b/c' -> 'a.b.c'
            if mod_path not in seen_mods:
                seen_mods.add(mod_path)
                alias = f"mod_{idx}"
                alias_names[sid] = alias
                imports_lines.append(f"import {mod_path} as {alias}")
            else:
                # nếu module đã seen, vẫn cần alias_names cho sid hiện tại
                alias_names[sid] = next(a for k,a in alias_names.items() if k in alias_names and id2mod.get(k, "").replace(os.sep,".") == mod_path)

        # tạo trình tự gọi run()
        call_lines: List[str] = []
        for sid in order:
            alias = alias_names[sid]
            call_lines.append(f"    part = {alias}.run(state)")
            call_lines.append( "    if isinstance(part, dict):")
            call_lines.append( "        state.update(part)")

        code = PIPELINE_TEMPLATE.format(
            imports="\n".join(imports_lines),
            calls="\n".join(call_lines)
        )
        out_dir = Path("artifacts/latest_bundle")
        out_dir.mkdir(parents=True, exist_ok=True)
        fp = out_dir / "pipeline.py"
        fp.write_text(code, encoding="utf-8")
        return str(fp)

    # ---------- Validate cú pháp pipeline ----------
    def _validate_pipeline(self, file_path: str) -> Dict[str, Any]:
        try:
            src = Path(file_path).read_text(encoding="utf-8")
            ast.parse(src)  # chỉ validate cú pháp
            return {"ok": True, "error": None}
        except SyntaxError as e:
            return {"ok": False, "error": f"SyntaxError: {e}"}
        except Exception as e:
            return {"ok": False, "error": f"Error: {e}"}

    # ---------- Public API ----------
    def integrate(self, run_id: str, dev_specs: List[Dict[str, Any]], modules: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        plan = self._llm_plan(dev_specs)
        pipeline_path = self._emit_pipeline(modules or [], plan)
        check = self._validate_pipeline(pipeline_path)
        now = datetime.now(timezone.utc).isoformat()

        return {
            "agent": "code_integration",
            "run_id": run_id,
            "plan": plan,
            "pipeline_path": pipeline_path,
            "syntax_check": check,   # {ok:bool, error:str|None}
            "ts_utc": now
        }

