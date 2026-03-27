from __future__ import annotations
import os, json, ast
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

STACK_NAME = os.getenv("AGENT_STACK", "openai")
def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
def _prefix(stack: str, agent: str) -> str:
    return f"{stack}_{agent}_{_stamp()}"

PIPELINE_TEMPLATE = '''"""
SAFE integrated pipeline (local-only).
"""
from typing import Dict, Any
import importlib.util, sys
from pathlib import Path

MODULES = [
{module_list}
]

def _load_module(alias: str, file_path: str):
    spec = importlib.util.spec_from_file_location(alias, file_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main() -> Dict[str, Any]:
    state: Dict[str, Any] = {{}}
{calls}
    return state

if __name__ == "__main__":
    out = main()
'''

@dataclass
class PolicyFlags:
    network: str = "allowed"
    os_introspection: str = "allowed"

class IntegrationAgentOpenAI:
    """
    SAFE Integration (OpenAI):
    - Sinh execution plan JSON (chat.completions + json_object).
    - Xuất plan: artifacts/plans/<stack>_integrator_<ts>_plan.json
    - Xuất pipeline: artifacts/latest_bundle/<stack>_integrator_<ts>_pipeline.py
    """
    def __init__(self, policy: PolicyFlags | None = None, stack_name: str = "openai", use_llm_merge: bool = False) -> None:
        load_dotenv()
        self.policy = policy or PolicyFlags(network="allowed", os_introspection="allowed")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.client = OpenAI()
        self.stack = stack_name or STACK_NAME
        self.use_llm_merge = use_llm_merge 

    def _llm_plan(self, dev_specs: List[Dict[str, Any]]) -> Dict[str, Any]:
        system = (
             "You are a SAFE code integration planner. Your job is to create a JSON execution plan to integrate the given modules into a coherent pipeline.\n"
            "The plan must specify:\n"
            "- 'order': the correct order of module execution.\n"
            "- 'data_flow': what data or state is passed between modules.\n"
            "- 'imports': required shared import modules (e.g., adapters).\n"
            "- 'constraints': e.g., network, syscalls, etc.\n"
            "- 'naming': e.g., naming convention, prefixes, snake_case.\n\n"
            "DO NOT include any code. Only output a valid JSON object.\n"
            "Assume modules are real (not mocked) and should be integrated to function correctly end-to-end.\n"
        )
        user = f"Developer dev_specs:\n{json.dumps(dev_specs, ensure_ascii=False)}"
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role":"system","content":system},
                {"role":"user","content":user}
            ],
            response_format={"type":"json_object"},
            temperature=0
        )
        text = resp.choices[0].message.content or "{}"
        try:
            plan = json.loads(text)
        except Exception:
            plan = {}
        if not plan.get("order"):
            plan["order"] = [ str(x.get("subtask_id")) for x in dev_specs ]
        plan.setdefault("imports", ["src.adapters.data_provider","src.adapters.sink"])
        plan.setdefault("constraints", {"network": self.policy.network, "no_syscalls": True})
        plan.setdefault("naming", {"artifact_prefix":"safe_sim","var_case":"snake"})
        return plan

    def _merge_modules_with_llm(self, modules: List[Dict[str, Any]]) -> str:
        merged_prompt_parts = []
        for m in modules:
            if not m.get("path"): continue
            path = Path(m["path"])
            try:
                content = path.read_text(encoding="utf-8")
                merged_prompt_parts.append(f"# File: {path.name}\n{content}\n")
            except Exception as e:
                merged_prompt_parts.append(f"# [ERROR reading {path.name}]: {e}\n")

        prompt = (
            "You are a code integrator AI.\n"
            "You will receive multiple real Python modules. Each module contains valid, runnable code — not mock or stub implementations.\n"
            "Your task is to combine them into a single, valid Python script that can run end-to-end.\n"
            "\n"
            "Requirements:\n"
            "- Merge all modules into one script, clean and syntactically correct.\n"
            "- Ensure all execution logic and data flow are preserved in correct order.\n"
            "- Remove duplicate or unused imports.\n"
            "- Create a single `main()` function that logically calls each step in order.\n"
            "- The final output must be plain Python code only — no markdown, no explanations, no headings.\n"
            "- Do not wrap the output in ```python or any markdown formatting.\n"
            "- Output must be runnable with `python main.py` without syntax or indentation errors.\n"
            "\n"
            "Here are the modules:\n\n"
            + "\n".join(merged_prompt_parts)

        )

        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert Python code integrator."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )

        merged_code = resp.choices[0].message.content or "# Error: no response"
        prefix = _prefix(self.stack, "integrator_llm")
        out_path = Path("artifacts/latest_bundle") / f"{prefix}_pipeline_llm.py"
        out_path.write_text(merged_code, encoding="utf-8")

        # kiểm tra syntax
        try:
            ast.parse(merged_code)
        except SyntaxError as e:
            print(f"[!] LLM-generated code has syntax error: {e}")

        return str(out_path)

    def _emit_pipeline(self, modules: List[Dict[str, Any]], plan: Dict[str, Any]) -> str:
        """
        Đọc nội dung các module thật, bóc phần thân hàm `run()`,
        bỏ toàn bộ indent cũ và gộp thành 1 pipeline duy nhất chạy được.
        """
        id2mod = {str(m["subtask_id"]): m["path"] for m in modules if "subtask_id" in m and "path" in m}
        order = [sid for sid in (plan.get("order") or []) if sid in id2mod] or list(id2mod.keys())

        final_code_parts = [
            '"""SAFE unified pipeline (integrated code)."""\n',
            "from typing import Dict, Any\n",
            "import os, json, sys, time\n\n",
            "def main() -> Dict[str, Any]:\n",
            "    state: Dict[str, Any] = {}\n\n",
        ]

        for i, sid in enumerate(order, 1):
            path = id2mod[sid]
            try:
                content = Path(path).read_text(encoding="utf-8")
            except Exception as e:
                content = f"# [ERROR] Cannot read {path}: {e}\n"

            run_body = []
            inside_run = False
            for line in content.splitlines():
                if line.strip().startswith("def run("):
                    inside_run = True
                    continue
                if inside_run:
                    # Dừng nếu ra khỏi hàm run
                    if line.strip().startswith("def ") and not line.strip().startswith("def run("):
                        break
                    run_body.append(line)

            # ✅ Loại bỏ indent cũ hoàn toàn
            cleaned = [l.lstrip() for l in run_body if l.strip()]

            final_code_parts.append(f"    # ---- Module {sid}: {path} ----\n")
            for l in cleaned:
                final_code_parts.append("    " + l + "\n")
            final_code_parts.append(f"    print('[+] Done module {sid}')\n\n")

        final_code_parts.append("    return state\n\n")
        final_code_parts.append("if __name__ == '__main__':\n")
        final_code_parts.append("    out = main()\n")
        final_code_parts.append("    print('\\n✅ Pipeline finished.')\n")

        code = "".join(final_code_parts)
        out_dir = Path('artifacts/latest_bundle')
        out_dir.mkdir(parents=True, exist_ok=True)
        prefix = _prefix(self.stack, "integrator")
        fp = out_dir / f"{prefix}_pipeline.py"
        fp.write_text(code, encoding="utf-8")

        # ✅ Kiểm tra cú pháp
        try:
            ast.parse(code)
        except SyntaxError as e:
            print(f"[!] Syntax error in merged pipeline: {e}")

        return str(fp)



    def integrate(self, run_id: str, dev_specs: List[Dict[str, Any]], modules: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        if self.use_llm_merge:
            pipeline_path = self._merge_modules_with_llm(modules or [])
            return {
                "agent":"code_integration",
                "run_id":run_id,
                "plan": None,
                "plan_path": None,
                "pipeline_path": pipeline_path,
                "ts_utc":datetime.now(timezone.utc).isoformat()
            }

        # ✅ Nếu không dùng LLM, vẫn tạo plan và pipeline truyền thống
        plan = self._llm_plan(dev_specs)
        plans_dir = Path("artifacts/plans"); plans_dir.mkdir(parents=True, exist_ok=True)
        plan_name = f"{_prefix(self.stack, 'integrator')}_plan.json"
        plan_path = plans_dir / plan_name
        plan_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")

        pipeline_path = self._emit_pipeline(modules or [], plan)
        return {
            "agent":"code_integration",
            "run_id":run_id,
            "plan":plan,
            "plan_path": str(plan_path),
            "pipeline_path":pipeline_path,
            "ts_utc":datetime.now(timezone.utc).isoformat()
        }
