from __future__ import annotations
import os, json, ast, time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Any
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI, RateLimitError

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
        self.max_retries = 3
        self.base_delay = 5

    def _call_with_retry(self, func, *args, **kwargs):
        """Call OpenAI API with retry on rate limit"""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except RateLimitError as e:
                if attempt == self.max_retries - 1:
                    raise
                
                wait_time = self.base_delay
                if "Please try again in" in str(e):
                    try:
                        wait_time = int(str(e).split("try again in ")[1].split("s")[0]) + 1
                    except:
                        wait_time = self.base_delay * (attempt + 1)
                
                print(f"⏳ Rate limit. Waiting {wait_time}s (attempt {attempt+1}/{self.max_retries})...")
                time.sleep(wait_time)
        
        raise Exception("Max retries exceeded")

    def _llm_plan(self, dev_specs: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Optimized: Reduced from ~200 tokens to ~100 tokens
        system = (
            "Integration planner. Create JSON execution plan:\n"
            "{'order':[module_ids],'data_flow':'description','imports':[],'constraints':{},'naming':{}}\n"
            "Assume real modules (not mocks). JSON only, no code."
        )
        
        # Compact spec representation
        spec_summary = [{"id": s.get("subtask_id"), "cat": s.get("spec", {}).get("malware_category")} 
                        for s in dev_specs]
        user = f"Specs:{json.dumps(spec_summary,separators=(',',':'))}"
        
        resp = self._call_with_retry(
            self.client.chat.completions.create,
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
            plan["order"] = [str(x.get("subtask_id")) for x in dev_specs]
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

        # Optimized: Reduced from ~300 tokens to ~150 tokens
        prompt = (
            "Code integrator. Merge Python modules into single runnable script.\n"
            "Requirements:\n"
            "- Preserve all logic and execution order\n"
            "- Remove duplicate imports\n"
            "- Create main() calling each step\n"
            "- Output plain Python only (no markdown, no ```)\n"
            "- Must be syntactically correct\n\n"
            "Modules:\n" + "\n".join(merged_prompt_parts)
        )

        resp = self._call_with_retry(
            self.client.chat.completions.create,
            model=self.model,
            messages=[
                {"role": "system", "content": "Expert Python code integrator."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )

        merged_code = resp.choices[0].message.content or "# Error: no response"
        
        # Strip markdown if LLM includes it anyway
        if merged_code.startswith("```python"):
            merged_code = merged_code.split("```python")[1].split("```")[0].strip()
        elif merged_code.startswith("```"):
            merged_code = merged_code.split("```")[1].split("```")[0].strip()
        
        prefix = _prefix(self.stack, "integrator_llm")
        out_path = Path("artifacts/latest_bundle") / f"{prefix}_pipeline_llm.py"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(merged_code, encoding="utf-8")

        # Syntax check with helpful error
        try:
            ast.parse(merged_code)
            print("✅ LLM-merged code is syntactically valid")
        except SyntaxError as e:
            print(f"⚠️  Syntax error in LLM merge (line {e.lineno}): {e.msg}")
            print(f"    Code saved to: {out_path}")

        return str(out_path)

    def _emit_pipeline(self, modules: List[Dict[str, Any]], plan: Dict[str, Any]) -> str:
        """
        Read real modules, extract run() body, merge into single pipeline.
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
                    if line.strip().startswith("def ") and not line.strip().startswith("def run("):
                        break
                    run_body.append(line)

            # Remove old indentation completely
            cleaned = [l.lstrip() for l in run_body if l.strip()]

            final_code_parts.append(f"    # ---- Module {sid}: {Path(path).name} ----\n")
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

        # Syntax check
        try:
            ast.parse(code)
            print("✅ Template-based pipeline is syntactically valid")
        except SyntaxError as e:
            print(f"⚠️  Syntax error in pipeline (line {e.lineno}): {e.msg}")

        return str(fp)

    def integrate(self, run_id: str, dev_specs: List[Dict[str, Any]], modules: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        if self.use_llm_merge:
            print("🔧 Using LLM merge mode...")
            pipeline_path = self._merge_modules_with_llm(modules or [])
            return {
                "agent":"code_integration",
                "run_id":run_id,
                "plan": None,
                "plan_path": None,
                "pipeline_path": pipeline_path,
                "ts_utc":datetime.now(timezone.utc).isoformat()
            }

        # Template-based integration
        print("🔧 Using template-based integration...")
        plan = self._llm_plan(dev_specs)
        plans_dir = Path("artifacts/plans")
        plans_dir.mkdir(parents=True, exist_ok=True)
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


# if __name__ == "__main__":
#     import argparse
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--dev-result", required=True, help="Path to developer JSON output")
#     parser.add_argument("--run-id", default="int_run_001")
#     parser.add_argument("--use-llm-merge", action="store_true", help="Use LLM to merge (vs template)")
#     args = parser.parse_args()

#     with open(args.dev_result, "r") as f:
#         dev_data = json.load(f)
    
#     agent = IntegrationAgentOpenAI(use_llm_merge=args.use_llm_merge)
#     result = agent.integrate(
#         run_id=args.run_id,
#         dev_specs=dev_data.get("dev_specs", []),
#         modules=dev_data.get("modules", [])
#     )
#     print(json.dumps(result, indent=2, ensure_ascii=False))