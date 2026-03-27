#!/usr/bin/env bash
set -euo pipefail

fix_planner() {
python - "$@" <<'PY'
from pathlib import Path
p = Path("src/agents/planner_openai.py")
s = p.read_text(encoding="utf-8")

needle = "def _llm_subtasks(self, intent: str) -> List[SubTask]:"
start = s.find(needle)
if start == -1:
    print("[planner] skip: function not found"); exit(0)
end = s.find("\n    def ", start+1)
if end == -1: end = len(s)

block = f'''
    def _llm_subtasks(self, intent: str) -> List[SubTask]:
        system = (
            "You are a SAFE Task Planner for a defensive simulation. "
            "Decompose the user's intent into atomic, harmless subtasks. "
            "No real OS calls, no outbound network; use safe/local-only behaviors. "
            "Return ONLY JSON with key 'subtasks'."
        )
        user = (
            f"Intent: {intent}\\n"
            f"Policy: network={{self.policy.network}}, os_introspection={{self.policy.os_introspection}}\\n"
            "Schema: {\\"subtasks\\": [{\\"id\\": \\"...\\", \\"name\\": \\"...\\", \\"type\\": \\"...\\", \\"desc\\": \\"...\\"}]}\\n"
            "3-5 items."
        )
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {{"role":"system","content":system}},
                {{"role":"user","content":user}},
            ],
            response_format={{"type":"json_object"}},
            temperature=0
        )
        text = (resp.choices[0].message.content or "{{}}")
        try:
            data = json.loads(text)
        except Exception:
            data = {{}}
        items = data.get("subtasks", []) if isinstance(data, dict) else []
        if not items:
            items = [
                {{"id":"st1","name":"collect_os_env","type":"collect_os_env_safe","desc":"Collect benign OS/env info (static/sample)."}},
                {{"id":"st2","name":"list_processes","type":"list_processes_safe","desc":"List processes from sample dataset."}},
                {{"id":"st3","name":"persist_output","type":"persist_local_json","desc":"Write combined result to local JSON."}},
            ]
        return [SubTask(**{{k:str(v) for k,v in it.items()}}) for it in items[:5]]
'''
s2 = s[:start] + needle + block.split(needle,1)[1] + s[end:]
p.write_text(s2, encoding="utf-8")
print("✓ patched planner_openai.py")
PY
}

fix_developer() {
python - "$@" <<'PY'
from pathlib import Path
p = Path("src/agents/developer_openai.py")
s = p.read_text(encoding="utf-8")

needle = "def _llm_specs(self, subtasks: List[Dict[str, Any]]) -> List[DevSpec]:"
start = s.find(needle)
if start == -1:
    print("[developer] skip: function not found"); exit(0)
end = s.find("\n    def ", start+1)
if end == -1: end = len(s)

block = f'''
    def _llm_specs(self, subtasks: List[Dict[str, Any]]) -> List[DevSpec]:
        system = (
            "You are a SAFE developer. For EACH subtask produce a harmless spec JSON:\\n"
            "- providers allowed: adapters.data_provider.MockHostInfo | MockUserInfo | MockProcessList | MockNetConfig (or null for persist step)\\n"
            "- sink: adapters.sink.LocalJsonWriter ; path under artifacts/latest_bundle/output.json\\n"
            "No code/commands/URLs/system calls.\\n"
            "Return ONLY JSON with key 'dev_specs'."
        )
        user = f"Subtasks JSON:\\n{{json.dumps(subtasks, ensure_ascii=False)}}"
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {{"role":"system","content":system}},
                {{"role":"user","content":user}}
            ],
            response_format={{"type":"json_object"}},
            temperature=0
        )
        text = (resp.choices[0].message.content or "{{}}")
        try:
            data = json.loads(text)
        except Exception:
            data = {{}}
        items = data.get("dev_specs", []) if isinstance(data, dict) else []
        if not items:
            for st in subtasks:
                t = (st.get("type") or "").lower()
                if "process" in t: provider = "adapters.data_provider.MockProcessList"; fields=["pid","name","user"]
                elif "net" in t:   provider = "adapters.data_provider.MockNetConfig";  fields=["iface","ip","gateway"]
                elif "user" in (st.get("name","").lower()): provider = "adapters.data_provider.MockUserInfo"; fields=["username","uid"]
                else: provider = "adapters.data_provider.MockHostInfo"; fields=["platform","arch","ram_mb"]
                items.append({{
                    "subtask_id": st.get("id",""),
                    "spec": {{"provider":provider,"fields":fields,"sink":"adapters.sink.LocalJsonWriter","path":"artifacts/latest_bundle/output.json","note":"SAFE fallback"}}
                }})
        return [DevSpec(subtask_id=str(it["subtask_id"]), spec=it["spec"]) for it in items]
'''
s2 = s[:start] + needle + block.split(needle,1)[1] + s[end:]
p.write_text(s2, encoding="utf-8")
print("✓ patched developer_openai.py")
PY
}

fix_integrator() {
python - "$@" <<'PY'
from pathlib import Path
p = Path("src/agents/integrator_openai.py")
s = p.read_text(encoding="utf-8")

needle = "def _llm_plan(self, dev_specs: List[Dict[str, Any]]) -> Dict[str, Any]:"
start = s.find(needle)
if start == -1:
    print("[integrator] skip: function not found"); exit(0)
end = s.find("\n    def ", start+1)
if end == -1: end = len(s)

block = f'''
    def _llm_plan(self, dev_specs: List[Dict[str, Any]]) -> Dict[str, Any]:
        system = (
            "You are a SAFE code integration planner. Produce ONLY an execution plan JSON. "
            "Keys: order, data_flow, imports, constraints, naming. No code."
        )
        user = f"Developer dev_specs:\\n{{json.dumps(dev_specs, ensure_ascii=False)}}"
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {{"role":"system","content":system}},
                {{"role":"user","content":user}}
            ],
            response_format={{"type":"json_object"}},
            temperature=0
        )
        text = (resp.choices[0].message.content or "{{}}")
        try:
            plan = json.loads(text)
        except Exception:
            plan = {{}}
        if not plan.get("order"):
            plan["order"] = [ str(x.get("subtask_id")) for x in dev_specs ]
        plan.setdefault("imports", ["src.adapters.data_provider","src.adapters.sink"])
        plan.setdefault("constraints", {{"network": self.policy.network, "no_syscalls": True}})
        plan.setdefault("naming", {"artifact_prefix":"safe_sim","var_case":"snake"})
        return plan
'''
s2 = s[:start] + needle + block.split(needle,1)[1] + s[end:]
p.write_text(s2, encoding="utf-8")
print("✓ patched integrator_openai.py")
PY
}

fix_planner
fix_developer
fix_integrator
echo "✓ All OpenAI agents switched to Chat Completions + JSON object."
