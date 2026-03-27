from __future__ import annotations
import json, os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any

from dotenv import load_dotenv
from google import genai

@dataclass
class PolicyFlags:
    network: str = "blocked"            # blocked | localhost-only
    os_introspection: str = "mock_only" # mock_only | none

@dataclass
class SubTask:
    id: str
    name: str
    type: str
    desc: str

class PlannerAgentGemini:
    """
    SAFE Planner dùng Gemini (Developer API) để đề xuất subtasks BENIGN.
    - Không syscall, không egress; chỉ mock providers + local JSON sink.
    - Đầu ra: subtasks (list) + task_map (dict) cho downstream agents.
    """
    def __init__(self, policy: PolicyFlags | None = None) -> None:
        load_dotenv()
        self.policy = policy or PolicyFlags()
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("Missing GOOGLE_API_KEY")
        # Dùng model hợp lệ với key của bạn (đã test): ví dụ "gemini-1.5-flash-latest" hoặc "gemini-2.5-flash"
        self.model = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash-latest")
        self.client = genai.Client(api_key=api_key)

    def _llm_subtasks(self, intent: str) -> List[SubTask]:
        system = (
            "You are a SAFE Task Planner for a defensive simulation. "
            "Decompose the user's intent into a sequence of ATOMIC, harmless subtasks. "
            "Allowed task types ONLY:\n"
            "  - collect_os_env_mock: benign mock of OS/env info\n"
            "  - list_processes_mock: benign mock of process listing\n"
            "  - list_net_config_mock: benign mock of net configuration\n"
            "  - persist_local_json: write combined result to a local JSON file (no network)\n"
            "Constraints:\n"
            "  - NO real OS/system calls, NO outbound network, NO URLs.\n"
            "Return STRICT JSON object:\n"
            '{\"subtasks\":[{\"id\":\"st1\",\"name\":\"...\",\"type\":\"collect_os_env_mock|list_processes_mock|list_net_config_mock|persist_local_json\",\"desc\":\"...\"}, ...]} '
            "with 3-5 items. Keep IDs unique and stable like st1, st2, st3."
        )
        user = (
            f"Intent: {intent}\n"
            f"Policy: network={self.policy.network}, os_introspection={self.policy.os_introspection}\n"
            "Goal: produce a structured list compatible with downstream Developer/Integration agents."
        )

        resp = self.client.models.generate_content(
            model=self.model,
            contents=[system, user],
            config={"response_mime_type": "application/json"}
        )
        content = resp.text or "{}"
        data = json.loads(content)
        items = data.get("subtasks", [])

        subtasks: List[SubTask] = []
        for i, st in enumerate(items[:5], 1):
            sid  = str(st.get("id")   or f"st{i}")
            name = str(st.get("name") or "task")
            typ  = str(st.get("type") or "collect_os_env_mock")
            desc = str(st.get("desc") or "benign mock subtask")
            # Chuẩn hoá type
            allowed = {"collect_os_env_mock","list_processes_mock","list_net_config_mock","persist_local_json"}
            if typ not in allowed:
                # map heuristics
                low = (name + " " + desc).lower()
                if "process" in low:
                    typ = "list_processes_mock"
                elif "net" in low or "network" in low:
                    typ = "list_net_config_mock"
                elif "persist" in low or "save" in low or "write" in low:
                    typ = "persist_local_json"
                else:
                    typ = "collect_os_env_mock"
            subtasks.append(SubTask(id=sid, name=name, type=typ, desc=desc))

        # Fallback an toàn tối thiểu nếu LLM trả rỗng
        if not subtasks:
            subtasks = [
                SubTask("st1","collect_os_env","collect_os_env_mock","Collect benign mock OS/env info"),
                SubTask("st2","list_processes","list_processes_mock","List processes (mock)"),
                SubTask("st3","list_network_config","list_net_config_mock","List network config (mock)"),
                SubTask("st4","persist_output","persist_local_json","Write combined result to local JSON"),
            ]
        return subtasks

    def plan(self, input_intent: str) -> Dict[str, Any]:
        simulated_ttps = ["T1082(simulated)", "T1087(simulated)", "T1041(simulated)"]
        subtasks = self._llm_subtasks(input_intent)

        # Xây task_map có cấu trúc cho downstream
        task_map: Dict[str, Dict[str, Any]] = {}
        for st in subtasks:
            task_map[st.name] = {
                "id":   st.id,
                "type": st.type,
                "desc": st.desc,
            }

        return {
            "subtasks": [asdict(s) for s in subtasks],
            "task_map": task_map,
            "simulated_ttps": simulated_ttps,
            "policy_flags": asdict(self.policy),
            "ts_utc": datetime.now(timezone.utc).isoformat()
        }

