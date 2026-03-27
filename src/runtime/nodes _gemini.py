from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from src.agents.planner_gemini import PlannerAgentGemini, PolicyFlags as PlanPolicy
from src.agents.developer_gemini import DeveloperAgentGemini, PolicyFlags as DevPolicy
from src.agents.integrator_gemini import IntegrationAgentGemini, PolicyFlags as IntPolicy
# tái dùng builder openai nhưng set stack_name="gemini"
from src.agents.builder_openai import ExecutableBuilder, BuildConfig

def _append_jsonl(path: str, record: Dict[str, Any]) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

# ---- Planner
def planner_node(state: Dict[str, Any]) -> Dict[str, Any]:
    policy = state.get("policy", {}) or {}
    agent = PlannerAgentGemini(
        PlanPolicy(
            network=policy.get("network","blocked"),
            os_introspection=policy.get("os_introspection","mock_only")
        )
    )
    plan = agent.plan(state["input_intent"])
    _append_jsonl(state.get("logs_path","logs/pipeline.jsonl"), {"agent":"planner", **plan})

    new = dict(state)
    new["subtasks"] = plan["subtasks"]
    new["task_map"] = plan.get("task_map", {})
    new["simulated_ttps"] = plan.get("simulated_ttps", [])
    return new

# ---- Developer
def developer_node(state: Dict[str, Any]) -> Dict[str, Any]:
    policy = state.get("policy", {}) or {}
    subtasks = state.get("subtasks", []) or []
    agent = DeveloperAgentGemini(
        DevPolicy(
            network=policy.get("network","blocked"),
            os_introspection=policy.get("os_introspection","mock_only")
        )
    )
    out = agent.develop(state["run_id"], subtasks)
    _append_jsonl(state.get("logs_path","logs/pipeline.jsonl"), {"agent":"developer", **out})

    new = dict(state)
    new["dev_specs"] = out["dev_specs"]
    new["modules"] = out.get("modules", [])
    return new

# ---- Integration
def integration_node(state: Dict[str, Any]) -> Dict[str, Any]:
    policy = state.get("policy", {}) or {}
    dev_specs = state.get("dev_specs", []) or []
    modules = state.get("modules", []) or []
    agent = IntegrationAgentGemini(
        IntPolicy(
            network=policy.get("network","blocked"),
            os_introspection=policy.get("os_introspection","mock_only")
        )
    )
    out = agent.integrate(state["run_id"], dev_specs, modules)
    _append_jsonl(state.get("logs_path","logs/pipeline.jsonl"), {"agent":"code_integration", **out})

    new = dict(state)
    new["integration"] = out["plan"]
    new["pipeline_path"] = out["pipeline_path"]
    return new

# ---- Builder
def builder_node(state: Dict[str, Any]) -> Dict[str, Any]:
    run_id = state["run_id"]
    pipeline_path = state.get("pipeline_path", "artifacts/latest_bundle/pipeline.py")
    plan = state.get("integration", {})
    modules = state.get("modules", [])

    # reuse OpenAI builder but label outputs with "gemini"
    builder = ExecutableBuilder(BuildConfig(), stack_name="gemini")
    out = builder.build(run_id, pipeline_path, plan=plan, modules=modules)
    _append_jsonl(state.get("logs_path","logs/pipeline.jsonl"), out)

    new = dict(state)
    new["manifest_path"] = out["manifest_path"]
    new["executable"] = out["executable"]
    new["build_sha256"] = out["sha256"]
    new["build_size_bytes"] = out["size_bytes"]
    return new

