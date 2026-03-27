from __future__ import annotations
import argparse, json, os, sys
from datetime import datetime, timezone

from dotenv import load_dotenv  # <-- NEW
from src.runtime.graph import build_graph

def main():
    load_dotenv()  # <-- NEW: auto-load .env at startup

    ap = argparse.ArgumentParser(description="malgen-safe runner (OpenAI/Gemini)")
    ap.add_argument("--intent", required=True, help="Input intent (natural language)")
    ap.add_argument("--run-id", default=None, help="Run identifier")
    ap.add_argument("--logs", default="logs/pipeline.jsonl", help="Path to JSONL log file")
    ap.add_argument("--policy-network", default="blocked", choices=["blocked","localhost-only"])
    ap.add_argument("--policy-os", default="mock_only", choices=["mock_only","none"])

    ap.add_argument("--agent-stack", default=None, choices=["openai","gemini"],
                    help="Chọn bộ agent: openai | gemini (mặc định đọc AGENT_STACK từ .env)")
    ap.add_argument("--start-from", default="planner",
                    choices=["planner","developer","integrator","builder"],
                    help="Bắt đầu chạy từ node nào (debug).")
    ap.add_argument("--stop-after", default="builder",
                    choices=["planner","developer","integrator","builder"],
                    help="Dừng sau node nào (debug).")

    args = ap.parse_args()

    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    agent_stack = args.agent_stack or os.getenv("AGENT_STACK", "openai")
    # set env so graph.py can import the correct nodes module
    os.environ["AGENT_STACK"] = agent_stack  # <-- NEW

    if agent_stack == "openai" and not os.getenv("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY chưa có trong môi trường.", file=sys.stderr)
    if agent_stack == "gemini" and not os.getenv("GOOGLE_API_KEY"):
        print("[!] GOOGLE_API_KEY chưa có trong môi trường.", file=sys.stderr)

    state = {
        "run_id": run_id,
        "input_intent": args.intent,
        "subtasks": [],
        "dev_specs": [],
        "modules": [],
        "integration": {},
        "pipeline_path": "artifacts/latest_bundle/pipeline.py",
        "build": {},
        "policy": {"network": args.policy_network, "os_introspection": args.policy_os},
        "logs_path": args.logs,
        "simulated_ttps": [],
        "agent_stack": agent_stack,
        "start_from": args.start_from,
        "stop_after": args.stop_after,
    }

    graph = build_graph()
    final_state = graph.invoke(state)

    out = {
        "run_id": final_state.get("run_id"),
        "agent_stack": agent_stack,
        "start_from": args.start_from,
        "stop_after": args.stop_after,
        "logs_path": final_state.get("logs_path"),
    }
    if args.stop_after in ("planner","developer","integrator","builder"):
        out["subtasks"] = final_state.get("subtasks", [])
    if args.stop_after in ("developer","integrator","builder"):
        out["dev_specs"] = final_state.get("dev_specs", [])
        out["modules"] = final_state.get("modules", [])
    if args.stop_after in ("integrator","builder"):
        out["integration_plan"] = final_state.get("integration", {})
        out["pipeline_path"] = final_state.get("pipeline_path")
    if args.stop_after == "builder":
        out["manifest_path"] = final_state.get("manifest_path")
        out["executable"] = final_state.get("executable")
        out["build_sha256"] = final_state.get("build_sha256")
        out["build_size_bytes"] = final_state.get("build_size_bytes")

    print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()

