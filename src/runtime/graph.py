# path: src/runtime/graph.py
from __future__ import annotations
import os, importlib
from langgraph.graph import StateGraph, END

def _load_nodes():
    """
    Chọn bộ nodes theo biến môi trường AGENT_STACK (openai|gemini).
    Fallback về openai nếu gemini không import được.
    """
    stack = os.getenv("AGENT_STACK", "openai").lower()
    mod_name = "src.runtime.nodes_openai" if stack == "openai" else "src.runtime.nodes_gemini"
    try:
        return importlib.import_module(mod_name)
    except Exception:
        # fallback an toàn
        return importlib.import_module("src.runtime.nodes_openai")

def build_graph():
    nodes = _load_nodes()
    g = StateGraph(dict)  # dùng dict cho skeleton
    g.add_node("planner", nodes.planner_node)
    g.add_node("developer", nodes.developer_node)
    g.add_node("integrator", nodes.integration_node)
    g.add_node("builder", nodes.builder_node)
    g.set_entry_point("planner")
    g.add_edge("planner", "developer")
    g.add_edge("developer", "integrator")
    g.add_edge("integrator", "builder")
    g.add_edge("builder", END)
    return g.compile()

