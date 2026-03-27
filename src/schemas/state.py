from __future__ import annotations
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class Policy(BaseModel):
    network: str = Field("blocked", description="blocked | localhost-only")
    os_introspection: str = Field("mock_only", description="mock_only | none")

class SubTask(BaseModel):
    id: str
    name: str
    desc: str

class State(BaseModel):
    run_id: str
    input_intent: str
    subtasks: List[Dict[str, Any]] = []
    dev_specs: List[Dict[str, Any]] = []
    integration: Dict[str, Any] = {}
    build: Dict[str, Any] = {}
    policy: Policy = Policy()
    logs_path: str = "logs/pipeline.jsonl"
    simulated_ttps: List[str] = []
