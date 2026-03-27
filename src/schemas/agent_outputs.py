from __future__ import annotations
from typing import List, Dict, Any
from pydantic import BaseModel

class PlannerOutput(BaseModel):
    agent: str = "planner"
    run_id: str
    input_intent: str
    subtasks: List[Dict[str, Any]]
    simulated_ttps: List[str]
    policy_flags: Dict[str, Any]
    ts_utc: str

class DeveloperOutput(BaseModel):
    agent: str = "developer"
    run_id: str
    dev_specs: List[Dict[str, Any]]
    ts_utc: str

class IntegrationOutput(BaseModel):
    agent: str = "code_integration"
    run_id: str
    plan: Dict[str, Any]
    ts_utc: str

class BuilderOutput(BaseModel):
    agent: str = "builder"
    run_id: str
    manifest: Dict[str, Any]
    ts_utc: str
