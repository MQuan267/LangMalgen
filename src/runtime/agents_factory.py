from __future__ import annotations
import os
from typing import Any, Tuple

def load_agents(stack: str) -> Tuple[Any, Any, Any]:
    """
    Trả về bộ 3 lớp agent (Planner, Developer, Integrator) theo stack.
    """
    s = (stack or os.getenv("AGENT_STACK","gemini")).lower()
    if s == "openai":
        from src.agents.planner_openai import PlannerAgentOpenAI as Planner, PolicyFlags as PlanPolicy
        from src.agents.developer_openai import DeveloperAgentOpenAI as Developer, PolicyFlags as DevPolicy
        from src.agents.integrator_openai import IntegrationAgentOpenAI as Integrator, PolicyFlags as IntPolicy
        return ( (Planner, PlanPolicy), (Developer, DevPolicy), (Integrator, IntPolicy) )
    # default: gemini
    from src.agents.planner_gemini import PlannerAgentGemini as Planner, PolicyFlags as PlanPolicy
    from src.agents.developer_gemini import DeveloperAgentGemini as Developer, PolicyFlags as DevPolicy
    from src.agents.integrator_gemini import IntegrationAgentGemini as Integrator, PolicyFlags as IntPolicy
    return ( (Planner, PlanPolicy), (Developer, DevPolicy), (Integrator, IntPolicy) )

