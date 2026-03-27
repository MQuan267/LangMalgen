from __future__ import annotations
import os, json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from openai import OpenAI
import time

@dataclass
class PolicyFlags:
    network: str = "allowed"
    os_introspection: str = "no mock"

@dataclass
class SubTask:
    id: str
    name: str
    type: str
    desc: str

STACK_NAME = os.getenv("AGENT_STACK", "openai")

VALID_TYPES = {
    "recon", "initial-access", "execution", "privilege-escalation", 
    "persistence", "defense-evasion", "exfiltration", "lateral-movement",
    "credential-access", "discovery"
}

ATTACK_CHAIN_ORDER = [
    "recon", "initial-access", "execution", "discovery", "credential-access",
    "privilege-escalation", "defense-evasion", "persistence", 
    "lateral-movement", "exfiltration"
]

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

def _prefix(stack: str, agent: str) -> str:
    return f"{stack}_{agent}_{_stamp()}"

class PlannerAgentOpenAI:
    """Optimized Planner - Reduced token usage"""
    
    def __init__(self, policy: PolicyFlags | None = None, stack_name: str = "openai") -> None:
        load_dotenv()
        self.policy = policy or PolicyFlags()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.client = OpenAI()
        self.stack = stack_name or STACK_NAME

    def _detect_target_os(self, intent: str) -> str:
        """Detect target OS from intent"""
        intent_lower = intent.lower()
        windows_kw = ["windows", "ntlm", "token", "system", "registry", "powershell"]
        linux_kw = ["linux", "dirty pipe", "sudo", "kernel", "bash", "elf"]
        
        w_score = sum(1 for kw in windows_kw if kw in intent_lower)
        l_score = sum(1 for kw in linux_kw if kw in intent_lower)
        
        return "Windows" if w_score > l_score else "Linux" if l_score > w_score else "Unknown"

    def _build_system_prompt(self) -> str:
        """Compact system prompt - heavily optimized for tokens"""
        return (
             "Break attack intent into subtasks. CRITICAL: Follow LOGICAL TEMPORAL ORDER.\n"
            "Data collection → Data processing → Data transmission\n"
            "Discovery/Recon tasks MUST come BEFORE execution/exfiltration.\n"
            "NEVER put data preparation before data collection.\n\n"
            
            "Valid types: recon,initial-access,execution,privilege-escalation,persistence,defense-evasion,exfiltration,lateral-movement,credential-access,discovery\n"
            "Be specific with techniques/tools. Match OS.\n\n"
            
            "BAD: Prepare data → Collect data → Send data ❌\n"
            "GOOD: Collect data → Prepare data → Send data ✅\n\n"
            
            "Example:\n"
            'Intent: "Steal SYSTEM token on Windows"\n'
            '{"subtasks":[{"id":"1","name":"Check Privileges","type":"discovery","desc":"Run whoami /priv for SeImpersonate"},{"id":"2","name":"Token Theft","type":"privilege-escalation","desc":"Steal SYSTEM token via RPCSS"}]}\n\n'
            "Return ONLY JSON with subtasks array."
        )

    def _validate_subtask(self, item: dict) -> Optional[SubTask]:
        """Validate subtask"""
        try:
            if not all(k in item for k in ["id", "name", "type", "desc"]):
                return None
            
            task_type = str(item["type"]).lower().strip()
            if task_type not in VALID_TYPES:
                type_map = {
                    "reconnaissance": "recon", "privesc": "privilege-escalation",
                    "exploit": "execution", "maintain": "persistence", 
                    "evasion": "defense-evasion", "collect": "exfiltration"
                }
                task_type = type_map.get(task_type, "execution")
            
            return SubTask(
                id=str(item["id"]),
                name=str(item["name"]),
                type=task_type,
                desc=str(item["desc"])
            )
        except Exception:
            return None

    def _post_process_plan(self, subtasks: List[SubTask]) -> List[SubTask]:
        """Sort by attack chain order"""
        for idx, task in enumerate(subtasks, start=1):
            task.id = str(idx)
    
        return subtasks

    def _fallback_plan(self, intent: str, target_os: str) -> List[SubTask]:
        """Generic fallback plan"""
        return [
            SubTask("1", "System Discovery", "discovery", 
                   f"Gather {target_os} info: OS version, security controls, privileges"),
            SubTask("2", "Capability Check", "execution",
                   "Verify tools, permissions, network access"),
            SubTask("3", "Execute Objective", "execution",
                   f"Main goal: {intent[:80]}")
        ]

    def _llm_subtasks(self, intent: str, max_retries: int = 3) -> List[SubTask]:
        """Generate subtasks with retry and rate limit handling"""
        target_os = self._detect_target_os(intent)
        system = self._build_system_prompt()
        
        # Compact user prompt
        user = f"Intent: {intent}\nOS: {target_os}\n{'{\"subtasks\":[...]}'}"
        
        for attempt in range(max_retries):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=800  # Reduced from 1500
                )
                
                text = (resp.choices[0].message.content or "{}").strip()
                
                # Clean markdown
                for marker in ["```json", "```"]:
                    text = text.replace(marker, "")
                text = text.strip()
                
                data = json.loads(text)
                items = data.get("subtasks", [])
                
                if not isinstance(items, list):
                    raise ValueError("Invalid subtasks format")
                
                validated = [s for s in (self._validate_subtask(i) for i in items) if s]
                
                if validated:
                    return self._post_process_plan(validated)[:5]
                
                print(f"Attempt {attempt + 1}: No valid subtasks")
                
            except Exception as e:
                print(f"Attempt {attempt + 1}: {type(e).__name__} - {str(e)[:100]}")
                
                # Handle rate limits with longer backoff
                if "rate_limit" in str(e).lower() or "429" in str(e):
                    wait_time = 30 * (2 ** attempt)  # 30s, 60s, 120s
                    print(f"Rate limited. Waiting {wait_time}s...")
                    if attempt < max_retries - 1:
                        time.sleep(wait_time)
                    else:
                        break
                elif attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        
        print(f"Using fallback plan")
        return self._fallback_plan(intent, target_os)

    def plan(self, input_intent: str) -> Dict[str, Any]:
        """Generate plan"""
        subtasks = self._llm_subtasks(input_intent)
        task_map = {s.name: {"id": s.id, "type": s.type, "desc": s.desc} for s in subtasks}
        
        out = {
            "subtasks": [asdict(s) for s in subtasks],
            "task_map": task_map,
            "target_os": self._detect_target_os(input_intent),
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "simulated_ttps": [s.type for s in subtasks],
            "model_used": self.model
        }
        
        out_dir = Path("artifacts/plans")
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{_prefix(self.stack, 'planner')}_plan.json"
        fpath = out_dir / fname
        fpath.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        out["plan_path"] = str(fpath)
        
        return out


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Optimized OpenAI Planner")
    parser.add_argument("--intent", required=True, help="Attack intent")
    parser.add_argument("--policy-os", default="mock_only", choices=["mock_only", "none"])
    parser.add_argument("--policy-network", default="blocked", 
                       choices=["blocked", "localhost-only", "full"])
    args = parser.parse_args()

    agent = PlannerAgentOpenAI(
        policy=PolicyFlags(
            network=args.policy_network,
            os_introspection=args.policy_os
        )
    )

    output = agent.plan(args.intent)
    print(json.dumps(output, indent=2, ensure_ascii=False))