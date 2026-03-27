from src.schemas.state import State, Policy

def test_state_defaults():
    s = State(run_id="r1", input_intent="demo")
    assert s.policy.network in ("blocked","localhost-only")
    assert s.logs_path.endswith(".jsonl")
