# Local JSON writer — không egress mạng
import json
from pathlib import Path
from typing import Any, Dict

def LocalJsonWriter(path: str, payload: Dict[str, Any]) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return str(p)
