# path: src/agents/builder_openai.py
from __future__ import annotations
import json, os, sys, hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from dotenv import load_dotenv

# ---------- naming helpers (avoid overwrite) ----------
STACK_NAME = os.getenv("AGENT_STACK", "openai")

def _stamp() -> str:
    # UTC timestamp, microsecond precision để tránh đè file
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")

def _prefix(stack: str, agent: str) -> str:
    return f"{stack}_{agent}_{_stamp()}"

@dataclass
class BuildConfig:
    onefile: bool = True
    name_prefix: str = "malgen_safe"  # không còn dùng cho tên output; giữ để tương thích
    dist_dir: str = "artifacts/dist"
    work_dir: str = "artifacts/build"
    spec_dir: str = "artifacts/build"

class ExecutableBuilder:
    """
    SAFE Executable Builder (PyInstaller)
    - Build pipeline.py thành executable onefile
    - Xuất manifest + checksum
    - Đặt tên theo: <stack>_builder_<timestamp>
    """
    def __init__(self, cfg: BuildConfig | None = None, stack_name: str = "openai") -> None:
        load_dotenv()
        self.cfg = cfg or BuildConfig()
        self.stack = stack_name or STACK_NAME

    def _hash_sha256(self, file_path: Path) -> str:
        h = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _ensure_paths(self) -> None:
        Path(self.cfg.dist_dir).mkdir(parents=True, exist_ok=True)
        Path(self.cfg.work_dir).mkdir(parents=True, exist_ok=True)
        Path(self.cfg.spec_dir).mkdir(parents=True, exist_ok=True)

    def _pyinstaller_run(self, entry: Path, name: str) -> None:
        try:
            import PyInstaller.__main__ as pyimain
        except Exception as e:
            raise RuntimeError("PyInstaller chưa được cài. Hãy: pip install pyinstaller") from e

        args = [
            str(entry),
            "--name", name,
            "--distpath", self.cfg.dist_dir,
            "--workpath", self.cfg.work_dir,
            "--specpath", self.cfg.spec_dir,
            "--clean",
            "--noconfirm",
            "--paths", str(Path(".").resolve()),
        ]
        if self.cfg.onefile:
            args.append("--onefile")

        try:
            pyimain.run(args)
        except SystemExit as se:
            code = getattr(se, "code", 0)
            if code not in (0, None):
                raise RuntimeError(f"PyInstaller failed with exit code {code}") from se

    def build(self, run_id: str, pipeline_path: str, plan: Dict[str, Any] | None = None,
              modules: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        self._ensure_paths()

        entry = Path(pipeline_path)
        if not entry.exists():
            raise FileNotFoundError(f"pipeline_path not found: {entry}")

        # tên KHÔNG đè: <stack>_builder_<timestamp>
        prefix = _prefix(self.stack, "builder")
        exe_name = f"{prefix}"

        # chạy pyinstaller
        self._pyinstaller_run(entry, exe_name)

        exe_path = Path(self.cfg.dist_dir) / exe_name
        if sys.platform.startswith("win"):
            exe_path = exe_path.with_suffix(".exe")

        # fallback nếu PyInstaller thêm hậu tố
        if not exe_path.exists():
            candidates = list(Path(self.cfg.dist_dir).glob(f"{exe_name}*"))
            if candidates:
                exe_path = candidates[0]
            else:
                raise RuntimeError("Build complete nhưng không tìm thấy artifact trong dist.")

        size = exe_path.stat().st_size
        sha256 = self._hash_sha256(exe_path)

        manifest = {
            "agent": "builder",
            "stack": self.stack,
            "run_id": run_id,
            "built_at_utc": datetime.now(timezone.utc).isoformat(),
            "entry": str(entry),
            "executable": str(exe_path),
            "sha256": sha256,
            "size_bytes": size,
            "plan": plan or {},
            "modules": modules or [],
            "tool": "pyinstaller",
            "options": {
                "onefile": self.cfg.onefile,
                "dist_dir": self.cfg.dist_dir,
                "work_dir": self.cfg.work_dir,
                "spec_dir": self.cfg.spec_dir,
            },
            "safety_notes": "Fully integrated real modules. Not a mock simulation. Runtime behavior depends on actual module logic."
        }

        # manifest KHÔNG đè: artifacts/latest_bundle/<stack>_builder_<ts>_manifest.json
        manifest_path = Path("artifacts/latest_bundle") / f"{prefix}_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

        return {
            "agent": "builder",
            "run_id": run_id,
            "manifest_path": str(manifest_path),
            "executable": str(exe_path),
            "sha256": sha256,
            "size_bytes": size,
            "ts_utc": datetime.now(timezone.utc).isoformat()
        }

