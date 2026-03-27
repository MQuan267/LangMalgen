from __future__ import annotations
import json, os, sys, hashlib, shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from dotenv import load_dotenv

@dataclass
class BuildConfig:
    onefile: bool = True
    name_prefix: str = "malgen_safe"
    dist_dir: str = "artifacts/dist"
    work_dir: str = "artifacts/build"
    spec_dir: str = "artifacts/build"

class ExecutableBuilder:
    """
    SAFE Executable Builder
    - Nhận pipeline_path (từ Integration).
    - Build bằng PyInstaller (--onefile).
    - Xuất manifest.json, sha256, size và đường dẫn executable.
    """
    def __init__(self, cfg: BuildConfig | None = None) -> None:
        load_dotenv()
        self.cfg = cfg or BuildConfig()

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
        # Chạy PyInstaller programmatically
        try:
            import PyInstaller.__main__ as pyimain
        except Exception as e:
            raise RuntimeError(
                "PyInstaller chưa được cài. Hãy chạy: pip install pyinstaller"
            ) from e

        args = [
            str(entry),
            "--name", name,
            "--distpath", self.cfg.dist_dir,
            "--workpath", self.cfg.work_dir,
            "--specpath", self.cfg.spec_dir,
            "--clean",
            "--noconfirm",
            "--paths", str(Path(".").resolve()),   # thêm project root vào PYTHONPATH
        ]
        if self.cfg.onefile:
            args.append("--onefile")

        # Lưu ý: PyInstaller sẽ SystemExit(0/!=0). Bọc để ra lỗi có ý nghĩa.
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

        # Tạo tên file executable
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        exe_name = f"{self.cfg.name_prefix}_{run_id[:8]}_{ts}"

        # Build
        self._pyinstaller_run(entry, exe_name)

        # Xác định đường dẫn output
        exe_path = Path(self.cfg.dist_dir) / exe_name
        if sys.platform.startswith("win"):
            exe_path = exe_path.with_suffix(".exe")

        if not exe_path.exists():
            # PyInstaller có thể tạo thư mục thay vì onefile (nếu lỗi)
            # thử tìm file tên tương tự trong dist_dir
            candidates = list(Path(self.cfg.dist_dir).glob(f"{exe_name}*"))
            if candidates:
                exe_path = candidates[0]
            else:
                raise RuntimeError("Build complete nhưng không tìm thấy artifact trong dist.")

        # Tính size & hash
        size = exe_path.stat().st_size
        sha256 = self._hash_sha256(exe_path)

        # Ghi manifest
        manifest = {
            "agent": "builder",
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
            "safety_notes": "This artifact is a SAFE mock simulation. No network egress. No syscalls beyond Python runtime."
        }
        manifest_path = Path("artifacts/latest_bundle/manifest.json")
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

