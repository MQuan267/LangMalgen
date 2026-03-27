#!/usr/bin/env python3
"""
Build executable from integrated pipeline .py file.
Uses PyInstaller — no external builder dependency.

Usage:
    python build_exe.py
    # then enter path when prompted
"""
import os
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def build_exe(pipeline_path: str) -> dict:
    """Build standalone .exe from Python pipeline file using PyInstaller."""
    src = Path(pipeline_path)
    if not src.exists():
        return {"success": False, "error": f"File not found: {pipeline_path}"}

    run_id   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir  = Path("artifacts/builds") / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    exe_name = src.stem  # e.g. ransomware_encrypt_documents

    print(f"\n🔨 Building: {src.name}")
    print(f"   Output  : {out_dir}/")
    print(f"   Exe name: {exe_name}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                        # single exe
        "--distpath", str(out_dir),         # output dir
        "--workpath", str(out_dir / "build"),
        "--specpath", str(out_dir / "spec"),
        "--name", exe_name,
        "--noconfirm",
        "--clean",
        str(src),
    ]

    print(f"\n   Running: {' '.join(cmd[:5])} ...\n")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        exe_path = out_dir / f"{exe_name}.exe"
        if not exe_path.exists():
            # Linux output has no .exe
            exe_path = out_dir / exe_name

        success = exe_path.exists()

        return {
            "success":      success,
            "run_id":       run_id,
            "source":       str(src),
            "exe_path":     str(exe_path) if success else None,
            "exe_size_kb":  round(exe_path.stat().st_size / 1024) if success else None,
            "returncode":   result.returncode,
            "stdout_tail":  result.stdout[-500:] if result.stdout else "",
            "stderr_tail":  result.stderr[-300:] if result.stderr else "",
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "PyInstaller timeout (>120s)"}
    except FileNotFoundError:
        return {
            "success": False,
            "error": "PyInstaller not found. Run: pip install pyinstaller"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    print("═" * 50)
    print("  LangMal — Build Executable")
    print("═" * 50)

    # Interactive path input
    default = "artifacts/integration/malware_latest.py"
    prompt  = f"\nEnter path to integrated .py file\n[default: {default}]: "
    user_input = input(prompt).strip()

    pipeline_path = user_input if user_input else default

    result = build_exe(pipeline_path)

    print("\n" + "─" * 50)
    if result.get("success"):
        print(f"✅ Build successful!")
        print(f"   Run ID  : {result['run_id']}")
        print(f"   Exe     : {result['exe_path']}")
        print(f"   Size    : {result['exe_size_kb']} KB")
    else:
        print(f"❌ Build failed: {result.get('error', 'unknown')}")
        if result.get("stderr_tail"):
            print(f"\nStderr:\n{result['stderr_tail']}")

    return result


if __name__ == "__main__":
    main()