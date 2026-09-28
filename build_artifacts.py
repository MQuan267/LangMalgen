#!/usr/bin/env python3
"""
build_artifacts.py
Build all caseXX_artifact.py files into .exe using PyInstaller.

Expected input:
    results/with_verifier/per_case/case01_artifact.py
    results/no_verifier/per_case/case01_artifact.py

Output:
    artifacts/build/with_verifier/case01_with_verifier.exe
    artifacts/build/no_verifier/case01_no_verifier.exe

Usage:
    python build_artifacts.py
    python build_artifacts.py --results-dir results_deepseek
    python build_artifacts.py --mode with_verifier
    python build_artifacts.py --mode no_verifier
    python build_artifacts.py --clean
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(".").resolve()

MODES = ["with_verifier", "no_verifier"]

BUILD_ROOT = ROOT / "artifacts" / "build"

PYINSTALLER_WORK_ROOT = ROOT / "artifacts" / "pyinstaller_work"
PYINSTALLER_SPEC_ROOT = ROOT / "artifacts" / "pyinstaller_spec"


def check_pyinstaller() -> None:
    try:
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        print("PyInstaller chua duoc cai.")
        print("Cai bang lenh: pip install pyinstaller")
        sys.exit(1)


def build_one(py_file: Path, mode: str, results_dir: str) -> bool:
    case_id  = py_file.name.replace("_artifact.py", "")
    build_tag = Path(results_dir).name  # "results" hoặc "results_deepseek"
    suffix   = "_deep" if "deepseek" in build_tag else ""
    exe_name = f"{case_id}_{mode}{suffix}"
    dist_dir  = BUILD_ROOT / build_tag / mode
    work_dir  = PYINSTALLER_WORK_ROOT / build_tag / mode / case_id
    spec_dir  = PYINSTALLER_SPEC_ROOT / build_tag / mode

    dist_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)

    output_exe = dist_dir / f"{exe_name}.exe"

    print(f"\nBuilding {py_file.name}")
    print(f"   -> {output_exe}")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--noconfirm", "--clean",
        "--distpath", str(dist_dir),
        "--workpath", str(work_dir),
        "--specpath", str(spec_dir),
        "--name", exe_name,
        str(py_file),
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="ignore",
    )

    if result.returncode != 0:
        print(f"FAILED: {py_file.name}")
        print(result.stderr[-1000:])
        return False

    if output_exe.exists():
        size_mb = output_exe.stat().st_size / 1_048_576
        print(f"OK: {output_exe.name}  ({size_mb:.1f} MB)")
        return True

    print(f"WARN: build finished but EXE not found: {output_exe}")
    return False


def build_mode(mode: str, results_dir: str) -> tuple[int, int]:
    per_case_dir = ROOT / results_dir / mode / "per_case"

    if not per_case_dir.exists():
        print(f"WARN: Not found: {per_case_dir}")
        return 0, 0

    py_files = sorted(per_case_dir.glob("case*_artifact.py"))

    if not py_files:
        print(f"WARN: No case*_artifact.py in: {per_case_dir}")
        return 0, 0

    print(f"\n{'=' * 65}")
    print(f"MODE: {mode}  |  source: {results_dir}")
    print(f"Found {len(py_files)} artifact files")
    print(f"{'=' * 65}")

    ok = fail = 0
    for py_file in py_files:
        if build_one(py_file, mode, results_dir):
            ok += 1
        else:
            fail += 1
    return ok, fail


def clean_build_dirs() -> None:
    for path in [BUILD_ROOT, PYINSTALLER_WORK_ROOT, PYINSTALLER_SPEC_ROOT]:
        if path.exists():
            print(f"Removing {path}")
            shutil.rmtree(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build LangMal artifacts into EXE files.")
    parser.add_argument("--mode", choices=["with_verifier", "no_verifier", "all"],
                        default="all")
    parser.add_argument("--results-dir", default="results",
                        help="Root results directory (default: results, use results_deepseek for DeepSeek)")
    parser.add_argument("--clean", action="store_true",
                        help="Clean old build folders before building.")
    args = parser.parse_args()

    check_pyinstaller()

    if args.clean:
        clean_build_dirs()

    modes = MODES if args.mode == "all" else [args.mode]

    total_ok = total_fail = 0
    for mode in modes:
        ok, fail = build_mode(mode, args.results_dir)
        total_ok += ok
        total_fail += fail

    print(f"\n{'=' * 65}")
    print("BUILD SUMMARY")
    print(f"{'=' * 65}")
    print(f"OK     : {total_ok}")
    print(f"Failed : {total_fail}")
    print(f"Output : {BUILD_ROOT}")
    print(f"{'=' * 65}")


if __name__ == "__main__":
    main()