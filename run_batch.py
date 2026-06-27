#!/usr/bin/env python3
"""
run_batch.py – LangMal Batch Runner + Auto Scorer (with Ablation)
==================================================================
Chạy 15 intents qua pipeline, tự động tính điểm TTP P/R/F1.
Hỗ trợ 3 mode:

  --mode with_verifier   (default) Planner → Verifier → Developer → Integrator
  --mode no_verifier               Planner → Developer → Integrator  (ablation)
  --mode compare                   Chạy cả hai, xuất bảng so sánh delta F1

Usage:
    python run_batch.py --benchmark benchmark.json
    python run_batch.py --benchmark benchmark.json --mode no_verifier
    python run_batch.py --benchmark benchmark.json --mode compare
    python run_batch.py --benchmark benchmark.json --ids 1 2 3
    python run_batch.py --benchmark benchmark.json --skip-pipeline   # rescore only

Output (mode=with_verifier):   results/with_verifier/
Output (mode=no_verifier):     results/no_verifier/
Output (mode=compare):         results/with_verifier/ + results/no_verifier/
                                results/ablation_compare.csv
                                results/ablation_compare.json
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Config — sửa các path này nếu folder khác
# ---------------------------------------------------------------------------

MISSIONS_DIR    = Path("artifacts/missions")
VERIFIED_DIR    = Path("artifacts/missions_verified")
MODULES_DIR     = Path("artifacts/modules")
INTEGRATION_DIR = Path("artifacts/integration")

PLANNER_SCRIPT    = "src/agents/plannerv8.py"
VERIFIER_SCRIPT   = "src/agents/verifierv8.py"
DEVELOPER_SCRIPT  = "src/agents/developerv8.py"
INTEGRATOR_SCRIPT = "src/agents/integratorv8.py"

TRAM2_DATASET  = "src/data/tram2.jsonl"
VERIFIER_CACHE = ".verifier_cache"

PRICING = {
    "gpt-4o":       (2.50, 10.00),
    "gpt-4o-mini":  (0.15,  0.60),
    "gpt-4.1":      (2.00,  8.00),
    "gpt-4.1-mini": (0.40,  1.60),
}

# TRAM2 frequency tiers — dựa trên distribution thực tế (36,594 samples, 50 TTPs)
# High  : >= 1000 samples
# Mid   : 300–999 samples
# Low   : < 300 samples
# Not-in-index: T1486, T1485, T1491, T1620, T1049, T1046, T1087.002,
#               T1135, T1134.002, T1078.003, T1115, T1546.003, T1059.001,
#               T1055.002, T1070.001, T1497.001, T1497.003, T1027.002 → 0 samples

HIGH_FREQ: Set[str] = {
    # >= 1000 samples
    "T1027",      # 4955
    "T1140",      # 3438
    "T1059.003",  # 2604
    "T1055",      # 2096
    "T1105",      # 1783
    "T1106",      # 1452
    "T1090",      # 1211
    "T1071.001",  # 1171
}
MID_FREQ: Set[str] = {
    # 300–999 samples
    "T1082",      # 890
    "T1078",      # 868
    "T1053.005",  # 828
    "T1112",      # 768
    "T1003.001",  # 747
    "T1204.002",  # 670
    "T1083",      # 666
    "T1566.001",  # 615
    "T1021.001",  # 612
    "T1047",      # 595
    "T1057",      # 581
    "T1041",      # 576
    "T1070.004",  # 564
    "T1574.002",  # 542
    "T1562.001",  # 537
    "T1036.005",  # 536
    "T1573.001",  # 495
    "T1095",      # 483
    "T1190",      # 469
    "T1547.001",  # 462
    "T1218.011",  # 448
    "T1056.001",  # 417
    "T1016",      # 383
    "T1005",      # 378
    "T1110",      # 375
    "T1570",      # 365
    "T1219",      # 359
    "T1113",      # 341
    "T1543.003",  # 336
    "T1033",      # 318
}
# LOW_FREQ: < 300 samples
LOW_FREQ_EXPLICIT: Set[str] = {
    "T1518.001",  # 233
    "T1548.002",  # 215
    "T1569.002",  # 177
    "T1074.001",  # 175
    "T1012",      # 165
    "T1552.001",  # 147
    "T1564.001",  # 117
    "T1210",      # 108
    "T1484.001",  # 90
    "T1072",      # 90
    "T1068",      # 80
    "T1557.001",  # 63
}
# NOT_IN_INDEX: TTPs hoàn toàn không có trong TRAM2 (0 samples)
# T1486, T1485, T1491, T1620, T1049, T1046, T1087.002, T1135,
# T1134.002, T1078.003, T1115, T1546.003, T1059.001, T1055.002,
# T1070.001, T1497.001, T1497.003, T1027.002
# → Bất kỳ GT label nào thuộc nhóm này đều không thể được verify đúng

OUT_OF_COVERAGE: Set[int] = {}   # #9: T1486/T1485 absent from TRAM2; #11: T1497.* absent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: str, timeout: int = 1800) -> Tuple[int, str, str]:
    import subprocess
    print(f"    $ {cmd[:120]}")
    try:
        r = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        if r.stdout:
            print(r.stdout[:500], end="")
        return r.returncode, r.stdout, r.stderr

    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="ignore")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="ignore")
        msg = f"\n[TIMEOUT] Command timed out after {timeout}s:\n{cmd}\n"
        print(msg)
        return 124, stdout, stderr + msg


def _latest_file(directory: Path, pattern: str) -> Optional[Path]:
    files = sorted(directory.glob(pattern), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def _parse_tokens_json(data: Dict) -> Tuple[int, int]:
    u = data.get("planner_summary", {}).get("token_usage", {})
    return u.get("prompt_tokens", 0), u.get("completion_tokens", 0)


def _parse_tokens_stdout(stdout: str) -> Tuple[int, int]:
    p = re.search(r"prompt\s+:\s+([\d,]+)", stdout)
    c = re.search(r"completion\s+:\s+([\d,]+)", stdout)
    return (
        int(p.group(1).replace(",", "")) if p else 0,
        int(c.group(1).replace(",", "")) if c else 0,
    )


def _cost(prompt: int, completion: int, model: str = "gpt-4o") -> float:
    pp, cp = PRICING.get(model, (0, 0))
    return (prompt / 1_000_000) * pp + (completion / 1_000_000) * cp


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _extract_ttps(mission: Dict, use_planner_only: bool = False) -> List[str]:
    """
    Lấy predicted TTPs từ mission JSON.

    use_planner_only=True  → dùng top-1 mitre_candidates (ablation: no verifier)
    use_planner_only=False → dùng mitre_techniques (sau verifier)
    """
    ttps: List[str] = []
    for task in mission.get("execution_graph", []):
        if not use_planner_only:
            verified = task.get("mitre_techniques") or []
            if verified:
                ttps.extend(t.strip() for t in verified if t.strip())
                continue
        # Fallback: top-1 planner candidate
        for cand in task.get("mitre_candidates") or []:
            tid = cand.get("id", "").strip()
            if tid:
                ttps.append(tid)
                break
    # Deduplicate, preserve order
    seen: Set[str] = set()
    out: List[str] = []
    for t in ttps:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _metrics(predicted: List[str], ground_truth: List[str]) -> Dict[str, Any]:
    pred = set(predicted)
    gt   = set(ground_truth)
    tp   = len(pred & gt)
    fp   = len(pred - gt)
    fn   = len(gt  - pred)
    p    = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    return {
        "precision": round(p,  4),
        "recall":    round(r,  4),
        "f1":        round(f1, 4),
        "tp": tp, "fp": fp, "fn": fn,
    }


def _artifact_check(path: Optional[Path]) -> Dict[str, Any]:
    if not path or not path.exists():
        return {"artifact_valid": False, "reason": "file_not_found", "loc": 0}
    code = path.read_text(encoding="utf-8", errors="ignore")
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {"artifact_valid": False, "syntax_valid": False,
                "reason": str(e), "loc": len(code.splitlines())}
    fns       = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    task_fns  = sorted(f for f in fns if f.startswith("task_"))
    has_main  = "main" in fns
    return {
        "artifact_valid": has_main,
        "syntax_valid":   True,
        "has_main":       has_main,
        "task_functions": task_fns,
        "task_fn_count":  len(task_fns),
        "loc":            len(code.splitlines()),
        "reason":         None if has_main else "missing main()",
    }


def _code_quality(manifest_path: Optional[Path]) -> Dict[str, Any]:
    if not manifest_path or not manifest_path.exists():
        return {}
    manifest   = json.loads(manifest_path.read_text(encoding="utf-8"))
    modules    = manifest.get("modules", [])
    total      = len(modules)
    if total == 0:
        return {}
    successful = [m for m in modules if m.get("status") == "success"]
    q_scores   = [m.get("metrics", {}).get("quality", 0) for m in successful]
    loc_scores = [m.get("metrics", {}).get("lines",   0) for m in successful]
    avg_att    = sum(m.get("generation_attempt", 1) for m in modules) / total
    return {
        "total_modules":      total,
        "successful_modules": len(successful),
        "success_rate":       round(len(successful) / total, 4),
        "avg_quality_score":  round(sum(q_scores)   / len(q_scores)   if q_scores   else 0, 4),
        "avg_loc":            round(sum(loc_scores)  / len(loc_scores) if loc_scores else 0, 1),
        "avg_attempts":       round(avg_att, 2),
    }


def _fallback_rate(mission: Dict) -> Dict[str, Any]:
    reports = mission.get("verifier_task_reports", [])
    if not reports:
        return {"total_tasks": 0, "fallback_tasks": 0, "fallback_rate": 0.0}
    n_fb = sum(1 for r in reports
               if r.get("decision_trace", {}).get("fallback_used"))
    return {
        "total_tasks":    len(reports),
        "fallback_tasks": n_fb,
        "fallback_rate":  round(n_fb / len(reports), 4),
    }


# ---------------------------------------------------------------------------
# Pipeline runners
# ---------------------------------------------------------------------------

def _run_planner(intent: str, case_id: str, per_case_dir: Path,
                 stage_tokens: Dict, errors: List[str]) -> Optional[Path]:
    """Chạy Planner, trả về path mission JSON hoặc None nếu fail."""
    print(f"\n  [1] Planner...")

    # Đảm bảo folder tồn tại trước khi ghi intent file
    per_case_dir.mkdir(parents=True, exist_ok=True)

    # Ghi intent ra file tạm để tránh PowerShell truncate argument dài
    intent_file = per_case_dir / f"{case_id}_intent.txt"
    intent_file.write_text(intent, encoding="utf-8")

    rc, stdout, stderr = _run(
        f'python {PLANNER_SCRIPT} --intent-file "{intent_file}" --out-dir {MISSIONS_DIR}'
    )
    if rc != 0:
        # Ghi full error ra file để debug
        error_log = per_case_dir / f"{case_id}_planner_error.txt"
        error_log.write_text(stderr, encoding="utf-8", errors="ignore")
        print(f"  ❌ Planner failed (full error → {error_log})")
        print(f"  ERROR: {stderr[:500]}")
        errors.append(f"Planner failed: {stderr[:500]}")
        return None

    mission_file = _latest_file(MISSIONS_DIR, "*.json")
    if not mission_file:
        errors.append("Planner: no output JSON")
        return None

    # Lưu copy
    mission_dst = per_case_dir / f"{case_id}_mission.json"
    shutil.copy(mission_file, mission_dst)

    mission_data = json.loads(mission_file.read_text(encoding="utf-8"))
    p, c = _parse_tokens_json(mission_data)
    stage_tokens["planner"] = {"prompt": p, "completion": c, "cost": _cost(p, c)}
    print(f"  ✅ Mission saved  tokens={p+c:,}")
    return mission_file


def _run_verifier(mission_file: Path, case_id: str, per_case_dir: Path,
                  errors: List[str]) -> Optional[Path]:
    """Chạy Verifier, trả về path verified JSON hoặc None nếu fail."""
    print(f"\n  [2] Verifier...")
    rc, stdout, stderr = _run(
        f'python {VERIFIER_SCRIPT} '
        f'--mission "{mission_file}" '
        f'--datasets {TRAM2_DATASET} '
        f'--cache-dir {VERIFIER_CACHE}'
    )
    if rc != 0:
        error_log = per_case_dir / f"{case_id}_verifier_error.txt"
        error_log.write_text(stderr, encoding="utf-8", errors="ignore")
        print(f"  ❌ Verifier failed (full error → {error_log})")
        print(f"  ERROR: {stderr[:800]}")
        errors.append(f"Verifier failed: {stderr[:300]}")
        return None

    verified_file = _latest_file(VERIFIED_DIR, "*_verified.json")
    if not verified_file:
        errors.append("Verifier: no output JSON")
        return None

    verified_dst = per_case_dir / f"{case_id}_verified.json"
    shutil.copy(verified_file, verified_dst)
    print(f"  ✅ Verified saved")
    return verified_file


def _run_developer(mission_file: Path, case_id: str, per_case_dir: Path,
                   stage_tokens: Dict, errors: List[str]) -> Optional[Path]:
    """Chạy Developer, trả về path manifest.json hoặc None."""
    print(f"\n  [3] Developer...")
    rc, stdout, stderr = _run(
        f'python {DEVELOPER_SCRIPT} --mission "{mission_file}"'
    )
    if rc != 0:
        errors.append(f"Developer failed: {stderr[:200]}")
        print(f"  ❌ Developer failed")

    p, c = _parse_tokens_stdout(stdout + stderr)
    stage_tokens["developer"] = {"prompt": p, "completion": c, "cost": _cost(p, c)}

    runtime_dir   = _latest_file(MODULES_DIR, "runtime_*")
    manifest_file = (runtime_dir / "manifest.json") if runtime_dir else None
    if manifest_file and manifest_file.exists():
        shutil.copy(manifest_file, per_case_dir / f"{case_id}_manifest.json")
        print(f"  ✅ Developer  tokens={p+c:,}")
        return manifest_file

    errors.append("Developer: manifest not found")
    return None


def _run_integrator(mission_file: Path, manifest_file: Path,
                    case_id: str, per_case_dir: Path,
                    stage_tokens: Dict, errors: List[str]) -> Optional[Path]:
    """Chạy Integrator, trả về path artifact .py hoặc None."""
    print(f"\n  [4] Integrator...")

    # Ghi nhận timestamp TRƯỚC khi chạy để chỉ lấy file MỚI sinh ra
    run_start = time.time()

    rc, stdout, stderr = _run(
        f'python {INTEGRATOR_SCRIPT} '
        f'--mission "{mission_file}" '
        f'--manifest "{manifest_file}"'
    )
    if rc != 0:
        errors.append(f"Integrator failed: {stderr[:200]}")
        print(f"  ⚠ Integrator failed (continuing)")

    p, c = _parse_tokens_stdout(stdout + stderr)
    stage_tokens["integrator"] = {"prompt": p, "completion": c, "cost": _cost(p, c)}
    print(f"  ✅ Integrator tokens={p+c:,}")

    # Chỉ lấy file .py được tạo SAU khi run bắt đầu (tránh lấy file cũ từ run trước)
    artifact_file = None
    if INTEGRATION_DIR.exists():
        candidates = [
            p for p in INTEGRATION_DIR.glob("*.py")
            if p.exists() and p.stat().st_mtime >= run_start - 2
        ]
        if candidates:
            artifact_file = max(candidates, key=lambda p: p.stat().st_mtime)

    if artifact_file and artifact_file.exists():
        artifact_dst = per_case_dir / f"{case_id}_artifact.py"
        try:
            shutil.copy(artifact_file, artifact_dst)
            return artifact_dst
        except OSError as e:
            errors.append(f"Integrator copy failed: {e}")
            print(f"  ⚠ Could not copy artifact: {e}")
            return None

    errors.append("Integrator: no artifact .py found after run")
    print(f"  ⚠ No artifact generated")
    return None


# ---------------------------------------------------------------------------
# run_one: chạy 1 sample theo mode
# ---------------------------------------------------------------------------

def run_one(
    sample:        Dict,
    per_case_dir:  Path,
    mode:          str  = "with_verifier",  # "with_verifier" | "no_verifier"
    skip_pipeline: bool = False,
) -> Dict[str, Any]:
    """
    Chạy pipeline cho 1 sample.

    mode="with_verifier"  → Planner → Verifier → Developer → Integrator
    mode="no_verifier"    → Planner → Developer → Integrator  (skip Verifier)
    """
    sid     = int(sample["id"])
    intent  = sample["intent"]
    case_id = f"case{sid:02d}"

    print(f"\n{'='*65}")
    print(f"  [{case_id}][{mode}] {intent[:65]}...")
    print(f"{'='*65}")

    per_case_dir.mkdir(parents=True, exist_ok=True)

    # File paths trong per_case_dir
    verified_dst = per_case_dir / f"{case_id}_verified.json"
    manifest_dst = per_case_dir / f"{case_id}_manifest.json"
    artifact_dst = per_case_dir / f"{case_id}_artifact.py"

    stage_tokens: Dict  = {}
    errors:       List  = []
    total_prompt        = 0
    total_completion    = 0
    case_start          = time.time()  # ← bắt đầu tính thời gian

    # ── Skip pipeline: load kết quả cũ và chỉ rescore ───────────────────────
    if skip_pipeline:
        if mode == "with_verifier":
            # with_verifier: load verified JSON, không chạy lại gì
            src = verified_dst
            if not src.exists():
                print(f"  ⚠ Không tìm thấy {src.name}")
                return _build_result(sid, sample, None, None, None,
                                     stage_tokens, errors, 0, 0, mode)
            print(f"  ✅ Rescore từ: {src.name}")

        else:
            # no_verifier: có mission JSON rồi → chạy Developer + Integrator
            mission_src = per_case_dir / f"{case_id}_mission.json"
            if not mission_src.exists():
                print(f"  ⚠ Không tìm thấy {mission_src.name}")
                return _build_result(sid, sample, None, None, None,
                                     stage_tokens, errors, 0, 0, mode)

            # Manifest và artifact đã có chưa?
            if manifest_dst.exists() and artifact_dst.exists():
                print(f"  ✅ Rescore từ: {mission_src.name} (dev+int đã có)")
            else:
                print(f"  ✅ Mission sẵn có: {mission_src.name} → chạy Developer + Integrator")

                # Copy mission sang artifacts/missions để agents tìm được
                import shutil as _sh
                tmp_mission = MISSIONS_DIR / f"{case_id}_noverifier_tmp.json"
                MISSIONS_DIR.mkdir(parents=True, exist_ok=True)
                _sh.copy(mission_src, tmp_mission)

                # Developer
                manifest_file = _run_developer(
                    tmp_mission, case_id, per_case_dir, stage_tokens, errors
                )
                p, c = stage_tokens.get("developer", {}).get("prompt", 0), \
                       stage_tokens.get("developer", {}).get("completion", 0)
                total_prompt += p; total_completion += c

                # Integrator — dùng tmp_mission làm dev_input
                if manifest_file:
                    _run_integrator(tmp_mission, manifest_file,
                                    case_id, per_case_dir,
                                    stage_tokens, errors)
                    p, c = stage_tokens.get("integrator", {}).get("prompt", 0), \
                           stage_tokens.get("integrator", {}).get("completion", 0)
                    total_prompt += p; total_completion += c
                    print(f"  ✅ Developer + Integrator done")
                else:
                    errors.append("Integrator skipped: no manifest")
                    print(f"  ⚠ Integrator skipped")

                # Cleanup tmp file
                try:
                    tmp_mission.unlink()
                except Exception:
                    pass

    else:
        # ── 1. Planner (chạy cả 2 mode) ─────────────────────────────────────
        mission_file = _run_planner(intent, case_id, per_case_dir,
                                    stage_tokens, errors)
        if not mission_file:
            return _build_result(sid, sample, None, None, None,
                                 stage_tokens, errors, 0, 0, mode)
        p, c = stage_tokens["planner"]["prompt"], stage_tokens["planner"]["completion"]
        total_prompt += p; total_completion += c

        # ── 2. Verifier (chỉ mode with_verifier) ────────────────────────────
        if mode == "with_verifier":
            verified_file = _run_verifier(mission_file, case_id, per_case_dir, errors)
            if not verified_file:
                return _build_result(sid, sample, None, None, None,
                                     stage_tokens, errors, total_prompt, total_completion, mode)
            dev_input = verified_file   # Developer nhận verified mission
        else:
            # no_verifier: Developer nhận raw planner mission trực tiếp
            print(f"\n  [2] Verifier → SKIPPED (ablation: no_verifier)")
            dev_input = mission_file

        # ── 3. Developer ─────────────────────────────────────────────────────
        manifest_file = _run_developer(dev_input, case_id, per_case_dir,
                                       stage_tokens, errors)
        p, c = stage_tokens.get("developer", {}).get("prompt", 0), \
               stage_tokens.get("developer", {}).get("completion", 0)
        total_prompt += p; total_completion += c

        # ── 4. Integrator ────────────────────────────────────────────────────
        if manifest_file:
            artifact_path = _run_integrator(dev_input, manifest_file,
                                            case_id, per_case_dir,
                                            stage_tokens, errors)
            p, c = stage_tokens.get("integrator", {}).get("prompt", 0), \
                   stage_tokens.get("integrator", {}).get("completion", 0)
            total_prompt += p; total_completion += c
        else:
            errors.append("Integrator skipped: no manifest")
            print(f"  ⚠ Integrator skipped")

    # ── Load mission JSON để score ────────────────────────────────────────────
    if mode == "with_verifier":
        mission_src = verified_dst
    else:
        mission_src = per_case_dir / f"{case_id}_mission.json"

    mission_data = None
    if mission_src.exists():
        mission_data = json.loads(mission_src.read_text(encoding="utf-8"))

    manifest_path = manifest_dst  if manifest_dst.exists()  else None
    artifact_path = artifact_dst  if artifact_dst.exists()  else None

    elapsed_sec = round(time.time() - case_start, 1)

    # ── Scoring ───────────────────────────────────────────────────────────────
    print(f"\n  [Score]  ⏱ {elapsed_sec}s")
    return _build_result(
        sid, sample, mission_data, manifest_path, artifact_path,
        stage_tokens, errors, total_prompt, total_completion, mode,
        elapsed_sec=elapsed_sec,
    )


# ---------------------------------------------------------------------------
# Build result dict + print score
# ---------------------------------------------------------------------------

def _build_result(
    sid:             int,
    sample:          Dict,
    mission_data:    Optional[Dict],
    manifest_path:   Optional[Path],
    artifact_path:   Optional[Path],
    stage_tokens:    Dict,
    errors:          List[str],
    total_prompt:    int,
    total_completion: int,
    mode:            str,
    elapsed_sec:     float = 0.0,
) -> Dict[str, Any]:

    gt_tram2 = sample.get("ground_truth_ttps_tram2", [])
    gt_full  = sample.get("ground_truth_ttps_full",  [])

    # no_verifier mode: lấy TTPs từ planner candidates (không có mitre_techniques)
    use_planner_only = (mode == "no_verifier")

    if mission_data:
        predicted     = _extract_ttps(mission_data, use_planner_only=use_planner_only)
        metrics_tram2 = _metrics(predicted, gt_tram2)
        metrics_full  = _metrics(predicted, gt_full)
        fb_info       = _fallback_rate(mission_data) if not use_planner_only else {}
        task_summary  = [
            {
                "task_id":    r.get("task_id"),
                "stage":      r.get("stage"),
                "techniques": r.get("final_mitre_techniques"),
                "confidence": r.get("mapping_confidence"),
                "fallback":   r.get("decision_trace", {}).get("fallback_used"),
                "top_score":  r.get("decision_trace", {}).get("top_candidate_score"),
            }
            for r in mission_data.get("verifier_task_reports", [])
        ]
    else:
        predicted     = []
        metrics_tram2 = {"precision": 0, "recall": 0, "f1": 0, "tp": 0, "fp": 0, "fn": 0}
        metrics_full  = {"precision": 0, "recall": 0, "f1": 0, "tp": 0, "fp": 0, "fn": 0}
        fb_info       = {}
        task_summary  = []

    cq  = _code_quality(_artifact_check(artifact_path) and manifest_path or manifest_path)
    av  = _artifact_check(artifact_path)
    total_cost = sum(s.get("cost", 0) for s in stage_tokens.values())

    # Print score
    m  = metrics_tram2
    mf = metrics_full
    print(f"  TRAM2  P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}"
          f"  (TP={m['tp']} FP={m['fp']} FN={m['fn']})")
    print(f"  Full   P={mf['precision']:.3f}  R={mf['recall']:.3f}  F1={mf['f1']:.3f}")
    print(f"  Pred : {predicted}")
    if cq:
        print(f"  Code : {cq.get('successful_modules')}/{cq.get('total_modules')} modules"
              f"  avgQ={cq.get('avg_quality_score')}/10")
    print(f"  Art  : {'✅' if av.get('artifact_valid') else '❌'}  LOC={av.get('loc',0)}")
    print(f"  Cost : ${total_cost:.4f}  tokens={total_prompt+total_completion:,}  ⏱ {elapsed_sec}s")
    if errors:
        for e in errors:
            print(f"  ⚠  {e}")

    return {
        "sample_id":          sid,
        "case_id":            f"case{sid:02d}",
        "mode":               mode,
        "intent":             sample["intent"][:100] + "...",
        "ground_truth_stage": sample.get("ground_truth_stage", ""),
        "evaluation_note":    sample.get("evaluation_note", ""),
        "status":             "error" if not mission_data else "success",
        "errors":             errors,

        "predicted_ttps":     predicted,
        "ground_truth_tram2": gt_tram2,
        "ground_truth_full":  gt_full,

        "metrics_tram2":      metrics_tram2,
        "metrics_full":       metrics_full,

        "verifier_fallback":  fb_info,
        "task_summary":       task_summary,
        "code_quality":       cq,
        "artifact_validity":  av,

        "token_usage": {
            "prompt":     total_prompt,
            "completion": total_completion,
            "total":      total_prompt + total_completion,
            "cost_usd":   round(total_cost, 4),
            "by_stage":   stage_tokens,
        },
        "elapsed_sec": elapsed_sec,
        "model":       os.environ.get("OPENAI_MODEL", "unknown"),
    }


# ---------------------------------------------------------------------------
# Aggregate metrics
# ---------------------------------------------------------------------------

def aggregate(results: List[Dict]) -> Dict[str, Any]:
    successful = [r for r in results if r["status"] == "success"]
    main_set   = [r for r in successful if r["sample_id"] not in OUT_OF_COVERAGE]

    def _macro(rs: List[Dict], label: str) -> Dict:
        vals = [r[f"metrics_{label}"] for r in rs if f"metrics_{label}" in r]
        if not vals:
            return {}
        return {
            "macro_precision": round(sum(v["precision"] for v in vals) / len(vals), 4),
            "macro_recall":    round(sum(v["recall"]    for v in vals) / len(vals), 4),
            "macro_f1":        round(sum(v["f1"]        for v in vals) / len(vals), 4),
            "n": len(vals),
        }

    def _tier_f1(rs: List[Dict], tier: Set[str]) -> Optional[float]:
        scores = []
        for r in rs:
            pred = set(r.get("predicted_ttps", []))
            gt   = set(r.get("ground_truth_tram2", []))
            pt   = pred & tier;  gt_t = gt & tier
            if not gt_t:
                continue
            tp = len(pt & gt_t); fp = len(pt - gt_t); fn = len(gt_t - pt)
            p  = tp/(tp+fp) if (tp+fp) > 0 else 0.0
            rc = tp/(tp+fn) if (tp+fn) > 0 else 0.0
            scores.append(2*p*rc/(p+rc) if (p+rc) > 0 else 0.0)
        return round(sum(scores)/len(scores), 4) if scores else None

    # Low-freq = dùng explicit set từ distribution thực tế
    LOW_FREQ = LOW_FREQ_EXPLICIT

    cq_list  = [r["code_quality"] for r in successful if r.get("code_quality")]
    n_valid  = sum(1 for r in results if r.get("artifact_validity", {}).get("artifact_valid"))
    all_tasks = sum(r.get("verifier_fallback", {}).get("total_tasks",    0) for r in successful)
    all_fb    = sum(r.get("verifier_fallback", {}).get("fallback_tasks", 0) for r in successful)

    return {
        "mode":              results[0]["mode"] if results else "unknown",
        "n_total":           len(results),
        "n_successful":      len(successful),
        "n_main_set":        len(main_set),

        "ttp_metrics": {
            "tram2_main": _macro(main_set,   "tram2"),
            "full_main":  _macro(main_set,   "full"),
            "tram2_all":  _macro(successful, "tram2"),
        },

        "frequency_tier_f1": {
            "high_freq":  _tier_f1(main_set, HIGH_FREQ),
            "mid_freq":   _tier_f1(main_set, MID_FREQ),
            "low_freq":   _tier_f1(main_set, LOW_FREQ),
            "note": "High>=1000, Mid=300-999, Low<300 samples in TRAM2 (36,594 total)",
        },

        # TTPs trong GT nhưng không có trong TRAM2 index → không thể verify
        "coverage_gap": {
            "not_in_index_ttps": sorted({
                t for r in results
                for t in r.get("ground_truth_full", [])
                if t not in HIGH_FREQ and t not in MID_FREQ and t not in LOW_FREQ
            }),
            "note": "TTPs present in ground_truth_full but absent from TRAM2 50-technique index",
        },

        "code_quality": {
            "avg_module_success_rate": round(
                sum(q["success_rate"]      for q in cq_list) / len(cq_list), 4) if cq_list else 0,
            "avg_quality_score_10":    round(
                sum(q["avg_quality_score"] for q in cq_list) / len(cq_list), 4) if cq_list else 0,
        },

        "artifact_validity": {
            "n_valid":    n_valid,
            "n_total":    len(results),
            "valid_rate": round(n_valid / len(results), 4) if results else 0.0,
        },

        "verifier_metrics": {
            "total_tasks":    all_tasks,
            "fallback_tasks": all_fb,
            "fallback_rate":  round(all_fb / all_tasks, 4) if all_tasks > 0 else 0.0,
        },

        "cost": {
            "total_tokens": sum(r["token_usage"]["total"]   for r in results),
            "total_usd":    round(sum(r["token_usage"]["cost_usd"] for r in results), 4),
        },
        "timing": {
            "total_sec":   round(sum(r.get("elapsed_sec", 0) for r in results), 1),
            "avg_sec":     round(sum(r.get("elapsed_sec", 0) for r in results) / len(results), 1) if results else 0,
            "min_sec":     round(min((r.get("elapsed_sec", 0) for r in results), default=0), 1),
            "max_sec":     round(max((r.get("elapsed_sec", 0) for r in results), default=0), 1),
        },
    }


# ---------------------------------------------------------------------------
# Ablation comparison table
# ---------------------------------------------------------------------------

def compare_ablation(
    results_with: List[Dict],
    results_no:   List[Dict],
    out_dir:      Path,
) -> None:
    """
    Tạo bảng so sánh F1 delta giữa with_verifier và no_verifier.
    """
    by_id_with = {r["sample_id"]: r for r in results_with}
    by_id_no   = {r["sample_id"]: r for r in results_no}

    rows = []
    for sid in sorted(set(by_id_with) | set(by_id_no)):
        rw = by_id_with.get(sid, {})
        rn = by_id_no.get(sid,   {})

        f1_with = rw.get("metrics_tram2", {}).get("f1", None)
        f1_no   = rn.get("metrics_tram2", {}).get("f1", None)
        delta   = round(f1_with - f1_no, 4) if (f1_with is not None and f1_no is not None) else None

        rows.append({
            "sample_id":      sid,
            "case_id":        f"case{sid:02d}",
            "stage":          rw.get("ground_truth_stage", rn.get("ground_truth_stage", "")),
            "gt_tram2":       "|".join(rw.get("ground_truth_tram2", [])),
            # with_verifier
            "pred_with":      "|".join(rw.get("predicted_ttps", [])),
            "F1_with":        f1_with,
            "P_with":         rw.get("metrics_tram2", {}).get("precision"),
            "R_with":         rw.get("metrics_tram2", {}).get("recall"),
            # no_verifier
            "pred_no":        "|".join(rn.get("predicted_ttps", [])),
            "F1_no":          f1_no,
            "P_no":           rn.get("metrics_tram2", {}).get("precision"),
            "R_no":           rn.get("metrics_tram2", {}).get("recall"),
            # delta
            "delta_F1":       delta,
            "verifier_helps": ("yes" if delta and delta > 0
                               else "no" if delta and delta < 0
                               else "tie"),
            "out_of_coverage": "yes" if sid in OUT_OF_COVERAGE else "no",
        })

    # CSV
    csv_path = out_dir / "ablation_compare.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    # Summary stats
    main_rows  = [r for r in rows if r["out_of_coverage"] == "no"
                  and r["F1_with"] is not None and r["F1_no"] is not None]
    avg_with   = sum(r["F1_with"] for r in main_rows) / len(main_rows) if main_rows else 0
    avg_no     = sum(r["F1_no"]   for r in main_rows) / len(main_rows) if main_rows else 0
    avg_delta  = sum(r["delta_F1"] for r in main_rows) / len(main_rows) if main_rows else 0
    n_helps    = sum(1 for r in main_rows if r["verifier_helps"] == "yes")
    n_hurts    = sum(1 for r in main_rows if r["verifier_helps"] == "no")
    n_tie      = sum(1 for r in main_rows if r["verifier_helps"] == "tie")

    compare_summary = {
        "n_main_samples":      len(main_rows),
        "macro_f1_with_verifier": round(avg_with,  4),
        "macro_f1_no_verifier":   round(avg_no,    4),
        "avg_delta_f1":           round(avg_delta, 4),
        "verifier_helps":  n_helps,
        "verifier_hurts":  n_hurts,
        "verifier_tie":    n_tie,
        "per_sample":      rows,
    }

    json_path = out_dir / "ablation_compare.json"
    json_path.write_text(
        json.dumps(compare_summary, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # Print
    print(f"\n{'='*65}")
    print(f"  ABLATION COMPARISON")
    print(f"{'='*65}")
    print(f"  Samples (excl #11)   : {len(main_rows)}")
    print(f"  Macro-F1 WITH verifier : {avg_with:.4f}")
    print(f"  Macro-F1 NO  verifier  : {avg_no:.4f}")
    print(f"  Avg delta F1 (+better) : {avg_delta:+.4f}")
    print(f"  Verifier helps / hurts / tie: {n_helps} / {n_hurts} / {n_tie}")
    print(f"\n  Per-sample:")
    print(f"  {'#':>3}  {'F1_with':>8}  {'F1_no':>7}  {'delta':>7}  result")
    print(f"  {'-'*45}")
    for r in sorted(rows, key=lambda x: x["sample_id"]):
        oor  = " [oor]" if r["out_of_coverage"] == "yes" else ""
        icon = "↑" if r["verifier_helps"] == "yes" else ("↓" if r["verifier_helps"] == "no" else "=")
        fw   = f"{r['F1_with']:.3f}" if r["F1_with"] is not None else "  N/A"
        fn   = f"{r['F1_no']:.3f}"   if r["F1_no"]   is not None else "  N/A"
        dl   = f"{r['delta_F1']:+.3f}" if r["delta_F1"] is not None else "   N/A"
        print(f"  #{r['sample_id']:>2}  {fw:>8}  {fn:>7}  {dl:>7}  {icon}{oor}")
    print(f"{'='*65}")
    print(f"  CSV  → {csv_path}")
    print(f"  JSON → {json_path}")


# ---------------------------------------------------------------------------
# CSV + Summary
# ---------------------------------------------------------------------------

def export_csv(results: List[Dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for r in results:
        m  = r.get("metrics_tram2", {})
        mf = r.get("metrics_full",  {})
        cq = r.get("code_quality",  {})
        av = r.get("artifact_validity", {})
        fb = r.get("verifier_fallback", {})
        rows.append({
            "case_id":            r["case_id"],
            "sample_id":          r["sample_id"],
            "mode":               r["mode"],
            "stage":              r["ground_truth_stage"],
            "status":             r["status"],
            "predicted_ttps":     "|".join(r.get("predicted_ttps", [])),
            "gt_tram2":           "|".join(r.get("ground_truth_tram2", [])),
            "gt_full":            "|".join(r.get("ground_truth_full",  [])),
            "P_tram2":            m.get("precision", ""),
            "R_tram2":            m.get("recall",    ""),
            "F1_tram2":           m.get("f1",        ""),
            "TP":                 m.get("tp", ""),
            "FP":                 m.get("fp", ""),
            "FN":                 m.get("fn", ""),
            "P_full":             mf.get("precision", ""),
            "R_full":             mf.get("recall",    ""),
            "F1_full":            mf.get("f1",        ""),
            "module_success_rate": cq.get("success_rate",      ""),
            "avg_quality_10":      cq.get("avg_quality_score", ""),
            "avg_loc":             cq.get("avg_loc",           ""),
            "artifact_valid":      av.get("artifact_valid",    ""),
            "artifact_loc":        av.get("loc",               ""),
            "task_fn_count":       av.get("task_fn_count",     ""),
            "fallback_rate":       fb.get("fallback_rate",     ""),
            "cost_usd":            r["token_usage"]["cost_usd"],
            "total_tokens":        r["token_usage"]["total"],
            "out_of_coverage":     "yes" if r["sample_id"] in OUT_OF_COVERAGE else "no",
            "evaluation_note":     r.get("evaluation_note", ""),
        })
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  📊 CSV → {path}")


def print_summary(results: List[Dict], agg: Dict) -> str:
    mode = agg.get("mode", "unknown")
    model = results[0].get("model", "unknown") if results else "unknown"
    lines = [
        f"\n{'='*65}",
        f"  BATCH SUMMARY  [{mode}]  model={model}",
        f"{'='*65}",
        f"  Total   : {agg['n_total']}  |  OK: {agg['n_successful']}  |  Main set: {agg['n_main_set']}",
        "",
    ]
    t  = agg["ttp_metrics"]["tram2_main"]
    ft = agg["frequency_tier_f1"]
    lines += [
        "  TTP Metrics (TRAM2, main set):",
        f"    Macro-P  : {t.get('macro_precision', 0):.4f}",
        f"    Macro-R  : {t.get('macro_recall',    0):.4f}",
        f"    Macro-F1 : {t.get('macro_f1',        0):.4f}",
        "",
        "  F1 by Frequency Tier:",
        f"    High-freq (>=1000) : {ft.get('high_freq', 'N/A')}",
        f"    Mid-freq  (300-999): {ft.get('mid_freq',  'N/A')}",
        f"    Low-freq  (<300)   : {ft.get('low_freq',  'N/A')}",
        "",
    ]
    av = agg["artifact_validity"]
    cq = agg["code_quality"]
    vm = agg["verifier_metrics"]
    lines += [
        "  Code & Artifact:",
        f"    Artifact valid   : {av['valid_rate']:.0%} ({av['n_valid']}/{av['n_total']})",
        f"    Module success   : {cq['avg_module_success_rate']:.0%}",
        f"    Avg quality (/10): {cq['avg_quality_score_10']:.2f}",
        "",
    ]
    if vm["total_tasks"] > 0:
        lines += [
            "  Verifier:",
            f"    Fallback rate : {vm['fallback_rate']:.0%}"
            f" ({vm['fallback_tasks']}/{vm['total_tasks']} tasks)",
            "",
        ]
    cost = agg["cost"]
    tm   = agg.get("timing", {})
    lines += [
        "  Cost & Timing:",
        f"    Tokens     : {cost['total_tokens']:,}",
        f"    USD        : ${cost['total_usd']:.4f}",
        f"    Total time : {tm.get('total_sec', 0)}s ({tm.get('total_sec', 0)/60:.1f} min)",
        f"    Avg/case   : {tm.get('avg_sec', 0)}s",
        f"    Min/Max    : {tm.get('min_sec', 0)}s / {tm.get('max_sec', 0)}s",
        "",
        "  Per-sample F1 (TRAM2):",
    ]
    for r in sorted(results, key=lambda x: x["sample_id"]):
        f1   = r.get("metrics_tram2", {}).get("f1", 0)
        st   = "✅" if r["status"] == "success" else "❌"
        oor  = " [oor]" if r["sample_id"] in OUT_OF_COVERAGE else ""
        bar_filled = int(f1 * 10)
        bar  = "█" * bar_filled + "░" * (10 - bar_filled)
        lines.append(f"    {st} #{r['sample_id']:2d}  [{bar}] {f1:.3f}  {r['ground_truth_stage']}{oor}")
    lines.append("=" * 65)
    text = "\n".join(lines)
    print(text)
    return text


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="LangMal Batch Runner + Ablation Scorer")
    parser.add_argument("--benchmark",     required=True)
    parser.add_argument("--mode",
                        choices=["with_verifier", "no_verifier", "compare"],
                        default="with_verifier",
                        help="Pipeline mode. 'compare' chạy cả 2 rồi so sánh.")
    parser.add_argument("--ids",           type=int, nargs="*",
                        help="Chỉ chạy các sample IDs này")
    parser.add_argument("--skip-pipeline", action="store_true",
                        help="Chỉ rescore, không chạy lại pipeline")
    parser.add_argument("--out-dir",       default="results")
    parser.add_argument("--delay",         type=float, default=5.0,
                        help="Giây chờ giữa các runs (tránh rate limit)")
    args = parser.parse_args()

    benchmark  = json.loads(Path(args.benchmark).read_text(encoding="utf-8"))
    samples    = {int(s["id"]): s for s in benchmark}
    target_ids = sorted(args.ids if args.ids else samples.keys())
    out_root   = Path(args.out_dir)

    modes_to_run = (
        ["with_verifier", "no_verifier"] if args.mode == "compare"
        else [args.mode]
    )

    print(f"\n🚀 LangMal Batch Runner")
    print(f"   Benchmark : {args.benchmark}  ({len(benchmark)} samples)")
    print(f"   Mode      : {args.mode}")
    print(f"   IDs       : {target_ids}")
    print(f"   Skip pipe : {args.skip_pipeline}")

    all_results_by_mode: Dict[str, List[Dict]] = {}
    batch_start = time.time()

    for mode in modes_to_run:
        mode_dir     = out_root / mode
        per_case_dir = mode_dir / "per_case"
        mode_dir.mkdir(parents=True, exist_ok=True)
        per_case_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n\n{'#'*65}")
        print(f"#  MODE: {mode}")
        print(f"{'#'*65}")

        mode_results: List[Dict] = []
        n_total = len(target_ids)

        for i, sid in enumerate(target_ids):
            if sid not in samples:
                print(f"\n⚠ Sample {sid} not in benchmark, skipping")
                continue

            # ── Progress header ──────────────────────────────────────────────
            pct      = (i + 1) / n_total * 100
            oor_tag  = " [out-of-coverage]" if sid in OUT_OF_COVERAGE else ""
            elapsed_so_far = time.time() - batch_start
            eta_str  = ""
            if i > 0:
                avg_per_case = elapsed_so_far / i
                eta_sec      = avg_per_case * (n_total - i)
                eta_str      = f"  ETA ≈ {eta_sec/60:.1f} min"
            print(f"\n  ── Progress: {i+1}/{n_total} ({pct:.0f}%){oor_tag}{eta_str}")

            result = run_one(
                sample        = samples[sid],
                per_case_dir  = per_case_dir,
                mode          = mode,
                skip_pipeline = args.skip_pipeline,
            )
            result["mode"] = mode
            mode_results.append(result)

            # Incremental save
            (mode_dir / "incremental.json").write_text(
                json.dumps(mode_results, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )

            if i < len(target_ids) - 1 and not args.skip_pipeline:
                print(f"\n  ⏳ Chờ {args.delay}s...")
                time.sleep(args.delay)

        # Aggregate + export cho mode này
        agg          = aggregate(mode_results)
        summary_text = print_summary(mode_results, agg)

        (mode_dir / "results.json").write_text(
            json.dumps({"aggregate": agg, "samples": mode_results},
                       indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        export_csv(mode_results, mode_dir / "results.csv")
        (mode_dir / "summary.txt").write_text(summary_text, encoding="utf-8")

        all_results_by_mode[mode] = mode_results

    # ── Ablation comparison (mode=compare) ────────────────────────────────────
    if args.mode == "compare" and len(all_results_by_mode) == 2:
        compare_ablation(
            results_with = all_results_by_mode["with_verifier"],
            results_no   = all_results_by_mode["no_verifier"],
            out_dir      = out_root,
        )

    elapsed = time.time() - batch_start
    print(f"\n  ⏱ Total: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"  📁 Output: {out_root}/")


if __name__ == "__main__":
    main()