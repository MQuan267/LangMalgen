#!/usr/bin/env python3
"""
report_tables.py – LangMal Multi-objective Evaluation Tables
=============================================================
Nhận output JSON từ run_batch.py, tạo tất cả bảng đánh giá
cho báo cáo đồ án chuyên ngành.

5 objectives được đánh giá:
  O1: TTP Accuracy     → Precision, Recall, F1 (TRAM2 + Full labels)
  O2: Artifact Validity → syntax valid, has main(), task_fn_count, LOC
  O3: Module Success   → success rate, avg quality score, avg LOC, avg attempts
  O4: Cost Efficiency  → tokens, USD per sample, per stage breakdown
  O5: Reliability      → error rate, fallback rate, avg generation attempts

Usage:
    # Chỉ có with_verifier
    python report_tables.py --results results/with_verifier/results.json

    # So sánh ablation (with vs no verifier)
    python report_tables.py \
        --results     results/with_verifier/results.json \
        --results-nv  results/no_verifier/results.json \
        --ablation    results/ablation_compare.json

    # Export ra file (thêm --out-dir)
    python report_tables.py \
        --results results/with_verifier/results.json \
        --out-dir results/tables
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# TRAM2 frequency tiers
# ---------------------------------------------------------------------------

HIGH_FREQ: Set[str] = {
    "T1027", "T1140", "T1059.003", "T1055", "T1105",
    "T1106", "T1090", "T1071.001", "T1082", "T1078", "T1053.005",
}
MID_FREQ: Set[str] = {
    "T1112", "T1003.001", "T1083", "T1057", "T1041", "T1070.004",
    "T1574.002", "T1562.001", "T1036.005", "T1573.001", "T1095",
    "T1547.001", "T1218.011", "T1056.001", "T1016", "T1005",
    "T1113", "T1543.003", "T1033",
}
OUT_OF_COVERAGE: Set[int] = {11}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(path: str) -> Dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _pct(v: float) -> str:
    return f"{v:.1%}"


def _f(v: Optional[float], decimals: int = 4) -> str:
    if v is None:
        return "N/A"
    fmt = f"{{:.{decimals}f}}"
    return fmt.format(v)


def _tier(ttp: str) -> str:
    if ttp in HIGH_FREQ:
        return "High"
    if ttp in MID_FREQ:
        return "Mid"
    return "Low"


def _sep(width: int = 68) -> str:
    return "-" * width


def _header(title: str, width: int = 68) -> str:
    return f"\n{'='*width}\n  {title}\n{'='*width}"


def _write_csv(rows: List[Dict], path: Path) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"  → CSV: {path}")


# ---------------------------------------------------------------------------
# O1: TTP Accuracy Table
# ---------------------------------------------------------------------------

def table_ttp_accuracy(
    samples: List[Dict],
    out_dir: Optional[Path] = None,
) -> None:
    """
    Bảng O1: TTP Accuracy per sample
    Columns: Case | Stage | GT (TRAM2) | Predicted | P | R | F1 | TP | FP | FN | Tier | OOC
    """
    print(_header("TABLE O1 — TTP Accuracy (TRAM2 labels, main score)"))
    print(f"  {'#':>3}  {'Stage':<35}  {'P':>6}  {'R':>6}  {'F1':>6}  "
          f"{'TP':>3}  {'FP':>3}  {'FN':>3}  {'Tier':<5}  OOC")
    print(f"  {_sep(78)}")

    rows = []
    main = [s for s in samples if s["sample_id"] not in OUT_OF_COVERAGE]
    oor  = [s for s in samples if s["sample_id"]     in OUT_OF_COVERAGE]

    for s in sorted(samples, key=lambda x: x["sample_id"]):
        m   = s.get("metrics_tram2", {})
        gt  = s.get("ground_truth_tram2", [])
        ooc = "yes" if s["sample_id"] in OUT_OF_COVERAGE else "no"

        # Determine dominant tier from GT TTPs
        tiers = [_tier(t) for t in gt]
        tier  = max(set(tiers), key=tiers.count) if tiers else "N/A"

        print(f"  #{s['sample_id']:>2}  {s['ground_truth_stage']:<35}  "
              f"{_f(m.get('precision'),3):>6}  {_f(m.get('recall'),3):>6}  "
              f"{_f(m.get('f1'),3):>6}  "
              f"{m.get('tp',''):>3}  {m.get('fp',''):>3}  {m.get('fn',''):>3}  "
              f"{tier:<5}  {ooc}")
        rows.append({
            "sample_id":    s["sample_id"],
            "stage":        s["ground_truth_stage"],
            "gt_tram2":     "|".join(gt),
            "gt_full":      "|".join(s.get("ground_truth_full", [])),
            "predicted":    "|".join(s.get("predicted_ttps", [])),
            "precision":    m.get("precision", ""),
            "recall":       m.get("recall",    ""),
            "f1":           m.get("f1",        ""),
            "tp":           m.get("tp",  ""),
            "fp":           m.get("fp",  ""),
            "fn":           m.get("fn",  ""),
            "tier":         tier,
            "out_of_coverage": ooc,
        })

    # Aggregate rows
    print(f"  {_sep(78)}")

    def _macro_row(rs: List[Dict], label: str) -> None:
        vals = [r.get("metrics_tram2", {}) for r in rs
                if r.get("metrics_tram2", {}).get("f1") is not None]
        if not vals:
            return
        p  = sum(v.get("precision", 0) for v in vals) / len(vals)
        r  = sum(v.get("recall",    0) for v in vals) / len(vals)
        f1 = sum(v.get("f1",        0) for v in vals) / len(vals)
        tp = sum(v.get("tp", 0) for v in vals)
        fp = sum(v.get("fp", 0) for v in vals)
        fn = sum(v.get("fn", 0) for v in vals)
        print(f"  {label:<40}  {p:.3f}  {r:.3f}  {f1:.3f}  "
              f"{tp:>3}  {fp:>3}  {fn:>3}")

    _macro_row(main, f"Macro-avg (n={len(main)}, excl #11)")
    _macro_row(oor,  f"Out-of-coverage (#11 only)")

    # Also show Full-label metrics
    print(f"\n  [Full labels — secondary, for coverage gap analysis]")
    print(f"  {'#':>3}  {'Stage':<35}  {'P':>6}  {'R':>6}  {'F1':>6}")
    print(f"  {_sep(60)}")
    for s in sorted(samples, key=lambda x: x["sample_id"]):
        mf = s.get("metrics_full", {})
        oor_tag = " [oor]" if s["sample_id"] in OUT_OF_COVERAGE else ""
        print(f"  #{s['sample_id']:>2}  {s['ground_truth_stage']:<35}  "
              f"{_f(mf.get('precision'),3):>6}  {_f(mf.get('recall'),3):>6}  "
              f"{_f(mf.get('f1'),3):>6}{oor_tag}")

    if out_dir:
        _write_csv(rows, out_dir / "O1_ttp_accuracy.csv")


# ---------------------------------------------------------------------------
# O2: Artifact Validity Table
# ---------------------------------------------------------------------------

def table_artifact_validity(
    samples: List[Dict],
    out_dir: Optional[Path] = None,
) -> None:
    """
    Bảng O2: Artifact Validity per sample
    Columns: Case | Stage | Syntax OK | Has main() | Task fns | LOC | Valid
    """
    print(_header("TABLE O2 — Artifact Validity"))
    print(f"  {'#':>3}  {'Stage':<32}  {'Syntax':>7}  {'main()':>7}  "
          f"{'TaskFns':>8}  {'LOC':>6}  {'Valid':>6}")
    print(f"  {_sep(75)}")

    rows = []
    n_valid = 0
    n_total = len(samples)

    for s in sorted(samples, key=lambda x: x["sample_id"]):
        av     = s.get("artifact_validity", {})
        valid  = av.get("artifact_valid", False)
        syntax = av.get("syntax_valid",   False)
        main_  = av.get("has_main",       False)
        fns    = av.get("task_fn_count",  0)
        loc    = av.get("loc",            0)

        if valid:
            n_valid += 1

        v_str  = "✅" if valid  else "❌"
        s_str  = "✅" if syntax else "❌"
        m_str  = "✅" if main_  else "❌"
        reason = av.get("reason") or ""

        print(f"  #{s['sample_id']:>2}  {s['ground_truth_stage']:<32}  "
              f"{s_str:>7}  {m_str:>7}  {fns:>8}  {loc:>6}  {v_str:>6}"
              + (f"  [{reason}]" if reason else ""))

        rows.append({
            "sample_id":    s["sample_id"],
            "stage":        s["ground_truth_stage"],
            "syntax_valid": syntax,
            "has_main":     main_,
            "task_fn_count": fns,
            "loc":          loc,
            "artifact_valid": valid,
            "reason":       reason,
        })

    print(f"  {_sep(75)}")
    valid_rate = n_valid / n_total if n_total > 0 else 0.0
    avg_loc    = sum(r["loc"] for r in rows) / len(rows) if rows else 0
    avg_fns    = sum(r["task_fn_count"] for r in rows) / len(rows) if rows else 0
    print(f"  Valid artifacts : {n_valid}/{n_total}  ({valid_rate:.0%})")
    print(f"  Avg LOC         : {avg_loc:.0f}")
    print(f"  Avg task fns    : {avg_fns:.1f}")

    if out_dir:
        _write_csv(rows, out_dir / "O2_artifact_validity.csv")


# ---------------------------------------------------------------------------
# O3: Module Success Rate Table
# ---------------------------------------------------------------------------

def table_module_success(
    samples: List[Dict],
    out_dir: Optional[Path] = None,
) -> None:
    """
    Bảng O3: Module (Developer) Success Rate per sample
    Columns: Case | Stage | Total modules | Success | Rate | Avg Q/10 | Avg LOC | Avg attempts
    """
    print(_header("TABLE O3 — Module Success Rate (Developer Agent)"))
    print(f"  {'#':>3}  {'Stage':<30}  {'Total':>6}  {'OK':>4}  "
          f"{'Rate':>6}  {'AvgQ':>6}  {'AvgLOC':>7}  {'Tries':>6}")
    print(f"  {_sep(75)}")

    rows = []
    for s in sorted(samples, key=lambda x: x["sample_id"]):
        cq = s.get("code_quality", {})
        if not cq:
            total = ok = 0
            rate = q = loc = att = 0.0
        else:
            total = cq.get("total_modules",      0)
            ok    = cq.get("successful_modules",  0)
            rate  = cq.get("success_rate",        0.0)
            q     = cq.get("avg_quality_score",   0.0)
            loc   = cq.get("avg_loc",             0.0)
            att   = cq.get("avg_attempts",        0.0)

        print(f"  #{s['sample_id']:>2}  {s['ground_truth_stage']:<30}  "
              f"{total:>6}  {ok:>4}  {_pct(rate):>6}  "
              f"{q:>6.2f}  {loc:>7.0f}  {att:>6.2f}")
        rows.append({
            "sample_id":       s["sample_id"],
            "stage":           s["ground_truth_stage"],
            "total_modules":   total,
            "successful":      ok,
            "success_rate":    rate,
            "avg_quality_10":  q,
            "avg_loc":         loc,
            "avg_attempts":    att,
        })

    valid_rows = [r for r in rows if r["total_modules"] > 0]
    if valid_rows:
        print(f"  {_sep(75)}")
        avg_rate = sum(r["success_rate"]   for r in valid_rows) / len(valid_rows)
        avg_q    = sum(r["avg_quality_10"] for r in valid_rows) / len(valid_rows)
        avg_loc  = sum(r["avg_loc"]        for r in valid_rows) / len(valid_rows)
        avg_att  = sum(r["avg_attempts"]   for r in valid_rows) / len(valid_rows)
        print(f"  Avg (n={len(valid_rows)}){'':<22}"
              f"{'':>6}  {'':>4}  {_pct(avg_rate):>6}  "
              f"{avg_q:>6.2f}  {avg_loc:>7.0f}  {avg_att:>6.2f}")

    if out_dir:
        _write_csv(rows, out_dir / "O3_module_success.csv")


# ---------------------------------------------------------------------------
# O4: Cost Efficiency Table
# ---------------------------------------------------------------------------

def table_cost(
    samples: List[Dict],
    out_dir: Optional[Path] = None,
) -> None:
    """
    Bảng O4: Token + USD Cost per sample và per stage
    """
    print(_header("TABLE O4 — Cost Efficiency (gpt-4o pricing)"))
    print(f"  {'#':>3}  {'Stage':<28}  {'Planner':>9}  {'Developer':>10}  "
          f"{'Integrator':>11}  {'Total$':>8}  {'Tokens':>8}")
    print(f"  {_sep(85)}")

    rows = []
    total_usd    = 0.0
    total_tokens = 0

    for s in sorted(samples, key=lambda x: x["sample_id"]):
        tu     = s.get("token_usage", {})
        by_s   = tu.get("by_stage", {})
        cost   = tu.get("cost_usd",  0.0)
        tokens = tu.get("total",     0)

        p_cost  = by_s.get("planner",    {}).get("cost", 0.0)
        d_cost  = by_s.get("developer",  {}).get("cost", 0.0)
        i_cost  = by_s.get("integrator", {}).get("cost", 0.0)

        total_usd    += cost
        total_tokens += tokens

        print(f"  #{s['sample_id']:>2}  {s['ground_truth_stage']:<28}  "
              f"${p_cost:>8.4f}  ${d_cost:>9.4f}  ${i_cost:>10.4f}  "
              f"${cost:>7.4f}  {tokens:>8,}")
        rows.append({
            "sample_id":       s["sample_id"],
            "stage":           s["ground_truth_stage"],
            "planner_usd":     round(p_cost,  4),
            "developer_usd":   round(d_cost,  4),
            "integrator_usd":  round(i_cost,  4),
            "total_usd":       round(cost,    4),
            "total_tokens":    tokens,
        })

    print(f"  {_sep(85)}")
    n = len(rows)
    print(f"  TOTAL                                                          "
          f"  ${total_usd:>7.4f}  {total_tokens:>8,}")
    print(f"  Avg per sample                                                 "
          f"  ${total_usd/n if n else 0:>7.4f}  {total_tokens//n if n else 0:>8,}")

    if out_dir:
        _write_csv(rows, out_dir / "O4_cost.csv")


# ---------------------------------------------------------------------------
# O5: Reliability Table
# ---------------------------------------------------------------------------

def table_reliability(
    samples: List[Dict],
    out_dir: Optional[Path] = None,
) -> None:
    """
    Bảng O5: Reliability — pipeline error rate, verifier fallback rate,
    developer retry rate
    """
    print(_header("TABLE O5 — Reliability"))
    print(f"  {'#':>3}  {'Stage':<30}  {'Status':>8}  "
          f"{'FB_tasks':>9}  {'FB_rate':>8}  {'Avg_tries':>10}  Errors")
    print(f"  {_sep(80)}")

    rows = []
    n_success = 0
    n_total   = len(samples)

    for s in sorted(samples, key=lambda x: x["sample_id"]):
        status = s.get("status", "error")
        fb     = s.get("verifier_fallback", {})
        cq     = s.get("code_quality",      {})
        errors = s.get("errors", [])

        fb_tasks = fb.get("fallback_tasks", 0)
        fb_rate  = fb.get("fallback_rate",  0.0)
        fb_total = fb.get("total_tasks",    0)
        avg_att  = cq.get("avg_attempts",   1.0) if cq else 1.0

        if status == "success":
            n_success += 1

        st_icon = "✅" if status == "success" else "❌"
        fb_str  = f"{fb_tasks}/{fb_total}" if fb_total > 0 else "N/A"
        err_str = "; ".join(errors[:1])[:40] if errors else ""

        print(f"  #{s['sample_id']:>2}  {s['ground_truth_stage']:<30}  "
              f"{st_icon:>8}  {fb_str:>9}  {_pct(fb_rate):>8}  "
              f"{avg_att:>10.2f}  {err_str}")
        rows.append({
            "sample_id":       s["sample_id"],
            "stage":           s["ground_truth_stage"],
            "status":          status,
            "fallback_tasks":  fb_tasks,
            "total_tasks":     fb_total,
            "fallback_rate":   round(fb_rate, 4),
            "avg_dev_attempts": round(avg_att, 2),
            "errors":          "; ".join(errors),
        })

    print(f"  {_sep(80)}")
    pipeline_success_rate = n_success / n_total if n_total > 0 else 0.0
    all_fb    = sum(r["fallback_tasks"] for r in rows)
    all_tasks = sum(r["total_tasks"]    for r in rows)
    fb_agg    = all_fb / all_tasks if all_tasks > 0 else 0.0
    att_rows  = [r["avg_dev_attempts"] for r in rows if r["avg_dev_attempts"] > 0]
    avg_att   = sum(att_rows) / len(att_rows) if att_rows else 0.0

    print(f"  Pipeline success rate    : {_pct(pipeline_success_rate)} ({n_success}/{n_total})")
    print(f"  Verifier fallback rate   : {_pct(fb_agg)} ({all_fb}/{all_tasks} tasks)")
    print(f"  Avg developer attempts   : {avg_att:.2f}")

    if out_dir:
        _write_csv(rows, out_dir / "O5_reliability.csv")


# ---------------------------------------------------------------------------
# Ablation Summary Table (O1 với 2 variants)
# ---------------------------------------------------------------------------

def table_ablation(
    ablation_data: Dict,
    out_dir: Optional[Path] = None,
) -> None:
    """
    Bảng ablation: so sánh F1 with_verifier vs no_verifier per sample.
    Input: ablation_compare.json từ run_batch.py --mode compare
    """
    print(_header("TABLE ABLATION — Verifier Contribution (ΔF1 = with − no)"))
    print(f"  {'#':>3}  {'Stage':<30}  {'F1_with':>8}  {'F1_no':>7}  "
          f"{'ΔF1':>7}  {'Effect':>8}")
    print(f"  {_sep(70)}")

    per_sample = ablation_data.get("per_sample", [])
    rows = []

    for r in sorted(per_sample, key=lambda x: x["sample_id"]):
        fw   = r.get("F1_with")
        fn   = r.get("F1_no")
        dl   = r.get("delta_F1")
        icon = ("↑ helps" if r.get("verifier_helps") == "yes"
                else "↓ hurts" if r.get("verifier_helps") == "no"
                else "= tie")
        oor  = " [oor]" if r.get("out_of_coverage") == "yes" else ""

        fw_s = f"{fw:.3f}" if fw is not None else " N/A"
        fn_s = f"{fn:.3f}" if fn is not None else " N/A"
        dl_s = f"{dl:+.3f}" if dl is not None else "  N/A"

        print(f"  #{r['sample_id']:>2}  {r.get('stage',''):<30}  "
              f"{fw_s:>8}  {fn_s:>7}  {dl_s:>7}  {icon}{oor}")
        rows.append({
            "sample_id":       r["sample_id"],
            "stage":           r.get("stage", ""),
            "gt_tram2":        r.get("gt_tram2", ""),
            "F1_with_verifier": fw,
            "F1_no_verifier":   fn,
            "delta_F1":         dl,
            "effect":           r.get("verifier_helps", ""),
            "out_of_coverage":  r.get("out_of_coverage", "no"),
        })

    print(f"  {_sep(70)}")
    agg_f1_w = ablation_data.get("macro_f1_with_verifier")
    agg_f1_n = ablation_data.get("macro_f1_no_verifier")
    agg_dl   = ablation_data.get("avg_delta_f1")
    n_helps  = ablation_data.get("verifier_helps", 0)
    n_hurts  = ablation_data.get("verifier_hurts", 0)
    n_tie    = ablation_data.get("verifier_tie",   0)
    n        = ablation_data.get("n_main_samples",  0)

    print(f"\n  Macro-F1 with_verifier  : {_f(agg_f1_w, 4)}")
    print(f"  Macro-F1 no_verifier    : {_f(agg_f1_n, 4)}")
    print(f"  Avg ΔF1 (main set n={n}) : {f'{agg_dl:+.4f}' if agg_dl is not None else 'N/A'}")
    print(f"  Verifier helps / hurts / tie : {n_helps} / {n_hurts} / {n_tie}")

    if out_dir:
        _write_csv(rows, out_dir / "ABLATION_verifier_contribution.csv")


# ---------------------------------------------------------------------------
# Multi-objective Overview Table
# ---------------------------------------------------------------------------

def table_multiobjective_overview(
    agg_with: Dict,
    agg_no:   Optional[Dict] = None,
    out_dir:  Optional[Path] = None,
) -> None:
    """
    Bảng tổng hợp 5 objectives — dùng cho paper Table 1 hoặc abstract.
    """
    print(_header("TABLE SUMMARY — Multi-objective Overview"))

    def _row(obj: str, metric: str, val_with: Any, val_no: Any = None) -> None:
        if val_no is not None:
            print(f"  {obj:<5}  {metric:<35}  {str(val_with):>12}  {str(val_no):>12}")
        else:
            print(f"  {obj:<5}  {metric:<35}  {str(val_with):>12}")

    header = (f"  {'Obj':<5}  {'Metric':<35}  {'with_verifier':>12}"
              + (f"  {'no_verifier':>12}" if agg_no else ""))
    print(header)
    print(f"  {_sep(70 if agg_no else 55)}")

    t_w  = agg_with.get("ttp_metrics", {}).get("tram2_main", {})
    tf_w = agg_with.get("frequency_tier_f1", {})
    av_w = agg_with.get("artifact_validity", {})
    cq_w = agg_with.get("code_quality", {})
    vm_w = agg_with.get("verifier_metrics", {})
    co_w = agg_with.get("cost", {})

    if agg_no:
        t_n  = agg_no.get("ttp_metrics", {}).get("tram2_main", {})
        tf_n = agg_no.get("frequency_tier_f1", {})
        av_n = agg_no.get("artifact_validity", {})
        cq_n = agg_no.get("code_quality", {})
        co_n = agg_no.get("cost", {})
    else:
        t_n = tf_n = av_n = cq_n = co_n = None

    # O1: TTP Accuracy
    _row("O1", "Macro-Precision (TRAM2)",
         _f(t_w.get("macro_precision"), 4),
         _f(t_n.get("macro_precision"), 4) if t_n else None)
    _row("O1", "Macro-Recall (TRAM2)",
         _f(t_w.get("macro_recall"), 4),
         _f(t_n.get("macro_recall"), 4) if t_n else None)
    _row("O1", "Macro-F1 (TRAM2, main set)",
         _f(t_w.get("macro_f1"), 4),
         _f(t_n.get("macro_f1"), 4) if t_n else None)
    _row("O1", "F1 High-freq TTPs",
         _f(tf_w.get("high_freq"), 4),
         _f(tf_n.get("high_freq"), 4) if tf_n else None)
    _row("O1", "F1 Mid-freq TTPs",
         _f(tf_w.get("mid_freq"), 4),
         _f(tf_n.get("mid_freq"), 4) if tf_n else None)
    _row("O1", "F1 Low-freq TTPs",
         _f(tf_w.get("low_freq"), 4),
         _f(tf_n.get("low_freq"), 4) if tf_n else None)

    print(f"  {_sep(70 if agg_no else 55)}")

    # O2: Artifact Validity
    _row("O2", "Artifact valid rate",
         _pct(av_w.get("valid_rate", 0)),
         _pct(av_n.get("valid_rate", 0)) if av_n else None)
    _row("O2", "Valid artifacts (n)",
         f"{av_w.get('n_valid',0)}/{av_w.get('n_total',0)}",
         f"{av_n.get('n_valid',0)}/{av_n.get('n_total',0)}" if av_n else None)

    print(f"  {_sep(70 if agg_no else 55)}")

    # O3: Module Success
    _row("O3", "Avg module success rate",
         _pct(cq_w.get("avg_module_success_rate", 0)),
         _pct(cq_n.get("avg_module_success_rate", 0)) if cq_n else None)
    _row("O3", "Avg quality score (/10)",
         _f(cq_w.get("avg_quality_score_10"), 2),
         _f(cq_n.get("avg_quality_score_10"), 2) if cq_n else None)

    print(f"  {_sep(70 if agg_no else 55)}")

    # O4: Cost
    n_w = agg_with.get("n_total", 1) or 1
    _row("O4", "Total cost (USD)",
         f"${co_w.get('total_usd', 0):.4f}",
         f"${co_n.get('total_usd', 0):.4f}" if co_n else None)
    _row("O4", "Avg cost per sample",
         f"${co_w.get('total_usd', 0)/n_w:.4f}",
         f"${co_n.get('total_usd', 0)/agg_no.get('n_total',1):.4f}" if co_n else None)
    _row("O4", "Total tokens",
         f"{co_w.get('total_tokens', 0):,}",
         f"{co_n.get('total_tokens', 0):,}" if co_n else None)

    print(f"  {_sep(70 if agg_no else 55)}")

    # O5: Reliability
    _row("O5", "Pipeline success rate",
         _pct(agg_with.get("n_successful", 0) / agg_with.get("n_total", 1)),
         _pct(agg_no.get("n_successful", 0) / agg_no.get("n_total", 1)) if agg_no else None)
    _row("O5", "Verifier fallback rate",
         _pct(vm_w.get("fallback_rate", 0)), None)

    print(f"  {_sep(70 if agg_no else 55)}")

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        # Save as JSON for easy reference
        overview = {
            "with_verifier": {
                "O1_ttp_accuracy": {
                    "macro_precision": t_w.get("macro_precision"),
                    "macro_recall":    t_w.get("macro_recall"),
                    "macro_f1":        t_w.get("macro_f1"),
                    "f1_high_freq":    tf_w.get("high_freq"),
                    "f1_mid_freq":     tf_w.get("mid_freq"),
                    "f1_low_freq":     tf_w.get("low_freq"),
                },
                "O2_artifact_validity": {
                    "valid_rate": av_w.get("valid_rate"),
                    "n_valid":    av_w.get("n_valid"),
                    "n_total":    av_w.get("n_total"),
                },
                "O3_module_success": {
                    "avg_success_rate":  cq_w.get("avg_module_success_rate"),
                    "avg_quality_score": cq_w.get("avg_quality_score_10"),
                },
                "O4_cost": {
                    "total_usd":    co_w.get("total_usd"),
                    "total_tokens": co_w.get("total_tokens"),
                },
                "O5_reliability": {
                    "pipeline_success_rate": agg_with.get("n_successful", 0) / n_w,
                    "fallback_rate":         vm_w.get("fallback_rate"),
                },
            },
        }
        if agg_no:
            overview["no_verifier"] = {
                "O1_ttp_accuracy": {
                    "macro_f1":     t_n.get("macro_f1"),
                    "f1_high_freq": tf_n.get("high_freq"),
                    "f1_mid_freq":  tf_n.get("mid_freq"),
                },
                "O2_artifact_validity": {"valid_rate": av_n.get("valid_rate")},
                "O3_module_success":    {"avg_success_rate": cq_n.get("avg_module_success_rate")},
                "O4_cost":              {"total_usd": co_n.get("total_usd")},
            }
        (out_dir / "SUMMARY_multiobjective.json").write_text(
            json.dumps(overview, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"  → JSON: {out_dir / 'SUMMARY_multiobjective.json'}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="LangMal Report Tables Generator")
    parser.add_argument("--results",    required=True,
                        help="results/with_verifier/results.json")
    parser.add_argument("--results-nv", default="",
                        help="results/no_verifier/results.json (ablation)")
    parser.add_argument("--ablation",   default="",
                        help="results/ablation_compare.json")
    parser.add_argument("--out-dir",    default="",
                        help="Directory để lưu CSV (optional)")
    parser.add_argument("--tables",     nargs="*",
                        choices=["O1","O2","O3","O4","O5","ablation","summary","all"],
                        default=["all"],
                        help="Chỉ in các bảng này (mặc định: all)")
    args = parser.parse_args()

    data_w   = _load(args.results)
    samples  = data_w.get("samples",   [])
    agg_w    = data_w.get("aggregate", {})

    data_nv  = _load(args.results_nv) if args.results_nv else None
    agg_nv   = data_nv.get("aggregate", {}) if data_nv else None

    ablation = _load(args.ablation) if args.ablation else None

    out_dir  = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    want = set(args.tables)
    run_all = "all" in want

    print(f"\n🔬 LangMal — Multi-objective Evaluation Report")
    print(f"   Results : {args.results}  ({len(samples)} samples)")
    if data_nv:
        print(f"   Ablation: {args.results_nv}")

    if run_all or "O1" in want:
        table_ttp_accuracy(samples, out_dir)

    if run_all or "O2" in want:
        table_artifact_validity(samples, out_dir)

    if run_all or "O3" in want:
        table_module_success(samples, out_dir)

    if run_all or "O4" in want:
        table_cost(samples, out_dir)

    if run_all or "O5" in want:
        table_reliability(samples, out_dir)

    if (run_all or "ablation" in want) and ablation:
        table_ablation(ablation, out_dir)
    elif (run_all or "ablation" in want) and not ablation:
        print("\n  [ablation] Bỏ qua — chưa có --ablation file")

    if run_all or "summary" in want:
        table_multiobjective_overview(agg_w, agg_nv, out_dir)

    if out_dir:
        print(f"\n  📁 Tất cả CSV saved → {out_dir}/")


if __name__ == "__main__":
    main()