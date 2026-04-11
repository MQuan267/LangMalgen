"""
run_benchmark.py — Full benchmark pipeline
==========================================
Flow:
  1. Read benchmark JSON (tier1 + tier2)
  2. For each entry: run planner → run verifier → evaluate
  3. Print formatted result table with token usage and cost

Usage:
  python run_benchmark.py \
    --benchmark data/tram2_31_benchmark.json \
    --datasets data/tram2.jsonl \
    --planner src/agents/plannerv8.py \
    --verifier src/agents/verifierv8.py \
    --tiers tier1 tier2
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Token pricing table (per 1M tokens)
# ---------------------------------------------------------------------------
PRICING_TABLE: dict[str, dict[str, float]] = {
    "gpt-4o-mini":   {"input": 0.150,  "output": 0.600},
    "gpt-4o":        {"input": 2.50,   "output": 10.00},
    "gpt-4.1":       {"input": 2.00,   "output": 8.00},
    "gpt-4.1-mini":  {"input": 0.40,   "output": 1.60},
    "gpt-4.1-nano":  {"input": 0.10,   "output": 0.40},
    "gpt-5":         {"input": 1.25,   "output": 10.00},
    "gpt-5-mini":    {"input": 0.25,   "output": 2.00},
    "gpt-5-nano":    {"input": 0.05,   "output": 0.40},
    "gpt-5.1":       {"input": 1.25,   "output": 10.00},
    "gpt-5.2":       {"input": 1.75,   "output": 14.00},
}
DEFAULT_MODEL_PRICING = "gpt-4o-mini"

# Set at runtime from --model-pricing arg
_active_pricing: dict[str, float] = PRICING_TABLE[DEFAULT_MODEL_PRICING]

def calc_cost(prompt_tokens: int, completion_tokens: int) -> float:
    return (prompt_tokens     / 1_000_000 * _active_pricing["input"] +
            completion_tokens / 1_000_000 * _active_pricing["output"])


# ---------------------------------------------------------------------------
# Step 1 — Run planner
# ---------------------------------------------------------------------------

def run_planner(planner_path: str, intent: str, out_dir: Path, entry_id: str) -> Path | None:
    cmd = [
        sys.executable, planner_path,
        "--intent", intent,
        "--out-dir", str(out_dir),
    ]
    print(f"  [{entry_id}] planner ...", end=" ", flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{RED}FAILED{RESET}")
        print(f"    stderr: {result.stderr[:200]}")
        return None

    # Find saved path from stdout
    for line in result.stdout.splitlines():
        if "Mission saved" in line and "→" in line:
            path_str = line.split("→")[-1].strip()
            p = Path(path_str)
            if p.exists():
                print(f"{GREEN}OK{RESET} → {p.name}")
                return p

    # Fallback: find newest JSON in out_dir
    jsons = sorted(out_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    if jsons:
        print(f"{GREEN}OK{RESET} → {jsons[0].name}")
        return jsons[0]

    print(f"{RED}FAILED (file not found){RESET}")
    return None


# ---------------------------------------------------------------------------
# Step 2 — Run verifier
# ---------------------------------------------------------------------------

def run_verifier(verifier_path: str, mission_path: Path, datasets: list[str],
                 cache_dir: str) -> Path | None:
    verified_path = mission_path.with_name(mission_path.stem + "_verified.json")
    cmd = [
        sys.executable, verifier_path,
        "--mission", str(mission_path),
        "--datasets", *datasets,
        "--cache-dir", cache_dir,
        "--out", str(verified_path),
    ]
    print(f"  [{mission_path.stem[:30]}] verifier ...", end=" ", flush=True)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{RED}FAILED{RESET}")
        print(f"    stderr: {result.stderr[:200]}")
        return None

    if verified_path.exists():
        print(f"{GREEN}OK{RESET}")
        return verified_path

    print(f"{RED}FAILED (file not found){RESET}")
    return None


# ---------------------------------------------------------------------------
# Step 3 — Evaluate
# ---------------------------------------------------------------------------

def get_predicted_ttps(verified_path: Path) -> set[str]:
    data = json.loads(verified_path.read_text(encoding="utf-8"))
    ttps: set[str] = set()
    for task in data.get("execution_graph", []):
        for t in task.get("mitre_techniques", []):
            if t:
                ttps.add(t.strip())
    return ttps


def get_token_usage(mission_path: Path) -> dict:
    """Extract token usage from planner mission JSON."""
    try:
        data = json.loads(mission_path.read_text(encoding="utf-8"))
        usage = data.get("planner_summary", {}).get("token_usage", {})
        prompt_tokens     = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens      = usage.get("total_tokens", prompt_tokens + completion_tokens)
        attempts          = usage.get("attempts", 1)
        cost              = calc_cost(prompt_tokens, completion_tokens)
        return {
            "prompt_tokens":     prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens":      total_tokens,
            "attempts":          attempts,
            "cost_usd":          cost,
        }
    except Exception:
        return {
            "prompt_tokens": 0, "completion_tokens": 0,
            "total_tokens": 0, "attempts": 0, "cost_usd": 0.0,
        }


def evaluate(predicted: set[str], selected: set[str], core: set[str]) -> dict:
    tp_sel = predicted & selected
    fp_sel = predicted - selected
    fn_sel = selected - predicted

    precision = len(tp_sel) / len(predicted) if predicted else 0.0
    recall    = len(tp_sel) / len(selected)  if selected  else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    core_recall = len(predicted & core) / len(core) if core else 0.0

    return {
        "precision":    round(precision, 3),
        "recall":       round(recall, 3),
        "f1":           round(f1, 3),
        "core_recall":  round(core_recall, 3),
        "tp":           sorted(tp_sel),
        "fp":           sorted(fp_sel),
        "fn":           sorted(fn_sel),
        "predicted":    sorted(predicted),
        "selected":     sorted(selected),
        "core":         sorted(core),
    }


# ---------------------------------------------------------------------------
# Printing helpers
# ---------------------------------------------------------------------------

def _ttp_list(ttps: list[str], color: str) -> str:
    if not ttps:
        return "—"
    return color + "  ".join(ttps) + RESET


def _bar(value: float, width: int = 20) -> str:
    filled = int(round(value * width))
    bar = "█" * filled + "░" * (width - filled)
    color = GREEN if value >= 0.7 else (YELLOW if value >= 0.4 else RED)
    return f"{color}{bar}{RESET} {value:.3f}"


def print_entry_result(entry: dict, metrics: dict, token_info: dict,
                       idx: int, total: int) -> None:
    eid      = entry["id"]
    category = entry.get("category", "")
    prompt   = entry["malgen_input_prompt"][:90]

    w = 90
    sep = "─" * w

    print(f"\n{BOLD}┌{sep}┐{RESET}")
    print(f"{BOLD}│ [{idx:02d}/{total:02d}] {eid}  [{category}]{' ' * max(0, w - 14 - len(eid) - len(category))}│{RESET}")
    print(f"{BOLD}├{sep}┤{RESET}")
    print(f"│ Prompt : {prompt:<{w-10}}│")
    print(f"{BOLD}├{sep}┤{RESET}")

    # Metrics
    print(f"│ {'Precision':<14} {_bar(metrics['precision']):<50} {'':>{w-66}}│")
    print(f"│ {'Recall':<14} {_bar(metrics['recall']):<50} {'':>{w-66}}│")
    print(f"│ {'F1':<14} {_bar(metrics['f1']):<50} {'':>{w-66}}│")
    print(f"│ {'Core Recall':<14} {_bar(metrics['core_recall']):<50} {'':>{w-66}}│")

    print(f"{BOLD}├{sep}┤{RESET}")

    # Token usage
    tok   = token_info
    cost  = tok['cost_usd']
    c_color = GREEN if cost < 0.001 else (YELLOW if cost < 0.005 else RED)
    print(f"│ {CYAN}Tokens{RESET}   in={tok['prompt_tokens']:>5}  out={tok['completion_tokens']:>5}  "
          f"total={tok['total_tokens']:>6}  attempts={tok['attempts']}  "
          f"cost={c_color}${cost:.5f}{RESET}")

    print(f"{BOLD}├{sep}┤{RESET}")

    # TTP breakdown
    tp_str   = _ttp_list(metrics["tp"], GREEN)
    fp_str   = _ttp_list(metrics["fp"], RED)
    fn_str   = _ttp_list(metrics["fn"], YELLOW)
    pred_str = "  ".join(metrics["predicted"]) or "—"

    print(f"│ {BOLD}Predicted {RESET}: {pred_str}")
    print(f"│ {GREEN}✓ Hit     {RESET}: {tp_str}")
    print(f"│ {RED}✗ FP      {RESET}: {fp_str}")
    print(f"│ {YELLOW}△ Missed  {RESET}: {fn_str}")

    print(f"{BOLD}└{sep}┘{RESET}")


def print_summary(results: list[dict], tiers_used: list[str]) -> None:
    w = 90
    sep = "─" * w
    dsep = "═" * w

    print(f"\n{BOLD}╔{dsep}╗{RESET}")
    print(f"{BOLD}║{'BENCHMARK SUMMARY':^{w}}║{RESET}")
    print(f"{BOLD}╠{dsep}╣{RESET}")

    # Header
    print(f"{BOLD}║ {'ID':<8} {'Category':<18} {'P':>6} {'R':>6} {'F1':>6} {'CoreR':>7} "
          f"{'Tok':>7} {'Cost':>9} {'':>{w-79}}║{RESET}")
    print(f"{BOLD}╠{dsep}╣{RESET}")

    total_p = total_r = total_f1 = total_cr = 0.0
    total_tokens = 0
    total_cost   = 0.0

    for r in results:
        m   = r["metrics"]
        tok = r.get("token_info", {})
        eid = r["id"]
        cat = r.get("category", "")[:16]

        p_str  = f"{m['precision']:.3f}"
        r_str  = f"{m['recall']:.3f}"
        f1_str = f"{m['f1']:.3f}"
        cr_str = f"{m['core_recall']:.3f}"

        f1_color = GREEN if m["f1"] >= 0.7 else (YELLOW if m["f1"] >= 0.4 else RED)
        status   = "✓" if m["f1"] >= 0.5 else "✗"
        s_color  = GREEN if m["f1"] >= 0.5 else RED

        t_total = tok.get("total_tokens", 0)
        cost    = tok.get("cost_usd", 0.0)
        c_color = GREEN if cost < 0.001 else (YELLOW if cost < 0.005 else RED)

        print(
            f"║ {s_color}{status}{RESET} {eid:<7} {cat:<18} "
            f"{p_str:>6} {r_str:>6} {f1_color}{f1_str:>6}{RESET} "
            f"{cr_str:>7} {t_total:>7} {c_color}${cost:.5f}{RESET}"
            f"{' ' * max(0, w - 80)}║"
        )

        total_p      += m["precision"]
        total_r      += m["recall"]
        total_f1     += m["f1"]
        total_cr     += m["core_recall"]
        total_tokens += t_total
        total_cost   += cost

    n = len(results)
    avg_p  = total_p  / n if n else 0
    avg_r  = total_r  / n if n else 0
    avg_f1 = total_f1 / n if n else 0
    avg_cr = total_cr / n if n else 0

    print(f"{BOLD}╠{dsep}╣{RESET}")
    print(
        f"{BOLD}║ {'AVERAGE':<8} {'':<18} "
        f"{avg_p:>6.3f} {avg_r:>6.3f} {avg_f1:>6.3f} "
        f"{avg_cr:>7.3f} {total_tokens:>7} ${total_cost:.5f}"
        f"{' ' * max(0, w - 80)}║{RESET}"
    )
    print(f"{BOLD}╠{dsep}╣{RESET}")
    print(f"{BOLD}║ Tiers evaluated : {', '.join(tiers_used):<{w-20}}║{RESET}")
    print(f"{BOLD}║ Total entries   : {n:<{w-20}}║{RESET}")
    print(f"{BOLD}║ Avg F1          : {avg_f1:.3f}{' ' * (w-21)}║{RESET}")
    print(f"{BOLD}║ Avg Core Recall : {avg_cr:.3f}{' ' * (w-21)}║{RESET}")
    print(f"{BOLD}║ Total tokens    : {total_tokens:<{w-20}}║{RESET}")
    print(f"{BOLD}║ Total cost      : ${total_cost:.5f} USD{' ' * (w-28)}║{RESET}")
    print(f"{BOLD}╚{dsep}╝{RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="LangMal Benchmark Runner")
    parser.add_argument("--benchmark",  required=True,  help="Path to benchmark JSON")
    parser.add_argument("--datasets",   required=True,  nargs="+", help="Dataset paths for verifier")
    parser.add_argument("--planner",    default="src/agents/plannerv8.py")
    parser.add_argument("--verifier",   default="src/agents/verifierv8.py")
    parser.add_argument("--tiers",      nargs="+", default=["tier1", "tier2"],
                        choices=["tier1", "tier2", "tier3"])
    parser.add_argument("--cache-dir",  default=".verifier_cache")
    parser.add_argument("--out-dir",    default="artifacts/missions")
    parser.add_argument("--results-dir",default="artifacts/benchmark_results")
    parser.add_argument("--model-pricing", default=DEFAULT_MODEL_PRICING,
                        choices=list(PRICING_TABLE.keys()),
                        help="Model pricing to use for cost calculation (default: gpt-4o-mini)")
    args = parser.parse_args()

    # Activate selected pricing
    global _active_pricing
    _active_pricing = PRICING_TABLE[args.model_pricing]
    price_info = PRICING_TABLE[args.model_pricing]

    # Timestamp for this run
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.out_dir) / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Load benchmark
    benchmark = json.loads(Path(args.benchmark).read_text(encoding="utf-8"))

    # Collect entries from requested tiers
    entries = []
    for tier in args.tiers:
        entries.extend(benchmark.get(tier, []))

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}LangMal Benchmark — {ts}{RESET}")
    print(f"Tiers   : {args.tiers}")
    print(f"Entries : {len(entries)}")
    print(f"Pricing : {args.model_pricing}  "
          f"(in=${price_info['input']}/1M  out=${price_info['output']}/1M)")
    print(f"Run dir : {run_dir}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    all_results = []

    for idx, entry in enumerate(entries, start=1):
        eid    = entry["id"]
        prompt = entry["malgen_input_prompt"]
        selected_ttps = set(entry.get("selected_ttps", []))
        core_ttps     = set(entry.get("core_ttps", []))

        print(f"\n{BOLD}[{idx}/{len(entries)}] {eid}{RESET}")

        # Step 1: Planner
        mission_path = run_planner(args.planner, prompt, run_dir, eid)
        if mission_path is None:
            print(f"  {RED}Skipping {eid} — planner failed{RESET}")
            continue

        # Step 2: Verifier
        verified_path = run_verifier(args.verifier, mission_path, args.datasets, args.cache_dir)
        if verified_path is None:
            print(f"  {RED}Skipping {eid} — verifier failed{RESET}")
            continue

        # Step 3: Evaluate
        predicted  = get_predicted_ttps(verified_path)
        metrics    = evaluate(predicted, selected_ttps, core_ttps)
        token_info = get_token_usage(mission_path)

        result = {
            "id":            eid,
            "category":      entry.get("category", ""),
            "prompt":        prompt,
            "metrics":       metrics,
            "token_info":    token_info,
            "mission_path":  str(mission_path),
            "verified_path": str(verified_path),
        }
        all_results.append(result)

        # Print per-entry result
        print_entry_result(entry, metrics, token_info, idx, len(entries))

    # Print summary table
    if all_results:
        print_summary(all_results, args.tiers)

        # Save results JSON
        results_path = results_dir / f"results_{ts}.json"
        results_path.write_text(
            json.dumps(all_results, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"\n{GREEN}Results saved → {results_path}{RESET}")
    else:
        print(f"\n{RED}No results to report.{RESET}")


if __name__ == "__main__":
    main()