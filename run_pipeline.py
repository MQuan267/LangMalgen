#!/usr/bin/env python3

import subprocess
import argparse
import json
import re
from pathlib import Path


def run_cmd(cmd: str) -> str:
    print(f"\n🚀 {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")

    if result.returncode != 0:
        raise RuntimeError(f"❌ Failed: {cmd}")

    return result.stdout


def parse_tokens(stdout: str):
    prompt = 0
    completion = 0

    m = re.search(r"prompt\s+:\s+([\d,]+)", stdout)
    if m:
        prompt = int(m.group(1).replace(",", ""))

    m = re.search(r"completion\s+:\s+([\d,]+)", stdout)
    if m:
        completion = int(m.group(1).replace(",", ""))

    return prompt, completion


# 🔥 Pricing chuẩn theo ảnh (per 1M tokens)
def compute_cost(prompt, completion, model="gpt-4o"):
    pricing = {
        "gpt-4o": (2.50, 10.00),
        "gpt-4o-mini": (0.15, 0.60),
        "gpt-4.1": (2.00, 8.00),
        "gpt-4.1-mini": (0.40, 1.60),
    }

    p_price, c_price = pricing.get(model, (0, 0))
    return (prompt / 1_000_000) * p_price + (completion / 1_000_000) * c_price


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--intent", required=True)
    args = parser.parse_args()

    intent = args.intent

    print("=" * 60)
    print("🚀 LangMal Pipeline")
    print(f"Intent: {intent}")
    print("=" * 60)

    total_prompt = 0
    total_completion = 0
    total_cost = 0.0

    planner_cost = developer_cost = integrator_cost = 0.0

    # ── 1. Planner ─────────────────────────────
    print("\n[1/4] Planner...")
    run_cmd(
        f'python src/agents/plannerv8.py '
        f'--intent "{intent}" '
        f'--out-dir artifacts/missions'
    )

    missions = sorted(
        Path("artifacts/missions").glob("*.json"),
        key=lambda p: p.stat().st_mtime
    )
    mission_file = missions[-1]
    print(f"📄 Mission: {mission_file}")

    # 🔥 lấy token từ Planner JSON
    with open(mission_file, encoding="utf-8") as f:
        mission_data = json.load(f)

    usage = mission_data.get("planner_summary", {}).get("token_usage", {})

    p = usage.get("prompt_tokens", 0)
    c = usage.get("completion_tokens", 0)

    total_prompt += p
    total_completion += c

    planner_cost = compute_cost(p, c)
    total_cost += planner_cost

    print(f"\n🧠 Planner tokens:")
    print(f"   prompt     : {p:,}")
    print(f"   completion : {c:,}")

    # ── 2. Verifier ────────────────────────────
    print("\n[2/4] Verifier...")
    run_cmd(
        f'python src/agents/verifierv8.py '
        f'--mission "{mission_file}" '
        f'--datasets tram2.jsonl '
        f'--cache-dir .verifier_cache'
    )

    verified = sorted(
        Path("artifacts/missions_verified").glob("*_verified.json"),
        key=lambda p: p.stat().st_mtime
    )
    verified_file = verified[-1]
    print(f"✅ Verified: {verified_file}")

    # ── 3. Developer ───────────────────────────
    print("\n[3/4] Developer...")
    stdout = run_cmd(
        f'python src/agents/developerv8.py --mission "{verified_file}"'
    )

    p, c = parse_tokens(stdout)

    total_prompt += p
    total_completion += c

    developer_cost = compute_cost(p, c)
    total_cost += developer_cost

    print(f"🧠 Developer tokens: {p:,} / {c:,}")

    runtime_dirs = sorted(
        Path("artifacts/modules").glob("runtime_*"),
        key=lambda p: p.stat().st_mtime
    )
    runtime_dir = runtime_dirs[-1]
    manifest = runtime_dir / "manifest.json"

    print(f"📦 Runtime: {runtime_dir}")

    # ── 4. Integrator ──────────────────────────
    print("\n[4/4] Integrator...")
    stdout = run_cmd(
        f'python src/agents/integratorv8.py '
        f'--mission "{verified_file}" '
        f'--manifest "{manifest}"'
    )

    p, c = parse_tokens(stdout)

    total_prompt += p
    total_completion += c

    integrator_cost = compute_cost(p, c)
    total_cost += integrator_cost

    print(f"🧠 Integrator tokens: {p:,} / {c:,}")

    # Latest file
    latest_file = Path("artifacts/latest/latest.py")

    if not latest_file.exists():
        raise RuntimeError("❌ latest/latest.py not found")

    print(f"📄 Latest file: {latest_file}")

    # ── 5. Git push ────────────────────────────
    print("\n[5/5] Git push...")

    run_cmd(f'git add "{latest_file}" -f')
    run_cmd('git commit -m "auto: update latest" || true')
    run_cmd('git push')

    # ── Summary ─────────────────────────────────
    total_tokens = total_prompt + total_completion

    print("\n" + "=" * 60)
    print("🎉 DONE")
    print(f"👉 Latest file: {latest_file}")

    print("\n💰 TOKEN USAGE SUMMARY")
    print("-" * 60)

    print(f"{'Prompt tokens':<25}: {total_prompt:>10,}")
    print(f"{'Completion tokens':<25}: {total_completion:>10,}")
    print(f"{'Total tokens':<25}: {total_tokens:>10,}")
    print(f"{'Estimated cost':<25}: ${total_cost:>10.4f}")

    print("-" * 60)

    print("\n📊 COST BY STAGE")
    print("-" * 60)
    print(f"{'Planner':<25}: ${planner_cost:>10.4f}")
    print(f"{'Developer':<25}: ${developer_cost:>10.4f}")
    print(f"{'Integrator':<25}: ${integrator_cost:>10.4f}")

    print("=" * 60)


if __name__ == "__main__":
    main()