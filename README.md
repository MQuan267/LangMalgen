# Improving TTP Alignment in LLM-Based Malware Artifact Generation via Hybrid Verification

> **Safe simulation for defensive research.** Generated artifacts are handled only inside isolated sandboxes; this project is intended solely for controlled malware-generation and detection-evaluation research (red-team simulation, adversarial robustness testing, defensive benchmarking).

## Overview

This project extends the MalGEN multi-agent architecture with a TTP-conditioned **Hybrid Verifier** placed between the Planner and Developer stages. Before code synthesis, candidate MITRE ATT&CK techniques are scored using planner confidence, attack-stage compatibility, semantic similarity, dataset-supported evidence, and rule-based adjustments; only verified techniques are forwarded to code generation. Built artifacts are subsequently analyzed in a CAPEv2 sandbox and submitted to VirusTotal.

The pipeline consists of four agent scripts run in sequence:

```
Planner (plannerv8.py) → Verifier (verifierv8.py) → Developer (developerv8.py) → Integrator (integratorv8.py)
```

Each stage is a standalone script under `src/agents/`, chained together by `run_pipeline.py` (single intent) or `run_batch.py` (full benchmark with ablation).

LLM calls go through the OpenAI-compatible Chat Completions API, so the same scripts run on either:
- **OpenAI** (e.g., `gpt-4o`)
- **DeepSeek** (via an OpenAI-compatible endpoint — set `OPENAI_BASE_URL` accordingly)

switching backends only requires changing `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` in `.env`.

## 1) Requirements

- Ubuntu / Debian-based system
- Python 3.10+ (3.12 recommended)
- `pyinstaller` (optional, only needed to build standalone executables via `build_artifacts.py`)

```bash
sudo apt update
sudo apt install python3-pip -y
sudo ln -s /usr/bin/pip3 /usr/bin/pip
```

## 2) Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 3) Environment configuration

Create a `.env` file in the project root:

```bash
# --- OpenAI ---
OPENAI_API_KEY=sk-xxx
OPENAI_MODEL=gpt-4o
OPENAI_BASE_URL=https://api.openai.com/v1

# --- DeepSeek (OpenAI-compatible) ---
# To run DeepSeek instead, point the same client at DeepSeek's endpoint/model:
# OPENAI_API_KEY=sk-deepseek-xxx
# OPENAI_MODEL=deepseek-chat
# OPENAI_BASE_URL=https://api.deepseek.com/v1
```

`plannerv8.py`, `developerv8.py`, and `integratorv8.py` all read `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` directly from the environment — there is no separate `--agent-stack` flag; the backend is selected purely by these three variables.

## 4) Running a single intent

```bash
source .venv/bin/activate
set -a; . ./.env; set +a

python run_pipeline.py --intent "Collect OS and user information and save locally (SAFE MOCK)"
```

`run_pipeline.py` runs Planner → Verifier → Developer → Integrator in sequence, reading each stage's output from `artifacts/` and printing token usage and estimated cost per stage. The final integrated artifact is written to `artifacts/latest/latest.py`.

To run the same intent with DeepSeek, set the DeepSeek values in `.env` and run the same command — no code or flag changes needed.

## 5) Running the full benchmark (ablation)

```bash
# With Hybrid Verifier
python run_batch.py --benchmark benchmark.json --mode with_verifier

# Without Hybrid Verifier (ablation baseline)
python run_batch.py --benchmark benchmark.json --mode no_verifier

# Both, with delta-F1 comparison
python run_batch.py --benchmark benchmark.json --mode compare
```

Useful flags: `--ids 1 2 3` to run a subset of cases, `--skip-pipeline` to re-score existing outputs without re-running the LLM stages, `--out-dir` to change the results directory (default `results/`), `--delay` to throttle requests between cases.

Outputs:
- `results/with_verifier/`, `results/no_verifier/` — per-case artifacts and scores
- `results/ablation_compare.csv`, `results/ablation_compare.json` — with/without-verifier comparison (mode `compare`)

Run the batch once against OpenAI and once against DeepSeek (by swapping `.env` between runs) to reproduce the two-backend comparison reported in the paper.

## 6) Building executables (optional)

```bash
python build_artifacts.py --results-dir results --mode with_verifier
python build_artifacts.py --results-dir results --mode no_verifier
```

Packages each `caseXX_artifact.py` under `results/<mode>/per_case/` into a standalone executable with PyInstaller, written to `artifacts/build/<mode>/`.

## 7) Analysis and reporting

```bash
python report_tables.py                 # result tables (Macro-F1, TA/FA/TR/FR, etc.)
python analyze_verifier.py               # verifier ablation analysis (OpenAI runs)
python analyze_verifier_deepseek.py      # verifier ablation analysis (DeepSeek runs)
```

## Repository layout

```
├─ src/agents/            # plannerv8.py, verifierv8.py, developerv8.py, integratorv8.py, builderv1.py
├─ src/data/              # tram2.jsonl and TRAM2-derived benchmark files used by the Verifier
├─ run_pipeline.py        # single-intent end-to-end run
├─ run_batch.py           # benchmark runner with with/no-verifier ablation
├─ build_artifacts.py     # PyInstaller packaging of per-case artifacts
├─ report_tables.py       # result table generation
├─ analyze_verifier*.py   # verifier ablation analysis
├─ benchmark.json / test_split.json  # evaluation benchmark and held-out split
└─ artifacts/, results/, logs/       # pipeline outputs (generated at runtime)
```

## Safety notes

- All generated artifacts are for controlled, sandboxed research only — no real system calls or network exfiltration are intended in the mock providers used by generated code.
- Network egress and OS introspection are governed by `configs/policy.yaml`; do not disable these controls outside a sandboxed research environment.
