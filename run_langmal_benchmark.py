from __future__ import annotations

import glob
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set

DATASET_FILE = "tram2_langmal_25intents.json"

PLANNER_PATH = "src/agents/plannerv7.py"
VERIFIER_PATH = "src/agents/verifierv8.py"

TRAM2_DATASET = "tram2.jsonl"

CACHE_DIR = ".verifier_cache"
MISSIONS_DIR = "artifacts/missions"

OUTPUT_JSON = "benchmark_resultsv4.json"
OUTPUT_CSV = "benchmark_resultsv4.csv"


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def latest_json_file(folder: str) -> str:
    files = sorted(
        glob.glob(os.path.join(folder, "*.json")),
        key=os.path.getmtime,
    )
    if not files:
        raise FileNotFoundError(f"No json files found in {folder}")
    return files[-1]


def collect_predicted_techniques(mission: Dict[str, Any]) -> Set[str]:
    predicted: Set[str] = set()
    for task in mission.get("execution_graph", []):
        predicted.update(task.get("mitre_techniques", []))
    return predicted


def write_csv(results: List[Dict[str, Any]], out_path: str) -> None:
    headers = [
        "case",
        "category",
        "doc_title",
        "precision",
        "recall",
        "n_predicted",
        "n_truth",
        "n_overlap",
        "predicted",
        "truth",
        "overlap",
    ]

    lines = [",".join(headers)]

    for r in results:
        row = [
            r["case"],
            r["category"],
            r["doc_title"],
            r["precision"],
            r["recall"],
            len(r["predicted"]),
            len(r["truth"]),
            len(r["overlap"]),
            ";".join(r["predicted"]),
            ";".join(r["truth"]),
            ";".join(r["overlap"]),
        ]

        lines.append(",".join(map(str, row)))

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")


def main():

    dataset = load_json(DATASET_FILE)

    results: List[Dict[str, Any]] = []
    global_techniques: Set[str] = set()

    print("\n========== LangMal Benchmark ==========\n")

    for idx, item in enumerate(dataset, start=1):

        intent = item["intent"]
        truth = set(item.get("labels", []))

        print(f"\n===== CASE {idx} =====")
        print("Intent:", intent)

        # ---- planner ----
        subprocess.run(
            ["python", PLANNER_PATH, "--intent", intent],
            check=True
        )

        mission_file = latest_json_file(MISSIONS_DIR)

        # ---- verifier ----
        subprocess.run(
            [
                "python",
                VERIFIER_PATH,
                "--mission",
                mission_file,
                "--datasets",
                TRAM2_DATASET,
                "--cache-dir",
                CACHE_DIR,
            ],
            check=True
        )

        verified_file = mission_file.replace(".json", "_verified.json")

        verified = load_json(verified_file)

        predicted = collect_predicted_techniques(verified)

        overlap = predicted & truth

        global_techniques.update(predicted)

        precision = len(overlap) / max(len(predicted), 1)
        recall = len(overlap) / max(len(truth), 1)

        print("Predicted:", sorted(predicted))
        print("Truth:", sorted(truth))
        print("Overlap:", sorted(overlap))

        print(f"Precision: {precision:.3f}")
        print(f"Recall: {recall:.3f}")

        results.append({
            "case": idx,
            "doc_title": item.get("doc_title", ""),
            "category": item.get("category", ""),
            "predicted": sorted(predicted),
            "truth": sorted(truth),
            "overlap": sorted(overlap),
            "precision": precision,
            "recall": recall,
        })

    avg_precision = sum(r["precision"] for r in results) / len(results)
    avg_recall = sum(r["recall"] for r in results) / len(results)

    summary = {
        "n_cases": len(results),
        "avg_precision": avg_precision,
        "avg_recall": avg_recall,
        "technique_diversity": len(global_techniques),
        "unique_predicted_techniques": sorted(global_techniques),
        "results": results,
    }

    Path(OUTPUT_JSON).write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8"
    )

    write_csv(results, OUTPUT_CSV)

    print("\n========== SUMMARY ==========")

    print(f"Average Precision: {avg_precision:.3f}")
    print(f"Average Recall: {avg_recall:.3f}")
    print(f"Technique Diversity: {len(global_techniques)}")

    print(f"\nSaved JSON: {OUTPUT_JSON}")
    print(f"Saved CSV: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()