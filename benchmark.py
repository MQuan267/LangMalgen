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

TRAM2_DATASET  = "tram2.jsonl"
ATTACK_DATASET = "attack_procedures.jsonl"

CACHE_DIR = ".verifier_cache"
MISSIONS_DIR = "artifacts/missions"

OUTPUT_JSON = "benchmark_resultsv5.json"
OUTPUT_CSV = "benchmark_resultsv5.csv"


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
        "f1",
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
            round(r["precision"], 4),
            round(r["recall"], 4),
            round(r["f1"], 4),
            len(r["predicted"]),
            len(r["truth"]),
            len(r["overlap"]),
            ";".join(r["predicted"]),
            ";".join(r["truth"]),
            ";".join(r["overlap"]),
        ]
        lines.append(",".join(map(str, row)))

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")


def print_summary_table(results: List[Dict[str, Any]]) -> None:
    # Header
    col_case     = 4
    col_category = 20
    col_title    = 45
    col_prec     = 9
    col_rec      = 9
    col_f1       = 9
    col_pred     = 7
    col_truth    = 7
    col_overlap  = 9

    sep = (
        "+" + "-" * (col_case + 2)
        + "+" + "-" * (col_category + 2)
        + "+" + "-" * (col_title + 2)
        + "+" + "-" * (col_prec + 2)
        + "+" + "-" * (col_rec + 2)
        + "+" + "-" * (col_f1 + 2)
        + "+" + "-" * (col_pred + 2)
        + "+" + "-" * (col_truth + 2)
        + "+" + "-" * (col_overlap + 2)
        + "+"
    )

    def row(case, cat, title, prec, rec, f1, pred, truth, ovlp):
        return (
            f"| {str(case):<{col_case}} "
            f"| {str(cat):<{col_category}} "
            f"| {str(title):<{col_title}} "
            f"| {str(prec):<{col_prec}} "
            f"| {str(rec):<{col_rec}} "
            f"| {str(f1):<{col_f1}} "
            f"| {str(pred):<{col_pred}} "
            f"| {str(truth):<{col_truth}} "
            f"| {str(ovlp):<{col_overlap}} |"
        )

    print("\n" + sep)
    print(row("Case", "Category", "Document Title", "Precision", "Recall", "F1", "#Pred", "#Truth", "#Overlap"))
    print(sep)

    for r in results:
        title = r["doc_title"][:col_title]
        print(row(
            r["case"],
            r["category"][:col_category],
            title,
            f"{r['precision']:.3f}",
            f"{r['recall']:.3f}",
            f"{r['f1']:.3f}",
            len(r["predicted"]),
            len(r["truth"]),
            len(r["overlap"]),
        ))

    print(sep)

    # Tính avg
    avg_p  = sum(r["precision"] for r in results) / len(results)
    avg_r  = sum(r["recall"]    for r in results) / len(results)
    avg_f1 = sum(r["f1"]        for r in results) / len(results)
    avg_pred  = sum(len(r["predicted"]) for r in results) / len(results)
    avg_truth = sum(len(r["truth"])     for r in results) / len(results)
    avg_ovlp  = sum(len(r["overlap"])   for r in results) / len(results)

    print(row(
        "AVG",
        "",
        "",
        f"{avg_p:.3f}",
        f"{avg_r:.3f}",
        f"{avg_f1:.3f}",
        f"{avg_pred:.1f}",
        f"{avg_truth:.1f}",
        f"{avg_ovlp:.1f}",
    ))
    print(sep)


def print_category_table(results: List[Dict[str, Any]]) -> None:
    from collections import defaultdict

    cat_data: Dict[str, List] = defaultdict(list)
    for r in results:
        cat_data[r["category"]].append(r)

    col_cat  = 20
    col_n    = 6
    col_prec = 9
    col_rec  = 9
    col_f1   = 9

    sep = (
        "+" + "-" * (col_cat + 2)
        + "+" + "-" * (col_n + 2)
        + "+" + "-" * (col_prec + 2)
        + "+" + "-" * (col_rec + 2)
        + "+" + "-" * (col_f1 + 2)
        + "+"
    )

    def row(cat, n, prec, rec, f1):
        return (
            f"| {str(cat):<{col_cat}} "
            f"| {str(n):<{col_n}} "
            f"| {str(prec):<{col_prec}} "
            f"| {str(rec):<{col_rec}} "
            f"| {str(f1):<{col_f1}} |"
        )

    print("\n\nKết quả theo loại malware:")
    print(sep)
    print(row("Category", "Cases", "Precision", "Recall", "F1"))
    print(sep)

    for cat, items in sorted(cat_data.items()):
        ap = sum(r["precision"] for r in items) / len(items)
        ar = sum(r["recall"]    for r in items) / len(items)
        af = sum(r["f1"]        for r in items) / len(items)
        print(row(cat, len(items), f"{ap:.3f}", f"{ar:.3f}", f"{af:.3f}"))

    print(sep)


def main():
    dataset = load_json(DATASET_FILE)

    results: List[Dict[str, Any]] = []
    global_techniques: Set[str] = set()

    print("\n========== LangMal Benchmark ==========\n")

    for idx, item in enumerate(dataset, start=1):

        intent = item["intent"]
        truth  = set(item.get("labels", []))

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
                "--mission",   mission_file,
                "--datasets",  TRAM2_DATASET,
                "--cache-dir", CACHE_DIR,
            ],
            check=True
        )

        verified_file = mission_file.replace(".json", "_verified.json")
        verified      = load_json(verified_file)
        predicted     = collect_predicted_techniques(verified)
        overlap       = predicted & truth

        global_techniques.update(predicted)

        precision = len(overlap) / max(len(predicted), 1)
        recall    = len(overlap) / max(len(truth),     1)
        f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        print("Predicted:", sorted(predicted))
        print("Truth:",     sorted(truth))
        print("Overlap:",   sorted(overlap))
        print(f"Precision: {precision:.3f} | Recall: {recall:.3f} | F1: {f1:.3f}")

        results.append({
            "case":      idx,
            "doc_title": item.get("doc_title", ""),
            "category":  item.get("category",  ""),
            "predicted": sorted(predicted),
            "truth":     sorted(truth),
            "overlap":   sorted(overlap),
            "precision": precision,
            "recall":    recall,
            "f1":        f1,
        })

    # ---- Summary ----
    avg_precision = sum(r["precision"] for r in results) / len(results)
    avg_recall    = sum(r["recall"]    for r in results) / len(results)
    avg_f1        = sum(r["f1"]        for r in results) / len(results)

    summary = {
        "n_cases":                   len(results),
        "avg_precision":             avg_precision,
        "avg_recall":                avg_recall,
        "avg_f1":                    avg_f1,
        "technique_diversity":       len(global_techniques),
        "unique_predicted_techniques": sorted(global_techniques),
        "results":                   results,
    }

    Path(OUTPUT_JSON).write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    write_csv(results, OUTPUT_CSV)

    # ---- In bảng ----
    print_summary_table(results)
    print_category_table(results)

    print(f"\n{'='*50}")
    print(f"  Average Precision : {avg_precision:.3f}")
    print(f"  Average Recall    : {avg_recall:.3f}")
    print(f"  Average F1        : {avg_f1:.3f}")
    print(f"  Technique Diversity: {len(global_techniques)}")
    print(f"{'='*50}")
    print(f"\nSaved → {OUTPUT_JSON}")
    print(f"Saved → {OUTPUT_CSV}")


if __name__ == "__main__":
    main()