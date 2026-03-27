"""
Fetch ATT&CK Enterprise procedure examples và convert sang JSONL
dùng để bổ sung vào dataset cho Verifier index.

Chạy: python fetch_attack_procedures.py
Output: attack_procedures.jsonl
"""

import json
import urllib.request
from pathlib import Path

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_FILE = "attack_procedures.jsonl"

# 50 techniques có trong TRAM2 dataset
TRAM2_TECHNIQUES = {
    "T1003.001", "T1005", "T1012", "T1016", "T1021.001",
    "T1027", "T1033", "T1036.005", "T1041", "T1047",
    "T1053.005", "T1055", "T1056.001", "T1057", "T1059.003",
    "T1068", "T1070.004", "T1071.001", "T1072", "T1074.001",
    "T1078", "T1082", "T1083", "T1090", "T1095",
    "T1105", "T1106", "T1110", "T1112", "T1113",
    "T1140", "T1190", "T1204.002", "T1210", "T1218.011",
    "T1219", "T1484.001", "T1518.001", "T1543.003", "T1547.001",
    "T1548.002", "T1552.001", "T1557.001", "T1562.001", "T1564.001",
    "T1566.001", "T1569.002", "T1570", "T1573.001", "T1574.002",
}


def get_technique_id(obj):
    """Extract technique ID từ external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def fetch_attack_data(url):
    print(f"Downloading ATT&CK data from MITRE...")
    with urllib.request.urlopen(url) as response:
        data = json.loads(response.read().decode("utf-8"))
    print(f"Downloaded. Total objects: {len(data['objects'])}")
    return data


def extract_technique_descriptions(data):
    """Extract technique name + description cho các techniques trong TRAM2."""
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        tid = get_technique_id(obj)
        if tid not in TRAM2_TECHNIQUES:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "").strip()

        if not description:
            continue

        # Lấy description chính (bỏ markdown links)
        import re
        description = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description)
        description = re.sub(r"\(Citation:[^\)]+\)", "", description)
        description = " ".join(description.split())

        if len(description) > 50:
            results.append({
                "text": f"{name}: {description[:500]}",
                "technique_id": tid,
                "source": "attack_description"
            })

    print(f"Extracted {len(results)} technique descriptions")
    return results


def extract_procedure_examples(data):
    """Extract procedure examples (real-world usage) từ relationships."""
    # Build map: technique_id → technique_name
    technique_map = {}
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        tid = get_technique_id(obj)
        if tid in TRAM2_TECHNIQUES:
            technique_map[obj["id"]] = tid

    # Extract relationships (use → technique)
    results = []
    for obj in data["objects"]:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue

        target_ref = obj.get("target_ref", "")
        if target_ref not in technique_map:
            continue

        tid = technique_map[target_ref]
        description = obj.get("description", "").strip()

        if not description or len(description) < 30:
            continue

        # Clean markdown
        import re
        description = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", description)
        description = re.sub(r"\(Citation:[^\)]+\)", "", description)
        description = " ".join(description.split())

        if len(description) > 30:
            results.append({
                "text": description[:400],
                "technique_id": tid,
                "source": "attack_procedure"
            })

    print(f"Extracted {len(results)} procedure examples")
    return results


def main():
    # Download ATT&CK data
    data = fetch_attack_data(ATTACK_URL)

    # Extract descriptions + procedures
    descriptions = extract_technique_descriptions(data)
    procedures = extract_procedure_examples(data)

    all_examples = descriptions + procedures

    # Deduplicate
    seen = set()
    unique = []
    for ex in all_examples:
        key = (ex["text"][:100], ex["technique_id"])
        if key not in seen:
            seen.add(key)
            unique.append(ex)

    print(f"\nTotal unique examples: {len(unique)}")

    # Phân bố theo technique
    from collections import Counter
    counter = Counter(ex["technique_id"] for ex in unique)
    print(f"Techniques covered: {len(counter)}")
    print("\nTop 10:")
    for tid, count in counter.most_common(10):
        print(f"  {tid}: {count}")
    print("\nBottom 10:")
    for tid, count in counter.most_common()[:-11:-1]:
        print(f"  {tid}: {count}")

    # Lưu ra file
    out = Path(OUTPUT_FILE)
    with open(out, "w", encoding="utf-8") as f:
        for ex in unique:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"\nSaved {len(unique)} examples → {OUTPUT_FILE}")
    print("\nBước tiếp theo:")
    print("  python build_verifier_index.py \\")
    print("    --datasets tram2.jsonl attack_procedures.jsonl \\")
    print("    --cache-dir .verifier_cache \\")
    print("    --rep-per-technique 200")


if __name__ == "__main__":
    main()