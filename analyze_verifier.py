import json
from pathlib import Path

with_path = Path("results/with_verifier/results.json")
no_path   = Path("results/no_verifier/results.json")

with_data = json.loads(with_path.read_text(encoding="utf-8"))
no_data   = json.loads(no_path.read_text(encoding="utf-8"))

with_samples = {s["sample_id"]: s for s in with_data["samples"]}
no_samples   = {s["sample_id"]: s for s in no_data["samples"]}

rows = []
total_ta = total_fa = total_tr = total_fr = 0

for sid in sorted(with_samples):
    w = with_samples[sid]
    n = no_samples.get(sid)
    if n is None:
        continue

    gt = set(w["ground_truth_tram2"])
    p  = set(n["predicted_ttps"])   # Planner / no verifier
    v  = set(w["predicted_ttps"])   # With verifier

    true_accept  = v & gt
    false_accept = v - gt
    true_reject  = (p - v) - gt
    false_reject = (p & gt) - v

    total_ta += len(true_accept)
    total_fa += len(false_accept)
    total_tr += len(true_reject)
    total_fr += len(false_reject)

    rows.append({
        "sample_id":   sid,
        "GT":          sorted(gt),
        "Planner":     sorted(p),
        "Verifier":    sorted(v),
        "True Accept":  sorted(true_accept),
        "False Accept": sorted(false_accept),
        "True Reject":  sorted(true_reject),
        "False Reject": sorted(false_reject),
        "TA_count": len(true_accept),
        "FA_count": len(false_accept),
        "TR_count": len(true_reject),
        "FR_count": len(false_reject),
    })

print("\nPer-case Verifier Error Analysis")
print("=" * 80)

for r in rows:
    print(f"\nCase {r['sample_id']}")
    print(f"  GT       : {r['GT']}")
    print(f"  Planner  : {r['Planner']}")
    print(f"  Verifier : {r['Verifier']}")
    print(f"  TA={r['TA_count']} FA={r['FA_count']} TR={r['TR_count']} FR={r['FR_count']}")
    print(f"  False Accept : {r['False Accept']}")
    print(f"  False Reject : {r['False Reject']}")

print("\nSummary")
print("=" * 80)
print(f"True Accept  : {total_ta}")
print(f"False Accept : {total_fa}")
print(f"True Reject  : {total_tr}")
print(f"False Reject : {total_fr}")

precision_accept = total_ta / (total_ta + total_fa) if total_ta + total_fa else 0
reject_quality   = total_tr / (total_tr + total_fr) if total_tr + total_fr else 0
net              = total_ta - total_fa

print(f"\nVerifier Accept Precision : {precision_accept:.4f}")
print(f"Verifier Reject Quality   : {reject_quality:.4f}")
print(f"Net Contribution (TA-FA)  : {net:+d}")