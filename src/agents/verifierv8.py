from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np


@dataclass
class CandidateScore:
    technique_id: str
    score: float
    support_count: int
    reasons: List[str] = field(default_factory=list)
    source: str = "candidate_rerank"


def _norm(vec: np.ndarray) -> np.ndarray:
    denom = np.linalg.norm(vec, axis=1, keepdims=True) + 1e-12
    return vec / denom


def _cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return _norm(a) @ _norm(b).T


def _hash_paths(paths: List[str]) -> str:
    raw = "||".join(sorted(str(Path(p).resolve()) for p in paths))
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:12]


def _task_text(task: Dict[str, Any], mission_intent: str = "", use_stage: bool = True) -> str:
    parts = []
    if mission_intent:
        parts.append(f"mission: {mission_intent}")
    if use_stage:
        parts.append(f"stage: {task.get('stage', '')}")
    parts.append(f"intent: {task.get('intent', '')}")
    parts.append(f"goal: {task.get('behavioral_goal', '')}")
    return " | ".join(parts).strip()


def _topk_indices_desc(scores: np.ndarray, k: int) -> np.ndarray:
    if len(scores) == 0:
        return np.array([], dtype=np.int64)
    k = min(k, len(scores))
    idx = np.argpartition(-scores, k - 1)[:k]
    return idx[np.argsort(-scores[idx])]


class SciBERTEncoder:
    def __init__(self, model_name: str = "allenai/scibert_scivocab_uncased") -> None:
        from transformers import AutoModel, AutoTokenizer
        import torch
        torch.set_num_threads(4)
        torch.set_num_interop_threads(1)
        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True, local_files_only=True)
        self.model = AutoModel.from_pretrained(model_name, local_files_only=True)
        self.model.to(self.device)
        self.model.eval()

    def encode(self, texts: List[str], batch_size: int = 4, max_length: int = 128) -> np.ndarray:
        vecs = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            toks = self.tokenizer(batch, padding=True, truncation=True, max_length=max_length, return_tensors="pt")
            toks = {k: v.to(self.device) for k, v in toks.items()}
            with self.torch.no_grad():
                out = self.model(**toks)
                hidden = out.last_hidden_state
                mask = toks["attention_mask"].unsqueeze(-1)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
                vecs.append(pooled.detach().cpu().numpy().astype(np.float32))
        return np.vstack(vecs) if vecs else np.zeros((0, 768), dtype=np.float32)


class VerifierIndex:
    def __init__(self, dataset_paths: List[str], cache_dir: str = ".verifier_cache") -> None:
        dataset_hash = _hash_paths(dataset_paths)
        cache_root = Path(cache_dir)
        emb_path = cache_root / f"examples_{dataset_hash}.npy"
        meta_path = cache_root / f"examples_{dataset_hash}.meta.json"
        centroids_path = cache_root / f"tech_centroids_{dataset_hash}.npz"
        if not emb_path.exists() or not meta_path.exists() or not centroids_path.exists():
            raise FileNotFoundError("Verifier index not found. Run build_verifier_index.py first.")
        self.example_emb = np.load(emb_path).astype(np.float32)
        self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.centroid_npz = np.load(centroids_path)
        self.examples = self.meta["examples"]
        self.examples_by_tid = self.meta["examples_by_tid"]
        self.representative_indices = self.meta["representative_indices"]
        self.stage_hints = {tid: set(v) for tid, v in self.meta["stage_hints"].items()}
        self.technique_ids = self.meta["technique_ids"]
        self.technique_centroids = {tid: self.centroid_npz[tid].astype(np.float32) for tid in self.technique_ids}

    def stage_compatible_techniques(self, stage: str) -> List[str]:
        stage = stage.strip().lower()
        if not stage:
            return self.technique_ids
        out = []
        for tid in self.technique_ids:
            hints = self.stage_hints.get(tid, set())
            if not hints or stage in hints:
                out.append(tid)
        return out or self.technique_ids

    def representative_example_rows(self, tid: str) -> List[int]:
        return self.representative_indices.get(tid, self.examples_by_tid.get(tid, []))


class SciBERTDatasetVerifierV8:
    def __init__(self, dataset_paths, encoder_backend="scibert",
                 model_name="allenai/scibert_scivocab_uncased",
                 candidate_top_k_examples=5, accept_threshold=0.62,
                 ambiguity_gap=0.06, weak_candidate_threshold=0.52,
                 fallback_top_k_techniques=5, cache_dir=".verifier_cache") -> None:
        if encoder_backend != "scibert":
            raise ValueError("v8 is intended for scibert backend only")
        self.encoder = SciBERTEncoder(model_name=model_name)
        self.index = VerifierIndex(dataset_paths=dataset_paths, cache_dir=cache_dir)
        self.candidate_top_k_examples = candidate_top_k_examples
        self.accept_threshold = accept_threshold
        self.ambiguity_gap = ambiguity_gap
        self.weak_candidate_threshold = weak_candidate_threshold
        self.fallback_top_k_techniques = fallback_top_k_techniques

    def _planner_candidate_ids(self, task):
        out = []
        for cand in task.get("mitre_candidates", []) or []:
            tid = cand.get("id")
            if isinstance(tid, str) and tid.strip():
                out.append(tid.strip())
        return list(dict.fromkeys(out))

    def _score_tids(self, task_emb, tids, source):
        scored = []
        for tid in tids:
            rep_idxs = self.index.representative_example_rows(tid)
            if not rep_idxs:
                continue
            ex_emb = self.index.example_emb[rep_idxs]
            sims = _cosine(task_emb, ex_emb)[0]
            order = _topk_indices_desc(sims, self.candidate_top_k_examples)
            top_scores = sims[order]
            top_rows = [rep_idxs[j] for j in order]
            score = float(np.mean(top_scores)) if len(top_scores) else 0.0
            reasons = [f"{self.index.examples[row]['source']}: {self.index.examples[row]['text'][:140]}" for row in top_rows]
            support_count = len(self.index.examples_by_tid.get(tid, []))
            scored.append(CandidateScore(technique_id=tid, score=score, support_count=support_count, reasons=reasons, source=source))
        scored.sort(key=lambda x: (x.score, x.support_count), reverse=True)
        return scored

    def _fallback_retrieve(self, task_emb, stage):
        pool = self.index.stage_compatible_techniques(stage)
        centroid_matrix = np.vstack([self.index.technique_centroids[tid] for tid in pool]).astype(np.float32)
        sims = _cosine(task_emb, centroid_matrix)[0]
        order = _topk_indices_desc(sims, self.fallback_top_k_techniques)
        top_tids = [pool[i] for i in order]
        return self._score_tids(task_emb, top_tids, source="fallback_retrieval")

    def _decide(self, scored):
        if not scored:
            return [], "unmapped", "low", "no candidates to verify", []

        top1 = scored[0]
        top2 = scored[1] if len(scored) > 1 else None

        debug_scores = [{"technique_id": s.technique_id, "score": round(s.score, 4),
                         "support_count": s.support_count, "source": s.source,
                         "top_reasons": s.reasons[:3]} for s in scored]

        if top1.score < self.accept_threshold:
            return [], "unmapped", "low", "dataset evidence below acceptance threshold", debug_scores

        final_tids = [top1.technique_id]
        note = f"verified via {top1.source} against {top1.support_count} examples"

        known_overlap_pairs = {
            frozenset({"T1041", "T1071.001"}),
            frozenset({"T1547.001", "T1053.005"}),
            frozenset({"T1548", "T1134.001"}),
        }

        if top2:
            close_scores = abs(top1.score - top2.score) <= self.ambiguity_gap
            both_strong = top2.score >= self.accept_threshold
            known_overlap = frozenset({top1.technique_id, top2.technique_id}) in known_overlap_pairs
            both_from_candidates = (top1.source == "candidate_rerank" and top2.source == "candidate_rerank")

            if both_strong and (known_overlap or (close_scores and both_from_candidates)):
                final_tids.append(top2.technique_id)
                note = (f"multi-label verified via {top1.source}/{top2.source}; "
                        f"top candidates both supported ({top1.technique_id}, {top2.technique_id})")

        if top1.score >= 0.80:
            confidence = "high"
        elif top1.score >= 0.68:
            confidence = "medium"
        else:
            confidence = "low"

        if len(final_tids) >= 2:
            confidence = "medium"

        if len(final_tids) == 2 and top2 and abs(top1.score - top2.score) <= self.ambiguity_gap:
            note += " | scores are close but both retained as final techniques"

        return final_tids, "verified", confidence, note, debug_scores

    def verify_mission(self, mission):
        out = deepcopy(mission)
        mission_intent = str(out.get("normalized_intent") or out.get("original_intent") or out.get("intent", ""))
        reports = []

        for task in out.get("execution_graph", []):
            stage = str(task.get("stage", "")).strip().lower()

            if stage == "data-processing":
                task["mitre_techniques"] = []
                task["mitre_status"] = "not_applicable"
                task["mapping_confidence"] = "high"
                existing_note = str(task.get("ambiguity_notes", "") or "").strip()
                task["ambiguity_notes"] = f"{existing_note} | data-processing task; no MITRE verification required".strip(" |")
                reports.append({"task_id": task.get("task_id"), "stage": task.get("stage"),
                                 "intent": task.get("intent"), "behavioral_goal": task.get("behavioral_goal"),
                                 "final_mitre_techniques": [], "mitre_status": "not_applicable",
                                 "mapping_confidence": "high", "candidate_scores": []})
                continue

            task_text = _task_text(task, mission_intent=mission_intent)
            task_emb = self.encoder.encode([task_text], batch_size=1, max_length=128)
            planner_candidate_ids = self._planner_candidate_ids(task)
            scored = self._score_tids(task_emb, planner_candidate_ids, source="candidate_rerank")

            need_fallback = (not scored or (scored and scored[0].score < self.weak_candidate_threshold))

            if need_fallback:
                fallback_scored = self._fallback_retrieve(task_emb, stage=stage)
                merged = {s.technique_id: s for s in scored}
                for fs in fallback_scored:
                    cur = merged.get(fs.technique_id)
                    if cur is None or fs.score > cur.score:
                        merged[fs.technique_id] = fs
                scored = sorted(merged.values(), key=lambda x: (x.score, x.support_count), reverse=True)

            final_tids, mitre_status, confidence, note, debug_scores = self._decide(scored)

            task["mitre_techniques"] = final_tids
            task["mitre_status"] = mitre_status
            task["mapping_confidence"] = confidence
            existing_note = str(task.get("ambiguity_notes", "") or "").strip()
            task["ambiguity_notes"] = f"{existing_note} | {note}".strip(" |")

            reports.append({"task_id": task.get("task_id"), "stage": task.get("stage"),
                             "intent": task.get("intent"), "behavioral_goal": task.get("behavioral_goal"),
                             "planner_candidate_ids": planner_candidate_ids,
                             "final_mitre_techniques": final_tids, "mitre_status": mitre_status,
                             "mapping_confidence": confidence, "candidate_scores": debug_scores})

        out["verifier_summary"] = {
            "backend": "SciBERTEncoder",
            "dataset_example_count": self.index.meta["example_count"],
            "technique_count": len(self.index.technique_ids),
            "mode": "offline_indexed_candidate_reranking_with_fallback_retrieval",
            "rep_per_technique": self.index.meta["rep_per_technique"],
        }
        out["verifier_task_reports"] = reports
        return out


def main() -> None:
    parser = argparse.ArgumentParser(description="SciBERT Verifier v8")
    parser.add_argument("--mission", required=True)
    parser.add_argument("--datasets", required=True, nargs="+")
    parser.add_argument("--backend", choices=["scibert"], default="scibert")
    parser.add_argument("--model-name", default="allenai/scibert_scivocab_uncased")
    parser.add_argument("--accept-threshold", type=float, default=0.62)
    parser.add_argument("--ambiguity-gap", type=float, default=0.06)
    parser.add_argument("--weak-candidate-threshold", type=float, default=0.52)
    parser.add_argument("--fallback-top-k-techniques", type=int, default=5)
    parser.add_argument("--cache-dir", default=".verifier_cache")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    mission = json.loads(Path(args.mission).read_text(encoding="utf-8"))

    verifier = SciBERTDatasetVerifierV8(
        dataset_paths=args.datasets,
        encoder_backend=args.backend,
        model_name=args.model_name,
        accept_threshold=args.accept_threshold,
        ambiguity_gap=args.ambiguity_gap,
        weak_candidate_threshold=args.weak_candidate_threshold,
        fallback_top_k_techniques=args.fallback_top_k_techniques,
        cache_dir=args.cache_dir,
    )

    verified = verifier.verify_mission(mission)

    out_path = (
        Path(args.out) if args.out
        else Path(args.mission).with_name(Path(args.mission).stem + "_verified.json")
    )
    out_path.write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")

    # In summary
    all_techniques = set()
    print(f"\n{'='*60}")
    print(f"Mission : {verified.get('mission_id', '')}")
    print(f"Intent  : {str(verified.get('normalized_intent', verified.get('intent', '')))[:80]}")
    print(f"{'='*60}")

    for task in verified.get("execution_graph", []):
        candidates = [c.get("id") for c in task.get("mitre_candidates", [])]
        techniques = task.get("mitre_techniques", [])
        status     = task.get("mitre_status")
        confidence = task.get("mapping_confidence")
        all_techniques.update(techniques)

        print(f"\n  {task.get('task_id')} [{task.get('stage')}]")
        print(f"    Intent : {task.get('intent', '')}")
        print(f"    Goal   : {task.get('behavioral_goal', '')[:80]}")
        print(f"    Before : {candidates}")
        print(f"    After  : {techniques} [{status}, {confidence}]")

    print(f"\n{'='*60}")
    print(f"All verified techniques : {sorted(all_techniques)}")
    print(f"Total unique            : {len(all_techniques)}")
    print(f"{'='*60}")
    print(f"Saved → {out_path}")


if __name__ == "__main__":
    main()