from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


# ============================================================
# Data structures
# ============================================================

@dataclass
class Example:
    text: str
    technique_id: str
    source: str = "dataset"


@dataclass
class CandidateScore:
    technique_id: str
    score: float
    support_count: int
    reasons: List[str] = field(default_factory=list)
    source: str = "candidate_rerank"


# ============================================================
# Utilities
# ============================================================

def _norm(vec: np.ndarray) -> np.ndarray:
    denom = np.linalg.norm(vec, axis=1, keepdims=True) + 1e-12
    return vec / denom


def _cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return _norm(a) @ _norm(b).T


def _hash_paths(paths: List[str]) -> str:
    raw = "||".join(sorted(str(Path(p).resolve()) for p in paths))
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:12]


def _task_text(
    task: Dict[str, Any],
    mission_intent: str = "",
    use_stage: bool = True,
) -> str:
    parts = []
    if mission_intent:
        parts.append(f"mission: {mission_intent}")
    if use_stage:
        parts.append(f"stage: {task.get('stage', '')}")
    parts.append(f"intent: {task.get('intent', '')}")
    parts.append(f"goal: {task.get('behavioral_goal', '')}")
    return " | ".join(parts).strip()


def _load_json_or_jsonl(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        return []

    if p.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("examples"), list):
        return data["examples"]
    if isinstance(data, dict):
        return [data]

    raise ValueError(f"Unsupported dataset format: {path}")


def _load_examples(paths: List[str]) -> List[Example]:
    examples: List[Example] = []
    seen: set[tuple[str, str]] = set()

    for path in paths:
        rows = _load_json_or_jsonl(path)
        for row in rows:
            tid = (
                row.get("technique_id")
                or row.get("mitre_id")
                or row.get("label")
                or row.get("ground_truth")
            )
            text = (
                row.get("text")
                or row.get("intent")
                or row.get("sentence")
                or row.get("description")
                or row.get("behavior")
            )

            if not tid or not text:
                continue

            text = str(text).strip()
            tid = str(tid).strip()
            if not text or not tid:
                continue

            key = (text, tid)
            if key in seen:
                continue
            seen.add(key)

            examples.append(
                Example(
                    text=text,
                    technique_id=tid,
                    source=str(row.get("source", Path(path).stem)),
                )
            )
    return examples


def _mean_rows(x: np.ndarray) -> np.ndarray:
    if len(x) == 0:
        return np.zeros((1, 1), dtype=np.float32)
    return np.mean(x, axis=0, keepdims=True)


def _topk_indices_desc(scores: np.ndarray, k: int) -> np.ndarray:
    if len(scores) == 0:
        return np.array([], dtype=np.int64)
    k = min(k, len(scores))
    idx = np.argpartition(-scores, k - 1)[:k]
    return idx[np.argsort(-scores[idx])]


def _looks_like_ttechnique(tid: str) -> bool:
    return bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid))


# ============================================================
# Encoder backends
# ============================================================

class BaseEncoder:
    def encode(self, texts: List[str]) -> np.ndarray:
        raise NotImplementedError


class SciBERTEncoder(BaseEncoder):
    def __init__(self, model_name: str = "allenai/scibert_scivocab_uncased") -> None:
        from transformers import AutoModel, AutoTokenizer
        import torch

        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()

    def encode(self, texts: List[str]) -> np.ndarray:
        vecs = []
        batch_size = 8

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            toks = self.tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=256,
                return_tensors="pt",
            )
            toks = {k: v.to(self.device) for k, v in toks.items()}

            with self.torch.no_grad():
                out = self.model(**toks)
                hidden = out.last_hidden_state
                mask = toks["attention_mask"].unsqueeze(-1)
                summed = (hidden * mask).sum(dim=1)
                counts = mask.sum(dim=1).clamp(min=1)
                pooled = summed / counts
                vecs.append(pooled.detach().cpu().numpy())

        return np.vstack(vecs) if vecs else np.zeros((0, 768), dtype=np.float32)


class TfidfEncoder(BaseEncoder):
    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            max_features=20000,
        )
        self._is_fit = False

    def fit(self, corpus: List[str]) -> None:
        self.vectorizer.fit(corpus)
        self._is_fit = True

    def encode(self, texts: List[str]) -> np.ndarray:
        if not self._is_fit:
            raise RuntimeError("TfidfEncoder must be fit before encode()")
        return self.vectorizer.transform(texts).toarray().astype(np.float32)


# ============================================================
# Verifier
# ============================================================

class SciBERTDatasetVerifierV3:
    """
    v3:
    - rerank planner candidates first
    - fallback retrieve from full technique space when:
        * no planner candidates
        * or planner candidates are too weak
    - stage-aware fallback to reduce nonsense techniques
    - cached example embeddings + technique centroids
    """

    def __init__(
        self,
        dataset_paths: List[str],
        encoder_backend: str = "scibert",
        model_name: str = "allenai/scibert_scivocab_uncased",
        candidate_top_k_examples: int = 5,
        accept_threshold: float = 0.62,
        ambiguity_gap: float = 0.06,
        weak_candidate_threshold: float = 0.52,
        fallback_top_k_techniques: int = 5,
        cache_dir: str = ".verifier_cache",
    ) -> None:
        self.dataset_paths = dataset_paths
        self.examples = _load_examples(dataset_paths)
        if not self.examples:
            raise ValueError("No valid examples loaded from dataset paths")

        self.candidate_top_k_examples = candidate_top_k_examples
        self.accept_threshold = accept_threshold
        self.ambiguity_gap = ambiguity_gap
        self.weak_candidate_threshold = weak_candidate_threshold
        self.fallback_top_k_techniques = fallback_top_k_techniques

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if encoder_backend == "scibert":
            self.encoder: BaseEncoder = SciBERTEncoder(model_name=model_name)
        elif encoder_backend == "tfidf":
            self.encoder = TfidfEncoder()
        else:
            raise ValueError("encoder_backend must be 'scibert' or 'tfidf'")

        self.example_texts = [ex.text for ex in self.examples]

        if isinstance(self.encoder, TfidfEncoder):
            self.encoder.fit(self.example_texts)
            self.example_emb = self.encoder.encode(self.example_texts)
        else:
            self.example_emb = self._load_or_build_embedding_cache()

        self.examples_by_tid: Dict[str, List[int]] = {}
        for i, ex in enumerate(self.examples):
            self.examples_by_tid.setdefault(ex.technique_id, []).append(i)

        self.technique_ids = sorted(
            [tid for tid in self.examples_by_tid.keys() if _looks_like_ttechnique(tid)]
        )
        self.technique_centroids = self._build_technique_centroids()
        self.technique_stage_hints = self._infer_stage_hints()

    # --------------------------------------------------------
    # Cache
    # --------------------------------------------------------

    def _cache_files(self) -> tuple[Path, Path]:
        dataset_hash = _hash_paths(self.dataset_paths)
        emb_path = self.cache_dir / f"examples_{dataset_hash}.npy"
        meta_path = self.cache_dir / f"examples_{dataset_hash}.meta.json"
        return emb_path, meta_path

    def _load_or_build_embedding_cache(self) -> np.ndarray:
        emb_path, meta_path = self._cache_files()

        if emb_path.exists() and meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if meta.get("count") == len(self.example_texts):
                    print(f"[cache] loading example embeddings from {emb_path}")
                    return np.load(emb_path)
            except Exception:
                pass

        print("[cache] building example embeddings...")
        emb = self.encoder.encode(self.example_texts)
        np.save(emb_path, emb)
        meta_path.write_text(
            json.dumps(
                {
                    "count": len(self.example_texts),
                    "paths": [str(Path(p).resolve()) for p in self.dataset_paths],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        print(f"[cache] saved example embeddings to {emb_path}")
        return emb

    # --------------------------------------------------------
    # Technique-level indexing
    # --------------------------------------------------------

    def _build_technique_centroids(self) -> Dict[str, np.ndarray]:
        centroids: Dict[str, np.ndarray] = {}
        for tid in self.technique_ids:
            idxs = self.examples_by_tid.get(tid, [])
            ex_emb = self.example_emb[idxs]
            centroids[tid] = _mean_rows(ex_emb)
        return centroids

    def _infer_stage_hints(self) -> Dict[str, set[str]]:
        """
        Heuristic stage hints from example text.
        Good enough for fallback pruning; not a source of truth.
        """
        hints: Dict[str, set[str]] = {tid: set() for tid in self.technique_ids}

        for tid in self.technique_ids:
            idxs = self.examples_by_tid.get(tid, [])[:50]
            texts = " ".join(self.examples[i].text.lower() for i in idxs)

            if any(k in texts for k in ["send", "upload", "exfil", "post ", "remote server", "c2"]):
                hints[tid].add("exfiltration")
            if any(k in texts for k in ["encrypt", "obfuscat", "masquerad", "disable defender", "modify registry"]):
                hints[tid].add("defense-evasion")
            if any(k in texts for k in ["dump lsass", "credential", "password", "hash", "token"]):
                hints[tid].add("credential-access")
            if any(k in texts for k in ["screenshot", "keylog", "inject", "execute", "command shell", "run command"]):
                hints[tid].add("execution")
            if any(k in texts for k in ["registry run", "startup", "scheduled task", "persistence"]):
                hints[tid].add("persistence")
            if any(k in texts for k in ["discover", "enumerate", "system information", "process", "file and directory"]):
                hints[tid].add("discovery")
            if any(k in texts for k in ["elevate", "privilege", "uac", "debug privilege"]):
                hints[tid].add("privilege-escalation")
            if any(k in texts for k in ["http", "https", "web protocol", "beacon", "c2 channel"]):
                hints[tid].add("c2-setup")
        return hints

    # --------------------------------------------------------
    # Candidate scoring
    # --------------------------------------------------------

    def _score_specific_candidate_ids(
        self,
        task_emb: np.ndarray,
        candidate_ids: List[str],
    ) -> List[CandidateScore]:
        scored: List[CandidateScore] = []

        for tid in candidate_ids:
            example_idxs = self.examples_by_tid.get(tid, [])
            if not example_idxs:
                scored.append(
                    CandidateScore(
                        technique_id=tid,
                        score=0.0,
                        support_count=0,
                        reasons=["no supporting dataset examples"],
                        source="candidate_rerank",
                    )
                )
                continue

            ex_emb = self.example_emb[example_idxs]
            sims = _cosine(task_emb, ex_emb)[0]
            order = _topk_indices_desc(sims, self.candidate_top_k_examples)

            top_scores = sims[order]
            top_examples = [self.examples[example_idxs[j]] for j in order]
            score = float(np.mean(top_scores)) if len(top_scores) else 0.0

            reasons = [f"{ex.source}: {ex.text[:140]}" for ex in top_examples]

            scored.append(
                CandidateScore(
                    technique_id=tid,
                    score=score,
                    support_count=len(example_idxs),
                    reasons=reasons,
                    source="candidate_rerank",
                )
            )

        scored.sort(key=lambda x: (x.score, x.support_count), reverse=True)
        return scored

    def _planner_candidate_ids(self, task: Dict[str, Any]) -> List[str]:
        planner_candidates = task.get("mitre_candidates", []) or []
        ids: List[str] = []

        for cand in planner_candidates:
            tid = cand.get("id")
            if isinstance(tid, str) and tid.strip():
                ids.append(tid.strip())

        return list(dict.fromkeys(ids))

    # --------------------------------------------------------
    # Fallback retrieval
    # --------------------------------------------------------

    def _stage_compatible_techniques(self, stage: str) -> List[str]:
        stage = stage.strip().lower()
        if not stage:
            return self.technique_ids

        compatible = []
        for tid in self.technique_ids:
            hints = self.technique_stage_hints.get(tid, set())
            if not hints or stage in hints:
                compatible.append(tid)

        return compatible or self.technique_ids

    def _fallback_retrieve(
        self,
        task_emb: np.ndarray,
        stage: str,
    ) -> List[CandidateScore]:
        technique_pool = self._stage_compatible_techniques(stage)

        centroid_matrix = np.vstack([self.technique_centroids[tid] for tid in technique_pool])
        sims = _cosine(task_emb, centroid_matrix)[0]
        order = _topk_indices_desc(sims, self.fallback_top_k_techniques)

        scored: List[CandidateScore] = []
        for idx in order:
            tid = technique_pool[idx]
            ex_idxs = self.examples_by_tid.get(tid, [])
            if not ex_idxs:
                continue

            ex_emb = self.example_emb[ex_idxs]
            fine_sims = _cosine(task_emb, ex_emb)[0]
            fine_order = _topk_indices_desc(fine_sims, self.candidate_top_k_examples)
            top_scores = fine_sims[fine_order]
            top_examples = [self.examples[ex_idxs[j]] for j in fine_order]

            score = float(np.mean(top_scores)) if len(top_scores) else 0.0
            reasons = [f"{ex.source}: {ex.text[:140]}" for ex in top_examples]

            scored.append(
                CandidateScore(
                    technique_id=tid,
                    score=score,
                    support_count=len(ex_idxs),
                    reasons=reasons,
                    source="fallback_retrieval",
                )
            )

        scored.sort(key=lambda x: (x.score, x.support_count), reverse=True)
        return scored

    # --------------------------------------------------------
    # Decision logic
    # --------------------------------------------------------

    def _decide(
        self,
        scored: List[CandidateScore],
    ) -> Tuple[List[str], str, str, str, List[Dict[str, Any]]]:
        if not scored:
            return [], "unmapped", "low", "no candidates to verify", []

        top1 = scored[0]
        top2 = scored[1] if len(scored) > 1 else None

        debug_scores = [
            {
                "technique_id": s.technique_id,
                "score": round(s.score, 4),
                "support_count": s.support_count,
                "source": s.source,
                "top_reasons": s.reasons[:3],
            }
            for s in scored
        ]

        if top1.score < self.accept_threshold:
            return [], "ambiguous", "low", "dataset evidence below acceptance threshold", debug_scores

        if top2 and abs(top1.score - top2.score) <= self.ambiguity_gap:
            return [], "ambiguous", "medium", f"top candidates too close: {top1.technique_id} vs {top2.technique_id}", debug_scores

        if top1.score >= 0.80:
            confidence = "high"
        elif top1.score >= 0.68:
            confidence = "medium"
        else:
            confidence = "low"

        return [top1.technique_id], "verified", confidence, f"verified via {top1.source} against {top1.support_count} examples", debug_scores

    # --------------------------------------------------------
    # Public API
    # --------------------------------------------------------

    def verify_mission(self, mission: Dict[str, Any]) -> Dict[str, Any]:
        out = deepcopy(mission)
        mission_intent = str(
            out.get("normalized_intent")
            or out.get("original_intent")
            or out.get("intent", "")
        )

        verifier_summary = {
            "backend": self.encoder.__class__.__name__,
            "dataset_example_count": len(self.examples),
            "technique_count": len(self.technique_ids),
            "mode": "candidate_reranking_with_fallback_retrieval",
        }

        task_reports: List[Dict[str, Any]] = []

        for task in out.get("execution_graph", []):
            stage = str(task.get("stage", "")).strip().lower()

            if stage == "data-processing":
                task["mitre_techniques"] = []
                task["mitre_status"] = "not_applicable"
                task["mapping_confidence"] = "high"

                existing_note = str(task.get("ambiguity_notes", "") or "").strip()
                note = "data-processing task; no MITRE verification required"
                task["ambiguity_notes"] = f"{existing_note} | {note}".strip(" |")

                task_reports.append(
                    {
                        "task_id": task.get("task_id"),
                        "stage": task.get("stage"),
                        "intent": task.get("intent"),
                        "behavioral_goal": task.get("behavioral_goal"),
                        "final_mitre_techniques": [],
                        "mitre_status": "not_applicable",
                        "mapping_confidence": "high",
                        "candidate_scores": [],
                    }
                )
                continue

            task_text = _task_text(task, mission_intent=mission_intent)
            task_emb = self.encoder.encode([task_text])

            planner_candidate_ids = self._planner_candidate_ids(task)
            scored = self._score_specific_candidate_ids(task_emb, planner_candidate_ids)

            need_fallback = (
                not scored
                or (scored and scored[0].score < self.weak_candidate_threshold)
            )

            if need_fallback:
                fallback_scored = self._fallback_retrieve(task_emb, stage=stage)

                # merge by technique id, keep best score
                merged: Dict[str, CandidateScore] = {s.technique_id: s for s in scored}
                for fs in fallback_scored:
                    cur = merged.get(fs.technique_id)
                    if cur is None or fs.score > cur.score:
                        merged[fs.technique_id] = fs

                scored = sorted(
                    merged.values(),
                    key=lambda x: (x.score, x.support_count),
                    reverse=True,
                )

            final_tids, mitre_status, confidence, note, debug_scores = self._decide(scored)

            task["mitre_techniques"] = final_tids
            task["mitre_status"] = mitre_status
            task["mapping_confidence"] = confidence

            existing_note = str(task.get("ambiguity_notes", "") or "").strip()
            task["ambiguity_notes"] = f"{existing_note} | {note}".strip(" |")

            task_reports.append(
                {
                    "task_id": task.get("task_id"),
                    "stage": task.get("stage"),
                    "intent": task.get("intent"),
                    "behavioral_goal": task.get("behavioral_goal"),
                    "planner_candidate_ids": planner_candidate_ids,
                    "final_mitre_techniques": final_tids,
                    "mitre_status": mitre_status,
                    "mapping_confidence": confidence,
                    "candidate_scores": debug_scores,
                }
            )

        out["verifier_summary"] = verifier_summary
        out["verifier_task_reports"] = task_reports
        return out


# ============================================================
# CLI
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Verifier v3: SciBERT/TFiDF dataset reranker for planner output")
    parser.add_argument("--mission", required=True, help="Planner mission JSON path")
    parser.add_argument("--datasets", required=True, nargs="+", help="Dataset files (.json or .jsonl) with text + technique_id")
    parser.add_argument("--backend", choices=["scibert", "tfidf"], default="scibert")
    parser.add_argument("--model-name", default="allenai/scibert_scivocab_uncased")
    parser.add_argument("--accept-threshold", type=float, default=0.62)
    parser.add_argument("--ambiguity-gap", type=float, default=0.06)
    parser.add_argument("--weak-candidate-threshold", type=float, default=0.52)
    parser.add_argument("--fallback-top-k-techniques", type=int, default=5)
    parser.add_argument("--cache-dir", default=".verifier_cache")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    mission = json.loads(Path(args.mission).read_text(encoding="utf-8"))

    verifier = SciBERTDatasetVerifierV3(
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
        Path(args.out)
        if args.out
        else Path(args.mission).with_name(Path(args.mission).stem + "_verified.json")
    )
    out_path.write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(verified, indent=2, ensure_ascii=False))
    print(f"\nSaved verified mission to: {out_path}")


if __name__ == "__main__":
    main()