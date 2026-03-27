from __future__ import annotations

import argparse
import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


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


def _norm(vec: np.ndarray) -> np.ndarray:
    denom = np.linalg.norm(vec, axis=1, keepdims=True) + 1e-12
    return vec / denom


def _cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return _norm(a) @ _norm(b).T


def _task_text(task: Dict[str, Any], use_stage: bool = True) -> str:
    parts = []
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
    for path in paths:
        rows = _load_json_or_jsonl(path)
        for row in rows:
            tid = row.get("technique_id") or row.get("mitre_id") or row.get("label") or row.get("ground_truth")
            text = row.get("text") or row.get("intent") or row.get("sentence") or row.get("description") or row.get("behavior")
            if not tid or not text:
                continue
            examples.append(
                Example(
                    text=str(text).strip(),
                    technique_id=str(tid).strip(),
                    source=str(row.get("source", Path(path).stem)),
                )
            )
    return examples


class BaseEncoder:
    def encode(self, texts: List[str]) -> np.ndarray:
        raise NotImplementedError


class SciBERTEncoder(BaseEncoder):
    def __init__(self, model_name: str = "allenai/scibert_scivocab_uncased") -> None:
        from transformers import AutoModel, AutoTokenizer

        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.eval()

    def encode(self, texts: List[str]) -> np.ndarray:
        import torch

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
            with torch.no_grad():
                out = self.model(**toks)
                hidden = out.last_hidden_state
                mask = toks["attention_mask"].unsqueeze(-1)
                summed = (hidden * mask).sum(dim=1)
                counts = mask.sum(dim=1).clamp(min=1)
                pooled = summed / counts
                vecs.append(pooled.cpu().numpy())
        return np.vstack(vecs) if vecs else np.zeros((0, 768), dtype=np.float32)


class TfidfEncoder(BaseEncoder):
    def __init__(self) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), max_features=20000)
        self._is_fit = False

    def fit(self, corpus: List[str]) -> None:
        self.vectorizer.fit(corpus)
        self._is_fit = True

    def encode(self, texts: List[str]) -> np.ndarray:
        if not self._is_fit:
            raise RuntimeError("TfidfEncoder must be fit before encode()")
        return self.vectorizer.transform(texts).toarray().astype(np.float32)


class SciBERTDatasetVerifier:
    """
    Planner proposes mitre_candidates.
    Verifier reranks ONLY within those candidates using TRAM2/AnnoCTR-like examples.
    Dataset acts as evidence, not absolute truth.
    """

    def __init__(
        self,
        dataset_paths: List[str],
        encoder_backend: str = "scibert",
        model_name: str = "allenai/scibert_scivocab_uncased",
        candidate_top_k_examples: int = 5,
        accept_threshold: float = 0.62,
        ambiguity_gap: float = 0.06,
    ) -> None:
        self.examples = _load_examples(dataset_paths)
        if not self.examples:
            raise ValueError("No valid examples loaded from dataset paths")

        self.candidate_top_k_examples = candidate_top_k_examples
        self.accept_threshold = accept_threshold
        self.ambiguity_gap = ambiguity_gap

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

        self.examples_by_tid: Dict[str, List[int]] = {}
        for i, ex in enumerate(self.examples):
            self.examples_by_tid.setdefault(ex.technique_id, []).append(i)

    def _score_candidates(self, task: Dict[str, Any]) -> List[CandidateScore]:
        task_text = _task_text(task)
        task_emb = self.encoder.encode([task_text])

        planner_candidates = task.get("mitre_candidates", []) or []
        candidate_ids = []
        for cand in planner_candidates:
            tid = cand.get("id")
            if isinstance(tid, str) and tid.strip():
                candidate_ids.append(tid.strip())
        candidate_ids = list(dict.fromkeys(candidate_ids))

        if not candidate_ids:
            return []

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
                    )
                )
                continue

            ex_emb = self.example_emb[example_idxs]
            sims = _cosine(task_emb, ex_emb)[0]
            order = np.argsort(-sims)[: self.candidate_top_k_examples]
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
                )
            )

        scored.sort(key=lambda x: (x.score, x.support_count), reverse=True)
        return scored

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

        return [top1.technique_id], "verified", confidence, f"verified from dataset similarity against {top1.support_count} examples", debug_scores

    def verify_mission(self, mission: Dict[str, Any]) -> Dict[str, Any]:
        out = deepcopy(mission)
        verifier_summary = {
            "backend": self.encoder.__class__.__name__,
            "dataset_example_count": len(self.examples),
            "mode": "candidate_reranking_over_planner_output",
        }

        task_reports: List[Dict[str, Any]] = []

        for task in out.get("execution_graph", []):
            scored = self._score_candidates(task)
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
                    "final_mitre_techniques": final_tids,
                    "mitre_status": mitre_status,
                    "mapping_confidence": confidence,
                    "candidate_scores": debug_scores,
                }
            )

        out["verifier_summary"] = verifier_summary
        out["verifier_task_reports"] = task_reports
        return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Verifier: SciBERT/TFiDF dataset reranker for planner output")
    parser.add_argument("--mission", required=True, help="Planner mission JSON path")
    parser.add_argument("--datasets", required=True, nargs="+", help="Dataset files (.json or .jsonl) with text + technique_id")
    parser.add_argument("--backend", choices=["scibert", "tfidf"], default="scibert")
    parser.add_argument("--model-name", default="allenai/scibert_scivocab_uncased")
    parser.add_argument("--accept-threshold", type=float, default=0.62)
    parser.add_argument("--ambiguity-gap", type=float, default=0.06)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    mission = json.loads(Path(args.mission).read_text(encoding="utf-8"))

    verifier = SciBERTDatasetVerifier(
        dataset_paths=args.datasets,
        encoder_backend=args.backend,
        model_name=args.model_name,
        accept_threshold=args.accept_threshold,
        ambiguity_gap=args.ambiguity_gap,
    )

    verified = verifier.verify_mission(mission)

    out_path = Path(args.out) if args.out else Path(args.mission).with_name(Path(args.mission).stem + "_verified.json")
    out_path.write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(verified, indent=2, ensure_ascii=False))
    print(f"\nSaved verified mission to: {out_path}")


if __name__ == "__main__":
    main()
