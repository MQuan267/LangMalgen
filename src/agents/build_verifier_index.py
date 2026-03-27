from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import numpy as np


@dataclass
class Example:
    text: str
    technique_id: str
    source: str = "dataset"


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


class SciBERTEncoder:
    def __init__(self, model_name: str = "allenai/scibert_scivocab_uncased") -> None:
        from transformers import AutoModel, AutoTokenizer
        import torch

        torch.set_num_threads(4)
        torch.set_num_interop_threads(1)

        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
        self.model = AutoModel.from_pretrained(model_name)
        self.model.to(self.device)
        self.model.eval()

    def encode(self, texts: List[str], batch_size: int = 4, max_length: int = 128) -> np.ndarray:
        vecs = []

        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            print(f"[encode] batch {i} -> {i + len(batch) - 1} / {len(texts) - 1}", flush=True)

            toks = self.tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            )
            toks = {k: v.to(self.device) for k, v in toks.items()}

            with self.torch.no_grad():
                out = self.model(**toks)
                hidden = out.last_hidden_state
                mask = toks["attention_mask"].unsqueeze(-1)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
                vecs.append(pooled.detach().cpu().numpy().astype(np.float32))

        return np.vstack(vecs) if vecs else np.zeros((0, 768), dtype=np.float32)


def _hash_paths(paths: List[str]) -> str:
    raw = "||".join(sorted(str(Path(p).resolve()) for p in paths))
    return hashlib.md5(raw.encode("utf-8")).hexdigest()[:12]


def _mean_rows(x: np.ndarray) -> np.ndarray:
    return np.mean(x, axis=0, keepdims=True).astype(np.float32)


def _infer_stage_hints(texts: List[str]) -> List[str]:
    joined = " ".join(t.lower() for t in texts[:50])
    hints = set()

    if any(k in joined for k in ["send", "upload", "exfil", "post ", "remote server", "c2"]):
        hints.add("exfiltration")
    if any(k in joined for k in ["encrypt", "obfuscat", "masquerad", "disable defender", "modify registry"]):
        hints.add("defense-evasion")
    if any(k in joined for k in ["dump lsass", "credential", "password", "hash", "token"]):
        hints.add("credential-access")
    if any(k in joined for k in ["screenshot", "keylog", "inject", "execute", "command shell", "run command"]):
        hints.add("execution")
    if any(k in joined for k in ["registry run", "startup", "scheduled task", "persistence"]):
        hints.add("persistence")
    if any(k in joined for k in ["discover", "enumerate", "system information", "process", "file and directory"]):
        hints.add("discovery")
    if any(k in joined for k in ["elevate", "privilege", "uac", "debug privilege"]):
        hints.add("privilege-escalation")
    if any(k in joined for k in ["http", "https", "web protocol", "beacon", "c2 channel"]):
        hints.add("c2-setup")

    return sorted(hints)


def build_index(
    dataset_paths: List[str],
    model_name: str,
    cache_dir: str,
    rep_per_technique: int,
) -> None:
    cache_root = Path(cache_dir)
    cache_root.mkdir(parents=True, exist_ok=True)

    dataset_hash = _hash_paths(dataset_paths)

    examples = _load_examples(dataset_paths)
    if not examples:
        raise ValueError("No valid examples loaded")

    print(f"[info] loaded {len(examples)} unique examples")

    encoder = SciBERTEncoder(model_name=model_name)
    example_texts = [ex.text for ex in examples]
    example_emb = encoder.encode(example_texts, batch_size=4, max_length=128)

    emb_path = cache_root / f"examples_{dataset_hash}.npy"
    meta_path = cache_root / f"examples_{dataset_hash}.meta.json"
    np.save(emb_path, example_emb)

    examples_by_tid: Dict[str, List[int]] = defaultdict(list)
    for i, ex in enumerate(examples):
        examples_by_tid[ex.technique_id].append(i)

    technique_ids = sorted(examples_by_tid.keys())
    centroids = {}
    stage_hints = {}
    representative_indices = {}

    rng = np.random.default_rng(42)

    for tid in technique_ids:
        idxs = examples_by_tid[tid]
        centroids[tid] = _mean_rows(example_emb[idxs])

        texts = [examples[i].text for i in idxs]
        stage_hints[tid] = _infer_stage_hints(texts)

        if len(idxs) <= rep_per_technique:
            rep_idxs = idxs
        else:
            rep_idxs = sorted(rng.choice(idxs, size=rep_per_technique, replace=False).tolist())
        representative_indices[tid] = rep_idxs

    np.savez_compressed(
        cache_root / f"tech_centroids_{dataset_hash}.npz",
        **{tid: centroids[tid] for tid in technique_ids},
    )

    metadata = {
        "dataset_paths": [str(Path(p).resolve()) for p in dataset_paths],
        "dataset_hash": dataset_hash,
        "example_count": len(examples),
        "technique_ids": technique_ids,
        "examples": [
            {"text": ex.text, "technique_id": ex.technique_id, "source": ex.source}
            for ex in examples
        ],
        "examples_by_tid": {tid: idxs for tid, idxs in examples_by_tid.items()},
        "representative_indices": representative_indices,
        "stage_hints": stage_hints,
        "embedding_dim": int(example_emb.shape[1]) if len(example_emb) else 0,
        "rep_per_technique": rep_per_technique,
        "model_name": model_name,
    }
    meta_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[done] saved embeddings to {emb_path}")
    print(f"[done] saved metadata to {meta_path}")
    print(f"[done] saved centroids to {cache_root / f'tech_centroids_{dataset_hash}.npz'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build verifier index for full TRAM2")
    parser.add_argument("--datasets", required=True, nargs="+", help="Dataset files")
    parser.add_argument("--model-name", default="allenai/scibert_scivocab_uncased")
    parser.add_argument("--cache-dir", default=".verifier_cache")
    parser.add_argument("--rep-per-technique", type=int, default=200)
    args = parser.parse_args()

    build_index(
        dataset_paths=args.datasets,
        model_name=args.model_name,
        cache_dir=args.cache_dir,
        rep_per_technique=args.rep_per_technique,
    )


if __name__ == "__main__":
    main()