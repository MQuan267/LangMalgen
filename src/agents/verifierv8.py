"""
verifier_v9.py – Hybrid MITRE ATT&CK Verifier (v9)
====================================================
Architecture: planner_prior + stage_fit + ontology/rules + SciBERT evidence

Changes from v8:
  - CandidateScore extended with hybrid signal breakdown
  - _planner_candidate_map(): rank-aware prior (not flat 0.65)
  - _score_tids_hybrid(): multi-signal final_score with weights 0.25/0.25/0.35/0.15
  - _rule_adjustments(): per-technique bonuses/penalties
  - _fallback_retrieve(): 2-tier (stage pool → centroid pre-filter shortlist)
  - VerifierIndex: precomputed centroid_matrix (no rebuild per task)
  - representative_example_rows(): capped at [:8]
  - _decide(): re-check threshold AFTER parent-child cleanup + sort
  - KNOWN_OVERLAP_PAIRS: added T1055+T1134.001, T1003.001+T1134.001
  - Multi-label confidence: not auto-capped to "medium"
  - both_from_candidates condition removed — source no longer required to match
  - decision_trace in verifier_task_reports

Patch (benchmark analysis):
  - Fix T1033 FP: strong penalty when no user discovery evidence
  - Fix T1106 FP: penalty when no explicit native API wording
  - Fix T1095 FN: strong boost for raw socket / TCP wording
  - Fix T1071.001 FP: penalty when raw socket wording present
  - Fix T1218.011 FN: strong boost for rundll32 / lolbin wording
  - Fix T1574.002 FP: penalty when rundll32 without dll hijack signal
  - Fix T1074.001 FP: penalty when no staging signal
  - Fix T1070.004 FN: boost for delete/cleanup/forensic wording
  - Fix T1078 FP: penalty when no credential reuse signal
  - Fix T1112 FP: penalty when registry context is persistence-only
  - Fix T1547.001/T1053.005: keyword disambiguation boost
  - KNOWN_OVERLAP_PAIRS extended: T1218.011+T1059.003, T1027+T1140, T1055+T1106
"""

from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CandidateScore:
    technique_id: str
    score: float            # final hybrid score
    scibert_score: float    # semantic evidence
    planner_prior: float    # from planner mitre_candidates
    stage_fit: float        # rule-based stage compatibility
    support_bonus: float    # dataset support signal
    support_count: int
    reasons: List[str] = field(default_factory=list)
    source: str = "hybrid"
    rule_notes: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# SciBERT encoder
# ---------------------------------------------------------------------------

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
            toks = self.tokenizer(
                batch, padding=True, truncation=True,
                max_length=max_length, return_tensors="pt"
            )
            toks = {k: v.to(self.device) for k, v in toks.items()}
            with self.torch.no_grad():
                out = self.model(**toks)
                hidden = out.last_hidden_state
                mask = toks["attention_mask"].unsqueeze(-1)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
                vecs.append(pooled.detach().cpu().numpy().astype(np.float32))
        return np.vstack(vecs) if vecs else np.zeros((0, 768), dtype=np.float32)


# ---------------------------------------------------------------------------
# Verifier index
# ---------------------------------------------------------------------------

class VerifierIndex:
    def __init__(self, dataset_paths: List[str], cache_dir: str = ".verifier_cache") -> None:
        dataset_hash = _hash_paths(dataset_paths)
        cache_root = Path(cache_dir)
        emb_path        = cache_root / f"examples_{dataset_hash}.npy"
        meta_path       = cache_root / f"examples_{dataset_hash}.meta.json"
        centroids_path  = cache_root / f"tech_centroids_{dataset_hash}.npz"

        if not emb_path.exists() or not meta_path.exists() or not centroids_path.exists():
            raise FileNotFoundError("Verifier index not found. Run build_verifier_index.py first.")

        self.example_emb = np.load(emb_path).astype(np.float32)
        self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        self.centroid_npz = np.load(centroids_path)

        self.examples               = self.meta["examples"]
        self.examples_by_tid        = self.meta["examples_by_tid"]
        self.representative_indices = self.meta["representative_indices"]
        self.stage_hints            = {tid: set(v) for tid, v in self.meta["stage_hints"].items()}
        self.technique_ids          = self.meta["technique_ids"]
        self.technique_centroids    = {
            tid: self.centroid_npz[tid].astype(np.float32)
            for tid in self.technique_ids
        }

        # Precomputed centroid matrix — avoids rebuild on every fallback call
        self.centroid_matrix = np.vstack([
            self.technique_centroids[tid] for tid in self.technique_ids
        ]).astype(np.float32)

    def stage_compatible_techniques(self, stage: str) -> List[str]:
        stage = stage.strip().lower()
        if not stage:
            return self.technique_ids
        out = [
            tid for tid in self.technique_ids
            if not self.stage_hints.get(tid) or stage in self.stage_hints[tid]
        ]
        return out or self.technique_ids

    def representative_example_rows(self, tid: str) -> List[int]:
        """Cap at 8 to avoid noisy over-sized example sets."""
        reps = self.representative_indices.get(tid, [])
        if reps:
            return reps[:8]
        rows = self.examples_by_tid.get(tid, [])[:8]
        if not rows:
            print(f"[verifier] warning: no representative examples for {tid}, skipping")
        return rows


# ---------------------------------------------------------------------------
# Hybrid Verifier
# ---------------------------------------------------------------------------

class HybridVerifierV9:
    """
    Hybrid verifier:
      final_score = 0.30 * planner_prior
                  + 0.30 * stage_fit
                  + 0.25 * scibert_score
                  + 0.15 * support_bonus
                  + rule_bonus
    """

    KNOWN_OVERLAP_PAIRS = {
        frozenset({"T1041",     "T1071.001"}),   # exfil + web protocol
        frozenset({"T1547.001", "T1053.005"}),   # registry run + scheduled task
        frozenset({"T1548",     "T1134.001"}),   # elevation + token manipulation
        frozenset({"T1055",     "T1134.001"}),   # injection + token manipulation
        frozenset({"T1003.001", "T1134.001"}),   # LSASS dump + debug privilege
        frozenset({"T1218.011", "T1059.003"}),   # rundll32 + cmd shell (NEW)
        frozenset({"T1027",     "T1140"}),       # obfuscate + deobfuscate (loader, NEW)
        frozenset({"T1055",     "T1106"}),       # injection + native API (NEW)
    }

    SPECIFIC_OVER_GENERIC = {
        "T1548.002": "T1548",
    }

    # Keep legacy alias so existing CLI/scripts still work
    SciBERTDatasetVerifierV8 = None  # set after class definition

    def __init__(
        self,
        dataset_paths: List[str],
        encoder_backend: str = "scibert",
        model_name: str = "allenai/scibert_scivocab_uncased",
        candidate_top_k_examples: int = 5,
        accept_threshold: float = 0.62,
        ambiguity_gap: float = 0.06,
        weak_candidate_threshold: float = 0.52,
        fallback_top_k_techniques: int = 8,
        cache_dir: str = ".verifier_cache",
    ) -> None:
        if encoder_backend != "scibert":
            raise ValueError("v9 is intended for scibert backend only")
        self.encoder = SciBERTEncoder(model_name=model_name)
        self.index = VerifierIndex(dataset_paths=dataset_paths, cache_dir=cache_dir)
        self.candidate_top_k_examples   = candidate_top_k_examples
        self.accept_threshold           = accept_threshold
        self.ambiguity_gap              = ambiguity_gap
        self.weak_candidate_threshold   = weak_candidate_threshold
        self.fallback_top_k_techniques  = fallback_top_k_techniques

    # ------------------------------------------------------------------
    # Planner candidate helpers
    # ------------------------------------------------------------------

    def _planner_candidate_ids(self, task: Dict[str, Any]) -> List[str]:
        out = []
        for cand in task.get("mitre_candidates", []) or []:
            tid = cand.get("id")
            if isinstance(tid, str) and tid.strip():
                out.append(tid.strip())
        return list(dict.fromkeys(out))

    def _planner_candidate_map(self, task: Dict[str, Any]) -> Dict[str, float]:
        """
        Rank-aware prior:
        - use planner numeric score when available
        - fallback by rank (not flat 0.65) when score is missing
        """
        out: Dict[str, float] = {}
        for rank, cand in enumerate(task.get("mitre_candidates", []) or []):
            tid = cand.get("id")
            if not isinstance(tid, str) or not tid.strip():
                continue
            raw = cand.get("score")
            try:
                val = float(raw) if raw is not None else None
            except Exception:
                val = None

            if val is None:
                prior = 0.70 if rank == 0 else (0.58 if rank == 1 else 0.50)
            else:
                prior = max(0.0, min(1.0, val))

            out[tid.strip()] = prior
        return out

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _stage_fit_score(self, tid: str, stage: str) -> float:
        hints = self.index.stage_hints.get(tid, set())
        if not hints:
            return 0.55
        if stage in hints:
            return 1.0

        related: Dict[str, set] = {
            "exfiltration":        {"c2-setup", "defense-evasion", "collection"},
            "c2-setup":            {"exfiltration", "execution", "collection"},
            "execution":           {"defense-evasion", "privilege-escalation", "discovery"},
            "defense-evasion":     {"execution", "persistence", "exfiltration"},
            "credential-access":   {"privilege-escalation", "discovery"},
            "privilege-escalation":{"execution", "credential-access", "discovery"},
            "persistence":         {"defense-evasion", "execution"},
            "discovery":           {"execution", "credential-access", "privilege-escalation", "collection"},
            "initial-access":      {"execution", "credential-access"},
            "lateral-movement":    {"execution", "credential-access", "c2-setup"},
            "collection":          {"discovery", "exfiltration", "defense-evasion"},
        }
        if stage in related and hints.intersection(related[stage]):
            return 0.70
        return 0.20

    def _support_bonus(self, support_count: int) -> float:
        if support_count >= 10:
            return 1.0
        if support_count >= 5:
            return 0.75
        if support_count >= 2:
            return 0.50
        return 0.25

    def _resolve_specific_over_generic(self, tids: List[str]) -> List[str]:
        out = set(tids)
        for specific, generic in self.SPECIFIC_OVER_GENERIC.items():
            if specific in out and generic in out:
                out.remove(generic)
        return list(out)

    def _rule_adjustments(self, tid: str, task: Dict[str, Any]) -> Tuple[float, List[str]]:
        notes: List[str] = []
        bonus = 0.0
        stage = str(task.get("stage", "")).strip().lower()
        text  = _task_text(task, mission_intent="", use_stage=True).lower()

        # ── T1071.001 Web/C2 protocol ──────────────────────────────────────────
        if tid == "T1071.001":
            if any(x in text for x in ["http", "https", "web", "post", "beacon", "callback"]):
                bonus += 0.08
                notes.append("explicit web/protocol wording")
            # Penalize if intent says raw socket / TCP — that's T1095
            if any(x in text for x in ["raw socket", "tcp socket", "udp", "tcp c2", "custom protocol"]):
                bonus -= 0.25
                notes.append("web protocol penalized: raw socket wording → likely T1095")

        # ── T1041 Exfiltration over C2 ────────────────────────────────────────
        if tid == "T1041":
            if any(x in text for x in ["http", "https", "web", "post"]):
                bonus -= 0.04
                notes.append("generic exfil slightly penalized vs web-specific protocol")

        # ── T1095 Non-Application Layer Protocol (raw TCP/UDP) ────────────────
        if tid == "T1095":
            if any(x in text for x in [
                "raw socket", "tcp socket", "udp", "tcp c2",
                "custom protocol", "icmp", "non-http", "raw tcp"
            ]):
                bonus += 0.20
                notes.append("explicit raw socket/protocol boost for T1095")

        # ── T1548 / T1548.002 UAC bypass ──────────────────────────────────────
        if tid == "T1548.002":
            has_priv_signal = any(x in text for x in [
                "uac", "privilege escalation", "elevate", "admin", "runas"
            ])
            has_inject_only = any(x in text for x in ["inject", "shellcode"])
            if not has_priv_signal:
                bonus -= 0.35
                notes.append("strong penalty: no privilege escalation evidence for T1548.002")
            if has_inject_only and not has_priv_signal:
                bonus -= 0.20
                notes.append("block co-occurrence: injection without privilege escalation")
        if tid == "T1548" and "uac" in text:
            bonus -= 0.08
            notes.append("generic elevation penalized vs UAC-specific T1548.002")

        # ── T1056.001 Keylogging vs T1113 Screen Capture ──────────────────────
        if tid == "T1056.001":
            if any(x in text for x in ["keylog", "keystroke", "keyboard"]):
                bonus += 0.10
                notes.append("explicit keylogging wording")
        if tid == "T1113":
            if any(x in text for x in ["keylog", "keystroke", "keyboard"]):
                bonus -= 0.20
                notes.append("screen capture penalized for keylogging wording")

        # ── T1055 Process Injection ────────────────────────────────────────────
        if tid == "T1055":
            if any(x in text for x in [
                "inject", "shellcode", "createremotethread", "writeprocessmemory"
            ]):
                bonus += 0.10
                notes.append("explicit injection wording")
        if tid == "T1204.002":
            if any(x in text for x in [
                "inject", "shellcode", "createremotethread", "writeprocessmemory"
            ]):
                bonus -= 0.20
                notes.append("user execution penalized for injection wording")

        # ── T1033 System Owner/User Discovery ─────────────────────────────────
        # Very common FP: appears even when intent has no user discovery requirement
        if tid == "T1033":
            has_user_signal = any(x in text for x in [
                "current user", "whoami", "username", "logged in user",
                "user discovery", "account discovery", "system owner"
            ])
            if not has_user_signal:
                bonus -= 0.35
                notes.append("strong penalty: no user discovery evidence for T1033")

        # ── T1106 Native API ──────────────────────────────────────────────────
        # FP when intent mentions injection but not explicit win32 API usage
        if tid == "T1106":
            has_api_signal = any(x in text for x in [
                "native api", "win32api", "ctypes", "winapi",
                "system call", "win32", "windows api"
            ])
            if not has_api_signal:
                bonus -= 0.20
                notes.append("native API penalized: no explicit API wording in intent")

        # ── T1218.011 Rundll32 / Lolbin ───────────────────────────────────────
        # Commonly missed — needs strong boost when keyword present
        if tid == "T1218.011":
            if any(x in text for x in [
                "rundll32", "comsvcs", "lolbin", "living off the land"
            ]):
                bonus += 0.25
                notes.append("explicit rundll32/lolbin boost for T1218.011")

        # ── T1574.002 DLL Side-Loading / Hijacking ────────────────────────────
        if tid == "T1574.002":
            if any(x in text for x in [
                "dll hijack", "dll sideload", "search order",
                "dll side-load", "dll search order", "phantom dll"
            ]):
                bonus += 0.15
                notes.append("explicit DLL hijack wording boost")
            else:
                bonus += 0.05
                notes.append("slight boost to survive stage filter")
            # FP when only rundll32 (lolbin) is mentioned without dll hijack signal
            if any(x in text for x in ["rundll32", "lolbin"]) and \
               not any(x in text for x in [
                   "dll hijack", "dll sideload", "search order", "dll side-load"
               ]):
                bonus -= 0.30
                notes.append("DLL hijack penalized: rundll32 without dll hijack signal")

        # ── T1573.001 Encrypted Channel ───────────────────────────────────────
        if tid == "T1573.001":
            if any(x in text for x in [
                "tls", "ssl", "encrypt", "secure channel", "encrypted channel",
                "encrypt c2", "secure communication", "tls c2", "encrypt communication"
            ]):
                bonus += 0.15
                notes.append("encrypted channel boost for T1573.001")

        # ── T1005 vs T1083 collection/discovery disambiguation ────────────────
        _collect_signals = [
            "collect", "gather", "harvest", "sensitive files",
            "copy files", "local filesystem", "local files"
        ]
        _enumerate_signals = [
            "enumerate", "list files", "discover files",
            "list processes", "scan", "file discovery", "directory discovery"
        ]
        if tid == "T1005":
            if any(k in text for k in _collect_signals):
                bonus += 0.10
                notes.append("collection keyword boost for T1005")
            if any(k in text for k in _enumerate_signals):
                bonus -= 0.20
                notes.append("penalize: enumerate mistaken as collection for T1005")
        if tid == "T1083":
            if any(k in text for k in _enumerate_signals):
                bonus += 0.10
                notes.append("enumerate/discover boost for T1083")
            if any(k in text for k in _collect_signals) and \
               not any(k in text for k in _enumerate_signals):
                bonus -= 0.10
                notes.append("discovery T1083 penalized vs collection wording")

        # ── T1105 vs T1219 tool transfer disambiguation ───────────────────────
        _transfer_signals = [
            "download", "remote server", "fetch tool", "additional tools",
            "transfer tool", "retrieve tool", "drop tool"
        ]
        if any(k in text for k in _transfer_signals):
            if tid == "T1105":
                bonus += 0.10
                notes.append("tool transfer boost for T1105")
            if tid == "T1219":
                bonus -= 0.10
                notes.append("remote access T1219 penalized vs tool transfer wording")

        # ── T1074.001 Local Data Staging ──────────────────────────────────────
        # FP in collect+delete context — staging ≠ collecting then wiping
        if tid == "T1074.001":
            has_staging_signal = any(x in text for x in [
                "stage", "staging", "aggregate", "gather before exfil"
            ])
            has_delete_signal = any(x in text for x in [
                "delete", "remove", "erase", "wipe", "forensic", "cleanup"
            ])
            if not has_staging_signal:
                bonus -= 0.20
                notes.append("staging penalized: no explicit staging signal")
            if has_delete_signal and not has_staging_signal:
                bonus -= 0.15
                notes.append("staging further penalized: delete/wipe context without staging")

        # ── T1070.004 File Deletion ────────────────────────────────────────────
        # Boost to recover FN cases where intent clearly says delete/cleanup
        if tid == "T1070.004":
            if any(x in text for x in [
                "delete", "securely delete", "remove traces", "erase",
                "cleanup", "forensic evidence", "wipe artifact", "wipe file"
            ]):
                bonus += 0.10
                notes.append("file deletion/cleanup boost for T1070.004")

        # ── T1078 Valid Accounts ───────────────────────────────────────────────
        # FP in credential dump context — dumping ≠ reusing credentials
        if tid == "T1078":
            has_reuse_signal = any(x in text for x in [
                "valid account", "stolen credential login", "compromised account",
                "reuse credential", "credential reuse", "login with"
            ])
            if not has_reuse_signal:
                bonus -= 0.30
                notes.append("valid accounts penalized: no credential reuse signal")

        # ── T1112 Modify Registry ─────────────────────────────────────────────
        # FP when intent only implies registry persistence (T1547.001), not modification
        if tid == "T1112":
            has_modify_signal = any(x in text for x in [
                "modify registry", "write registry", "reg add", "registry modify",
                "registry value", "change registry"
            ])
            has_persist_only = any(x in text for x in [
                "registry run", "run key", "hkcu run", "hklm run",
                "registry persistence", "autorun"
            ])
            if not has_modify_signal and has_persist_only:
                bonus -= 0.25
                notes.append("registry modify penalized: persistence-only context → T1547.001")
            elif not has_modify_signal:
                bonus -= 0.15
                notes.append("registry modify penalized: no explicit modify signal")

        # ── T1547.001 vs T1053.005 persistence disambiguation ─────────────────
        if tid == "T1547.001":
            if any(x in text for x in [
                "registry run", "run key", "hkcu", "hklm", "autorun", "startup folder"
            ]):
                bonus += 0.08
                notes.append("registry run key boost for T1547.001")
        if tid == "T1053.005":
            if any(x in text for x in [
                "scheduled task", "schtasks", "task scheduler"
            ]):
                bonus += 0.08
                notes.append("scheduled task boost for T1053.005")

        # ── Stage compatibility penalty (generic) ─────────────────────────────
        stage_fit = self._stage_fit_score(tid, stage)
        if stage_fit < 0.3:
            bonus -= 0.10
            notes.append("poor stage compatibility")

        return bonus, notes

    def _score_tids_hybrid(
        self,
        task_emb: np.ndarray,
        tids: List[str],
        source: str,
        task: Dict[str, Any],
        planner_prior_map: Dict[str, float],
    ) -> List[CandidateScore]:
        scored: List[CandidateScore] = []

        for tid in tids:
            rep_idxs = self.index.representative_example_rows(tid)
            if not rep_idxs:
                continue

            ex_emb     = self.index.example_emb[rep_idxs]
            sims       = _cosine(task_emb, ex_emb)[0]
            order      = _topk_indices_desc(sims, self.candidate_top_k_examples)
            top_scores = sims[order]
            top_rows   = [rep_idxs[j] for j in order]

            scibert_score  = float(np.mean(top_scores)) if len(top_scores) else 0.0
            support_count  = len(self.index.examples_by_tid.get(tid, []))
            planner_prior  = planner_prior_map.get(tid, 0.0)
            stage          = str(task.get("stage", "")).strip().lower()
            stage_fit      = self._stage_fit_score(tid, stage)
            support_bonus  = self._support_bonus(support_count)
            rule_bonus, rule_notes = self._rule_adjustments(tid, task)

            final_score = (
                0.30 * planner_prior  +
                0.30 * stage_fit      +
                0.25 * scibert_score  +
                0.15 * support_bonus  +
                rule_bonus
            )

            reasons = [
                f"{self.index.examples[row]['source']}: {self.index.examples[row]['text'][:140]}"
                for row in top_rows
            ]

            scored.append(CandidateScore(
                technique_id  = tid,
                score         = float(final_score),
                scibert_score = float(scibert_score),
                planner_prior = float(planner_prior),
                stage_fit     = float(stage_fit),
                support_bonus = float(support_bonus),
                support_count = support_count,
                reasons       = reasons,
                source        = source,
                rule_notes    = rule_notes,
            ))

        scored.sort(key=lambda x: (x.score, x.scibert_score, x.support_count), reverse=True)
        return scored

    # ------------------------------------------------------------------
    # Fallback retrieval (2-tier)
    # ------------------------------------------------------------------

    def _fallback_retrieve_from_pool(
        self,
        task_emb: np.ndarray,
        tids: List[str],
        task: Dict[str, Any],
        planner_prior_map: Dict[str, float],
    ) -> List[CandidateScore]:
        return self._score_tids_hybrid(
            task_emb=task_emb,
            tids=tids,
            source="fallback_retrieval",
            task=task,
            planner_prior_map=planner_prior_map,
        )

    def _fallback_retrieve(
        self,
        task_emb: np.ndarray,
        stage: str,
        task: Dict[str, Any],
        planner_prior_map: Dict[str, float],
    ) -> List[CandidateScore]:
        # Tier 1: stage-compatible pool
        pool   = self.index.stage_compatible_techniques(stage)
        scored = self._fallback_retrieve_from_pool(task_emb, pool, task, planner_prior_map)
        if scored and scored[0].score >= 0.58:
            return scored

        # Tier 2: centroid pre-filter (cached matrix) → shortlist → hybrid score
        sims  = _cosine(task_emb, self.index.centroid_matrix)[0]
        order = _topk_indices_desc(sims, min(self.fallback_top_k_techniques, len(self.index.technique_ids)))
        shortlisted = [self.index.technique_ids[i] for i in order]
        return self._fallback_retrieve_from_pool(task_emb, shortlisted, task, planner_prior_map)

    # ------------------------------------------------------------------
    # Decision logic
    # ------------------------------------------------------------------

    def _decide(
        self,
        scored: List[CandidateScore],
    ) -> Tuple[List[str], str, str, str, List[Dict]]:
        if not scored:
            return [], "unmapped", "low", "no candidates to verify", []

        # Parent-child cleanup + re-sort
        cleaned_ids = self._resolve_specific_over_generic([s.technique_id for s in scored])
        scored = [s for s in scored if s.technique_id in cleaned_ids]
        scored.sort(key=lambda x: (x.score, x.scibert_score, x.support_count), reverse=True)

        if not scored:
            return [], "unmapped", "low", "all candidates removed by ontology cleanup", []

        top1 = scored[0]
        top2 = scored[1] if len(scored) > 1 else None

        debug_scores = [{
            "technique_id":  s.technique_id,
            "final_score":   round(s.score, 4),
            "scibert_score": round(s.scibert_score, 4),
            "planner_prior": round(s.planner_prior, 4),
            "stage_fit":     round(s.stage_fit, 4),
            "support_bonus": round(s.support_bonus, 4),
            "support_count": s.support_count,
            "source":        s.source,
            "rule_notes":    s.rule_notes[:5],
            "top_reasons":   s.reasons[:3],
        } for s in scored]

        # Re-check threshold AFTER cleanup
        if top1.score < self.accept_threshold:
            return [], "unmapped", "low", \
                "top candidate after ontology cleanup below threshold", debug_scores

        final_tids = [top1.technique_id]
        note = f"verified via hybrid scoring; top={top1.technique_id}"

        # Multi-label — source no longer required to match
        if top2:
            pair        = frozenset({top1.technique_id, top2.technique_id})
            close_scores = abs(top1.score - top2.score) <= self.ambiguity_gap
            both_strong  = top2.score >= self.accept_threshold

            if both_strong and (pair in self.KNOWN_OVERLAP_PAIRS or close_scores):
                candidate_pair = self._resolve_specific_over_generic(
                    [top1.technique_id, top2.technique_id]
                )
                if len(candidate_pair) == 2:
                    final_tids = candidate_pair
                    note = (
                        f"multi-label verified via hybrid scoring; "
                        f"both supported ({candidate_pair[0]}, {candidate_pair[1]})"
                    )

        # Confidence — multi-label not auto-capped at medium
        if len(final_tids) == 1:
            if top1.score >= 0.82 and top1.scibert_score >= 0.68:
                confidence = "high"
            elif top1.score >= 0.68:
                confidence = "medium"
            else:
                confidence = "low"
        else:
            if top2 and top1.score >= 0.82 and top2.score >= 0.78:
                confidence = "high"
            else:
                confidence = "medium"

        if len(final_tids) == 2 and top2 and abs(top1.score - top2.score) <= self.ambiguity_gap:
            note += " | scores are close and both retained"

        return final_tids, "verified", confidence, note, debug_scores

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def verify_mission(self, mission: Dict[str, Any]) -> Dict[str, Any]:
        out = deepcopy(mission)
        mission_intent = str(
            out.get("normalized_intent") or
            out.get("original_intent") or
            out.get("intent", "")
        )
        reports = []

        for task in out.get("execution_graph", []):
            stage = str(task.get("stage", "")).strip().lower()

            # data-processing: skip MITRE verification
            if stage == "data-processing":
                task["mitre_techniques"]  = []
                task["mitre_status"]      = "not_applicable"
                task["mapping_confidence"] = "high"
                existing_note = str(task.get("ambiguity_notes", "") or "").strip()
                task["ambiguity_notes"] = (
                    f"{existing_note} | data-processing task; no MITRE verification required"
                ).strip(" |")
                reports.append({
                    "task_id":               task.get("task_id"),
                    "stage":                 task.get("stage"),
                    "intent":                task.get("intent"),
                    "behavioral_goal":       task.get("behavioral_goal"),
                    "final_mitre_techniques":[], 
                    "mitre_status":          "not_applicable",
                    "mapping_confidence":    "high",
                    "decision_trace":        {"mode": "data-processing-skip"},
                    "candidate_scores":      [],
                })
                continue

            task_text_str     = _task_text(task, mission_intent=mission_intent)
            task_emb          = self.encoder.encode([task_text_str], batch_size=1, max_length=128)
            planner_candidate_ids = self._planner_candidate_ids(task)
            planner_prior_map     = self._planner_candidate_map(task)

            # Step 1: score planner candidates
            scored = self._score_tids_hybrid(
                task_emb=task_emb,
                tids=planner_candidate_ids,
                source="candidate_rerank",
                task=task,
                planner_prior_map=planner_prior_map,
            )

            # Step 2: smarter fallback trigger
            need_fallback = (
                not scored
                or scored[0].score < self.weak_candidate_threshold
                or len(planner_candidate_ids) < 2
            )
            if scored and len(scored) >= 2:
                if abs(scored[0].score - scored[1].score) <= 0.03 and scored[0].score < 0.68:
                    need_fallback = True

            if need_fallback:
                fallback_scored = self._fallback_retrieve(
                    task_emb=task_emb,
                    stage=stage,
                    task=task,
                    planner_prior_map=planner_prior_map,
                )
                merged = {s.technique_id: s for s in scored}
                for fs in fallback_scored:
                    cur = merged.get(fs.technique_id)
                    if cur is None or fs.score > cur.score:
                        merged[fs.technique_id] = fs
                scored = sorted(
                    merged.values(),
                    key=lambda x: (x.score, x.scibert_score, x.support_count),
                    reverse=True,
                )

            final_tids, mitre_status, confidence, note, debug_scores = self._decide(scored)

            task["mitre_techniques"]   = final_tids
            task["mitre_status"]       = mitre_status
            task["mapping_confidence"] = confidence
            existing_note = str(task.get("ambiguity_notes", "") or "").strip()
            task["ambiguity_notes"] = f"{existing_note} | {note}".strip(" |")

            reports.append({
                "task_id":                task.get("task_id"),
                "stage":                  task.get("stage"),
                "intent":                 task.get("intent"),
                "behavioral_goal":        task.get("behavioral_goal"),
                "planner_candidate_ids":  planner_candidate_ids,
                "final_mitre_techniques": final_tids,
                "mitre_status":           mitre_status,
                "mapping_confidence":     confidence,
                "decision_trace": {
                    "fallback_used":              need_fallback,
                    "planner_candidate_count":    len(planner_candidate_ids),
                    "top_candidate_after_hybrid": debug_scores[0]["technique_id"] if debug_scores else None,
                    "top_candidate_score":        debug_scores[0]["final_score"]   if debug_scores else None,
                },
                "candidate_scores": debug_scores,
            })

        out["verifier_summary"] = {
            "backend":              "HybridVerifierV9",
            "dataset_example_count": self.index.meta["example_count"],
            "technique_count":      len(self.index.technique_ids),
            "mode":                 "hybrid_planner_prior_rules_scibert_with_fallback",
            "rep_per_technique":    self.index.meta["rep_per_technique"],
        }
        out["verifier_task_reports"] = reports
        return out


# Legacy alias — keeps existing scripts/CLI working
SciBERTDatasetVerifierV8 = HybridVerifierV9


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Verifier v9")
    parser.add_argument("--mission",                    required=True)
    parser.add_argument("--datasets",                   required=True, nargs="+")
    parser.add_argument("--backend",                    choices=["scibert"], default="scibert")
    parser.add_argument("--model-name",                 default="allenai/scibert_scivocab_uncased")
    parser.add_argument("--accept-threshold",           type=float, default=0.62)
    parser.add_argument("--ambiguity-gap",              type=float, default=0.06)
    parser.add_argument("--weak-candidate-threshold",   type=float, default=0.52)
    parser.add_argument("--fallback-top-k-techniques",  type=int,   default=8)
    parser.add_argument("--cache-dir",                  default=".verifier_cache")
    parser.add_argument("--out",                        default="")
    args = parser.parse_args()

    mission = json.loads(Path(args.mission).read_text(encoding="utf-8"))

    verifier = HybridVerifierV9(
        dataset_paths            = args.datasets,
        encoder_backend          = args.backend,
        model_name               = args.model_name,
        accept_threshold         = args.accept_threshold,
        ambiguity_gap            = args.ambiguity_gap,
        weak_candidate_threshold = args.weak_candidate_threshold,
        fallback_top_k_techniques= args.fallback_top_k_techniques,
        cache_dir                = args.cache_dir,
    )

    verified = verifier.verify_mission(mission)

    out_dir = Path("artifacts/missions_verified")
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = (
        Path(args.out) if args.out
        else out_dir / (Path(args.mission).stem + "_verified.json")
    )
    out_path.write_text(json.dumps(verified, indent=2, ensure_ascii=False), encoding="utf-8")

    # Summary
    all_techniques: set = set()
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