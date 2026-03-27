"""
mitre_classifier.py — Two-Stage MITRE ATT&CK Technique Classifier
==================================================================
Stage 1 : Coarse filter — map task stage → candidate technique families (O(1))
Stage 2 : Fine classification — cosine similarity on OpenAI embeddings
Fallback : Constrained LLM (gpt-4o-mini) — only when similarity < threshold

Cost estimate:
  - Build index : ~700 techniques × ~50 tokens = ~35K tokens ≈ $0.0007 (one-time)
  - Runtime     : ~10 tokens per task ≈ $0.0000002 per classification

Usage:
    classifier = MitreClassifier(openai_client)
    result = classifier.classify(
        behavioral_goal="Capture full desktop bitmap at interval",
        stage="execution",
    )
    # → ClassificationResult(techniques=["T1113"], method="override", ...)

Setup:
    pip install openai numpy python-dotenv
    python mitre_classifier.py --build-index   # one-time, ~30 seconds
    python mitre_classifier.py --test           # verify accuracy
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# ── Constants ──────────────────────────────────────────────────────────────────

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

CACHE_DIR       = Path("artifacts/mitre_cache")
STIX_CACHE      = CACHE_DIR / "enterprise-attack.json"
EMBEDDING_CACHE = CACHE_DIR / "technique_embeddings_oai.npz"
METADATA_CACHE  = CACHE_DIR / "technique_metadata.json"

EMBEDDING_MODEL      = "text-embedding-3-small"
SIMILARITY_THRESHOLD = 0.45   # below this → LLM fallback

# ── Stage → MITRE Tactic Mapping (Stage 1 coarse filter) ──────────────────────

STAGE_TO_TACTICS: Dict[str, List[str]] = {
    "recon":               ["reconnaissance"],
    "discovery":           ["discovery"],
    "initial-access":      ["initial-access"],
    "execution":           ["execution", "collection", "command-and-control"],  # c2 has T1105
    "privilege-escalation":["privilege-escalation"],
    "persistence":         ["persistence"],
    "defense-evasion":     ["defense-evasion"],
    "exfiltration":        ["exfiltration", "command-and-control"],
    "lateral-movement":    ["lateral-movement"],
    "credential-access":   ["credential-access"],
    "weaponization":       ["execution", "defense-evasion"],
    "c2-setup":            ["command-and-control"],
    "data-processing":     [],  # always empty — no MITRE
}

# ── Override Rules (deterministic, no model needed) ───────────────────────────
# Format: (keywords_any_of, stage_filter, techniques)
# Applied BEFORE embedding — highest confidence patterns

OVERRIDE_RULES: List[Tuple[Tuple[str, ...], str, List[str]]] = [
    # Screenshot / screen capture
    (("screenshot", "screen capture", "desktop bitmap", "capture desktop",
      "imagegrab", "printscreen", "capture screen", "capture full desktop",
      "bitmap at interval"),
     "execution", ["T1113"]),

    # Keylogger
    (("keylog", "keystroke", "keyboard hook", "hook keyboard"),
     "execution", ["T1056.001"]),

    # HTTPS/HTTP exfiltration
    (("https post", "http post", "post encrypted", "post to c2",
      "upload to c2", "exfil via https", "exfil via http"),
     "exfiltration", ["T1041", "T1071.001"]),

    # Registry run key persistence
    (("registry", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
      "hklm\\software", "run key"),
     "persistence", ["T1547.001"]),

    # Scheduled task persistence
    (("scheduled task", "schtasks", "task scheduler"),
     "persistence", ["T1053.005"]),

    # Encrypt/obfuscate before transmit
    (("aes-encrypt", "aes encrypt", "encrypt before transmit",
      "encrypt before send", "encrypt payload", "aes-encrypt compressed"),
     "defense-evasion", ["T1027"]),

    # Download payload / ingress tool transfer
    (("download", "shellcode", "fetch payload", "pull from", "remote server",
      "ingress", "dropper", "download payload", "download shellcode",
      "fetch from", "retrieve from"),
     "execution", ["T1105"]),

    # Process enumeration
    (("enumerate process", "running process", "list process", "process list",
      "ps aux", "tasklist", "enum process"),
     "discovery", ["T1057"]),

    # Process injection
    (("inject", "process injection", "shellcode inject"),
     "defense-evasion", ["T1055"]),

    # LSASS dump
    (("lsass", "minidump", "credential dump"),
     "credential-access", ["T1003.001"]),

    # File enumeration / discovery
    (("enumerate file", "enumerate all", ".pdf", ".xlsx", ".docx", ".doc",
      "glob", "os.walk", "file and directory", "find file", "search file"),
     "discovery", ["T1083"]),

    # Archive / compress collected data
    (("compress", "zip archive", "zip file", "archive", "compress file",
      "compress into zip", "zipfile"),
     "defense-evasion", ["T1560.001"]),
]


# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class TechniqueMetadata:
    tid:             str
    name:            str
    description:     str
    tactics:         List[str]
    is_subtechnique: bool = False

    def embed_text(self) -> str:
        """Text sent to embedding model."""
        return f"{self.tid} {self.name}: {self.description[:250]}"


@dataclass
class ClassificationResult:
    techniques:           List[str]
    scores:               Dict[str, float]
    method:               str   # "override"|"embedding"|"llm_fallback"|"empty"
    candidates_evaluated: int = 0


# ── MitreClassifier ────────────────────────────────────────────────────────────

class MitreClassifier:
    """
    Two-stage MITRE ATT&CK technique classifier backed by OpenAI embeddings.

    Stage 1  : stage → tactic families → candidate indices  (O(1), deterministic)
    Stage 2  : cosine similarity query vs candidates         (deterministic after cache)
    Fallback : constrained LLM with candidate list           (only <5% of cases)
    """

    def __init__(
        self,
        openai_client=None,
        model:     str   = "gpt-4o-mini",
        threshold: float = SIMILARITY_THRESHOLD,
        verbose:   bool  = False,
    ) -> None:
        self.client    = openai_client
        self.model     = model
        self.threshold = threshold
        self.verbose   = verbose

        self._embeddings:   Optional[np.ndarray]      = None
        self._metadata:     List[TechniqueMetadata]   = []
        self._tactic_index: Dict[str, List[int]]      = {}

        self._ensure_cache()
        self._load_index()

    # ── Public API ─────────────────────────────────────────────────────────────

    def classify(
        self,
        behavioral_goal: str,
        stage: str,
        top_k: int = 2,
    ) -> ClassificationResult:
        """Classify a single task into MITRE techniques."""
        stage = stage.lower().strip()

        # data-processing → always empty
        if stage == "data-processing":
            return ClassificationResult([], {}, "empty")

        # ── Override rules ─────────────────────────────────────────────────
        override = self._apply_overrides(behavioral_goal, stage)
        if override is not None:
            self._log(f"override → {override}")
            return ClassificationResult(
                override, {t: 1.0 for t in override}, "override"
            )

        # ── Stage 1: coarse filter ─────────────────────────────────────────
        candidate_idx = self._stage1_filter(stage)
        if not candidate_idx:
            candidate_idx = list(range(len(self._metadata)))
        self._log(f"stage1: {len(candidate_idx)} candidates for '{stage}'")

        # ── Stage 2: embedding similarity ─────────────────────────────────
        query = f"Malware task stage={stage}: {behavioral_goal}"
        results, scores = self._stage2_similarity(query, candidate_idx, top_k)
        best = max(scores.values()) if scores else 0.0
        self._log(f"stage2 best={best:.3f} → {results}")

        if best >= self.threshold:
            results = self._enrich_exfil(results, behavioral_goal, stage)
            return ClassificationResult(
                results, scores, "embedding", len(candidate_idx)
            )

        # ── Fallback: constrained LLM ──────────────────────────────────────
        self._log(f"below threshold ({best:.3f}) → LLM fallback")
        llm = self._llm_fallback(behavioral_goal, stage, candidate_idx[:20])
        if llm:
            llm = self._enrich_exfil(llm, behavioral_goal, stage)
            return ClassificationResult(
                llm, {}, "llm_fallback", len(candidate_idx)
            )

        # Best-effort: return low-confidence embedding result
        results = self._enrich_exfil(results, behavioral_goal, stage)
        return ClassificationResult(results, scores, "embedding", len(candidate_idx))

    def classify_mission(
        self, mission: dict
    ) -> Tuple[dict, List[str], List[str]]:
        """
        Classify all tasks in a mission dict.
        Drop-in replacement for PlannerVerifier._llm_mitre_fix().

        For each task:
          1. classify(goal, stage) → new_techniques
          2. _validate_techniques(new, stage) → filter invalid ones
          3. If any technique fails validation → rollback to old
          4. Else apply new

        Returns: (updated_mission, fixes, warnings)
        """
        mission  = deepcopy(mission)
        fixes:    List[str] = []
        warnings: List[str] = []

        for task in mission.get("execution_graph", []):
            tid   = task.get("task_id", "?")
            stage = task.get("stage", "")
            goal  = task.get("behavioral_goal", "")
            old   = task.get("mitre_techniques", [])

            result = self.classify(goal, stage)

            if stage == "data-processing":
                if old:
                    task["mitre_techniques"] = []
                    fixes.append(f"{tid}: data-processing → []")
                continue

            new = result.techniques

            # ── Self-validation loop ───────────────────────────────────────
            valid, invalid = self._validate_techniques(new, stage)

            if invalid:
                self._log(f"{tid}: validation rejected {invalid} for stage='{stage}'")
                if valid:
                    # Keep only validated subset
                    new = valid
                    warnings.append(
                        f"{tid}: dropped invalid techniques {invalid} "
                        f"(not matching stage '{stage}')"
                    )
                else:
                    # All new techniques failed → rollback to old
                    self._log(f"{tid}: all new techniques invalid → rollback to {old}")
                    warnings.append(
                        f"{tid}: classifier result fully invalid for stage '{stage}', "
                        f"keeping original {old}"
                    )
                    continue

            # Guard: embedding adds extra techniques on top of already-correct old
            # → keep existing to avoid noise
            if (
                old
                and result.method == "embedding"
                and all(t in new for t in old)
                and len(new) > len(old)
            ):
                self._log(f"{tid}: keeping existing {old} (embedding would add noise {new})")
                continue

            if sorted(old) != sorted(new):
                task["mitre_techniques"] = new
                fixes.append(
                    f"{tid}: MITRE {old} → {new} "
                    f"(method={result.method}, "
                    f"candidates_evaluated={result.candidates_evaluated})"
                )

        return mission, fixes, warnings

    def _validate_techniques(
        self,
        techniques: List[str],
        stage: str,
    ) -> Tuple[List[str], List[str]]:
        """
        Validate each technique is appropriate for the given stage.

        Looks up technique in metadata → checks if ANY tactic matches
        the expected tactics for this stage.

        Unknown techniques (not in index) → pass through (benefit of doubt).

        Returns: (valid_techniques, invalid_techniques)
        """
        if not techniques:
            return [], []

        expected_tactics = set(STAGE_TO_TACTICS.get(stage, []))
        if not expected_tactics:
            return list(techniques), []

        tid_to_meta: Dict[str, TechniqueMetadata] = {
            m.tid: m for m in self._metadata
        }

        valid:   List[str] = []
        invalid: List[str] = []

        for tid in techniques:
            meta = tid_to_meta.get(tid)

            if meta is None:
                # Sub-technique or unknown → accept (benefit of doubt)
                self._log(f"  validate: {tid} not in index → accept")
                valid.append(tid)
                continue

            technique_tactics = set(meta.tactics)
            if technique_tactics & expected_tactics:
                self._log(
                    f"  validate: {tid} ({meta.name}) "
                    f"tactics={meta.tactics} ∩ expected={sorted(expected_tactics)} ✅"
                )
                valid.append(tid)
            else:
                self._log(
                    f"  validate: {tid} ({meta.name}) "
                    f"tactics={meta.tactics} ∩ expected={sorted(expected_tactics)} ❌"
                )
                invalid.append(tid)

        return valid, invalid

    # ── Stage 1 ────────────────────────────────────────────────────────────────

    def _stage1_filter(self, stage: str) -> List[int]:
        tactics  = STAGE_TO_TACTICS.get(stage, [])
        indices: set = set()
        for tactic in tactics:
            indices.update(self._tactic_index.get(tactic, []))
        return list(indices)

    # ── Stage 2 ────────────────────────────────────────────────────────────────

    def _stage2_similarity(
        self,
        query: str,
        candidate_idx: List[int],
        top_k: int,
    ) -> Tuple[List[str], Dict[str, float]]:
        if not candidate_idx or self._embeddings is None:
            return [], {}

        query_emb = self._embed([query])[0]           # [D]
        cand_embs = self._embeddings[candidate_idx]   # [N, D]
        sims      = cand_embs @ query_emb             # [N] cosine (normalized)

        k       = min(top_k, len(candidate_idx))
        top_pos = np.argpartition(sims, -k)[-k:]
        top_pos = top_pos[np.argsort(sims[top_pos])[::-1]]

        results, scores = [], {}
        for pos in top_pos:
            meta  = self._metadata[candidate_idx[pos]]
            score = float(sims[pos])
            if score > 0:
                results.append(meta.tid)
                scores[meta.tid] = round(score, 4)
                self._log(f"  {meta.tid} ({meta.name}): {score:.4f}")

        return results, scores

    # ── Override & Enrich ──────────────────────────────────────────────────────

    def _apply_overrides(self, goal: str, stage: str) -> Optional[List[str]]:
        goal_lower = goal.lower()
        for keywords, rule_stage, techniques in OVERRIDE_RULES:
            if rule_stage and rule_stage != stage:
                continue
            if any(kw in goal_lower for kw in keywords):
                return techniques
        return None

    def _enrich_exfil(
        self, techniques: List[str], goal: str, stage: str
    ) -> List[str]:
        """HTTPS exfil always needs T1041 + T1071.001."""
        if stage != "exfiltration":
            return techniques
        if any(k in goal.lower() for k in ("https", "http", "post", "requests", "upload")):
            result = list(techniques)
            for must in ("T1041", "T1071.001"):
                if must not in result:
                    result.append(must)
            return result
        return techniques

    # ── LLM Fallback ───────────────────────────────────────────────────────────

    def _llm_fallback(
        self,
        goal: str,
        stage: str,
        candidate_idx: List[int],
    ) -> Optional[List[str]]:
        if not self.client:
            return None

        candidates = [self._metadata[i] for i in candidate_idx]
        tech_list  = "\n".join(
            f"- {t.tid} | {t.name} | {t.description[:80]}"
            for t in candidates
        )

        prompt = (
            "You are a MITRE ATT&CK v14 classifier. Classify the task below.\n\n"
            f"Stage          : {stage}\n"
            f"Behavioral goal: {goal}\n\n"
            f"Choose ONLY from these candidates:\n{tech_list}\n\n"
            "Rules:\n"
            "- Pick 1-2 most specific techniques\n"
            "- Prefer sub-techniques (T1xxx.xxx) over parent when available\n"
            "- Do NOT invent techniques outside the list above\n"
            "- Return [] if truly none apply\n\n"
            'Return ONLY JSON: {"techniques": ["T1xxx"], "reasoning": "one line"}'
        )

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=150,
            )
            result = json.loads(resp.choices[0].message.content or "{}")
            return result.get("techniques", [])
        except Exception as e:
            self._log(f"LLM fallback failed: {e}")
            return None

    # ── OpenAI Embedding ───────────────────────────────────────────────────────

    def _embed(self, texts: List[str]) -> np.ndarray:
        """
        Embed texts via OpenAI text-embedding-3-small.
        Returns L2-normalized float32 array [N, D].
        """
        if not self.client:
            raise RuntimeError(
                "OpenAI client required. Pass openai_client to MitreClassifier()."
            )
        response = self.client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=texts,
        )
        vectors = np.array(
            [item.embedding for item in response.data],
            dtype=np.float32,
        )
        # L2 normalize → cosine similarity = dot product
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        return vectors / np.maximum(norms, 1e-9)

    # ── Cache Management ───────────────────────────────────────────────────────

    def _ensure_cache(self) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

        if not STIX_CACHE.exists():
            print("📥 Downloading MITRE ATT&CK STIX (~10MB)...")
            urllib.request.urlretrieve(MITRE_STIX_URL, STIX_CACHE)
            print(f"   Saved → {STIX_CACHE}")

        if not METADATA_CACHE.exists():
            self._parse_stix()

        if not EMBEDDING_CACHE.exists():
            if not self.client:
                print("⚠️  No OpenAI client — run --build-index to generate embeddings")
                return
            self._build_embeddings()

    def _parse_stix(self) -> None:
        """Parse STIX JSON → metadata JSON cache."""
        print("🔨 Parsing MITRE STIX...")
        stix     = json.loads(STIX_CACHE.read_text(encoding="utf-8"))
        metadata = []

        for obj in stix.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            # Enterprise ATT&CK only — exclude ICS and Mobile
            domains = obj.get("x_mitre_domains", [])
            if domains and "enterprise-attack" not in domains:
                continue

            tid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tid = ref.get("external_id")
                    break
            if not tid or not tid.startswith("T"):
                continue

            tactics = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]

            desc = obj.get("description", "")
            desc = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", desc)
            desc = re.sub(r"\s+", " ", desc).strip()

            metadata.append({
                "tid":             tid,
                "name":            obj.get("name", ""),
                "description":     desc[:300],
                "tactics":         tactics,
                "is_subtechnique": "." in tid,
            })

        METADATA_CACHE.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"   Parsed {len(metadata)} techniques → {METADATA_CACHE}")

    def _build_embeddings(self) -> None:
        """Encode all technique descriptions, save .npz cache."""
        raw   = json.loads(METADATA_CACHE.read_text(encoding="utf-8"))
        texts = [TechniqueMetadata(**m).embed_text() for m in raw]

        total_tokens_est = sum(len(t.split()) for t in texts)
        cost_est = total_tokens_est / 1_000_000 * 0.02
        print(f"🔢 Encoding {len(texts)} techniques ({total_tokens_est:,} tokens est.)")
        print(f"   Estimated cost: ~${cost_est:.4f} (one-time only)")

        batch_size     = 100
        all_embeddings = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            embs  = self._embed(batch)
            all_embeddings.append(embs)
            print(f"   {min(i + batch_size, len(texts))}/{len(texts)} encoded...")

        embeddings = np.vstack(all_embeddings).astype(np.float32)
        np.savez_compressed(EMBEDDING_CACHE, embeddings=embeddings)
        print(f"   Saved → {EMBEDDING_CACHE}  shape={embeddings.shape}")

    def _load_index(self) -> None:
        if not METADATA_CACHE.exists() or not EMBEDDING_CACHE.exists():
            return

        raw = json.loads(METADATA_CACHE.read_text(encoding="utf-8"))
        self._metadata = [TechniqueMetadata(**m) for m in raw]

        data             = np.load(EMBEDDING_CACHE)
        self._embeddings = data["embeddings"]

        for i, m in enumerate(self._metadata):
            for tactic in m.tactics:
                self._tactic_index.setdefault(tactic, []).append(i)

        print(
            f"✓ MITRE index: {len(self._metadata)} techniques, "
            f"{len(self._tactic_index)} tactics"
        )

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"    [mitre] {msg}")


# ── Integration: drop-in patch for PlannerVerifier ────────────────────────────

def patch_planner_verifier(
    verifier_instance, verbose: bool = False
) -> MitreClassifier:
    """
    Patch a PlannerVerifier to use MitreClassifier instead of _llm_mitre_fix().

    Add 2 lines to verifierv5.py:
        from mitre_classifier import patch_planner_verifier
        patch_planner_verifier(verifier)
    """
    import types

    classifier = MitreClassifier(
        openai_client=verifier_instance.client,
        model=verifier_instance.model,
        verbose=verbose,
    )

    def _patched(self, mission, intent=""):
        return classifier.classify_mission(mission)

    verifier_instance._llm_mitre_fix = types.MethodType(
        _patched, verifier_instance
    )
    return classifier


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    from openai import OpenAI

    load_dotenv()
    client = OpenAI()

    parser = argparse.ArgumentParser(description="MITRE Two-Stage Classifier")
    parser.add_argument("--build-index", action="store_true",
                        help="Download STIX + build embedding index (one-time)")
    parser.add_argument("--classify",    type=str, default="",
                        help="Classify a behavioral goal string")
    parser.add_argument("--stage",       type=str, default="execution")
    parser.add_argument("--threshold",   type=float, default=SIMILARITY_THRESHOLD)
    parser.add_argument("--verbose",     action="store_true")
    parser.add_argument("--test",        action="store_true",
                        help="Run built-in accuracy test suite")
    args = parser.parse_args()

    classifier = MitreClassifier(
        openai_client=client,
        threshold=args.threshold,
        verbose=args.verbose,
    )

    if args.build_index:
        print("✅ Index ready")

    elif args.classify:
        result = classifier.classify(args.classify, args.stage)
        print(f"\nGoal  : {args.classify}")
        print(f"Stage : {args.stage}")
        print(f"Result: {result.techniques}  (method={result.method})")
        for tid, score in sorted(result.scores.items(), key=lambda x: -x[1]):
            print(f"  {tid}: {score:.4f}")

    elif args.test:
        TEST_CASES = [
            ("Capture full desktop bitmap at interval",          "execution",       ["T1113"]),
            ("JPEG-compress screenshot to reduce exfiltration",  "data-processing", []),
            ("AES-encrypt compressed image before transmission", "defense-evasion", ["T1027"]),
            ("POST encrypted image to C2 endpoint via HTTPS",    "exfiltration",    ["T1041", "T1071.001"]),
            ("Add registry run key for persistence",             "persistence",     ["T1547.001"]),
            ("Hook keyboard to capture keystrokes",              "execution",       ["T1056.001"]),
            ("Enumerate running processes on host",              "discovery",       ["T1057"]),
            ("Download shellcode payload from remote server",    "execution",       ["T1105"]),
        ]

        passed = 0
        print("\n" + "="*65)
        print("MITRE CLASSIFIER — TEST SUITE")
        print("="*65)

        for goal, stage, expected in TEST_CASES:
            result  = classifier.classify(goal, stage)
            ok      = all(t in result.techniques for t in expected)
            passed += ok
            status  = "✅ PASS" if ok else "❌ FAIL"
            print(f"\n{status} [{stage}]")
            print(f"  Goal    : {goal}")
            print(f"  Expected: {expected}")
            print(f"  Got     : {result.techniques}  (method={result.method})")

        print(f"\n{'='*65}")
        print(f"Accuracy: {passed}/{len(TEST_CASES)}  ({passed/len(TEST_CASES)*100:.0f}%)")
        print("="*65)