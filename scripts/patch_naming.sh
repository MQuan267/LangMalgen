
#!/usr/bin/env bash
set -euo pipefail

# small helper: add helpers + STACK_NAME after a matched import line
inject_helpers() { # file default_stack
  local f="$1"; local defstack="$2"
  if ! grep -q "_stamp():" "$f"; then
    awk -v defstack="$defstack" '
      /from openai import OpenAI|from google import genai/ && !done {
        print $0
        print ""
        print "import os"
        print "from datetime import datetime, timezone  # for stamp"
        print ""
        print "STACK_NAME = os.getenv(\"AGENT_STACK\", \"" defstack "\")"
        print ""
        print "def _stamp() -> str:"
        print "    return datetime.now(timezone.utc).strftime(\"%Y%m%d_%H%M%S_%f\")"
        print ""
        print "def _prefix(stack: str, agent: str, idx: int | None = None) -> str:"
        print "    parts = [stack, agent]"
        print "    if idx is not None:"
        print "        parts.append(f\"{idx:02d}\")"
        print "    parts.append(_stamp())"
        print "    return \"_\".join(parts)"
        print ""
        done=1; next
      }
      { print $0 }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  fi
}

# ------------- Developer (OpenAI/Gemini) -------------
patch_developer() { # file
  local f="$1"
  inject_helpers "$f" "$(echo "$f" | grep -q openai && echo openai || echo gemini)"

  # 1) add index param in _emit_module_file signature
  sed -i 's/def _emit_module_file(\([^)]*\)) -> str:/def _emit_module_file(\1, index: int) -> str:/' "$f"

  # 2) change output filename to prefixed pattern
  #   insert prefix=... line before fp=... and change fp format
  awk '
    BEGIN{changed=0}
    /out_dir = Path\("artifacts\/modules"\).*fp = out_dir/ {changed=1}
    {print > ".__tmp"}
  ' "$f" >/dev/null 2>&1 || true
  if grep -q 'fp = out_dir / f".*subtask_id.*safe_name.*\.py"' "$f"; then
    sed -i 's/fp = out_dir \/ f\"\(.*\)subtask_id\(.*\)safe_name\(.*\)\.py\"/prefix = _prefix(STACK_NAME, "developer", index)\n    fp = out_dir \/ f"{prefix}_\1subtask_id\2safe_name\3.py"/' "$f"
  else
    # a safer generic replace for previous variant
    sed -i 's/fp = out_dir \/ f\".*\"/prefix = _prefix(STACK_NAME, "developer", index)\n    fp = out_dir \/ f"{prefix}_{subtask_id}_{safe_name}.py"/' "$f"
  fi

  # 3) enumerate specs and pass idx
  sed -i 's/for s in specs:/for idx, s in enumerate(specs, 1):/' "$f"
  sed -i 's/_emit_module_file(\(.*\)s\.spec)/_emit_module_file(\1s.spec, idx)/' "$f"
}

# ------------- Integrator (OpenAI/Gemini) -------------
patch_integrator() { # file
  local f="$1"
  inject_helpers "$f" "$(echo "$f" | grep -q openai && echo openai || echo gemini)"

  # change pipeline filename to prefixed pattern
  # from: fp = out_dir / "pipeline.py"
  # to:   prefix = _prefix(STACK_NAME, "integrator"); fp = out_dir / f"{prefix}_pipeline.py"
  if grep -q 'fp = out_dir / "pipeline.py"' "$f"; then
    sed -i 's/fp = out_dir \/ "pipeline.py"/prefix = _prefix(STACK_NAME, "integrator")\n        fp = out_dir \/ f"{prefix}_pipeline.py"/' "$f"
  fi
  # another variant (already had name) – normalize anyway
  if grep -q 'fp = out_dir / f".*_pipeline.py"' "$f"; then
    sed -i 's/fp = out_dir \/ f".*_pipeline.py"/prefix = _prefix(STACK_NAME, "integrator")\n        fp = out_dir \/ f"{prefix}_pipeline.py"/' "$f"
  fi
}

# ------------- Builder (OpenAI/Gemini) -------------
patch_builder() { # file
  local f="$1"
  inject_helpers "$f" "$(echo "$f" | grep -q openai && echo openai || echo gemini)"

  # exe_name line -> prefix-based
  # from: exe_name = f"{self.cfg.name_prefix}_{run_id[:8]}_{ts}"
  # to:   prefix = _prefix(STACK_NAME, "builder"); exe_name = f"{prefix}"
  if grep -q 'exe_name = f"{self.cfg.name_prefix}' "$f"; then
    sed -i 's/exe_name = f"{self.cfg.name_prefix}[^"]*"/prefix = _prefix(STACK_NAME, "builder")\n        exe_name = f"{prefix}"/' "$f"
  fi

  # manifest path -> prefix-based manifest file
  if grep -q 'manifest_path = Path("artifacts/latest_bundle/manifest.json")' "$f"; then
    sed -i 's|manifest_path = Path("artifacts/latest_bundle/manifest.json")|manifest_path = Path("artifacts/latest_bundle") / f"{prefix}_manifest.json"|' "$f"
  fi
}

# Run patches
files_dev=("src/agents/developer_openai.py" "src/agents/developer_gemini.py")
files_int=("src/agents/integrator_openai.py" "src/agents/integrator_gemini.py")
files_bld=("src/agents/builder_openai.py" "src/agents/builder_gemini.py")

for f in "${files_dev[@]}"; do
  [[ -f "$f" ]] && patch_developer "$f" || echo "[skip] $f not found"
done
for f in "${files_int[@]}"; do
  [[ -f "$f" ]] && patch_integrator "$f" || echo "[skip] $f not found"
done
for f in "${files_bld[@]}"; do
  [[ -f "$f" ]] && patch_builder "$f" || echo "[skip] $f not found"
done

echo "✓ Naming patch applied. Files will now be saved as <stack>_<agent>_<index?>_<timestamp>..."


