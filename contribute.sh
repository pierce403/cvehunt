#!/usr/bin/env bash
set -euo pipefail

KNOWN_HARNESSES=(codex gemini claude opencode pi)
DEFAULT_CVE="CVE-2025-55182"

usage() {
  cat <<'USAGE'
Usage: ./contribute.sh [CVE-ID]

Interactive contributor runner for CVEHunt.

Environment overrides:
  CVEHUNT_CVE       CVE to run when no positional CVE is provided
  CVEHUNT_HARNESS   Agent harness label to record, for example codex or gemini
  CVEHUNT_MODEL     Model name to record; use the harness' real model slug
  CVEHUNT_SKIP_INSTALL=1  Skip uv/npm dependency installation checks
  CVEHUNT_SKIP_BUILD=1  Skip npm run build after the persisted run
  CVEHUNT_SKIP_GIT=1    Skip automatic git commit/push and PR recommendation
  CVEHUNT_DRY_RUN=1     Print commands without running them
  CVEHUNT_EXECUTE_POC=1 Build/run the localhost harness PoC with --execute-poc
USAGE
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

detect_harnesses() {
  local harness
  for harness in "${KNOWN_HARNESSES[@]}"; do
    if has_command "$harness"; then
      printf '%s\n' "$harness"
    fi
  done
}

is_known_harness() {
  local candidate="$1"
  local harness
  for harness in "${KNOWN_HARNESSES[@]}"; do
    if [[ "$candidate" == "$harness" ]]; then
      return 0
    fi
  done
  return 1
}

prompt() {
  local label="$1"
  local default_value="${2:-}"
  local value

  if [[ -n "$default_value" ]]; then
    read -r -p "$label [$default_value]: " value
    printf '%s\n' "${value:-$default_value}"
  else
    read -r -p "$label: " value
    printf '%s\n' "$value"
  fi
}

select_harness() {
  local override="${CVEHUNT_HARNESS:-}"
  local detected=("$@")
  local selected
  local index

  if [[ -n "$override" ]]; then
    if ! is_known_harness "$override"; then
      echo "Unsupported CVEHUNT_HARNESS: $override" >&2
      echo "Known harnesses: ${KNOWN_HARNESSES[*]}" >&2
      exit 2
    fi
    printf '%s\n' "$override"
    return
  fi

  if [[ "${#detected[@]}" -eq 0 ]]; then
    echo "No known harness CLI detected on PATH." >&2
    selected="$(prompt "Harness label to record (${KNOWN_HARNESSES[*]})" "")"
    if ! is_known_harness "$selected"; then
      echo "Unsupported harness: $selected" >&2
      exit 2
    fi
    printf '%s\n' "$selected"
    return
  fi

  echo "Detected harnesses:" >&2
  for index in "${!detected[@]}"; do
    printf '  %d) %s\n' "$((index + 1))" "${detected[$index]}" >&2
  done

  if [[ "${#detected[@]}" -eq 1 ]]; then
    selected="$(prompt "Harness" "${detected[0]}")"
  else
    selected="$(prompt "Harness number or name" "${detected[0]}")"
  fi

  if [[ "$selected" =~ ^[0-9]+$ ]]; then
    index=$((selected - 1))
    if (( index < 0 || index >= ${#detected[@]} )); then
      echo "Harness selection out of range: $selected" >&2
      exit 2
    fi
    selected="${detected[$index]}"
  fi

  if ! is_known_harness "$selected"; then
    echo "Unsupported harness: $selected" >&2
    exit 2
  fi

  printf '%s\n' "$selected"
}

codex_default_model() {
  local discovered
  discovered="$(codex debug models 2>/dev/null | python3 -c 'import json, sys
preferred = ["gpt-5.5", "gpt-5.4", "gpt-5.3-codex", "gpt-5.4-mini"]
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
slugs = [model.get("slug", "") for model in data.get("models", [])]
for candidate in preferred:
    if candidate in slugs:
        print(candidate)
        sys.exit(0)
if slugs:
    print(slugs[0])
' 2>/dev/null || true)"
  if [[ -n "$discovered" ]]; then
    printf '%s\n' "$discovered"
  else
    printf '%s\n' "gpt-5.5"
  fi
}

codex_model_is_available() {
  local model="$1"
  if ! has_command codex || ! has_command python3; then
    return 2
  fi
  codex debug models 2>/dev/null | python3 -c 'import json, sys
wanted = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(2)
for model in data.get("models", []):
    if model.get("slug") == wanted or model.get("display_name") == wanted:
        sys.exit(0)
sys.exit(1)
' "$model"
}

list_codex_models() {
  if ! has_command codex || ! has_command python3; then
    return
  fi
  codex debug models 2>/dev/null | python3 -c 'import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print(", ".join(model.get("slug", "") for model in data.get("models", []) if model.get("slug")))
' 2>/dev/null || true
}

pi_model_is_available() {
  local model="$1"
  local search="$model"
  local output
  if ! has_command pi; then
    return 2
  fi
  case "$search" in
    */*) search="${search#*/}" ;;
  esac
  output="$(pi --list-models "$search" 2>&1 || true)"
  printf '%s\n' "$output" | awk -v wanted="$search" 'NR > 1 && $2 == wanted { found = 1 } END { exit found ? 0 : 1 }'
}

validate_model_for_harness() {
  local harness="$1"
  local model="$2"
  local available

  case "$harness" in
    codex)
      if codex_model_is_available "$model"; then
        return
      fi
      available="$(list_codex_models)"
      echo "Unsupported Codex model: $model" >&2
      if [[ -n "$available" ]]; then
        echo "Available Codex model slugs: $available" >&2
      fi
      echo "Pick a real Codex slug from the local catalog instead of recording an unverifiable label." >&2
      exit 2
      ;;
    pi)
      if pi_model_is_available "$model"; then
        return
      fi
      echo "Unsupported Pi model: $model" >&2
      echo "Run 'pi --list-models' or open /model and use an exact listed provider/model label." >&2
      exit 2
      ;;
    *)
      echo "Warning: no local model catalog validator for $harness; recording '$model' as user-supplied attribution." >&2
      ;;
  esac
}

default_model_for_harness() {
  case "$1" in
    codex) codex_default_model ;;
    gemini) printf '%s\n' "gemini-2.5-pro" ;;
    claude) printf '%s\n' "" ;;
    opencode) printf '%s\n' "" ;;
    pi) printf '%s\n' "bastet/AEON-7/Gemma-4-31B-it-DECKARD-HERETIC-Uncensored-NVFP4" ;;
    *) printf '%s\n' "" ;;
  esac
}

confirm() {
  local label="$1"
  local answer

  read -r -p "$label [Y/n]: " answer
  case "$answer" in
    n|N|no|NO) return 1 ;;
    *) return 0 ;;
  esac
}

ensure_project_dependencies() {
  if [[ "${CVEHUNT_SKIP_INSTALL:-0}" == "1" ]]; then
    return
  fi

  if ! has_command uv; then
    echo "Missing required command: uv" >&2
    echo "Install uv first, then rerun this script." >&2
    exit 127
  fi

  if [[ ! -d ".venv" ]]; then
    if confirm "Python dependencies are not synced. Run uv sync --dev now?"; then
      uv sync --dev
    else
      echo "Cannot continue without Python dependencies." >&2
      exit 1
    fi
  fi

  if [[ "${CVEHUNT_SKIP_BUILD:-0}" != "1" ]]; then
    if ! has_command npm; then
      echo "Missing required command for dashboard build: npm" >&2
      echo "Set CVEHUNT_SKIP_BUILD=1 to run only the CVEHunt workflow." >&2
      exit 127
    fi

    if [[ ! -d "node_modules" ]]; then
      if confirm "Node dependencies are not installed. Run npm install now?"; then
        npm install
      else
        echo "Skipping dashboard build because node dependencies are missing." >&2
        export CVEHUNT_SKIP_BUILD=1
      fi
    fi
  fi
}

git_has_changes() {
  ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]
}

sanitize_ref_component() {
  printf '%s' "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//'
}

github_owner_from_remote_url() {
  local remote_url="$1"
  case "$remote_url" in
    git@github.com:*) printf '%s' "${remote_url#git@github.com:}" | cut -d/ -f1 ;;
    https://github.com/*) printf '%s' "${remote_url#https://github.com/}" | cut -d/ -f1 ;;
    *) return 1 ;;
  esac
}

extract_run_id() {
  local output_file="$1"
  local cve_id="$2"
  local run_id

  run_id="$(python3 - "$output_file" <<'PY' 2>/dev/null || true
import json
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
start = text.find("{")
end = text.rfind("}")
if start == -1 or end == -1 or end < start:
    raise SystemExit(1)
data = json.loads(text[start : end + 1])
print(data["run"]["run_id"])
PY
)"

  if [[ -z "$run_id" && -d "cves/$cve_id/runs" ]]; then
    run_id="$(ls -1 "cves/$cve_id/runs" | sort | tail -n 1)"
  fi

  if [[ -z "$run_id" ]]; then
    echo "Could not determine persisted run id for $cve_id" >&2
    exit 1
  fi

  printf '%s\n' "$run_id"
}

write_contribution_audit() {
  local cve_id="$1"
  local run_id="$2"
  local harness="$3"
  local model="$4"
  local model_label="$5"
  local run_json_output="$6"
  local contribution_log="$7"
  local run_dir="cves/$cve_id/runs/$run_id"

  if [[ ! -d "$run_dir" ]]; then
    echo "Could not write contribution audit; run directory missing: $run_dir" >&2
    return
  fi

  cp "$run_json_output" "$run_dir/contribute-output.log"
  cp "$contribution_log" "$run_dir/contribution-interaction.log"

  CVEHUNT_AUDIT_CVE_ID="$cve_id" \
  CVEHUNT_AUDIT_RUN_ID="$run_id" \
  CVEHUNT_AUDIT_HARNESS="$harness" \
  CVEHUNT_AUDIT_MODEL="$model" \
  CVEHUNT_AUDIT_MODEL_LABEL="$model_label" \
  CVEHUNT_AUDIT_RUN_DIR="$run_dir" \
  CVEHUNT_AUDIT_EXECUTE_POC="${CVEHUNT_EXECUTE_POC:-0}" \
  python3 <<'PY'
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

run_dir = Path(os.environ["CVEHUNT_AUDIT_RUN_DIR"])
cve_id = os.environ["CVEHUNT_AUDIT_CVE_ID"]
run_id = os.environ["CVEHUNT_AUDIT_RUN_ID"]
harness = os.environ["CVEHUNT_AUDIT_HARNESS"]
model = os.environ["CVEHUNT_AUDIT_MODEL"]
model_label = os.environ["CVEHUNT_AUDIT_MODEL_LABEL"]
execute_poc = os.environ.get("CVEHUNT_AUDIT_EXECUTE_POC") == "1"

pipeline_status_path = run_dir / "pipeline_status.json"
report_path = run_dir / "report.json"
pipeline_status = json.loads(pipeline_status_path.read_text(encoding="utf-8")) if pipeline_status_path.exists() else {}
report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}

validation_source = {
    "codex": "codex debug models",
    "pi": "pi --list-models",
}.get(harness, "user-supplied; no local model catalog validator is available for this harness")
validation_state = "validated" if harness in {"codex", "pi"} else "accepted_unvalidated"

stages = pipeline_status.get("stages", []) if isinstance(pipeline_status, dict) else []
observed_stages = [
    {
        "phase": stage.get("phase"),
        "status": stage.get("status"),
        "message": stage.get("message"),
        "artifact": stage.get("artifact"),
    }
    for stage in stages
]

exploiter = report.get("exploiter") if isinstance(report, dict) else None
fix = report.get("fix") if isinstance(report, dict) else None

audit = {
    "schema_version": 1,
    "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
    "runner": "./contribute.sh",
    "cve_id": cve_id,
    "run_id": run_id,
    "harness": harness,
    "model": model,
    "model_label": model_label,
    "model_attribution": {
        "state": validation_state,
        "validation_source": validation_source,
        "meaning": "This label records contributor attribution for the run. The current CVEHunt workflow is deterministic Python and does not call the named model as an internal decision-making API.",
    },
    "interaction_logging": {
        "captured": [
            "./contribute.sh terminal output and prompts in contribution-interaction.log",
            "CVEHunt JSON stdout in contribute-output.log",
            "selected harness, model label, and validation source in this audit file",
            "pipeline phase events in trace.jsonl",
        ],
        "not_captured": [
            "Private external agent transcripts, unless the harness CLI itself writes them outside this repository",
            "Raw typed prompt answers beyond the selected harness/model values recorded here",
        ],
    },
    "pipeline_boundaries": {
        "will_do": [
            "Collect CVE metadata available to the local workflow",
            "Acquire supported vulnerable and patched package releases for offline inspection",
            "Generate localhost-only vulnerable/patched harness scaffolding",
            "Generate harness-scoped PoC artifacts for supported vulnerability classes",
            "Promote the upstream vulnerable-to-patched diff as a candidate remediation artifact",
            "Run the harness PoC only when explicitly invoked with CVEHUNT_EXECUTE_POC=1 / --execute-poc",
        ],
        "refuses": [
            "Target real third-party systems",
            "Generate non-localhost PoC targets or environment-overridable target hosts",
            "Add reverse shells, bind shells, credential exfiltration, or weaponization guidance",
            "Treat unsupported ecosystems as validated without local evidence",
        ],
        "not_yet_implemented": [
            "Rebuild a locally patched source tree from fix/candidate.patch and re-run the PoC against it",
            "Use the named model as an internal autonomous planner/evaluator inside the Python workflow",
            "Guarantee full exploitability proof when the upstream package exposes no probeable local surface",
        ],
        "requested_execute_poc": execute_poc,
    },
    "observed_pipeline": {
        "overall_status": pipeline_status.get("overall_status"),
        "confidence": pipeline_status.get("confidence"),
        "requested_full_pipeline_completed": pipeline_status.get("requested_full_pipeline_completed"),
        "exploit_generated": pipeline_status.get("exploit_generated"),
        "fix_generated": pipeline_status.get("fix_generated"),
        "fix_validated": pipeline_status.get("fix_validated"),
        "exploiter_status": exploiter.get("status") if isinstance(exploiter, dict) else None,
        "fix_status": fix.get("status") if isinstance(fix, dict) else None,
        "stages": observed_stages,
    },
    "artifacts": {
        "interaction_log": "contribution-interaction.log",
        "workflow_stdout": "contribute-output.log",
        "trace": "trace.jsonl",
        "pipeline_status": "pipeline_status.json",
        "report": "report.json",
        "human_report": "report.md",
    },
}

(run_dir / "contribution_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")

lines = [
    f"# Contribution Audit: {cve_id}",
    "",
    f"Run ID: {run_id}",
    f"Harness: {harness}",
    f"Model label: {model_label}",
    f"Model validation: {validation_state} via {validation_source}",
    "",
    "## Attribution Boundary",
    "",
    audit["model_attribution"]["meaning"],
    "",
    "## Interaction Logging",
    "",
]
lines.extend(f"- Captured: {item}" for item in audit["interaction_logging"]["captured"])
lines.extend(f"- Not captured: {item}" for item in audit["interaction_logging"]["not_captured"])
lines.extend(["", "## Pipeline Will Do", ""])
lines.extend(f"- {item}" for item in audit["pipeline_boundaries"]["will_do"])
lines.extend(["", "## Pipeline Refuses", ""])
lines.extend(f"- {item}" for item in audit["pipeline_boundaries"]["refuses"])
lines.extend(["", "## Not Yet Implemented", ""])
lines.extend(f"- {item}" for item in audit["pipeline_boundaries"]["not_yet_implemented"])
lines.extend([
    "",
    "## Observed Outcome",
    "",
    f"- Overall status: {audit['observed_pipeline']['overall_status']}",
    f"- Confidence: {audit['observed_pipeline']['confidence']}",
    f"- Full pipeline completed: {audit['observed_pipeline']['requested_full_pipeline_completed']}",
    f"- Exploit generated: {audit['observed_pipeline']['exploit_generated']}",
    f"- Fix generated: {audit['observed_pipeline']['fix_generated']}",
    f"- Fix validated: {audit['observed_pipeline']['fix_validated']}",
    "",
    "## Stage Outcomes",
    "",
])
for stage in observed_stages:
    lines.append(f"- {stage['phase']}: {stage['status']} - {stage['message']}")

(run_dir / "contribution_audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

  echo "Wrote contribution audit artifacts to $run_dir/contribution_audit.{json,md}"
}

auto_commit_push_and_recommend_pr() {
  local cve_id="$1"
  local model_label="$2"

  if [[ "${CVEHUNT_SKIP_GIT:-0}" == "1" ]]; then
    echo "Skipping git commit/push because CVEHUNT_SKIP_GIT=1."
    return
  fi

  if ! has_command git || ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Git is not available here; skipping automatic commit/push."
    return
  fi

  if ! git_has_changes; then
    echo "No git changes detected; nothing to commit or push."
    return
  fi

  local branch
  branch="$(git branch --show-current 2>/dev/null || true)"
  if [[ -z "$branch" ]]; then
    branch="cvehunt/$(sanitize_ref_component "$cve_id")-$(date -u +%Y%m%d%H%M%S)"
    git switch -c "$branch"
  fi

  if [[ "$branch" == "main" || "$branch" == "master" ]]; then
    branch="cvehunt/$(sanitize_ref_component "$cve_id")-$(date -u +%Y%m%d%H%M%S)"
    git switch -c "$branch"
  fi

  git add cves docs/data/cves.json
  if git diff --cached --quiet; then
    echo "No CVEHunt artifact changes staged; skipping commit/push."
    return
  fi

  local commit_subject
  commit_subject="Add CVEHunt run for $cve_id"
  git commit -m "$commit_subject" -m "Model: $model_label"

  local remote="origin"
  if ! git remote get-url "$remote" >/dev/null 2>&1; then
    remote="$(git remote | head -n 1)"
  fi

  if [[ -z "$remote" ]]; then
    echo "No git remote configured; committed locally on $branch."
    return
  fi

  git push -u "$remote" "$branch"

  echo
  echo "Pushed $branch to $remote."
  if has_command gh; then
    local base_repo=""
    base_repo="$(gh repo view --json parent,nameWithOwner --jq '.parent.nameWithOwner // .nameWithOwner' 2>/dev/null || true)"
    if [[ -n "$base_repo" ]]; then
      local head_ref="$branch"
      local push_owner=""
      push_owner="$(github_owner_from_remote_url "$(git remote get-url "$remote" 2>/dev/null || true)" || true)"
      if [[ -n "$push_owner" && "$base_repo" != "$push_owner/"* ]]; then
        head_ref="$push_owner:$branch"
      fi
      echo "Recommended PR command:"
      printf '  gh pr create --repo %q --base main --head %q --title %q --body %q\n' \
        "$base_repo" "$head_ref" "$commit_subject" "Adds the persisted CVEHunt run artifacts generated by ./contribute.sh for $cve_id using $model_label."
    else
      echo "Recommended PR: open a pull request from $branch to the upstream main branch."
    fi
  else
    echo "Recommended PR: open a pull request from $branch to the upstream main branch."
  fi
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$repo_root"

  local contribution_log
  contribution_log="$(mktemp "${TMPDIR:-/tmp}/cvehunt-contribute.XXXXXX.log")"
  exec > >(tee -a "$contribution_log") 2>&1
  echo "Contribution interaction log started at $contribution_log"

  local detected_harnesses
  detected_harnesses=()
  while IFS= read -r harness; do
    detected_harnesses[${#detected_harnesses[@]}]="$harness"
  done < <(detect_harnesses)

  local cve_id="${1:-${CVEHUNT_CVE:-}}"
  if [[ -z "$cve_id" ]]; then
    cve_id="$(prompt "CVE ID" "$DEFAULT_CVE")"
  fi
  cve_id="$(printf '%s' "$cve_id" | tr '[:lower:]' '[:upper:]')"

  local harness
  harness="$(select_harness "${detected_harnesses[@]}")"

  local model="${CVEHUNT_MODEL:-}"
  if [[ -z "$model" ]]; then
    model="$(prompt "Model for $harness" "$(default_model_for_harness "$harness")")"
  fi

  if [[ -z "$model" ]]; then
    echo "Model is required." >&2
    exit 2
  fi

  case "$model" in
    "$harness":*) model="${model#*:}" ;;
  esac

  validate_model_for_harness "$harness" "$model"

  local model_label="$harness:$model"
  export CVEHUNT_MODEL="$model_label"
  export CVEHUNT_HARNESS="$harness"

  echo "Running CVEHunt for $cve_id with $model_label"
  if [[ "${CVEHUNT_DRY_RUN:-0}" == "1" ]]; then
    if [[ "${CVEHUNT_SKIP_INSTALL:-0}" != "1" ]]; then
      echo "Would check/install project dependencies"
    fi
    if [[ "${CVEHUNT_EXECUTE_POC:-0}" == "1" ]]; then
      printf 'Would run: uv run cvehunt run %q --persist --json --model %q --execute-poc\n' "$cve_id" "$model_label"
    else
      printf 'Would run: uv run cvehunt run %q --persist --json --model %q\n' "$cve_id" "$model_label"
    fi
    if [[ "${CVEHUNT_SKIP_BUILD:-0}" != "1" ]]; then
      echo "Would run: npm run build"
    fi
    if [[ "${CVEHUNT_SKIP_GIT:-0}" != "1" ]]; then
      echo "Would commit CVEHunt artifacts, push the current contribution branch, and recommend a PR"
    fi
    exit 0
  fi

  ensure_project_dependencies

  local run_json_output
  local run_id
  local run_command
  run_json_output="$(mktemp "${TMPDIR:-/tmp}/cvehunt-run-json.XXXXXX.log")"
  run_command=(uv run cvehunt run "$cve_id" --persist --json --model "$model_label")
  if [[ "${CVEHUNT_EXECUTE_POC:-0}" == "1" ]]; then
    run_command=("${run_command[@]}" --execute-poc)
  fi

  printf 'Running command:'
  printf ' %q' "${run_command[@]}"
  printf '\n'
  "${run_command[@]}" | tee "$run_json_output"
  run_id="$(extract_run_id "$run_json_output" "$cve_id")"
  write_contribution_audit "$cve_id" "$run_id" "$harness" "$model" "$model_label" "$run_json_output" "$contribution_log"

  if [[ "${CVEHUNT_SKIP_BUILD:-0}" != "1" ]]; then
    echo "Regenerating dashboard data and docs"
    npm run build
  fi

  auto_commit_push_and_recommend_pr "$cve_id" "$model_label"

  echo "Done. Review cves/$cve_id/runs/ and docs/data/cves.json, then open the recommended PR if one was not opened already."
}

main "$@"
