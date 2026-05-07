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
  CVEHUNT_MODEL     Model name to record
  CVEHUNT_SKIP_INSTALL=1  Skip uv/npm dependency installation checks
  CVEHUNT_SKIP_BUILD=1  Skip npm run build after the persisted run
  CVEHUNT_DRY_RUN=1     Print commands without running them
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

default_model_for_harness() {
  case "$1" in
    codex) printf '%s\n' "gpt-5.5-cyber" ;;
    gemini) printf '%s\n' "gemini-2.5-pro" ;;
    claude) printf '%s\n' "opus-4.7-cyber" ;;
    opencode) printf '%s\n' "opencode-default" ;;
    pi) printf '%s\n' "pi-default" ;;
    *) printf '%s\n' "unspecified" ;;
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

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$repo_root"

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

  local model_label="$harness:$model"
  export CVEHUNT_MODEL="$model_label"
  export CVEHUNT_HARNESS="$harness"

  echo "Running CVEHunt for $cve_id with $model_label"
  if [[ "${CVEHUNT_DRY_RUN:-0}" == "1" ]]; then
    if [[ "${CVEHUNT_SKIP_INSTALL:-0}" != "1" ]]; then
      echo "Would check/install project dependencies"
    fi
    printf 'Would run: uv run cvehunt run %q --persist --json --model %q\n' "$cve_id" "$model_label"
    if [[ "${CVEHUNT_SKIP_BUILD:-0}" != "1" ]]; then
      echo "Would run: npm run build"
    fi
    exit 0
  fi

  ensure_project_dependencies

  uv run cvehunt run "$cve_id" --persist --json --model "$model_label"

  if [[ "${CVEHUNT_SKIP_BUILD:-0}" != "1" ]]; then
    echo "Regenerating dashboard data and docs"
    npm run build
  fi

  echo "Done. Review cves/$cve_id/runs/ and docs/data/cves.json before committing."
}

main "$@"
