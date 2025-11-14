#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ci_local_runner.sh [options] [-- <extra run_all_detection args>]

Create (or reuse) a local virtual environment, install dependencies, and run the
static detection pipeline. By default the script analyses tests/samples/Obfuscated3.lua
and writes artefacts to out/ci_local.

Options:
  --file PATH           Target Lua payload (default: tests/samples/Obfuscated3.lua)
  --output-dir PATH     Output directory for artefacts (default: out/ci_local)
  --venv PATH           Virtual environment directory (default: .venv)
  --python PATH         Python interpreter used to manage the virtualenv (default: python3)
  --skip-install        Skip dependency installation (reuse whatever is already in the venv)
  --help                Show this message and exit

Extra arguments after "--" are passed directly to python -m src.tools.run_all_detection.
USAGE
}

log_info() {
  echo "[ci-local] $*"
}

log_warn() {
  echo "[ci-local][warn] $*" >&2
}

log_error() {
  echo "[ci-local][error] $*" >&2
}

die() {
  log_error "$1"
  exit 1
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "$PROJECT_ROOT"

TARGET_FILE="tests/samples/Obfuscated3.lua"
OUTPUT_DIR="out/ci_local"
VENV_DIR=".venv"
PYTHON_BIN="python3"
INSTALL_DEPS=1
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --file)
      [[ $# -ge 2 ]] || die "Missing value for --file"
      TARGET_FILE="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || die "Missing value for --output-dir"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --venv)
      [[ $# -ge 2 ]] || die "Missing value for --venv"
      VENV_DIR="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || die "Missing value for --python"
      PYTHON_BIN="$2"
      shift 2
      ;;
    --skip-install)
      INSTALL_DEPS=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        EXTRA_ARGS+=("$1")
        shift
      done
      break
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  die "Python interpreter not found: $PYTHON_BIN"
fi

if [[ ! -d "$VENV_DIR" ]]; then
  log_info "Creating virtualenv in $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR" || die "Failed to create virtualenv at $VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

if [[ $INSTALL_DEPS -eq 1 ]]; then
  log_info "Installing/updating dependencies"
  python -m pip install --upgrade pip
  python -m pip install -r requirements.txt
  if [[ -f requirements-dev.txt ]]; then
    python -m pip install -r requirements-dev.txt
  fi
fi

[[ -f "$TARGET_FILE" ]] || die "Target file not found: $TARGET_FILE"

OUTPUT_DIR_ABS=$(python - "$OUTPUT_DIR" <<'PY'
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
)

mkdir -p "$OUTPUT_DIR_ABS"

log_info "Running detection pipeline on $TARGET_FILE"
RUN_CMD=(python -m src.tools.run_all_detection --file "$TARGET_FILE" --output-dir "$OUTPUT_DIR_ABS")
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  RUN_CMD+=("${EXTRA_ARGS[@]}")
fi

if ! "${RUN_CMD[@]}"; then
  die "Pipeline run failed"
fi

deactivate >/dev/null 2>&1 || true

log_info "Pipeline artefacts saved under: $OUTPUT_DIR_ABS"

report_hint() {
  local label="$1"; shift
  local path="$1"
  if [[ -f "$path" ]]; then
    log_info "$label: $path"
  fi
}

report_hint "Detection report" "$OUTPUT_DIR_ABS/detection_report.md"
report_hint "Final report" "$OUTPUT_DIR_ABS/final_report.md"
report_hint "Pipeline candidates" "$OUTPUT_DIR_ABS/pipeline_candidates.json"
report_hint "Opcode proposals" "$OUTPUT_DIR_ABS/opcode_proposals.json"
report_hint "Parity report" "$OUTPUT_DIR_ABS/parity_report.md"
report_hint "Recommendations" "$OUTPUT_DIR_ABS/recommendations.md"
report_hint "Ambiguity log" "$OUTPUT_DIR_ABS/ambiguous.md"

if [[ -d "$OUTPUT_DIR_ABS" ]]; then
  log_info "Other artefacts:"
  find "$OUTPUT_DIR_ABS" -maxdepth 2 -type f -print | sed 's/^/[ci-local]   /'
else
  log_warn "Output directory $OUTPUT_DIR_ABS not found"
fi

cat <<'TROUBLESHOOT'

Troubleshooting tips:
  • Linux/macOS: ensure python3-venv is installed (e.g., `apt install python3-venv`).
  • Windows (WSL or Git Bash): run this script inside WSL for best compatibility and make
    sure the repository path does not contain spaces. If activation fails, use
    `source <venv>/Scripts/activate` instead of `bin/activate`.
  • If pip install fails due to SSL or proxy settings, export `PIP_INDEX_URL` to a trusted
    mirror or run `python -m pip install --trusted-host` for your environment.
  • On repeated runs you can pass --skip-install to speed things up when dependencies are
    already present.
  • If you need to provide a session key, pass `-- --use-key <value>` after the script
    options; the key is forwarded directly to the pipeline and never written to disk.
TROUBLESHOOT
