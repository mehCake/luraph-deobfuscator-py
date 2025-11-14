#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python}"

if [[ $# -gt 0 ]]; then
  SAMPLE="$1"
  shift
else
  SAMPLE="$ROOT_DIR/tests/parity/sample_lph.bin"
fi

REPORT_PATH="${PARITY_REPORT:-$ROOT_DIR/out/parity_report.md}"
INTERMEDIATE_DIR="${PARITY_INTERMEDIATE_DIR:-$ROOT_DIR/out/intermediate}"

mkdir -p "$(dirname "$REPORT_PATH")"

echo "[parity-check] running parity harness on ${SAMPLE}" >&2
"$PYTHON_BIN" -m src.tools.parity_test "$SAMPLE" --report "$REPORT_PATH" --dump-intermediate "$INTERMEDIATE_DIR" "$@"
