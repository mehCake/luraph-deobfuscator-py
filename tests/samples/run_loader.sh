#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

INPUT="${SCRIPT_DIR}/Obfuscated3.lua"
OUTPUT_DIR="${PROJECT_ROOT}/out"
RAW_PAYLOAD="${OUTPUT_DIR}/raw_payload.txt"
MANIFEST_JSON="${OUTPUT_DIR}/raw_manifest.json"
CANDIDATES_JSON="${OUTPUT_DIR}/bootstrap_candidates.json"

if [[ ! -f "${INPUT}" ]];
then
  echo "Sample payload not found: ${INPUT}" >&2
  exit 1
fi

python -m src.io.loader "${INPUT}" --output-dir "${OUTPUT_DIR}" --raw-name "$(basename "${RAW_PAYLOAD}")"
python -m src.bootstrap.extract_bootstrap "${MANIFEST_JSON}" --raw-text "${RAW_PAYLOAD}" --output "${CANDIDATES_JSON}"

echo "Bootstrap candidates written to ${CANDIDATES_JSON}"
