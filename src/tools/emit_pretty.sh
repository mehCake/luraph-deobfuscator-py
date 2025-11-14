#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: emit_pretty.sh [options]

Run the lifter → IR → prettify pipeline and write out/deobfuscated_pretty.lua.

Options:
  --out-dir DIR         Output directory containing detection artefacts (default: out)
  --unpacked PATH       Path to unpacked_dump.json (default: <out-dir>/unpacked_dump.json)
  --constants PATH      Path to a constants manifest JSON (default: auto-detect or recover)
  --opcode-map PATH     Optional opcode map JSON passed to the lifter
  --profile PATH        Transform profile used for hints/provenance (default: <out-dir>/transform_profile.json)
  --output PATH         Destination for the prettified Lua (default: <out-dir>/deobfuscated_pretty.lua)
  --force               Overwrite existing output
  --ir-output PATH      Where to write the intermediate IR JSON (default: <out-dir>/ir/emit_pretty_ir.json)
  --skip-annotation     Do not inject a provenance header into the prettified output
  -h, --help            Show this help message
USAGE
}

log_info() {
  echo "[emit_pretty] $*"
}

log_warn() {
  echo "[emit_pretty][warn] $*" >&2
}

die() {
  echo "[emit_pretty][error] $*" >&2
  exit 1
}

make_absolute() {
  python3 - "$1" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
cd "$PROJECT_ROOT"

OUT_DIR="out"
PROFILE_PATH=""
FORCE=0
UNPACKED_PATH=""
CONSTANTS_PATH=""
OPCODE_MAP_PATH=""
OUTPUT_PATH=""
IR_OUTPUT_PATH=""
ANNOTATE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      [[ $# -ge 2 ]] || die "Missing value for --out-dir"
      OUT_DIR="$2"
      shift 2
      ;;
    --unpacked)
      [[ $# -ge 2 ]] || die "Missing value for --unpacked"
      UNPACKED_PATH="$2"
      shift 2
      ;;
    --constants)
      [[ $# -ge 2 ]] || die "Missing value for --constants"
      CONSTANTS_PATH="$2"
      shift 2
      ;;
    --opcode-map)
      [[ $# -ge 2 ]] || die "Missing value for --opcode-map"
      OPCODE_MAP_PATH="$2"
      shift 2
      ;;
    --profile)
      [[ $# -ge 2 ]] || die "Missing value for --profile"
      PROFILE_PATH="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || die "Missing value for --output"
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --ir-output)
      [[ $# -ge 2 ]] || die "Missing value for --ir-output"
      IR_OUTPUT_PATH="$2"
      shift 2
      ;;
    --skip-annotation|--no-annotate)
      ANNOTATE=0
      shift
      ;;
    --force|-f)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

OUT_DIR_ABS=$(make_absolute "$OUT_DIR")
mkdir -p "$OUT_DIR_ABS"

if [[ -z "$UNPACKED_PATH" ]]; then
  UNPACKED_PATH="$OUT_DIR_ABS/unpacked_dump.json"
else
  UNPACKED_PATH=$(make_absolute "$UNPACKED_PATH")
fi

if [[ -z "$PROFILE_PATH" ]]; then
  PROFILE_PATH="$OUT_DIR_ABS/transform_profile.json"
else
  PROFILE_PATH=$(make_absolute "$PROFILE_PATH")
fi

if [[ -z "$OUTPUT_PATH" ]]; then
  OUTPUT_PATH="$OUT_DIR_ABS/deobfuscated_pretty.lua"
else
  OUTPUT_PATH=$(make_absolute "$OUTPUT_PATH")
fi

if [[ -z "$IR_OUTPUT_PATH" ]]; then
  IR_OUTPUT_PATH="$OUT_DIR_ABS/ir/emit_pretty_ir.json"
else
  IR_OUTPUT_PATH=$(make_absolute "$IR_OUTPUT_PATH")
fi

if [[ -n "$CONSTANTS_PATH" ]]; then
  CONSTANTS_PATH=$(make_absolute "$CONSTANTS_PATH")
fi

if [[ -n "$OPCODE_MAP_PATH" ]]; then
  OPCODE_MAP_PATH=$(make_absolute "$OPCODE_MAP_PATH")
fi

log_info "Project root: $PROJECT_ROOT"
log_info "Output directory: $OUT_DIR_ABS"

[[ -f "$UNPACKED_PATH" ]] || die "Unpacked payload not found at $UNPACKED_PATH"

if [[ -e "$OUTPUT_PATH" && $FORCE -eq 0 ]]; then
  die "Refusing to overwrite existing output at $OUTPUT_PATH (use --force to replace)"
fi

VERSION_HINT=""
if [[ -f "$PROFILE_PATH" ]]; then
  log_info "Using transform profile: $PROFILE_PATH"
  if ! VERSION_HINT=$(python3 - "$PROFILE_PATH" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)
metadata = data.get("metadata") if isinstance(data, dict) else None
hint = None
if isinstance(metadata, dict):
    hint = metadata.get("version_hint")
    if not hint:
        hints = metadata.get("pipeline_hints")
        if isinstance(hints, (list, tuple)):
            for item in hints:
                if isinstance(item, str) and item.strip():
                    hint = item
                    break
if not hint and isinstance(data, dict):
    hint = data.get("version_hint")
if hint:
    print(str(hint))
PY
  ); then
    VERSION_HINT=""
  fi
else
  log_warn "Transform profile not found at $PROFILE_PATH; continuing without it"
fi

CONSTANTS_MANIFEST=""
if [[ -n "$CONSTANTS_PATH" ]]; then
  [[ -f "$CONSTANTS_PATH" ]] || die "Constants manifest not found at $CONSTANTS_PATH"
  CONSTANTS_MANIFEST="$CONSTANTS_PATH"
else
  if ! CONSTANTS_MANIFEST=$(python3 - "$OUT_DIR_ABS" <<'PY'
import json
import sys
from pathlib import Path
out_dir = Path(sys.argv[1])
const_dir = out_dir / "constants"
best_path = None
best_score = -1.0
if const_dir.exists():
    for path in const_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            payload = data.get("constants")
            if isinstance(payload, list):
                score = len(payload)
            else:
                continue
        elif isinstance(data, list):
            score = len(data)
        else:
            continue
        if score > best_score:
            best_score = float(score)
            best_path = path
if best_path:
    print(best_path)
PY
  ); then
    CONSTANTS_MANIFEST=""
  fi
fi

if [[ -z "$CONSTANTS_MANIFEST" ]]; then
  log_warn "No constants manifest detected; attempting recovery from out/bytes/meta.json"
  if ! CANDIDATE_JSON=$(python3 - "$OUT_DIR_ABS" <<'PY'
import json
import sys
from pathlib import Path
out_dir = Path(sys.argv[1])
meta_path = out_dir / "bytes" / "meta.json"
if not meta_path.exists():
    sys.exit(0)
try:
    entries = json.loads(meta_path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(0)
best = None
for entry in entries:
    if not isinstance(entry, dict):
        continue
    path = entry.get("path") or entry.get("name")
    if not path:
        continue
    candidate_path = Path(path)
    if not candidate_path.is_absolute():
        candidate_path = (out_dir / candidate_path).resolve()
    if not candidate_path.exists():
        continue
    size = entry.get("size") or 0
    conf = entry.get("confidence") or 0
    try:
        score = (float(conf), int(size))
    except Exception:
        score = (0.0, int(size) if isinstance(size, int) else 0)
    payload = {
        "path": str(candidate_path),
        "name": entry.get("name") or candidate_path.stem,
    }
    if best is None or score > best[0]:
        best = (score, payload)
if best:
    print(json.dumps(best[1]))
PY
  ); then
    CANDIDATE_JSON=""
  fi
  if [[ -n "${CANDIDATE_JSON:-}" ]]; then
    CANDIDATE_PATH=$(python3 - <<'PY'
import json
import sys
data = json.loads(sys.stdin.read())
print(data.get("path", ""))
PY
<<<"$CANDIDATE_JSON")
    CANDIDATE_NAME=$(python3 - <<'PY'
import json
import sys
data = json.loads(sys.stdin.read())
print(data.get("name", "constants"))
PY
<<<"$CANDIDATE_JSON")
    [[ -n "$CANDIDATE_PATH" ]] || die "Failed to determine candidate bytes for constant recovery"
    CONSTANTS_DIR="$OUT_DIR_ABS/constants"
    mkdir -p "$CONSTANTS_DIR"
    log_info "Recovering constants from $CANDIDATE_PATH"
    RECOVER_CMD=(python3 -m src.decoders.constant_recover "$CANDIDATE_PATH" --candidate "$CANDIDATE_NAME" --output-dir "$CONSTANTS_DIR")
    if [[ -f "$PROFILE_PATH" ]]; then
      RECOVER_CMD+=(--profile "$PROFILE_PATH")
    fi
    "${RECOVER_CMD[@]}"
    SLUG=$(python3 - <<'PY'
import re
import sys
name = sys.argv[1]
slug = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")
print(slug or "constants")
PY
"$CANDIDATE_NAME")
    CONSTANTS_MANIFEST="$CONSTANTS_DIR/$SLUG.json"
  fi
fi

if [[ -z "$CONSTANTS_MANIFEST" ]]; then
  log_warn "Falling back to empty constant pool"
  CONSTANTS_DIR="$OUT_DIR_ABS/constants"
  mkdir -p "$CONSTANTS_DIR"
  CONSTANTS_MANIFEST="$CONSTANTS_DIR/empty.json"
  cat >"$CONSTANTS_MANIFEST" <<'JSON'
{"constants": []}
JSON
fi

[[ -f "$CONSTANTS_MANIFEST" ]] || die "Constants manifest not available at $CONSTANTS_MANIFEST"

mkdir -p "$(dirname "$IR_OUTPUT_PATH")"
log_info "Writing intermediate IR to $IR_OUTPUT_PATH"
LIFTER_CMD=(python3 -m src.vm.lifter "$UNPACKED_PATH" --output "$IR_OUTPUT_PATH" --ir-format structured --summary)
if [[ -n "$VERSION_HINT" ]]; then
  LIFTER_CMD+=(--version-hint "$VERSION_HINT")
fi
if [[ -n "$OPCODE_MAP_PATH" ]]; then
  LIFTER_CMD+=(--opcode-map "$OPCODE_MAP_PATH")
fi
log_info "Running lifter: ${LIFTER_CMD[*]}"
"${LIFTER_CMD[@]}"

log_info "Running beautifier"
BEAUTIFIER_CMD=(python3 -m src.pretty.beautifier "$IR_OUTPUT_PATH" "$CONSTANTS_MANIFEST" --output "$OUTPUT_PATH" --intermediate-dir "$OUT_DIR_ABS/beautifier")
if [[ $FORCE -eq 1 ]]; then
  BEAUTIFIER_CMD+=(--overwrite)
fi
if [[ -n "$VERSION_HINT" ]]; then
  BEAUTIFIER_CMD+=(--version-hint "$VERSION_HINT")
fi
if [[ -f "$PROFILE_PATH" ]]; then
  BEAUTIFIER_CMD+=(--profile "$PROFILE_PATH" --profile-label "emit_pretty")
fi
log_info "Executing beautifier: ${BEAUTIFIER_CMD[*]}"
"${BEAUTIFIER_CMD[@]}"

if [[ $ANNOTATE -eq 1 ]]; then
  PIPELINE_JSON_PATH="$OUT_DIR_ABS/pipeline_candidates.json"
  if python3 -m src.tools.annotate_output --output "$OUTPUT_PATH" --pipeline-json "$PIPELINE_JSON_PATH" >/dev/null; then
    log_info "Annotated $OUTPUT_PATH with provenance header"
  else
    log_warn "Failed to annotate $OUTPUT_PATH; leaving original content intact"
  fi
else
  log_info "Annotation step disabled by user"
fi

if ! python3 -m src.tools.ensure_license --repo-root "$PROJECT_ROOT" --output-dir "$OUT_DIR_ABS" --header "$OUTPUT_PATH" >/dev/null; then
  log_warn "Failed to ensure license coverage for $OUTPUT_PATH"
fi

log_info "Beautified pseudo-Lua written to $OUTPUT_PATH"
