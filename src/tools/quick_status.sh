#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: quick_status.sh [--output-dir DIR]

Display a concise status summary for detection artefacts in DIR (default: out).
USAGE
}

OUTPUT_DIR="out"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dir|--output-dir)
      if [[ $# -lt 2 ]]; then
        echo "Error: missing value for $1" >&2
        exit 1
      fi
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

python3 - "$OUTPUT_DIR" <<'PYCODE'
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

out_dir = Path(sys.argv[1]).resolve()

pipeline_path = out_dir / "pipeline_candidates.json"
report_path = out_dir / "detection_report.md"
parity_report_path = out_dir / "parity_report.md"
user_report_path = out_dir / "user_report.md"
recommendations_path = out_dir / "recommendations.md"
profile_path = out_dir / "transform_profile.json"
beautified_path = out_dir / "deobfuscated_pretty.lua"
final_report_path = out_dir / "final_report.md"
parity_suggestions_path = out_dir / "parity_suggestions.md"
ir_dir = out_dir / "ir_candidates"
pretty_dir = out_dir / "intermediate"
opcode_dir = out_dir / "opcode_maps"
sanity_dir = out_dir / "sanity"

status_lines: List[str] = []
status_lines.append(f"Quick detection status (output dir: {out_dir})")

pipeline_data: Optional[Dict[str, Any]] = None
if pipeline_path.exists():
    try:
        pipeline_data = json.loads(pipeline_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        status_lines.append(f"- Failed to parse {pipeline_path.name}: {exc}")
    else:
        pipelines = pipeline_data.get("pipelines")
        if isinstance(pipelines, Sequence):
            pipeline_count = sum(1 for item in pipelines if isinstance(item, dict))
        else:
            pipeline_count = 0
        pipeline_confidence = pipeline_data.get("pipeline_confidence")
        try:
            pipeline_confidence = float(pipeline_confidence)
        except (TypeError, ValueError):
            pipeline_confidence = None
        summary_line = f"- Pipeline candidates: {pipeline_count}"
        if pipeline_confidence is not None:
            summary_line += f" (overall pipeline confidence: {pipeline_confidence:.3f})"
        status_lines.append(summary_line)

        top_candidate: Optional[Dict[str, Any]] = None
        best_conf = -1.0
        if isinstance(pipelines, Sequence):
            for candidate in pipelines:
                if not isinstance(candidate, dict):
                    continue
                confidence = candidate.get("confidence")
                try:
                    score = float(confidence)
                except (TypeError, ValueError):
                    score = None
                if score is None:
                    hypothesis = candidate.get("hypothesis_score") or {}
                    if isinstance(hypothesis, dict):
                        try:
                            score = float(hypothesis.get("overall"))
                        except (TypeError, ValueError):
                            score = None
                if score is None:
                    continue
                if score > best_conf:
                    best_conf = score
                    top_candidate = candidate

        version_guess: Optional[str] = None
        if isinstance(top_candidate, dict):
            hint = top_candidate.get("version_hint")
            if isinstance(hint, str) and hint.strip():
                version_guess = hint.strip()
        if not version_guess:
            hint = pipeline_data.get("version_hint")
            if isinstance(hint, str) and hint.strip():
                version_guess = hint.strip()
        if not version_guess:
            hints = pipeline_data.get("pipeline_hints")
            if isinstance(hints, Sequence):
                for hint in hints:
                    if isinstance(hint, str) and "14.4." in hint:
                        version_guess = hint.strip()
                        break
        status_lines.append(
            f"- Version guess (heuristics): {version_guess or 'unknown'}"
        )

        detection_summary_lines: List[str] = []
        if report_path.exists():
            try:
                content = report_path.read_text(encoding="utf-8")
            except Exception:  # pragma: no cover - defensive
                content = ""
            if content:
                capture = False
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.lower().startswith("## summary"):
                        capture = True
                        continue
                    if capture and stripped.startswith("## "):
                        break
                    if capture and stripped:
                        detection_summary_lines.append(stripped)
                detection_summary_lines = detection_summary_lines[:5]
        if detection_summary_lines:
            status_lines.append("- Detection report summary:")
            for item in detection_summary_lines:
                status_lines.append(f"    • {item}")

        if isinstance(top_candidate, dict):
            status_lines.append("\nTop pipeline candidate:")
            sequence = top_candidate.get("sequence")
            if isinstance(sequence, Sequence):
                seq_text = " -> ".join(
                    str(part) for part in sequence if str(part).strip()
                )
            else:
                seq_text = "(no operations detected)"
            confidence_text = "unknown"
            if best_conf >= 0:
                confidence_text = f"{best_conf:.3f}"
            status_lines.append(f"  Sequence: {seq_text}")
            status_lines.append(f"  Confidence: {confidence_text}")
            hint = top_candidate.get("version_hint")
            if isinstance(hint, str) and hint.strip():
                status_lines.append(f"  Version hint: {hint.strip()}")
            hypothesis = top_candidate.get("hypothesis_score")
            if isinstance(hypothesis, dict):
                components = hypothesis.get("components")
                if isinstance(components, dict) and components:
                    parts: List[str] = []
                    seen: set[str] = set()
                    for key in ("pipeline", "english", "lua", "parity", "mapping"):
                        if key in components:
                            try:
                                value = float(components[key])
                            except (TypeError, ValueError):
                                continue
                            parts.append(f"{key}={value:.3f}")
                            seen.add(key)
                    for key, value in components.items():
                        if key in seen:
                            continue
                        try:
                            value_f = float(value)
                        except (TypeError, ValueError):
                            continue
                        parts.append(f"{key}={value_f:.3f}")
                    if parts:
                        status_lines.append(
                            "  Confidence components: " + ", ".join(parts)
                        )

        parity_summary = None
        if isinstance(pipeline_data, dict):
            ps = pipeline_data.get("parity_summary")
            if isinstance(ps, dict):
                parity_summary = ps
        status_lines.append("\nParity status:")
        if parity_summary:
            success = parity_summary.get("success")
            status = "success" if success else "mismatch"
            prefix = parity_summary.get("matching_prefix")
            limit = parity_summary.get("limit")
            try:
                prefix_text = int(prefix)
            except (TypeError, ValueError):
                prefix_text = prefix
            try:
                limit_text = int(limit)
            except (TypeError, ValueError):
                limit_text = limit
            status_lines.append(
                f"  Status: {status} (matching prefix {prefix_text}/{limit_text})"
            )
        elif parity_report_path.exists():
            status_lines.append(
                f"  Available: {parity_report_path} (parse for detailed metrics)"
            )
        else:
            status_lines.append("  No parity information available")
else:
    status_lines.append(
        f"- No pipeline candidates found at {pipeline_path} (run run_all_detection.py first?)"
    )

artefact_candidates: List[tuple[str, Path]] = [
    ("Detection report", report_path),
    ("Pipeline report", pipeline_path),
    ("User summary", user_report_path),
    ("Recommendations", recommendations_path),
    ("Parity report", parity_report_path),
    ("Parity suggestions", parity_suggestions_path),
    ("Transform profile", profile_path),
    ("Beautified Lua", beautified_path),
    ("Final report", final_report_path),
]

status_lines.append("\nKey artefacts:")
found_any = False
for label, path in artefact_candidates:
    if path.exists():
        status_lines.append(f"  {label}: {path}")
        found_any = True

if ir_dir.exists():
    status_lines.append(f"  IR candidates directory: {ir_dir}")
    found_any = True
if pretty_dir.exists():
    status_lines.append(f"  Beautifier intermediates: {pretty_dir}")
    found_any = True
if opcode_dir.exists():
    status_lines.append(f"  Opcode maps: {opcode_dir}")
    found_any = True
if sanity_dir.exists():
    status_lines.append(f"  Sanity checks: {sanity_dir}")
    found_any = True
if not found_any:
    status_lines.append("  (No artefacts found yet)")

print("\n".join(status_lines))
PYCODE
