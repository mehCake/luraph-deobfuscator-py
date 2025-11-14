"""Export labelled byte transforms from synthetic pipelines for ML experiments."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableMapping, Sequence

LOGGER = logging.getLogger(__name__)

try:
    # Avoid import cycles – these helpers already implement the synthetic pipeline
    from src.tests import generate_sample as samplegen
except Exception as exc:  # pragma: no cover - defensive guard
    raise ImportError("Synthetic sample generator unavailable") from exc

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SYNTHETIC_ROOT = _REPO_ROOT / "tests" / "samples" / "pipelines"
_DEFAULT_OUTPUT = _REPO_ROOT / "out" / "ml" / "training_pairs.jsonl"

__all__ = [
    "TrainingExample",
    "export_training_data",
    "main",
]


@dataclass(frozen=True)
class TrainingExample:
    """Representation of a labelled transform example."""

    sample: str
    stage: int
    label: str
    input_bytes: bytes
    output_bytes: bytes
    operation_metadata: Mapping[str, object]
    spec_path: Path

    def to_record(self) -> Mapping[str, object]:
        return {
            "sample": self.sample,
            "stage": self.stage,
            "label": self.label,
            "input_hex": self.input_bytes.hex(),
            "input_len": len(self.input_bytes),
            "output_hex": self.output_bytes.hex(),
            "output_len": len(self.output_bytes),
            "operation_metadata": dict(self.operation_metadata),
            "spec": str(self.spec_path),
        }


def _ensure_synthetic_spec(path: Path, *, allow_external: bool) -> Path:
    resolved = path.resolve()
    if allow_external:
        return resolved
    try:
        resolved.relative_to(_SYNTHETIC_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(
            f"Spec path {resolved} is outside the synthetic samples directory; "
            "provide --allow-external to override"
        ) from exc
    return resolved


def _sanitise_operation_metadata(operation: Mapping[str, object]) -> Mapping[str, object]:
    cleaned: dict[str, object] = {}
    for key, value in operation.items():
        key_lower = str(key).lower()
        if key_lower == "type":
            continue
        if key_lower == "key":
            cleaned["key"] = {"redacted": True}
            continue
        cleaned[str(key)] = value
    return cleaned


def _iter_examples_from_spec(spec_path: Path) -> Iterable[TrainingExample]:
    spec = samplegen._load_spec(spec_path)
    sample_name = str(spec.get("name") or spec_path.stem)
    operations = spec.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError(f"Spec {spec_path} does not define any operations")

    current = samplegen._resolve_payload(spec)
    for index, operation in enumerate(operations, start=1):
        if not isinstance(operation, MutableMapping):
            continue
        op_type = str(operation.get("type", "")).lower()
        if op_type == "prga":
            transformed = samplegen._apply_prga(current, operation)
        elif op_type == "permute":
            transformed = samplegen._apply_permutation(current, operation)
        elif op_type == "pack":
            # pack operations serialise to Lua strings; they do not yield byte pairs
            samplegen._pack_payload(current, operation, sample_name=sample_name)
            continue
        else:
            LOGGER.debug("Skipping unsupported operation type: %s", op_type)
            continue

        metadata = _sanitise_operation_metadata(operation)
        yield TrainingExample(
            sample=sample_name,
            stage=index,
            label=op_type,
            input_bytes=current,
            output_bytes=transformed,
            operation_metadata=metadata,
            spec_path=spec_path,
        )
        current = transformed


def export_training_data(
    spec_paths: Sequence[Path],
    output_path: Path,
    *,
    limit: int | None = None,
    allow_external: bool = False,
) -> Sequence[TrainingExample]:
    """Export labelled byte-transform pairs from synthetic specifications."""

    examples: List[TrainingExample] = []
    remaining = None if limit is None or limit <= 0 else int(limit)

    validated_specs = [
        _ensure_synthetic_spec(path, allow_external=allow_external) for path in spec_paths
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for spec in validated_specs:
            for example in _iter_examples_from_spec(spec):
                json.dump(example.to_record(), handle)
                handle.write("\n")
                examples.append(example)
                if remaining is not None:
                    remaining -= 1
                    if remaining <= 0:
                        LOGGER.info(
                            "Export limit reached after processing %s examples", len(examples)
                        )
                        return tuple(examples)
        LOGGER.info("Exported %s training examples to %s", len(examples), output_path)
    return tuple(examples)


def _discover_specs(spec_dir: Path) -> List[Path]:
    if not spec_dir.exists():
        return []
    specs = sorted(spec_dir.glob("*.yaml")) + sorted(spec_dir.glob("*.json"))
    return specs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export labelled byte transforms from synthetic pipeline specifications",
    )
    parser.add_argument(
        "--spec",
        action="append",
        type=Path,
        dest="specs",
        help="Synthetic specification to process (can be repeated)",
    )
    parser.add_argument(
        "--spec-dir",
        type=Path,
        default=_SYNTHETIC_ROOT,
        help="Directory containing synthetic pipeline specifications",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Output JSONL path (default: {_DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of examples to export (default: unlimited)",
    )
    parser.add_argument(
        "--allow-external",
        action="store_true",
        help="Permit specifications outside tests/samples for experimentation",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    specs: List[Path]
    if args.specs:
        specs = list(dict.fromkeys(args.specs))
    else:
        specs = _discover_specs(args.spec_dir)
    if not specs:
        LOGGER.error("No synthetic specifications found")
        return 1

    try:
        examples = export_training_data(
            specs,
            args.output,
            limit=args.limit,
            allow_external=args.allow_external,
        )
    except Exception as exc:  # pragma: no cover - defensive guard for CLI
        LOGGER.error("Failed to export training data: %s", exc)
        return 1

    summary = {"count": len(examples), "output": str(args.output)}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
