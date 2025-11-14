"""Generate a sanitised JSON bundle for external reviewers."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

SENSITIVE_TOKENS = {"key", "secret", "token"}

__all__ = [
    "JsonExportSummary",
    "ExportJsonForReviewError",
    "export_json_for_review",
    "build_arg_parser",
    "main",
]


@dataclass(slots=True)
class JsonExportSummary:
    """Summary of the generated review JSON package."""

    package_path: Path
    included: Dict[str, Path]
    skipped: Dict[str, str]
    dry_run: bool = False


class ExportJsonForReviewError(RuntimeError):
    """Raised when the JSON review export fails."""


@dataclass(slots=True)
class _ArtefactRule:
    name: str
    relative_path: Path
    optional: bool = True
    loader: Callable[[Path], Tuple[object, Path]] | None = None


def _default_loader(target: Path) -> Tuple[object, Path]:
    if not target.exists():
        raise FileNotFoundError(str(target))
    if target.is_dir():
        raise IsADirectoryError(str(target))
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ExportJsonForReviewError(f"failed to parse JSON artefact {target}: {exc}") from exc
    return payload, target


def _latest_json_from_dir(target: Path) -> Tuple[object, Path]:
    if not target.exists():
        raise FileNotFoundError(str(target))
    if target.is_file():
        return _default_loader(target)
    candidates = sorted(
        (path for path in target.glob("*.json") if path.is_file()),
        key=lambda item: (item.stat().st_mtime, item.name),
    )
    if not candidates:
        raise FileNotFoundError(f"no JSON artefacts found in {target}")
    latest = candidates[-1]
    return _default_loader(latest)


DEFAULT_RULES: Tuple[_ArtefactRule, ...] = (
    _ArtefactRule("pipeline_report", Path("pipeline_candidates.json"), optional=False),
    _ArtefactRule("mapping_candidates", Path("mapping_candidates.json")),
    _ArtefactRule("bootstrap_candidates", Path("bootstrap_candidates.json")),
    _ArtefactRule("byte_metadata", Path("bytes") / "meta.json"),
    _ArtefactRule("transform_profile", Path("transform_profile.json")),
    _ArtefactRule("metrics_report", Path("metrics"), loader=_latest_json_from_dir),
    _ArtefactRule("run_manifest", Path("runs"), loader=_latest_json_from_dir),
)


def _looks_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in SENSITIVE_TOKENS)


def _sanitize(value: object) -> object:
    if isinstance(value, MutableMapping):
        cleaned: Dict[str, object] = {}
        for key, child in value.items():
            key_str = str(key)
            if _looks_sensitive_name(key_str):
                LOGGER.debug("Dropping sensitive field %s", key_str)
                continue
            cleaned[key_str] = _sanitize(child)
        return cleaned
    if isinstance(value, Mapping):  # pragma: no cover - defensive branch
        return {
            str(key): _sanitize(child)
            for key, child in value.items()
            if not _looks_sensitive_name(str(key))
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize(item) for item in value)
    return value


def _unique_filename(dest_dir: Path, *, timestamp: Optional[datetime]) -> Path:
    stamp = (timestamp or datetime.utcnow()).strftime("%Y%m%d-%H%M%S")
    candidate = dest_dir / f"review-json-{stamp}.json"
    counter = 2
    while candidate.exists():
        candidate = dest_dir / f"review-json-{stamp}-{counter}.json"
        counter += 1
    return candidate


def _gather_rules(rules: Sequence[_ArtefactRule]) -> Iterable[_ArtefactRule]:
    seen: set[str] = set()
    for rule in rules:
        if rule.name in seen:
            continue
        seen.add(rule.name)
        yield rule


def export_json_for_review(
    *,
    out_dir: Path,
    dest_dir: Path,
    timestamp: Optional[datetime] = None,
    extra_rules: Sequence[_ArtefactRule] | None = None,
    dry_run: bool = False,
) -> JsonExportSummary:
    """Assemble a sanitised JSON package for reviewers."""

    if not out_dir.exists():
        raise ExportJsonForReviewError(f"output directory {out_dir} does not exist")

    artefacts: Dict[str, object] = {}
    included: Dict[str, Path] = {}
    skipped: Dict[str, str] = {}

    combined_rules = tuple(_gather_rules(tuple(extra_rules or ()) + DEFAULT_RULES))

    for rule in combined_rules:
        candidate_path = out_dir / rule.relative_path
        loader = rule.loader or _default_loader
        try:
            payload, actual_path = loader(candidate_path)
        except FileNotFoundError:
            if rule.optional:
                skipped[rule.name] = "missing"
                continue
            raise ExportJsonForReviewError(
                f"required artefact '{rule.name}' not found at {candidate_path}"
            )
        except IsADirectoryError as exc:
            raise ExportJsonForReviewError(str(exc)) from exc

        artefacts[rule.name] = _sanitize(payload)
        included[rule.name] = actual_path

    metadata_included: Dict[str, str] = {}
    for name, path in included.items():
        try:
            relative = path.relative_to(out_dir)
        except ValueError:
            metadata_included[name] = str(path)
        else:
            metadata_included[name] = relative.as_posix()

    package = {
        "generated_at": (timestamp or datetime.utcnow()).isoformat(timespec="seconds"),
        "source": str(out_dir.resolve()),
        "artefacts": artefacts,
        "metadata": {
            "included": metadata_included,
            "skipped": skipped,
        },
    }

    dest_dir.mkdir(parents=True, exist_ok=True)
    output_path = _unique_filename(dest_dir, timestamp=timestamp)

    if dry_run:
        LOGGER.info("Dry run: review JSON would be written to %s", output_path)
        return JsonExportSummary(output_path, included, skipped, dry_run=True)

    output_path.write_text(
        json.dumps(package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    LOGGER.info("Review JSON written to %s", output_path)
    return JsonExportSummary(output_path, included, skipped)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Directory containing analysis artefacts",
    )
    parser.add_argument(
        "--dest-dir",
        type=Path,
        default=Path("out") / "review_json",
        help="Directory where the sanitised JSON package will be written",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be exported without writing files",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        summary = export_json_for_review(
            out_dir=args.out_dir,
            dest_dir=args.dest_dir,
            dry_run=args.dry_run,
        )
    except ExportJsonForReviewError as exc:
        LOGGER.error(str(exc))
        return 1

    if summary.dry_run:
        LOGGER.info("Included artefacts: %s", ", ".join(sorted(summary.included)))
    else:
        LOGGER.info("Sanitised package written to %s", summary.package_path)
    return 0
