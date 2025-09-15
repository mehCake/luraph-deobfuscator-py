"""Command line interface for running the deobfuscation pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from . import pipeline, utils
from .deobfuscator import LuaDeobfuscator
from version_detector import VersionInfo

LOG_FILE = Path("deobfuscator.log")


class _ColourFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG: "blue",
        logging.INFO: "green",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "magenta",
    }

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - trivial wrapper
        message = super().format(record)
        colour = self.COLOURS.get(record.levelno, "green")
        return utils.colorize_text(message, colour)


@dataclass
class WorkItem:
    source: Path
    destination: Path


@dataclass
class WorkResult:
    item: WorkItem
    success: bool
    output_path: Optional[Path] = None
    summary: str = ""
    error: Optional[str] = None


def configure_logging(verbose: bool) -> None:
    """Configure root logging handlers."""

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    level = logging.DEBUG if verbose else logging.INFO
    root.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if verbose:
        stream = logging.StreamHandler()
        stream.setFormatter(_ColourFormatter("%(levelname)s: %(message)s"))
        root.addHandler(stream)


def _split_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _gather_inputs(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if not target.exists():
        raise FileNotFoundError(target)
    files: List[Path] = []
    for candidate in target.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() in {".lua", ".txt"} or not candidate.suffix:
            files.append(candidate)
    return sorted(files)


def _default_output_path(source: Path, fmt: str) -> Path:
    suffix = ".json" if fmt == "json" else ".lua"
    return source.with_name(f"{source.stem}_deob{suffix}")


def _prepare_work_items(inputs: List[Path], override: Optional[Path], fmt: str) -> Iterable[WorkItem]:
    if override is not None and len(inputs) > 1:
        raise ValueError("--out/--output can only be used with a single input file")
    for src in inputs:
        dst = override if override is not None else _default_output_path(src, fmt)
        yield WorkItem(src, dst)


def _artifact_dir(base: Optional[Path], source: Path, iteration: int) -> Optional[Path]:
    if base is None:
        return None
    identifier = hashlib.sha1(str(source).encode("utf-8")).hexdigest()[:8]
    return base / f"{source.stem}_{identifier}" / f"iter_{iteration:02d}"


def _serialise_version(version: Optional[VersionInfo]) -> Optional[dict[str, object]]:
    if version is None:
        return None
    return {
        "name": version.name,
        "major": version.major,
        "minor": version.minor,
        "confidence": version.confidence,
        "features": sorted(version.features) if version.features else [],
        "matched_categories": list(version.matched_categories),
    }


def _format_detection(ctx: pipeline.Context, fmt: str) -> str:
    version = _serialise_version(ctx.detected_version)
    if fmt == "json":
        payload = {"version": version, "input": str(ctx.input_path)}
        return json.dumps(payload, indent=2, sort_keys=True)
    if version is None:
        return "-- no version detected\n"
    return (
        f"-- detected Luraph version: {version['name']} (confidence {version['confidence']:.2f})\n"
    )


def _format_pipeline_output(
    ctx: pipeline.Context,
    timings: Sequence[tuple[str, float]],
    fmt: str,
    source: Path,
) -> str:
    if fmt == "json":
        payload = {
            "input": str(source),
            "version": _serialise_version(ctx.detected_version),
            "passes": ctx.pass_metadata,
            "timings": [
                {"name": name, "duration": duration} for name, duration in timings
            ],
            "iterations": ctx.iteration + 1,
            "output": ctx.output or ctx.stage_output,
        }
        if ctx.decoded_payloads:
            payload["decoded_payloads"] = ctx.decoded_payloads
        return json.dumps(payload, indent=2, sort_keys=True)
    return ctx.output or ctx.stage_output or ctx.raw_input


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Luraph-obfuscated Lua files")
    parser.add_argument("--in", dest="input_path", help="input file or directory")
    parser.add_argument("path", nargs="?", help="input file or directory (fallback)")
    parser.add_argument("-o", "--out", "--output", dest="output", help="output file path")
    parser.add_argument("--format", choices=("lua", "json"), default="lua", help="output format")
    parser.add_argument("--max-iterations", type=int, default=1, help="run the pipeline up to N times")
    parser.add_argument("--skip-passes", help="comma separated list of passes to skip")
    parser.add_argument("--only-passes", help="comma separated list of passes to run exclusively")
    parser.add_argument("--profile", action="store_true", help="print pass timings to stdout")
    parser.add_argument("--verbose", action="store_true", help="enable verbose colourised logging")
    parser.add_argument("--vm-trace", action="store_true", help="capture VM trace logs during execution")
    parser.add_argument("--trace", dest="vm_trace", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--detect-only", action="store_true", help="only detect version information")
    parser.add_argument("--write-artifacts", metavar="DIR", help="write per-pass artifacts to DIR")
    parser.add_argument("--version", help="override version detection with an explicit value")
    parser.add_argument("--jobs", type=int, default=1, help="process inputs in parallel using N workers")

    args = parser.parse_args(argv)

    target_arg = args.input_path or args.path
    if not target_arg:
        parser.error("an input path must be supplied via --in or as a positional argument")

    configure_logging(args.verbose)

    target = Path(target_arg)
    try:
        inputs = _gather_inputs(target)
    except FileNotFoundError:
        logging.getLogger(__name__).error("input %s not found", target)
        return 2
    if not inputs:
        logging.getLogger(__name__).warning("no input files discovered for %s", target)
        return 0

    override = Path(args.output) if args.output else None
    try:
        work_items = list(_prepare_work_items(inputs, override, args.format))
    except ValueError as exc:
        logging.getLogger(__name__).error(str(exc))
        return 2

    jobs = max(1, args.jobs)
    skip = _split_list(args.skip_passes)
    only = _split_list(args.only_passes)
    iterations = max(1, args.max_iterations)
    artifacts_root = Path(args.write_artifacts).resolve() if args.write_artifacts else None
    if artifacts_root:
        utils.ensure_directory(artifacts_root)

    def _process(item: WorkItem) -> WorkResult:
        log = logging.getLogger(__name__)
        content = utils.safe_read_file(str(item.source))
        if content is None:
            return WorkResult(item, False, error="unable to read input file")

        deob = LuaDeobfuscator(vm_trace=args.vm_trace)
        previous = content
        final_ctx: Optional[pipeline.Context] = None
        final_timings: List[tuple[str, float]] = []

        try:
            for iteration in range(iterations):
                ctx = pipeline.Context(
                    input_path=item.source,
                    raw_input=previous,
                    stage_output=previous,
                    version_override=args.version,
                    artifacts=_artifact_dir(artifacts_root, item.source, iteration),
                    deobfuscator=deob,
                    iteration=iteration,
                )
                ctx.options.update(
                    {
                        "detect_only": args.detect_only,
                        "format": args.format,
                    }
                )
                only_selection: Optional[Iterable[str]] = only or None
                if args.detect_only:
                    only_selection = ["detect"]
                timings = pipeline.PIPELINE.run_passes(
                    ctx,
                    skip=skip,
                    only=only_selection,
                    profile=True,
                )
                final_ctx = ctx
                final_timings = list(timings)

                if args.detect_only:
                    break

                produced = ctx.output or ctx.stage_output or previous
                if produced == previous:
                    break
                previous = produced
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("error processing %s", item.source)
            return WorkResult(item, False, error=str(exc))

        if final_ctx is None:
            return WorkResult(item, False, error="pipeline did not produce output")

        if args.detect_only:
            output_text = _format_detection(final_ctx, args.format)
        else:
            output_text = _format_pipeline_output(final_ctx, final_timings, args.format, item.source)

        if not utils.safe_write_file(str(item.destination), output_text):
            return WorkResult(item, False, error="failed to write output")

        summary_lines: List[str] = []
        if final_ctx.detected_version:
            summary_lines.append(f"Version: {final_ctx.detected_version.name}")
        if final_timings:
            summary_lines.append(utils.format_pass_summary(final_timings))
        summary = "\n".join(line for line in summary_lines if line)
        return WorkResult(item, True, output_path=item.destination, summary=summary)

    try:
        results, duration = utils.run_parallel(work_items, _process, jobs=jobs)
    except Exception:  # pragma: no cover - catastrophic failure
        logging.getLogger(__name__).exception("unexpected error while processing inputs")
        return 1

    exit_code = 0
    for result in results:
        if result.summary:
            print(f"\n== {result.item.source} ==\n{result.summary}\n")
        if not result.success:
            exit_code = 1
            if result.error:
                logging.getLogger(__name__).error(
                    "failed processing %s: %s", result.item.source, result.error
                )
            else:
                logging.getLogger(__name__).error("failed processing %s", result.item.source)

    logging.getLogger(__name__).info(
        "processed %d file(s) in %.2fs with %d job(s)",
        len(work_items),
        duration,
        jobs,
    )

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
