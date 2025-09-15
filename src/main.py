"""Command line interface for running the deobfuscation pipeline."""
from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from . import utils
from .deobfuscator import LuaDeobfuscator

LOG_FILE = Path("deobfuscator.log")


def configure_logging(trace: bool) -> None:
    """Configure root logging to write to :data:`LOG_FILE`."""

    level = logging.DEBUG if trace else logging.INFO
    root = logging.getLogger()
    # Clear pre-existing handlers to avoid duplicate logs when tests run the CLI
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)


@dataclass
class WorkItem:
    source: Path
    destination: Path


@dataclass
class WorkResult:
    item: WorkItem
    success: bool
    error: Optional[str] = None


def _gather_inputs(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if not target.exists():
        raise FileNotFoundError(target)
    files: List[Path] = []
    for candidate in target.rglob("*"):
        if candidate.is_file():
            if candidate.suffix.lower() in {".lua", ".txt"} or candidate.suffix == "":
                files.append(candidate)
    return sorted(files)


def _default_output_path(source: Path) -> Path:
    return source.with_name(f"{source.stem}_deob.lua")


def _prepare_work_items(inputs: List[Path], override: Path | None) -> Iterable[WorkItem]:
    if override is not None and len(inputs) > 1:
        raise ValueError("--output can only be used with a single input file")
    for src in inputs:
        dst = override if override is not None else _default_output_path(src)
        yield WorkItem(src, dst)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Luraph-obfuscated Lua files")
    parser.add_argument("path", help="input file or directory")
    parser.add_argument("-o", "--output", help="output file path (single input only)")
    parser.add_argument("--max-iterations", type=int, default=1, help="run the pipeline up to N times")
    parser.add_argument("--version", help="override version detection with an explicit value")
    parser.add_argument("--trace", action="store_true", help="enable verbose VM tracing")
    parser.add_argument("--jobs", type=int, default=1, help="process inputs in parallel using N workers")
    args = parser.parse_args(argv)

    configure_logging(args.trace)

    target = Path(args.path)
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
        work_items = list(_prepare_work_items(inputs, override))
    except ValueError as exc:
        logging.getLogger(__name__).error(str(exc))
        return 2

    jobs = max(1, args.jobs)

    def _process(item: WorkItem) -> WorkResult:
        log = logging.getLogger(__name__)
        log.info("processing %s", item.source)
        content = utils.safe_read_file(str(item.source))
        if content is None:
            return WorkResult(item, False, "unable to read input file")
        deob = LuaDeobfuscator()
        try:
            output_text = deob.deobfuscate_content(
                content,
                max_iterations=max(args.max_iterations, 1),
                version_override=args.version,
            )
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("error processing %s", item.source)
            return WorkResult(item, False, str(exc))
        if not utils.safe_write_file(str(item.destination), output_text):
            return WorkResult(item, False, "failed to write output")
        log.info("wrote %s", item.destination)
        return WorkResult(item, True, None)

    try:
        results, duration = utils.run_parallel(work_items, _process, jobs=jobs)
    except Exception:  # pragma: no cover - catastrophic failure
        logging.getLogger(__name__).exception("unexpected error while processing inputs")
        return 1

    exit_code = 0
    failures = 0
    for result in results:
        if not result.success:
            exit_code = 1
            failures += 1
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
    if failures:
        logging.getLogger(__name__).warning("%d file(s) failed", failures)

    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

