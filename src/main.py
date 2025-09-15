"""Command line interface for the Luraph deobfuscator."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import List, Sequence

from . import utils
from .pipeline import Context, PIPELINE


def _parse_list(value: str | None) -> List[str] | None:
    if not value:
        return None
    return [item for item in value.split(",") if item]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deobfuscate Luraph-protected Lua files")
    parser.add_argument("-i", "--in", dest="input", required=True, help="input Lua file")
    parser.add_argument("-o", "--out", dest="output", help="output file path")
    parser.add_argument("--format", choices=["lua", "json"], default="lua", help="output format")
    parser.add_argument("--max-iterations", type=int, default=1, help="maximum pipeline iterations")
    parser.add_argument("--skip-passes", help="comma-separated list of passes to skip")
    parser.add_argument("--only-passes", help="comma-separated list restricting passes")
    parser.add_argument("--profile", action="store_true", help="measure pass execution times")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose logging")
    parser.add_argument("--vm-trace", action="store_true", help="emit VM trace (no-op placeholder)")
    parser.add_argument("--detect-only", action="store_true", help="only run version detection")
    parser.add_argument("--write-artifacts", help="directory to store per-pass logs")
    args = parser.parse_args(argv)

    utils.setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    ctx = Context(input_path=args.input, artifacts=Path(args.write_artifacts) if args.write_artifacts else None)
    skip = _parse_list(args.skip_passes)
    only = _parse_list(args.only_passes)

    results = PIPELINE.run_passes(ctx, skip=skip, only=only, profile=args.profile)

    if args.detect_only:
        if ctx.detected_version:
            print(ctx.detected_version)
            return 0
        return 1

    if not ctx.output:
        logging.error("no output produced")
        return 1

    out_path = args.output or utils.create_output_path(args.input, suffix="_deob.lua" if args.format == "lua" else "_deob.json")
    utils.safe_write_file(out_path, ctx.output)

    if args.profile or args.verbose:
        print("Pass\tTime(s)")
        for name, duration in results:
            print(f"{name}\t{duration:.3f}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
