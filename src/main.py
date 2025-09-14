#!/usr/bin/env python3
"""Command line interface for the Lua deobfuscator."""

import argparse
from pathlib import Path

from .deobfuscator import LuaDeobfuscator
from . import utils


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Luraph-obfuscated Lua files")
    parser.add_argument("file", help="input Lua file")
    parser.add_argument("-o", "--output", help="output file path")
    args = parser.parse_args(argv)

    deob = LuaDeobfuscator()
    result = deob.deobfuscate_file(args.file)
    out_path = args.output or utils.create_output_path(args.file, suffix="_deob.lua")
    utils.safe_write_file(out_path, result)
    print(f"Deobfuscated output written to {out_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

