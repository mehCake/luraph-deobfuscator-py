#!/usr/bin/env python3
"""Command line interface for the Lua deobfuscator.

The CLI now exposes a richer set of options for inspecting the
intermediate representation, reconstructed constants and control flow
graphs.  Output can be written either as prettified Lua source or as a
placeholder ``.luac`` blob for tooling that expects bytecode files.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Iterable, List

from . import utils
from .deobfuscator import LuaDeobfuscator
from .beautifier import LuaBeautifier
from .variable_renamer import VariableRenamer
from constant_reconstructor import ConstantReconstructor
from pattern_analyzer import PatternAnalyzer, IRInstruction


class _ColourFormatter(logging.Formatter):
    """Simple colourised logging formatter used in verbose mode."""

    COLOURS = {
        logging.DEBUG: "blue",
        logging.INFO: "green",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "magenta",
    }

    def format(self, record: logging.LogRecord) -> str:  # pragma: no cover - trivial
        msg = super().format(record)
        colour = self.COLOURS.get(record.levelno, "green")
        return utils.colorize_text(msg, colour)


def _write_ir(path: Path, ir: Iterable[IRInstruction]) -> None:
    with path.open("w", encoding="utf8") as fh:
        for ins in ir:
            args = " ".join(ins.args)
            fh.write(f"{ins.index:04d} {ins.opcode} {args}\n")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Luraph-obfuscated Lua files")
    parser.add_argument("file", help="input Lua file")
    parser.add_argument("-o", "--lua-out", help="path for decompiled pseudo-Lua output")
    parser.add_argument("--luac-out", help="write cleaned bytecode to this file")
    parser.add_argument("--dump-ir", action="store_true", help="dump intermediate representation")
    parser.add_argument("--dump-constants", action="store_true", help="dump reconstructed constants")
    parser.add_argument("--dump-cfg", action="store_true", help="dump control flow graph in DOT format")
    parser.add_argument("--verbose", action="store_true", help="enable verbose colourised logging")
    args = parser.parse_args(argv)

    utils.setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    if args.verbose:  # apply colour formatter
        formatter = _ColourFormatter("%(levelname)s: %(message)s")
        for handler in logging.getLogger().handlers:
            handler.setFormatter(formatter)

    deob = LuaDeobfuscator()
    content = deob.deobfuscate_file(args.file)

    # Reconstruct constants and replace inline
    recon = ConstantReconstructor()
    constants = recon.reconstruct_all_constants(content)
    for src, dst in {**constants["strings"], **constants["numbers"]}.items():
        content = content.replace(src, str(dst))

    # Rename variables and pretty print
    renamer = VariableRenamer()
    content = renamer.rename_variables(content)
    beautifier = LuaBeautifier()
    pretty = beautifier.beautify(content)

    out_lua = args.lua_out or utils.create_output_path(args.file, suffix="_deob.lua")
    utils.safe_write_file(out_lua, pretty)
    print(f"Pseudo-Lua written to {out_lua}")

    if args.luac_out:
        utils.safe_write_file(args.luac_out, pretty)
        print(f"Cleaned bytecode written to {args.luac_out}")

    analyzer = PatternAnalyzer()
    if args.dump_ir or args.dump_cfg:
        ir = analyzer.parse_ir(pretty)
        if args.dump_ir:
            ir_path = Path(out_lua).with_suffix(".ir")
            _write_ir(ir_path, ir)
            print(f"IR written to {ir_path}")
        if args.dump_cfg:
            cfg = analyzer.build_cfg(ir)
            cfg = analyzer.remove_dead_code(cfg)
            dot_path = Path(out_lua).with_suffix(".dot")
            analyzer.dump_cfg(cfg, dot_path)
            print(f"CFG written to {dot_path}")

    if args.dump_constants:
        const_path = Path(out_lua).with_suffix(".const.json")
        with const_path.open("w", encoding="utf8") as fh:
            json.dump(constants, fh, indent=2, sort_keys=True)
        print(f"Constants written to {const_path}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
