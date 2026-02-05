"""Utility script that summarises the v14.3 serialized chunk layout."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from pattern_analyzer import Constant
from src.versions import v14_3_loader


def _summarise_constants(prototype) -> Dict[str, Any]:
    entries = []
    for index, constant in enumerate(prototype.constants):
        entry: Dict[str, Any] = {"index": index}
        if isinstance(constant, Constant):
            entry["kind"] = constant.kind
            entry["metadata"] = dict(constant.metadata)
            value = constant.value
            role = constant.metadata.get("role")
            if role == "raw_blob" and isinstance(value, (bytes, bytearray)):
                entry["length"] = len(value)
            elif isinstance(value, dict):
                entry["value"] = value
            else:
                entry["value"] = repr(value)
        else:
            entry["kind"] = type(constant).__name__
            entry["value"] = repr(constant)
        entries.append(entry)
    return {
        "constant_count": len(entries),
        "constants": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "script",
        nargs="?",
        default="Obfuscated4.lua",
        help="Path to the v14.3 loader script (defaults to Obfuscated4.lua).",
    )
    args = parser.parse_args()

    script_path = Path(args.script)
    source = script_path.read_text(encoding="utf-8", errors="ignore")
    descriptor, data = v14_3_loader.extract_v14_3_serialized_chunk_bytes_from_source(
        source
    )
    chunk = v14_3_loader.build_v14_3_serialized_chunk_from_bytes(
        descriptor,
        data,
        attach_re_probes=True,
        allow_re_fallback=True,
    )
    if not chunk.prototypes:
        raise SystemExit("extracted chunk did not expose any prototypes")

    prototype = chunk.prototypes[0]
    summary = {
        "script": str(script_path),
        "descriptor": {
            "buffer_name": descriptor.buffer_name,
            "initial_offset": descriptor.initial_offset,
        },
        "prototypes": len(chunk.prototypes),
        "constants": _summarise_constants(prototype),
    }
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
