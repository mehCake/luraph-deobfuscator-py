"""
src/versions/luraph_v14_4_initv4.py

Version handler for Luraph v14.4.x / initv4 bootstrapper.

Responsibilities:
 - Provide version-specific identification (version banner, dispatch names)
 - Build or update the `opcode_table()` using extracted metadata
 - Provide fallback opcode defaults or merging when extraction incomplete
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("version.initv4")
logger.setLevel(logging.DEBUG)

# Baseline opcode defaults (fallback or reference). You must fill this with
# your existing known opcodes (from your manual deobfuscation). Example skeleton:
_DEFAULT_OPCODE_MAP = {
    0x00: "MOVE",
    0x01: "LOADK",
    0x02: "LOADBOOL",
    0x03: "LOADNIL",
    0x04: "GETUPVAL",
    0x05: "GETGLOBAL",
    # ... fill all known opcodes
    # For unknown opcodes, you may leave them out and allow dynamic fill
}


class InitV4Handler:
    """
    Handler for Luraph initv4 / v14.4 bootstrap flows.
    """

    @staticmethod
    def version_name():
        return "luraph_v14_4_initv4"

    @staticmethod
    def match_banner(src: str) -> bool:
        # confirm this handler is correct by scanning for prefixes
        return "initv4" in src or "superflow_bytecode_ext" in src

    @classmethod
    def build_opcode_table(cls, bootstrap_metadata: Dict[str, Any]) -> Dict[int, str]:
        """
        Generate the opcode_table (id → mnemonic) using:
         - The default opcode map
         - Overlays from bootstrap_metadata["opcode_map"] if present
         - If extraction is incomplete, merge defaults and alert
        """
        result = dict(_DEFAULT_OPCODE_MAP)  # make a copy

        # If metadata contains extracted opcode_map, overlay it
        extracted = bootstrap_metadata.get("opcode_map") or bootstrap_metadata.get("opcode_dispatch")
        if isinstance(extracted, dict):
            for op_id, name in extracted.items():
                try:
                    oid = int(op_id)
                except Exception:
                    # maybe hex string like "0x1A"
                    try:
                        oid = int(op_id, 16)
                    except Exception:
                        logger.warning(f"Skipping invalid opcode key: {op_id}")
                        continue
                # override or append
                result[oid] = name
            logger.debug(f"Overlayed {len(extracted)} opcodes from bootstrap metadata")
        else:
            logger.warning("No opcode_map found in bootstrap_metadata; using fallback defaults")

        # Check completeness: if many gaps (e.g. >20 missing), log warning
        missing = [oid for oid in range(max(result.keys()) + 1) if oid not in result]
        if len(missing) > 10:
            logger.warning(f"Opcode table likely incomplete: {len(missing)} missing IDs (e.g. {missing[:5]})")

        return result

    @classmethod
    def decode_blob_with_metadata(cls, decoded_bytes: bytes, bootstrap_metadata: Dict[str, Any]) -> Any:
        """
        Optionally perform version-specific tweaks or checks on the decoded payload.
        E.g. detect internal stubs, strip wrapper layers, patch minor patterns.
        """
        # In most cases, the decoded_bytes are already raw VM bytecode; return as-is
        return decoded_bytes

    @classmethod
    def get_name(cls):
        return "initv4"
