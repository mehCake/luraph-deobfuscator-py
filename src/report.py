"""Structured deobfuscation report helpers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DeobReport:
    """Summarises a single deobfuscation run for maintainers."""

    version_detected: str
    script_key_used: str | None
    bootstrapper_used: str | None
    blob_count: int
    decoded_bytes: int
    opcode_stats: Dict[str, int]
    unknown_opcodes: List[int]
    traps_removed: int
    constants_decrypted: int
    variables_renamed: int
    output_length: int
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_text(self) -> str:
        """Format the report as a human-readable summary."""

        lines: List[str] = []
        lines.append(f"Detected version: {self.version_detected}")
        if self.script_key_used:
            prefix = self.script_key_used[:6]
            lines.append(
                f"Script key: {prefix}... (len={len(self.script_key_used)})"
            )
        if self.bootstrapper_used:
            lines.append(f"Bootstrapper: {self.bootstrapper_used}")
        lines.append(
            f"Decoded {self.blob_count} blobs, total {self.decoded_bytes} bytes"
        )
        lines.append("Opcode counts:")
        for op, count in sorted(self.opcode_stats.items()):
            lines.append(f"  {op}: {count}")
        if self.unknown_opcodes:
            lines.append(f"Unknown opcodes: {self.unknown_opcodes}")
        lines.append(f"Traps removed: {self.traps_removed}")
        lines.append(f"Constants decrypted: {self.constants_decrypted}")
        lines.append(f"Variables renamed: {self.variables_renamed}")
        lines.append(f"Final output length: {self.output_length} chars")
        if self.warnings:
            lines.append("Warnings:")
            lines.extend(f"  - {warning}" for warning in self.warnings)
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"  - {error}" for error in self.errors)
        return "\n".join(lines)
