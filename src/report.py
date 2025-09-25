"""Structured deobfuscation report helpers."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List


def _mask_script_key(value: str | None) -> str | None:
    """Return the first six characters of the key followed by an ellipsis."""

    if not value:
        return None
    prefix = value[:6]
    return f"{prefix}... (len={len(value)})"


@dataclass
class DeobReport:
    """Summarises a single deobfuscation run for maintainers."""

    version_detected: str | None = None
    confirmed: bool = False
    script_key_used: str | None = None
    bootstrapper_used: str | None = None
    blob_count: int = 0
    decoded_bytes: int = 0
    payload_iterations: int = 0
    opcode_stats: Dict[str, int] = field(default_factory=dict)
    unknown_opcodes: List[int] = field(default_factory=list)
    traps_removed: int = 0
    constants_decrypted: int = 0
    variables_renamed: int = 0
    output_length: int = 0
    chunks: List[Dict[str, object]] = field(default_factory=list)
    vm_metadata: Dict[str, object] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def masked_script_key(self) -> str | None:
        """Return a masked representation of the script key for logging/JSON."""

        return _mask_script_key(self.script_key_used)

    def to_text(self) -> str:
        """Format the report as a human-readable summary."""

        lines: List[str] = []
        lines.append(f"Detected version: {self.version_detected}")
        lines.append("User confirmed detection: " + ("yes" if self.confirmed else "no"))
        masked_key = self.masked_script_key()
        if masked_key:
            lines.append(f"Script key: {masked_key}")
        if self.bootstrapper_used:
            lines.append(f"Bootstrapper: {self.bootstrapper_used}")
        lines.append(
            f"Decoded {self.blob_count} blobs, total {self.decoded_bytes} bytes"
        )
        lines.append(
            "Payload iterations: "
            + (str(self.payload_iterations) if self.payload_iterations else "0")
        )
        lines.append("Opcode counts:")
        for op, count in sorted(self.opcode_stats.items()):
            lines.append(f"  {op}: {count}")
        if self.unknown_opcodes:
            lines.append(f"Unknown opcodes: {self.unknown_opcodes}")
        else:
            lines.append("Unknown opcodes: none")
        lines.append(f"Traps removed: {self.traps_removed}")
        lines.append(f"Constants decrypted: {self.constants_decrypted}")
        lines.append(f"Variables renamed: {self.variables_renamed}")
        lines.append(f"Final output length: {self.output_length} chars")
        if self.chunks:
            lines.append("Chunk summary:")
            for chunk in self.chunks:
                index = chunk.get("index")
                size = chunk.get("size")
                decoded = chunk.get("decoded_byte_count")
                lifted = chunk.get("lifted_instruction_count")
                lines.append(
                    f"  - chunk {index}: size={size}, decoded={decoded}, lifted={lifted}"
                )
        if self.warnings:
            lines.append("Warnings:")
            lines.extend(f"  - {warning}" for warning in self.warnings)
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"  - {error}" for error in self.errors)
        return "\n".join(lines)

    def to_json(self) -> Dict[str, object]:
        """Return a JSON-serialisable representation with masked secrets."""

        data = asdict(self)
        data["script_key_used"] = self.masked_script_key()
        iterations = self.payload_iterations if self.payload_iterations > 0 else 0
        data["payload_iterations"] = iterations

        chunk_payload: List[Dict[str, object]] = []
        for entry in self.chunks:
            if not isinstance(entry, dict):
                continue
            chunk_payload.append(
                {
                    "index": entry.get("index"),
                    "size": entry.get("size"),
                    "decoded_byte_count": entry.get("decoded_byte_count"),
                    "lifted_instruction_count": entry.get(
                        "lifted_instruction_count", 0
                    ),
                    "used_key_masked": entry.get(
                        "used_key_masked", self.masked_script_key()
                    ),
                    "suspicious": bool(entry.get("suspicious", False)),
                }
            )

        data["chunks"] = chunk_payload
        return data
