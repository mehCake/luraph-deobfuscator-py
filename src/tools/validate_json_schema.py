"""Lightweight JSON schema validation for analysis artefacts.

This module provides a very small schema system tailored to the structures
emitted by the analysis pipeline.  It intentionally avoids third-party
dependencies so it can run in restricted environments while still catching
structural regressions in ``out/`` artefacts.  Schemas are intentionally
flexible – unknown keys are generally allowed – but the critical fields and
types are verified.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

LOGGER = logging.getLogger(__name__)

ROOT_PATH = "<root>"


# ---------------------------------------------------------------------------
# Validation result containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaValidationIssue:
    """Represents a single schema validation failure for a JSON artefact."""

    file: Path
    path: str
    message: str


class SchemaValidationError(RuntimeError):
    """Raised when schema validation fails for one or more artefacts."""

    def __init__(self, issues: Sequence[SchemaValidationIssue]):
        super().__init__("JSON schema validation failed")
        self.issues = list(issues)


@dataclass(frozen=True)
class ValidationError:
    """Internal representation of an error emitted by a schema node."""

    path: str
    message: str


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "array"
    return type(value).__name__


def _format_path(base: str, segment: str | int) -> str:
    if not base or base == ROOT_PATH:
        prefix = ROOT_PATH
    else:
        prefix = base
    if isinstance(segment, int):
        return f"{prefix}[{segment}]"
    return f"{prefix}.{segment}" if prefix != ROOT_PATH else segment


# ---------------------------------------------------------------------------
# Schema node implementations
# ---------------------------------------------------------------------------


class Schema:
    """Base class for schema nodes."""

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        return []


class AnySchema(Schema):
    """Schema that accepts any JSON value."""

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:  # noqa: D401
        return []


class TypeSchema(Schema):
    """Schema enforcing a Python ``isinstance`` check."""

    def __init__(self, expected: tuple[type, ...], description: str) -> None:
        self.expected = expected
        self.description = description

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if not isinstance(value, self.expected):
            return [
                ValidationError(
                    path,
                    f"expected {self.description}, got {_type_name(value)}",
                )
            ]
        return []


class BooleanSchema(TypeSchema):
    def __init__(self) -> None:
        super().__init__((bool,), "boolean")


class StringSchema(TypeSchema):
    def __init__(self) -> None:
        super().__init__((str,), "string")


class NumberSchema(Schema):
    """Schema accepting either integers or floats (but not booleans)."""

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if isinstance(value, bool):
            return [ValidationError(path, "expected number, got boolean")]
        if not isinstance(value, (int, float)):
            return [ValidationError(path, f"expected number, got {_type_name(value)}")]
        return []


class IntegerSchema(Schema):
    """Schema accepting integers (excluding booleans)."""

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if isinstance(value, bool) or not isinstance(value, int):
            return [ValidationError(path, f"expected integer, got {_type_name(value)}")]
        return []


class ArraySchema(Schema):
    """Schema enforcing array contents."""

    def __init__(self, item_schema: Schema, *, min_items: int = 0) -> None:
        self.item_schema = item_schema
        self.min_items = min_items

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            return [ValidationError(path, f"expected array, got {_type_name(value)}")]
        errors: List[ValidationError] = []
        if len(value) < self.min_items:
            errors.append(
                ValidationError(path, f"expected at least {self.min_items} item(s)")
            )
        for index, item in enumerate(value):
            errors.extend(self.item_schema.validate(item, _format_path(path, index)))
        return errors


class ObjectSchema(Schema):
    """Schema validating JSON objects with required/optional fields."""

    def __init__(
        self,
        required: Mapping[str, Schema] | None = None,
        optional: Mapping[str, Schema] | None = None,
        *,
        allow_extra: bool = True,
    ) -> None:
        self.required = dict(required or {})
        self.optional = dict(optional or {})
        self.allow_extra = allow_extra

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if not isinstance(value, Mapping):
            return [ValidationError(path, f"expected object, got {_type_name(value)}")]

        errors: List[ValidationError] = []
        for key, schema in self.required.items():
            if key not in value:
                errors.append(ValidationError(_format_path(path, key), "missing required field"))
            else:
                errors.extend(schema.validate(value[key], _format_path(path, key)))

        for key, schema in self.optional.items():
            if key in value:
                errors.extend(schema.validate(value[key], _format_path(path, key)))

        if not self.allow_extra:
            allowed = set(self.required) | set(self.optional)
            extras = set(value.keys()) - allowed
            if extras:
                extras_list = ", ".join(sorted(str(item) for item in extras))
                errors.append(
                    ValidationError(path, f"unexpected field(s): {extras_list}")
                )
        return errors


class DictSchema(Schema):
    """Schema validating dictionaries with uniform value schemas."""

    def __init__(self, value_schema: Schema, *, key_type: type = str) -> None:
        self.value_schema = value_schema
        self.key_type = key_type

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if not isinstance(value, Mapping):
            return [ValidationError(path, f"expected object, got {_type_name(value)}")]
        errors: List[ValidationError] = []
        for key, item in value.items():
            if not isinstance(key, self.key_type):
                errors.append(
                    ValidationError(
                        _format_path(path, str(key)),
                        f"expected key of type {self.key_type.__name__}",
                    )
                )
            errors.extend(
                self.value_schema.validate(item, _format_path(path, str(key)))
            )
        return errors


class LiteralSchema(Schema):
    """Schema enforcing a literal value."""

    def __init__(self, literal: Any) -> None:
        self.literal = literal

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        if value != self.literal:
            return [ValidationError(path, f"expected {self.literal!r}, got {value!r}")]
        return []


class UnionSchema(Schema):
    """Schema that accepts any of the provided schemas."""

    def __init__(self, schemas: Sequence[Schema]) -> None:
        self.schemas = list(schemas)

    def validate(self, value: Any, path: str = ROOT_PATH) -> List[ValidationError]:
        best_failure: Optional[List[ValidationError]] = None
        for schema in self.schemas:
            result = schema.validate(value, path)
            if not result:
                return []
            if best_failure is None or len(result) < len(best_failure):
                best_failure = result
        return best_failure or [ValidationError(path, "value did not match any schema option")]


def string_schema() -> Schema:
    return StringSchema()


def boolean_schema() -> Schema:
    return BooleanSchema()


def number_schema() -> Schema:
    return NumberSchema()


def integer_schema() -> Schema:
    return IntegerSchema()


def array_schema(item_schema: Schema, *, min_items: int = 0) -> Schema:
    return ArraySchema(item_schema, min_items=min_items)


def object_schema(
    required: Mapping[str, Schema] | None = None,
    optional: Mapping[str, Schema] | None = None,
    *,
    allow_extra: bool = True,
) -> Schema:
    return ObjectSchema(required=required, optional=optional, allow_extra=allow_extra)


def dict_schema(value_schema: Schema, *, key_type: type = str) -> Schema:
    return DictSchema(value_schema, key_type=key_type)


def optional_schema(schema: Schema) -> Schema:
    return UnionSchema([schema, LiteralSchema(None)])


# ---------------------------------------------------------------------------
# Schema registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaDefinition:
    pattern: str
    schema: Schema
    description: str


def _bootstrap_candidate_schema() -> Schema:
    autocorr_schema = dict_schema(number_schema())
    return object_schema(
        required={
            "type": string_schema(),
            "start_offset": integer_schema(),
            "end_offset": integer_schema(),
            "confidence": number_schema(),
            "references": array_schema(string_schema()),
            "reasons": array_schema(string_schema()),
            "snippet": string_schema(),
            "autocorrelation": autocorr_schema,
            "payload_length": integer_schema(),
        },
        optional={
            "note": string_schema(),
        },
        allow_extra=True,
    )


def _pipeline_entry_schema() -> Schema:
    return object_schema(
        required={
            "sequence": array_schema(string_schema()),
            "confidence": number_schema(),
        },
        optional={
            "confidence_breakdown": dict_schema(number_schema()),
            "version_hint": string_schema(),
            "preferred_presets": array_schema(string_schema()),
            "hypothesis_score": object_schema(
                optional={
                    "overall": number_schema(),
                    "components": dict_schema(number_schema()),
                    "notes": array_schema(string_schema()),
                },
                allow_extra=True,
            ),
            "scoring_context": object_schema(
                optional={
                    "pipeline_confidence": number_schema(),
                    "english_scores": array_schema(number_schema()),
                    "lua_scores": array_schema(number_schema()),
                },
                allow_extra=True,
            ),
            "notes": array_schema(string_schema()),
        },
        allow_extra=True,
    )


def _handler_test_manifest_schema() -> Schema:
    test_schema = object_schema(
        required={
            "handler": string_schema(),
            "opcode": optional_schema(integer_schema()),
            "mnemonics": array_schema(string_schema()),
            "snippet": string_schema(),
            "entrypoint": string_schema(),
            "instructions": array_schema(string_schema()),
            "notes": array_schema(string_schema()),
        },
        allow_extra=True,
    )
    return object_schema(
        required={
            "generated_at": string_schema(),
            "pipeline_source": optional_schema(string_schema()),
            "global_instructions": array_schema(string_schema()),
            "tests": array_schema(test_schema),
        },
        allow_extra=True,
    )


def _handler_tests_definitions_schema() -> Schema:
    testcase_schema = object_schema(
        required={
            "name": string_schema(),
            "lua_path": string_schema(),
            "entrypoint": string_schema(),
            "args": array_schema(AnySchema()),
            "metadata": object_schema(
                optional={
                    "handler": string_schema(),
                    "opcode": optional_schema(integer_schema()),
                    "mnemonics": array_schema(string_schema()),
                },
                allow_extra=True,
            ),
        },
        allow_extra=True,
    )
    return object_schema(
        required={
            "instructions": array_schema(string_schema()),
            "testcases": array_schema(testcase_schema),
        },
        allow_extra=True,
    )


def _mapping_table_schema() -> Schema:
    pair_schema = object_schema(
        required={
            "index": integer_schema(),
            "value": integer_schema(),
            "score": number_schema(),
            "support": integer_schema(),
            "total": integer_schema(),
        },
        allow_extra=True,
    )
    return object_schema(
        required={
            "name": string_schema(),
            "confidence": number_schema(),
            "samples": integer_schema(),
            "permutation_score": number_schema(),
            "hints": array_schema(string_schema()),
            "pairs": array_schema(pair_schema),
        },
        optional={
            "sequence_preview": array_schema(number_schema()),
            "stats": object_schema(allow_extra=True),
            "affine_params": object_schema(
                optional={
                    "a": integer_schema(),
                    "b": integer_schema(),
                    "modulus": integer_schema(),
                },
                allow_extra=True,
            ),
            "length": integer_schema(),
            "version_hint": string_schema(),
        },
        allow_extra=True,
    )


def _opcode_candidate_schema() -> Schema:
    return object_schema(
        required={
            "opnum": integer_schema(),
            "candidates": array_schema(string_schema()),
            "stats": object_schema(allow_extra=True),
            "sample_pcs": array_schema(integer_schema()),
        },
        allow_extra=True,
    )


def _opcode_map_schema() -> Schema:
    selection_schema = object_schema(
        optional={
            "mnemonic": string_schema(),
            "confidence": number_schema(),
            "handlers": array_schema(string_schema()),
            "reasons": array_schema(string_schema()),
        },
        allow_extra=True,
    )
    return object_schema(
        required={
            "confidence": number_schema(),
            "mapping": dict_schema(string_schema()),
            "selections": dict_schema(selection_schema),
        },
        optional={
            "name": string_schema(),
            "permutation_score": number_schema(),
        },
        allow_extra=True,
    )


def _snapshot_manifest_schema() -> Schema:
    return object_schema(
        required={
            "run_name": string_schema(),
            "created_at": string_schema(),
            "snapshot_count": integer_schema(),
            "snapshots": array_schema(string_schema()),
        },
        allow_extra=True,
    )


def _snapshot_entry_schema() -> Schema:
    return object_schema(
        required={
            "label": string_schema(),
            "index": integer_schema(),
            "created_at": string_schema(),
            "payload": AnySchema(),
        },
        allow_extra=True,
    )


def _snapshot_diff_schema() -> Schema:
    return object_schema(
        required={
            "base_label": string_schema(),
            "current_label": string_schema(),
            "added": object_schema(allow_extra=True),
            "removed": object_schema(allow_extra=True),
            "changed": object_schema(allow_extra=True),
        },
        allow_extra=True,
    )


def _schema_definitions() -> List[SchemaDefinition]:
    bootstrap_candidate = _bootstrap_candidate_schema()
    pipeline_entry = _pipeline_entry_schema()

    pipeline_schema = object_schema(
        required={
            "pipelines": array_schema(pipeline_entry),
            "pipeline_confidence": number_schema(),
        },
        optional={
            "pipeline": array_schema(string_schema()),
            "chunks": array_schema(object_schema(allow_extra=True)),
            "pipeline_hints": array_schema(string_schema()),
            "checksum_summary": object_schema(
                required={
                    "total": integer_schema(),
                    "valid": integer_schema(),
                    "invalid": integer_schema(),
                },
                allow_extra=True,
            ),
            "opcode_handlers": dict_schema(array_schema(string_schema())),
            "opcode_mnemonics": dict_schema(array_schema(string_schema())),
            "dispatcher_cfg_count": integer_schema(),
            "pipelines": array_schema(pipeline_entry),
            "version_hint": string_schema(),
            "byte_candidates": array_schema(object_schema(allow_extra=True)),
            "bootstrap_candidates": array_schema(object_schema(allow_extra=True)),
            "opcode_proposals": array_schema(object_schema(allow_extra=True)),
            "opcode_map_candidates": array_schema(object_schema(allow_extra=True)),
            "opcode_map_files": array_schema(string_schema()),
            "parity_summary": object_schema(
                optional={
                    "success": boolean_schema(),
                    "matching_prefix": optional_schema(integer_schema()),
                    "limit": optional_schema(integer_schema()),
                },
                allow_extra=True,
            ),
            "pipeline_graph_files": array_schema(string_schema()),
            "transform_profile": string_schema(),
            "handler_tests": object_schema(
                optional={
                    "count": integer_schema(),
                    "manifest": string_schema(),
                    "definitions": string_schema(),
                },
                allow_extra=True,
            ),
            "vm_style": object_schema(
                optional={
                    "style": string_schema(),
                    "confidence": number_schema(),
                    "sample_size": integer_schema(),
                },
                allow_extra=True,
            ),
            "pipeline_report_version": string_schema(),
        },
        allow_extra=True,
    )

    mapping_report_schema = object_schema(
        required={
            "tables": array_schema(_mapping_table_schema()),
            "byte_tables": array_schema(_mapping_table_schema()),
            "total_tables": integer_schema(),
            "total_pairs": integer_schema(),
            "byte_table_count": integer_schema(),
            "mapping_files": array_schema(string_schema()),
        },
        allow_extra=True,
    )

    opcode_proposal_schema = object_schema(
        required={
            "opcode": integer_schema(),
            "mnemonic": string_schema(),
            "confidence": number_schema(),
            "handlers": array_schema(string_schema()),
            "reasons": array_schema(string_schema()),
        },
        allow_extra=True,
    )

    opcode_candidate_schema = object_schema(
        required={
            "confidence": number_schema(),
            "mapping": dict_schema(string_schema()),
            "selections": dict_schema(
                object_schema(
                    optional={
                        "mnemonic": string_schema(),
                        "confidence": number_schema(),
                        "handlers": array_schema(string_schema()),
                        "reasons": array_schema(string_schema()),
                    },
                    allow_extra=True,
                )
            ),
        },
        allow_extra=True,
    )

    transform_profile_schema = object_schema(
        required={
            "version": string_schema(),
        },
        optional={
            "prga_params": object_schema(allow_extra=True),
            "permute_table": array_schema(integer_schema()),
            "opcode_map_ids": array_schema(string_schema()),
            "candidate_scores": dict_schema(number_schema()),
            "metadata": object_schema(allow_extra=True),
        },
        allow_extra=True,
    )

    run_manifest_schema = object_schema(
        required={
            "schema_version": string_schema(),
            "run_id": string_schema(),
            "created_at": string_schema(),
            "target": string_schema(),
            "pipeline_steps": array_schema(string_schema()),
            "pipeline_confidence": number_schema(),
            "pipeline_hints": array_schema(string_schema()),
            "pipeline_components": object_schema(allow_extra=True),
            "artefacts": object_schema(allow_extra=True),
            "candidate_maps": array_schema(object_schema(allow_extra=True)),
            "mapping_summary": object_schema(allow_extra=True),
            "scoring": object_schema(allow_extra=True),
            "notes": array_schema(string_schema()),
        },
        optional={
            "version_hint": string_schema(),
        },
        allow_extra=True,
    )

    metrics_schema = object_schema(
        required={
            "run_id": string_schema(),
            "created_at": string_schema(),
            "runtime_seconds": number_schema(),
            "max_rss_kib": optional_schema(integer_schema()),
            "step_counts": object_schema(allow_extra=True),
            "metrics": object_schema(allow_extra=True),
            "extra": object_schema(allow_extra=True),
        },
        allow_extra=True,
    )

    ci_sample_schema = object_schema(
        required={
            "sample": string_schema(),
            "output_dir": string_schema(),
            "notes": array_schema(string_schema()),
            "artefacts": object_schema(
                required={
                    "raw_payload": string_schema(),
                    "manifest": string_schema(),
                    "bootstrap_candidates": string_schema(),
                    "bytes_metadata": string_schema(),
                    "pipeline_report": string_schema(),
                },
                allow_extra=True,
            ),
        },
        allow_extra=True,
    )

    ci_summary_schema = object_schema(
        required={
            "generated_at": string_schema(),
            "nightly": boolean_schema(),
            "samples": array_schema(ci_sample_schema),
        },
        optional={
            "parity": object_schema(
                optional={
                    "report": string_schema(),
                    "success": optional_schema(boolean_schema()),
                },
                allow_extra=True,
            ),
        },
        allow_extra=True,
    )

    bytes_meta_schema = object_schema(
        required={
            "name": string_schema(),
            "type": string_schema(),
            "path": string_schema(),
            "size": integer_schema(),
            "endianness_hint": string_schema(),
        },
        optional={
            "endianness_score": number_schema(),
            "start_offset": optional_schema(integer_schema()),
            "end_offset": optional_schema(integer_schema()),
            "confidence": optional_schema(number_schema()),
        },
        allow_extra=True,
    )

    opcode_candidate_map_schema = object_schema(
        required={
            "mapping": array_schema(integer_schema(), min_items=0),
        },
        optional={
            "inverse": optional_schema(dict_schema(integer_schema())),
            "confidence": number_schema(),
            "permutation_score": number_schema(),
            "hints": array_schema(string_schema()),
            "stats": object_schema(allow_extra=True),
            "length": integer_schema(),
            "name": string_schema(),
            "source": string_schema(),
            "version_hint": string_schema(),
            "affine_params": object_schema(
                optional={
                    "a": integer_schema(),
                    "b": integer_schema(),
                    "modulus": integer_schema(),
                },
                allow_extra=True,
            ),
        },
        allow_extra=True,
    )

    return [
        SchemaDefinition(
            "raw_manifest.json",
            array_schema(
                object_schema(
                    required={
                        "type": string_schema(),
                        "start_offset": integer_schema(),
                        "end_offset": integer_schema(),
                        "payload_length": integer_schema(),
                        "source_length": integer_schema(),
                    },
                    optional={
                        "payload_file": string_schema(),
                        "note": string_schema(),
                    },
                    allow_extra=True,
                )
            ),
            "Loader manifest entries",
        ),
        SchemaDefinition(
            "bootstrap_chunks.json",
            array_schema(
                object_schema(
                    required={
                        "kind": string_schema(),
                        "start": integer_schema(),
                        "end": integer_schema(),
                        "text": string_schema(),
                    },
                    allow_extra=True,
                )
            ),
            "Bootstrap chunk summaries",
        ),
        SchemaDefinition(
            "bootstrap_candidates.json",
            array_schema(bootstrap_candidate),
            "Bootstrap candidate report",
        ),
        SchemaDefinition(
            "bytes/meta.json",
            array_schema(bytes_meta_schema),
            "Byte extractor metadata",
        ),
        SchemaDefinition(
            "pipeline_candidates.json",
            pipeline_schema,
            "Pipeline candidate analysis",
        ),
        SchemaDefinition(
            "mapping_candidates.json",
            mapping_report_schema,
            "Mapping candidate analysis",
        ),
        SchemaDefinition(
            "opcode_proposals.json",
            object_schema(
                required={
                    "proposals": array_schema(opcode_proposal_schema),
                    "candidates": array_schema(opcode_candidate_schema),
                },
                allow_extra=True,
            ),
            "Opcode proposal summary",
        ),
        SchemaDefinition(
            "opcode_maps/*.json",
            _opcode_map_schema(),
            "Candidate opcode map",
        ),
        SchemaDefinition(
            "mappings/*.json",
            opcode_candidate_map_schema,
            "Permutation mapping candidate",
        ),
        SchemaDefinition(
            "transform_profile.json",
            transform_profile_schema,
            "Auto-generated transform profile",
        ),
        SchemaDefinition(
            "runs/*.manifest.json",
            run_manifest_schema,
            "Run manifest",
        ),
        SchemaDefinition(
            "metrics/*.json",
            metrics_schema,
            "Metrics report",
        ),
        SchemaDefinition(
            "handler_tests/tests_manifest.json",
            _handler_test_manifest_schema(),
            "Handler test manifest",
        ),
        SchemaDefinition(
            "handler_tests/tests.json",
            _handler_tests_definitions_schema(),
            "Handler test definitions",
        ),
        SchemaDefinition(
            "ci_results/**/ci_summary.json",
            ci_summary_schema,
            "CI pipeline summary",
        ),
        SchemaDefinition(
            "backups/*/backup_manifest.json",
            object_schema(
                required={"files": object_schema(allow_extra=True)},
                allow_extra=True,
            ),
            "Backup manifest",
        ),
        SchemaDefinition(
            "snapshots/*/manifest.json",
            _snapshot_manifest_schema(),
            "Snapshot manifest",
        ),
        SchemaDefinition(
            "snapshots/*/snapshot_*.json",
            _snapshot_entry_schema(),
            "Snapshot payload",
        ),
        SchemaDefinition(
            "snapshots/*/diff_*.json",
            _snapshot_diff_schema(),
            "Snapshot diff",
        ),
        SchemaDefinition(
            "opcode_candidates.json",
            object_schema(allow_extra=True),
            "Opcode candidate cache",
        ),
        SchemaDefinition(
            "summary.json",
            object_schema(allow_extra=True),
            "Pipeline summary cache",
        ),
        SchemaDefinition(
            "lift_ir.json",
            array_schema(object_schema(allow_extra=True)),
            "Lifted instruction dump",
        ),
        SchemaDefinition(
            "unpacked_dump.json",
            AnySchema(),
            "Legacy unpacked dump",
        ),
        SchemaDefinition(
            "raw_manifest_backup.json",
            array_schema(object_schema(allow_extra=True)),
            "Legacy manifest backup",
        ),
    ]


SCHEMA_DEFINITIONS = _schema_definitions()


def _discover_files(base_dir: Path, patterns: Sequence[str]) -> List[Path]:
    discovered: set[Path] = set()
    for pattern in patterns:
        for path in base_dir.rglob(pattern):
            if path.is_file():
                discovered.add(path)
    return sorted(discovered)


def _match_schema(relative: Path) -> Optional[SchemaDefinition]:
    text = relative.as_posix()
    for definition in SCHEMA_DEFINITIONS:
        if fnmatch.fnmatch(text, definition.pattern):
            return definition
    return None


def validate_json_directory(
    base_dir: Path,
    *,
    patterns: Sequence[str] = ("*.json",),
    strict: bool = False,
    raise_on_error: bool = True,
) -> List[SchemaValidationIssue]:
    """Validate JSON artefacts beneath ``base_dir``.

    Parameters
    ----------
    base_dir:
        Directory whose JSON files should be validated.
    patterns:
        Glob patterns used to discover candidate files.  Defaults to ``("*.json",)``.
    strict:
        If ``True`` unknown files (without a registered schema) are treated as
        failures instead of being skipped.
    raise_on_error:
        When ``True`` (the default) a :class:`SchemaValidationError` is raised if
        any validation issues are discovered.
    """

    if not base_dir.exists():
        return []

    issues: List[SchemaValidationIssue] = []
    for candidate in _discover_files(base_dir, patterns):
        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            issues.append(
                SchemaValidationIssue(
                    candidate.relative_to(base_dir), ROOT_PATH, f"unable to read file: {exc}"
                )
            )
            continue

        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            issues.append(
                SchemaValidationIssue(
                    candidate.relative_to(base_dir), ROOT_PATH, f"invalid JSON: {exc}"
                )
            )
            continue

        relative = candidate.relative_to(base_dir)
        definition = _match_schema(relative)
        if definition is None:
            if strict:
                issues.append(
                    SchemaValidationIssue(
                        relative,
                        ROOT_PATH,
                        "no schema registered for this artefact",
                    )
                )
            else:
                LOGGER.debug("Skipping JSON file with no schema: %s", relative)
            continue

        errors = definition.schema.validate(payload, ROOT_PATH)
        for error in errors:
            issues.append(SchemaValidationIssue(relative, error.path, error.message))

    if issues and raise_on_error:
        raise SchemaValidationError(issues)
    return issues


def _format_issue(issue: SchemaValidationIssue) -> str:
    location = f"{issue.file}" if issue.path == ROOT_PATH else f"{issue.file}:{issue.path}"
    return f"{location} -> {issue.message}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate JSON artefacts emitted by the analysis pipeline.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path("out"),
        help="Directory to scan for JSON artefacts (default: out)",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        dest="patterns",
        default=None,
        help="Additional glob pattern for candidate files (default: *.json)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat JSON files without a registered schema as failures",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    patterns = tuple(args.patterns) if args.patterns else ("*.json",)
    try:
        issues = validate_json_directory(
            args.base_dir, patterns=patterns, strict=args.strict, raise_on_error=False
        )
    except SchemaValidationError as exc:  # pragma: no cover - defensive
        issues = exc.issues

    if issues:
        for issue in issues:
            LOGGER.error(_format_issue(issue))
        return 1

    LOGGER.info("All JSON artefacts beneath %s passed validation", args.base_dir)
    return 0


__all__ = [
    "SchemaValidationIssue",
    "SchemaValidationError",
    "validate_json_directory",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
