"""Helpers for human-friendly presentation of lifted IR."""

from .prettify import CommentInjection, Provenance, format_file, format_pseudo_lua
from .comment_injector import (
    CommentHint,
    inject_comments,
    load_hints,
    write_with_comments,
)
from .rename_map import apply_rename_map, propose_rename_map, save_rename_map
from .reflow_controlflow import ReflowResult, ReflowStats, reflow_file, reflow_pseudo_lua
from .inline_constants import InlineSummary, inline_constants, inline_constants_payload, write_inlined_lua
from .reporter import FinalReport, OpcodeSummary, PipelineProfile, build_final_report, write_final_report
from .string_deobf import (
    DecodingCandidate,
    StringEntryResult,
    decode_string_table,
    decode_tables_from_file,
    write_candidates,
)
from .beautifier import BeautifyResult, beautify

__all__ = [
    "CommentInjection",
    "Provenance",
    "format_file",
    "format_pseudo_lua",
    "CommentHint",
    "inject_comments",
    "load_hints",
    "write_with_comments",
    "apply_rename_map",
    "propose_rename_map",
    "save_rename_map",
    "ReflowResult",
    "ReflowStats",
    "reflow_file",
    "reflow_pseudo_lua",
    "InlineSummary",
    "inline_constants",
    "inline_constants_payload",
    "write_inlined_lua",
    "PipelineProfile",
    "OpcodeSummary",
    "FinalReport",
    "build_final_report",
    "write_final_report",
    "DecodingCandidate",
    "StringEntryResult",
    "decode_string_table",
    "decode_tables_from_file",
    "write_candidates",
    "BeautifyResult",
    "beautify",
]
