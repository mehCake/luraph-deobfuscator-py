"""Virtual machine components for the Luraph deobfuscator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - used only for type checkers
    from src.vm.emulator import LuraphVM
    from src.vm.state import VMState
    from src.vm.disassembler import Disassembler, DisassemblerConfig, FieldConfig, Instruction
    from src.vm.disasm_driver import (
        DEFAULT_SPLITS,
        DisassemblyCandidate,
        build_config_from_split,
        generate_disassembly_candidates,
        run_driver,
    )
    from src.vm.lifter import BasicBlock, IRProgram, IROp, IROperand, Lifter
    from src.vm.opcode_map import (
        MapCandidate,
        OpcodeMap,
        apply_map_to_disasm,
        load_map,
        persist_candidate,
        score_map,
        suggest_map_from_handlers,
    )
    from src.vm.opcode_proposer import (
        OpcodeMapCandidate,
        OpcodeProposal,
        generate_map_candidates,
        group_proposals_by_opcode,
        propose_opcode_mappings,
        render_ir_candidate,
    )
    from src.vm.opcode_mapper_tui import (
        HandlerInfo,
        OpcodeMappingSession,
        OpcodeMappingShell,
        load_handler_index,
        load_mapping_file,
    )
    from src.vm.block_recover import DispatcherBlock, DispatcherCFG
    from src.vm.compare_handlers import (
        DEFAULT_PATTERNS as _DEFAULT_HANDLER_PATTERNS,
        HandlerComparison as _HandlerComparison,
        HandlerFingerprint as _HandlerFingerprint,
        HandlerPattern as _HandlerPattern,
        compare_handler_bytes as _compare_handler_bytes,
        fingerprint_bytes as _fingerprint_bytes,
    )
    from src.vm.reconstruct_controlflow import (
        BlockNode,
        ControlFlowReconstructor,
        IfNode,
        SequenceNode,
        StructuredProgram,
        TrapNode,
        WhileNode,
        reconstruct_control_flow,
    )
    from src.vm.inline_emitter import emit_inline, emit_inline_from_dict
    from src.vm.ir_utils import (
        collapse_trivial_blocks,
        compute_cfg,
        pretty_print_ir,
    )
    from src.vm.opcode_map_validator import (
        StrictnessProfile,
        ValidationIssue,
        ValidationSummary,
        run_cli as run_opcode_validator_cli,
        validate_opcode_map,
        write_validation_report,
    )

__all__ = [
    "Disassembler",
    "DisassemblerConfig",
    "FieldConfig",
    "Instruction",
    "DispatcherBlock",
    "DispatcherCFG",
    "DisassemblyCandidate",
    "DEFAULT_SPLITS",
    "build_config_from_split",
    "generate_disassembly_candidates",
    "run_driver",
    "LuraphVM",
    "MapCandidate",
    "OpcodeMap",
    "VMState",
    "Lifter",
    "IRProgram",
    "BasicBlock",
    "IROp",
    "IROperand",
    "HandlerPattern",
    "HandlerComparison",
    "HandlerFingerprint",
    "DEFAULT_HANDLER_PATTERNS",
    "compare_handler_bytes",
    "fingerprint_bytes",
    "OpcodeProposal",
    "OpcodeMapCandidate",
    "propose_opcode_mappings",
    "group_proposals_by_opcode",
    "generate_map_candidates",
    "render_ir_candidate",
    "compute_opcode_usage",
    "load_handler_suggestions",
    "load_disassembly_instructions",
    "synthesise_opcode_proposals",
    "write_proposals",
    "run_opcode_proposer_cli",
    "HandlerInfo",
    "OpcodeMappingSession",
    "OpcodeMappingShell",
    "load_handler_index",
    "load_mapping_file",
    "recover_dispatcher_cfg",
    "write_dispatcher_cfg",
    "ControlFlowReconstructor",
    "StructuredProgram",
    "SequenceNode",
    "BlockNode",
    "IfNode",
    "WhileNode",
    "TrapNode",
    "reconstruct_control_flow",
    "emit_inline",
    "emit_inline_from_dict",
    "apply_map_to_disasm",
    "load_map",
    "persist_candidate",
    "score_map",
    "suggest_map_from_handlers",
    "compute_cfg",
    "pretty_print_ir",
    "collapse_trivial_blocks",
    "validate_opcode_map",
    "write_validation_report",
    "ValidationSummary",
    "ValidationIssue",
    "StrictnessProfile",
    "run_opcode_validator_cli",
]


def __getattr__(name: str) -> Any:
    if name == "LuraphVM":
        from src.vm.emulator import LuraphVM as _LuraphVM
        return _LuraphVM
    if name == "VMState":
        from src.vm.state import VMState as _VMState
        return _VMState
    if name == "Disassembler":
        from src.vm.disassembler import Disassembler as _Disassembler
        return _Disassembler
    if name == "DisassemblerConfig":
        from src.vm.disassembler import DisassemblerConfig as _DisassemblerConfig
        return _DisassemblerConfig
    if name == "FieldConfig":
        from src.vm.disassembler import FieldConfig as _FieldConfig
        return _FieldConfig
    if name == "Instruction":
        from src.vm.disassembler import Instruction as _Instruction
        return _Instruction
    if name == "DispatcherBlock":
        from src.vm.block_recover import DispatcherBlock as _DispatcherBlock

        return _DispatcherBlock
    if name == "DispatcherCFG":
        from src.vm.block_recover import DispatcherCFG as _DispatcherCFG

        return _DispatcherCFG
    if name == "write_dispatcher_cfg":
        from src.vm.block_recover import write_dispatcher_cfg as _write_dispatcher_cfg

        return _write_dispatcher_cfg
    if name == "DisassemblyCandidate":
        from src.vm.disasm_driver import DisassemblyCandidate as _DisassemblyCandidate
        return _DisassemblyCandidate
    if name == "DEFAULT_SPLITS":
        from src.vm.disasm_driver import DEFAULT_SPLITS as _DEFAULT_SPLITS
        return _DEFAULT_SPLITS
    if name == "build_config_from_split":
        from src.vm.disasm_driver import build_config_from_split as _build_config_from_split
        return _build_config_from_split
    if name == "generate_disassembly_candidates":
        from src.vm.disasm_driver import (
            generate_disassembly_candidates as _generate_disassembly_candidates,
        )
        return _generate_disassembly_candidates
    if name == "run_driver":
        from src.vm.disasm_driver import run_driver as _run_driver
        return _run_driver
    if name == "Lifter":
        from src.vm.lifter import Lifter as _Lifter
        return _Lifter
    if name == "IRProgram":
        from src.vm.lifter import IRProgram as _IRProgram
        return _IRProgram
    if name == "BasicBlock":
        from src.vm.lifter import BasicBlock as _BasicBlock
        return _BasicBlock
    if name == "IROp":
        from src.vm.lifter import IROp as _IROp
        return _IROp
    if name == "IROperand":
        from src.vm.lifter import IROperand as _IROperand
        return _IROperand
    if name == "OpcodeMap":
        from src.vm.opcode_map import OpcodeMap as _OpcodeMap
        return _OpcodeMap
    if name == "MapCandidate":
        from src.vm.opcode_map import MapCandidate as _MapCandidate
        return _MapCandidate
    if name == "suggest_map_from_handlers":
        from src.vm.opcode_map import suggest_map_from_handlers as _suggest
        return _suggest
    if name == "score_map":
        from src.vm.opcode_map import score_map as _score
        return _score
    if name == "apply_map_to_disasm":
        from src.vm.opcode_map import apply_map_to_disasm as _apply
        return _apply
    if name == "persist_candidate":
        from src.vm.opcode_map import persist_candidate as _persist
        return _persist
    if name == "load_map":
        from src.vm.opcode_map import load_map as _load
        return _load
    if name == "compute_cfg":
        from src.vm.ir_utils import compute_cfg as _compute_cfg
        return _compute_cfg
    if name == "pretty_print_ir":
        from src.vm.ir_utils import pretty_print_ir as _pretty_print_ir
        return _pretty_print_ir
    if name == "collapse_trivial_blocks":
        from src.vm.ir_utils import collapse_trivial_blocks as _collapse_trivial_blocks
        return _collapse_trivial_blocks
    if name == "OpcodeProposal":
        from src.vm.opcode_proposer import OpcodeProposal as _OpcodeProposal
        return _OpcodeProposal
    if name == "OpcodeMapCandidate":
        from src.vm.opcode_proposer import OpcodeMapCandidate as _OpcodeMapCandidate
        return _OpcodeMapCandidate
    if name == "propose_opcode_mappings":
        from src.vm.opcode_proposer import propose_opcode_mappings as _propose_opcode_mappings
        return _propose_opcode_mappings
    if name == "group_proposals_by_opcode":
        from src.vm.opcode_proposer import group_proposals_by_opcode as _group_proposals_by_opcode
        return _group_proposals_by_opcode
    if name == "generate_map_candidates":
        from src.vm.opcode_proposer import generate_map_candidates as _generate_map_candidates
        return _generate_map_candidates
    if name == "render_ir_candidate":
        from src.vm.opcode_proposer import render_ir_candidate as _render_ir_candidate
        return _render_ir_candidate
    if name == "compute_opcode_usage":
        from src.vm.opcode_proposer import compute_opcode_usage as _compute_opcode_usage
        return _compute_opcode_usage
    if name == "load_handler_suggestions":
        from src.vm.opcode_proposer import load_handler_suggestions as _load_handler_suggestions
        return _load_handler_suggestions
    if name == "load_disassembly_instructions":
        from src.vm.opcode_proposer import (
            load_disassembly_instructions as _load_disassembly_instructions,
        )

        return _load_disassembly_instructions
    if name == "synthesise_opcode_proposals":
        from src.vm.opcode_proposer import synthesise_opcode_proposals as _synthesise_opcode_proposals

        return _synthesise_opcode_proposals
    if name == "write_proposals":
        from src.vm.opcode_proposer import write_proposals as _write_proposals

        return _write_proposals
    if name == "run_opcode_proposer_cli":
        from src.vm.opcode_proposer import run_cli as _run_cli

        return _run_cli
    if name == "HandlerInfo":
        from src.vm.opcode_mapper_tui import HandlerInfo as _HandlerInfo
        return _HandlerInfo
    if name == "OpcodeMappingSession":
        from src.vm.opcode_mapper_tui import OpcodeMappingSession as _OpcodeMappingSession
        return _OpcodeMappingSession
    if name == "OpcodeMappingShell":
        from src.vm.opcode_mapper_tui import OpcodeMappingShell as _OpcodeMappingShell
        return _OpcodeMappingShell
    if name == "load_handler_index":
        from src.vm.opcode_mapper_tui import load_handler_index as _load_handler_index
        return _load_handler_index
    if name == "load_mapping_file":
        from src.vm.opcode_mapper_tui import load_mapping_file as _load_mapping_file
        return _load_mapping_file
    if name == "recover_dispatcher_cfg":
        from src.vm.block_recover import recover_dispatcher_cfg as _recover_dispatcher_cfg

        return _recover_dispatcher_cfg
    if name == "ControlFlowReconstructor":
        from src.vm.reconstruct_controlflow import (
            ControlFlowReconstructor as _ControlFlowReconstructor,
        )

        return _ControlFlowReconstructor
    if name == "StructuredProgram":
        from src.vm.reconstruct_controlflow import StructuredProgram as _StructuredProgram

        return _StructuredProgram
    if name == "SequenceNode":
        from src.vm.reconstruct_controlflow import SequenceNode as _SequenceNode

        return _SequenceNode
    if name == "BlockNode":
        from src.vm.reconstruct_controlflow import BlockNode as _BlockNode

        return _BlockNode
    if name == "IfNode":
        from src.vm.reconstruct_controlflow import IfNode as _IfNode

        return _IfNode
    if name == "WhileNode":
        from src.vm.reconstruct_controlflow import WhileNode as _WhileNode

        return _WhileNode
    if name == "TrapNode":
        from src.vm.reconstruct_controlflow import TrapNode as _TrapNode

        return _TrapNode
    if name == "reconstruct_control_flow":
        from src.vm.reconstruct_controlflow import (
            reconstruct_control_flow as _reconstruct_control_flow,
        )

        return _reconstruct_control_flow
    if name == "HandlerPattern":
        from src.vm.compare_handlers import HandlerPattern as _HandlerPattern

        return _HandlerPattern
    if name == "HandlerComparison":
        from src.vm.compare_handlers import HandlerComparison as _HandlerComparison

        return _HandlerComparison
    if name == "HandlerFingerprint":
        from src.vm.compare_handlers import HandlerFingerprint as _HandlerFingerprint

        return _HandlerFingerprint
    if name == "DEFAULT_HANDLER_PATTERNS":
        from src.vm.compare_handlers import DEFAULT_PATTERNS as _DEFAULT_HANDLER_PATTERNS

        return _DEFAULT_HANDLER_PATTERNS
    if name == "compare_handler_bytes":
        from src.vm.compare_handlers import compare_handler_bytes as _compare_handler_bytes

        return _compare_handler_bytes
    if name == "fingerprint_bytes":
        from src.vm.compare_handlers import fingerprint_bytes as _fingerprint_bytes

        return _fingerprint_bytes
    if name == "emit_inline":
        from src.vm.inline_emitter import emit_inline as _emit_inline

        return _emit_inline
    if name == "emit_inline_from_dict":
        from src.vm.inline_emitter import emit_inline_from_dict as _emit_inline_from_dict

        return _emit_inline_from_dict
    if name == "validate_opcode_map":
        from src.vm.opcode_map_validator import validate_opcode_map as _validate_opcode_map

        return _validate_opcode_map
    if name == "write_validation_report":
        from src.vm.opcode_map_validator import write_validation_report as _write_validation_report

        return _write_validation_report
    if name == "ValidationSummary":
        from src.vm.opcode_map_validator import ValidationSummary as _ValidationSummary

        return _ValidationSummary
    if name == "ValidationIssue":
        from src.vm.opcode_map_validator import ValidationIssue as _ValidationIssue

        return _ValidationIssue
    if name == "StrictnessProfile":
        from src.vm.opcode_map_validator import StrictnessProfile as _StrictnessProfile

        return _StrictnessProfile
    if name == "run_opcode_validator_cli":
        from src.vm.opcode_map_validator import run_cli as _run_opcode_validator_cli

        return _run_opcode_validator_cli
    raise AttributeError(name)
