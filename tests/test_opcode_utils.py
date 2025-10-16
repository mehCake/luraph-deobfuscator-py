from __future__ import annotations

from src.bootstrap_extractor.bootstrap_parser import OpcodeHandler
from src.versions import OpSpec
from src.vm.opcode_utils import normalize_mnemonic, operand_model_from_handler, opcode_table_merge


def test_normalize_mnemonic_aliases() -> None:
    assert normalize_mnemonic("move_reg") == "MOVE"
    assert normalize_mnemonic("pushk") == "LOADK"
    assert normalize_mnemonic("tail_call") == "TAILCALL"


def test_operand_model_from_handler_infers_models() -> None:
    snippet_bx = """
    function(dispatch_state, a, bx)
      return dispatch_state.constants[bx]
    end
    """
    snippet_sbx = """
    function(dispatch_state, sbx)
      return sbx
    end
    """
    snippet_ab = """
    function(dispatch_state, a, b)
      dispatch_state[a] = b
    end
    """
    snippet_ax = """
    function(dispatch_state, a)
      return a
    end
    """

    assert operand_model_from_handler(snippet_bx) == "A Bx"
    assert operand_model_from_handler(snippet_sbx) == "sBx"
    assert operand_model_from_handler(snippet_ab) == "A B"
    assert operand_model_from_handler(snippet_ax) == "Ax"


def test_opcode_table_merge_prefers_high_trust() -> None:
    bootstrap_handlers = {
        0x10: OpcodeHandler(
            opcode=0x10,
            mnemonic="move_reg",
            operands="A B",
            trust="high",
            source_snippet="function(state, a, b) return a end",
            offset=0,
        ),
        0x11: OpcodeHandler(
            opcode=0x11,
            mnemonic="mystery_op",
            operands="",
            trust="low",
            source_snippet="function(state, a, b, c) return a + b + c end",
            offset=4,
        ),
    }
    heuristic_table = {
        0x10: OpSpec(mnemonic="MOVE", operands=("A", "B")),
        0x11: OpSpec(mnemonic="ADD", operands=("A", "B", "C")),
    }

    merged = opcode_table_merge(bootstrap_handlers, heuristic_table)

    assert merged[0x10]["mnemonic"] == "MOVE"
    assert merged[0x10]["operands"] == "A B"
    assert merged[0x10]["trust"] == "high"
    assert merged[0x10]["source"] == "bootstrap"

    assert merged[0x11]["mnemonic"] == "ADD"
    assert merged[0x11]["operands"] == "A B C"
    assert merged[0x11]["trust"] == "low"


def test_opcode_table_merge_marks_confidence_and_mandatory() -> None:
    bootstrap_handlers = {
        0x00: OpcodeHandler(
            opcode=0x00,
            mnemonic="move",
            operands="A B",
            trust="high",
            source_snippet="function(state, a, b) state[a] = state[b] end",
            offset=0,
        )
    }
    heuristic_table = {
        0x00: OpSpec("MOVE", ("A", "B")),
        0x01: OpSpec("LOADK", ("A", "Bx")),
        0x1C: OpSpec("CALL", ("A", "B", "C")),
    }

    merged = opcode_table_merge(bootstrap_handlers, heuristic_table)

    move_entry = merged[0x00]
    assert move_entry["trust"] == "high"
    assert move_entry["confidence"] >= 3
    assert move_entry["mandatory"] is True
    assert move_entry["source"] == "bootstrap"

    loadk_entry = merged[0x01]
    assert loadk_entry["trust"] == "heuristic"
    assert loadk_entry["confidence"] == 0
    assert loadk_entry["mandatory"] is True
    assert loadk_entry["source"] == "heuristic"
