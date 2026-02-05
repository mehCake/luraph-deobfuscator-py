import csv
import json
import re
from pathlib import Path

import pytest

from pattern_analyzer import PatternAnalyzer


OPAQUE_IR = """\
LOADK R0 0
EQ R0 1 4
LOADK R1 10
JMP 5
LOADK R1 20
RETURN R1
"""


PEEPHOLE_IR = """\
LOADK R0 0
ADD R1 R0 0
CONCAT R2 "foo" "bar"
JMP 5
JMP 5
RETURN R2
"""


def test_opaque_predicate_reduced_to_single_branch(tmp_path):
    analyzer = PatternAnalyzer()
    instructions = analyzer.parse_ir(OPAQUE_IR)
    optimised = analyzer.optimise_ir(instructions)

    # the opaque EQ predicate should have been rewritten to a direct flow
    opcodes = [ins.opcode for ins in optimised]
    assert "EQ" not in opcodes
    assert opcodes.count("JMP") == 1

    report = analyzer.last_report
    assert report is not None
    assert report.opaque_predicates == {1}
    assert all("20" not in ins.args for ins in optimised)


@pytest.mark.parametrize("ir_text, golden_name", [(PEEPHOLE_IR, "ir_cleanup.out")])
def test_ir_cleanup_matches_golden(tmp_path, ir_text: str, golden_name: str):
    analyzer = PatternAnalyzer()
    formatted = analyzer.optimise_ir_text(ir_text)
    golden_path = Path("tests/golden") / golden_name
    expected = golden_path.read_text().strip()
    assert formatted.strip() == expected


def test_generate_upcode_table_normalises_mnemonics():
    analyzer = PatternAnalyzer()
    raw_table = {
        0x01: {
            "mnemonic": "LOADK",
            "extra": "keep",
            "operand_types": ["R", "K"],
            "sample_usage": "LOADK R0 0",
        },
        0x02: {
            "mnemonic": "OP_CUSTOM",
            "operand_types": ["R0"],
            "sample_usage": "OP_CUSTOM R0",
        },
        0x03: {
            "operand_types": [],
            "sample_usage": "auto generated",
        },
        0x04: {
            "mnemonic": None,
            "operand_types": ["R1"],
            "sample_usage": "fallback",
        },
        0x05: {
            "mnemonic": "jmp",
            "operand_types": ["label"],
            "sample_usage": "JMP 0x10",
        },
        0x06: {
            "handler": "function helperB() end",
            "operand_types": ["R2"],
            "sample_usage": "helperB()",
        },
        0x07: {
            "notes": ["uses helperC inside"],
            "operand_types": ["R3"],
            "sample_usage": "helperC()",
        },
        0x08: {
            "mnemonic": "op-extra$",
            "operand_types": ["R4"],
            "sample_usage": "OP_EXTRA R4",
        },
    }

    table = analyzer.generate_upcode_table(raw_table)

    assert set(table) == set(raw_table)
    assert table[0x01]["mnemonic"] == "OP_LOADK"
    assert table[0x01]["extra"] == "keep"
    assert table[0x02]["mnemonic"] == "OP_CUSTOM"
    assert table[0x03]["mnemonic"] == "OP_03"
    assert table[0x04]["mnemonic"] == "OP_04"
    assert table[0x05]["mnemonic"] == "OP_JMP"
    assert table[0x06]["mnemonic"] == "OP_HELPERB"
    assert table[0x07]["mnemonic"] == "OP_HELPERC"
    assert table[0x08]["mnemonic"] == "OP_EXTRA"

    for entry in table.values():
        assert entry["mnemonic"].startswith("OP_")
        assert "operand_types" in entry
        assert "sample_usage" in entry


def test_generate_upcode_table_outputs_docs(tmp_path):
    analyzer = PatternAnalyzer()
    raw_table = {
        0x01: {
            "mnemonic": "move",
            "frequency": 3,
            "operand_types": ["R", "R"],
            "sample_usage": "MOVE R0 R1",
        },
        0x02: {
            "handler": "function helperA() end",
            "frequency": "5",
            "operand_types": ["R0"],
            "sample_usage": "helperA()",
        },
        0x03: {
            "mnemonic": "op-mixed",
            "frequency": None,
            "operand_types": ["R2"],
            "sample_usage": "OP_MIXED R2",
        },
        0x04: {
            "operand_types": [],
            "sample_usage": "fallback",
        },
        0x05: {
            "mnemonic": None,
            "operand_types": ["label"],
            "sample_usage": "JMP 0x20",
        },
    }

    outputs = analyzer.generate_upcode_table_outputs_docs(raw_table, tmp_path)

    expected_keys = {"json", "md", "csv", "html"}
    assert expected_keys <= outputs.keys(), (
        "Missing documentation outputs: "
        f"expected {sorted(expected_keys)}, got {sorted(outputs.keys())}"
    )

    for key in expected_keys:
        path = outputs[key]
        assert path.is_file(), f"Expected {key.upper()} output to exist at {path!s}"

    payload = json.loads(outputs["json"].read_text())
    assert payload, "JSON documentation payload should not be empty"

    for entry in payload:
        opcode = entry.get("opcode", "<unknown>")
        mnemonic = entry.get("mnemonic")
        if not mnemonic:
            pytest.fail(f"Opcode {opcode} missing mnemonic in documentation entry: {entry}")
        if not str(mnemonic).startswith("OP_"):
            pytest.fail(
                f"Opcode {opcode} has invalid mnemonic {mnemonic!r}; expected to start with 'OP_'"
            )
        if "frequency" not in entry:
            pytest.fail(f"Opcode {opcode} missing frequency in documentation entry: {entry}")
        frequency = entry["frequency"]
        if not isinstance(frequency, int):
            pytest.fail(
                f"Opcode {opcode} frequency must be an integer, got {type(frequency).__name__}: {entry}"
            )
        if frequency < 0:
            pytest.fail(
                f"Opcode {opcode} has negative frequency {frequency}; expected non-negative"
            )


def test_generate_upcode_table_doc_outputs_are_consistent(tmp_path):
    analyzer = PatternAnalyzer()
    raw_table = {
        0x01: {
            "mnemonic": "move",
            "frequency": 2,
            "operand_types": ["R", "R"],
            "sample_usage": "MOVE R0 R1",
        },
        0x02: {
            "handler": "function helperB() end",
            "frequency": "7",
            "operand_types": ["R0"],
            "sample_usage": "helperB()",
        },
        0x03: {
            "mnemonic": "op-extra",
            "operand_types": ["K"],
            "sample_usage": "OP_EXTRA K0",
        },
    }

    outputs = analyzer.generate_upcode_table_outputs_docs(raw_table, tmp_path)

    json_rows = json.loads(outputs["json"].read_text())

    with outputs["csv"].open(newline="", encoding="utf-8") as handle:
        csv_rows = list(csv.DictReader(handle))

    html_text = outputs["html"].read_text()
    html_rows = [
        {
            "opcode": match.group(1),
            "mnemonic": match.group(2),
            "frequency": match.group(3),
        }
        for match in re.finditer(
            r"<tr><td>([^<]+)</td><td>([^<]+)</td><td>([^<]+)</td></tr>", html_text
        )
    ]

    assert json_rows, "JSON output should contain opcode rows"
    assert csv_rows, "CSV output should contain opcode rows"
    assert html_rows, "HTML output should contain opcode rows"

    def normalise(rows):
        mapping = {}
        for row in rows:
            opcode = row["opcode"]
            mnemonic = row["mnemonic"]
            mapping[opcode] = mnemonic
        return mapping

    json_map = normalise(json_rows)
    csv_map = normalise(csv_rows)
    html_map = normalise(html_rows)

    assert len(json_map) == len(csv_map) == len(html_map), (
        "Documentation outputs should contain an identical number of opcodes: "
        f"json={len(json_map)}, csv={len(csv_map)}, html={len(html_map)}"
    )

    assert json_map == csv_map == html_map, (
        "Documentation outputs should report matching mnemonics for each opcode:\n"
        f"JSON: {json_map}\nCSV: {csv_map}\nHTML: {html_map}"
    )

def test_generate_upcode_table_requires_schema_fields():
    analyzer = PatternAnalyzer()

    with pytest.raises(ValueError) as exc:
        analyzer.generate_upcode_table(
            {
                0x01: {
                    "mnemonic": "MOVE",
                    "operand_types": ["R0", "R1"],
                    # sample_usage intentionally omitted
                }
            }
        )

    assert "sample_usage" in str(exc.value)


def test_locate_serialized_chunk_v14_3():
    analyzer = PatternAnalyzer()
    source = Path("Obfuscated4.lua").read_text(encoding="utf8")

    chunk = analyzer.locate_serialized_chunk(source)
    assert chunk is not None
    assert chunk.buffer_name == "E"
    assert chunk.initial_offset == 1

    helpers = chunk.helper_functions
    assert set(helpers) == {"o", "t3", "a3", "M", "r"}
    assert helpers["o"] == "o"
    assert helpers["t3"] == "t3"
    assert helpers["a3"] == "a3"
    assert helpers["M"] == "M"
    assert helpers["r"] == "r"


def test_detect_bootstrap_state_machine_recognises_v14_3_dispatcher():
    analyzer = PatternAnalyzer()
    source = Path("Obfuscated4.lua").read_text(encoding="utf8")

    machine = analyzer.detect_bootstrap_state_machine(source)

    assert machine is not None, "Expected bootstrap state machine to be detected"
    assert machine.variable == "x"
    assert len(machine.states) >= 2

    first_state = machine.states[0]
    assert first_state.state_id.lower() in {"85", "0x55"}
    assert any(op.startswith("F3[") for op in first_state.operations)
    assert any(tr.expression for tr in first_state.transitions)

    break_state = next(
        (state for state in machine.states if any(tr.expression == "break" for tr in state.transitions)),
        None,
    )
    assert break_state is not None


def test_analyze_cache_slots_classifies_v14_3_cache_usage():
    analyzer = PatternAnalyzer()
    source = Path("Obfuscated4.lua").read_text(encoding="utf8")

    payload = analyzer.analyze_cache_slots(source)

    assert payload["slot_count"] >= 5
    assert "slots" in payload and payload["slots"], "Expected cache slot summary"

    # ensure the payload is JSON serialisable and mirrored in the side-band store
    serialised = json.dumps(payload)
    assert serialised, "Serialised cache slot payload should not be empty"
    assert analyzer.side_band.get("cache_slots") == payload

    slots = {slot["index_literal"].lower(): slot for slot in payload["slots"]}

    assert "0x42d" in slots
    assert slots["0x42d"]["classification"] == "table reference"

    assert "6056" in slots
    assert slots["6056"]["semantic_role"] == "double mantissa mask"

    passthrough = slots.get("0x16e7")
    assert passthrough is not None
    assert passthrough["classification"] == "passthrough"

    # At least one slot should describe string limits to support constant evaluation downstream
    assert any(
        slot["semantic_role"] == "string length limit" for slot in payload["slots"]
    )


def test_identify_c3_primitives_extracts_v14_3_mapping():
    analyzer = PatternAnalyzer()
    source = Path("Obfuscated4.lua").read_text(encoding="utf8")

    payload = analyzer.identify_c3_primitives(source)

    assert payload is not None, "Expected primitive table metadata to be detected"
    assert payload["count"] == len(payload["entries"])
    assert payload["count"] >= 5
    assert analyzer.side_band.get("c3_primitives") == payload

    modules = set(payload["modules"])
    assert {"bit32", "string", "table"} <= modules

    entries = payload["entries"]
    assert entries[0]["slot"] == "n"
    assert entries[0]["builtin"] == "string.unpack"
    assert entries[0]["accessor"] == "C3.n"

    keyed = {entry["slot"]: entry for entry in entries if entry["slot_type"] == "key"}
    assert keyed["u"]["builtin"] == "bit32.bxor"
    assert keyed["K"]["builtin"] == "string.sub"
    assert keyed["Y"]["builtin"] == "table.create"

    assert entries[-1]["builtin"] == "bit32.band"


def test_identify_primitive_table_info_extracts_token_math():
    analyzer = PatternAnalyzer()
    source = Path("Obfuscated4.lua").read_text(encoding="utf8")

    info = analyzer.identify_primitive_table_info(source)

    assert info is not None, "Expected primitive table info to be recovered"
    assert info.token_width == 5
    assert info.base_offset == 33
    assert info.radix == 85
    assert info.weights[:3] == [1, 0x55, 0x55 * 0x55]
    assert info.alphabet_literal and info.alphabet_literal.startswith("\"")
    assert info.xor_pairs, "At least one xor pair should be recorded"
    assert "lshift" in info.shift_counts
    assert analyzer.side_band.get("primitive_table_info", {}).get("token_width") == 5
