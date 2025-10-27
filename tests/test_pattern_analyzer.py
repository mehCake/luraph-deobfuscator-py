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
