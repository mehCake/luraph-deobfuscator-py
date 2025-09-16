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
