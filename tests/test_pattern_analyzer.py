import json
from pathlib import Path

import pytest

from src.ir import VMFunction, VMInstruction
from version_detector import extract_fragments

from snapshot_manager import SnapshotManager

from pattern_analyzer import (
    PatternAnalyzer,
    build_vm_cfg,
    helpers_to_opcodes,
    find_vm_signatures,
    generate_upcode_table,
    lift_vm,
    opcode_frequency_heatmap,
    opcode_semantics_guesses,
    simulate_vm,
)


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


OBFUSCATED2_TEMP_IR = """\
LOADK R0 41
MOVE R1 R0
MOVE R2 R1
RETURN R2
"""

# Extracted from the small helper that bumps a register before returning it in
# ``Obfuscated2.lua``.
OBFUSCATED2_SELF_ADD_IR = """\
LOADK R0 1
ADD R0 R0 2
RETURN R0
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


def test_ssa_constant_propagation_eliminates_temporaries():
    analyzer = PatternAnalyzer()
    instructions = analyzer.parse_ir(OBFUSCATED2_TEMP_IR)

    optimised = analyzer.optimise_ir(instructions)
    opcodes = [ins.opcode for ins in optimised]

    assert "MOVE" not in opcodes

    return_args = next(ins.args for ins in optimised if ins.opcode == "RETURN")
    assert return_args == ["41"]

    report = analyzer.last_report
    assert report is not None
    assert report.temporaries_eliminated >= 2
    assert report.size_before > report.size_after

    chains = analyzer.last_ssa_chains
    assert chains == {}


def test_ssa_conversion_preserves_previous_versions_for_self_ops():
    analyzer = PatternAnalyzer()
    instructions = analyzer.parse_ir(OBFUSCATED2_SELF_ADD_IR)

    ssa = analyzer.convert_to_ssa(instructions)
    add_ins = next(ins for ins in ssa.instructions if ins.opcode == "ADD")

    assert add_ins.args == ["R0_2", "R0_1", "2"]
    assert ssa.definitions["R0_1"] == 0
    assert ssa.definitions["R0_2"] == 1
    assert ssa.uses["R0_1"] == {1}
    assert ssa.uses["R0_2"] == {2}


def test_ssa_constant_propagation_folds_self_referential_add():
    analyzer = PatternAnalyzer()
    instructions = analyzer.parse_ir(OBFUSCATED2_SELF_ADD_IR)

    optimised = analyzer.optimise_ir(instructions)

    assert [ins.opcode for ins in optimised] == ["RETURN"]
    assert optimised[0].args == ["3"]

    report = analyzer.last_report
    assert report is not None
    assert report.temporaries_eliminated >= 2
    assert report.size_before == 3
    assert report.size_after == 1

def test_build_use_def_chains_tracks_assignments():
    analyzer = PatternAnalyzer()
    instructions = analyzer.parse_ir(OBFUSCATED2_TEMP_IR)

    chains = analyzer.build_use_def_chains(instructions)

    assert chains["R0_1"]["definition"] == 0
    assert chains["R2_1"]["definition"] == 2
    assert chains["R2_1"]["uses"] == [3]


def test_register_model_analysis_produces_allocation_and_pseudo_lua():
    analyzer = PatternAnalyzer()
    func = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("LOADK", a=0, aux={"b_mode": "const", "const_b": 5}),
            VMInstruction("MOVE", a=1, b=0),
            VMInstruction("ADD", a=1, b=1, c=0),
            VMInstruction("RETURN", a=1, aux={"b_mode": "immediate", "immediate_b": 2}),
        ],
        num_params=1,
        register_count=3,
    )

    report = analyzer.analyse_register_model(func)

    assert report["model"] == "register"
    assert report["register_count"] == 2
    assert report["stack_depth"] == 0
    assert report["stack_slots"] == {}
    assert report["register_usage"][0]["name"] == "arg0"
    assert report["register_usage"][1]["role"] == "temp"
    assert report["max_pressure"] >= 2
    assert any(entry["count"] >= 2 for entry in report["pressure_profile"])

    pseudo = report["pseudo_lua"].splitlines()
    assert pseudo[0] == "local arg0, t1"
    assert "arg0 = 5" in pseudo[1]
    assert "t1 = arg0" in pseudo[2]
    assert "t1 = t1 + arg0" in pseudo[3]
    assert pseudo[-1] == "return t1"

    assert analyzer.last_register_analysis is report


def test_stack_model_detection_and_plan():
    analyzer = PatternAnalyzer()
    func = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("PUSHK", aux={"value": "foo"}),
            VMInstruction("PUSHK", aux={"value": "bar"}),
            VMInstruction("POP"),
        ],
    )

    report = analyzer.analyse_register_model(func)

    assert report["model"] == "stack"
    assert report["register_usage"] == {}
    assert report["max_pressure"] == 0
    assert report["pressure_profile"] == []
    assert report["stack_depth"] == 2
    assert report["stack_slots"] == {0: "stack0", 1: "stack1"}
    assert any(entry["depth"] == 2 for entry in report["stack_profile"])

    pseudo = report["pseudo_lua"]
    assert "local stack0, stack1" in pseudo
    assert "stack1 = nil" in pseudo

    assert analyzer.last_register_analysis is report


def test_optimise_vm_function_reduces_instruction_count():
    analyzer = PatternAnalyzer()
    func = VMFunction(
        constants=[],
        instructions=[
            VMInstruction(
                "BAND",
                a=0,
                aux={"b_mode": "immediate", "immediate_b": 3, "c_mode": "immediate", "immediate_c": 1},
            ),
            VMInstruction(
                "ADD",
                a=1,
                b=0,
                aux={"c_mode": "immediate", "immediate_c": 0},
            ),
            VMInstruction("LOADK", a=1, aux={"b_mode": "const", "const_b": 42}),
            VMInstruction("LOADK", a=1, aux={"b_mode": "const", "const_b": 42}),
            VMInstruction("MOVE", a=2, b=1),
            VMInstruction("RETURN", a=1, aux={"b_mode": "immediate", "immediate_b": 2}),
        ],
        register_count=3,
    )

    report = analyzer.optimise_vm_function(func)

    assert report["original_instructions"] == 6
    assert report["optimized_instructions"] < report["original_instructions"]
    assert report["reduction"] >= 1
    assert report["size_before"] == report["original_instructions"]
    assert report["size_after"] == report["optimized_instructions"]
    assert 0.0 <= report["reduction_ratio"] <= 1.0
    assert report["reduction_percent"] == pytest.approx(report["reduction_ratio"] * 100)

    optimised = report["function"].instructions
    assert optimised
    assert optimised[0].opcode == "LOADK"
    value, known = analyzer._vm_loadk_value(optimised[0])
    assert known and value == 1

    assert analyzer.last_vm_optimisation is report


def test_vm_optimizer_preserves_runtime_semantics():
    analyzer = PatternAnalyzer()
    program = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("LOADK", a=0, aux={"b_mode": "const", "const_b": 10}),
            VMInstruction("LOADK", a=1, aux={"b_mode": "const", "const_b": 32}),
            VMInstruction("MOVE", a=2, b=0),
            VMInstruction("ADD", a=2, b=2, c=1),
            VMInstruction("MOVE", a=3, b=2),
            VMInstruction("RETURN", a=3, aux={"b_mode": "immediate", "immediate_b": 2}),
        ],
        register_count=4,
    )

    original = simulate_vm(program, inputs=[])
    report = analyzer.optimise_vm_function(program)
    optimised_program = report["function"]
    optimised = simulate_vm(optimised_program, inputs=[])

    assert original.output == optimised.output == 42
    assert report["optimized_instructions"] < report["original_instructions"]
    assert report["reduction"] >= 1


def test_find_vm_signatures_detects_dispatcher():
    pytest.importorskip("luaparser")
    source = """
local handlers = {
    [1] = function(state) return state + 1 end,
    [2] = function(state) return state - 1 end,
    [3] = function(state) return state end,
}

local function dispatcher(state, opcode)
    bit32.bxor(opcode, 3)
    if opcode == 1 then
        return handlers[1](state)
    elseif opcode == 2 then
        return handlers[2](state)
    end
    return handlers[3](state)
end

return dispatcher
"""

    results = find_vm_signatures(source)
    assert results
    top = results[0]
    assert top["name"] == "dispatcher"
    assert any(case["opcode"] == 1 for case in top["opcode_cases"])
    assert top["handler_tables"] and top["handler_tables"][0]["name"] == "handlers"
    assert "bit32.bxor" in top["bit_ops"]
    assert "if-chain" in top["summary"]


def test_find_vm_signatures_obfuscated2_smoke():
    pytest.importorskip("luaparser")
    source = Path("Obfuscated2.lua").read_text(encoding="utf-8")
    results = find_vm_signatures(source)
    assert results
    assert any(candidate["handler_tables"] for candidate in results)
    assert any(
        isinstance(case["opcode"], (int, float))
        for candidate in results
        for case in candidate["opcode_cases"]
    )
    assert all(candidate["summary"] for candidate in results)


def test_find_vm_signatures_regex_fallback(monkeypatch):
    ast = pytest.importorskip("luaparser.ast")
    source = """
local handlers = {}
handlers[0] = function() end
handlers[1] = function() end

local function dispatcher(op)
    if op == 0 then
        return handlers[0]()
    elseif op == 1 then
        return handlers[1]()
    end
end
"""

    def boom(_src):
        raise ast.SyntaxException("boom")

    monkeypatch.setattr(ast, "parse", boom)

    results = find_vm_signatures(source)
    assert results
    top = results[0]
    assert top["handler_tables"]
    assert any(isinstance(case["opcode"], int) for case in top["opcode_cases"])
    assert "handlers" in top["summary"]


def test_opcode_frequency_heatmap_reports_counts():
    pytest.importorskip("luaparser")
    source = Path("Obfuscated2.lua").read_text(encoding="utf-8")
    report = opcode_frequency_heatmap(source)

    assert report["frequencies"]
    csv_lines = report["csv"].splitlines()
    assert csv_lines[0] == "opcode,count"
    first_opcode, first_count = csv_lines[1].split(",")
    counts = dict(report["frequencies"])
    assert int(first_opcode) in counts
    assert counts[int(first_opcode)] == int(first_count)

    histogram_lines = report["histogram"].splitlines()
    assert histogram_lines
    assert all("(" in line and ")" in line for line in histogram_lines)
    assert histogram_lines[0].strip()


def test_helpers_to_opcodes_maps_helper_calls(tmp_path):
    pytest.importorskip("luaparser")

    sample = """
local handlers = {}

handlers[0x10] = function(vm)
    return helperA(vm, 41)
end

handlers[0x20] = function(vm)
    return vm:helperB()
end

handlers[0x21] = function(vm)
    return helperA(vm, helperB(vm))
end

local function dispatcher(vm, opcode)
    if opcode == 0x10 then
        return handlers[0x10](vm)
    elseif opcode == 0x20 then
        return handlers[0x20](vm)
    elseif opcode == 0x21 then
        return handlers[0x21](vm)
    end
end

return({
    helperA = function(self, value)
        return value + 1
    end,
    helperB = function(self)
        return self.value or 0
    end,
    run = dispatcher,
})
"""

    output_path = tmp_path / "helpers.json"
    report = helpers_to_opcodes(sample, output_path=output_path)

    assert output_path.exists()
    on_disk = json.loads(output_path.read_text())
    assert on_disk["helpers"] == report["helpers"]

    helpers = report["helpers"]
    assert {"helperA", "helperB"}.issubset(helpers.keys())

    helper_a_calls = sorted(site["opcode"] for site in helpers["helperA"]["call_sites"])
    assert helper_a_calls == [0x10, 0x21]
    assert any(":helperB" in site["snippet"] for site in helpers["helperB"]["call_sites"])
    helper_b_calls = sorted(site["opcode"] for site in helpers["helperB"]["call_sites"])
    assert helper_b_calls == [0x20, 0x21]


def _find_function_by_name(module, name: str):
    body = getattr(module, "body", None)
    if body is None:
        return None
    if isinstance(body, list):
        statements = body
    else:
        statements = getattr(body, "body", []) or []
    for stmt in statements:
        node_name = getattr(getattr(stmt, "name", None), "id", None)
        if node_name == name:
            return stmt
    return None


def test_lift_vm_generates_unique_ir_nodes():
    luaparser = pytest.importorskip("luaparser")
    ast = luaparser.ast

    source = """
local handlers = {}
local stack = {}

local function dispatcher(state, opcode)
    if opcode == 10 then
        local top = stack[opcode]
        return handlers[top](state)
    elseif opcode == 11 then
        stack[opcode] = state
        state = state + 1
    elseif opcode == 12 then
        return string.byte(state)
    end
end
"""

    module = ast.parse(source)
    dispatcher_node = _find_function_by_name(module, "dispatcher")
    assert dispatcher_node is not None

    nodes = lift_vm(dispatcher_node)
    assert [node.opcode for node in nodes] == [10, 11, 12]
    assert len(nodes) == len({node.opcode for node in nodes})

    first, second, third = nodes
    assert "handlers" in first.args and "stack" in first.args
    assert "top" in first.effects

    assert set(second.effects) == {"stack", "state"}
    assert "opcode" in second.args and "state" in second.args

    assert third.effects == []
    assert "string" in third.args or any(name.startswith("string") for name in third.args)


def test_opcode_semantics_guesses_produces_mapping(tmp_path):
    pytest.importorskip("luaparser")
    source = """
local handlers = {}
handlers[1] = function(state)
    table.insert(state, 1)
end
handlers[2] = function(state)
    return bit32.band(state[1], 255)
end

local function dispatcher(state, opcode)
    if opcode == 1 then
        return handlers[1](state)
    elseif opcode == 2 then
        return handlers[2](state)
    end
end

return dispatcher
"""

    output_path = tmp_path / "guesses.json"
    report = opcode_semantics_guesses(source, top_n=2, output_path=output_path)
    assert output_path.exists()

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data == report

    guesses = report["guesses"]
    assert guesses["1"]["guess"] == "SET/GET"
    assert guesses["2"]["guess"] == "bit ops"
    assert guesses["1"]["confidence"] >= 0.7
    assert guesses["2"]["confidence"] >= 0.8
    assert guesses["1"]["guess_source"] == "heuristic"
    assert "ml_guess" in guesses["1"]
    assert guesses["1"]["ml_training_size"] >= 1


def test_opcode_semantics_obfuscated2_has_nontrivial_guesses(tmp_path):
    pytest.importorskip("luaparser")
    source = Path("Obfuscated2.lua").read_text(encoding="utf-8")
    output_path = tmp_path / "obfuscated2_guesses.json"
    report = opcode_semantics_guesses(source, output_path=output_path)

    assert report["top_n"] <= 30
    assert report["guesses"]
    assert any(entry["guess"] != "unknown" for entry in report["guesses"].values())
    assert output_path.exists()
    # Ensure ML metadata is recorded for at least one opcode.
    assert any("ml_guess" in entry for entry in report["guesses"].values())


def test_opcode_semantics_ml_suggests_for_unknown_opcode():
    pytest.importorskip("luaparser")
    source = """
local helper_band
local helper_push

local handlers = {}

helper_band = function(state)
    return bit32.band(state[1], 255)
end

helper_push = function(state, value)
    table.insert(state, value)
end

handlers[1] = function(state)
    local value = helper_band(state)
    return bit32.band(value, 255)
end

handlers[2] = function(state)
    helper_push(state, 42)
    return state
end

handlers[3] = function(state)
    return helper_band(state)
end

local function dispatcher(state, opcode)
    if opcode == 1 then
        return handlers[1](state)
    elseif opcode == 2 then
        return handlers[2](state)
    elseif opcode == 3 then
        return handlers[3](state)
    end
end

return dispatcher
"""

    report = opcode_semantics_guesses(source, top_n=3, output_path=None)
    guesses = report["guesses"]
    first = guesses["1"]
    second = guesses["2"]
    third = guesses["3"]

    assert first["guess"] == "bit ops"
    assert first["guess_source"] == "heuristic"
    assert second["guess"] == "SET/GET"
    assert second["guess_source"] in {"heuristic", "ml"}
    if second["guess_source"] == "ml":
        assert second["ml_guess"] == "SET/GET"
        assert second.get("ml_metadata_source") == "builtin"

    # Heuristic analysis cannot see into helper_band, but ML should suggest it.
    assert third["guess_source"] == "ml"
    assert third["guess"] == "bit ops"
    assert third["ml_guess"] == "bit ops"
    assert third["ml_confidence"] >= 0.5
    assert third["ml_training_size"] >= 2


def test_opcode_semantics_uses_builtin_ml_metadata():
    pytest.importorskip("luaparser")
    source = """
local handlers = {}
handlers[1] = function(state)
  state.index = state.index + 1
  return state
end

handlers[2] = function(state)
  repeat
    state.index = state.index - 1
    if state.index <= 0 then
      break
    end
  until false
end

local function dispatcher(state, opcode)
  if opcode == 1 then
    return handlers[1](state)
  elseif opcode == 2 then
    return handlers[2](state)
  end
end

return dispatcher
"""

    report = opcode_semantics_guesses(source, top_n=2, output_path=None)
    guesses = report["guesses"]

    first = guesses["1"]
    second = guesses["2"]

    # Builtin metadata should provide enough diversity for the classifier to fire.
    assert "ml_guess" in second
    assert second["guess_source"] == "ml"
    assert second.get("ml_metadata_source") == "builtin"
    assert second["ml_training_size"] >= 2

    # The first opcode can also pick up ML hints but should remain deterministic.
    assert first["ml_training_size"] >= 2


def test_simulate_vm_concatenates_obfuscated_fragments():
    fragments = extract_fragments("Obfuscated2.lua")
    assert len(fragments) > 30

    sample = fragments[38]["text"][:16]
    left, right = sample[:8], sample[8:16]

    program = VMFunction(
        constants=[left, right],
        instructions=[
            VMInstruction("LOADK", a=0, aux={"b_mode": "const", "const_b": left}),
            VMInstruction("LOADK", a=1, aux={"b_mode": "const", "const_b": right}),
            VMInstruction("CONCAT", a=2, b=0, c=1),
            VMInstruction(
                "RETURN",
                a=2,
                b=2,
                aux={"b_mode": "immediate", "immediate_b": 2},
            ),
        ],
        register_count=3,
    )

    result = simulate_vm(program, inputs=[])

    assert result.output == sample
    assert len(result.steps) == 4
    assert result.steps[0].opcode == "LOADK"
    assert result.step(3).opcode == "RETURN"
    assert result.trace_log


def test_simulate_vm_handles_byte_inputs():
    fragments = extract_fragments("Obfuscated2.lua")
    payload = fragments[38]["text"][:16]
    data_bytes = payload.encode("latin-1", errors="ignore")

    def bytes_to_text(data: bytes | bytearray | list[int]) -> str:
        if isinstance(data, (bytes, bytearray)):
            return data.decode("latin-1")
        return "".join(chr(int(ch) & 0xFF) for ch in data)

    program = VMFunction(
        constants=[bytes_to_text],
        instructions=[
            VMInstruction("MOVE", a=1, b=0),
            VMInstruction("LOADK", a=0, aux={"b_mode": "const", "const_b": bytes_to_text}),
            VMInstruction(
                "CALL",
                a=0,
                b=0,
                c=0,
                aux={
                    "b_mode": "immediate",
                    "immediate_b": 2,
                    "c_mode": "immediate",
                    "immediate_c": 2,
                },
            ),
            VMInstruction(
                "RETURN",
                a=0,
                b=0,
                aux={"b_mode": "immediate", "immediate_b": 2},
            ),
        ],
        register_count=3,
        num_params=1,
    )

    result = simulate_vm(program, inputs=[data_bytes])

    assert result.output == payload
    assert any(step.opcode == "CALL" for step in result.steps)
    assert result.steps[-1].result == payload


def test_generate_upcode_table_outputs_docs(tmp_path):
    pytest.importorskip("luaparser")

    source = """
local helpers = {}

helpers[0x10] = function(vm)
    return helperA(vm, 41)
end

    helpers[0x11] = function(vm)
        vm.stack = vm.stack or {}
        vm.stack[1] = (vm.stack[1] or 0) + 1
        return helperB(vm)
    end

    helpers[0x12] = function(vm)
        return helperC(vm, vm.seed or 1)
    end

    local function dispatcher(vm, opcode)
        if opcode == 0x10 then
            return helpers[0x10](vm)
        elseif opcode == 0x11 then
            return helpers[0x11](vm)
        elseif opcode == 0x12 then
            return helpers[0x12](vm)
        end
        return vm
    end

    return({
    helperA = function(self, value)
        return value + 1
    end,
    helperB = function(self)
        return string.byte(self.seed or "A")
    end,
    helperC = function(self, value)
        return value * 2
    end,
    run = dispatcher,
})
"""

    json_path = tmp_path / "upcodes.json"
    md_path = tmp_path / "upcodes.md"
    csv_path = tmp_path / "upcodes.csv"
    html_path = tmp_path / "upcodes.html"

    report = generate_upcode_table(
        source,
        output_json=json_path,
        output_markdown=md_path,
        output_csv=csv_path,
        output_html=html_path,
        top_n=5,
    )

    assert report["entries"]
    assert report["metadata"]["structure"] == "return({...})"
    assert "helperA" in report["metadata"]["top_keys"]
    assert json_path.exists()
    assert md_path.exists()
    assert csv_path.exists()
    assert html_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["metadata"]["structure"] == "return({...})"
    entry = next(entry for entry in data["entries"] if entry["opcode"] == 0x10)
    assert entry["mnemonic"]
    assert entry["operand_types"]["inputs"]
    assert any(sample.get("helper") == "helperA" for sample in entry["sample_usage"])
    assert any(sample.get("line") is not None for sample in entry["sample_usage"])

    fallback_entry = next(entry for entry in data["entries"] if entry["opcode"] == 0x12)
    assert fallback_entry["frequency"] >= 0
    assert fallback_entry["mnemonic"].startswith("OP_")

    md_text = md_path.read_text(encoding="utf-8")
    assert "Detected structure" in md_text
    assert "Opcode 16" in md_text
    assert "helper `helperA`" in md_text

    csv_text = csv_path.read_text(encoding="utf-8")
    assert "opcode,mnemonic" in csv_text.splitlines()[0]
    assert any(line.startswith("16,") for line in csv_text.splitlines()[1:])

    html_text = html_path.read_text(encoding="utf-8")
    assert "<table" in html_text
    assert "helperA" in html_text


def test_generate_upcode_table_records_snapshot(tmp_path):
    manager = SnapshotManager(tmp_path / "snapshot.json")
    manager.reset()

    report = generate_upcode_table(
        "return({ run = function() end })",
        output_json=tmp_path / "json",
        output_markdown=tmp_path / "md",
        snapshot=manager,
    )

    snapshot_file = tmp_path / "snapshot.json"
    assert snapshot_file.exists()
    snapshot_data = json.loads(snapshot_file.read_text(encoding="utf-8"))
    mappings = snapshot_data.get("opcode_mappings", {})
    assert mappings.get("entries") == report["entries"]


def test_generate_upcode_table_fallback_sources(monkeypatch, tmp_path):
    def fake_semantics(src: str, top_n: int = 30, output_path=None):
        return {
            "top_n": top_n,
            "frequencies": [[1, 5], [2, 3]],
            "guesses": {
                "1": {
                    "guess": "math op",
                    "confidence": 0.9,
                    "evidence": "return a + b",
                }
            },
        }

    monkeypatch.setattr("pattern_analyzer.opcode_semantics_guesses", fake_semantics)
    monkeypatch.setattr("pattern_analyzer.find_vm_signatures", lambda src: [])

    helper_report = {
        "helpers": {
            "helperB": {
                "call_sites": [
                    {
                        "opcode": 2,
                        "line": 42,
                        "column": 7,
                        "snippet": "helperB(vm, 3)",
                        "handler_table": "dispatch",
                    }
                ]
            }
        }
    }

    monkeypatch.setattr("pattern_analyzer.helpers_to_opcodes", lambda src, output_path=None: helper_report)

    report = generate_upcode_table("return {}", output_json=tmp_path / "json", output_markdown=tmp_path / "md")

    opcodes = {entry["opcode"]: entry for entry in report["entries"]}
    assert 1 in opcodes and 2 in opcodes
    assert opcodes[1]["semantic"] == "math op"
    assert opcodes[2]["mnemonic"].startswith("OP_")
    assert opcodes[2]["sample_usage"][0]["line"] == 42
    assert report["metadata"]["structure"]

    md_text = Path(report["output_markdown"]).read_text(encoding="utf-8")
    assert "line 42" in md_text


def test_generate_upcode_table_inlines_unique_helpers(monkeypatch, tmp_path):
    def fake_semantics(src: str, top_n: int = 30, output_path=None):
        return {
            "top_n": top_n,
            "frequencies": [[0x33, 4], [0x77, 2]],
            "guesses": {},
        }

    helper_report = {
        "helpers": {
            "singleHelper": {
                "body": "local function singleHelper(a)\n    return a + 1\nend",
                "snippet": "singleHelper(vm, a)",
                "call_sites": [
                    {"opcode": "0x33", "line": 12, "column": 8, "snippet": "ops[0x33] = singleHelper"}
                ],
            },
            "sharedHelper": {
                "body": "local function sharedHelper() return true end",
                "call_sites": [
                    {"opcode": 0x33, "line": 20, "column": 4},
                    {"opcode": 0x77, "line": 28, "column": 9},
                ],
            },
        }
    }

    monkeypatch.setattr("pattern_analyzer.opcode_semantics_guesses", fake_semantics)
    monkeypatch.setattr("pattern_analyzer.find_vm_signatures", lambda src: [])
    monkeypatch.setattr("pattern_analyzer.helpers_to_opcodes", lambda src, output_path=None: helper_report)

    report = generate_upcode_table(
        "return {}",
        output_json=tmp_path / "inline.json",
        output_markdown=tmp_path / "inline.md",
    )

    entries = {entry["opcode"]: entry for entry in report["entries"]}
    assert 0x33 in entries and 0x77 in entries

    inline_entry = entries[0x33]
    inline_info = inline_entry.get("inlined_helper")
    assert inline_info and inline_info["name"] == "singleHelper"
    assert "return a + 1" in inline_info["body"]

    assert "inlined_helper" not in entries[0x77]

    md_text = Path(report["output_markdown"]).read_text(encoding="utf-8")
    assert "Inlined helper" in md_text
    assert "singleHelper" in md_text


def test_generate_upcode_table_handles_semantic_failure(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise RuntimeError("no luaparser")

    monkeypatch.setattr("pattern_analyzer.opcode_semantics_guesses", boom)
    monkeypatch.setattr("pattern_analyzer.find_vm_signatures", lambda src: [])
    monkeypatch.setattr(
        "pattern_analyzer.helpers_to_opcodes",
        lambda src, output_path=None: {
            "helpers": {
                "helper": {
                    "call_sites": [
                        {
                            "opcode": 7,
                            "line": 8,
                            "column": 2,
                            "snippet": "helper(vm)",
                        }
                    ]
                }
            }
        },
    )

    report = generate_upcode_table("return {}", output_json=tmp_path / "json2", output_markdown=tmp_path / "md2")
    entry = next(item for item in report["entries"] if item["opcode"] == 7)
    assert entry["semantic"] == "unknown"
    assert entry["sample_usage"][0]["line"] == 8
    assert report["metadata"].get("structure")


def test_build_vm_cfg_emits_dot_files(tmp_path):
    root_func = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("LOADK", pc=0),
            VMInstruction("JMPIF", pc=1, offset=2),
            VMInstruction("CALL", pc=2),
            VMInstruction("LOADK", pc=3),
            VMInstruction("RETURN", pc=4),
            VMInstruction("LOADK", pc=5),
            VMInstruction("RETURN", pc=6),
        ],
        prototypes=[],
    )

    proto_a = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("LOADK", pc=0),
            VMInstruction("JMP", pc=1, offset=1),
            VMInstruction("LOADK", pc=2),
            VMInstruction("RETURN", pc=3),
        ],
        prototypes=[],
    )

    proto_b = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("LOADK", pc=0),
            VMInstruction("TFORLOOP", pc=1, offset=1),
            VMInstruction("LOADK", pc=2),
            VMInstruction("RETURN", pc=3),
            VMInstruction("RETURN", pc=4),
        ],
        prototypes=[],
    )

    proto_c = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("LOADK", pc=0),
            VMInstruction("RETURN", pc=1),
        ],
        prototypes=[],
    )

    root_func.prototypes = [proto_a, proto_b, proto_c]

    output_dir = tmp_path / "cfg"
    report = build_vm_cfg(root_func, output_dir=output_dir, max_functions=3)

    functions = report["functions"]
    assert len(functions) == 3
    labels = {entry["label"] for entry in functions}
    assert {"root", "root_0", "root_1"}.issubset(labels)

    for entry in functions:
        dot_path = Path(entry["dot_path"])
        assert dot_path.exists()
        content = dot_path.read_text(encoding="utf-8")
        assert "digraph" in content
        assert entry["block_count"] >= 1
        if entry["label"] == "root":
            cfg = entry["cfg"]
            call_blocks = [
                block
                for block in cfg.blocks.values()
                if any(ins.opcode == "CALL" for ins in block.instructions)
            ]
            assert call_blocks, "CALL block should be present"
            call_block = call_blocks[0]
            call_edges = [edge for edge in cfg.edges.get(call_block.index, []) if edge.kind == "call"]
            assert call_edges and call_edges[0].target is not None

            return_edges = [
                edge
                for edges in cfg.edges.values()
                for edge in edges
                if edge.kind in {"return", "tailcall"}
            ]
            assert return_edges, "Return edges should be recorded"
            assert "call" in content
