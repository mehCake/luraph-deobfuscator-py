from src.pipeline import Context
from src.passes.vm_devirtualize import IRDevirtualizer, run as vm_devirtualize_run
from src.utils_pkg import ast as lua_ast
from src.utils_pkg.ir import IRBasicBlock, IRInstruction, IRModule


def _make_module(
    instructions: list[IRInstruction],
    *,
    blocks: dict[str, IRBasicBlock] | None = None,
    order: list[str] | None = None,
    entry: str = "entry",
    constants: list[object] | None = None,
    prototypes: dict[int, IRModule] | None = None,
) -> IRModule:
    block_map = blocks or {}
    block_order = order or (list(block_map.keys()) if block_map else [])
    return IRModule(
        blocks=block_map,
        order=block_order,
        entry=entry,
        register_types={},
        constants=constants or [],
        instructions=instructions,
        warnings=[],
        bytecode_size=len(instructions),
        prototypes=prototypes or {},
    )


def _render(module: IRModule) -> str:
    chunk, _ = IRDevirtualizer(module, module.constants).lower()
    return lua_ast.to_source(chunk)


def test_ir_devirtualizer_handles_if_else() -> None:
    instructions = [
        IRInstruction(pc=0, opcode="LoadK", args={"dest": 0, "const_value": True}, dest=0),
        IRInstruction(
            pc=1,
            opcode="Test",
            args={"reg": 0, "target": 4, "conditional": "JMPIFNOT"},
        ),
        IRInstruction(pc=2, opcode="LoadK", args={"dest": 1, "const_value": "then"}, dest=1),
        IRInstruction(pc=3, opcode="Jump", args={"target": 5}),
        IRInstruction(pc=4, opcode="LoadK", args={"dest": 1, "const_value": "else"}, dest=1),
        IRInstruction(pc=5, opcode="Return", args={"base": 1, "count": 1}),
    ]
    module = _make_module(instructions)
    source = _render(module)
    assert "if true then" in source
    assert "else" in source
    assert "local R1 = 'then'" in source
    assert "local R1 = 'else'" in source


def test_ir_devirtualizer_builds_while_loops() -> None:
    instructions = [
        IRInstruction(pc=0, opcode="LoadK", args={"dest": 0, "const_value": 0}, dest=0),
        IRInstruction(pc=1, opcode="LoadK", args={"dest": 1, "const_value": 3}, dest=1),
        IRInstruction(
            pc=2,
            opcode="Test",
            args={"op": "LT", "lhs": 0, "rhs": 1, "target": 6, "conditional": "JMPIFNOT"},
        ),
        IRInstruction(pc=3, opcode="LoadK", args={"dest": 2, "const_value": 1}, dest=2),
        IRInstruction(pc=4, opcode="BinOp", args={"op": "ADD", "dest": 0, "lhs": 0, "rhs": 2}, dest=0),
        IRInstruction(pc=5, opcode="Jump", args={"target": 2}),
        IRInstruction(pc=6, opcode="Return", args={"base": 0, "count": 1}),
    ]
    module = _make_module(instructions)
    source = _render(module)
    assert "while 0 < 3 do" in source
    assert "local R2 = 1" in source


def test_ir_devirtualizer_emits_generic_for() -> None:
    instructions = [
        IRInstruction(pc=0, opcode="LoadK", args={"dest": 0, "const_value": "iter"}, dest=0),
        IRInstruction(pc=1, opcode="LoadK", args={"dest": 1, "const_value": "state"}, dest=1),
        IRInstruction(pc=2, opcode="LoadK", args={"dest": 2, "const_value": "seed"}, dest=2),
        IRInstruction(pc=3, opcode="LoadK", args={"dest": 4, "const_value": 0}, dest=4),
        IRInstruction(
            pc=4,
            opcode="TForLoop",
            args={"base": 0, "target": 7, "offset": 0, "nvars": 1},
        ),
        IRInstruction(pc=5, opcode="BinOp", args={"op": "ADD", "dest": 4, "lhs": 4, "rhs": 3}, dest=4),
        IRInstruction(pc=6, opcode="Jump", args={"target": 4}),
        IRInstruction(pc=7, opcode="Return", args={"base": 4, "count": 1}),
    ]
    module = _make_module(instructions)
    source = _render(module)
    assert "for R3 in" in source
    assert "'iter', 'state', 'seed'" in source
    assert "R4 =" in source


def test_ir_devirtualizer_skips_unreachable_blocks() -> None:
    live0 = IRInstruction(pc=0, opcode="LoadK", args={"dest": 0, "const_value": "alive"}, dest=0)
    live1 = IRInstruction(pc=1, opcode="Return", args={"base": 0, "count": 1})
    trap0 = IRInstruction(pc=2, opcode="LoadK", args={"dest": 1, "const_value": "trap"}, dest=1)
    trap1 = IRInstruction(pc=3, opcode="Jump", args={"target": 2})

    entry_block = IRBasicBlock(label="entry", start_pc=0, instructions=[live0, live1], successors=[])
    trap_block = IRBasicBlock(label="trap", start_pc=2, instructions=[trap0, trap1], successors=["trap"])

    module = _make_module(
        [live0, live1, trap0, trap1],
        blocks={"entry": entry_block, "trap": trap_block},
        order=["entry", "trap"],
    )

    devirt = IRDevirtualizer(module, module.constants)
    chunk, metadata = devirt.lower()
    source = lua_ast.to_source(chunk)

    assert "trap" not in source
    assert metadata.get("unreachable_blocks") == 1
    assert metadata.get("eliminated_instructions") == 2
    assert metadata.get("unreachable_pcs") == [2, 3]
    pc_map = metadata.get("pc_mapping")
    assert isinstance(pc_map, list) and any(entry.get("pc") == 0 for entry in pc_map)


def test_ir_devirtualizer_lowers_closures() -> None:
    proto_instructions = [
        IRInstruction(pc=0, opcode="LoadK", args={"dest": 0, "const_value": 42}, dest=0),
        IRInstruction(pc=1, opcode="Return", args={"base": 0, "count": 1}),
    ]
    proto_module = _make_module(proto_instructions, entry="proto")

    main_instructions = [
        IRInstruction(pc=0, opcode="Closure", args={"dest": 0, "proto": 0}, dest=0),
        IRInstruction(pc=1, opcode="Return", args={"base": 0, "count": 1}),
    ]
    module = _make_module(main_instructions, prototypes={0: proto_module})

    chunk, _ = IRDevirtualizer(module, module.constants).lower()
    source = lua_ast.to_source(chunk)

    assert "local function R0()" in source
    assert "local R0 = 42" in source
    assert "return R0" in source


def test_vm_devirtualize_pass_renames_and_formats(tmp_path) -> None:
    instructions = [
        IRInstruction(pc=0, opcode="LoadK", args={"dest": 0, "const_value": 1}, dest=0),
        IRInstruction(pc=1, opcode="LoadK", args={"dest": 1, "const_value": 2}, dest=1),
        IRInstruction(pc=2, opcode="BinOp", args={"op": "ADD", "dest": 2, "lhs": 0, "rhs": 1}, dest=2),
        IRInstruction(pc=3, opcode="Return", args={"base": 2, "count": 1}),
    ]
    module = _make_module(instructions)

    ctx = Context(input_path=tmp_path / "sample.lua", raw_input="", stage_output="")
    ctx.ir_module = module

    metadata = vm_devirtualize_run(ctx)

    assert "local a = 1" in ctx.stage_output
    assert "local b = 2" in ctx.stage_output
    assert "R0" not in ctx.stage_output
    assert metadata["renamed_identifiers"] is True
    assert metadata["renamed_count"] >= 2
    assert ctx.report.variables_renamed == metadata["renamed_count"]
    assert "pc_mapping" in metadata
