import json
from textwrap import dedent

from src.tools.parser_tracer import match_handler_patterns
from src.vm.block_recover import (
    DispatcherBlock,
    DispatcherCFG,
    recover_dispatcher_cfg,
    write_dispatcher_cfg,
)


def _block_map(cfg: DispatcherCFG) -> dict[str, DispatcherBlock]:
    return {block.block_id: block for block in cfg.blocks}


def test_recover_dispatcher_cfg_builds_cfg_with_goto() -> None:
    source = dedent(
        """
        local handlers = {}
        ::loop::
        local opcode = stream[ip]
        if opcode == 0 then
            return handler_zero(state)
        elseif opcode == 1 then
            goto slowpath
            return handler_one(state)
        end
        ::slowpath::
        if opcode == 2 then
            return handler_two(state)
        end
        """
    )
    handlers = match_handler_patterns(source)
    cfg = recover_dispatcher_cfg(source, handlers)
    blocks = _block_map(cfg)

    assert cfg.entry == "entry"
    assert "branch_00" in blocks and "branch_01" in blocks
    assert "handler_00" in blocks and "handler_01" in blocks
    assert "label:loop" in blocks and "label:slowpath" in blocks

    branch0 = blocks["branch_00"]
    assert branch0.opcode == 0
    assert "handler_00" in branch0.successors
    assert "branch_01" in branch0.successors

    handler1 = blocks["handler_01"]
    assert handler1.handler == "handler_one"
    assert "label:slowpath" in handler1.successors

    slow_label = blocks["label:slowpath"]
    assert any(successor.startswith("branch_") for successor in slow_label.successors)


def test_recover_dispatcher_cfg_without_handlers() -> None:
    cfg = recover_dispatcher_cfg("", [])
    assert isinstance(cfg, DispatcherCFG)
    assert len(cfg.blocks) == 1
    entry_block = cfg.blocks[0]
    assert entry_block.block_id == "entry"
    assert entry_block.kind == "entry"


def test_recover_dispatcher_cfg_marks_trap_handler() -> None:
    source = dedent(
        """
        local function handler_trap(state)
            error("trap triggered")
        end

        local function handler_safe(state)
            return state
        end

        ::loop::
        local opcode = stream[ip]
        if opcode == 0 then
            return handler_trap(state)
        elseif opcode == 1 then
            goto loop
            return handler_safe(state)
        end
        """
    )
    handlers = match_handler_patterns(source)
    cfg = recover_dispatcher_cfg(source, handlers)
    blocks = _block_map(cfg)

    trap_block = blocks["handler_00"]
    assert trap_block.kind == "trap"
    assert "trap" in trap_block.hints
    assert trap_block.metadata.get("trap_reason") == "error-call"
    assert trap_block.metadata.get("isolated") is True
    assert trap_block.successors == ()

    branch_block = blocks["branch_00"]
    assert branch_block.metadata.get("trap_reason") == "error-call"
    assert any(succ.startswith("branch_01") for succ in branch_block.successors)


def test_recover_dispatcher_cfg_marks_opaque_predicate() -> None:
    source = dedent(
        """
        local function handler_zero(state)
            return state
        end

        local function handler_one(state)
            return state
        end

        ::loop::
        local opcode = stream[ip]
        if opcode == 0 then
            if (flag - flag) ~= 0 then
                goto slowpath
            end
            return handler_zero(state)
        elseif opcode == 1 then
            return handler_one(state)
        end

        ::slowpath::
        return handler_one(state)
        """
    )
    handlers = match_handler_patterns(source)
    cfg = recover_dispatcher_cfg(source, handlers)
    blocks = _block_map(cfg)

    branch_block = blocks["branch_00"]
    assert "opaque-predicate" in branch_block.hints
    assert branch_block.metadata.get("opaque_predicate") == "self-arithmetic predicate"


def test_write_dispatcher_cfg(tmp_path) -> None:
    source = dedent(
        """
        local function handler_zero(state)
            return state
        end

        ::loop::
        local opcode = stream[ip]
        if opcode == 0 then
            return handler_zero(state)
        end
        """
    )
    handlers = match_handler_patterns(source)
    cfg = recover_dispatcher_cfg(source, handlers)

    output_path = write_dispatcher_cfg(cfg, tmp_path, "candidate")
    assert output_path.exists()
    data = json.loads(output_path.read_text())
    assert data["entry"] == "entry"
    assert output_path.parent == tmp_path
