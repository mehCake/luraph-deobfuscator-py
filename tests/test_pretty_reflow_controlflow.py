from __future__ import annotations

from pathlib import Path

from src.pretty.reflow_controlflow import reflow_file, reflow_pseudo_lua


def test_reflow_removes_redundant_goto() -> None:
    source = """
::L1::
goto L2

::L2::
return 0
""".strip()

    rewritten, stats = reflow_pseudo_lua(source)

    assert "goto L2" not in rewritten
    assert "-- alias L2 -> L1" in rewritten
    assert stats.removed_gotos == 1


def test_reflow_merges_label_aliases() -> None:
    source = """
::A::

::B::
goto B
""".strip()

    rewritten, stats = reflow_pseudo_lua(source)

    assert "-- alias B -> A" in rewritten
    assert "goto A" in rewritten
    assert stats.merged_labels >= 1


def test_reflow_reorders_block_functions() -> None:
    source = """
local function block_4()
    return 4
end

local function block_1()
    return 1
end

local function structured_main()
    block_1()
    block_4()
end
""".strip()

    rewritten, stats = reflow_pseudo_lua(source)

    first_block = rewritten.split("local function block_", 1)[1]
    assert first_block.startswith("1")
    assert stats.reordered_blocks == 1


def test_reflow_dispatcher_sections_sorted_for_v1442() -> None:
    source = """
::handler_10::
return 10

::handler_2::
return 2
""".strip()

    rewritten, stats = reflow_pseudo_lua(source, version_hint="v14.4.2")

    assert rewritten.index("handler_2") < rewritten.index("handler_10")
    assert stats.reordered_dispatchers == 1


def test_reflow_file_creates_backup(tmp_path: Path) -> None:
    input_path = tmp_path / "demo.lua"
    input_path.write_text("::X::\ngoto Y\n\n::Y::\nreturn 1\n", encoding="utf-8")

    result = reflow_file(input_path, output_dir=tmp_path / "out")

    assert result.output_path.exists()
    assert result.backup_path is not None and result.backup_path.exists()
    assert "goto" not in result.text
