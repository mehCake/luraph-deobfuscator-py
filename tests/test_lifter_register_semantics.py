from src.lifter.lifter import lift_program


def test_vararg_return_round_trip():
    instructions = [
        {"pc": 0, "mnemonic": "VARARG", "A": 1, "B": 0},
        {"pc": 1, "mnemonic": "RETURN", "A": 0, "B": 0},
    ]

    result = lift_program(instructions, [], {})

    assert "return local_0, ..." in result.lua_source
    final_registers = result.stack_trace[-1]["registers"]
    assert final_registers.get("local_1") == "..."


def test_self_call_resugars_to_method_invocation():
    instructions = [
        {"pc": 0, "mnemonic": "LOADK", "A": 2, "Bx": 1},
        {"pc": 1, "mnemonic": "SELF", "A": 0, "B": 0, "C": 0x100},
        {"pc": 2, "mnemonic": "CALL", "A": 0, "B": 3, "C": 2},
        {"pc": 3, "mnemonic": "RETURN", "A": 0, "B": 2},
    ]
    constants = ["m", "x"]

    result = lift_program(instructions, constants, {})

    assert "local_0:m(\"x\")" in result.lua_source
    call_entries = [row for row in result.ir_entries if row.get("op") == "CALL"]
    assert call_entries and ":m(" in call_entries[0]["lua"]


def test_closure_captures_reported_in_metadata():
    instructions = [
        {"pc": 0, "mnemonic": "SETUPVAL", "A": 0, "B": 0},
        {
            "pc": 1,
            "mnemonic": "CLOSURE",
            "A": 1,
            "Bx": 0,
            "captures": [
                {"type": "upvalue", "index": 0},
                {"type": "register", "index": 1},
            ],
        },
        {"pc": 2, "mnemonic": "RETURN", "A": 1, "B": 2},
    ]

    result = lift_program(instructions, [], {})

    closure_map = result.metadata.get("closure_upvalues", {})
    assert closure_map.get("0") == ["UPVAL0", "local_1"]
    closure_entries = [row for row in result.ir_entries if row.get("op") == "CLOSURE"]
    assert closure_entries and closure_entries[0].get("closure_upvalues") == [
        "UPVAL0",
        "local_1",
    ]


def _table_fixture_instructions(key_index: int) -> list[dict[str, int]]:
    return [
        {"pc": 0, "mnemonic": "GETUPVAL", "A": 0, "B": 0},
        {"pc": 1, "mnemonic": "GETTABLE", "A": 1, "B": 0, "C": 0x100 + key_index},
        {"pc": 2, "mnemonic": "SETTABLE", "A": 0, "B": 0x100 + key_index, "C": 0x101},
        {"pc": 3, "mnemonic": "RETURN", "A": 0, "B": 2},
    ]


def test_table_access_uses_dot_syntax_for_string_keys():
    instructions = _table_fixture_instructions(0)
    constants = ["foo", "value", "bad key"]

    result = lift_program(instructions, constants, {})

    assert "local_1 = local_0.foo  -- GETTABLE" in result.lua_source
    assert "local_0.foo = \"value\"  -- SETTABLE" in result.lua_source


def test_table_access_respects_metatable_flag():
    instructions = _table_fixture_instructions(0)
    constants = ["foo", "value", "bad key"]

    result = lift_program(
        instructions,
        constants,
        {},
        vm_metadata={"lifter": {"has_metatable_flow": True}},
    )

    assert "local_1 = local_0[\"foo\"]  -- GETTABLE" in result.lua_source
    assert "local_0[\"foo\"] = \"value\"  -- SETTABLE" in result.lua_source


def test_table_access_keeps_non_identifier_keys():
    instructions = _table_fixture_instructions(2)
    constants = ["foo", "value", "bad key"]

    result = lift_program(instructions, constants, {})

    assert "local_1 = local_0[\"bad key\"]  -- GETTABLE" in result.lua_source
    assert "local_0[\"bad key\"] = \"value\"  -- SETTABLE" in result.lua_source


def test_tabup_translations_apply_dot_sugar():
    instructions = [
        {"pc": 0, "mnemonic": "GETTABUP", "A": 0, "B": 0, "C": 0x100},
        {"pc": 1, "mnemonic": "SETTABUP", "A": 0, "B": 0x100, "C": 0x101},
        {"pc": 2, "mnemonic": "RETURN", "A": 0, "B": 2},
    ]
    constants = ["foo", "value"]

    result = lift_program(instructions, constants, {})

    assert "local_0 = UPVAL0.foo  -- GETTABUP" in result.lua_source
    assert "UPVAL0.foo = \"value\"  -- SETTABUP" in result.lua_source

    flagged = lift_program(
        instructions,
        constants,
        {},
        vm_metadata={"lifter": {"has_metatable_flow": True}},
    )

    assert "local_0 = UPVAL0[\"foo\"]  -- GETTABUP" in flagged.lua_source
    assert "UPVAL0[\"foo\"] = \"value\"  -- SETTABUP" in flagged.lua_source
