from trap_detector import TrapDetector


def test_neutralizes_advanced_traps():
    code = (
        "local l = debug.getinfo(1, 'l').currentline\n"
        "local ok, res = pcall(function() return true end, 'x')\n"
        "local f = function() end\n"
        "if string.dump(f) ~= '' then error('bad') end"
    )
    td = TrapDetector()
    cleaned = td.sanitize_code(code, remove_noops=True, confirm=True)
    assert 'debug.getinfo' not in cleaned
    assert 'string.dump' not in cleaned
    assert 'debug_getinfo_stub' in cleaned
    assert 'pcall_stub' in cleaned
    assert 'dump_stub' in cleaned
    assert 'pcall(' not in cleaned.replace('pcall_stub', '')


def test_debug_hooks_and_nil_indexers_are_stubbed():
    code = (
        "local t = {}\n"
        "local guard = t[nil]\n"
        "debug.sethook(function() end, 'cr', 1)\n"
        "setmetatable(t, {__gc=function() end})\n"
        "return xpcall(function() return true end, print)"
    )
    td = TrapDetector()
    cleaned = td.sanitize_code(code, remove_noops=True, confirm=True)
    assert '__nil_index_guard' in cleaned
    assert 'debug_sethook_stub' in cleaned
    assert 'setmetatable_stub' in cleaned
    assert 'xpcall_stub' in cleaned
    assert '[__nil_index_guard()]' in cleaned
    assert 'debug.sethook' not in cleaned


def test_detects_noop_helpers_and_loops():
    code = (
        "local function junk()\n"
        "  -- intentionally blank\n"
        "end\n"
        "local function identity(x)\n"
        "  return x\n"
        "end\n"
        "for i = 1, 3 do\n"
        "end\n"
        "for i = 1, 3 do\n"
        "end\n"
    )
    td = TrapDetector()
    cleaned = td.sanitize_code(code, remove_noops=True, confirm=True)
    report = td.noop_report()
    kinds = {entry['kind'] for entry in report}
    assert 'empty_helper' in kinds
    assert 'identity_helper' in kinds
    loop_entries = [entry for entry in report if entry['kind'] == 'junk_loop']
    assert loop_entries
    assert any(item['proof']['duplicate_count'] == 2 for item in loop_entries)
    assert 'for i = 1, 3 do' not in cleaned
    assert 'function junk' not in cleaned
    assert 'function identity' not in cleaned


def test_noop_helper_in_use_is_not_removed():
    code = (
        "local function identity(x)\n"
        "  return x\n"
        "end\n"
        "return identity(42)\n"
    )
    td = TrapDetector()
    cleaned = td.sanitize_code(code, remove_noops=True, confirm=True)
    report = td.noop_report()
    assert 'function identity' in cleaned
    identity = next(entry for entry in report if entry['name'] == 'identity')
    assert identity['proof']['call_count'] == 1
    assert identity['removable'] is False


def test_noop_removal_requires_confirmation():
    code = (
        "local function junk()\n"
        "end\n"
    )
    td = TrapDetector()
    cleaned = td.sanitize_code(code)
    assert 'function junk' in cleaned
    try:
        td.sanitize_code(code, remove_noops=True)
    except ValueError as exc:
        assert "Explicit confirmation" in str(exc)
    else:
        raise AssertionError("Expected ValueError when confirmation missing")
