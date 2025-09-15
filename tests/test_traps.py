from trap_detector import TrapDetector


def test_neutralizes_advanced_traps():
    code = (
        "local l = debug.getinfo(1, 'l').currentline\n"
        "local ok, res = pcall(function() return true end, 'x')\n"
        "local f = function() end\n"
        "if string.dump(f) ~= '' then error('bad') end"
    )
    td = TrapDetector()
    cleaned = td.sanitize_code(code)
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
    cleaned = td.sanitize_code(code)
    assert '__nil_index_guard' in cleaned
    assert 'debug_sethook_stub' in cleaned
    assert 'setmetatable_stub' in cleaned
    assert 'xpcall_stub' in cleaned
    assert '[__nil_index_guard()]' in cleaned
    assert 'debug.sethook' not in cleaned
