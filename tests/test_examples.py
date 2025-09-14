from src.deobfuscator import LuaDeobfuscator


def deobfuscate(path: str) -> str:
    return LuaDeobfuscator().deobfuscate_file(path)


def test_example_obfuscated_decodes_hello_world(tmp_path):
    out = deobfuscate('example_obfuscated.lua')
    assert 'hello world' in out.lower()


def test_complex_example_contains_script_key(tmp_path):
    out = deobfuscate('examples/complex_obfuscated')
    assert 'script_key' in out


def test_json_wrapped_example(tmp_path):
    out = deobfuscate('examples/json_wrapped.lua')
    assert 'script_key' in out
