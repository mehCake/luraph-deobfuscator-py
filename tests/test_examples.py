from pathlib import Path
import re

from constant_reconstructor import ConstantReconstructor
from src.deobfuscator import LuaDeobfuscator
from utils import normalize_whitespace


VM_SCAFFOLD_PATTERNS = (
    re.compile(r"vm_dispatch", re.IGNORECASE),
    re.compile(r"vm_stack", re.IGNORECASE),
    re.compile(r"vm_state", re.IGNORECASE),
    re.compile(r"superflow_bytecode", re.IGNORECASE),
    re.compile(r"LPH_ENCFUNC", re.IGNORECASE),
    re.compile(r"opaque[_\s-]?predicate", re.IGNORECASE),
)


def deobfuscate(path: str) -> str:
    return LuaDeobfuscator().deobfuscate_file(path)


def golden(path: str) -> str:
    name = Path(path).name
    return Path("tests/golden") / f"{name}.out"


def test_example_obfuscated_matches_golden(tmp_path):
    out = deobfuscate("example_obfuscated.lua")
    expected = golden("example_obfuscated.lua").read_text()
    assert out == expected


def test_json_wrapped_matches_golden(tmp_path):
    out = deobfuscate("examples/json_wrapped.lua")
    expected = golden("json_wrapped.lua").read_text()
    assert out == expected


def test_complex_example_matches_golden(tmp_path):
    out = deobfuscate("examples/complex_obfuscated")
    expected = golden("complex_obfuscated").read_text()
    assert normalize_whitespace(out) == normalize_whitespace(expected)


def test_complex_example_outputs_without_vm_scaffolding():
    target = Path("examples/complex_obfuscated")
    paths = [target]
    if target.is_dir():
        paths = sorted(p for p in target.rglob("*") if p.is_file())

    deob = LuaDeobfuscator()
    for src in paths:
        output = deob.deobfuscate_file(str(src))
        assert output.strip(), f"expected non-empty output for {src}"
        for pattern in VM_SCAFFOLD_PATTERNS:
            assert not pattern.search(output), f"unexpected VM scaffold {pattern.pattern} in {src}"


def test_complex_fixture_dynamic_calls_are_reconstructed():
    content = Path("examples/complex_obfuscated").read_text(encoding="utf-8", errors="ignore")
    recon = ConstantReconstructor()
    result = recon.reconstruct(content, None)
    assert result["constants"]["replacements"]
