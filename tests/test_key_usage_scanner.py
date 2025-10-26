import hashlib
import json
import re
from pathlib import Path
from typing import Callable, Dict

import pytest

import key_usage_scanner as kus
from key_usage_scanner import (
    ExactUpcodeParityReport,
    ParityMismatchError,
    build_key_candidate_report,
    bruteforce_key_variants,
    clear_transform_cache,
    diff_candidates,
    derive_symbolic_key_constraints,
    discover_transform_order,
    exact_upcode_parity_test,
    prga_candidates,
    probe_prga,
    run_probe_harness,
    scan_key_usage,
)
from utils import byte_diff
from src.decoders.initv4_prga import apply_prga
from src.decoders.lph85 import decode_lph85


REPO_ROOT = Path(__file__).resolve().parents[1]
INITV4_PATH = REPO_ROOT / "initv4.lua"
BOOTSTRAP_SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


def _make_test_key(tag: str, prefix: str = "TEST") -> bytes:
    digest = hashlib.sha256(tag.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}".encode("ascii")


def _hex_literal(data: bytes) -> str:
    return '"' + ''.join(f"\\x{byte:02x}" for byte in data) + '"'


def test_scan_key_usage_obfuscated2_prints_lines(capsys) -> None:
    candidates = scan_key_usage("Obfuscated2.lua")
    xor_lines = sorted({c.line for c in candidates if "xor" in c.name.lower() or c.kind.startswith("bit32")})
    assert xor_lines, "expected XOR related candidates in Obfuscated2.lua"
    print("Key candidate lines:", xor_lines[:5])
    captured = capsys.readouterr()
    assert "Key candidate lines:" in captured.out


def test_build_key_candidate_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    report = build_key_candidate_report(["Obfuscated2.lua"], output)
    assert output.exists()
    data = json.loads(output.read_text())
    assert data == report
    assert all(entry.get("version") == "14.4.2" for entry in data)


def test_probe_prga_known_vectors() -> None:
    data = b"Plaintext"
    key = b"Key"
    results = probe_prga(key, data)
    assert results["rc4_like"] == bytes.fromhex("bbf316e8d940af0ad3")
    assert results["repeating_xor"] == bytes(
        [ord("P") ^ ord("K"), ord("l") ^ ord("e"), ord("a") ^ ord("y"), ord("i") ^ ord("K"),
         ord("n") ^ ord("e"), ord("t") ^ ord("y"), ord("e") ^ ord("K"), ord("x") ^ ord("e"),
         ord("t") ^ ord("y")]
    )
    assert results["lfsr_mask"] == bytes.fromhex("95ae6031e0a4a6fc38")
    assert results["rotate_permute"] == prga_candidates(key)["rotate_permute"](data)
    assert results["sieve_rotate"] == prga_candidates(key)["sieve_rotate"](data)


def test_prga_candidates_produce_expected_variants() -> None:
    key = b"Key"
    candidates = prga_candidates(key)
    assert {"rc4_like", "rotate_permute", "sieve_rotate"}.issubset(candidates)

    data = b"Plaintext"
    outputs = {name: fn(data) for name, fn in candidates.items()}
    assert outputs["rc4_like"] == bytes.fromhex("bbf316e8d940af0ad3")
    assert outputs["rotate_permute"] == bytes.fromhex("5278555cf4872f857c")
    assert outputs["sieve_rotate"] == bytes.fromhex("28a0fd468ad41b2403")


def test_prga_candidates_respect_native_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"Plaintext"
    key = b"Key"
    calls: list[bytes] = []

    class _FakeCipher:
        def __init__(self, key_bytes: bytes) -> None:
            self._key = key_bytes

        def encrypt(self, payload: bytes) -> bytes:
            calls.append(self._key)
            return b"\xAA" * len(payload)

    def _fake_build_arc4_cipher(key_bytes: bytes):
        return _FakeCipher(key_bytes)

    monkeypatch.setattr(kus, "_ARC4_MODULE", object(), raising=False)
    monkeypatch.setattr(kus, "_build_arc4_cipher", _fake_build_arc4_cipher)

    native_outputs = prga_candidates(key, enable_native=True)["rc4_like"](data)
    assert native_outputs == b"\xAA" * len(data)
    assert calls == [key]

    calls.clear()
    python_outputs = prga_candidates(key, enable_native=False)["rc4_like"](data)
    assert python_outputs == kus._rc4_crypt_python(data, key)
    assert calls == []


def test_prga_candidates_native_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"Plaintext"
    key = b"Key"

    def _fake_build_arc4_cipher(key_bytes: bytes):
        return None

    monkeypatch.setattr(kus, "_ARC4_MODULE", object(), raising=False)
    monkeypatch.setattr(kus, "_build_arc4_cipher", _fake_build_arc4_cipher)

    result = prga_candidates(key, enable_native=True)["rc4_like"](data)
    assert result == kus._rc4_crypt_python(data, key)


def test_bruteforce_key_variants_finds_suffix_null() -> None:
    base_key = _make_test_key("bruteforce-base")
    variant_key = base_key + b"\x00"
    plaintext = b"function foo() return 42 end"
    encoded = prga_candidates(variant_key)["repeating_xor"](plaintext)

    results = bruteforce_key_variants(base_key, encoded)

    assert results, "expected at least one brute-force result"
    match = next(
        (
            result
            for result in results
            if result.key_variant == "suffix_null" and result.method == "repeating_xor"
        ),
        None,
    )
    assert match is not None, "suffix_null variant should decode repeating_xor payload"
    assert match.payload == plaintext
    assert "function foo" in match.text


def test_probe_prga_round_trip_and_parity() -> None:
    key = _make_test_key("probe-round-trip")
    plaintext = bytes(range(32))

    encoded = prga_candidates(key)["repeating_xor"](plaintext)
    decoded = probe_prga(key, encoded)["repeating_xor"]

    assert decoded == plaintext

    stages = kus._initv4_pipeline_steps(encoded, key)
    report = exact_upcode_parity_test(encoded, stages["rotate"], key)

    assert report.success is True
    assert report.discovery is not None
    assert tuple(report.discovery.order) == tuple(kus._PARITY_STAGE_ORDER)


def test_symbolic_key_constraints_allow_expected_key() -> None:
    key = _make_test_key("symbolic-allow")
    encoded = bytes(range(1, 33))
    xor_stage = kus._initv4_xor_stage(encoded, key)
    expected = kus._initv4_rotate_stage(xor_stage, key)

    constraints = derive_symbolic_key_constraints(encoded, expected, ("xor", "rotate"))
    assert constraints is not None
    assert constraints.satisfiable()
    assert constraints.is_key_compatible(key)

    other_key = _make_test_key("symbolic-other")
    assert not constraints.is_key_compatible(other_key)


def test_symbolic_key_constraints_detect_impossible_order() -> None:
    key = _make_test_key("symbolic-impossible")
    encoded = bytes(range(16))
    xor_stage = kus._initv4_xor_stage(encoded, key)
    expected = kus._initv4_rotate_stage(xor_stage, key)

    constraints = derive_symbolic_key_constraints(encoded, expected, ("rotate",))
    assert constraints is not None
    assert not constraints.satisfiable()


def test_bruteforce_respects_symbolic_constraints() -> None:
    base_key = _make_test_key("symbolic-brute-base")
    variant_key = base_key + b"\x00"
    plaintext = b"function foo() return 42 end"
    encoded = prga_candidates(variant_key)["repeating_xor"](plaintext)

    constraints = derive_symbolic_key_constraints(encoded, plaintext, ("xor",))
    assert constraints is not None
    assert constraints.satisfiable()
    assert constraints.is_key_compatible(variant_key)
    assert not constraints.is_key_compatible(base_key)

    results = bruteforce_key_variants(base_key, encoded, constraints=constraints)
    assert results and all(result.key_variant != "base" for result in results)


def test_run_probe_harness_filters_lua(tmp_path: Path) -> None:
    clear_text = "function foo() return 42 end"
    key_byte = 0x2A
    encoded = bytes((ord(ch) ^ key_byte) for ch in clear_text)
    sample_path = tmp_path / "payload.bin"
    sample_path.write_bytes(encoded)

    output_dir = tmp_path / "candidates"
    saved = run_probe_harness(sample_path, output_dir=output_dir)

    assert saved, "expected at least one saved candidate"
    assert any(".full." in path.name for path in saved)
    decoded_variants = [path.read_text().lower() for path in saved]
    assert any("function foo() return 42 end" in text for text in decoded_variants)
    metadata_lines = saved[0].read_text().splitlines()[:3]
    assert any(line.startswith("-- emulator validation:") for line in metadata_lines)

    manifest_path = output_dir / "run_manifest.json"
    assert manifest_path.exists(), "run_manifest.json should be created"
    manifest_text = manifest_path.read_text()
    manifest = json.loads(manifest_text)
    assert manifest.get("results_saved"), "manifest should list saved results"
    assert manifest.get("transforms_attempted"), "manifest should record attempts"
    assert manifest.get("keys"), "manifest should contain key hashes"
    assert all("hmac" in entry for entry in manifest["keys"])
    assert "TINY" not in manifest_text, "plaintext key material must not appear"
    hotspots = manifest.get("hotspots")
    assert hotspots, "manifest should include benchmark hotspots"
    categories = {entry.get("category") for entry in hotspots}
    assert "decode_attempt" in categories
    assert "prga_transform" in categories
    assert manifest.get("hotspot_report"), "manifest should include hotspot report"
    native_crypto = manifest.get("native_crypto")
    assert native_crypto, "manifest should record native crypto state"
    assert native_crypto.get("enabled") is False
    assert native_crypto.get("requested") is None


def test_byte_diff_reports_first_difference() -> None:
    result = byte_diff(b"abcdef", b"abxdef")
    assert result["match"] is False
    assert result["index"] == 2
    assert result["a_byte"] == ord("c")
    assert result["b_byte"] == ord("x")


def test_run_probe_harness_prioritises_entropy_fragments(tmp_path: Path) -> None:
    plaintext = b"function bar() return 99 end"
    key_byte = 0x10
    encoded = bytes(byte ^ key_byte for byte in plaintext)
    source = f"return {_hex_literal(encoded)}\n"
    sample_path = tmp_path / "entropy.lua"
    sample_path.write_text(source, encoding="utf-8")

    output_dir = tmp_path / "candidates"
    saved = run_probe_harness(sample_path, output_dir=output_dir, max_results=1)

    assert saved
    path = saved[0]
    assert ".fragment" in path.name
    metadata_lines = path.read_text().splitlines()
    assert any(line.startswith("-- fragment: fragment0000") for line in metadata_lines)


def test_diff_candidates_reports_prefix_and_suffix() -> None:
    left = "function foo() return 1 end"
    right = "--header\n" + left + "\n--footer"
    diff = diff_candidates(left, right)
    assert diff["match"] is False
    assert any("prefix" in suggestion for suggestion in diff["suggestions"])
    assert any("suffix" in suggestion for suggestion in diff["suggestions"])
    non_equal = [op for op in diff["operations"] if op["tag"] != "equal"]
    assert non_equal, "expected non-equal operations"


def test_diff_candidates_detects_whitespace_only_change() -> None:
    a = "function foo()\n  return 1\nend"
    b = "\n" + a + "  \n"
    diff = diff_candidates(a, b)
    assert any("whitespace-only" in suggestion for suggestion in diff["suggestions"])
    assert diff["summary"].startswith("whitespace")


def test_run_probe_harness_snapshot_resume(tmp_path: Path) -> None:
    plaintext = b"function baz() return 7 end"
    key = _make_test_key("snapshot")
    key_text = key.decode("ascii")
    encoded = prga_candidates(key)["repeating_xor"](plaintext)

    sample_path = tmp_path / "payload.bin"
    sample_path.write_bytes(encoded)

    output_dir = tmp_path / "candidates"
    snapshot_path = tmp_path / "snapshot.json"

    saved_first = run_probe_harness(
        sample_path,
        output_dir=output_dir,
        extra_keys=[key],
        snapshot_path=snapshot_path,
    )

    assert saved_first, "expected candidates saved on initial run"
    manifest_first_path = output_dir / "run_manifest.json"
    manifest_first = json.loads(manifest_first_path.read_text())
    assert manifest_first.get("results_saved"), "first run should record saved results"
    assert any(
        entry.get("status") == "saved" for entry in manifest_first.get("transforms_attempted", [])
    )
    assert key_text not in json.dumps(manifest_first)
    snapshot_text = snapshot_path.read_text(encoding="utf-8")
    data = json.loads(snapshot_text)
    assert data.get("prga_attempts"), "snapshot should record attempted jobs"
    assert key_text not in snapshot_text

    saved_second = run_probe_harness(
        sample_path,
        output_dir=output_dir,
        extra_keys=[key],
        snapshot_path=snapshot_path,
        resume=True,
    )

    assert saved_second == []
    manifest_second_path = output_dir / "run_manifest.json"
    manifest_second = json.loads(manifest_second_path.read_text())
    assert not manifest_second.get("results_saved"), "resume run should not save candidates"
    assert not manifest_second.get("transforms_attempted"), "resume run should skip attempts"
    assert key_text not in json.dumps(manifest_second)
    data_after = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert len(data_after.get("prga_attempts", [])) == len(data.get("prga_attempts", []))


def test_run_probe_harness_includes_diff_metadata(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"ignored")

    outputs = {
        "method_a": b"function foo() return 1 end",
        "method_b": b"--pref\nfunction foo() return 1 end",
    }

    def fake_candidates(
        key: bytes, **_ignored: object
    ) -> Dict[str, Callable[[bytes], bytes]]:  # type: ignore[override]
        def make(payload: bytes) -> Callable[[bytes], bytes]:
            return lambda data: payload

        return {name: make(payload) for name, payload in outputs.items()}

    monkeypatch.setattr(kus, "prga_candidates", fake_candidates)

    def fake_iter(extra_keys=None):  # pragma: no cover - deterministic iterator
        yield b"\x00"

    monkeypatch.setattr(kus, "_iter_probe_keys", fake_iter)
    monkeypatch.setattr(kus, "entropy_detector", lambda path: [])

    output_dir = tmp_path / "candidates"
    saved = run_probe_harness(sample, output_dir=output_dir, max_results=4)

    assert len(saved) >= 2
    metadata = saved[1].read_text().splitlines()
    assert any(line.startswith("-- diff vs method_a:") for line in metadata)


def test_run_probe_harness_dedupes_by_sha(tmp_path: Path, monkeypatch) -> None:
    clear_transform_cache()
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"ignored")

    outputs = {
        "method_a": b"function foo() return 1 end",
        "method_b": b"function foo() return 1 end",
    }

    def fake_candidates(
        key: bytes, **_ignored: object
    ) -> Dict[str, Callable[[bytes], bytes]]:  # type: ignore[override]
        def make(payload: bytes) -> Callable[[bytes], bytes]:
            return lambda data: payload

        return {name: make(payload) for name, payload in outputs.items()}

    def fake_iter(extra_keys=None):  # pragma: no cover - deterministic iterator
        yield b"\x00"

    monkeypatch.setattr(kus, "prga_candidates", fake_candidates)
    monkeypatch.setattr(kus, "_iter_probe_keys", fake_iter)
    monkeypatch.setattr(kus, "entropy_detector", lambda path: [])

    output_dir = tmp_path / "out"
    saved = run_probe_harness(sample, output_dir=output_dir, max_results=None, max_workers=1)

    assert len(saved) == 1
    contents = saved[0].read_text()
    assert "candidate generated" in contents


def test_probe_worker_pool_reuses_cached_transform(
    tmp_path: Path, monkeypatch
) -> None:
    clear_transform_cache()
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"payload")

    def fake_iter(extra_keys=None):  # pragma: no cover - deterministic iterator
        yield b"\x01"

    call_count = {"invocations": 0}

    def fake_candidates(
        key: bytes, **_ignored: object
    ) -> Dict[str, Callable[[bytes], bytes]]:  # type: ignore[override]
        def transform(data: bytes) -> bytes:
            call_count["invocations"] += 1
            return b"function cached() return 1 end"

        return {"cached": transform}

    monkeypatch.setattr(kus, "_iter_probe_keys", fake_iter)
    monkeypatch.setattr(kus, "prga_candidates", fake_candidates)
    monkeypatch.setattr(kus, "entropy_detector", lambda path: [])

    first_dir = tmp_path / "out1"
    second_dir = tmp_path / "out2"

    run_probe_harness(sample, output_dir=first_dir, max_results=5)
    assert call_count["invocations"] == 1

    run_probe_harness(sample, output_dir=second_dir, max_results=5)
    assert call_count["invocations"] == 1, "transform should be reused from cache"


def test_exact_upcode_parity_success() -> None:
    key = _make_test_key("parity-success")
    encoded = bytes(range(32))
    stages = kus._initv4_pipeline_steps(encoded, key)
    expected_final = stages["rotate"]

    report = exact_upcode_parity_test(encoded, expected_final, key)

    assert isinstance(report, ExactUpcodeParityReport)
    assert report.success is True
    assert report.stages["rotate"].actual == expected_final
    assert report.stages["permute"].actual == stages["permute"]
    assert report.failure_stage is None
    assert report.discovery is not None
    assert report.discovery.success is True
    assert tuple(report.discovery.order) == tuple(kus._PARITY_STAGE_ORDER)


def test_exact_upcode_parity_reports_rotate_mismatch() -> None:
    key = _make_test_key("parity-rotate")
    encoded = bytes(range(16))
    stages = kus._initv4_pipeline_steps(encoded, key)
    expected_final = bytearray(stages["rotate"])
    expected_final[0] ^= 0xFF

    overrides = {
        "permute": stages["permute"],
        "xor": stages["xor"],
        "rotate": bytes(expected_final),
    }

    with pytest.raises(ParityMismatchError) as excinfo:
        exact_upcode_parity_test(
            encoded,
            bytes(expected_final),
            key,
            expected_stage_outputs=overrides,
        )

    error = excinfo.value
    assert "Stage rotate mismatch" in str(error)
    report = error.report
    assert report.failure_stage == "rotate"
    assert report.stages["rotate"].match is False
    assert report.stages["xor"].match is True
    assert report.discovery is not None
    assert report.discovery.order
    assert "best pipeline guess" in report.failure_message


def test_exact_upcode_parity_reports_perm_mismatch() -> None:
    key = _make_test_key("parity-permute")
    encoded = bytes(range(16))
    stages = kus._initv4_pipeline_steps(encoded, key)
    expected_final = stages["rotate"]
    tampered = bytearray(encoded)
    tampered[0] ^= 0x01

    with pytest.raises(ParityMismatchError) as excinfo:
        exact_upcode_parity_test(bytes(tampered), expected_final, key)

    error = excinfo.value
    assert "Stage permute mismatch" in str(error)
    report = error.report
    assert report.failure_stage == "permute"
    assert report.stages["permute"].diff is not None
    assert report.discovery is not None
    assert report.discovery.order
    assert "best pipeline guess" in report.failure_message


def test_discover_transform_order_finds_perm_xor_rotate() -> None:
    key = _make_test_key("discover-pipeline")
    encoded = bytes(range(32))
    permute_stage = kus._rotating_permute_prga(encoded, key)
    xor_stage = kus._initv4_xor_stage(permute_stage, key)
    expected = kus._initv4_rotate_stage(xor_stage, key)

    result = discover_transform_order(encoded, expected, key)

    assert result.success is True
    assert tuple(result.order) == tuple(kus._PARITY_STAGE_ORDER)
    assert len(result.stages) == 3


def test_discover_transform_order_prefers_rotate_left_when_needed() -> None:
    key = _make_test_key("discover-rotate-left")
    encoded = bytes(range(16))
    permute_stage = kus._rotating_permute_prga(encoded, key)
    xor_stage = kus._initv4_xor_stage(permute_stage, key)
    expected = kus._invert_rotate_stage(xor_stage, key)

    result = discover_transform_order(encoded, expected, key)

    assert result.success is True
    assert tuple(result.order) == ("permute", "xor", "rotate_left")


def _extract_bootstrapper_sample(n_bytes: int = 96) -> bytes:
    if not INITV4_PATH.exists():
        pytest.skip("initv4.lua missing")
    text = INITV4_PATH.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"LPH![!-~]{40,}", text)
    if not match:
        pytest.skip("bootstrapper payload missing")
    decoded = decode_lph85(match.group(0))
    if len(decoded) < n_bytes:
        pytest.skip("bootstrapper sample too short")
    return decoded[:n_bytes]


def test_discover_transform_order_matches_bootstrapper_pipeline() -> None:
    encoded_sample = _extract_bootstrapper_sample()
    key = BOOTSTRAP_SCRIPT_KEY.encode("utf-8")
    expected = apply_prga(encoded_sample, key)

    result = discover_transform_order(encoded_sample, expected, key)

    assert result.success is True
    assert "xor" in result.order
    assert result.order and result.order[-1].startswith("rotate")
    if "permute" in result.order:
        assert result.order.index("permute") <= result.order.index("xor")
