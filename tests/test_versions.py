import base64
import csv
import gzip
import hmac
import zipfile
import hashlib
import importlib.util
import json
import math
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

import pytest

from utils import benchmark_recorder
from src import main as cli_main

from version_detector import (
    VersionDetector,
    analyze_identifier_frequencies,
    cluster_fragments_by_similarity,
    detect_compressed_fragments,
    detect_embedded_bytecode,
    detect_dangerous_calls,
    detect_bootstrapper_source,
    detect_luraph_header,
    detect_multistage,
    extract_embedded_comments,
    extract_metadata_provenance,
    entropy_detector,
    infer_encoding_order,
    fuzz_vm_behavior,
    extract_fragments,
    generate_run_summary,
    lift_helper_tables_to_modules,
    generate_helper_unit_tests,
    generate_pipeline_documentation,
    normalize_bracket_literals,
    introspect_top_level_table,
    ir_to_lua,
    evaluate_deobfuscation_checklist,
    evaluate_quality_gate,
    _escape_lua_string_body,
    parity_test,
    complete_deobfuscate,
    pipeline_static_rebuild,
    pretty_print_with_mapping,
    reconstruct_text,
    round_trip_test,
    split_functions_from_payload,
    divide_unit_of_work,
    verify_reconstructed_strings,
    PIPELINE_STAGE_DOCS,
    _iter_decoded_fragments,
)
from src import pipeline
from src.deobfuscator import LuaDeobfuscator
from src.vm.emulator import LuraphVM
from src.versions import VersionHandler, decode_constant_pool, get_handler
from src.decoders.initv4_prga import apply_prga
from src.decoders.lph85 import decode_lph85
from src.ir import VMFunction, VMInstruction


def test_detect_version_examples() -> None:
    detector = VersionDetector()
    json_wrapped = Path('examples/json_wrapped.lua').read_text()
    simple = Path('examples/simple_obfuscated or remote for complex_obfuscated').read_text()
    complex_payload = Path('examples/complex_obfuscated').read_text()

    assert detector.detect_version(json_wrapped).name == 'v14.0.2'
    assert detector.detect_version(simple).name == 'v14.1'
    assert detector.detect_version(complex_payload).name == 'luraph_v14_4_initv4'

    deob = LuaDeobfuscator()
    assert deob.detect_version(json_wrapped).name == 'v14.0.2'
    assert deob.detect_version(complex_payload).name == 'luraph_v14_4_initv4'


def _encode_bytes_literal(data: bytes) -> str:
    return '"' + ''.join(f"\\x{byte:02x}" for byte in data) + '"'


def test_escape_lua_string_body_handles_bom() -> None:
    assert _escape_lua_string_body("\ufeff") == r"\xEF\xBB\xBF"
    assert _escape_lua_string_body("\ufeffA") == r"\xEF\xBB\xBFA"
    assert _escape_lua_string_body("\u2028") == r"\xE2\x80\xA8"


def _build_test_key(tag: str, prefix: str = "TEST") -> str:
    digest = hashlib.sha256(tag.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


_BYTECODE_SAMPLE = base64.b64decode(
    "G0x1YVEAGZMNChoKBAQECAAAAAAAAAAAAAAAAAAAAAICAgAAAAEAAAAeAAABAQAAAAMAAAAAAABFQAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


def _fragment_bytes(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "surrogatepass")


def _load_obfuscated2_snapshot() -> Dict[str, Any]:
    snapshot_path = Path("tests/golden/obfuscated2_fragment_snapshot.json")
    return json.loads(snapshot_path.read_text(encoding="utf-8"))


def test_detect_compressed_fragments_zlib(tmp_path: Path) -> None:
    payload = b"local function sample() return 42 end\n"
    compressed = zlib.compress(payload)
    literal = _encode_bytes_literal(compressed)
    source = f"return {literal}\n"
    path = tmp_path / "zlib_fragment.lua"
    path.write_text(source, encoding="utf-8")

    results = detect_compressed_fragments(path)
    zlib_hits = [entry for entry in results if entry.get("compression") == "zlib"]

    assert zlib_hits
    record = zlib_hits[0]
    assert record["success"] is True
    assert record["looks_like_lua"] is True
    assert "local function" in record.get("decoded_preview", "")


def test_detect_compressed_fragments_gzip(tmp_path: Path) -> None:
    payload = b"local data = {1, 2, 3}\nreturn data\n"
    compressed = gzip.compress(payload)
    literal = _encode_bytes_literal(compressed)
    source = f"return {literal}\n"
    path = tmp_path / "gzip_fragment.lua"
    path.write_text(source, encoding="utf-8")

    results = detect_compressed_fragments(path)
    gzip_hits = [entry for entry in results if entry.get("compression") == "gzip"]

    assert gzip_hits
    record = gzip_hits[0]
    assert record["success"] is True
    assert record["looks_like_lua"] is True
    assert "return data" in record.get("decoded_preview", "")


def test_detect_embedded_bytecode(tmp_path: Path) -> None:
    literal = _encode_bytes_literal(_BYTECODE_SAMPLE)
    path = tmp_path / "bytecode.lua"
    path.write_text(f"return {literal}\n", encoding="utf-8")

    results = detect_embedded_bytecode(path)

    assert len(results) == 1
    record = results[0]
    assert record["version"] == "5.1"
    assert record["instructions"] == 2
    assert "LOADK" in record["report"]
    assert "RETURN" in record["report"]


def test_detect_dangerous_calls(tmp_path: Path) -> None:
    source = tmp_path / "danger.lua"
    source.write_text(
        "game:HttpGet('https://example.com')\n" "os.execute('ls')\n" "-- os.execute in comment\n",
        encoding="utf-8",
    )

    result = detect_dangerous_calls(source, context_lines=2)

    assert result["count"] == 2
    findings = result["findings"]
    assert findings[0]["line"] == 1
    assert "game:http" in findings[0]["matches"]
    assert any("http access" == label for label in findings[0]["matches"])
    assert findings[1]["line"] == 2
    assert findings[1]["matches"] == ["os.execute"]
    assert all("--" not in entry["code"] for entry in findings)

    report_path = Path(result["path"])
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Line 1" in report_text
    assert "Line 2" in report_text


def test_detect_multistage_base64_then_xor() -> None:
    plaintext = "function foo() return 42 end"
    key = 0x23
    xored = bytes(ord(ch) ^ key for ch in plaintext)
    encoded = base64.b64encode(xored).decode("ascii")

    fragment = {"text": encoded, "type": "long_quoted", "index": 1}
    result = detect_multistage(fragment)

    pipelines = result["pipelines"]
    assert pipelines, "expected at least one multi-stage pipeline"
    best = pipelines[0]
    stages = [stage["name"] for stage in best["stages"]]
    assert stages[:2] == ["base64", "single_byte_xor"]
    assert "function foo" in best["decoded"]
    assert best["looks_like_lua"] is True


def test_detect_multistage_hex_reverse() -> None:
    plaintext = "local data = {1, 2, 3}"
    reversed_bytes = plaintext.encode("utf-8")[::-1]
    encoded = reversed_bytes.hex()

    fragment = {"text": encoded, "type": "long_quoted", "index": 2}
    result = detect_multistage(fragment)

    pipelines = result["pipelines"]
    assert pipelines, "expected a pipeline for reversed hex payload"
    name_sets = [{stage["name"] for stage in record["stages"]} for record in pipelines]
    assert any("hex" in names and "reverse" in names for names in name_sets)
    decoded_candidates = [record["decoded"] for record in pipelines if {stage["name"] for stage in record["stages"]} >= {"hex", "reverse"}]
    assert any("local data" in decoded for decoded in decoded_candidates)


def test_pipeline_static_rebuild_detects_bytecode(tmp_path: Path) -> None:
    literal = _encode_bytes_literal(_BYTECODE_SAMPLE)
    source = tmp_path / "sample.lua"
    source.write_text(f"return {literal}\n", encoding="utf-8")

    result = pipeline_static_rebuild(source)

    reports = result["bytecode_reports"]
    assert reports
    assert reports[0]["version"] == "5.1"

    output_dir = result["bytecode_output_dir"]
    assert output_dir is not None
    dump_dir = Path(output_dir)
    assert dump_dir.exists()
    dumps = list(dump_dir.glob("*.lua"))
    assert dumps
    dump_text = dumps[0].read_text(encoding="utf-8")
    assert "Decompiled Lua chunk" in dump_text


def test_entropy_detector_ranks_fragments(tmp_path: Path) -> None:
    low_bytes = b"A" * 64
    high_bytes = bytes(range(256)) * 2

    source = (
        f"local low = {_encode_bytes_literal(low_bytes)}\n"
        f"local high = {_encode_bytes_literal(high_bytes)}\n"
    )
    path = tmp_path / "entropy.lua"
    path.write_text(source, encoding="utf-8")

    rankings = entropy_detector(path)

    assert len(rankings) >= 2
    top, bottom = rankings[0], rankings[-1]

    assert top["entropy"] >= bottom["entropy"]
    assert top["classification"] in {"high", "medium"}
    assert bottom["classification"] in {"low", "short"}


def test_cluster_fragments_by_similarity(tmp_path: Path) -> None:
    source = (
        'local a = "function helper(a, b) return a + b end"\n'
        'local b = "function helper(x, y) return x + y end"\n'
        'local c = "local mask = bit32.band(value, 0xff)"\n'
        'local d = "local mask = bit32.band(result, 0xff)"\n'
    )
    path = tmp_path / "cluster.lua"
    path.write_text(source, encoding="utf-8")

    clusters = cluster_fragments_by_similarity(path, min_length=10)

    assert len(clusters) >= 2
    sizes = sorted(cluster["size"] for cluster in clusters)
    assert sizes[-1] >= 2

    helper_cluster = next(cluster for cluster in clusters if "helper" in cluster["suggested_name"])
    assert helper_cluster["size"] == 2
    assert "function helper" in helper_cluster["prototype"]
    assert helper_cluster["macro_hint"]
    assert all("index" in member for member in helper_cluster["members"])
    assert helper_cluster["average_similarity"] >= 0.6


def test_infer_encoding_order_sequential(tmp_path: Path) -> None:
    source = (
        "local parts = {\n"
        '  "A",\n'
        '  "B",\n'
        '  "C",\n'
        "}\n"
        "local function build()\n"
        "  local out = {}\n"
        "  for i = 1, #parts do\n"
        "    out[#out + 1] = parts[i]\n"
        "  end\n"
        "  return table.concat(out)\n"
        "end\n"
    )
    path = tmp_path / "sequential.lua"
    path.write_text(source, encoding="utf-8")

    result = infer_encoding_order(path)

    assert result["strategy"] == "sequential"
    assert result["order"] == [0, 1, 2]


def test_infer_encoding_order_indexed(tmp_path: Path) -> None:
    source = (
        "local fragments = {\n"
        '  "AA",\n'
        '  "BB",\n'
        '  "CC",\n'
        "}\n"
        "local order = {3, 1, 2}\n"
        "local function build()\n"
        "  local buffer = {}\n"
        "  for i = 1, #order do\n"
        "    buffer[#buffer + 1] = fragments[order[i]]\n"
        "  end\n"
        "  return table.concat(buffer)\n"
        "end\n"
    )
    path = tmp_path / "indexed.lua"
    path.write_text(source, encoding="utf-8")

    result = infer_encoding_order(path)

    assert result["strategy"] == "indexed_reassembly"
    assert result["order"] == [2, 0, 1]
    assert any(entry.get("type") == "order_array" for entry in result["evidence"])


def test_extract_embedded_comments(tmp_path: Path) -> None:
    source = (
        "return {\n"
        '  warning = "-- WARNING: Do not modify this loader; manual patching required.",\n'
        '  helper = "Use this helper to decode binary arrays quickly.",\n'
        '  binary = "\\x01\\x02\\xff",\n'
        "}\n"
    )
    path = tmp_path / "strings.lua"
    path.write_text(source, encoding="utf-8")

    output_path = tmp_path / "notes.md"
    result = extract_embedded_comments(path, output_path=output_path)

    assert len(result["notes"]) == 2
    assert str(path) in result["files"]

    content = output_path.read_text(encoding="utf-8")
    assert "WARNING: Do not modify" in content


def test_extract_metadata_provenance(tmp_path: Path) -> None:
    key_hint = _build_test_key("metadata-hint", prefix="TINY")
    sample = (
        "-- This file was protected using Luraph Obfuscator v14.4.2 [https://lura.ph/]\n"
        "-- build at 2023-08-01 12:00:00\n"
        f"local key = \"{key_hint}\"\n"
    )
    path = tmp_path / "metadata.lua"
    path.write_text(sample, encoding="utf-8")

    report = extract_metadata_provenance(path)

    assert report["header"]["version"] == "14.4.2"
    assert report["timestamps"]
    timestamp = report["timestamps"][0]
    assert timestamp["iso"].startswith("2023-08-01T12:00:00")

    hints = report["key_hints"]
    assert hints
    assert hints[0]["preview"].startswith("TINY-")
    assert hints[0]["preview"] != key_hint
    assert len({hint["hash"] for hint in hints}) == len(hints)

    markers = {entry["line"] for entry in report["comment_markers"]}
    assert markers == {1, 2}


def test_detect_version_from_banner_only() -> None:
    detector = VersionDetector()
    sample = "-- Luraph Obfuscator v14.4.1"
    detected = detector.detect(sample)
    assert detected.name == 'luraph_v14_4_initv4'


def test_detect_version_banner_in_json() -> None:
    detector = VersionDetector()
    sample = '{"banner": "Luraph v14.2"}'
    detected = detector.detect(sample, from_json=True)
    assert detected.name == 'luraph_v14_2_json'


def test_v142_pcall_bypass() -> None:
    vm = LuraphVM(bytecode=[["PCALL", 2611], ["RETURN"]])
    handler = get_handler("v14.2")
    handler.process(vm)
    assert vm.state.bytecode[0][1] == 1
    vm.run()  # should not raise


def test_get_handler_unknown() -> None:
    import pytest

    with pytest.raises(KeyError):
        get_handler("v0")


def test_luraph_v142_json_handler_detection() -> None:
    blob = base64.b64encode(b"hello world" * 30).decode()
    sample = (
        "local script_key = script_key or getgenv().script_key\n"
        "local init_fn = function(blob)\n"
        "    return loadstring(blob)()\n"
        "end\n"
        f"local payload = [[{{\"constants\": [\"{blob}\"], \"bytecode\": [1, 2, 3]}}]]\n"
        "return init_fn(payload)\n"
    )

    handler = get_handler("luraph_v14_2_json")
    assert isinstance(handler, VersionHandler)
    assert handler.matches(sample)
    payload = handler.locate_payload(sample)
    assert payload is not None
    raw_constants: Iterable[object] = []
    if payload.data:
        value = payload.data.get("constants")
        if isinstance(value, list):
            raw_constants = value
    decoder = handler.const_decoder()
    assert decoder is not None
    decoded_constants = decode_constant_pool(decoder, raw_constants)
    assert any("hello world" in entry for entry in decoded_constants if isinstance(entry, str))
    assert handler.extract_bytecode(payload) == b"\x01\x02\x03"

    detector = VersionDetector()
    detected = detector.detect(sample)
    assert detected.name == "luraph_v14_2_json"

    deob = LuaDeobfuscator()
    assert deob.detect_version(sample).name == "luraph_v14_2_json"


def test_detect_pass_assigns_initv4_bootstrapper() -> None:
    sample_path = Path('examples/complex_obfuscated')
    text = sample_path.read_text()
    ctx = pipeline.Context(
        input_path=sample_path,
        raw_input=text,
        stage_output=text,
        original_text=text,
        working_text=text,
        deobfuscator=LuaDeobfuscator(),
    )
    ctx.options["confirm_detected_version"] = False
    pipeline._pass_detect(ctx)
    assert ctx.bootstrapper_path is not None
    assert Path(ctx.bootstrapper_path).name == 'initv4.lua'
    assert ctx.report.bootstrapper_used is not None


def test_version_detector_initv4_heuristics_trigger() -> None:
    detector = VersionDetector()
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+,-./:;<=>?@[]^_`{|}~"
    blob = "s8W-" + "!" * 256
    payload_json = json.dumps({"bytecode": [blob], "metadata": {"alphabet": alphabet}})
    script = (
        "local script_key = script_key or \"KeyForInit\"\n"
        "local init_fn = function(blob)\n    return blob\nend\n"
        f"local alphabet = \"{alphabet}\"\n"
        f"local payload = [[{payload_json}]]\n"
        "return init_fn(payload)\n"
    )

    detected = detector.detect(script)
    assert detected.name == "luraph_v14_4_initv4"


def test_detect_luraph_header_obfuscated2() -> None:
    result = detect_luraph_header("Obfuscated2.lua")
    assert result["version"] == "14.4.2"
    assert result["structure"] == "return({...})"
    assert result["top_keys"][:5] == ["XD", "B", "G", "O3", "ND"]
    assert {"Z3", "wD", "FD"}.issubset(result["top_keys"])
    bootstrap = result.get("bootstrapper", {})
    assert bootstrap.get("mode") == "embedded"
    assert bootstrap.get("alphabet_strategy") == "embedded"


def test_detect_bootstrapper_source_external() -> None:
    info = detect_bootstrapper_source("Obfuscated.json")
    assert info["mode"] == "external"
    assert info["bootstrapper"] == "initv4"
    assert info["alphabet_strategy"] == "external_initv4"


def test_detect_bootstrapper_source_embedded_payload() -> None:
    info = detect_bootstrapper_source("Obfuscated2.lua")
    assert info["mode"] == "embedded"
    assert info["alphabet_strategy"] == "embedded"


def test_detect_bootstrapper_source_embedded(tmp_path: Path) -> None:
    sample = tmp_path / "embedded.lua"
    sample.write_text(
        "local alphabet = \"0123456789ABCDEF\"\nloadstring('return 1')\n",
        encoding="utf-8",
    )

    info = detect_bootstrapper_source(sample)
    assert info["mode"] == "embedded"
    assert info["alphabet_strategy"] == "embedded"


def test_extract_fragments_bracket_offsets() -> None:
    text = Path("Obfuscated2.lua").read_text(encoding="utf-8", errors="ignore")
    fragments = extract_fragments("Obfuscated2.lua")

    assert fragments == sorted(fragments, key=lambda frag: frag["start"])  # preserves order

    bracket_fragments = [frag for frag in fragments if frag["type"] == "long_bracket"]
    assert bracket_fragments, "expected at least one long bracket fragment"

    for fragment in bracket_fragments:
        start = fragment["start"]
        end = fragment["end"]
        snippet = fragment["text"]
        assert text[start:end] == snippet


def test_extract_fragments_bracket_equals(tmp_path: Path) -> None:
    source = tmp_path / "brackets.lua"
    source.write_text(
        "local data = [==[chunk with ]=] marker]==]\n",
        encoding="utf-8",
    )

    fragments = extract_fragments(source)
    bracket_fragments = [frag for frag in fragments if frag["type"] == "long_bracket"]

    assert len(bracket_fragments) == 1
    bracket = bracket_fragments[0]
    assert bracket["text"].startswith("[==[")
    assert bracket["equals"] == 2


def test_reconstruct_text_obfuscated2_parses() -> None:
    import pytest

    fragments = extract_fragments("Obfuscated2.lua")
    reconstructed = reconstruct_text(fragments)

    assert reconstructed

    stripped = reconstructed.lstrip()
    if not stripped.startswith(("return", "local", "function", "do")):
        pytest.skip("reconstructed payload is not raw Lua source")

    luaparser = pytest.importorskip("luaparser")
    from luaparser import ast

    parsed = ast.parse(reconstructed)
    assert parsed is not None


def test_normalize_bracket_literals_reduces_delimiters() -> None:
    text = "return [==[value]==]\n"

    normalized, stats = normalize_bracket_literals(text)

    assert normalized == "return [[value]]\n"
    assert stats["total"] == 1
    assert stats["normalized"] == 1
    assert stats["reduced"] == 1
    assert stats["increased"] == 0


def test_normalize_bracket_literals_preserves_required_level() -> None:
    text = "return [=[value ]] chunk]=]\n"

    normalized, stats = normalize_bracket_literals(text)

    assert normalized == text
    assert stats["total"] == 1
    assert stats["normalized"] == 0
    assert stats["unchanged"] == 1


def test_pipeline_static_rebuild_generates_output(tmp_path: Path) -> None:
    source = tmp_path / "payload.lua"
    source.write_text(
        (
            "return 'local value = 0x10\\n' .. 'local flag = 0b11\\n' .. [[function main()\n"
            "    local message = \"ready\"\n    return message\nend]]\n"
        ),
        encoding="utf-8",
    )

    manifest_path = tmp_path / "run_manifest.json"
    manifest_path.write_text(json.dumps({"attempts": []}), encoding="utf-8")

    result = pipeline_static_rebuild(source)
    output_path = Path(result["output_path"])

    assert output_path.exists()
    contents = output_path.read_text(encoding="utf-8")
    assert "local value = 16" in contents
    assert "local flag = 3" in contents
    assert contents.endswith("\n")

    assert not result["boundary_mismatch"]
    boundary_file = Path(result["diff_report_path"])
    assert boundary_file.exists()

    diff_payload = json.loads(boundary_file.read_text(encoding="utf-8"))
    assert diff_payload["reordered"] is False
    assert diff_payload["boundaries"], "expected recorded boundaries"

    verification = result["string_verification"]
    assert verification["checked"] >= 2

    bracket_stats = result["bracket_normalization"]
    assert isinstance(bracket_stats, dict)
    assert bracket_stats["total"] >= 0

    mapping_path = Path(result["numeric_mapping_path"])
    assert mapping_path.exists()
    mapping_payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    mappings = mapping_payload["mappings"]
    assert mappings == result["numeric_literal_map"]
    literal_pairs = {(entry["original"], entry["normalized"]) for entry in mappings}
    assert ("0x10", "16") in literal_pairs
    assert ("0b11", "3") in literal_pairs

    fragment_dump = Path(result["fragment_dump_path"])
    assert fragment_dump.exists()
    fragment_payload = json.loads(fragment_dump.read_text(encoding="utf-8"))
    assert fragment_payload["count"] == len(fragment_payload["fragments"])
    assert fragment_payload["count"] >= 1
    assert all("escaped" in entry for entry in fragment_payload["fragments"])

    evidence_path = Path(result["evidence_archive_path"])
    assert evidence_path.exists()
    included_labels = {entry["label"] for entry in result["evidence_included"]}
    assert {"original", "fragments", "deobfuscated", "mapping"}.issubset(
        included_labels
    )
    assert "original" not in result["evidence_missing"]
    assert "license_audit" in included_labels
    assert "dangerous_calls" in included_labels

    with zipfile.ZipFile(evidence_path) as archive:
        names = set(archive.namelist())
    assert f"original/{source.name}" in names
    assert f"fragments/{fragment_dump.name}" in names
    assert f"deobfuscated/{output_path.name}" in names
    assert f"mapping/{mapping_path.name}" in names
    assert any(name.startswith("upcodes/") for name in names)
    assert any(name.startswith("run_manifest/") for name in names)
    assert any(name.startswith("license_audit/") for name in names)
    assert any(name.startswith("dangerous_calls/") for name in names)

    license_info = result["license_audit"]
    license_json = Path(license_info["report_path"])
    license_text = Path(license_info["text_report_path"])
    assert license_json.exists()
    assert license_text.exists()
    payload = json.loads(license_json.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == len(payload["dependencies"])

    dangerous_calls = result["dangerous_calls"]
    assert dangerous_calls["count"] == 0
    danger_path = Path(dangerous_calls["path"])
    assert result["dangerous_calls_path"] == dangerous_calls["path"]
    assert danger_path.exists()
    content = danger_path.read_text(encoding="utf-8")
    assert "No dangerous call patterns" in content


def test_pipeline_static_rebuild_preserves_fragment_order(tmp_path: Path) -> None:
    original = Path("Obfuscated2.lua").read_text(encoding="utf-8", errors="ignore")
    sample = tmp_path / "Obfuscated2.lua"
    sample.write_text(original, encoding="utf-8")

    result = pipeline_static_rebuild(sample)
    boundary_report = result["boundary_report"]

    assert boundary_report == sorted(
        boundary_report, key=lambda entry: (entry["original_start"], entry["original_end"])
    )
    for idx in range(1, len(boundary_report)):
        prev = boundary_report[idx - 1]
        curr = boundary_report[idx]
        assert prev["output_end"] <= curr["output_start"]

    assert not result["boundary_mismatch"]
    assert result["string_verification"]["checked"] > 0


def test_complete_deobfuscate_runs_pipeline(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")

    source = tmp_path / "complete.lua"
    source.write_text(
        "return({\n"
        "  foo = function()\n"
        "    return 'payload'\n"
        "  end,\n"
        "  bar = function(value)\n"
        "    return value + 1\n"
        "  end,\n"
        "})\n",
        encoding="utf-8",
    )

    mapping_file = tmp_path / "mapping.json"
    mapping_file.write_text(
        json.dumps({"foo": "decoded_foo", "bar": "decoded_bar"}),
        encoding="utf-8",
    )

    result = complete_deobfuscate(
        source,
        key=_build_test_key("complete-deob", prefix="TINY"),
        confirm_owner=True,
        confirm_voluntary_key=True,
        mapping_path=mapping_file,
        parity_fragments=(),
    )

    artifacts = result["artifacts"]
    final_path = Path(artifacts["final_output"])
    assert final_path.exists()

    opcodes_md = artifacts.get("opcodes_markdown")
    if opcodes_md:
        assert Path(opcodes_md).exists()

    evidence_path = artifacts.get("evidence")
    if evidence_path:
        assert Path(evidence_path).exists()

    score = result.get("completeness_score")
    assert score is None or isinstance(score, float)

    confirmation = result.get("usage_confirmation", {})
    assert isinstance(confirmation.get("entries", 0), int)


def test_fragment_rebuild_handles_quotes_and_brackets(tmp_path: Path) -> None:
    source = (
        "local header = 'line1\\n' .. \"line2\\t\" .. [=[nested]=] .. [[done]]\n"
        "return header"
    )
    path = tmp_path / "mixed.lua"
    path.write_text(source, encoding="utf-8")

    fragments = extract_fragments(path)
    fragment_types = [fragment["type"] for fragment in fragments]
    assert fragment_types.count("long_quoted") == 2
    assert fragment_types.count("long_bracket") == 2

    rebuild = pipeline_static_rebuild(path, output_path=tmp_path / "rebuilt.lua")
    rebuilt_path = Path(rebuild["output_path"])
    rebuilt_text = rebuilt_path.read_text(encoding="utf-8")

    assert "line1" in rebuilt_text
    assert "line2\t" in rebuilt_text
    assert "nested" in rebuilt_text and "done" in rebuilt_text

    verification = rebuild["string_verification"]
    assert verification["checked"] >= 2

    bracket_stats = rebuild["bracket_normalization"]
    assert bracket_stats["total"] >= 0
    assert bracket_stats["normalized"] >= 0

    mapping = rebuild["numeric_literal_map"]
    assert isinstance(mapping, list)


def test_pipeline_static_rebuild_reports_unicode(tmp_path: Path) -> None:
    source = tmp_path / "unicode.lua"
    source.write_text(
        (
            "local combined = \"\\u{FEFF}\\0\" .. [[\ufeff]] .. "
            "\"\\u{0041}\\u{030A}\" .. '\\x01' .. \"\\n\"\n"
            "return combined\n"
        ),
        encoding="utf-8",
    )

    rebuild = pipeline_static_rebuild(source)

    report = rebuild["unicode_report"]
    assert report["bom_count"] == 2
    assert report["control_count"] >= 2
    assert report["samples"], "expected unicode samples"

    escaped_values = {
        occurrence["escaped"]
        for sample in report["samples"]
        for occurrence in sample["occurrences"]
    }
    assert "\\xEF\\xBB\\xBF" in escaped_values
    assert "\\x00" in escaped_values

    output_path = Path(rebuild["output_path"])
    text = output_path.read_text(encoding="utf-8")
    assert "\u00C5" in text

    fragment_dump = Path(rebuild["fragment_dump_path"])
    payload = json.loads(fragment_dump.read_text(encoding="utf-8"))
    assert all("escaped" in entry for entry in payload["fragments"])


def test_pipeline_static_rebuild_records_fingerprints(tmp_path: Path) -> None:
    source = tmp_path / "luraph.lua"
    source.write_text(
        (
            "return '-- This file was protected using Luraph Obfuscator v14.4.2 [https://lura.ph/]\\n' .."
            " 'local function helper()\\n    return string.byte(\\'A\\') + bit32.bxor(1, 2)\\nend\\n' .."
            " 'return ({ XD = helper, PRGA = function(key, data) return data end })\\n'"
        ),
        encoding="utf-8",
    )

    rebuild = pipeline_static_rebuild(source)
    fingerprint = rebuild["fingerprint_report"]

    assert fingerprint["fingerprints"], "expected fingerprint entries"
    entry = fingerprint["fingerprints"][0]
    assert entry["version"] == "14.4.2"
    assert entry["feature_counts"]["bit32_ops"] >= 1
    path = Path(fingerprint["path"])
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["fingerprints"], "fingerprints.json should contain entries"


def test_pipeline_static_rebuild_records_history(tmp_path: Path) -> None:
    source = tmp_path / "sample.lua"
    output = tmp_path / "reconstructed.lua"

    source.write_text("return 'first'\n", encoding="utf-8")
    first = pipeline_static_rebuild(source, output_path=output)

    history_dir = Path(first["history_dir"])
    first_entry = Path(first["history_entry_path"])

    assert history_dir.exists()
    assert first_entry.exists()
    assert first["history_previous_path"] is None
    assert first["history_diff_path"] is None

    source.write_text("return 'second'\n", encoding="utf-8")
    second = pipeline_static_rebuild(source, output_path=output)

    second_entry = Path(second["history_entry_path"])
    diff_path = Path(second["history_diff_path"])

    assert second_entry.exists()
    assert diff_path.exists()
    assert Path(second["history_previous_path"]) == first_entry

    diff_text = diff_path.read_text(encoding="utf-8")
    assert "second" in diff_text

    diff_summary = second["history_diff_summary"]
    assert diff_summary is not None
    assert diff_summary["added"] >= 1


def _write_manifest(path: Path) -> None:
    payload = {
        "timestamp": "2024-01-01T00:00:00Z",
        "git_commit": "deadbeef",
        "keys": [{"ref": "k0000", "hmac": "aa", "length": 4}],
        "transforms_attempted": [],
        "results_saved": [],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_evaluate_deobfuscation_checklist_passes(tmp_path: Path) -> None:
    source = tmp_path / "payload.lua"
    source.write_text(
        (
            "local part = 'foo'\n"
            "local body = [[bar]]\n"
            "return {\n"
            "    main = function()\n"
            "        return part .. body\n"
            "    end,\n"
            "    helper = function(value)\n"
            "        return value\n"
            "    end,\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    rebuild = pipeline_static_rebuild(source)
    reconstructed = Path(rebuild["output_path"])
    introspect_top_level_table(reconstructed)

    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(
        json.dumps({"main": "entry_point", "helper": "support_helper"}),
        encoding="utf-8",
    )

    upcodes_path = tmp_path / "upcodes.json"
    upcodes_path.write_text(
        json.dumps(
            {
                "entries": [
                    {"opcode": 1, "mnemonic": "OP_1"},
                    {"opcode": 2, "semantic": "UNKNOWN"},
                ]
            }
        ),
        encoding="utf-8",
    )

    manifest_path = tmp_path / "run_manifest.json"
    _write_manifest(manifest_path)

    checklist = evaluate_deobfuscation_checklist(
        source,
        reconstructed_path=reconstructed,
        fragment_dump_path=Path(rebuild["fragment_dump_path"]),
        mapping_path=mapping_path,
        upcodes_path=upcodes_path,
        parity_reports=[{"match": True}],
        manifest_path=manifest_path,
        top_level_path=Path(str(reconstructed) + ".top_level.json"),
    )

    assert checklist["passed"] is True
    assert all(entry["passed"] for entry in checklist["checks"])

    mapping_summary = checklist.get("mapping_summary")
    assert isinstance(mapping_summary, Mapping)
    assert mapping_summary["path"] == str(mapping_path)
    assert mapping_summary["high_confidence"] is True
    assert mapping_summary["functions_total"] == 2
    assert mapping_summary["functions_renamed"] == 2
    assert not mapping_summary["lock_present"]

    completeness = checklist["completeness"]
    assert math.isclose(completeness["score"], 1.0, rel_tol=1e-6)
    components = completeness["components"]
    assert components["fragments_fraction"] == pytest.approx(1.0)
    assert components["opcodes_fraction"] == pytest.approx(1.0)
    assert components["parity_rate"] == pytest.approx(1.0)
    assert components["runtime_component"] == pytest.approx(1.0)

    # Trigger lockfile creation and ensure subsequent runs reuse it.
    lock_result = evaluate_deobfuscation_checklist(
        source,
        reconstructed_path=reconstructed,
        fragment_dump_path=Path(rebuild["fragment_dump_path"]),
        mapping_path=mapping_path,
        upcodes_path=upcodes_path,
        parity_reports=[{"match": True}],
        manifest_path=manifest_path,
        top_level_path=Path(str(reconstructed) + ".top_level.json"),
        write_lock_if_high_confidence=True,
    )

    lock_summary = lock_result["mapping_summary"]
    assert lock_summary["lock_present"] is True
    lock_path = Path(lock_summary["lock_path"])
    assert lock_path.exists()
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    assert payload["high_confidence"] is True
    assert "TINY" not in lock_path.read_text(encoding="utf-8")

    follow_up = evaluate_deobfuscation_checklist(
        source,
        reconstructed_path=reconstructed,
        fragment_dump_path=Path(rebuild["fragment_dump_path"]),
        mapping_path=lock_path,
        upcodes_path=upcodes_path,
        parity_reports=[{"match": True}],
        manifest_path=manifest_path,
        top_level_path=Path(str(reconstructed) + ".top_level.json"),
    )

    follow_summary = follow_up["mapping_summary"]
    assert follow_summary["lock_exists"] is True


def test_evaluate_deobfuscation_checklist_reports_missing_rename(tmp_path: Path) -> None:
    source = tmp_path / "payload.lua"
    source.write_text(
        "return { main = function() return 1 end, helper = function() return 2 end }\n",
        encoding="utf-8",
    )

    rebuild = pipeline_static_rebuild(source)
    reconstructed = Path(rebuild["output_path"])
    introspect_top_level_table(reconstructed)

    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(json.dumps({"helper": "support"}), encoding="utf-8")

    manifest_path = tmp_path / "run_manifest.json"
    _write_manifest(manifest_path)

    upcodes_path = tmp_path / "upcodes.json"
    upcodes_path.write_text(
        json.dumps({"entries": [{"opcode": 1, "mnemonic": "OP_1"}]}),
        encoding="utf-8",
    )

    checklist = evaluate_deobfuscation_checklist(
        source,
        reconstructed_path=reconstructed,
        fragment_dump_path=Path(rebuild["fragment_dump_path"]),
        mapping_path=mapping_path,
        upcodes_path=upcodes_path,
        parity_reports=[{"match": True}],
        manifest_path=manifest_path,
        top_level_path=Path(str(reconstructed) + ".top_level.json"),
    )

    assert checklist["passed"] is False
    renamed = next(
        entry for entry in checklist["checks"] if entry["name"] == "top_level_functions_renamed"
    )
    assert renamed["detail"]["missing"] == ["main"]

    mapping_summary = checklist["mapping_summary"]
    assert mapping_summary["high_confidence"] is False
    assert mapping_summary["missing"] == ["main"]

    completeness = checklist["completeness"]
    assert isinstance(completeness["score"], float)


def test_evaluate_deobfuscation_checklist_detects_key_leak(tmp_path: Path) -> None:
    source = tmp_path / "payload.lua"
    source.write_text("return { main = function() return 1 end }\n", encoding="utf-8")

    rebuild = pipeline_static_rebuild(source)
    reconstructed = Path(rebuild["output_path"])
    introspect_top_level_table(reconstructed)

    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(json.dumps({"main": "entry"}), encoding="utf-8")

    manifest_path = tmp_path / "run_manifest.json"
    manifest_path.write_text(
        json.dumps({"keys": [{"ref": "k0000", "script_key": "TINY-EXPOSED"}]}),
        encoding="utf-8",
    )

    upcodes_path = tmp_path / "upcodes.json"
    upcodes_path.write_text(
        json.dumps({"entries": [{"opcode": 1, "mnemonic": "OP_1"}]}),
        encoding="utf-8",
    )

    checklist = evaluate_deobfuscation_checklist(
        source,
        reconstructed_path=reconstructed,
        fragment_dump_path=Path(rebuild["fragment_dump_path"]),
        mapping_path=mapping_path,
        parity_reports=[{"match": True}],
        manifest_path=manifest_path,
        upcodes_path=upcodes_path,
        top_level_path=Path(str(reconstructed) + ".top_level.json"),
    )

    mapping_summary = checklist["mapping_summary"]
    assert mapping_summary["runtime_flagged"] in (0, None)

    completeness = checklist["completeness"]
    assert "runtime_component" in completeness["components"]

    key_check = next(
        entry for entry in checklist["checks"] if entry["name"] == "key_material_not_saved"
    )
    assert key_check["passed"] is False
    assert any("potential key" in violation for violation in key_check["detail"]["violations"])


def test_confidence_history_tracks_timeline(tmp_path: Path) -> None:
    source = tmp_path / "payload.lua"
    source.write_text(
        (
            "return {\n"
            "    main = function() return 1 end,\n"
            "    helper = function() return 2 end,\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    rebuild = pipeline_static_rebuild(source)
    reconstructed = Path(rebuild["output_path"])
    introspect_top_level_table(reconstructed)

    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(
        json.dumps({"main": "entry", "helper": "support"}), encoding="utf-8"
    )

    manifest_path = tmp_path / "run_manifest.json"
    _write_manifest(manifest_path)

    upcodes_path = tmp_path / "upcodes.json"

    def _run_with_conf(conf: float, mnemonic: str = "OP_1") -> Mapping[str, object]:
        upcodes_path.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "opcode": 1,
                            "mnemonic": mnemonic,
                            "confidence": conf,
                            "semantic": "MOVE",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return evaluate_deobfuscation_checklist(
            source,
            reconstructed_path=reconstructed,
            fragment_dump_path=Path(rebuild["fragment_dump_path"]),
            mapping_path=mapping_path,
            upcodes_path=upcodes_path,
            parity_reports=[{"match": True}],
            manifest_path=manifest_path,
            top_level_path=Path(str(reconstructed) + ".top_level.json"),
        )

    first = _run_with_conf(0.25)
    history_info = first.get("confidence_history")
    assert history_info is not None
    history_path = Path(history_info["path"])
    assert history_path.exists()

    payload = json.loads(history_path.read_text(encoding="utf-8"))
    timeline = payload.get("timeline", {})
    assert "1" in timeline
    first_run_id = history_info.get("run_id")
    assert first_run_id is not None
    first_entries = [
        entry for entry in timeline["1"] if entry.get("run_id") == first_run_id
    ]
    assert first_entries, "expected run id to appear in timeline"
    first_entry = first_entries[0]
    assert pytest.approx(first_entry.get("confidence", 0.0), rel=1e-6) == 0.25

    second = _run_with_conf(0.75, mnemonic="OP_MOVE")
    second_info = second.get("confidence_history")
    assert second_info is not None
    payload_updated = json.loads(history_path.read_text(encoding="utf-8"))
    timeline_updated = payload_updated["timeline"]["1"]
    assert len(timeline_updated) >= len(timeline["1"])
    second_run_id = second_info.get("run_id")
    assert second_run_id is not None
    matching = [
        entry for entry in timeline_updated if entry.get("run_id") == second_run_id
    ]
    assert matching, "expected updated run id in timeline"
    latest = matching[0]
    assert pytest.approx(latest.get("confidence", 0.0), rel=1e-6) == 0.75
    if latest.get("delta") is not None:
        assert latest["delta"] >= 0


def _make_quality_checklist(score: float, *, parity_total: int, parity_passed: int) -> Dict[str, object]:
    return {
        "completeness": {"score": score},
        "checks": [
            {
                "name": "parity_tests_passed",
                "passed": parity_total > 0 and parity_passed == parity_total,
                "detail": {"total": parity_total, "passed": parity_passed},
            }
        ],
    }


def test_evaluate_quality_gate_passes_with_threshold() -> None:
    checklist = _make_quality_checklist(0.92, parity_total=3, parity_passed=3)

    result = evaluate_quality_gate(checklist, threshold=0.9)

    assert result["passed"] is True
    assert pytest.approx(result["score"], rel=1e-6) == 0.92
    assert result["parity"]["ok"] is True


def test_evaluate_quality_gate_fails_below_threshold() -> None:
    checklist = _make_quality_checklist(0.6, parity_total=2, parity_passed=2)

    result = evaluate_quality_gate(checklist, threshold=0.75)

    assert result["passed"] is False
    assert any("below threshold" in failure for failure in result["failures"])


def test_evaluate_quality_gate_requires_parity_by_default() -> None:
    checklist = _make_quality_checklist(0.95, parity_total=0, parity_passed=0)

    result = evaluate_quality_gate(checklist)

    assert result["passed"] is False
    assert any("parity" in failure for failure in result["failures"])


def test_evaluate_quality_gate_allows_missing_parity_when_disabled() -> None:
    checklist = _make_quality_checklist(0.88, parity_total=0, parity_passed=0)

    result = evaluate_quality_gate(checklist, threshold=0.85, require_parity=False)

    assert result["passed"] is True
    assert result["parity"]["ok"] is True


def test_generate_pipeline_documentation(tmp_path: Path) -> None:
    output_path = tmp_path / "PIPELINE.md"
    generated_path = generate_pipeline_documentation(output_path)

    assert generated_path == output_path
    assert output_path.exists()

    contents = output_path.read_text(encoding="utf-8")
    assert contents.startswith("# Deobfuscation Pipeline")
    assert "Stage overview" in contents
    assert "Runtime-only guidance" in contents

    for stage in PIPELINE_STAGE_DOCS:
        assert stage.name in contents
        assert stage.function in contents


def test_generate_run_summary(tmp_path: Path) -> None:
    class DummyReport:
        def __init__(self) -> None:
            self.version_detected = "v14.4.2"
            self.blob_count = 3
            self.decoded_bytes = 1024
            self.unknown_opcodes = [7, 12]
            self.warnings = ["runtime parity mismatch"]
            self.errors: list[str] = []

        def to_json(self) -> Dict[str, Any]:
            return {
                "version_detected": self.version_detected,
                "blob_count": self.blob_count,
                "decoded_bytes": self.decoded_bytes,
                "unknown_opcodes": list(self.unknown_opcodes),
                "warnings": list(self.warnings),
                "errors": list(self.errors),
            }

    checklist = {
        "completeness": {
            "score": 0.875,
            "components": {
                "fragments_fraction": 1.0,
                "opcodes_fraction": 0.75,
                "parity_rate": 0.5,
                "runtime_component": 1.0,
            },
            "inputs": {
                "fragments": {"processed": 12, "expected": 12},
                "opcodes": {"total": 16, "named": 12, "unmapped": [7, 12]},
                "parity": {"total": 4, "passed": 2},
                "runtime": {"flagged": 1, "total": 3, "source": "mapping.json"},
            },
        },
        "checks": [
            {
                "name": "upcodes_mapped",
                "passed": False,
                "detail": {"unmapped": [7, 12]},
            }
        ],
    }

    extras = {"dangerous_calls": {"count": 2, "path": "dangerous_calls.txt"}}

    summary_path = generate_run_summary(
        tmp_path / "SUMMARY.md",
        source="Obfuscated2.lua",
        report=DummyReport(),
        checklist=checklist,
        extras=extras,
    )

    text = summary_path.read_text(encoding="utf-8")
    assert "Deobfuscation Summary" in text
    assert "Version detected" in text
    assert "**Fragments decoded:** 12/12" in text
    assert "**Opcodes mapped:** 12/16" in text
    assert "Dangerous runtime calls detected" in text
    assert "Recover the remaining" not in text


def test_split_functions_from_payload(tmp_path: Path) -> None:
    source = (
        "-- Sample payload\n"
        "local function alpha(a, b)\n"
        "    return a + b\n"
        "end\n\n"
        "function beta(x)\n"
        "    local function inner(y)\n"
        "        return y * 2\n"
        "    end\n"
        "    return inner(x)\n"
        "end\n\n"
        "local gamma = function(z)\n"
        "    return z - 1\n"
        "end\n\n"
        "return function(value)\n"
        "    return value\n"
        "end\n\n"
        "local fake = \"function not real\"\n"
    )
    payload = tmp_path / "payload.lua"
    payload.write_text(source, encoding="utf-8")

    output_dir = tmp_path / "functions"
    result = split_functions_from_payload(payload, output_dir=output_dir)

    assert result["count"] == 4
    assert Path(result["output_dir"]) == output_dir
    assert "version" in result["metadata"]

    names = [entry["name"] for entry in result["functions"]]
    assert names == ["alpha", "beta", "gamma", "return_fn"]

    files = sorted(output_dir.glob("*.lua"))
    assert len(files) == 4
    alpha_text = files[0].read_text(encoding="utf-8")
    assert alpha_text.lstrip().startswith("local function alpha")
    return_text = files[-1].read_text(encoding="utf-8")
    assert return_text.lstrip().startswith("return function")

    last_entry = result["functions"][-1]
    assert last_entry["kind"] == "return"
    assert last_entry["line_end"] >= last_entry["line_start"]
    assert not any("inner" in path.stem for path in files)


def test_divide_unit_of_work(tmp_path: Path) -> None:
    has_luaparser = importlib.util.find_spec("luaparser") is not None

    source_path = Path("Obfuscated2.lua")
    copied = tmp_path / source_path.name
    copied.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")

    units_dir = tmp_path / "units"
    plan = divide_unit_of_work(copied, output_dir=units_dir)

    assert plan["source"] == str(copied)
    assert Path(plan["output_dir"]) == units_dir

    fragment_info = plan["fragments"]
    assert fragment_info["count"] >= 1
    fragment_files = list(Path(fragment_info["output_dir"]).glob("fragment_*.lua"))
    assert fragment_files
    for entry in fragment_info["entries"][:3]:
        assert Path(entry["file"]).exists()

    helper_info = plan["helper_tables"]
    assert Path(helper_info["output_dir"]).exists()
    if has_luaparser:
        assert helper_info["count"] >= 1
    else:
        assert "luaparser_missing" in helper_info.get("skipped", [])

    vm_info = plan["vm_sections"]
    assert Path(vm_info["output_dir"]).exists()
    if has_luaparser:
        assert vm_info["count"] >= 1
    else:
        assert vm_info["count"] == 0
        assert vm_info["skipped"]

    manifest_path = units_dir / "unit_of_work.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["fragments"]["count"] == fragment_info["count"]


def test_lift_helper_tables_to_modules(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")

    source = (
        "local string_ops = {\n"
        "  trim = function(s) return string.gsub(s, '^%s+', '') end,\n"
        "  bytes = function(s) return {string.byte(s, 1, #s)} end,\n"
        "}\n\n"
        "local bit_ops = {\n"
        "  mask = function(v) return bit32.band(v, 0xff) end,\n"
        "}\n"
    )
    path = tmp_path / "helpers.lua"
    path.write_text(source, encoding="utf-8")

    modules_dir = tmp_path / "modules"
    result = lift_helper_tables_to_modules(path, output_dir=modules_dir)

    assert result["tables_examined"] >= 2
    modules = {entry["module_name"]: entry for entry in result["modules"]}
    assert "string_helpers" in modules
    assert "bit_helpers" in modules

    string_module = modules_dir / "string_helpers.lua"
    bit_module = modules_dir / "bit_helpers.lua"
    assert string_module.exists()
    assert bit_module.exists()

    string_text = string_module.read_text(encoding="utf-8")
    bit_text = bit_module.read_text(encoding="utf-8")
    assert "function M.trim" in string_text
    assert "string.byte" in string_text
    assert "function M.mask" in bit_text
    assert "bit32.band" in bit_text

    string_helpers = modules["string_helpers"]["helpers"]
    accessors = {entry["module_accessor"] for entry in string_helpers}
    assert accessors == {"M.trim", "M.bytes"}


def test_lift_helper_tables_to_modules_text_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "luaparser" or name.startswith("luaparser."):
            raise ImportError("forced missing luaparser")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)

    source = (
        "local string_ops = {\n"
        "  trim = function(s) return string.gsub(s, '^%s+', '') end,\n"
        "  bytes = function(s) return {string.byte(s, 1, #s)} end,\n"
        "}\n\n"
        "local bit_ops = {\n"
        "  mask = function(v) return bit32.band(v, 0xff) end,\n"
        "}\n"
    )

    path = tmp_path / "helpers.lua"
    path.write_text(source, encoding="utf-8")

    modules_dir = tmp_path / "modules"
    result = lift_helper_tables_to_modules(path, output_dir=modules_dir, min_functions=1)

    assert "luaparser_missing" in result["skipped"]
    assert result["tables_examined"] >= 2

    modules = {entry["module_name"]: entry for entry in result["modules"]}
    assert "string_helpers" in modules
    assert "bit_helpers" in modules

    string_module = modules_dir / "string_helpers.lua"
    bit_module = modules_dir / "bit_helpers.lua"
    assert string_module.exists()
    assert bit_module.exists()

    string_text = string_module.read_text(encoding="utf-8")
    bit_text = bit_module.read_text(encoding="utf-8")
    assert "function M.trim" in string_text
    assert "string.byte" in string_text
    assert "function M.mask" in bit_text
    assert "bit32.band" in bit_text

def test_generate_helper_unit_tests_from_obfuscated2() -> None:
    call_counter = {"count": 0}

    def _stub_runner(_: str) -> Dict[str, Any]:
        call_counter["count"] += 1
        return {"success": True, "values": [f"value_{call_counter['count']}"]}

    result = generate_helper_unit_tests(
        per_helper=3,
        max_helpers=5,
        docstrings={"XD": "runtime entry helper"},
        sandbox_runner=_stub_runner,
    )

    assert result["helper_count"] >= 1
    assert Path(result["source_path"]).name == "Obfuscated2.lua"

    helpers = {entry["name"]: entry for entry in result["helpers"]}
    assert "XD" in helpers

    xd_entry = helpers["XD"]
    assert xd_entry.get("docstring") == "runtime entry helper"
    assert xd_entry["definition_preview"].startswith("XD=function")
    assert len(xd_entry["cases"]) == 3

    xd_case = xd_entry["cases"][0]
    texts = [arg["text"] for arg in xd_case["arguments"]]
    assert texts == ["O", "S", "Y", "N"]
    assert all(not arg["parsed"] for arg in xd_case["arguments"])
    assert xd_case["argument_count"] == 4
    assert xd_case["line"] >= 1 and xd_case["column"] >= 1
    assert xd_case["expected_values"] == ["value_1"]
    assert xd_case["expected_literals"]
    assert "value_1" in xd_case["expected_literals"][0]
    assert "XD(" in xd_case["assertion"]

    if "wD" in helpers:
        wd_case = helpers["wD"]["cases"][0]
        wd_texts = [arg["text"] for arg in wd_case["arguments"]]
        assert wd_texts == ["B", "q"]
        assert wd_case["expected_values"]

    if "assertions" in xd_entry:
        assert len(xd_entry["assertions"]) == len(xd_entry["cases"])


def test_verify_reconstructed_strings_roundtrip(tmp_path: Path) -> None:
    source = tmp_path / "fragments.lua"
    source.write_text(
        "'\\n' .. \"line\" .. '\\255' .. \"emoji\\u{1F600}\"",
        encoding="utf-8",
    )

    fragments = extract_fragments(source)
    verification = verify_reconstructed_strings(fragments)

    assert verification["checked"] == 4


def test_verify_reconstructed_strings_detects_mismatch() -> None:
    from version_detector import _verify_decoded_string_roundtrip

    fragment = {"type": "long_quoted", "text": "'\\x41'", "start": 0}
    with pytest.raises(AssertionError):
        _verify_decoded_string_roundtrip([(fragment, "B")])


def test_introspect_top_level_table_round_trip(tmp_path: Path) -> None:
    original = Path("Obfuscated2.lua").read_text(encoding="utf-8", errors="ignore")
    source = tmp_path / "Obfuscated2.lua"
    source.write_text(original, encoding="utf-8")

    rebuild = pipeline_static_rebuild(source)
    reconstructed = Path(rebuild["output_path"])
    assert reconstructed.exists()

    report = introspect_top_level_table(reconstructed)
    json_path = Path(report["output_path"])
    assert json_path.exists()

    mapping = json.loads(json_path.read_text(encoding="utf-8"))
    assert mapping, "expected discovered table entries"

    header = detect_luraph_header(source)
    for key in header["top_keys"][:10]:
        assert key in mapping
        assert mapping[key]["type"] in {"function", "value"}


def test_introspect_top_level_table_classifies_values(tmp_path: Path) -> None:
    reconstructed = tmp_path / "reconstructed.lua"
    reconstructed.write_text(
        (
            "return {\n"
            "    alpha = function(x)\n"
            "        if x then\n            return x\n        end\n"
            "    end,\n"
            "    ['bravo'] = 42,\n"
            "    [\"charlie\"] = { flag = true },\n"
        "}\n"
        ),
        encoding="utf-8",
    )

    report = introspect_top_level_table(reconstructed)
    mapping = report["entries"]

    assert mapping["alpha"]["type"] == "function"
    assert mapping["bravo"]["type"] == "value"
    assert mapping["charlie"]["type"] == "value"

    alpha_loc = mapping["alpha"]["location"]
    assert alpha_loc["line"] == 2
    assert alpha_loc["column"] == 5

def test_detect_luraph_header_multiple_versions() -> None:
    samples = {
        "Obfuscated.json": "14.4.1",
        "Obfuscated2.lua": "14.4.2",
        "Obfuscated3.lua": "14.4.2",
        "Obfuscated5.lua": "14.4.2",
        "Obfuscated6.lua": "14.3",
        "Obfuscated4.lua": "14.3",
    }

    for file_name, expected_version in samples.items():
        result = detect_luraph_header(file_name)
        assert result["version"] == expected_version
        bootstrap = result.get("bootstrapper", {})
        if file_name.endswith(".json"):
            assert bootstrap.get("mode") == "external"
            assert bootstrap.get("bootstrapper") == "initv4"
        else:
            assert bootstrap.get("mode") in {"self_contained", "embedded"}


def test_detect_luraph_header_prefers_lura_ph_url(tmp_path: Path) -> None:
    sample = tmp_path / "banner.lua"
    sample.write_text("-- https://lura.ph/ v14.4.3", encoding="utf-8")

    result = detect_luraph_header(sample)
    assert result["version"] == "14.4.3"
    assert result["bootstrapper"]["mode"] == "self_contained"

    detector = VersionDetector()
    detected = detector.detect(sample.read_text())
    assert detected.name == "14.4.3"


def test_analyze_identifier_frequencies_generates_plan(tmp_path: Path) -> None:
    original = Path("Obfuscated2.lua").read_text(encoding="utf-8", errors="ignore")
    sample = tmp_path / "Obfuscated2.lua"
    sample.write_text(original, encoding="utf-8")

    rebuild = pipeline_static_rebuild(sample)
    reconstructed = Path(rebuild["output_path"])
    assert reconstructed.exists()

    report = analyze_identifier_frequencies(reconstructed)
    csv_path = Path(report["output_path"])
    assert csv_path.exists()

    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert rows, "expected identifier frequency entries"

    names = {row["name"] for row in rows}
    assert "function" not in names

    core_entries = [row for row in rows if row["usage_type"] == "core_runtime"]
    helper_entries = [row for row in rows if row["usage_type"] == "helper"]

    assert core_entries, "expected core runtime identifiers to be detected"
    assert helper_entries, "expected helper identifiers to be detected"

    header = detect_luraph_header(sample)
    for exported in header["top_keys"][:5]:
        match = next((row for row in core_entries if row["name"] == exported), None)
        assert match is not None, f"expected export {exported} to be marked as core runtime"
        assert match["recommended_name"].startswith("runtime_"), match


def test_analyze_identifier_frequencies_skips_reserved_words(tmp_path: Path) -> None:
    lua_src = tmp_path / "sample.lua"
    lua_src.write_text(
        (
            "local function helper(pairs, value)\n"
            "    local math = pairs + value\n"
            "    for idx in pairs({1, 2, 3}) do\n"
            "        value = value + idx\n"
            "    end\n"
            "    return math\n"
            "end\n"
            "return { helper = helper }\n"
        ),
        encoding="utf-8",
    )

    report = analyze_identifier_frequencies(lua_src)
    csv_path = Path(report["output_path"])
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    names = {row["name"] for row in rows}
    assert "pairs" not in names
    assert "math" not in names
    assert any(row["name"] == "helper" for row in rows)


def test_parity_test_stubbed_sandbox(tmp_path: Path) -> None:
    sample = tmp_path / "payload.lua"
    sample.write_text("[=[LPH!!!!!]=]", encoding="utf-8")

    key = "K"

    def _sandbox(fragment_text: str, *, expected=None, inputs=None):  # type: ignore[override]
        payload = decode_lph85("LPH!!!!!")
        prga = apply_prga(payload, key.encode("utf-8"))
        words = list(struct.unpack("<I", prga[:4]))
        return {
            "success": True,
            "values": [words, prga],
            "error": None,
            "matches_expected": True,
            "environment": {"io": True},
        }

    result = parity_test(
        0,
        path=sample,
        key=key,
        word_count=1,
        sandbox_runner=_sandbox,
        pipeline="initv4",
    )

    payload = decode_lph85("LPH!!!!!")
    prga = apply_prga(payload, key.encode("utf-8"))
    expected_words = list(struct.unpack("<I", prga[:4]))

    assert result["match"] is True
    assert result["python_words"] == result["lua_words"] == expected_words


def test_parity_test_words_only(tmp_path: Path) -> None:
    sample = tmp_path / "payload.lua"
    sample.write_text("[=[LPH!!!!!]=]", encoding="utf-8")

    key = "K"

    def _sandbox(fragment_text: str, *, expected=None, inputs=None):  # type: ignore[override]
        payload = decode_lph85("LPH!!!!!")
        prga = apply_prga(payload, key.encode("utf-8"))
        words = list(struct.unpack("<I", prga[:4]))
        return {"success": True, "values": [words], "error": None}

    result = parity_test(
        0,
        path=sample,
        key=key,
        word_count=1,
        sandbox_runner=_sandbox,
        pipeline="initv4",
    )

    payload = decode_lph85("LPH!!!!!")
    prga = apply_prga(payload, key.encode("utf-8"))
    expected_words = list(struct.unpack("<I", prga[:4]))

    assert result["match"] is True
    assert result["python_words"] == expected_words
    assert result["lua_words"] == expected_words


def test_parity_test_reports_mismatch(tmp_path: Path) -> None:
    sample = tmp_path / "payload.lua"
    sample.write_text("[=[LPH!!!!!]=]", encoding="utf-8")

    key = "K"

    def _sandbox(fragment_text: str, *, expected=None, inputs=None):  # type: ignore[override]
        payload = decode_lph85("LPH!!!!!")
        prga = bytearray(apply_prga(payload, key.encode("utf-8")))
        prga[0] ^= 0xFF
        return {
            "success": True,
            "values": [[123], bytes(prga)],
            "error": None,
            "matches_expected": False,
            "environment": {},
        }

    with pytest.raises(AssertionError) as exc:
        parity_test(
            0,
            path=sample,
            key=key,
            word_count=1,
            sandbox_runner=_sandbox,
            pipeline="initv4",
        )

    assert "Word mismatch" in str(exc.value)


def test_parity_test_rejects_non_initv4(tmp_path: Path) -> None:
    sample = tmp_path / "Obfuscated2.lua"
    sample.write_text(
        "-- This file was protected using Luraph Obfuscator v14.4.2 [https://lura.ph/]\n"
        "return 'placeholder'\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        parity_test(0, path=sample, key="K", word_count=1)

    assert "initv4 parity harness" in str(excinfo.value)


def test_round_trip_test_success(tmp_path: Path) -> None:
    original = tmp_path / "original.lua"
    module = tmp_path / "module.lua"
    original.write_text("return { XD = function(v) return v .. (script_key or '') end }\n", encoding="utf-8")
    module.write_text("return { XD = function(v) return v .. (script_key or '') end }\n", encoding="utf-8")

    calls: list[str] = []

    def _sandbox(fragment_text: str, *, expected=None, inputs=None):  # type: ignore[override]
        if "-- round_trip: original" in fragment_text:
            calls.append("original")
            return {"success": True, "values": ["payloadKEY"], "environment": {}}
        if "-- round_trip: module" in fragment_text:
            calls.append("module")
            return {"success": True, "values": ["payloadKEY"], "environment": {}}
        raise AssertionError("unexpected snippet")

    logs: list[str] = []
    result = round_trip_test(
        path=original,
        module_path=module,
        key="KEY",
        inputs=["payload"],
        entry_name="XD",
        sandbox_runner=_sandbox,
        log_callback=logs.append,
    )

    assert result["match"] is True
    assert result["values"] == ["payloadKEY"]
    assert calls == ["original", "module"]
    assert logs == []


def test_round_trip_test_reports_difference(tmp_path: Path) -> None:
    original = tmp_path / "original.lua"
    module = tmp_path / "module.lua"
    original.write_text("return { XD = function(v) return v end }\n", encoding="utf-8")
    module.write_text("return { XD = function(v) return v end }\n", encoding="utf-8")

    def _sandbox(fragment_text: str, *, expected=None, inputs=None):  # type: ignore[override]
        if "-- round_trip: original" in fragment_text:
            return {"success": True, "values": [123], "environment": {}}
        if "-- round_trip: module" in fragment_text:
            return {"success": True, "values": [456], "environment": {}}
        raise AssertionError("unexpected snippet")

    logs: list[str] = []
    with pytest.raises(AssertionError) as exc:
        round_trip_test(
            path=original,
            module_path=module,
            key="KEY",
            inputs=[],
            entry_name="XD",
            sandbox_runner=_sandbox,
            log_callback=logs.append,
        )

    assert "Round-trip mismatch" in str(exc.value)
    assert logs and logs[0].startswith("value[0]")


def test_pretty_print_with_mapping_preserves_comments(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")
    source = tmp_path / "reconstructed.lua"
    source.write_text(
        (
            "-- heading\n"
            "local function XD(value)\n"
            "    -- inner\n"
            "    return value\n"
            "end\n"
        ),
        encoding="utf-8",
    )

    mapping_file = tmp_path / "mapping.json"
    mapping_file.write_text(
        json.dumps({"renames": [{"name": "XD", "recommended_name": "decode_driver"}]}),
        encoding="utf-8",
    )

    output_path = tmp_path / "pretty.lua"
    recorder = benchmark_recorder()
    snapshot = recorder.take_snapshot()
    result = pretty_print_with_mapping(source, mapping_file, output_path=output_path)
    summary = recorder.summarize(snapshot)
    categories = {entry["category"] for entry in summary}
    assert "pretty_print" in categories

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "-- Renamed identifiers" in text
    assert "XD -> decode_driver" in "\n".join(result["index_block"])
    assert "function decode_driver" in text
    assert "-- inner" in text


def test_pretty_print_with_mapping_updates_comment_headers_and_preview(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip("luaparser")

    source = tmp_path / "reconstructed.lua"
    source.write_text(
        (
            "-- foo helper\n"
            "local function foo(value)\n"
            "    return value\n"
            "end\n\n"
            "local result = foo(1) -- call foo\n"
            "return foo(result) -- tail foo\n"
        ),
        encoding="utf-8",
    )

    mapping_file = tmp_path / "mapping.json"
    mapping_file.write_text(json.dumps({"foo": "runtime"}), encoding="utf-8")

    output_path = tmp_path / "pretty.lua"
    result = pretty_print_with_mapping(source, mapping_file, output_path=output_path)
    captured = capsys.readouterr()

    assert "Rename preview:" in captured.out
    assert "runtime helper" in captured.out
    assert output_path.exists()

    pretty_text = output_path.read_text(encoding="utf-8")
    assert "runtime helper" in pretty_text
    assert "call runtime" in pretty_text
    assert "tail runtime" in pretty_text

    preview = result.get("rename_preview")
    assert isinstance(preview, list) and preview
    comment_lines = [entry for entry in preview if "runtime helper" in entry.get("updated", "")]
    assert comment_lines, "expected comment header rename to appear in preview"


def test_pretty_print_with_mapping_rerun(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")

    source = tmp_path / "reconstructed.lua"
    source.write_text(
        "local function XD(value)\n    return value\nend\n",
        encoding="utf-8",
    )

    mapping_file = tmp_path / "mapping.json"
    mapping_file.write_text(json.dumps({"XD": "first_pass"}), encoding="utf-8")

    output_path = tmp_path / "pretty.lua"
    first = pretty_print_with_mapping(source, mapping_file, output_path=output_path)
    first_text = Path(first["output_path"]).read_text(encoding="utf-8")
    assert "first_pass" in first_text

    mapping_file.write_text(json.dumps({"XD": "second_pass"}), encoding="utf-8")

    second = pretty_print_with_mapping(source, mapping_file, output_path=output_path)
    second_text = Path(second["output_path"]).read_text(encoding="utf-8")
    assert "second_pass" in second_text
    assert first_text != second_text


def test_pretty_print_with_mapping_is_deterministic(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")

    source = tmp_path / "reconstructed.lua"
    source.write_text(
        (
            "local function first_fn(value)\n"
            "    return value + 1\n"
            "end\n\n"
            "local function second_fn(value)\n"
            "    return value - 1\n"
            "end\n\n"
            "return {\n"
            "    second_fn = second_fn,\n"
            "    first_fn = first_fn,\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    mapping_file = tmp_path / "mapping.json"
    # First run: mapping entries appear in one order.
    mapping_file.write_text(
        json.dumps(
            [
                {"name": "second_fn", "rename": "beta_helper"},
                {"name": "first_fn", "rename": "alpha_helper"},
            ]
        ),
        encoding="utf-8",
    )

    output_path = tmp_path / "pretty.lua"
    first = pretty_print_with_mapping(source, mapping_file, output_path=output_path)
    first_text = Path(first["output_path"]).read_text(encoding="utf-8")

    # Second run: same mappings but in reverse order and via a dict form to
    # ensure deterministic canonicalisation regardless of JSON layout.
    mapping_file.write_text(
        json.dumps(
            {
                "first_fn": "alpha_helper",
                "second_fn": "beta_helper",
            }
        ),
        encoding="utf-8",
    )

    second = pretty_print_with_mapping(source, mapping_file, output_path=output_path)
    second_text = Path(second["output_path"]).read_text(encoding="utf-8")

    assert first_text == second_text


def test_name_opcode_cli_flow(tmp_path: Path) -> None:
    pytest.importorskip("luaparser")

    reconstructed = tmp_path / "reconstructed.lua"
    reconstructed.write_text(
        "local function OP_15(value)\n    return value * 2\nend\n",
        encoding="utf-8",
    )

    mapping_path = tmp_path / "mapping.json"
    output_path = tmp_path / "pretty.lua"
    upcodes = tmp_path / "upcodes.json"
    guesses = tmp_path / "guesses.json"

    upcodes.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "opcode": 15,
                        "mnemonic": "OP_15",
                        "frequency": 4,
                        "handler_table": "return_table",
                        "semantic": "unknown",
                        "sample_usage": [
                            {
                                "snippet": "handler=function(ctx) return ctx + 2 end",
                                "source": "handler_snippet",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    guesses.write_text(
        json.dumps(
            {
                "guesses": {
                    "15": {
                        "guess": "scale_pair",
                        "confidence": 0.55,
                        "evidence": "vm trace",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli_main.main(
        [
            "name_opcode",
            "15",
            "--name",
            "double_value",
            "--mapping",
            str(mapping_path),
            "--source",
            str(reconstructed),
            "--output",
            str(output_path),
            "--upcodes",
            str(upcodes),
            "--guesses",
            str(guesses),
            "--confirm-ownership",
            "--confirm-voluntary-key",
        ]
    )

    assert exit_code == 0
    mapping_payload = json.loads(mapping_path.read_text(encoding="utf-8"))
    assert mapping_payload["OP_15"] == "DOUBLE_VALUE"
    rendered = output_path.read_text(encoding="utf-8")
    assert "function DOUBLE_VALUE" in rendered


def test_fuzz_vm_behavior_collects_string_outputs(tmp_path: Path) -> None:
    module_path = tmp_path / "reconstructed.lua"
    module_path.write_text(
        (
            "return {\n"
            "    talk = function(value)\n"
            "        if value == \"boom\" then error(\"boom\") end\n"
            "        return (value or \"\") .. \"!\"\n"
            "    end,\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    def _stub_runner(snippet: str, **kwargs: Any) -> Dict[str, Any]:
        assert kwargs.get("allow_debug") is True
        target = re.search(r"-- fuzz_target: ([^\n]+)", snippet)
        assert target and target.group(1) == "talk"
        inputs_match = re.search(r"-- fuzz_inputs_json: (.+)", snippet)
        assert inputs_match is not None
        fuzz_inputs = json.loads(inputs_match.group(1))
        text = fuzz_inputs[0] if fuzz_inputs else ""
        coverage = {1: True, 10 + len(text): True}
        if text == "boom":
            return {"success": False, "values": [coverage, False, "boom"], "error": "boom"}
        return {"success": True, "values": [coverage, True, f"OUT:{text}"]}

    result = fuzz_vm_behavior(
        module_path,
        key=_build_test_key("fuzz-key", prefix="TINY"),
        sandbox_runner=_stub_runner,
        iterations_per_function=4,
        seed=0,
    )

    assert result["functions"], "expected at least one fuzzed function"
    entry = result["functions"][0]
    assert entry["name"] == "talk"
    assert entry["coverage"] >= 1
    assert entry["string_outputs"], "should record string-producing outputs"
    assert any(case["coverage_gain"] for case in entry["interesting_cases"])


def test_ir_to_lua_emits_readable_module(tmp_path: Path) -> None:
    instructions = [
        VMInstruction("MOVE", a=1, b=0, pc=0),
        VMInstruction("LOADK", a=2, aux={"const_b": "payload"}, pc=1),
        VMInstruction("CALL", a=1, b=2, c=1, pc=2),
        VMInstruction("RETURN", a=2, b=2, pc=3),
    ]
    program = VMFunction(
        constants=[],
        instructions=instructions,
        num_params=1,
        register_count=3,
        metadata={"function_name": "f"},
    )

    mapping_file = tmp_path / "mapping.json"
    mapping_file.write_text(json.dumps({"f": "handle_message"}), encoding="utf-8")

    output_path = tmp_path / "module.lua"
    result = ir_to_lua(
        program,
        mapping_path=mapping_file,
        output_path=output_path,
        module_name="Decoded",
        docstring_threshold=2,
    )

    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert "local function handle_message" in text
    assert "local t1, t2" in text
    assert "return Decoded" in text
    assert any("Complex sequence" in line for line in text.splitlines())
    assert result["function_name"] == "handle_message"
    assert result["module_name"] == "Decoded"
    assert any(entry.get("opcode") == "CALL" for entry in result["docstrings"])

    pytest.importorskip("luaparser")
    from luaparser import ast as lua_ast

    lua_ast.parse(text)


def test_obfuscated2_fragment_snapshot_static() -> None:
    snapshot = _load_obfuscated2_snapshot()
    fragments = extract_fragments("Obfuscated2.lua")
    decoded_pairs = list(_iter_decoded_fragments(fragments))

    assert snapshot["fragment_count"] == len(decoded_pairs)

    for idx, (expected, (_, decoded)) in enumerate(zip(snapshot["records"], decoded_pairs)):
        assert expected["index"] == idx
        payload = _fragment_bytes(decoded)
        digest = hashlib.sha256(payload).hexdigest()
        assert expected["sha256"] == digest
        assert expected["length"] == len(decoded)


def test_obfuscated2_fragment_snapshot_runtime_hmac() -> None:
    session_key = os.environ.get("LURAPH_SESSION_KEY")
    if not session_key:
        pytest.skip("session key required to validate fragment HMAC snapshot")

    snapshot = _load_obfuscated2_snapshot()
    fragments = extract_fragments("Obfuscated2.lua")
    decoded_pairs = list(_iter_decoded_fragments(fragments))

    assert snapshot["fragment_count"] == len(decoded_pairs)

    key_bytes = session_key.encode("utf-8")
    for idx, (expected, (_, decoded)) in enumerate(zip(snapshot["records"], decoded_pairs)):
        payload = _fragment_bytes(decoded)
        recorded = expected.get("hmac_sha256")
        assert recorded is not None, "snapshot missing hmac value"
        actual = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()
        assert actual == recorded, f"fragment {idx} HMAC mismatch"
