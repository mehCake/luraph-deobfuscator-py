from pathlib import Path
from typing import Iterable

import base64
import json
import logging

from luraph_deobfuscator import EnhancedLuraphDeobfuscator
from version_detector import VersionDetector, VersionFeature
from src import pipeline
from src.deobfuscator import LuaDeobfuscator
from src.vm.emulator import LuraphVM
from src.versions import VersionHandler, decode_constant_pool, get_handler


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


def test_detect_version_luraph_v143_vm() -> None:
    detector = VersionDetector()
    sample = Path('Obfuscated4.lua').read_text()
    detected = detector.detect(sample)
    assert detected.name == VersionFeature.LURAPH_V14_3_VM.value
    assert VersionFeature.LURAPH_V14_3_VM.value in detected.features
    assert detected.profile
    assert detected.profile.get('double_packed_constants') is True
    decoder_profile = detected.profile.get('string_decoder')
    assert isinstance(decoder_profile, dict)
    assert decoder_profile.get('token_length') == 5
    assert decoder_profile.get('local_variable_count', 0) >= 5
    assert decoder_profile.get('caches_results') is True


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


def test_legacy_summary_reports_v14_3_detection(caplog) -> None:
    sample = Path('Obfuscated4.lua').read_text(encoding='utf-8', errors='ignore')
    deob = EnhancedLuraphDeobfuscator()
    with caplog.at_level(logging.INFO, logger='LuraphDeobfuscator'):
        summary = deob.summarise_detection(sample, filename='Obfuscated4.lua')
    expected = "Luraph v14.3 (VM, Real Life HIGH, strings encrypted, double-packed constants)"
    assert summary == expected
    assert expected in caplog.text
