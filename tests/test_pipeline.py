from pathlib import Path

import pytest

from src import pipeline


def test_payload_decode_skipped_in_dry_run(tmp_path, monkeypatch):
    calls = []

    def fake_payload_decode(ctx):
        calls.append(True)
        return {"ran": True}

    monkeypatch.setattr(pipeline, "payload_decode_run", fake_payload_decode)

    source = tmp_path / "sample.lua"
    source.write_text("print('hi')\n", encoding="utf-8")

    ctx = pipeline.Context(input_path=source, raw_input=source.read_text(), options={"dry_run": True})

    pipeline._pass_payload_decode(ctx)

    assert not calls, "dry-run should skip payload decode pass"
    summary = ctx.pass_metadata.get("payload_decode")
    assert summary == {"skipped": True, "reason": "dry_run"}


def test_pipeline_execution_error_contains_pass_name(tmp_path):
    source = tmp_path / "dummy.lua"
    source.write_text("return 0\n", encoding="utf-8")

    ctx = pipeline.Context(input_path=source, raw_input=source.read_text())

    registry = pipeline.PassRegistry()

    def boom(ctx):
        raise RuntimeError("boom")

    registry.register_pass("test", boom, 10)

    with pytest.raises(pipeline.PipelineExecutionError) as excinfo:
        registry.run_passes(ctx)

    err = excinfo.value
    assert err.pass_name == "test"
    assert err.timings == []
    assert err.duration >= 0.0


def test_sanitize_decoded_applies_with_confirmation(tmp_path, monkeypatch):
    source = tmp_path / "sample.lua"
    source.write_text("return 0\n", encoding="utf-8")

    ctx = pipeline.Context(
        input_path=source,
        raw_input=source.read_text(),
        options={"sanitize_decoded": True},
    )
    ctx.decoded_payloads = ["return 'sk_live_0123456789abcdef012345'"]

    monkeypatch.setattr(pipeline, "ask_confirm", lambda _ctx, _msg: True)

    pipeline._pass_sanitize_decoded(ctx)

    summary = ctx.pass_metadata.get("sanitize_decoded")
    assert summary["applied"] is True
    assert summary["findings"] == 1
    assert "<redacted:stripe_secret_key>" in ctx.decoded_payloads[0]
    assert any("Sanitised" in warning for warning in ctx.report.warnings)


def test_sanitize_decoded_respects_decline(tmp_path, monkeypatch):
    source = tmp_path / "sample.lua"
    source.write_text("return 0\n", encoding="utf-8")

    ctx = pipeline.Context(
        input_path=source,
        raw_input=source.read_text(),
        options={"sanitize_decoded": True},
    )
    ctx.decoded_payloads = ["return 'sk_live_0123456789abcdef012345'"]

    monkeypatch.setattr(pipeline, "ask_confirm", lambda _ctx, _msg: False)

    pipeline._pass_sanitize_decoded(ctx)

    summary = ctx.pass_metadata.get("sanitize_decoded")
    assert summary["applied"] is False
    assert "sk_live_0123456789abcdef012345" in ctx.decoded_payloads[0]
    assert any("left unmodified" in warning for warning in ctx.report.warnings)
