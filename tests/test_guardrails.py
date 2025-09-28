import pytest

try:  # pragma: no cover
    from luraph_deobfuscator import EnhancedLuraphDeobfuscator  # type: ignore
except Exception as exc:  # pragma: no cover
    pytest.skip(f"legacy guardrails unavailable: {exc}", allow_module_level=True)


def test_process_input_rejects_http_urls():
    deob = EnhancedLuraphDeobfuscator()
    with pytest.raises(ValueError):
        deob.process_input("https://example.com/payload.lua")


def test_download_from_url_is_disabled():
    deob = EnhancedLuraphDeobfuscator()
    with pytest.raises(RuntimeError):
        deob.download_from_url("https://example.com/payload.lua")
