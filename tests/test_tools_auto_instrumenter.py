import json
from pathlib import Path

import pytest

from src.tools.auto_instrumenter import (
    AutoInstrumenterError,
    InstrumentationConfig,
    instrument_bootstrap,
    main as run_auto_instrumenter,
)

try:
    from lupa import LuaRuntime
except Exception:  # pragma: no cover - lupa import errors handled as fallback
    LuaRuntime = None  # type: ignore[assignment]


def _runtime_is_fallback() -> bool:
    if LuaRuntime is None:
        return True
    try:
        runtime = LuaRuntime()
    except Exception:  # pragma: no cover - defensive
        return True
    return bool(getattr(runtime, "is_fallback", False))


IS_FALLBACK = _runtime_is_fallback()


def _make_vm_snippet() -> str:
    return (
        "state = { pc = 0 }\n"
        "function vm_step()\n"
        "    state.pc = state.pc + 1\n"
        "    return state.pc\n"
        "end\n"
    )


def test_instrument_bootstrap_captures_calls_and_returns() -> None:
    snippet = _make_vm_snippet()
    config = InstrumentationConfig(
        functions=["vm_step"],
        invocations=["vm_step()", "vm_step()"],
        log_limit=16,
    )

    if IS_FALLBACK:
        with pytest.raises(AutoInstrumenterError):
            instrument_bootstrap(snippet, config)
        return

    result = instrument_bootstrap(snippet, config)

    vm_logs = [entry for entry in result.logs if entry.name == "vm_step"]
    assert [entry.event for entry in vm_logs[:4]] == ["call", "return", "call", "return"]
    # ensure return payload increments each time the helper executes
    returns = [entry.payload for entry in vm_logs if entry.event == "return"]
    assert returns == [[1], [2]]
    assert result.summary.restored is True


def test_instrument_bootstrap_rejects_unknown_targets() -> None:
    snippet = "function known() return true end"
    config = InstrumentationConfig(functions=["vm_step"])
    with pytest.raises(AutoInstrumenterError):
        instrument_bootstrap(snippet, config)


def test_auto_instrumenter_cli(tmp_path: Path) -> None:
    snippet_path = tmp_path / "snippet.lua"
    snippet_path.write_text(_make_vm_snippet(), encoding="utf-8")
    json_path = tmp_path / "out.json"

    argv = [
        str(snippet_path),
        "--function",
        "vm_step",
        "--invoke",
        "vm_step()",
        "--json-out",
        str(json_path),
    ]

    if IS_FALLBACK:
        with pytest.raises(SystemExit):
            run_auto_instrumenter(argv)
        return

    exit_code = run_auto_instrumenter(argv)
    assert exit_code == 0

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "logs" in payload and payload["logs"]
    assert payload["summary"]["instrumented_functions"] == ["vm_step"]
