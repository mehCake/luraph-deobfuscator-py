from __future__ import annotations

from src.vm.disasm_driver import build_config_from_split, inspect_candidates, run_driver


class _InputFeeder:
    def __init__(self, responses: list[str]):
        self._responses = responses

    def __call__(self, prompt: str = "") -> str:  # pragma: no cover - invoked via monkeypatch
        if not self._responses:
            raise EOFError
        return self._responses.pop(0)


def _pack(op: int, a: int, b: int, c: int) -> int:
    return op | (a << 8) | (b << 16) | (c << 24)


def _make_blob() -> bytes:
    words = [
        _pack(1, 2, 3, 4),
        _pack(5, 6, 7, 8),
        _pack(9, 10, 11, 12),
    ]
    return b"".join(word.to_bytes(4, "little") for word in words)


def test_build_config_from_split_round_trip() -> None:
    config = build_config_from_split((8, 8, 8, 8))
    blob = _make_blob()
    from src.vm.disassembler import Disassembler

    instructions = Disassembler(config).disassemble_bytes(blob)
    assert [inst.as_tuple() for inst in instructions] == [
        (1, 2, 3, 4),
        (5, 6, 7, 8),
        (9, 10, 11, 12),
    ]


def test_run_driver_ranks_expected_split() -> None:
    blob = _make_blob()
    results = run_driver(
        blob,
        candidate_config=None,
        splits=["8/8/8/8", "12/10/5/5"],
        top=2,
    )
    assert results
    assert results[0].split == (8, 8, 8, 8)


def test_inspect_candidates_lists_and_details(monkeypatch, capsys) -> None:
    blob = _make_blob()
    results = run_driver(
        blob,
        candidate_config=None,
        splits=["8/8/8/8"],
        top=1,
    )
    feeder = _InputFeeder(["1", "q"])
    monkeypatch.setattr("builtins.input", feeder)
    inspect_candidates(results, limit=2)
    out = capsys.readouterr().out
    assert "Interactive inspection mode" in out
    assert "Candidate Detail" in out
