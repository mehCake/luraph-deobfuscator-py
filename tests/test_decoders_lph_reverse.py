from pathlib import Path

from src.decoders.lph_reverse import reverse_lph, try_parameter_presets


def _forward_mask(data: bytes, params: dict) -> bytes:
    mode = (params.get("mode") or "xor").lower()
    stream = params.get("stream")
    if stream is not None:
        stream_bytes = bytes(stream) if not isinstance(stream, (bytes, bytearray)) else bytes(stream)
    else:
        value = int(params.get("value") or 0)
        stream_bytes = bytes([value & 0xFF])
    if not stream_bytes:
        return data
    out = bytearray(data)
    length = len(stream_bytes)
    for idx, value in enumerate(out):
        mask_byte = stream_bytes[idx % length]
        if mode == "xor":
            out[idx] = value ^ mask_byte
        elif mode == "add":
            out[idx] = (value + mask_byte) & 0xFF
        elif mode == "sub":
            out[idx] = (value - mask_byte) & 0xFF
        else:  # pragma: no cover - mirrored defensive branch
            raise ValueError(mode)
    return bytes(out)


def _forward_permutation(data: bytes, table):
    if not table:
        return data
    size = len(data)
    inverse = [0] * size
    for idx, target in enumerate(table):
        inverse[int(target)] = idx
    result = bytearray(size)
    for idx, src in enumerate(inverse):
        result[src] = data[idx]
    return bytes(result)


def _forward_inblock_permutation(data: bytes, table, block_size: int):
    if not table or not block_size:
        return data
    result = bytearray(data)
    inverse = [0] * block_size
    for idx, target in enumerate(table):
        inverse[int(target)] = idx
    for start in range(0, len(result), block_size):
        end = min(start + block_size, len(result))
        chunk = list(result[start:end])
        encoded = [0] * (end - start)
        for idx in range(end - start):
            encoded[inverse[idx]] = chunk[idx]
        result[start:end] = encoded
    return bytes(result)


def _rol8(value: int, rotation: int) -> int:
    rotation &= 7
    value &= 0xFF
    return ((value << rotation) | (value >> (8 - rotation))) & 0xFF


def _forward_rotate(data: bytes, params: dict) -> bytes:
    amount = params.get("amount")
    amounts = params.get("amounts")
    if amounts is not None:
        if isinstance(amounts, int):
            rotations = [amounts & 7]
        else:
            rotations = [int(v) & 7 for v in amounts]
    elif amount is None:
        return data
    else:
        rotations = [int(amount) & 7]
    direction = (params.get("direction") or "left").lower()
    if direction not in {"left", "right"}:
        raise ValueError(direction)
    result = bytearray(data)
    for idx, value in enumerate(result):
        rotation = rotations[idx % len(rotations)]
        if direction == "left":
            result[idx] = _rol8(value, rotation)
        else:
            result[idx] = _rol8(value, 8 - rotation)
    return bytes(result)


def _forward_block_rotate(data: bytes, params: dict) -> bytes:
    block_size = int(params.get("size") or 0)
    shift = int(params.get("shift") or 0)
    direction = (params.get("direction") or "left").lower()
    if not block_size or shift % block_size == 0:
        return data
    result = bytearray(data)
    shift %= block_size
    for start in range(0, len(result), block_size):
        end = min(start + block_size, len(result))
        chunk = result[start:end]
        if direction == "left":
            pivot = shift % len(chunk)
        else:
            pivot = len(chunk) - (shift % len(chunk))
        chunk = chunk[pivot:] + chunk[:pivot]
        result[start:end] = chunk
    return bytes(result)


def _forward_xor_mix(data: bytes, params: dict) -> bytes:
    mode = (params.get("mode") or "stream").lower()
    if mode == "stream":
        stream = params.get("stream") or b""
        if not isinstance(stream, (bytes, bytearray)):
            stream = bytes(stream)
        if not stream:
            return data
        return bytes(b ^ stream[idx % len(stream)] for idx, b in enumerate(data))

    if mode == "rolling":
        stride = max(1, int(params.get("stride") or 1))
        seed = params.get("seed")
        if seed is None:
            seed_bytes = b""
        elif isinstance(seed, (bytes, bytearray)):
            seed_bytes = bytes(seed)
        else:
            seed_bytes = bytes(seed)
        result = bytearray(len(data))
        for idx, value in enumerate(data):
            if idx < stride:
                mix = seed_bytes[idx % len(seed_bytes)] if seed_bytes else 0
            else:
                mix = data[idx - stride]
            result[idx] = value ^ mix
        return bytes(result)

    raise ValueError(mode)


def obfuscate(original: bytes, params: dict) -> bytes:
    buffer = bytes(original)
    for step in reversed(params.get("steps", [])):
        if step == "mask":
            buffer = _forward_mask(buffer, params.get("mask", {}))
        elif step == "permute":
            buffer = _forward_permutation(buffer, params.get("permute", {}).get("table"))
        elif step == "rotate":
            buffer = _forward_rotate(buffer, params.get("rotate", {}))
        elif step == "block_rotate":
            buffer = _forward_block_rotate(buffer, params.get("block_rotate", {}))
        elif step == "inblock_permute":
            block_params = params.get("inblock_permute", {})
            buffer = _forward_inblock_permutation(
                buffer,
                block_params.get("table"),
                int(block_params.get("block_size") or 0),
            )
        elif step == "xor_mix":
            buffer = _forward_xor_mix(buffer, params.get("xor_mix", {}))
    return buffer


def test_reverse_lph_basic_pipeline():
    params = {
        "steps": ["mask", "permute", "rotate"],
        "mask": {"mode": "xor", "value": 0x5A},
        "permute": {"table": [3, 0, 2, 1]},
        "rotate": {"amount": 3, "direction": "left"},
    }
    original = bytes(range(4))
    encoded = obfuscate(original, params)

    decoded = reverse_lph(encoded, params)
    assert decoded == original


def test_reverse_lph_block_and_xor(tmp_path: Path):
    params = {
        "steps": ["mask", "block_rotate", "inblock_permute", "rotate", "xor_mix"],
        "mask": {"mode": "xor", "value": 0x3C},
        "block_rotate": {"size": 8, "shift": 3, "direction": "right"},
        "inblock_permute": {"block_size": 4, "table": [1, 3, 0, 2]},
        "rotate": {"amount": 1, "direction": "left"},
        "xor_mix": {"mode": "rolling", "stride": 2, "seed": b"\x10\x20"},
    }
    original = bytes(range(1, 33))
    encoded = obfuscate(original, params)

    decoded = reverse_lph(encoded, params, debug=True, dump_dir=tmp_path)
    assert decoded == original

    dumps = sorted(tmp_path.glob("lph_*_*.bin"))
    assert dumps, "expected intermediate dumps when debug is enabled"


def test_try_parameter_presets_scoring():
    original = b"LuaChunk!"
    correct_params = {
        "steps": ["mask", "permute"],
        "mask": {"mode": "xor", "value": 0x11},
        "permute": {"table": list(range(len(original)))},
    }
    encoded = obfuscate(original, correct_params)

    wrong_params = {
        "steps": ["mask"],
        "mask": {"mode": "xor", "value": 0x22},
    }

    presets = [("wrong", wrong_params), ("correct", correct_params)]

    def score_fn(payload: bytes) -> float:
        return 1.0 if payload == original else 0.0

    candidates = try_parameter_presets(encoded, presets, score_fn=score_fn)
    assert [c.name for c in candidates] == ["correct", "wrong"]
    assert candidates[0].output == original
    assert candidates[0].trace


