import pytest

from src.versions.v14_3_loader import decode_varint

LUA_VARINT_SOURCE = """
return function(data)
  local index = 1
  local w = 0
  local multiplier = 1
  while true do
    local byte = string.byte(data, index, index)
    if not byte then
      error("unterminated varint")
    end
    index = index + 1
    local payload = (byte > 127) and (byte - 128) or byte
    w = w + payload * multiplier
    if byte < 128 then
      return w
    end
    multiplier = multiplier * 128
  end
end
"""


@pytest.fixture(scope="module")
def lua_varint_callable():
    lupa = pytest.importorskip("lupa")
    LuaRuntime = lupa.LuaRuntime
    runtime = LuaRuntime(unpack_returned_tuples=True)
    if getattr(runtime, "is_fallback", False):
        pytest.skip("Lua fallback runtime cannot evaluate varint reference")
    return runtime.eval(LUA_VARINT_SOURCE)


@pytest.mark.parametrize(
    "payload",
    [
        bytes([0x00]),
        bytes([0x7F]),
        bytes([0x80, 0x01]),
        bytes([0xFF, 0x01]),
        bytes([0x95, 0xBE, 0x04]),
        bytes([0xFF, 0xFF, 0xFF, 0x7F]),
    ],
)
def test_decode_varint_matches_lua(payload, lua_varint_callable):
    lua_value = lua_varint_callable(payload)
    python_value, consumed = decode_varint(payload)
    assert consumed == len(payload)
    assert python_value == lua_value


def test_decode_varint_handles_offsets():
    data = bytes([0x01, 0x80, 0x02, 0x7F])
    value, consumed = decode_varint(data, start=1)
    assert value == 0x100
    assert consumed == 2
    tail_value, tail_consumed = decode_varint(data, start=3)
    assert tail_value == 0x7F
    assert tail_consumed == 1


def test_decode_varint_rejects_truncated_sequences():
    with pytest.raises(ValueError):
        decode_varint(bytes([0x80]))


def test_decode_varint_validates_inputs():
    with pytest.raises(ValueError):
        decode_varint(bytes([0x00]), start=1)
    with pytest.raises(TypeError):
        decode_varint(["not", "bytes"])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        decode_varint([300])
