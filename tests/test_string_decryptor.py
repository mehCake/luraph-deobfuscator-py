import base64

from string_decryptor import StringDecryptor


def test_layered_xor_base64_hex_round_trip():
    plain = "secret value"
    hex_layer = plain.encode("utf-8").hex()
    base64_layer = base64.b64encode(hex_layer.encode("utf-8")).decode("ascii")
    key = " "  # XOR with space keeps characters printable
    xor_layer = "".join(chr(ord(ch) ^ ord(key)) for ch in base64_layer)
    xor_layer_escaped = xor_layer.replace("\\", "\\\\").replace('"', '\\"')

    lua_snippet = f'return xor_layer("{xor_layer_escaped}", "{key}")'

    decrypted = StringDecryptor().decrypt(lua_snippet)
    assert plain in decrypted

    # ensure decode -> encode round trips the original cipher text
    reconstructed_hex = plain.encode("utf-8").hex()
    reconstructed_base64 = base64.b64encode(reconstructed_hex.encode("utf-8")).decode("ascii")
    reconstructed_xor = "".join(chr(ord(ch) ^ ord(key)) for ch in reconstructed_base64)
    assert reconstructed_xor == xor_layer


def test_inline_closure_and_loadstring_are_folded():
    source = """
    local a = (function() return "hello" .. " " .. "world" end)()
    local b = loadstring("return 'ok'")()
    return a .. b
    """

    decrypted = StringDecryptor().decrypt(source)
    assert "function" not in decrypted
    assert "loadstring" not in decrypted
    assert '"hello world"' in decrypted
    assert "'ok'" in decrypted
