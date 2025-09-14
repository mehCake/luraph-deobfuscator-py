import base64
import binascii
import json
import re
import zlib
from pathlib import Path
from typing import Optional

def _is_printable(s: str) -> bool:
    return all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in s)

def decode_json_format(content: str) -> Optional[str]:
    try:
        data = json.loads(content)
    except Exception:
        return None
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not (isinstance(first, list) and len(first) == 2):
        return None
    hex_key, stub = first
    try:
        key_bytes = binascii.unhexlify(hex_key)
    except Exception:
        return None
    decoded_segments = []
    for seg in data[1:]:
        if not isinstance(seg, str):
            continue
        try:
            decoded = ''.join(chr(ord(ch) ^ key_bytes[i % len(key_bytes)]) for i, ch in enumerate(seg))
            if _is_printable(decoded):
                decoded_segments.append(decoded)
            else:
                decoded_segments.append(seg)
        except Exception:
            decoded_segments.append(seg)
    return stub + ''.join(decoded_segments)

def decode_superflow(content: str) -> Optional[str]:
    match = re.search(r'superflow_bytecode_ext0\s*=\s*"([^"]+)"', content)
    if not match:
        return None
    data = bytes(int(n) for n in re.findall(r'\\(\d{1,3})', match.group(1)))
    # Try XOR + zlib with brute-force key search
    for key in range(256):
        xored = bytes(b ^ key for b in data)
        try:
            out = zlib.decompress(xored)
            return out.decode('utf-8', errors='ignore')
        except Exception:
            continue
    return None


def _decode_numeric_arrays(content: str) -> str:
    pattern = re.compile(r'\{(\s*\d+(?:\s*,\s*\d+)*)\s*\}')

    def repl(match: re.Match) -> str:
        nums = [int(n.strip()) for n in match.group(1).split(',')]
        try:
            text = ''.join(chr(n) for n in nums)
            if _is_printable(text):
                return f'"{text}"'
        except Exception:
            pass
        return match.group(0)

    return pattern.sub(repl, content)


def _decode_base64_strings(content: str) -> str:
    pattern = re.compile(r'"([A-Za-z0-9+/=]{8,})"')

    def repl(match: re.Match) -> str:
        s = match.group(1)
        try:
            decoded = base64.b64decode(s).decode('utf-8')
            if _is_printable(decoded):
                return f'"{decoded}"'
        except Exception:
            pass
        return match.group(0)

    return pattern.sub(repl, content)


def _decode_numeric_escapes(content: str) -> str:
    pattern = re.compile(r'"((?:\\\d{1,3})+)"')

    def repl(match: re.Match) -> str:
        nums = re.findall(r'\\(\d{1,3})', match.group(1))
        try:
            text = ''.join(chr(int(n)) for n in nums)
            if _is_printable(text):
                return f'"{text}"'
        except Exception:
            pass
        return match.group(0)

    return pattern.sub(repl, content)


def decode_simple_obfuscations(content: str) -> str:
    content = _decode_numeric_arrays(content)
    content = _decode_base64_strings(content)
    content = _decode_numeric_escapes(content)
    return content

def deobfuscate(path: str) -> str:
    content = Path(path).read_text()
    result = decode_json_format(content)
    if result is not None:
        return result
    result = decode_superflow(content)
    if result is not None:
        return result
    return decode_simple_obfuscations(content)

def main():
    import argparse
    p = argparse.ArgumentParser(description='Attempt to deobfuscate Luraph/Luarmor Lua files')
    p.add_argument('input', help='Input obfuscated file')
    p.add_argument('-o', '--output', help='Output path')
    args = p.parse_args()
    result = deobfuscate(args.input)
    out_path = args.output or (str(args.input) + '_deob.lua')
    Path(out_path).write_text(result)
    print(f'Deobfuscated output written to {out_path}')

if __name__ == '__main__':
    main()
