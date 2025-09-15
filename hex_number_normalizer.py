import logging
import re
from typing import Union

class HexNumberNormalizer:
    """Normalizes various number formats in Lua code (hex, float, scientific notation)."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        self.patterns = {
            "hex": r"0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?(?:[pP][+-]?\d+)?",
            "scientific": r"\b\d+(?:\.\d*)?[eE][+-]?\d+\b",
            "float": r"\b\d+\.\d+\b",
            "hex_string": r"\\x([0-9a-fA-F]{2})",
            "unicode": r"\\u([0-9a-fA-F]{4})",
            "octal": r"\\(\d{3})",
        }

    # ------------------------------------------------------------------
    def parse_literal(self, literal: str) -> Union[int, float]:
        literal = literal.strip()
        if not literal:
            raise ValueError("empty literal")
        try:
            if literal.lower().startswith("0x"):
                if "p" in literal.lower() or "." in literal:
                    return float.fromhex(literal)
                return int(literal, 16)
            if literal.startswith("-") and literal[1:].lower().startswith("0x"):
                if "p" in literal.lower() or "." in literal:
                    return float.fromhex(literal)
                return int(literal, 16)
            if any(ch in literal for ch in "eE"):
                return float(literal)
            if "." in literal:
                value = float(literal)
                return int(value) if value.is_integer() else value
            return int(literal, 10)
        except ValueError as exc:
            raise ValueError(f"Unsupported numeric literal: {literal}") from exc

    def canonicalize_literal(self, literal: str) -> str:
        try:
            value = self.parse_literal(literal)
        except ValueError:
            return literal
        return self.format_literal(value)

    def format_literal(self, value: Union[int, float], prefer_hex: bool = False) -> str:
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        if isinstance(value, int):
            if prefer_hex:
                return hex(value)
            return str(value)
        if prefer_hex:
            return value.hex()
        text = f"{value:.12g}"
        if "e" in text or "E" in text:
            return text
        if value.is_integer():
            return str(int(value))
        return text.rstrip("0").rstrip(".") if "." in text else text

    def normalize_hex_string(self, hex_byte: str) -> str:
        try:
            char_code = int(hex_byte, 16)
            if 32 <= char_code <= 126:
                char = chr(char_code)
                if char in '"\'\\':
                    return f"\\{char}"
                return char
            else:
                return f"\\x{hex_byte}"
        except ValueError:
            return f"\\x{hex_byte}"

    def normalize_unicode_escape(self, unicode_hex: str) -> str:
        try:
            char_code = int(unicode_hex, 16)
            char = chr(char_code)
            if char.isprintable() and char not in '"\'\\':
                return char
            else:
                return f"\\u{unicode_hex}"
        except (ValueError, UnicodeDecodeError):
            return f"\\u{unicode_hex}"

    def normalize_octal_escape(self, octal_str: str) -> str:
        try:
            char_code = int(octal_str, 8)
            if 32 <= char_code <= 126:
                char = chr(char_code)
                if char in '"\'\\':
                    return f"\\{char}"
                return char
            else:
                return f"\\{octal_str}"
        except ValueError:
            return f"\\{octal_str}"

    def normalize_all_numbers(self, code: str) -> str:
        self.logger.info("Starting number normalization...")
        normalized_code = code
        normalization_count = 0

        def numeric_replacer(match: re.Match[str]) -> str:
            nonlocal normalization_count
            literal = match.group(0)
            normalized = self.canonicalize_literal(literal)
            if normalized != literal:
                normalization_count += 1
            return normalized

        normalized_code = re.sub(self.patterns["hex"], numeric_replacer, normalized_code)
        normalized_code = re.sub(self.patterns["scientific"], numeric_replacer, normalized_code)
        normalized_code = re.sub(self.patterns["float"], numeric_replacer, normalized_code)

        # Hex string
        def hex_string_replacer(match):
            nonlocal normalization_count
            hex_byte = match.group(1)
            normalized = self.normalize_hex_string(hex_byte)
            if normalized != f"\\x{hex_byte}":
                normalization_count += 1
            return normalized

        normalized_code = re.sub(self.patterns["hex_string"], hex_string_replacer, normalized_code)

        # Unicode
        def unicode_replacer(match):
            nonlocal normalization_count
            unicode_hex = match.group(1)
            normalized = self.normalize_unicode_escape(unicode_hex)
            if normalized != f"\\u{unicode_hex}":
                normalization_count += 1
            return normalized

        normalized_code = re.sub(self.patterns["unicode"], unicode_replacer, normalized_code)

        # Octal
        def octal_replacer(match):
            nonlocal normalization_count
            octal_str = match.group(1)
            normalized = self.normalize_octal_escape(octal_str)
            if normalized != f"\\{octal_str}":
                normalization_count += 1
            return normalized

        normalized_code = re.sub(self.patterns["octal"], octal_replacer, normalized_code)
        self.logger.info(f"Number normalization completed. {normalization_count} normalizations applied.")
        return normalized_code

    def normalize_string_literals(self, code: str) -> str:
        self.logger.info("Starting string literal normalization...")

        def normalize_string_content(match):
            quote_char = match.group(1)
            content = match.group(2)
            if quote_char in content:
                return match.group(0)
            normalized_content = content
            escape_map = {
                '\\n': '\n', '\\t': '\t', '\\r': '\r', '\\b': '\b',
                '\\f': '\f', '\\v': '\v', '\\0': '\0'
            }
            for k, v in escape_map.items():
                normalized_content = normalized_content.replace(k, v)
            return f'{quote_char}{normalized_content}{quote_char}'

        pattern = r'(["\'])((?:\\.|[^\\])*?)\1'
        normalized_code = re.sub(pattern, normalize_string_content, code)
        self.logger.info("String literal normalization completed.")
        return normalized_code

    def normalize_whitespace(self, code: str) -> str:
        """Normalize whitespace (remove trailing spaces, consistent indentation)."""
        return '\n'.join(line.rstrip() for line in code.splitlines())

    def apply_all_normalizations(self, code: str) -> str:
        self.logger.info("Starting comprehensive code normalization...")
        normalized = code
        normalized = self.normalize_whitespace(normalized)
        normalized = self.normalize_all_numbers(normalized)
        normalized = self.normalize_string_literals(normalized)
        self.logger.info("All normalizations completed.")
        return normalized
