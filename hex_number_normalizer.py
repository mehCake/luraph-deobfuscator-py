import re
import math
import logging
from typing import Union, Optional

class HexNumberNormalizer:
    """Normalizes various number formats in Lua code (hex, float, scientific notation)."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Number patterns
        self.patterns = {
            'hex_numbers': r'0[xX]([0-9a-fA-F]+(?:\.[0-9a-fA-F]*)?(?:[pP][+-]?\d+)?)',
            'scientific_notation': r'(\d+(?:\.\d*)?[eE][+-]?\d+)',
            'float_numbers': r'(\d+\.\d+)',
            'hex_strings': r'\\x([0-9a-fA-F]{2})',
            'unicode_escapes': r'\\u([0-9a-fA-F]{4})',
            'octal_numbers': r'\\(\d{3})',
        }

    def normalize_hex_number(self, hex_str: str) -> str:
        try:
            if 'p' in hex_str.lower():
                return str(float.fromhex('0x' + hex_str))
            else:
                if '.' in hex_str:
                    return str(float.fromhex('0x' + hex_str))
                else:
                    return str(int(hex_str, 16))
        except (ValueError, OverflowError):
            self.logger.warning(f"Could not convert hex number: {hex_str}")
            return f"0x{hex_str}"

    def normalize_scientific_notation(self, sci_str: str) -> str:
        try:
            value = float(sci_str)
            if value.is_integer() and abs(value) < 1e15:
                return str(int(value))
            if 1e-6 < abs(value) < 1e10:
                formatted = f"{value:.10f}".rstrip('0').rstrip('.')
                return formatted if '.' in formatted else f"{formatted}.0"
            return sci_str
        except (ValueError, OverflowError):
            self.logger.warning(f"Could not convert scientific notation: {sci_str}")
            return sci_str

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

        # Hex numbers
        def hex_replacer(match):
            nonlocal normalization_count
            hex_num = match.group(1)
            normalized = self.normalize_hex_number(hex_num)
            if normalized != f"0x{hex_num}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(self.patterns['hex_numbers'], hex_replacer, normalized_code)

        # Scientific notation
        def sci_replacer(match):
            nonlocal normalization_count
            sci_num = match.group(1)
            normalized = self.normalize_scientific_notation(sci_num)
            if normalized != sci_num:
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(self.patterns['scientific_notation'], sci_replacer, normalized_code)

        # Hex string
        def hex_string_replacer(match):
            nonlocal normalization_count
            hex_byte = match.group(1)
            normalized = self.normalize_hex_string(hex_byte)
            if normalized != f"\\x{hex_byte}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(r'\\x([0-9a-fA-F]{2})', hex_string_replacer, normalized_code)

        # Unicode
        def unicode_replacer(match):
            nonlocal normalization_count
            unicode_hex = match.group(1)
            normalized = self.normalize_unicode_escape(unicode_hex)
            if normalized != f"\\u{unicode_hex}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(r'\\u([0-9a-fA-F]{4})', unicode_replacer, normalized_code)

        # Octal
        def octal_replacer(match):
            nonlocal normalization_count
            octal_str = match.group(1)
            normalized = self.normalize_octal_escape(octal_str)
            if normalized != f"\\{octal_str}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(r'\\(\d{3})', octal_replacer, normalized_code)

        # Floating point cleanup
        def float_cleaner(match):
            float_str = match.group(1)
            try:
                value = float(float_str)
                if value.is_integer():
                    return str(int(value))
                cleaned = f"{value:.10f}".rstrip('0').rstrip('.')
                return cleaned if '.' in cleaned else str(int(float(cleaned)))
            except ValueError:
                return float_str

        normalized_code = re.sub(r'\b(\d+\.\d*)\b', float_cleaner, normalized_code)
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
