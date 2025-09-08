# code_normalizer.py

import re

class CodeNormalizer:
    
    def normalize_hex_number(self, value: str) -> str:
        # Convert hex string (case insensitive) to decimal
        return str(int(value, 16))
    
    def normalize_scientific_notation(self, value: str) -> str:
        # Convert scientific notation to float string
        return str(float(value))
    
    def normalize_hex_string(self, hex_str: str) -> str:
        val = int(hex_str, 16)
        # Printable ASCII (32-126) except quotes/backslash
        if 32 <= val <= 126 and val not in (34, 39, 92):
            return chr(val)
        # Otherwise return escaped
        return f"\\x{hex_str.upper()}"
    
    def normalize_unicode_escape(self, hex_str: str) -> str:
        val = int(hex_str, 16)
        if 32 <= val <= 126 and val not in (34, 39, 92):
            return chr(val)
        return f"\\u{hex_str.zfill(4).upper()}"
    
    def normalize_octal_escape(self, oct_str: str) -> str:
        val = int(oct_str, 8)
        if 32 <= val <= 126 and val not in (34, 39, 92):
            return chr(val)
        # Handle special escape chars
        if val == 34:
            return '\\"'
        if val == 39:
            return "\\'"
        if val == 92:
            return "\\\\"
        return f"\\{oct_str.zfill(3)}"
    
    def normalize_whitespace(self, code: str) -> str:
        # Replace tabs with space
        code = code.replace('\t', ' ')
        # Collapse multiple spaces into one
        code = re.sub(r' +', ' ', code)
        # Collapse multiple newlines into max 2
        code = re.sub(r'\n{3,}', '\n\n', code)
        return code.strip()
    
    def normalize_all_numbers(self, code: str) -> str:
        # Normalize hex numbers: 0xFF -> decimal
        code = re.sub(
            r'0x([0-9A-Fa-f]+)',
            lambda m: str(int(m.group(1), 16)),
            code
        )
        # Normalize scientific notation
        code = re.sub(
            r'(\d+\.?\d*)[eE]([+-]?\d+)',
            lambda m: str(float(m.group(0))),
            code
        )
        # Replace string hex and unicode escapes
        code = re.sub(
            r'\\x([0-9A-Fa-f]{2})',
            lambda m: self.normalize_hex_string(m.group(1)),
            code
        )
        code = re.sub(
            r'\\u([0-9A-Fa-f]{4})',
            lambda m: self.normalize_unicode_escape(m.group(1)),
            code
        )
        # Remove unnecessary .0 from floats
        code = re.sub(r'(\d+)\.0\b', r'\1', code)
        return code
