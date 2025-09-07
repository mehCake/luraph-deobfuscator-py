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
        """Convert hexadecimal number to decimal."""
        try:
            # Handle different hex formats
            if 'p' in hex_str.lower() or 'P' in hex_str:
                # Hexadecimal float with binary exponent
                return str(float.fromhex('0x' + hex_str))
            else:
                # Regular hex number
                if '.' in hex_str:
                    # Hex float
                    return str(float.fromhex('0x' + hex_str))
                else:
                    # Hex integer
                    return str(int(hex_str, 16))
        except (ValueError, OverflowError):
            self.logger.warning(f"Could not convert hex number: {hex_str}")
            return f"0x{hex_str}"

    def normalize_scientific_notation(self, sci_str: str) -> str:
        """Convert scientific notation to regular number if reasonable."""
        try:
            value = float(sci_str)
            
            # If the result is a clean integer, return as int
            if value.is_integer() and abs(value) < 1e15:
                return str(int(value))
            
            # If it's a reasonable float, return as float
            if abs(value) < 1e10 and abs(value) > 1e-6:
                formatted = f"{value:.10f}".rstrip('0').rstrip('.')
                return formatted if '.' in formatted else f"{formatted}.0"
            
            # Keep scientific notation for very large/small numbers
            return sci_str
        except (ValueError, OverflowError):
            self.logger.warning(f"Could not convert scientific notation: {sci_str}")
            return sci_str

    def normalize_hex_string(self, hex_byte: str) -> str:
        """Convert hex escape sequence to character."""
        try:
            char_code = int(hex_byte, 16)
            if 32 <= char_code <= 126:  # Printable ASCII
                char = chr(char_code)
                # Escape special Lua characters
                if char in '"\'\\':
                    return f"\\{char}"
                return char
            else:
                # Keep as hex escape for non-printable
                return f"\\x{hex_byte}"
        except ValueError:
            return f"\\x{hex_byte}"

    def normalize_unicode_escape(self, unicode_hex: str) -> str:
        """Convert unicode escape to character if printable."""
        try:
            char_code = int(unicode_hex, 16)
            char = chr(char_code)
            
            # Only convert printable characters
            if char.isprintable() and char not in '"\'\\':
                return char
            else:
                return f"\\u{unicode_hex}"
        except (ValueError, UnicodeDecodeError):
            return f"\\u{unicode_hex}"

    def normalize_octal_escape(self, octal_str: str) -> str:
        """Convert octal escape to character if printable."""
        try:
            char_code = int(octal_str, 8)
            if 32 <= char_code <= 126:  # Printable ASCII
                char = chr(char_code)
                if char in '"\'\\':
                    return f"\\{char}"
                return char
            else:
                return f"\\{octal_str}"
        except ValueError:
            return f"\\{octal_str}"

    def normalize_all_numbers(self, code: str) -> str:
        """Normalize all number formats in the code."""
        self.logger.info("Starting number normalization...")
        
        normalized_code = code
        normalization_count = 0
        
        # Normalize hex numbers
        def hex_replacer(match):
            nonlocal normalization_count
            hex_num = match.group(1)
            normalized = self.normalize_hex_number(hex_num)
            if normalized != f"0x{hex_num}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(self.patterns['hex_numbers'], hex_replacer, normalized_code)
        
        # Normalize scientific notation
        def sci_replacer(match):
            nonlocal normalization_count
            sci_num = match.group(1)
            normalized = self.normalize_scientific_notation(sci_num)
            if normalized != sci_num:
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(self.patterns['scientific_notation'], sci_replacer, normalized_code)
        
        # Normalize hex string escapes
        def hex_string_replacer(match):
            nonlocal normalization_count
            hex_byte = match.group(1)
            normalized = self.normalize_hex_string(hex_byte)
            if normalized != f"\\x{hex_byte}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(r'\\x([0-9a-fA-F]{2})', hex_string_replacer, normalized_code)
        
        # Normalize unicode escapes
        def unicode_replacer(match):
            nonlocal normalization_count
            unicode_hex = match.group(1)
            normalized = self.normalize_unicode_escape(unicode_hex)
            if normalized != f"\\u{unicode_hex}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(r'\\u([0-9a-fA-F]{4})', unicode_replacer, normalized_code)
        
        # Normalize octal escapes
        def octal_replacer(match):
            nonlocal normalization_count
            octal_str = match.group(1)
            normalized = self.normalize_octal_escape(octal_str)
            if normalized != f"\\{octal_str}":
                normalization_count += 1
            return normalized
        
        normalized_code = re.sub(r'\\(\d{3})', octal_replacer, normalized_code)
        
        # Clean up floating point numbers (remove unnecessary .0)
        def float_cleaner(match):
            float_str = match.group(1)
            try:
                value = float(float_str)
                if value.is_integer():
                    return str(int(value))
                else:
                    # Remove trailing zeros
                    cleaned =```python
                    cleaned = f"{value:.10f}".rstrip('0').rstrip('.')
                    return cleaned if '.' in cleaned else str(int(float(cleaned)))
            except ValueError:
                return float_str
        
        normalized_code = re.sub(r'\b(\d+\.\d*)\b', float_cleaner, normalized_code)
        
        self.logger.info(f"Number normalization completed. {normalization_count} normalizations applied.")
        return normalized_code

    def normalize_string_literals(self, code: str) -> str:
        """Normalize string literals by converting escape sequences to actual characters where appropriate."""
        self.logger.info("Starting string literal normalization...")
        
        def normalize_string_content(match):
            quote_char = match.group(1)
            content = match.group(2)
            
            # Don't normalize if it contains the same quote character
            if quote_char in content:
                return match.group(0)
            
            # Apply escape sequence normalizations
            normalized_content = content
            
            # Normalize common escape sequences
            escape_map = {
                '\\n': '\n',
                '\\t': '\t',
                '\\r': '\r',
                '\\b': '\b',
                '\\f': '\f',
                '\\v': '\v',
                '\\0': '\0'
            }
            
            for escape_seq, char in escape_map.items():
                if escape_seq in normalized_content:
                    normalized_content = normalized_content.replace(escape_seq, char)
            
            return f'{quote_char}{normalized_content}{quote_char}'
        
        # Match string literals (both single and double quotes)
        pattern = r'(["\'])((?:\\.|[^\\])*?)\1'
        normalized_code = re.sub(pattern, normalize_string_content, code)
        
        self.logger.info("String literal normalization completed.")
        return normalized_code

    def apply_all_normalizations(self, code: str) -> str:
        """Apply all normalization techniques to the code."""
        self.logger.info("Starting comprehensive code normalization...")
        
        # Apply normalizations in order
        normalized = code
        normalized = self.normalize_whitespace(normalized)
        normalized = self.normalize_all_numbers(normalized)
        normalized = self.normalize_string_literals(normalized)
        
        self.logger.info("All normalizations completed.")
        return normalized
```

<CodePalArtifact entry="main.py" id="code-normalizer" title="Code Normalizer Tool">
<CodePalFile path="main.py" language="python" description="Main script to demonstrate the CodeNormalizer functionality" tags="python, main, demo, cli" related-files="code_normalizer.py">
#!/usr/bin/env python3
"""
Main script for demonstrating the CodeNormalizer functionality.
"""

import sys
import argparse
from pathlib import Path
from code_normalizer import CodeNormalizer

def main():
    parser = argparse.ArgumentParser(description="Normalize code for better analysis")
    parser.add_argument("input_file", help="Input file to normalize")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Initialize normalizer
    normalizer = CodeNormalizer(debug=args.verbose)
    
    # Read input file
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1
    
    # Normalize code
    try:
        normalized_code = normalizer.apply_all_normalizations(code)
    except Exception as e:
        print(f"Error during normalization: {e}", file=sys.stderr)
        return 1
    
    # Output result
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(normalized_code)
            print(f"Normalized code written to '{args.output}'")
        except Exception as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            return 1
    else:
        print(normalized_code)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())