#!/usr/bin/env python3
"""
Advanced Lua Deobfuscator - Full Corrected Script with LPH Support
Comprehensive tool for deobfuscating Lua code with advanced pattern recognition
"""

import sys
import os
import re
import json
import base64
import logging
import argparse
from pathlib import Path

# Add src directory to Python path (if needed for utils)
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

# =======================
# Utility Functions
# =======================
def setup_logging(level=logging.INFO):
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=level
    )

def validate_file(filepath):
    return os.path.isfile(filepath) and os.access(filepath, os.R_OK)

def create_output_path(input_file):
    base, ext = os.path.splitext(input_file)
    return f"{base}_deobfuscated{ext}"

# =======================
# Lua String Extractor
# =======================
class StringExtractor:
    """Extract different types of obfuscated strings"""
    
    def extract_hex_strings(self, code):
        pattern = r'"(\\x[0-9a-fA-F]{2})+"'
        return [{'full_string': m.group(0)} for m in re.finditer(pattern, code)]

    def extract_base64_strings(self, code):
        pattern = r'["\']([A-Za-z0-9+/=]{8,})["\']'
        return [{'full_string': m.group(1)} for m in re.finditer(pattern, code)]

    def extract_concatenated_strings(self, code):
        pattern = r'(".*?")(?:\s*\.\s*".*?")+'
        return [{'full_string': m.group(0)} for m in re.finditer(pattern, code)]

    def extract_lph_strings(self, code):
        # Luraph strings usually look like: _LPH("encoded_string")
        pattern = r'_LPH\(["\'](.*?)["\']\)'
        return [{'full_string': m.group(0), 'content': m.group(1)} for m in re.finditer(pattern, code)]

# =======================
# Lua Deobfuscator
# =======================
class LuaDeobfuscator:
    def __init__(self, config=None):
        self.config = config or {}
        self.extractor = StringExtractor()
        self.logger = logging.getLogger(__name__)

    # -------------
    # Analysis
    # -------------
    def analyze_code(self, code):
        analysis = {
            'obfuscated': False,
            'confidence': 0.0,
            'method': None,
            'patterns': [],
            'complexity': {}
        }

        hex_strings = self.extractor.extract_hex_strings(code)
        base64_strings = self.extractor.extract_base64_strings(code)
        concat_strings = self.extractor.extract_concatenated_strings(code)
        lph_strings = self.extractor.extract_lph_strings(code)

        total_matches = len(hex_strings) + len(base64_strings) + len(concat_strings) + len(lph_strings)
        if total_matches > 0:
            analysis['obfuscated'] = True
            analysis['confidence'] = min(1.0, total_matches / 50.0)
            patterns = []
            if hex_strings: patterns.append('hex-encoded strings')
            if base64_strings: patterns.append('base64-encoded strings')
            if concat_strings: patterns.append('concatenated strings')
            if lph_strings: patterns.append('Luraph (LPH) strings')
            analysis['patterns'] = patterns

        analysis['complexity'] = {
            'control_flow': code.count('function'),
            'string_obfuscation': len(base64_strings) + len(hex_strings) + len(lph_strings),
            'variable_mangling': len(re.findall(r'\b[a-zA-Z_]{1,2}\b', code))
        }

        return analysis

    # -------------
    # Deobfuscation
    # -------------
    def deobfuscate(self, code, method=None):
        # Step 1: Decode hex strings
        for hex_info in self.extractor.extract_hex_strings(code):
            hex_str = hex_info['full_string']
            decoded = self._process_hex_string(hex_str)
            code = code.replace(hex_str, f'"{decoded}"')

        # Step 2: Decode base64 strings
        for b64_info in self.extractor.extract_base64_strings(code):
            b64_str = b64_info['full_string']
            decoded = self._process_base64_string(b64_str)
            code = code.replace(f'"{b64_str}"', f'"{decoded}"')

        # Step 3: Decode concatenated strings
        for concat_info in self.extractor.extract_concatenated_strings(code):
            concat_str = concat_info['full_string']
            decoded = self._process_concatenated_string(concat_str)
            code = code.replace(concat_str, f'"{decoded}"')

        # Step 4: Decode Luraph strings
        for lph_info in self.extractor.extract_lph_strings(code):
            full_str = lph_info['full_string']
            content = lph_info['content']
            decoded = self._process_lph_string(content)
            code = code.replace(full_str, f'"{decoded}"')

        return code

    # ------------------------
    # Internal helper methods
    # ------------------------
    def _process_hex_string(self, s):
        s = s.strip('"').strip("'")
        try:
            bytes_str = bytes(int(h, 16) for h in re.findall(r'\\x([0-9a-fA-F]{2})', s))
            return bytes_str.decode('utf-8', errors='ignore')
        except Exception:
            return s

    def _process_base64_string(self, s):
        try:
            s_bytes = base64.b64decode(s)
            return s_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return s

    def _process_concatenated_string(self, s):
        parts = re.findall(r'"(.*?)"', s)
        return ''.join(parts)

    def _process_lph_string(self, s):
        """
        Basic LPH decoding (simple XOR-based decoding typical in Luraph)
        """
        try:
            decoded = ''.join(chr(ord(c) ^ 0x55) for c in s)
            return decoded
        except Exception:
            return s

# =======================
# Command-line interface
# =======================
def create_parser():
    parser = argparse.ArgumentParser(
        description='Advanced Lua Deobfuscator with LPH Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py script.lua                    # Basic deobfuscation
  python run.py script.lua --analyze          # Analysis mode only
  python run.py script.lua -o clean.lua       # Specify output file
  python run.py script.lua --verbose          # Verbose output
  python run.py script.lua --method luraph    # Specific method
        """
    )
    parser.add_argument('input', help='Input Lua file to deobfuscate')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--analyze', action='store_true', help='Run analysis only')
    parser.add_argument('--method', choices=['generic', 'luraph', 'ironbrew'], 
                        help='Deobfuscation method')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--config', help='Configuration file path')
    return parser

def load_config(config_path=None):
    default_config_path = Path(__file__).parent / 'config.json'
    path = Path(config_path) if config_path else default_config_path
    if path.exists():
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            logging.warning("Invalid JSON config, using defaults")
    return {}

def main():
    parser = create_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    logger = logging.getLogger(__name__)

    if not validate_file(args.input):
        logger.error(f"Input file not found or not readable: {args.input}")
        return 1

    config = load_config(args.config)

    with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()

    if not code.strip():
        logger.error("Input file is empty")
        return 1

    deobfuscator = LuaDeobfuscator(config)

    if args.analyze:
        logger.info("Analyzing code...")
        analysis = deobfuscator.analyze_code(code)

        print("\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)
        print(f"File size: {len(code)} bytes")
        print(f"Lines of code: {len(code.splitlines())}")
        if analysis['obfuscated']:
            print("Status: OBFUSCATED")
            print(f"Confidence: {analysis['confidence']:.1%}")
            if analysis['method']:
                print(f"Detected method: {analysis['method']}")
            if analysis['patterns']:
                print("\nDetected patterns:")
                for pattern in analysis['patterns']:
                    print(f"  - {pattern}")
            print("\nComplexity metrics:")
            for k, v in analysis['complexity'].items():
                print(f"  - {k}: {v}")
        else:
            print("Status: CLEAN (not obfuscated)")
        print("="*60)
    else:
        logger.info("Starting deobfuscation...")
        deobfuscated_code = deobfuscator.deobfuscate(code, args.method)

        output_file = args.output or create_output_path(args.input)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(deobfuscated_code)

        logger.info(f"Deobfuscated code written to: {output_file}")
        print(f"\nOriginal size: {len(code)} bytes, lines: {len(code.splitlines())}")
        print(f"Deobfuscated size: {len(deobfuscated_code)} bytes, lines: {len(deobfuscated_code.splitlines())}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
