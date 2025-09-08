#!/usr/bin/env python3
"""
Main entry point for Advanced Lua Deobfuscator
Supports multiple normalization methods including Luraph-specific handling
"""

import argparse
import sys
import os
import logging

# Add src directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(current_dir, 'src')
sys.path.insert(0, src_dir)

try:
    from hex_number_normalizer import HexNumberNormalizer
except ImportError as e:
    print(f"Error importing HexNumberNormalizer: {e}")
    sys.exit(1)

def setup_logger(verbose: bool):
    """Configure logging based on verbosity"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s'
    )

def interactive_prompt():
    """Prompt user for input when no arguments are provided"""
    print("Advanced Lua Deobfuscator - Interactive Mode")
    input_file = input("Enter path to Lua file: ").strip()
    while not os.path.isfile(input_file):
        print("File not found. Try again.")
        input_file = input("Enter path to Lua file: ").strip()

    output_file = input("Enter output file path (leave blank for default): ").strip()
    method = input("Normalization method (default/luraph) [default]: ").strip() or "default"
    analyze_input = input("Analyze only? (y/N): ").strip().lower()
    analyze = analyze_input == "y"
    verbose_input = input("Enable verbose logging? (y/N): ").strip().lower()
    verbose = verbose_input == "y"

    return input_file, output_file, method, analyze, verbose

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Lua Deobfuscator - normalize numbers and strings in Lua code"
    )
    parser.add_argument('--file', '-f', help='Input Lua file to deobfuscate')
    parser.add_argument('--output', '-o', help='Output Lua file (default: adds _deobfuscated)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--analyze', action='store_true', help='Analyze only, no modifications applied')
    parser.add_argument('--method', choices=['default', 'luraph'], default='default', help='Normalization method')

    if len(sys.argv) == 1:
        # No arguments provided → interactive mode
        input_path, output_path, method, analyze, verbose = interactive_prompt()
    else:
        args = parser.parse_args()
        input_path = args.file
        output_path = args.output
        method = args.method
        analyze = args.analyze
        verbose = args.verbose

        if not input_path:
            parser.print_help()
            sys.exit(1)

    setup_logger(verbose)
    logger = logging.getLogger(__name__)

    if not os.path.isfile(input_path):
        logger.error(f"Input file does not exist: {input_path}")
        sys.exit(1)

    output_path = output_path or f"{os.path.splitext(input_path)[0]}_deobfuscated.lua"

    with open(input_path, 'r', encoding='utf-8') as f:
        code = f.read()

    normalizer = HexNumberNormalizer()

    if analyze:
        logger.info("Analyzing Lua code without modification...")
        normalized_code = code  # No changes
    else:
        logger.info(f"Applying all normalizations (method={method})...")
        normalized_code = normalizer.apply_all_normalizations(code)

        # Luraph-specific tweaks
        if method == 'luraph':
            logger.info("Applying Luraph-specific normalizations...")
            import re
            normalized_code = re.sub(r'__LURAPH__\d+\s*\([^)]*\)', '', normalized_code)
            normalized_code = re.sub(r'""\s*\.\s*', '', normalized_code)
            normalized_code = re.sub(r'\.\s*""', '', normalized_code)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(normalized_code)

    logger.info(f"Deobfuscated Lua code written to: {output_path}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
