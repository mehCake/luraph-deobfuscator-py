#!/usr/bin/env python3
"""
Advanced Lua Deobfuscator - Fixed Entry Point with Method Checks
Comprehensive tool for deobfuscating Lua code with advanced pattern recognition
"""

import sys
import os
import logging
import argparse
import json
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from deobfuscator import LuaDeobfuscator
    from utils import setup_logging, validate_file, create_output_path
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

def load_config():
    """Load configuration from config.json"""
    config_path = Path(__file__).parent / 'config.json'
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning("Invalid config.json, using defaults")
    return {}

def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Advanced Lua Deobfuscator',
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

def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    try:
        setup_logging(log_level)
    except Exception:
        logging.basicConfig(level=log_level)
    
    logger = logging.getLogger(__name__)
    
    try:
        # Validate input file
        if not validate_file(args.input):
            logger.error(f"Input file not found or not readable: {args.input}")
            return 1
        
        # Load configuration
        config = load_config()
        if args.config:
            try:
                with open(args.config, 'r') as f:
                    config.update(json.load(f))
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
        
        # Read input file
        logger.info(f"Reading input file: {args.input}")
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        if not code.strip():
            logger.error("Input file is empty")
            return 1
        
        # Initialize deobfuscator
        deobfuscator = LuaDeobfuscator(config)

        # Ensure required methods exist
        if not all(hasattr(deobfuscator, m) for m in ['analyze_code', 'deobfuscate']):
            logger.error("LuaDeobfuscator missing required methods")
            return 1
        
        if args.analyze:
            logger.info("Analyzing code...")
            try:
                analysis = deobfuscator.analyze_code(code)
                
                print("\n" + "="*60)
                print("ANALYSIS RESULTS")
                print("="*60)
                
                print(f"File size: {len(code)} bytes")
                print(f"Lines of code: {len(code.splitlines())}")
                
                if analysis.get('obfuscated', False):
                    print("Status: OBFUSCATED")
                    confidence = analysis.get('confidence', 0)
                    if confidence <= 1:
                        print(f"Confidence: {confidence:.1%}")
                    else:
                        print(f"Confidence: {confidence}%")
                    
                    if 'method' in analysis:
                        print(f"Detected method: {analysis['method']}")
                    
                    if 'patterns' in analysis and analysis['patterns']:
                        print("\nDetected patterns:")
                        for pattern in analysis['patterns']:
                            print(f"  - {pattern}")
                    
                    if 'complexity' in analysis:
                        complexity = analysis['complexity']
                        print(f"\nComplexity metrics:")
                        print(f"  - Control flow: {complexity.get('control_flow', 0)}")
                        print(f"  - String obfuscation: {complexity.get('string_obfuscation', 0)}")
                        print(f"  - Variable mangling: {complexity.get('variable_mangling', 0)}")
                else:
                    print("Status: CLEAN (not obfuscated)")
                
                print("="*60)
                
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                return 1
        else:
            logger.info("Starting deobfuscation process...")
            try:
                analysis = deobfuscator.analyze_code(code)
                
                if not analysis.get('obfuscated', False):
                    logger.info("Code appears clean, no deobfuscation needed")
                    deobfuscated_code = code
                else:
                    logger.info(f"Detected obfuscation method: {analysis.get('method', 'unknown')}")
                    deobfuscated_code = deobfuscator.deobfuscate(code, args.method)
                
                if not args.output:
                    args.output = create_output_path(args.input)
                
                output_dir = os.path.dirname(args.output)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                
                logger.info(f"Writing deobfuscated code to: {args.output}")
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(deobfuscated_code)
                
                logger.info("Deobfuscation completed successfully!")
                
                original_lines = len(code.splitlines())
                deobfuscated_lines = len(deobfuscated_code.splitlines())
                
                print(f"\nStatistics:")
                print(f"  Original size: {len(code)} bytes ({original_lines} lines)")
                print(f"  Deobfuscated size: {len(deobfuscated_code)} bytes ({deobfuscated_lines} lines)")
                
            except Exception as e:
                logger.error(f"Deobfuscation failed: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                return 1
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
