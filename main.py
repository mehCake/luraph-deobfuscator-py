#!/usr/bin/env python3
"""
Advanced Lua Deobfuscator - Main Entry Point
Supports interactive CLI, command-line arguments, and GUI modes
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from typing import Optional, List

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.deobfuscator import LuaDeobfuscator
from src.gui_handler import show_interactive_menu
from src.url_handler import URLHandler
from src.utils import setup_logging, colorize_text, show_banner
from src.batch_processor import BatchProcessor

def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Advanced Lua Deobfuscator - Handles Luraph, LuaMor, and custom obfuscators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                    # Interactive mode
  python main.py --file script.txt                 # Basic file processing
  python main.py --url https://pastebin.com/raw/abc # Process URL
  python main.py --batch folder/ --output out/     # Batch processing
  python main.py --file script.txt --method luraph --beautify
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--file", "-f", type=str, help="Input file path")
    input_group.add_argument("--url", "-u", type=str, help="URL to process (supports Pastebin)")
    input_group.add_argument("--batch", "-b", type=str, help="Batch process directory")
    
    # Output options
    parser.add_argument("--output", "-o", type=str, help="Output file/directory path")
    
    # Deobfuscation methods
    parser.add_argument("--method", "-m", 
                       choices=["auto", "luraph", "luamor", "generic", "advanced"],
                       default="auto", help="Deobfuscation method")
    
    # Feature flags
    parser.add_argument("--recursive", action="store_true", 
                       help="Enable recursive loadstring resolution")
    parser.add_argument("--vm-simulation", action="store_true",
                       help="Use full VM emulation")
    parser.add_argument("--pattern-analysis", action="store_true",
                       help="Enable opcode pattern detection")
    parser.add_argument("--trap-removal", action="store_true",
                       help="Remove anti-deobfuscation traps")
    parser.add_argument("--beautify", action="store_true",
                       help="Apply code formatting and variable renaming")
    parser.add_argument("--constants", action="store_true",
                       help="Extract dynamic constants")
    
    # Utility options
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--config", type=str, default="config.json", help="Configuration file")
    parser.add_argument("--gui", action="store_true", help="Show GUI interface")
    
    return parser

def process_single_file(file_path: str, args: argparse.Namespace) -> bool:
    """Process a single file"""
    try:
        if not os.path.exists(file_path):
            print(colorize_text(f"Error: File '{file_path}' not found", "red"))
            return False
            
        print(colorize_text(f"Processing file: {file_path}", "cyan"))
        
        # Initialize deobfuscator
        deobfuscator = LuaDeobfuscator(config_path=args.config)
        
        # Configure options
        options = {
            'recursive': args.recursive,
            'vm_simulation': args.vm_simulation,
            'pattern_analysis': args.pattern_analysis,
            'trap_removal': args.trap_removal,
            'beautify': args.beautify,
            'constants': args.constants,
            'method': args.method
        }
        
        # Process file
        result = deobfuscator.process_file(file_path, options)
        
        if result and result.get('success'):
            output_path = args.output or f"{Path(file_path).stem}_deobfuscated.lua"
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(result['deobfuscated_code'])
                
            print(colorize_text(f"Successfully deobfuscated to: {output_path}", "green"))
            
            # Show statistics
            if 'statistics' in result:
                stats = result['statistics']
                print(f"Statistics:")
                print(f"  - Method used: {stats.get('method', 'Unknown')}")
                print(f"  - Processing time: {stats.get('time', 0):.2f}s")
                print(f"  - Lines processed: {stats.get('lines', 0)}")
                print(f"  - Patterns detected: {stats.get('patterns', 0)}")
                
            return True
        else:
            error_msg = result.get('error', 'Unknown error') if result else 'Processing failed'
            print(colorize_text(f"Failed to process file: {error_msg}", "red"))
            return False
            
    except Exception as e:
        print(colorize_text(f"Error processing file: {str(e)}", "red"))
        logging.error(f"File processing error: {str(e)}", exc_info=True)
        return False

def process_url(url: str, args: argparse.Namespace) -> bool:
    """Process a URL"""
    try:
        print(colorize_text(f"Fetching content from: {url}", "cyan"))
        
        url_handler = URLHandler()
        content = url_handler.fetch_content(url)
        
        if not content:
            print(colorize_text("Failed to fetch content from URL", "red"))
            return False
            
        # Save to temporary file and process
        temp_file = "temp_downloaded_script.txt"
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(content)
            
        # Process the temporary file
        success = process_single_file(temp_file, args)
        
        # Clean up
        try:
            os.remove(temp_file)
        except:
            pass
            
        return success
        
    except Exception as e:
        print(colorize_text(f"Error processing URL: {str(e)}", "red"))
        logging.error(f"URL processing error: {str(e)}", exc_info=True)
        return False

def process_batch(batch_dir: str, args: argparse.Namespace) -> bool:
    """Process batch directory"""
    try:
        print(colorize_text(f"Processing batch directory: {batch_dir}", "cyan"))
        
        processor = BatchProcessor(config_path=args.config)
        
        options = {
            'recursive': args.recursive,
            'vm_simulation': args.vm_simulation,
            'pattern_analysis': args.pattern_analysis,
            'trap_removal': args.trap_removal,
            'beautify': args.beautify,
            'constants': args.constants,
            'method': args.method
        }
        
        output_dir = args.output or f"{batch_dir}_deobfuscated"
        results = processor.process_directory(batch_dir, output_dir, options)
        
        # Show results
        successful = sum(1 for r in results if r.get('success'))
        total = len(results)
        
        print(colorize_text(f"Batch processing completed: {successful}/{total} files processed successfully", "green"))
        
        return successful > 0
        
    except Exception as e:
        print(colorize_text(f"Error in batch processing: {str(e)}", "red"))
        logging.error(f"Batch processing error: {str(e)}", exc_info=True)
        return False

def main():
    """Main entry point"""
    # Show banner
    show_banner()
    
    # Parse arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)
    
    try:
        # Handle GUI mode
        if args.gui:
            show_interactive_menu()
            return
            
        # Handle command line arguments
        if args.file:
            success = process_single_file(args.file, args)
        elif args.url:
            success = process_url(args.url, args)
        elif args.batch:
            success = process_batch(args.batch, args)
        else:
            # Interactive mode
            print(colorize_text("Starting interactive mode...", "cyan"))
            show_interactive_menu()
            return
            
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(colorize_text("\nOperation cancelled by user", "yellow"))
        sys.exit(1)
    except Exception as e:
        print(colorize_text(f"Unexpected error: {str(e)}", "red"))
        logging.error(f"Main execution error: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
