import sys
import os
import logging
import argparse
import re
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any, Tuple

from utils import (
    setup_logging, read_file_content, save_output, 
    get_output_filename, validate_input, print_banner,
    extract_nested_loadstrings, normalize_whitespace
)
from lph_handler import LPHStringExtractor
from lua_vm_simulator import LuaVMSimulator
from opcode_lifter import OpcodeLifter
from string_decryptor import StringDecryptor
from version_detector import VersionDetector
from pattern_analyzer import PatternAnalyzer
from constant_reconstructor import ConstantReconstructor
from trap_detector import TrapDetector
from variable_renamer import VariableRenamer

class EnhancedLuraphDeobfuscator:
    """
    Enhanced Luraph Deobfuscator with comprehensive pattern analysis,
    VM simulation, and advanced anti-obfuscation techniques.
    """
    
    def __init__(self, debug: bool = False):
        self.logger = logging.getLogger(__name__)
        self.debug = debug
        
        # Initialize all components
        self.lph_extractor = LPHStringExtractor()
        self.vm_simulator = LuaVMSimulator()
        self.opcode_lifter = OpcodeLifter()
        self.string_decryptor = StringDecryptor()
        self.version_detector = VersionDetector()
        self.pattern_analyzer = PatternAnalyzer()
        self.constant_reconstructor = ConstantReconstructor()
        self.trap_detector = TrapDetector()
        self.variable_renamer = VariableRenamer()
        
        # Statistics
        self.stats = {
            'patterns_detected': 0,
            'constants_reconstructed': 0,
            'traps_removed': 0,
            'loadstrings_resolved': 0,
            'variables_renamed': 0
        }
    
    def download_from_url(self, url: str) -> str:
        """Network access has been disabled for safety reasons."""

        raise RuntimeError(
            "Downloading sources is not supported. Save the script locally and "
            "provide the file path instead."
        )
    
    def process_input(self, input_path: str) -> str:
        """Process input from file or URL."""
        parsed = urlparse(input_path)
        if parsed.scheme in {"http", "https"}:
            raise ValueError(
                "Network sources are not allowed. Provide a local file path instead."
            )
        return read_file_content(input_path)
    
    def detect_obfuscation_type(self, content: str) -> Dict[str, Any]:
        """Detect the type and version of obfuscation."""
        self.logger.info("Detecting obfuscation type and version...")
        
        # Use version detector
        version_info = self.version_detector.detect_version(content)
        
        # Enhanced detection patterns
        detection_patterns = {
            'luraph_v9': [
                r'local\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*{[^}]*}',
                r'loadstring\([^)]*\)\(\)',
                r'getfenv\(\)\[.*?\]',
                r'setmetatable\({},{__index=.*?}\)'
            ],
            'luraph_v10': [
                r'local\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\([^)]*\)\([^)]*\)',
                r'pcall\(loadstring,.*?\)',
                r'xpcall\(.*?,.*?\)',
                r'debug\.getupvalue'
            ],
            'luraph_v11_v12': [
                r'local\s+function\s+[a-zA-Z_][a-zA-Z0-9_]*\(.*?\)\s*local',
                r'return\s+function\(.*?\)\s*local',
                r'{\s*\[.*?\]\s*=\s*.*?}',
                r'bit32\.|bit\.'
            ],
            'luamor': [
                r'local\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*string\.char',
                r'table\.concat\({.*?}\)',
                r'string\.byte\(.*?\)',
                r'math\.floor\(.*?\)'
            ]
        }
        
        detected_types = []
        for obf_type, patterns in detection_patterns.items():
            matches = sum(1 for pattern in patterns if re.search(pattern, content))
            if matches > 0:
                detected_types.append((obf_type, matches))
        
        # Sort by confidence (number of matches)
        detected_types.sort(key=lambda x: x[1], reverse=True)
        
        result = {
            'primary_type': detected_types[0][0] if detected_types else 'unknown',
            'confidence': detected_types[0][1] if detected_types else 0,
            'all_detections': detected_types,
            'version_info': version_info
        }
        
        self.logger.info(f"Detected: {result['primary_type']} (confidence: {result['confidence']})")
        return result
    
    def analyze_patterns(self, content: str) -> Dict[str, Any]:
        """Analyze opcode patterns and extract insights."""
        self.logger.info("Analyzing opcode patterns...")
        
        patterns = self.pattern_analyzer.analyze(content)
        self.stats['patterns_detected'] = len(patterns.get('sequences', []))
        
        return patterns
    
    def reconstruct_constants(self, content: str, patterns: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Reconstruct dynamic constants."""
        self.logger.info("Reconstructing dynamic constants...")
        
        result = self.constant_reconstructor.reconstruct(content, patterns)
        self.stats['constants_reconstructed'] = len(result.get('constants', {}))
        
        return result['content'], result['constants']
    
    def remove_traps(self, content: str) -> str:
        """Remove anti-deobfuscation traps."""
        self.logger.info("Removing anti-deobfuscation traps...")
        
        result = self.trap_detector.remove_traps(content)
        self.stats['traps_removed'] = result.get('removed_count', 0)
        
        return result['content']
    
    def resolve_recursive_loadstrings(self, content: str, max_depth: int = 10) -> str:
        """Recursively resolve nested loadstring calls."""
        self.logger.info("Resolving recursive loadstrings...")
        
        current_content = content
        depth = 0
        
        while depth < max_depth:
            # Extract nested loadstrings
            nested = extract_nested_loadstrings(current_content)
            if not nested:
                break
            
            self.logger.info(f"Found {len(nested)} loadstring calls at depth {depth}")
            
            # Process each loadstring
            processed_any = False
            for loadstring_content in nested:
                try:
                    # Try to deobfuscate the loadstring content
                    deobfuscated = self.deobfuscate_content(loadstring_content, depth + 1)
                    if deobfuscated != loadstring_content:
                        current_content = current_content.replace(loadstring_content, deobfuscated)
                        processed_any = True
                        self.stats['loadstrings_resolved'] += 1
                except Exception as e:
                    self.logger.debug(f"Failed to process nested loadstring: {e}")
                    continue
            
            if not processed_any:
                break
                
            depth += 1
        
        self.logger.info(f"Resolved loadstrings at depth {depth}")
        return current_content
    
    def simulate_vm_execution(self, content: str) -> str:
        """Simulate VM execution to resolve dynamic behavior."""
        self.logger.info("Simulating VM execution...")
        
        try:
            result = self.vm_simulator.simulate(content)
            return result.get('deobfuscated_content', content)
        except Exception as e:
            self.logger.warning(f"VM simulation failed: {e}")
            return content
    
    def rename_variables(self, content: str) -> str:
        """Apply heuristic variable renaming."""
        self.logger.info("Applying heuristic variable renaming...")
        
        result = self.variable_renamer.rename_variables(content)
        self.stats['variables_renamed'] = result.get('renamed_count', 0)
        
        return result['content']
    
    def normalize_numbers(self, content: str) -> str:
        """Normalize hex/float/scientific notation numbers."""
        self.logger.info("Normalizing number formats...")
        
        # Hex numbers
        content = re.sub(r'0x([0-9a-fA-F]+)', lambda m: str(int(m.group(1), 16)), content)
        
        # Scientific notation
        content = re.sub(r'(\d+\.?\d*)e([+-]?\d+)', 
                        lambda m: str(float(f"{m.group(1)}e{m.group(2)}")), content)
        
        # Normalize float precision
        content = re.sub(r'(\d+\.\d{10,})', 
                        lambda m: f"{float(m.group(1)):.6f}", content)
        
        return content
    
    def deobfuscate_content(self, content: str, recursion_depth: int = 0) -> str:
        """
        Main deobfuscation logic with comprehensive analysis.
        """
        if recursion_depth > 5:  # Prevent infinite recursion
            return content
        
        self.logger.info(f"Starting deobfuscation (depth: {recursion_depth})...")
        
        # Step 1: Detect obfuscation type and version
        obf_info = self.detect_obfuscation_type(content)
        
        # Step 2: Remove anti-deobfuscation traps first
        content = self.remove_traps(content)
        
        # Step 3: Analyze opcode patterns
        patterns = self.analyze_patterns(content)
        
        # Step 4: Reconstruct dynamic constants
        content, constants = self.reconstruct_constants(content, patterns)
        
        # Step 5: Handle version-specific deobfuscation
        obf_type = obf_info['primary_type']
        
        if 'luraph' in obf_type:
            # LPH string extraction
            content = self.lph_extractor.extract_strings(content)
            
            # Opcode lifting
            content = self.opcode_lifter.lift_opcodes(content)
            
        elif obf_type == 'luamor':
            # LuaMor-specific handling
            content = self.string_decryptor.decrypt_luamor_strings(content)
        
        # Step 6: VM simulation for dynamic behavior
        content = self.simulate_vm_execution(content)
        
        # Step 7: Recursive loadstring resolution
        content = self.resolve_recursive_loadstrings(content, max_depth=3)
        
        # Step 8: Variable renaming
        content = self.rename_variables(content)
        
        # Step 9: Number normalization
        content = self.normalize_numbers(content)
        
        # Step 10: Final cleanup
        content = normalize_whitespace(content)
        
        return content
    
    def deobfuscate(self, input_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Main deobfuscation method.
        """
        try:
            # Validate input
            validate_input(input_path)
            
            # Read/download content
            content = self.process_input(input_path)
            self.logger.info(f"Loaded content: {len(content)} characters")
            
            # Deobfuscate
            deobfuscated = self.deobfuscate_content(content)
            
            # Generate output filename if not provided
            if not output_path:
                output_path = get_output_filename(input_path)
            
            # Save result
            save_output(deobfuscated, output_path)
            
            # Return results
            return {
                'success': True,
                'input_file': input_path,
                'output_file': output_path,
                'original_size': len(content),
                'deobfuscated_size': len(deobfuscated),
                'stats': self.stats,
                'reduction_ratio': (len(content) - len(deobfuscated)) / len(content) * 100
            }
            
        except Exception as e:
            self.logger.error(f"Deobfuscation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'stats': self.stats
            }

def main():
    """Main entry point."""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Enhanced Luraph Deobfuscator with Advanced Pattern Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python luraph_deobfuscator.py script.txt
  python luraph_deobfuscator.py script.txt -o deobfuscated.lua
  python luraph_deobfuscator.py https://pastebin.com/raw/YgnxtHAv
  python luraph_deobfuscator.py script.txt --debug -v
        """
    )
    
    parser.add_argument('input', help='Input file path or URL')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--stats', action='store_true', help='Show detailed statistics')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_level)
    
    # Create deobfuscator
    deobfuscator = EnhancedLuraphDeobfuscator(debug=args.debug)
    
    # Run deobfuscation
    result = deobfuscator.deobfuscate(args.input, args.output)
    
    # Print results
    if result['success']:
        print(f"\n✅ Deobfuscation completed successfully!")
        print(f"📁 Input: {result['input_file']}")
        print(f"💾 Output: {result['output_file']}")
        print(f"📏 Size: {result['original_size']:,} → {result['deobfuscated_size']:,} chars")
        
        if args.stats or args.verbose:
            print(f"\n📊 Statistics:")
            stats = result['stats']
            print(f"  • Patterns detected: {stats['patterns_detected']}")
            print(f"  • Constants reconstructed: {stats['constants_reconstructed']}")
            print(f"  • Traps removed: {stats['traps_removed']}")
            print(f"  • Loadstrings resolved: {stats['loadstrings_resolved']}")
            print(f"  • Variables renamed: {stats['variables_renamed']}")
            print(f"  • Size reduction: {result.get('reduction_ratio', 0):.1f}%")
    else:
        print(f"\n❌ Deobfuscation failed: {result['error']}")
        sys.exit(1)

if __name__ == '__main__':
    main()
