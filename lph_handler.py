import re
import logging
from typing import List, Dict, Any, Tuple, Optional
from utils import hex_to_bytes, bytes_to_string, calculate_entropy, LuraphError


class LPHExtractor:
    """Enhanced LPH and Hex String Extractor"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Extraction patterns for different versions
        self.extraction_patterns = {
            'v1.x': [
                r'superflow_bytecode_ext(\d+)\s*=\s*["\']([A-Fa-f0-9]+)["\']',
                r'loadstring\s*\(\s*["\']([A-Fa-f0-9]{32,})["\']',
                r'string\.char\s*\(\s*([0-9,\s]+)\s*\)'
            ],
            'v2.x': [
                r'lPH_([A-Fa-f0-9]{8,})\s*=',
                r'lPH_([A-Fa-f0-9]{8,})',
                r'LPH_([A-Fa-f0-9]{8,})',
                r'bit32\.bxor\s*\(\s*["\']([A-Fa-f0-9]+)["\']'
            ],
            'v3.x': [
                r'lPH_([A-Fa-f0-9]{16,})',
                r'_lph_([A-Fa-f0-9]{16,})',
                r'__lph__([A-Fa-f0-9]{16,})',
                r'debug\.getupvalue[^"\']*["\']([A-Fa-f0-9]{16,})["\']'
            ],
            'v4.x': [
                r'lPH_([A-Fa-f0-9]{20,})',
                r'rawget\s*\([^)]*["\']([A-Fa-f0-9]{20,})["\']',
                r'pcall\s*\([^)]*["\']([A-Fa-f0-9]{20,})["\']',
                r'select\s*\([^)]*["\']([A-Fa-f0-9]{20,})["\']'
            ],
            'v5.x': [
                r'lPH_([A-Fa-f0-9]{32,})',
                r'_G\s*\[[^]]*["\']([A-Fa-f0-9]{32,})["\']',
                r'math\.randomseed[^"\']*["\']([A-Fa-f0-9]{32,})["\']',
                r'unpack\s*\([^)]*["\']([A-Fa-f0-9]{32,})["\']'
            ],
            'unknown': [
                r'([A-Fa-f0-9]{32,})',  # Any long hex string
                r'lPH_([A-Fa-f0-9]{8,})',  # Generic LPH
                r'LPH_([A-Fa-f0-9]{8,})',  # Uppercase LPH
            ]
        }
    
    def extract_all_strings(self, content: str, version_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all hex and LPH strings based on detected version
        """
        version = version_info.get('version', 'unknown')
        
        self.logger.info(f"Extracting strings for version: {version}")
        
        # Get patterns for this version
        patterns = self.extraction_patterns.get(version, self.extraction_patterns['unknown'])
        
        # Extract strings
        hex_strings = []
        lph_strings = []
        metadata = []
        
        for pattern in patterns:
            matches = self._extract_with_pattern(content, pattern)
            for match_data in matches:
                if match_data['type'] == 'hex':
                    hex_strings.append(match_data)
                elif match_data['type'] == 'lph':
                    lph_strings.append(match_data)
        
        # Additional automatic detection
        auto_detected = self._auto_detect_strings(content, version_info)
        hex_strings.extend(auto_detected['hex'])
        lph_strings.extend(auto_detected['lph'])
        
        # Remove duplicates while preserving metadata
        hex_strings = self._deduplicate_strings(hex_strings)
        lph_strings = self._deduplicate_strings(lph_strings)
        
        # Validate and filter strings
        hex_strings = self._validate_hex_strings(hex_strings)
        lph_strings = self._validate_lph_strings(lph_strings)
        
        result = {
            'hex_strings': hex_strings,
            'lph_strings': lph_strings,
            'total_found': len(hex_strings) + len(lph_strings),
            'extraction_metadata': {
                'version': version,
                'patterns_used': len(patterns),
                'auto_detected': len(auto_detected['hex']) + len(auto_detected['lph'])
            }
        }
        
        self.logger.info(f"Extracted {result['total_found']} strings total")
        return result
    
    def _extract_with_pattern(self, content: str, pattern: str) -> List[Dict[str, Any]]:
        """Extract strings using a specific pattern"""
        matches = []
        
        try:
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                # Determine which group contains the hex data
                hex_data = None
                groups = match.groups()
                
                for group in groups:
                    if group and self._is_valid_hex(group):
                        hex_data = group
                        break
                
                if hex_data:
                    match_info = {
                        'hex_data': hex_data,
                        'length': len(hex_data),
                        'position': match.start(),
                        'pattern': pattern,
                        'type': 'lph' if 'lPH' in pattern else 'hex',
                        'context': content[max(0, match.start()-50):match.end()+50]
                    }
                    matches.append(match_info)
        
        except re.error as e:
            self.logger.warning(f"Regex pattern error: {pattern} - {e}")
        
        return matches
    
    def _auto_detect_strings(self, content: str, version_info: Dict[str, Any]) -> Dict[str, List]:
        """Automatically detect hex strings based on content analysis"""
        auto_hex = []
        auto_lph = []
        
        # Look for quoted hex strings
        quoted_hex_pattern = r'["\']([A-Fa-f0-9]{16,})["\']'
        for match in re.finditer(quoted_hex_pattern, content):
            hex_data = match.group(1)
            if self._is_likely_obfuscated_hex(hex_data):
                auto_hex.append({
                    'hex_data': hex_data,
                    'length': len(hex_data),
                    'position': match.start(),
                    'pattern': 'auto_quoted',
                    'type': 'hex',
                    'confidence': self._calculate_hex_confidence(hex_data)
                })
        
        # Look for variable assignments with hex values
        assignment_pattern = r'(\w+)\s*=\s*["\']([A-Fa-f0-9]{16,})["\']'
        for match in re.finditer(assignment_pattern, content):
            var_name = match.group(1)
            hex_data = match.group(2)
            
            if 'lph' in var_name.lower() or 'hex' in var_name.lower():
                auto_lph.append({
                    'hex_data': hex_data,
                    'length': len(hex_data),
                    'position': match.start(),
                    'pattern': 'auto_assignment',
                    'type': 'lph',
                    'variable_name': var_name,
                    'confidence': self._calculate_hex_confidence(hex_data)
                })
        
        # Look for function parameters with hex strings
        function_param_pattern = r'(\w+)\s*\(\s*["\']([A-Fa-f0-9]{16,})["\']'
        for match in re.finditer(function_param_pattern, content):
            func_name = match.group(1)
            hex_data = match.group(2)
            
            if func_name in ['loadstring', 'load', 'pcall', 'xpcall']:
                auto_hex.append({
                    'hex_data': hex_data,
                    'length': len(hex_data),
                    'position': match.start(),
                    'pattern': 'auto_function_param',
                    'type': 'hex',
                    'function_name': func_name,
                    'confidence': self._calculate_hex_confidence(hex_data)
                })
        
        return {'hex': auto_hex, 'lph': auto_lph}
    
    def _is_valid_hex(self, text: str) -> bool:
        """Check if text is valid hexadecimal"""
        if not text or len(text) < 8:
            return False
        
        try:
            int(text, 16)
            return True
        except ValueError:
            return False
    
    def _is_likely_obfuscated_hex(self, hex_string: str) -> bool:
        """Determine if hex string is likely obfuscated content"""
        if len(hex_string) < 16:
            return False
        
        # Check entropy (obfuscated data should have high entropy)
        entropy = calculate_entropy(hex_string)
        if entropy < 3.5:  # Low entropy suggests pattern/repetition
            return False
        
        # Check for patterns that suggest real data
        byte_data = hex_to_bytes(hex_string)
        if byte_data:
            # Look for common Lua bytecode headers
            if byte_data.startswith(b'\x1bLua') or byte_data.startswith(b'LUA'):
                return True
            
            # Check for common string patterns
            try:
                decoded = byte_data.decode('utf-8', errors='ignore')
                if any(keyword in decoded.lower() for keyword in ['function', 'local', 'end', 'if', 'then']):
                    return True
            except:
                pass
        
        return entropy > 4.0  # High entropy threshold
    
    def _calculate_hex_confidence(self, hex_string: str) -> float:
        """Calculate confidence that this hex string contains useful data"""
        confidence = 0.0
        
        # Length factor (longer strings more likely to be meaningful)
        if len(hex_string) >= 32:
            confidence += 0.3
        if len(hex_string) >= 64:
            confidence += 0.2
        if len(hex_string) >= 128:
            confidence += 0.2
        
        # Entropy factor
        entropy = calculate_entropy(hex_string)
        if entropy > 4.0:
            confidence += 0.3
        elif entropy > 3.5:
            confidence += 0.2
        
        # Pattern analysis
        byte_data = hex_to_bytes(hex_string)
        if byte_data:
            # Check for bytecode signatures
            if b'\x1bLua' in byte_data or b'LUA' in byte_data:
                confidence += 0.4
            
            # Check for common Lua constructs when decoded
            try:
                decoded = byte_data.decode('utf-8', errors='ignore')
                lua_keywords = ['function', 'local', 'end', 'if', 'then', 'else', 'while', 'for']
                keyword_count = sum(1 for keyword in lua_keywords if keyword in decoded.lower())
                confidence += min(keyword_count * 0.1, 0.3)
            except:
                pass
        
        return min(confidence, 1.0)
    
    def _deduplicate_strings(self, strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate hex strings while preserving best metadata"""
        seen = {}
        deduplicated = []
        
        for string_info in strings:
            hex_data = string_info['hex_data']
            
            if hex_data not in seen:
                seen[hex_data] = string_info
                deduplicated.append(string_info)
            else:
                # Keep the one with higher confidence or more```python
                existing = seen[hex_data]
                if (string_info.get('confidence', 0) > existing.get('confidence', 0) or
                    string_info.get('length', 0) > existing.get('length', 0)):
                    seen[hex_data] = string_info
                    # Replace in deduplicated list
                    for i, item in enumerate(deduplicated):
                        if item['hex_data'] == hex_data:
                            deduplicated[i] = string_info
                            break
        
        return deduplicated

class LuaDeobfuscator:
    """Main class for Lua deobfuscation operations"""
    
    def __init__(self):
        self.extractor = StringExtractor()
        self.stats = {
            'total_strings': 0,
            'successfully_decoded': 0,
            'failed_decodes': 0,
            'empty_results': 0
        }
    
    def deobfuscate_file(self, file_path: str) -> Dict[str, Any]:
        """Main method to deobfuscate a Lua file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return {'error': f'Failed to read file: {e}', 'results': []}
        
        return self.deobfuscate_content(content)
    
    def deobfuscate_content(self, content: str) -> Dict[str, Any]:
        """Deobfuscate Lua content string"""
        # Extract strings
        extraction_results = self.extractor.extract_strings(content)
        
        all_results = []
        
        # Process hex strings
        for hex_info in extraction_results['hex']:
            result = self._process_hex_string(hex_info)
            if result:
                all_results.append(result)
        
        # Process LPH strings
        for lph_info in extraction_results['lph']:
            result = self._process_lph_string(lph_info)
            if result:
                all_results.append(result)
        
        # Update statistics
        self.stats['total_strings'] = len(extraction_results['hex']) + len(extraction_results['lph'])
        
        # Sort results by confidence and usefulness
        all_results.sort(key=lambda x: (x.get('confidence', 0), x.get('usefulness_score', 0)), reverse=True)
        
        return {
            'results': all_results,
            'statistics': self.stats,
            'extraction_summary': {
                'hex_strings_found': len(extraction_results['hex']),
                'lph_strings_found': len(extraction_results['lph']),
                'total_processed': len(all_results)
            }
        }
    
    def _process_hex_string(self, hex_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single hex string"""
        hex_data = hex_info['hex_data']
        
        # Convert to bytes
        byte_data = hex_to_bytes(hex_data)
        if not byte_data:
            self.stats['failed_decodes'] += 1
            return None
        
        result = {
            'original_hex': hex_data,
            'type': hex_info.get('pattern', 'hex'),
            'position': hex_info.get('position', 0),
            'length': len(hex_data),
            'confidence': hex_info.get('confidence', 0.0),
            'decoded_results': []
        }
        
        # Try different decoding methods
        decoded_results = []
        
        # 1. Direct UTF-8 decode
        try:
            utf8_result = byte_data.decode('utf-8')
            if utf8_result.strip():
                decoded_results.append({
                    'method': 'utf-8',
                    'content': utf8_result,
                    'confidence': 0.8 if self._looks_like_lua_code(utf8_result) else 0.5
                })
        except UnicodeDecodeError:
            pass
        
        # 2. Try with error handling
        try:
            utf8_ignore = byte_data.decode('utf-8', errors='ignore')
            if utf8_ignore.strip() and utf8_ignore not in [r['content'] for r in decoded_results]:
                decoded_results.append({
                    'method': 'utf-8-ignore',
                    'content': utf8_ignore,
                    'confidence': 0.6 if self._looks_like_lua_code(utf8_ignore) else 0.3
                })
        except:
            pass
        
        # 3. Check if it's Lua bytecode
        if byte_data.startswith(b'\x1bLua'):
            decoded_results.append({
                'method': 'lua_bytecode',
                'content': f"[Lua Bytecode - {len(byte_data)} bytes]",
                'confidence': 0.9,
                'is_bytecode': True
            })
        
        # 4. Try base64 decode if it looks encoded
        if len(hex_data) % 4 == 0:
            try:
                # Convert hex to base64-like format and decode
                import base64
                base64_result = base64.b64decode(byte_data, validate=True)
                utf8_from_b64 = base64_result.decode('utf-8', errors='ignore')
                if utf8_from_b64.strip():
                    decoded_results.append({
                        'method': 'base64_from_hex',
                        'content': utf8_from_b64,
                        'confidence': 0.4
                    })
            except:
                pass
        
        if not decoded_results:
            # Try raw interpretation
            raw_content = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in byte_data[:100])
            if raw_content.strip():
                decoded_results.append({
                    'method': 'raw_ascii',
                    'content': raw_content,
                    'confidence': 0.2
                })
        
        if decoded_results:
            result['decoded_results'] = decoded_results
            result['usefulness_score'] = max(r.get('confidence', 0) for r in decoded_results)
            self.stats['successfully_decoded'] += 1
            return result
        else:
            self.stats['empty_results'] += 1
            return None
    
    def _process_lph_string(self, lph_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process LPH encoded string"""
        # LPH strings are typically more complex and may require specific decoding
        # For now, treat them similarly to hex strings
        return self._process_hex_string(lph_info)
    
    def _looks_like_lua_code(self, content: str) -> bool:
        """Check if content looks like Lua code"""
        lua_keywords = [
            'function', 'local', 'end', 'if', 'then', 'else', 'elseif',
            'while', 'for', 'do', 'repeat', 'until', 'return', 'break',
            'nil', 'true', 'false', 'and', 'or', 'not'
        ]
        
        content_lower = content.lower()
        keyword_count = sum(1 for keyword in lua_keywords if keyword in content_lower)
        
        # Also check for common Lua patterns
        has_lua_patterns = any(pattern in content for pattern in ['--', '[[', ']]', '=>', '~='])
        
        return keyword_count >= 2 or has_lua_patterns

def main():
    """Main CLI interface"""
    import argparse
    import sys
    import json
    
    parser = argparse.ArgumentParser(description='Lua Deobfuscator Tool')
    parser.add_argument('input_file', help='Input Lua file to deobfuscate')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--format', choices=['json', 'text'], default='text', help='Output format')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print(f"Error: File '{args.input_file}' not found.")
        sys.exit(1)
    
    deobfuscator = LuaDeobfuscator()
    results = deobfuscator.deobfuscate_file(args.input_file)
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Format output
    if args.format == 'json':
        output_data = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        output_data = format_text_output(results, args.verbose)
    
    # Write output
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_data)
            print(f"Results saved to: {args.output}")
        except Exception as e:
            print(f"Error writing output file: {e}")
            sys.exit(1)
    else:
        print(output_data)

def format_text_output(results: Dict[str, Any], verbose: bool = False) -> str:
    """Format results as readable text"""
    output = []
    
    # Summary
    stats = results.get('statistics', {})
    summary = results.get('extraction_summary', {})
    
    output.append("=== Lua Deobfuscation Results ===\n")
    output.append(f"Total strings processed: {stats.get('total_strings', 0)}")
    output.append(f"Successfully decoded: {stats.get('successfully_decoded', 0)}")
    output.append(f"Failed decodes: {stats.get('failed_decodes', 0)}")
    output.append(f"Hex strings found: {summary.get('hex_strings_found', 0)}")
    output.append(f"LPH strings found: {summary.get('lph_strings_found', 0)}")
    output.append("\n" + "="*50 + "\n")
    
    # Results
    for i, result in enumerate(results.get('results', []), 1):
        output.append(f"Result #{i}:")
        output.append(f"  Type: {result.get('type', 'unknown')}")
        output.append(f"  Position: {result.get('position', 0)}")
        output.append(f"  Confidence: {result.get('confidence', 0):.2f}")
        output.append(f"  Original hex length: {result.get('length', 0)}")
        
        if verbose:
            output.append(f"  Original hex: {result.get('original_hex', '')[:100]}...")
        
        decoded_results = result.get('decoded_results', [])
        if decoded_results:
            output.append("  Decoded content:")
            for j, decoded in enumerate(decoded_results):
                output.append(f"    Method {j+1}: {decoded.get('method', 'unknown')} (confidence: {decoded.get('confidence', 0):.2f})")
                content = decoded.get('content', '')
                if len(content) > 200 and not verbose:
                    content = content[:200] + "..."
                output.append(f"    Content: {repr(content)}")
        
        output.append("")  # Empty line between results
    
    return "\n".join(output)

if __name__ == "__main__":
    main()
```

<CodePalArtifact entry="deobfuscator.py" id="lua-deobfuscator" title="Lua Deobfuscator Tool">
<CodePalFile path="deobfuscator.py" language="python" description="Main Lua deobfuscator script with string extraction, hex decoding, and pattern matching capabilities" tags="lua, deobfuscation, hex, decoding, security, analysis" project-wide="true">
import re
import math
import binascii
import os
from typing import List, Dict, Any, Optional, Tuple

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of string"""
    if not data:
        return 0.0
    
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    
    entropy = 0.0
    length = len(data)
    
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

def hex_to_bytes(hex_string: str) -> Optional[bytes]:
    """Convert hex string to bytes with error handling"""
    try:
        # Remove any whitespace and ensure even length
        hex_clean = re.sub(r'\s+', '', hex_string)
        if len(hex_clean) % 2 != 0:
            hex_clean = '0' + hex_clean
        
        return bytes.fromhex(hex_clean)
    except ValueError:
        return None

class StringExtractor:
    """Extract potentially obfuscated strings from Lua code"""
    
    def __init__(self):
        # Common Lua obfuscation patterns
        self.patterns = {
            # Long hex strings in quotes
            'hex_quoted': r'["\']([0-9a-fA-F]{16,})["\']',
            
            # Hex strings as function parameters
            'hex_function': r'(\w+)\s*\(\s*["\']([0-9a-fA-F]{16,})["\']',
            
            # LPH-style encoding patterns
            'lph_pattern': r'LPH_[A-Z_]+\s*\(\s*["\']([0-9a-fA-F]+)["\']',
            
            # Base64-like patterns
            'base64_like': r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
            
            # Escaped hex sequences
            'escaped_hex': r'\\x([0-9a-fA-F]{2})+',
            
            # Large string concatenations
            'concat_strings': r'["\'][^"\']{10,}["\'](?:\s*\.\.\s*["\'][^"\']{10,}["\'])+',
        }
    
    def extract_strings(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """Extract all potentially obfuscated strings from content"""
        results = {
            'hex': [],
            'lph': [],
            'base64': [],
            'concatenated': []
        }
        
        # Extract hex strings
        hex_strings = self._extract_hex_strings(content)
        results['hex'].extend(hex_strings['hex'])
        results['lph'].extend(hex_strings['lph'])
        
        # Extract base64-like strings
        base64_strings = self._extract_base64_strings(content)
        results['base64'].extend(base64_strings)
        
        # Extract concatenated strings
        concat_strings = self._extract_concatenated_strings(content)
        results['concatenated'].extend(concat_strings)
        
        # Deduplicate and sort by confidence
        for category in results:
            results[category] = self._deduplicate_strings(results[category])
            results[category].sort(key=lambda x: x.get('confidence', 0), reverse=True)
        
        return results
    
    def _extract_hex_strings(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """Extract hex-encoded strings"""
        auto_hex = []
        auto_lph = []
        
        # Pattern 1: Direct hex strings in quotes
        hex_pattern = r'["\']([0-9a-fA-F]{16,})["\']'
        for match in re.finditer(hex_pattern, content):
            hex_data = match.group(1)
            
            if self._is_valid_hex(hex_data) and self._is_likely_obfuscated_hex(hex_data):
                auto_hex.append({
                    'hex_data': hex_data,
                    'length': len(hex_data),
                    'position': match.start(),
                    'pattern': 'quoted_hex',
                    'type': 'hex',
                    'confidence': self._calculate_hex_confidence(hex_data)
                })
        
        # Pattern 2: LPH-style patterns
        lph_pattern = r'LPH_[A-Z_]+\s*\(\s*["\']([0-9a-fA-F]+)["\']'
        for match in re.finditer(lph_pattern, content):
            hex_data = match.group(1)
            
            auto_lph.append({
                'hex_data': hex_data,
                'length': len(hex_data),
                'position': match.start(),
                'pattern': 'lph_encoding',
                'type': 'lph',
                'confidence': min(self._calculate_hex_confidence(hex_data) + 0.2, 1.0)
            })
        
        # Pattern 3: Function parameters with hex
        function_param_pattern = r'(\w+)\s*\(\s*["\']([0-9a-fA-F]{16,})["\']'
        for match in re.finditer(function_param_pattern, content):
            func_name = match.group(1)
            hex_data = match.group(2)
            
            if func_name in ['loadstring', 'load', 'pcall', 'xpcall']:
                auto_hex.append({
                    'hex_data': hex_data,
                    'length': len(hex_data),
                    'position': match.start(),
                    'pattern': 'auto_function_param',
                    'type': 'hex',
                    'function_name': func_name,
                    'confidence': self._calculate_hex_confidence(hex_data)
                })
        
        return {'hex': auto_hex, 'lph': auto_lph}
    
    def _extract_base64_strings(self, content: str) -> List[Dict[str, Any]]:
        """Extract potential base64 encoded strings"""
        base64_strings = []
        
        pattern = r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']'
        for match in re.finditer(pattern, content):
            b64_data = match.group(1)
            
            try:
                import base64
                decoded = base64.b64decode(b64_data, validate=True)
                
                base64_strings.append({
                    'encoded_data': b64_data,
                    'decoded_data': decoded,
                    'length': len(b64_data),
                    'position': match.start(),
                    'pattern': 'base64',
                    'type': 'base64',
                    'confidence': 0.7 if len(decoded) > 10 else 0.4
                })
            except:
                # Not valid base64, skip
                pass
        
        return base64_strings
    
    def _extract_concatenated_strings(self, content: str) -> List[Dict[str, Any]]:
        """Extract large concatenated strings that might hide content"""
        concat_strings = []
        
        # Pattern for string concatenation
        pattern = r'(["\'][^"\']{8,}["\'](?:\s*\.\.\s*["\'][^"\']{8,}["\'])+)'
        
        for match in re.finditer(pattern, content):
            full_match = match.group(1)
            
            # Extract individual strings
            string_parts = re.findall(r'["\']([^"\']+)["\']', full_match)
            combined = ''.join(string_parts)
            
            if len(combined) > 50:  # Only consider substantial concatenations
                concat_strings.append({
                    'concatenated_data': combined,
                    'parts': string_parts,
                    'part_count': len(string_parts),
                    'total_length': len(combined),
                    'position': match.start(),
                    'pattern': 'concatenated',
                    'type': 'concatenated',
                    'confidence': 0.5 if self._looks_like_meaningful_content(combined) else 0.3
                })
        
        return concat_strings
    
    def _is_valid_hex(self, text: str) -> bool:
        """Check if text is valid hexadecimal"""
        if not text or len(text) < 8:
            return False
        
        try:
            int(text, 16)
            return True
        except ValueError:
            return False
    
    def _is_likely_obfuscated_hex(self, hex_string: str) -> bool:
        """Determine if hex string is likely obfuscated content"""
        if len(hex_string) < 16:
            return False
        
        # Check entropy (obfuscated data should have high entropy)
        entropy = calculate_entropy(hex_string)
        if entropy < 3.5:  # Low entropy suggests pattern/repetition
            return False
        
        # Check for patterns that suggest real data
        byte_data = hex_to_bytes(hex_string)
        if byte_data:
            # Look for common Lua bytecode headers
            if byte_data.startswith(b'\x1bLua') or byte_data.startswith(b'LUA'):
                return True
            
            # Check for common string patterns
            try:
                decoded = byte_data.decode('utf-8', errors='ignore')
                if any(keyword in decoded.lower() for keyword in ['function', 'local', 'end', 'if', 'then']):
                    return True
            except:
                pass
        
        return entropy > 4.0  # High entropy threshold
    
    def _calculate_hex_confidence(self, hex_string: str) -> float:
        """Calculate confidence that this hex string contains useful data"""
        confidence = 0.0
        
        # Length factor (longer strings more likely to be meaningful)
        if len(hex_string) >= 32:
            confidence += 0.3
        if len(hex_string) >= 64:
            confidence += 0.2
        if len(hex_string) >= 128:
            confidence += 0.2
        
        # Entropy factor
        entropy = calculate_entropy(hex_string)
        if entropy > 4.0:
            confidence += 0.3
        elif entropy > 3.5:
            confidence += 0.2
        
        # Pattern analysis
        byte_data = hex_to_bytes(hex_string)
        if byte_data:
            # Check for bytecode signatures
            if b'\x1bLua' in byte_data or b'LUA' in byte_data:
                confidence += 0.4
            
            # Check for common Lua constructs when decoded
            try:
                decoded = byte_data.decode('utf-8', errors='ignore')
                lua_keywords = ['function', 'local', 'end', 'if', 'then', 'else', 'while', 'for']
                keyword_count = sum(1 for keyword in lua_keywords if keyword in decoded.lower())
                confidence += min(keyword_count * 0.1, 0.3)
            except:
                pass
        
        return min(confidence, 1.0)
    
    def _looks_like_meaningful_content(self, content: str) -> bool:
        """Check if content appears to be meaningful text or code"""
        # Check for common words, code patterns, etc.
        meaningful_patterns = [
            r'\b(function|local|end|if|then|else|return)\b',  # Lua keywords
            r'\b[A-Z][a-zA-Z]{3,}\b',  # Capitalized words
            r'\b\w+\s*=\s*\w+',  # Variable assignments
            r'[a-zA-Z]{4,}',  # Words of reasonable length
        ]
        
        matches = 0
        for pattern in meaningful_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches += 1
        
        return matches >= 2
    
    def _deduplicate_strings(self, strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate strings while preserving best metadata"""
        seen = {}
        deduplicated = []
        
        for string_info in strings:
            # Use appropriate key based on string type
            if 'hex_data' in string_info:
                key = string_info['hex_data']
            elif 'encoded_data' in string_info:
                key = string_info['encoded_data']
            elif 'concatenated_data' in string_info:
                key = string_info['concatenated_data']
            else:
                key = str(string_info)
            
            if key not in seen:
                seen[key] = string_info
                deduplicated.append(string_info)
            else:
                # Keep the one with higher confidence
                existing = seen[key]
                if string_info.get('confidence', 0) > existing.get('confidence', 0):
                    seen[key] = string_info
                    # Replace in deduplicated list
                    for i, item in enumerate(deduplicated):
                        item_key = item.get('hex_data') or item.get('encoded_data') or item.get('concatenated_data') or str(item)
                        if item_key == key:
                            deduplicated[i] = string_info
                            break
        
        return deduplicated

class LuaDeobfuscator:
    """Main class for Lua deobfuscation operations"""
    
    def __init__(self):
        self.extractor = StringExtractor()
        self.stats = {
            'total_strings': 0,
            'successfully_decoded': 0,
            'failed_decodes': 0,
            'empty_results': 0
        }
    
    def deobfuscate_file(self, file_path: str) -> Dict[str, Any]:
        """Main method to deobfuscate a Lua file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return {'error': f'Failed to read file: {e}', 'results': []}
        
        return self.deobfuscate_content(content)
    
    def deobfuscate_content(self, content: str) -> Dict[str, Any]:
        """Deobfuscate Lua content string"""
        # Extract strings
        extraction_results = self.extractor.extract_strings(content)
        
        all_results = []
        
        # Process different types of extracted strings
        for category, strings in extraction_results.items():
            for string_info in strings:
                if category == 'hex' or category == 'lph':
                    result = self._process_hex_string(string_info)
                elif category == 'base64':
                    result = self._process_base64_string(string_info)
                elif category == 'concatenated':
                    result = self._process_concatenated_string(string_info)
                else:
                    continue
                
                if result:
                    all_results.append(result)
        
        # Update statistics
        total_strings = sum(len(strings) for strings in extraction_results.values())
        self.stats['total_strings'] = total_strings
        
        # Sort results by confidence and usefulness
        all_results.sort(key=lambda x: (x.get('confidence', 0), x.get('usefulness_score', 0)), reverse=True)
        
        return {
            'results': all_results,
            'statistics': self.stats,
            'extraction_summary': {
                'hex_strings_found': len(extraction_results['hex']),
                'lph_strings_found': len(extraction_results['lph']),
                'base64_strings_found': len(extraction_results['base64']),
                'concatenated_strings_found': len(extraction_results['concatenated']),
                'total_processed': len(all_results)
            }
        }
    
    def _process_hex_string(self, hex_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single hex string"""
        hex_data = hex_info['hex_data']
        
        # Convert to bytes
        byte_data = hex_to_bytes(hex_data)
        if not byte_data:
            self.stats['failed_decodes'] += 1
            return None
        
        result = {
            'original_hex': hex_data,
            'type': hex_info.get('pattern', 'hex'),
            'position': hex_info.get('position', 0),
            'length': len(hex_data),
            'confidence': hex_info.get('confidence', 0.0),
            'decoded_results': []
        }
        
        # Try different decoding methods
        decoded_results = []
        
        # 1. Direct UTF-8 decode
        try:
            utf8_result = byte_data.decode('utf-8')
            if utf8_result.strip():
                decoded_results.append({
                    'method': 'utf-8',
                    'content': utf8_result,
                    'confidence': 0.8 if self._looks_like_lua_code(utf8_result) else 0.5
                })
        except UnicodeDecodeError:
            pass
        
        # 2. Try with error handling
        try:
            utf8_ignore = byte_data.decode('utf-8', errors='ignore')
            if utf8_ignore.strip() and utf8_ignore not in [r['content'] for r in decoded_results]:
                decoded_results.append({
                    'method': 'utf-8-ignore',
                    'content': utf8_ignore,
                    'confidence': 0.6 if self._looks_like_lua_code(utf8_ignore) else 0.3
                })
        except:
            pass
        
        # 3. Check if it's Lua bytecode
        if byte_data.startswith(b'\x1bLua'):
            decoded_results.append({
                'method': 'lua_bytecode',
                'content': f"[Lua Bytecode - {len(byte_data)} bytes]",
                'confidence': 0.9,
                'is_bytecode': True
            })
        
        # 4. Try other common encodings
        for encoding in ['latin1', 'ascii', 'cp1252']:
            try:
                decoded = byte_data.decode(encoding, errors='ignore')
                if decoded.strip() and decoded not in [r['content'] for r in decoded_results]:
                    decoded_results.append({
                        'method': encoding,
                        'content': decoded,
                        'confidence': 0.3
                    })
            except:
                pass
        
        if not decoded_results:
            # Try raw interpretation
            raw_content = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in byte_data[:100])
            if raw_content.strip():
                decoded_results.append({
                    'method': 'raw_ascii',
                    'content': raw_content,
                    'confidence': 0.2
                })
        
        if decoded_results:
            result['decoded_results'] = decoded_results
            result['usefulness_score'] = max(r.get('confidence', 0) for r in decoded_results)
            return result
        
        self.stats['failed_decodes'] += 1
        return None
    
    def _process_lph_string(self, lph_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single LPH string"""
        lph_data = lph_info['lph_data']
        
        # Convert to bytes
        byte_data = lph_to_bytes(lph_data)
        if not byte_data:
            self.stats['failed_decodes'] += 1
            return None
        
        result = {
            'original_lph': lph_data,
            'type': 'lph',
            'position': lph_info.get('position', 0),
            'length': len(lph_data),
            'confidence': lph_info.get('confidence', 0.0),
            'decoded_results': []
        }
        
        # Try UTF-8 decode
        try:
            decoded_content = byte_data.decode('utf-8')
            if decoded_content.strip():
                result['decoded_results'] = [{
                    'method': 'utf-8',
                    'content': decoded_content,
                    'confidence': 0.9 if self._looks_like_lua_code(decoded_content) else 0.7
                }]
                result['usefulness_score'] = result['decoded_results'][0]['confidence']
                return result
        except UnicodeDecodeError:
            pass
        
        # Try with error handling
        try:
            decoded_content = byte_data.decode('utf-8', errors='ignore')
            if decoded_content.strip():
                result['decoded_results'] = [{
                    'method': 'utf-8-ignore',
                    'content': decoded_content,
                    'confidence': 0.5
                }]
                result['usefulness_score'] = 0.5
                return result
        except:
            pass
        
        self.stats['failed_decodes'] += 1
        return None
    
    def _process_base64_string(self, base64_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single base64 string"""
        base64_data = base64_info['base64_data']
        
        # Decode base64
        try:
            byte_data = base64.b64decode(base64_data)
        except Exception:
            self.stats['failed_decodes'] += 1
            return None
        
        result = {
            'original_base64': base64_data,
            'type': 'base64',
            'position': base64_info.get('position', 0),
            'length': len(base64_data),
            'confidence': base64_info.get('confidence', 0.0),
            'decoded_results': []
        }
        
        decoded_results = []
        
        # Try UTF-8 decode
        try:
            utf8_content = byte_data.decode('utf-8')
            if utf8_content.strip():
                decoded_results.append({
                    'method': 'utf-8',
                    'content': utf8_content,
                    'confidence': 0.8 if self._looks_like_lua_code(utf8_content) else 0.6
                })
        except UnicodeDecodeError:
            pass
        
        # Check if it's Lua bytecode
        if byte_data.startswith(b'\x1bLua'):
            decoded_results.append({
                'method': 'lua_bytecode',
                'content': f"[Lua Bytecode - {len(byte_data)} bytes]",
                'confidence': 0.9,
                'is_bytecode': True
            })
        
        if decoded_results:
            result['decoded_results'] = decoded_results
            result['usefulness_score'] = max(r.get('confidence', 0) for r in decoded_results)
            return result
        
        self.stats['failed_decodes'] += 1
        return None
    
    def _process_concatenated_string(self, concat_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a concatenated string"""
        full_string = concat_info['full_string']
        
        result = {
            'original_concatenated': full_string,
            'type': 'concatenated',
            'position': concat_info.get('position', 0),
            'parts_count': len(concat_info.get('parts', [])),
            'confidence': concat_info.get('confidence', 0.0),
            'decoded_results': []
        }
        
        # The concatenated string is already the final result
        if full_string.strip():
            result['decoded_results'] = [{
                'method': 'concatenation',
                'content': full_string,
                'confidence': 0.7 if self._looks_like_lua_code(full_string) else 0.5
            }]
            result['usefulness_score'] = result['decoded_results'][0]['confidence']
            return result
        
        return None
    
    def _looks_like_lua_code(self, content: str) -> bool:
        """Check if content looks like Lua code"""
        lua_keywords = [
            'function', 'end', 'local', 'return', 'if', 'then', 'else',
            'for', 'while', 'do', 'break', 'repeat', 'until', 'in',
            'and', 'or', 'not', 'true', 'false', 'nil'
        ]
        
        content_lower = content.lower()
        keyword_count = sum(1 for keyword in lua_keywords if keyword in content_lower)
        
        # Check for Lua-specific patterns
        has_lua_patterns = (
            '--' in content or  # Lua comments
            'function(' in content or
            'end)' in content or
            'local ' in content
        )
        
        return keyword_count >= 2 or has_lua_patterns

<CodePalArtifact entry="main.py" id="lua-string-extractor" title="Lua String Extractor Tool">
<CodePalFile path="main.py" language="python" description="Main entry point for the Lua string extractor tool" tags="main, cli, entry-point" related-files="extractor.py,utils.py">
#!/usr/bin/env python3
"""
Main entry point for the Lua String Extractor tool.
"""

import argparse
import json
import sys
from pathlib import Path
from extractor import LuaStringExtractor

def main():
    parser = argparse.ArgumentParser(
        description='Extract and decode strings from Lua files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py script.lua
  python main.py script.lua -o output.json
  python main.py script.lua --verbose --min-confidence 0.7
        """
    )
    
    parser.add_argument('input_file', help='Input Lua file to process')
    parser.add_argument('-o', '--output', help='Output JSON file (default: stdout)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--min-confidence', type=float, default=0.0, 
                       help='Minimum confidence threshold (0.0-1.0)')
    parser.add_argument('--format', choices=['json', 'text'], default='json',
                       help='Output format')
    
    args = parser.parse_args()
    
    # Check input file
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' not found", file=sys.stderr)
        sys.exit(1)
    
    # Read input file
    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Extract strings
    extractor = LuaStringExtractor()
    results = extractor.extract_and_decode(content)
    
    # Filter by confidence
    if args.min_confidence > 0:
        filtered_results = []
        for result in results['results']:
            max_confidence = max(
                (r.get('confidence', 0) for r in result.get('decoded_results', [])),
                default=0
            )
            if max_confidence >= args.min_confidence:
                filtered_results.append(result)
        results['results'] = filtered_results
        results['statistics']['filtered_count'] = len(filtered_results)
    
    # Output results
    if args.format == 'json':
        output_data = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        output_data = format_text_output(results, args.verbose)
    
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_data)
            print(f"Results written to {args.output}")
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_data)

def format_text_output(results, verbose=False):
    """Format results as readable text"""
    lines = []
    
    # Summary
    stats = results['statistics']
    summary = results['extraction_summary']
    
    lines.append("=== Lua String Extractor Results ===\n")
    lines.append(f"Total strings found: {summary['total_processed']}")
    lines.append(f"  - Hex strings: {summary['hex_strings_found']}")
    lines.append(f"  - LPH strings: {summary['lph_strings_found']}")
    lines.append(f"  - Base64 strings: {summary['base64_strings_found']}")
    lines.append(f"  - Concatenated strings: {summary['concatenated_strings_found']}")
    lines.append(f"Successfully decoded: {stats['total_strings'] - stats['failed_decodes']}")
    lines.append(f"Failed to decode: {stats['failed_decodes']}")
    lines.append("")
    
    # Results
    if not results['results']:
        lines.append("No decodable strings found.")
        return '\n'.join(lines)
    
    lines.append("=== Decoded Strings ===\n")
    
    for i, result in enumerate(results['results'], 1):
        lines.append(f"--- Result #{i} ---")
        lines.append(f"Type: {result['type']}")
        lines.append(f"Position: {result.get('position', 'unknown')}")
        lines.append(f"Confidence: {result.get('confidence', 0):.2f}")
        
        if verbose and result['type'] == 'hex':
            lines.append(f"Original hex: {result['original_hex'][:100]}...")
        elif verbose and result['type'] == 'base64':
            lines.append(f"Original base64: {result['original_base64'][:100]}...")
        
        # Show decoded results
        for decode_result in result.get('decoded_results', []):
            lines.append(f"Method: {decode_result['method']}")
            lines.append(f"Confidence: {decode_result['confidence']:.2f}")
            
            content = decode_result['content']
            if decode_result.get('is_bytecode'):
                lines.append(f"Content: {content}")
            else:
                # Truncate long content
                if len(content) > 200 and not verbose:
                    content = content[:200] + "..."
                lines.append(f"Content:\n{content}")
            lines.append("")
        
        lines.append("")
    
    return '\n'.join(lines)

if __name__ == '__main__':
    main()