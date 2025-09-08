#!/usr/bin/env python3
import re
import logging
from typing import Dict, List, Any, Union

class ConstantReconstructor:
    """
    Dynamic constant reconstructor for extracting constants hidden inside
    functions, arrays, and dynamic generation patterns.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.constant_cache = {}
        self.function_cache = {}
        self.array_cache = {}
    
    def extract_string_constants(self, content: str) -> Dict[str, str]:
        """Extract string constants from various hiding patterns."""
        constants = {}
        
        # Pattern 1: string.char concatenation
        char_pattern = r'string\.char\(([^)]+)\)'
        for match in re.finditer(char_pattern, content):
            try:
                args = match.group(1)
                numbers = re.findall(r'\d+', args)
                if numbers:
                    chars = [chr(int(num)) for num in numbers if 0 <= int(num) <= 255]
                    reconstructed = ''.join(chars)
                    constants[match.group(0)] = f'"{reconstructed}"'
            except (ValueError, OverflowError):
                continue
        
        # Pattern 2: table.concat with string.char inside
        table_pattern = r'table\.concat\(\{([^}]+)\}\)'
        for match in re.finditer(table_pattern, content):
            try:
                args = match.group(1)
                if 'string.char' in args:
                    char_matches = re.findall(r'string\.char\((\d+)\)', args)
                    chars = [chr(int(c)) for c in char_matches if 0 <= int(c) <= 255]
                    if chars:
                        reconstructed = ''.join(chars)
                        constants[match.group(0)] = f'"{reconstructed}"'
            except (ValueError, IndexError):
                continue
        
        # Pattern 3: Escaped string reconstruction
        escape_pattern = r'(["\'])(?:\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\[nrtbfav\\])+\1'
        for match in re.finditer(escape_pattern, content):
            try:
                original = match.group(0)
                decoded = original.encode().decode('unicode_escape')
                if decoded != original:
                    constants[original] = decoded
            except (UnicodeDecodeError, ValueError):
                continue
        
        # Pattern 4: Base64 encoded strings
        base64_pattern = r'base64\.decode\(["\']([A-Za-z0-9+/=]+)["\']\)'
        for match in re.finditer(base64_pattern, content):
            try:
                import base64
                encoded = match.group(1)
                decoded = base64.b64decode(encoded).decode('utf-8')
                constants[match.group(0)] = f'"{decoded}"'
            except Exception:
                continue
        
        return constants
    
    def extract_numeric_constants(self, content: str) -> Dict[str, Union[int, float]]:
        """Extract numeric constants from obfuscated patterns."""
        constants = {}
        
        # Pattern 1: Simple mathematical expressions
        math_patterns = [
            r'(\d+)\s*[\+\-\*/]\s*(\d+)',
            r'math\.(floor|ceil|abs)\(([^)]+)\)',
            r'bit32\.(band|bor|bxor)\(([^)]+)\)'
        ]
        for pattern in math_patterns:
            for match in re.finditer(pattern, content):
                try:
                    if '+' in match.group(0):
                        parts = match.group(0).split('+')
                        if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                            result = int(parts[0].strip()) + int(parts[1].strip())
                            constants[match.group(0)] = result
                except (ValueError, IndexError):
                    continue
        
        # Pattern 2: Hexadecimal constants
        hex_pattern = r'0x[0-9a-fA-F]+'
        for match in re.finditer(hex_pattern, content):
            try:
                hex_val = match.group(0)
                decimal_val = int(hex_val, 16)
                constants[hex_val] = decimal_val
            except ValueError:
                continue
        
        return constants
    
    def reconstruct_array_constants(self, content: str) -> Dict[str, List]:
        """Reconstruct constants stored in arrays or tables."""
        arrays = {}
        
        # Pattern 1: Lua table definitions
        table_pattern = r'(\w+)\s*=\s*\{([^}]+)\}'
        for match in re.finditer(table_pattern, content):
            table_name = match.group(1)
            table_content = match.group(2)
            elements = []
            
            string_elements = re.findall(r'["\']([^"\']*)["\']', table_content)
            elements.extend(string_elements)
            
            numeric_elements = re.findall(r'(?<!["\'])\b(\d+(?:\.\d+)?)\b(?!["\'])', table_content)
            elements.extend([float(x) if '.' in x else int(x) for x in numeric_elements])
            
            if elements:
                arrays[table_name] = elements
        
        # Pattern 2: Function-based array generation
        func_array_pattern = r'function\s+(\w+)\(\)\s*return\s*\{([^}]+)\}\s*end'
        for match in re.finditer(func_array_pattern, content):
            func_name = match.group(1)
            array_content = match.group(2)
            elements = []
            
            string_elements = re.findall(r'["\']([^"\']*)["\']', array_content)
            elements.extend(string_elements)
            
            numeric_elements = re.findall(r'(?<!["\'])\b(\d+(?:\.\d+)?)\b(?!["\'])', array_content)
            elements.extend([float(x) if '.' in x else int(x) for x in numeric_elements])
            
            if elements:
                arrays[func_name] = elements
        
        return arrays
    
    def extract_function_constants(self, content: str) -> Dict[str, Any]:
        """Extract constants from function definitions."""
        functions = {}
        
        # Pattern 1: Simple return functions
        return_pattern = r'function\s+(\w+)\(\)\s*return\s+([^;\n]+)\s*end'
        for match in re.finditer(return_pattern, content):
            func_name = match.group(1)
            return_value = match.group(2).strip()
            if return_value.startswith('"') and return_value.endswith('"'):
                functions[func_name] = return_value[1:-1]
            elif return_value.isdigit():
                functions[func_name] = int(return_value)
            elif return_value.replace('.', '').isdigit():
                functions[func_name] = float(return_value)
            else:
                functions[func_name] = return_value
        
        # Pattern 2: String concatenation functions
        concat_pattern = r'function\s+(\w+)\(\)\s*return\s+(.+?)\s*end'
        for match in re.finditer(concat_pattern, content, re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(2)
            if '..' in func_body:
                parts = re.findall(r'["\']([^"\']*)["\']', func_body)
                if len(parts) > 1:
                    concatenated = ''.join(parts)
                    functions[func_name] = concatenated
        
        return functions
    
    def detect_dynamic_generation(self, content: str) -> List[Dict[str, Any]]:
        """Detect patterns where constants are generated dynamically."""
        patterns = []
        
        # Pattern 1: Loop-based generation
        loop_pattern = r'for\s+\w+\s*=\s*\d+,\s*\d+\s+do\s*(.*?)\s*end'
        for match in re.finditer(loop_pattern, content, re.DOTALL):
            loop_body = match.group(1)
            if 'string.char' in loop_body or 'table.insert' in loop_body:
                patterns.append({
                    'type': 'loop_generation',
                    'pattern': match.group(0),
                    'body': loop_body
                })
        
        # Pattern 2: Recursive generation
        recursive_pattern = r'function\s+(\w+)\([^)]*\).*?\1\([^)]*\)'
        for match in re.finditer(recursive_pattern, content, re.DOTALL):
            patterns.append({
                'type': 'recursive_generation',
                'pattern': match.group(0),
                'function': match.group(1)
            })
        
        return patterns
    
    def reconstruct_all_constants(self, content: str) -> Dict[str, Any]:
        """Perform comprehensive constant reconstruction."""
        self.logger.info("Starting constant reconstruction...")
        
        string_constants = self.extract_string_constants(content)
        numeric_constants = self.extract_numeric_constants(content)
        array_constants = self.reconstruct_array_constants(content)
        function_constants = self.extract_function_constants(content)
        dynamic_patterns = self.detect_dynamic_generation(content)
        
        self.logger.info(f"Reconstructed {len(string_constants)} string constants")
        self.logger.info(f"Reconstructed {len(numeric_constants)} numeric constants")
        self.logger.info(f"Reconstructed {len(array_constants)} array constants")
        self.logger.info(f"Reconstructed {len(function_constants)} function constants")
        self.logger.info(f"Found {len(dynamic_patterns)} dynamic generation patterns")
        
        return {
            'strings': string_constants,
            'numbers': numeric_constants,
            'arrays': array_constants,
            'functions': function_constants,
            'dynamic_patterns': dynamic_patterns,
            'summary': {
                'total_strings': len(string_constants),
                'total_numbers': len(numeric_constants),
                'total_arrays': len(array_constants),
                'total_functions': len(function_constants),
                'dynamic_patterns': len(dynamic_patterns)
            }
        }
