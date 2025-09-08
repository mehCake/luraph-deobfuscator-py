"""
Lua Code Beautification Module
"""

import re
from typing import List
import logging

class LuaBeautifier:
    """Beautifies and formats Lua code for better readability"""
    
    def __init__(self, indent_size: int = 2):
        self.indent_size = indent_size
        self.logger = logging.getLogger(__name__)
        if not self.logger.hasHandlers():
            logging.basicConfig(level=logging.INFO)
        
        # Keywords that increase indentation
        self.indent_increase = [
            'function', 'if', 'while', 'for', 'repeat', 'do', 'then'
        ]
        
        # Keywords that decrease indentation
        self.indent_decrease = [
            'end', 'until', 'else', 'elseif'
        ]
        
        # Keywords that don't change indentation but are special
        self.special_keywords = [
            'else', 'elseif'
        ]
    
    def beautify(self, code: str) -> str:
        """Main beautification function"""
        try:
            code = self._normalize_whitespace(code)
            code = self._apply_indentation(code)
            code = self._format_functions(code)
            code = self._format_tables(code)
            code = self._format_control_structures(code)
            code = self._add_operator_spacing(code)
            code = self._final_cleanup(code)
            return code
        except Exception as e:
            self.logger.error(f"Error during beautification: {e}")
            return code
    
    def _normalize_whitespace(self, code: str) -> str:
        """Normalize whitespace and line endings"""
        code = code.replace('\r\n', '\n').replace('\r','\n')
        lines = [line.rstrip() for line in code.split('\n')]
        
        cleaned_lines = []
        empty_count = 0
        for line in lines:
            if line.strip() == '':
                empty_count += 1
                if empty_count <= 1:
                    cleaned_lines.append('')
            else:
                empty_count = 0
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _apply_indentation(self, code: str) -> str:
        """Apply proper indentation to code"""
        lines = code.split('\n')
        indented_lines = []
        indent_level = 0
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                indented_lines.append('')
                continue
            
            # Decrease indent if line starts with decreasing keywords
            if any(stripped.startswith(keyword) for keyword in self.indent_decrease):
                indent_level = max(0, indent_level - 1)
            
            indented_line = ' ' * (indent_level * self.indent_size) + stripped
            indented_lines.append(indented_line)
            
            if self._line_increases_indent(stripped):
                indent_level += 1
        
        return '\n'.join(indented_lines)
    
    def _line_increases_indent(self, line: str) -> bool:
        """Check if a line should increase indentation"""
        clean_line = self._remove_comments_and_strings(line)
        
        if re.search(r'\bfunction\b\s*\w*\s*\(', clean_line):
            return True
        
        patterns = [
            r'\bif\b.*\bthen\b',
            r'\bwhile\b.*\bdo\b',
            r'\bfor\b.*\bdo\b',
            r'\brepeat\b',
            r'\bdo\b\s*$'
        ]
        
        return any(re.search(pat, clean_line) for pat in patterns)
    
    def _format_functions(self, code: str) -> str:
        """Format function definitions and calls"""
        code = re.sub(r'\bfunction\s*\(', 'function (', code)
        code = re.sub(r'\bfunction\s+(\w+)\s*\(', r'function \1(', code)
        
        def format_params(match):
            params = match.group(1)
            params = re.sub(r',(?!\s)', ', ', params)
            return f"({params})"
        
        code = re.sub(r'\(([^)]*)\)', format_params, code)
        return code
    
    def _format_tables(self, code: str) -> str:
        """Format table literals"""
        code = re.sub(r'\{(?!\s)', '{ ', code)
        code = re.sub(r'(?<!\s)\}', ' }', code)
        code = re.sub(r',(?!\s)', ', ', code)
        return code
    
    def _format_control_structures(self, code: str) -> str:
        """Format if/then/else and loop structures"""
        code = re.sub(r'\bif\s+', 'if ', code)
        code = re.sub(r'\bthen\b', 'then', code)
        code = re.sub(r'\belse\b', 'else', code)
        code = re.sub(r'\belseif\b', 'elseif', code)
        return code
    
    def _add_operator_spacing(self, code: str) -> str:
        """Add proper spacing around operators"""
        operators = [
            (r'([^=!<>])=([^=])', r'\1 = \2'),
            (r'==', ' == '),
            (r'~=', ' ~= '),
            (r'([^<])<=', r'\1 <= '),
            (r'([^>])>=', r'\1 >= '),
            (r'([^<>])>([^=])', r'\1 > \2'),
            (r'([^<>])<([^=])', r'\1 < \2'),
            (r'\+', ' + '),
            (r'([^\.])\.\.([^\.])', r'\1 .. \2'),
            (r'\band\b', ' and '),
            (r'\bor\b', ' or '),
            (r'\bnot\b', 'not '),
        ]
        for pattern, replacement in operators:
            code = re.sub(pattern, replacement, code)
        
        code = re.sub(r' +', ' ', code)
        return code
    
    def _final_cleanup(self, code: str) -> str:
        """Final cleanup of formatting"""
        lines = code.split('\n')
        cleaned_lines = []
        for line in lines:
            line = line.rstrip()
            line = re.sub(r'\s+', ' ', line)
            line = re.sub(r'^\s+$', '', line)
            cleaned_lines.append(line)
        
        while cleaned_lines and not cleaned_lines[-1].strip():
            cleaned_lines.pop()
        
        return '\n'.join(cleaned_lines)
    
    def _remove_comments_and_strings(self, line: str) -> str:
        """Remove comments and strings from a line for analysis"""
        line = re.sub(r'--.*$', '', line)
        line = re.sub(r'"[^"]*"', '""', line)
        line = re.sub(r"'[^']*'", "''", line)
        return line
