"""
Variable and Function Renaming Module
"""

import re
from typing import Dict, Set, Optional
import logging
from collections import defaultdict

class LuaVariableRenamer:
    """Renames variables and functions with meaningful names"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.variable_map: Dict[str, str] = {}
        self.function_map: Dict[str, str] = {}
        self.used_names: Set[str] = set()
        
        # Reserved Lua keywords
        self.lua_keywords = {
            'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
            'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
            'return', 'then', 'true', 'until', 'while'
        }
        
        # Extended meaningful variable names by context
        self.context_names = {
            'loop': ['index', 'counter', 'position', 'current', 'i', 'j', 'k', 'idx', 'step'],
            'string': ['text', 'content', 'message', 'data', 'line', 'input', 'output', 'str_value'],
            'number': ['value', 'amount', 'size', 'length', 'count', 'total', 'num', 'idx'],
            'boolean': ['flag', 'enabled', 'active', 'valid', 'is_ready', 'has_value', 'success', 'done'],
            'table': ['list', 'array', 'items', 'collection', 'table', 'dict', 'map', 'elements'],
            'function': ['handler', 'callback', 'processor', 'method', 'action', 'executor', 'func']
        }
    
    def rename_variables(self, code: str) -> str:
        """Main function to rename variables and functions"""
        try:
            self._identify_identifiers(code)
            self._generate_meaningful_names()
            code = self._apply_renaming(code)
            return code
        except Exception as e:
            self.logger.error(f"Error during variable renaming: {e}")
            return code
    
    def _identify_identifiers(self, code: str) -> None:
        """Identify all variables and functions in the code"""
        function_pattern = r'\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(function_pattern, code):
            func_name = match.group(1)
            if self._is_obfuscated_name(func_name):
                self.function_map[func_name] = ''

        local_pattern = r'\blocal\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for match in re.finditer(local_pattern, code):
            var_name = match.group(1)
            if self._is_obfuscated_name(var_name):
                self.variable_map[var_name] = ''

        assignment_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        for match in re.finditer(assignment_pattern, code):
            var_name = match.group(1)
            if self._is_obfuscated_name(var_name) and var_name not in self.lua_keywords:
                self.variable_map[var_name] = ''

    def _is_obfuscated_name(self, name: str) -> bool:
        """Determine if a name appears to be obfuscated"""
        if name in self.lua_keywords:
            return False
        
        if len(name) == 1 and name not in 'ijk':
            return True
        
        if len(name) > 1:
            if re.search(r'[a-z][A-Z][a-z]', name) or re.search(r'[A-Z][a-z][A-Z]', name):
                return True
            if re.search(r'[a-zA-Z]\d[a-zA-Z]', name):
                return True
            if len(name) <= 3 and not re.match(r'^[a-z]+$', name):
                return True
        
        return False
    
    def _generate_meaningful_names(self) -> None:
        """Generate meaningful names for identified variables and functions"""
        func_counter = 1
        for func_name in self.function_map.keys():
            new_name = f"function_{func_counter}"
            while new_name in self.used_names or new_name in self.lua_keywords:
                func_counter += 1
                new_name = f"function_{func_counter}"
            self.function_map[func_name] = new_name
            self.used_names.add(new_name)
            func_counter += 1
        
        var_counter = 1
        context_counters = defaultdict(int)
        
        for var_name in self.variable_map.keys():
            context = self._determine_variable_context(var_name)
            
            if context and context in self.context_names:
                context_names = self.context_names[context]
                context_counters[context] %= len(context_names)
                base_name = context_names[context_counters[context]]
                context_counters[context] += 1
                
                new_name = base_name
                suffix = 1
                while new_name in self.used_names or new_name in self.lua_keywords:
                    new_name = f"{base_name}_{suffix}"
                    suffix += 1
            else:
                new_name = f"var_{var_counter}"
                while new_name in self.used_names or new_name in self.lua_keywords:
                    var_counter += 1
                    new_name = f"var_{var_counter}"
                var_counter += 1
            
            self.variable_map[var_name] = new_name
            self.used_names.add(new_name)
    
    def _determine_variable_context(self, var_name: str) -> Optional[str]:
        """Try to determine the context/type of a variable"""
        if len(var_name) == 1 and var_name in 'ijk':
            return 'loop'
        # Optionally: detect string/number/table types from naming patterns
        if re.search(r'(txt|str|msg|content)', var_name, re.IGNORECASE):
            return 'string'
        if re.search(r'(num|cnt|val|total|length|size)', var_name, re.IGNORECASE):
            return 'number'
        if re.search(r'(is_|has_|flag|enabled|active)', var_name, re.IGNORECASE):
            return 'boolean'
        if re.search(r'(list|array|table|dict|map|collection)', var_name, re.IGNORECASE):
            return 'table'
        return None
    
    def _apply_renaming(self, code: str) -> str:
        """Apply the variable and function renaming to the code"""
        # Only apply separately
        for old_name, new_name in self.variable_map.items():
            if new_name:
                pattern = r'\b' + re.escape(old_name) + r'\b'
                code = re.sub(pattern, new_name, code)
        for old_name, new_name in self.function_map.items():
            if new_name:
                pattern = r'\b' + re.escape(old_name) + r'\b'
                code = re.sub(pattern, new_name, code)
        return code
    
    def get_mapping_report(self) -> str:
        """Generate a report of all variable and function mappings"""
        report = ["Variable and Function Renaming Report", "=" * 40]
        
        if self.function_map:
            report.append("\nFunctions:")
            for old, new in self.function_map.items():
                if new:
                    report.append(f"  {old} -> {new}")
        
        if self.variable_map:
            report.append("\nVariables:")
            for old, new in self.variable_map.items():
                if new:
                    report.append(f"  {old} -> {new}")
        
        return "\n".join(report)
