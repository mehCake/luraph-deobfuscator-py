import re
import logging
from typing import Dict, Set, List, Any
from collections import defaultdict

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class VariableRenamer:
    """Provides heuristic variable renaming for obfuscated Lua code."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.variable_map: Dict[str, str] = {}
        self.used_names: Set[str] = set()
        self.context_hints: Dict[str, Any] = {}

        # Common variable name patterns
        self.name_patterns = {
            'loop_indices': ['i', 'j', 'k', 'index', 'idx'],
            'counters': ['count', 'counter', 'num', 'n'],
            'temporary': ['temp', 'tmp', 'val', 'value'],
            'strings': ['str', 'string', 'text', 'msg'],
            'tables': ['tbl', 'table', 'data', 'list'],
            'functions': ['func', 'fn', 'callback', 'handler'],
            'results': ['result', 'ret', 'output', 'res'],
            'flags': ['flag', 'enabled', 'active', 'state'],
            'lengths': ['len', 'length', 'size', 'count']
        }

        # Reserved Lua keywords to avoid
        self.lua_keywords = {
            'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
            'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
            'return', 'then', 'true', 'until', 'while'
        }

        # Common Lua globals to avoid
        self.lua_globals = {
            'print', 'type', 'pairs', 'ipairs', 'next', 'tostring', 'tonumber',
            'string', 'table', 'math', 'io', 'os', 'debug', 'coroutine',
            'package', 'require', 'load', 'loadstring', 'pcall', 'xpcall',
            'error', 'assert', 'select', 'unpack', 'rawget', 'rawset',
            'getmetatable', 'setmetatable', 'getfenv', 'setfenv'
        }

    def analyze_variable_usage(self, code: str) -> Dict[str, Any]:
        """Analyze how variables are used to infer their purpose."""
        analysis = defaultdict(lambda: {
            'occurrences': 0,
            'contexts': [],
            'likely_type': 'unknown',
            'scope': 'unknown'
        })

        # Patterns for variable analysis
        patterns = {
            'local_declarations': r'local\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*)*)',
            'for_loops': r'for\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
            'for_pairs': r'for\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*)*)\s+in',
            'function_params': r'function\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(([^)]*)\)',
            'assignments': r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
            'table_access': r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\[',
            'function_calls': r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            'string_operations': r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\.',
            'numeric_operations': r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[+\-*/]',
            'comparisons': r'([a-zA-Z_][a-zA-Z0-9_]*)\s*[<>=!~]',
            'length_operations': r'#([a-zA-Z_][a-zA-Z0-9_]*)'
        }

        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, code)
            for match in matches:
                if isinstance(match, tuple):
                    variables = [v.strip() for v in match if v.strip()]
                else:
                    variables = [v.strip() for v in match.split(',') if v.strip()]

                for var in variables:
                    if var and re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var):
                        analysis[var]['occurrences'] += 1
                        analysis[var]['contexts'].append(pattern_name)

        # Infer variable types
        for var, info in analysis.items():
            contexts = set(info['contexts'])
            if 'for_loops' in contexts:
                info['likely_type'] = 'loop_index'
            elif 'length_operations' in contexts:
                info['likely_type'] = 'table_or_string'
            elif 'string_operations' in contexts:
                info['likely_type'] = 'string'
            elif 'numeric_operations' in contexts:
                info['likely_type'] = 'number'
            elif 'table_access' in contexts:
                info['likely_type'] = 'table'
            elif 'function_calls' in contexts:
                info['likely_type'] = 'function'
            elif 'comparisons' in contexts:
                info['likely_type'] = 'comparable'

        return dict(analysis)

    def generate_meaningful_name(self, old_name: str, var_info: Dict[str, Any]) -> str:
        """Generate a meaningful name based on variable usage analysis."""
        likely_type = var_info.get('likely_type', 'unknown')
        contexts = var_info.get('contexts', [])
        base_names: List[str] = []

        if likely_type == 'loop_index':
            base_names = self.name_patterns['loop_indices']
        elif likely_type == 'string':
            base_names = self.name_patterns['strings']
        elif likely_type == 'table':
            base_names = self.name_patterns['tables']
        elif likely_type == 'function':
            base_names = self.name_patterns['functions']
        elif likely_type == 'number':
            base_names = self.name_patterns['counters']
        else:
            if 'for_loops' in contexts or 'for_pairs' in contexts:
                base_names = self.name_patterns['loop_indices']
            elif 'function_params' in contexts:
                base_names = ['param', 'arg', 'value']
            else:
                base_names = self.name_patterns['temporary']

        for base_name in base_names:
            candidate = base_name
            counter = 1
            while (candidate in self.used_names or 
                   candidate in self.lua_keywords or 
                   candidate in self.lua_globals):
                candidate = f"{base_name}{counter}"
                counter += 1
            self.used_names.add(candidate)
            return candidate  # Return only after valid candidate found

        # Fallback
        counter = 1
        while f"var{counter}" in self.used_names:
            counter += 1
        candidate = f"var{counter}"
        self.used_names.add(candidate)
        return candidate

    def detect_obfuscated_variables(self, code: str) -> Set[str]:
        """Detect variables that are likely obfuscated."""
        obfuscated_vars: Set[str] = set()
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        all_vars = set(re.findall(var_pattern, code))

        for var in all_vars:
            if var in self.lua_keywords or var in self.lua_globals:
                continue
            is_obfuscated = (
                (len(var) == 1 and var not in ['i', 'j', 'k', 'n', 'x', 'y', 'z']) or
                (len(var) <= 3 and not any(word in var.lower() for word_list in self.name_patterns.values() for word in word_list)) or
                (len([c for c in var if c.isupper()]) > len(var) // 2 and len(var) > 1) or
                re.match(r'.*\d.*[a-zA-Z].*\d.*', var) or
                var.count('_') > len(var) // 3 or
                (len(var) > 10 and not any(common in var.lower() for common in ['function', 'table', 'string', 'value', 'data']))
            )
            if is_obfuscated:
                obfuscated_vars.add(var)

        self.logger.info(f"Detected {len(obfuscated_vars)} likely obfuscated variables")
        return obfuscated_vars

    def rename_variables(self, code: str, custom_mapping: Dict[str, str] = None) -> str:
        """Rename obfuscated variables with meaningful names."""
        self.logger.info("Starting heuristic variable renaming...")
        if custom_mapping:
            self.variable_map.update(custom_mapping)
            self.used_names.update(custom_mapping.values())

        var_analysis = self.analyze_variable_usage(code)
        obfuscated_vars = self.detect_obfuscated_variables(code)

        for var in obfuscated_vars:
            if var not in self.variable_map:
                var_info = var_analysis.get(var, {})
                new_name = self.generate_meaningful_name(var, var_info)
                self.variable_map[var] = new_name

        renamed_code = code
        sorted_vars = sorted(self.variable_map.items(), key=lambda x: len(x[0]), reverse=True)

        for old_name, new_name in sorted_vars:
            pattern = r'\b' + re.escape(old_name) + r'\b'
            renamed_code = re.sub(pattern, new_name, renamed_code)

        self.logger.info(f"Renamed {len(self.variable_map)} variables")
        return renamed_code

    def create_renaming_report(self) -> str:
        """Create a report of variable renamings performed."""
        if not self.variable_map:
            return "No variables were renamed."

        report = "Variable Renaming Report:\n" + "=" * 50 + "\n\n"
        by_type = defaultdict(list)

        for old_name, new_name in self.variable_map.items():
            var_type = 'other'
            for type_name, names in self.name_patterns.items():
                if any(name in new_name for name in names):
                    var_type = type_name
                    break
            by_type[var_type].append((old_name, new_name))

        for var_type, renames in by_type.items():
            if renames:
                report += f"{var_type.replace('_', ' ').title()}:\n"
                for old_name, new_name in sorted(renames):
                    report += f"  {old_name} -> {new_name}\n"
                report += "\n"

        return report

    def reset(self):
        """Reset the renamer state for a new analysis."""
        self.variable_map.clear()
        self.used_names.clear()
        self.context_hints.clear()
