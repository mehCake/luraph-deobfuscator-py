import re
import math
import logging
from typing import Dict, List, Any

class LuaVMSimulator:
    """
    Simplified Lua VM simulator for analyzing obfuscated code patterns
    without full execution. Focuses on constant extraction and control flow.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.variables: Dict[str, Any] = {}
        self.functions: Dict[str, str] = {}
        self.tables: Dict[str, List[Any]] = {}
        self.stack: List[Any] = []
        self.pc: int = 0  # Program counter
        self.instructions: List[str] = []

        # Built-in functions simulation
        self.builtins = {
            'string.char': self._string_char,
            'string.byte': self._string_byte,
            'string.sub': self._string_sub,
            'table.concat': self._table_concat,
            'table.insert': self._table_insert,
            'math.floor': math.floor,
            'math.ceil': math.ceil,
            'tonumber': self._tonumber,
            'tostring': str,
        }

    def _string_char(self, *args):
        try:
            return ''.join(chr(int(arg)) for arg in args if 0 <= int(arg) <= 255)
        except (ValueError, OverflowError):
            return ''

    def _string_byte(self, string_val, i=1):
        try:
            return ord(string_val[i - 1]) if 0 < i <= len(string_val) else None
        except (IndexError, TypeError):
            return None

    def _string_sub(self, string_val, i, j=None):
        try:
            if j is None:
                return string_val[i - 1:]
            return string_val[i - 1:j]
        except (IndexError, TypeError):
            return ''

    def _table_concat(self, table, sep='', i=1, j=None):
        try:
            if isinstance(table, list):
                if j is None:
                    j = len(table)
                return sep.join(str(x) for x in table[i - 1:j])
            return ''
        except (IndexError, TypeError):
            return ''

    def _table_insert(self, table, pos, value=None):
        try:
            if value is None:
                value = pos
                pos = len(table) + 1
            if isinstance(table, list):
                table.insert(pos - 1, value)
        except (IndexError, TypeError):
            pass

    def _tonumber(self, value, base=10):
        try:
            if isinstance(value, (int, float)):
                return value
            if isinstance(value, str):
                if base == 10:
                    return int(value) if value.isdigit() else float(value)
                return int(value, base)
        except (ValueError, TypeError):
            return None

    def parse_simple_expression(self, expr: str) -> Any:
        expr = expr.strip()

        # String literal
        if (expr.startswith('"') and expr.endswith('"')) or \
           (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]

        # Numeric literal
        if expr.isdigit():
            return int(expr)
        try:
            if '.' in expr:
                return float(expr)
        except ValueError:
            pass

        # Hex literal
        if expr.startswith('0x'):
            try:
                return int(expr, 16)
            except ValueError:
                pass

        # Variable lookup
        if expr in self.variables:
            return self.variables[expr]

        # Simple math
        for op in ['+', '-', '*', '/', '%']:
            if op in expr:
                parts = expr.split(op, 1)
                if len(parts) == 2:
                    left = self.parse_simple_expression(parts[0])
                    right = self.parse_simple_expression(parts[1])
                    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                        try:
                            return {
                                '+': left + right,
                                '-': left - right,
                                '*': left * right,
                                '/': left / right if right != 0 else None,
                                '%': left % right if right != 0 else None
                            }[op]
                        except Exception:
                            return None
        return expr

    def simulate_function_call(self, func_name: str, args: List[str]) -> Any:
        parsed_args = [self.parse_simple_expression(arg) for arg in args]

        if func_name in self.builtins:
            try:
                return self.builtins[func_name](*parsed_args)
            except Exception as e:
                self.logger.debug(f"Error calling {func_name}: {e}")
                return None

        if func_name in self.functions:
            return self.execute_function(func_name, parsed_args)
        return None

    def execute_function(self, func_name: str, args: List[Any]) -> Any:
        if func_name not in self.functions:
            return None
        func_def = self.functions[func_name]
        return_match = re.search(r'return\s+([^;\n]+)', func_def)
        if return_match:
            return self.parse_simple_expression(return_match.group(1).strip())
        return None

    def analyze_control_flow(self, content: str) -> Dict[str, List]:
        patterns = {
            'if_statements': [],
            'for_loops': [],
            'while_loops': [],
            'function_calls': [],
            'assignments': []
        }

        if_pattern = r'if\s+(.*?)\s+then(.*?)end'
        for match in re.finditer(if_pattern, content, re.DOTALL):
            patterns['if_statements'].append({
                'condition': match.group(1).strip(),
                'body': match.group(2).strip(),
                'position': match.start()
            })

        for_pattern = r'for\s+(\w+)\s*=\s*([^,]+),\s*([^do]+)do(.*?)end'
        for match in re.finditer(for_pattern, content, re.DOTALL):
            patterns['for_loops'].append({
                'variable': match.group(1),
                'start': match.group(2).strip(),
                'end': match.group(3).strip(),
                'body': match.group(4).strip(),
                'position': match.start()
            })

        while_pattern = r'while\s+(.*?)\s+do(.*?)end'
        for match in re.finditer(while_pattern, content, re.DOTALL):
            patterns['while_loops'].append({
                'condition': match.group(1).strip(),
                'body': match.group(2).strip(),
                'position': match.start()
            })

        call_pattern = r'(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(call_pattern, content):
            patterns['function_calls'].append({
                'function': match.group(1),
                'args': [arg.strip() for arg in match.group(2).split(',') if arg.strip()],
                'position': match.start()
            })

        assign_pattern = r'(\w+)\s*=\s*([^;\n]+)'
        for match in re.finditer(assign_pattern, content):
            patterns['assignments'].append({
                'variable': match.group(1),
                'value': match.group(2).strip(),
                'position': match.start()
            })

        return patterns

    def extract_string_operations(self, content: str) -> List[Dict[str, Any]]:
        operations = []

        concat_pattern = r'([^.\s][^.]*)\.\.\s*([^.\s][^.]*)'
        for match in re.finditer(concat_pattern, content):
            left = self.parse_simple_expression(match.group(1))
            right = self.parse_simple_expression(match.group(2))
            if isinstance(left, str) and isinstance(right, str):
                operations.append({
                    'type': 'concatenation',
                    'left': left,
                    'right': right,
                    'result': left + right,
                    'position': match.start()
                })

        string_funcs = ['string.char', 'string.byte', 'string.sub', 'string.find']
        for func in string_funcs:
            func_pattern = f'{func}\\s*\\(([^)]*)\\)'
            for match in re.finditer(func_pattern, content):
                args = [arg.strip() for arg in match.group(1).split(',') if arg.strip()]
                operations.append({
                    'type': 'function_call',
                    'function': func,
                    'args': args,
                    'result': self.simulate_function_call(func, args),
                    'position': match.start()
                })

        return operations

    def simulate_execution_path(self, content: str) -> Dict[str, Any]:
        self.logger.info("Starting VM simulation...")

        # Extract function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(.*?)\s*end'
        for match in re.finditer(func_pattern, content, re.DOTALL):
            self.functions[match.group(1)] = match.group(2)

        # Extract table definitions
        table_pattern = r'(\w+)\s*=\s*\{([^}]*)\}'
        for match in re.finditer(table_pattern, content):
            elements = [self.parse_simple_expression(e.strip()) for e in match.group(2).split(',')]
            self.tables[match.group(1)] = elements

        control_flow = self.analyze_control_flow(content)
        string_ops = self.extract_string_operations(content)

        # Resolve variables
        for assignment in control_flow['assignments']:
            self.variables[assignment['variable']] = self.parse_simple_expression(assignment['value'])

        simulated_calls = []
        for call in control_flow['function_calls']:
            simulated_calls.append({
                'function': call['function'],
                'args': call['args'],
                'result': self.simulate_function_call(call['function'], call['args']),
                'position': call['position']
            })

        return {
            'functions': dict(self.functions),
            'tables': dict(self.tables),
            'variables': dict(self.variables),
            'control_flow': control_flow,
            'string_operations': string_ops,
            'simulated_calls': simulated_calls,
            'execution_summary': {
                'functions_defined': len(self.functions),
                'tables_created': len(self.tables),
                'variables_assigned': len(self.variables),
                'function_calls_simulated': len(simulated_calls),
                'string_operations': len(string_ops)
            }
        }
