import re
import math
import logging
from typing import Dict, List, Any, Optional, Union, Callable
from collections import defaultdict

class LuaVMSimulator:
    """
    Simplified Lua VM simulator for analyzing obfuscated code patterns
    without full execution. Focuses on constant extraction and control flow.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.variables = {}
        self.functions = {}
        self.tables = {}
        self.stack = []
        self.pc = 0  # Program counter
        self.instructions = []
        
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
        """Simulate string.char function."""
        try:
            return ''.join(chr(int(arg)) for arg in args if 0 <= int(arg) <= 255)
        except (ValueError, OverflowError):
            return ''
    
    def _string_byte(self, string_val, i=1):
        """Simulate string.byte function."""
        try:
            return ord(string_val[i-1]) if 0 < i <= len(string_val) else None
        except (IndexError, TypeError):
            return None
    
    def _string_sub(self, string_val, i, j=None):
        """Simulate string.sub function."""
        try:
            if j is None:
                return string_val[i-1:]
            return string_val[i-1:j]
        except (IndexError, TypeError):
            return ''
    
    def _table_concat(self, table, sep='', i=1, j=None):
        """Simulate table.concat function."""
        try:
            if isinstance(table, list):
                if j is None:
                    j = len(table)
                return sep.join(str(x) for x in table[i-1:j])
            return ''
        except (IndexError, TypeError):
            return ''
    
    def _table_insert(self, table, pos, value=None):
        """Simulate table.insert function."""
        try:
            if value is None:
                value = pos
                pos = len(table) + 1
            if isinstance(table, list):
                table.insert(pos-1, value)
        except (IndexError, TypeError):
            pass
    
    def _tonumber(self, value, base=10):
        """Simulate tonumber function."""
        try:
            if isinstance(value, (int, float)):
                return value
            if isinstance(value, str):
                if base == 10:
                    return int(value) if value.isdigit() else float(value)
                else:
                    return int(value, base)
        except (ValueError, TypeError):
            return None
    
    def parse_simple_expression(self, expr: str) -> Any:
        """Parse and evaluate simple expressions."""
        expr = expr.strip()
        
        # Handle string literals
        if (expr.startswith('"') and expr.endswith('"')) or \
           (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]
        
        # Handle numeric literals
        if expr.isdigit():
            return int(expr)
        
        try:
            if '.' in expr:
                return float(expr)
        except ValueError:
            pass
        
        # Handle hexadecimal
        if expr.startswith('0x'):
            try:
                return int(expr, 16)
            except ValueError:
                pass
        
        # Handle variables
        if expr in self.variables:
            return self.variables[expr]
        
        # Handle simple mathematical operations
        for op in ['+', '-', '*', '/', '%']:
            if op in expr:
                parts = expr.split(op, 1)
                if len(parts) == 2:
                    try:
                        left = self.parse_simple_expression(parts[0])
                        right = self.parse_simple_expression(parts[1])
                        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                            if op == '+':
                                return left + right
                            elif op == '-':
                                return left - right
                            elif op == '*':
                                return left * right
                            elif op == '/' and right != 0:
                                return left / right
                            elif op == '%' and right != 0:
                                return left % right
                    except (ValueError, TypeError):
                        pass
        
        return expr
    
    def simulate_function_call(self, func_name: str, args: List[str]) -> Any:
        """Simulate function calls."""
        # Parse arguments
        parsed_args = []
        for arg in args:
            parsed_args.append(self.parse_simple_expression(arg))
        
        # Handle built-in functions
        if func_name in self.builtins:
            try:
                return self.builtins[func_name](*parsed_args)
            except Exception as e:
                self.logger.debug(f"Error calling {func_name}: {e}")
                return None
        
        # Handle user-defined functions
        if func_name in self.functions:
            return self.execute_function(func_name, parsed_args)
        
        return None
    
    def execute_function(self, func_name: str, args: List[Any]) -> Any:
        """Execute a user-defined function."""
        if func_name not in self.functions:
            return None
        
        func_def = self.functions[func_name]
        
        # Simple return value extraction
        if 'return' in func_def:
            return_match = re.search(r'return\s+([^;\n]+)', func_def)
            if return_match:
                return_expr = return_match.group(1).strip()
                return self.parse_simple_expression(return_expr)
        
        return None
    
    def analyze_control_flow(self, content: str) -> Dict[str, List]:
        """Analyze control flow patterns in the code."""
        patterns = {
            'if_statements': [],
            'for_loops': [],
            'while_loops': [],
            'function_calls': [],
            'assignments': []
        }
        
        # Find if statements
        if_pattern = r'if\s+([^then]+)\s+then\s*([^end]*)\s*end'
        for match in re.finditer(if_pattern, content, re.DOTALL):
            patterns['if_statements'].append({
                'condition': match.group(1).strip(),
                'body': match.group(2).strip(),
                'position': match.start()
            })
        
        # Find for loops
        for_pattern = r'for\s+(\w+)\s*=\s*([^,]+),\s*([^do]+)\s+do\s*([^end]*)\s*end'
        for match in re.finditer(for_pattern, content, re.DOTALL):
            patterns['for_loops'].append({
                'variable': match.group(1),
                'start': match.group(2).strip(),
                'end': match.group(3).strip(),
                'body': match.group(4).strip(),
                'position': match.start()
            })
        
        # Find while loops
        while_pattern = r'while\s+([^do]+)\s+do\s*([^end]*)\s*end'
        for match in re.finditer(while_pattern, content, re.DOTALL):
            patterns['while_loops'].append({
                'condition': match.group(1).strip(),
                'body': match.group(2).strip(),
                'position': match.start()
            })
        
        # Find function calls
        call_pattern = r'(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(call_pattern, content):
            patterns['function_calls'].append({
                'function': match.group(1),
                'args': [arg.strip() for arg in match.group(2).split(',') if arg.strip()],
                'position': match.start()
            })
        
        # Find assignments
        assign_pattern = r'(\w+)\s*=\s*([^;\n]+)'
        for match in re.finditer(assign_pattern, content):
            patterns['assignments'].append({
                'variable': match.group(1),
                'value': match.group(2).strip(),
                'position': match.start()
            })
        
        return patterns
    
    def extract_string_operations(self, content: str) -> List[Dict[str, Any]]:
        """Extract and analyze string operations."""
        operations = []
        
        # String concatenation patterns
        concat_pattern = r'([^.]*)\.\.\s*([^.]*)'
        for match in re.finditer(concat_pattern, content):
            left = self.parse_simple_expression(match.group(1))
            right = self.parse_simple_expression(match.group(2))
            
            if isinstance(left, str) and isinstance(right, str):
                result = left + right
                operations.append({
                    'type': 'concatenation',
                    'left': left,
                    'right': right,
                    'result': result,
                    'position': match.start()
                })
        
        # String function calls
        string_funcs = ['string.char', 'string.byte', 'string.sub', 'string.find']
        for func in string_funcs:
            func_pattern = f'{func}\\s*\\(([^)]*)\\)'
            for match in re.finditer(func_pattern, content):
                args = [arg.strip() for arg in match.group(1).split(',') if arg.strip()]
                result = self.simulate_function_call(func, args)
                
                operations.append({
                    'type': 'function_call',
                    'function': func,
                    'args': args,
                    'result': result,
                    'position': match.start()
                })
        
        return operations
    
    def simulate_execution_path(self, content: str) -> Dict[str, Any]:
        """Simulate execution and extract runtime information."""
        self.logger.info("Starting VM simulation...")
        
        # Extract function definitions
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*([^end]*)\s*end'
        for match in re.finditer(func_pattern, content, re.DOTALL):
            func_name = match.group(1)
            func_body = match.group(2)
            self.functions[func_name] = func_body
        
        # Extract table definitions
        table_pattern = r'(\w+)\s*=\s*\{([^}]*)\}'
        for match in re.finditer(table_pattern, content):
            table_name = match.group(1)
            table_content = match.group(2)
            
            # Parse table elements
            elements = []
            for element in table_content.split(','):
                element = element.strip()
                parsed = self.parse_simple_expression(element)
                elements.append(parsed)
            
            self.tables[table_name] = elements
        
        # Analyze control flow
        control_flow = self.analyze_control_flow(content)
        
        # Extract string operations
        string_ops = self.extract_string_operations(content)
        
        # Extract variable assignments
        for assignment in control_flow['assignments']:
            var_name = assignment['variable']
            value_expr = assignment['value']
            
            # Try to resolve the value
            resolved_value = self.parse_simple_expression(value_expr)
            self.variables[var_name] = resolved_value
        
        # Simulate function calls
        simulated_calls = []
        for call in control_flow['function_calls']:
            result = self.simulate_function_call(call['function'], call['args'])
            simulated_calls.append({
                'function': call['function'],
                'args': call['args'],
                'result': result,
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