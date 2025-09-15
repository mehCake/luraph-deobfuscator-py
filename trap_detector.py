import re
import logging
from typing import List, Dict, Any

class TrapDetector:
    """Detects and removes anti-deobfuscation traps from Luraph/LuaMor obfuscated code."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Common trap patterns
        self.trap_patterns = {
            'pcall_traps': [
                r'pcall\s*\(\s*function\s*\(\s*\)\s*error\s*\(["\'].*?["\'].*?\)\s*end\s*\)',
                r'pcall\s*\(\s*loadstring\s*\(["\'].*?error.*?["\'].*?\)\s*\)',
                r'pcall\s*\(\s*function\s*\(\s*\)\s*while\s+true\s+do\s*end\s*end\s*\)',
            ],
            'xpcall_traps': [
                r'xpcall\s*\(\s*function\s*\(\s*\).*?error.*?end\s*,\s*function.*?\)',
                r'xpcall\s*\(\s*loadstring.*?,\s*function.*?\)',
            ],
            'fake_loadstring': [
                r'loadstring\s*\(["\'].*?syntax\s+error.*?["\'].*?\)',
                r'loadstring\s*\(["\'].*?attempt\s+to.*?["\'].*?\)',
                r'loadstring\s*\(["\'].*?\x00.*?["\'].*?\)',
            ],
            'dummy_functions': [
                r'local\s+function\s+\w+\s*\(\s*\)\s*end',
                r'function\s+\w+\s*\(\s*\)\s*return\s*end',
                r'function\s+\w+\s*\(\s*.*?\s*\)\s*return\s+.*?\s*end',
            ],
            'infinite_loops': [
                r'while\s+true\s+do\s*end',
                r'repeat\s*until\s+false',
                r'for\s+\w+\s*=\s*1\s*,\s*math\.huge\s+do.*?end',
            ],
            'debug_hooks': [
                r'debug\.sethook\s*\([^)]+\)',
                r'debug\.traceback\s*\([^)]*\)',
            ],
            'environment_checks': [
                r'getfenv\s*\(\s*\)\s*\[\s*["\'].*?["\'].*?\s*\]',
                r'_G\s*\[\s*["\'].*?["\'].*?\].*?==.*?nil',
                r'type\s*\(\s*.*?\s*\)\s*~=\s*["\']function["\']',
            ],
        }

        # Function wrappers that do nothing
        self.dummy_wrapper_patterns = [
            r'local\s+(\w+)\s*=\s*function\s*\(\s*([^)]*)\s*\)\s*return\s+([^()]+)\s*\(\s*\2\s*\)\s*end',
            r'function\s+(\w+)\s*\(\s*([^)]*)\s*\)\s*return\s+([^()]+)\s*\(\s*\2\s*\)\s*end',
        ]

    def detect_traps(self, code: str) -> Dict[str, List[str]]:
        """Detect all types of anti-deobfuscation traps in the code."""
        detected_traps = {}
        for trap_type, patterns in self.trap_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, code, re.IGNORECASE | re.DOTALL)
                matches.extend(found)
            if matches:
                detected_traps[trap_type] = matches
                self.logger.info(f"Detected {len(matches)} {trap_type}")
        return detected_traps

    def remove_traps(self, code: str) -> str:
        """Remove detected traps from the code."""
        cleaned_code = code
        for trap_type, patterns in self.trap_patterns.items():
            for pattern in patterns:
                cleaned_code = re.sub(pattern, '', cleaned_code, flags=re.IGNORECASE | re.DOTALL)
        cleaned_code = self._remove_dummy_wrappers(cleaned_code)
        # Cleanup empty lines
        cleaned_code = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned_code)
        cleaned_code = re.sub(r'^\s*\n', '', cleaned_code, flags=re.MULTILINE)
        return cleaned_code

    def _remove_dummy_wrappers(self, code: str) -> str:
        """Remove function wrappers that do nothing but obscure calls."""
        cleaned_code = code
        for pattern in self.dummy_wrapper_patterns:
            matches = re.finditer(pattern, cleaned_code, re.IGNORECASE | re.DOTALL)
            for match in matches:
                wrapper_name = match.group(1)
                actual_function = match.group(3)
                # Remove wrapper definition
                cleaned_code = cleaned_code.replace(match.group(0), '')
                # Replace all calls to wrapper with actual function calls
                wrapper_call_pattern = rf'\b{re.escape(wrapper_name)}\s*\('
                cleaned_code = re.sub(wrapper_call_pattern, f'{actual_function}(', cleaned_code)
        return cleaned_code

    def analyze_function_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze functions to identify likely dummy functions."""
        functions = re.findall(
            r'(?:local\s+)?function\s+(\w+)\s*\([^)]*\)(.*?)end',
            code, re.DOTALL | re.IGNORECASE
        )
        analysis = {
            'total_functions': len(functions),
            'likely_dummies': [],
            'complex_functions': [],
            'suspicious_functions': []
        }
        for func_name, func_body in functions:
            body_lines = [line.strip() for line in func_body.split('\n') if line.strip()]
            non_comment_lines = [line for line in body_lines if not line.startswith('--')]
            characteristics = {
                'name': func_name,
                'total_lines': len(body_lines),
                'code_lines': len(non_comment_lines),
                'has_return': 'return' in func_body.lower(),
                'has_loops': any(k in func_body.lower() for k in ['while', 'for', 'repeat']),
                'has_conditionals': any(k in func_body.lower() for k in ['if', 'elseif', 'else']),
                'calls_other_functions': len(re.findall(r'\w+\s*\(', func_body)) > 0
            }
            if characteristics['code_lines'] <= 1 and not characteristics['has_return']:
                analysis['likely_dummies'].append(characteristics)
            elif (characteristics['code_lines'] > 10 and 
                  characteristics['has_loops'] and 
                  characteristics['has_conditionals']):
                analysis['complex_functions'].append(characteristics)
            elif (characteristics['calls_other_functions'] and 
                  not characteristics['has_loops'] and 
                  not characteristics['has_conditionals']):
                analysis['suspicious_functions'].append(characteristics)
        return analysis

    def detect_anti_debug_checks(self, code: str) -> List[str]:
        """Detect specific anti-debugging checks."""
        anti_debug_patterns = [
            r'debug\.getinfo\s*\(\s*\d+\s*\)',
            r'string\.dump\s*\([^)]+\)',
            r'getfenv\s*\(\s*0\s*\)',
            r'coroutine\.running\s*\(\s*\)',
            r'collectgarbage\s*\(\s*["\']count["\'].*?\)',
            r'os\.clock\s*\(\s*\).*?os\.clock\s*\(\s*\)',
        ]
        detected_checks = []
        for pattern in anti_debug_patterns:
            detected_checks.extend(re.findall(pattern, code, re.IGNORECASE | re.DOTALL))
        return detected_checks

    def sanitize_code(self, code: str) -> str:
        """Perform comprehensive code sanitization."""
        self.logger.info("Starting comprehensive trap detection and removal...")
        self.detect_traps(code)
        cleaned_code = self.remove_traps(code)
        cleaned_code = self.neutralize_advanced_traps(cleaned_code)
        self.analyze_function_complexity(cleaned_code)
        self.detect_anti_debug_checks(cleaned_code)
        return cleaned_code
    # Advanced trap neutralisation
    def neutralize_advanced_traps(self, code: str) -> str:
        """Replace advanced anti-debug checks with benign stubs.

        This makes line number checks via ``debug.getinfo`` return a static value,
        forces ``pcall`` to always succeed and neuters ``string.dump`` based
        integrity verification.  The original calls are replaced and small stub
        helpers are injected at the top of the script so execution can continue
        without triggering the protections.
        """

        stubs: List[str] = []

        if re.search(r'debug\.getinfo', code):
            code = re.sub(r'debug\.getinfo', 'debug_getinfo_stub', code)
            stubs.append('local debug_getinfo_stub=function(...) return {currentline=0} end')

        if re.search(r'\bpcall\b', code):
            code = re.sub(r'\bpcall\b', 'pcall_stub', code)
            stubs.append('local pcall_stub=function(f, ...) return true, f(...) end')

        if re.search(r'string\.dump', code):
            code = re.sub(r'string\.dump', 'dump_stub', code)
            stubs.append('local dump_stub=function(f) return "" end')

        if stubs:
            code = '\n'.join(stubs) + '\n' + code

        return code
