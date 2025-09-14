"""
Obfuscation Analysis Modules
"""

import re
from typing import Dict, List
from collections import defaultdict, Counter
import logging
from .utils import safe_read_file


class ObfuscationDetector:
    """Detects various types of obfuscation in Lua code"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = self._initialize_patterns()

    def _initialize_patterns(self) -> Dict[str, List[str]]:
        """Initialize obfuscation detection patterns"""
        return {
            'string_obfuscation': [
                r'loadstring\s*\(',
                r'\\x[0-9a-fA-F]{2}',
                r'\\[0-9]{1,3}',
                r'string\.char\s*\(',
                r'string\.byte\s*\(',
            ],
            'variable_mangling': [
                r'\b[a-zA-Z_][a-zA-Z0-9_]{20,}\b',  # Very long variable names
                r'\b[lI1O0]{3,}\b',  # Confusing characters
                r'\b_[_a-zA-Z0-9]+_\b',  # Underscore wrapped
            ],
            'control_flow': [
                r'goto\s+\w+',
                r'::\w+::',
                r'repeat.*until\s+false',
                r'while\s+true\s+do.*break',
            ],
            'function_obfuscation': [
                r'function\s*\(\s*\)\s*return\s+[^;]+\s*end',
                r'local\s+\w+\s*=\s*function\s*\([^)]*\)\s*return',
            ],
            'dead_code': [
                r'if\s+false\s+then',
                r'while\s+false\s+do',
                r'local\s+\w+\s*=\s*nil',
            ]
        }

    def analyze_code(self, code: str) -> Dict[str, any]:
        """Analyze code and return obfuscation information"""
        analysis = {
            'obfuscation_score': 0,
            'detected_types': [],
            'confidence': 'low',
            'recommendations': [],
            'statistics': self._calculate_statistics(code)
        }

        for obf_type, patterns in self.patterns.items():
            score = self._detect_pattern_type(code, patterns)
            if score > 0:
                analysis['detected_types'].append({
                    'type': obf_type,
                    'score': score,
                    'severity': self._get_severity(score)
                })
                analysis['obfuscation_score'] += score

        analysis['confidence'] = self._calculate_confidence(analysis['obfuscation_score'])
        analysis['recommendations'] = self._generate_recommendations(analysis['detected_types'])

        return analysis

    def _detect_pattern_type(self, code: str, patterns: List[str]) -> int:
        score = 0
        for pattern in patterns:
            matches = len(re.findall(pattern, code, re.IGNORECASE | re.MULTILINE))
            score += matches * 10
        return score

    def _get_severity(self, score: int) -> str:
        if score >= 100:
            return 'high'
        elif score >= 50:
            return 'medium'
        else:
            return 'low'

    def _calculate_confidence(self, total_score: int) -> str:
        if total_score >= 200:
            return 'high'
        elif total_score >= 100:
            return 'medium'
        else:
            return 'low'

    def _calculate_statistics(self, code: str) -> Dict[str, any]:
        lines = code.split('\n')
        code_lines = [l for l in lines if l.strip() and not l.strip().startswith('--')]
        comment_lines = [l for l in lines if l.strip().startswith('--')]

        return {
            'total_lines': len(lines),
            'code_lines': len(code_lines),
            'comment_lines': len(comment_lines),
            'empty_lines': len([l for l in lines if not l.strip()]),
            'average_line_length': sum(len(l) for l in lines) / len(lines) if lines else 0,
            'function_count': len(re.findall(r'function\s+\w*\s*\(', code)),
            'variable_count': len(set(re.findall(r'local\s+(\w+)', code))),
            'string_literals': len(re.findall(r'["\'].*?["\']', code))
        }

    def _generate_recommendations(self, detected_types: List[Dict]) -> List[str]:
        recommendations = []

        type_names = [dt['type'] for dt in detected_types]

        if 'string_obfuscation' in type_names:
            recommendations.append("Enable string decryption")
        if 'variable_mangling' in type_names:
            recommendations.append("Enable variable renaming")
        if 'control_flow' in type_names:
            recommendations.append("Enable control flow simplification")
        if 'function_obfuscation' in type_names:
            recommendations.append("Enable function call resolution")
        if 'dead_code' in type_names:
            recommendations.append("Enable dead code removal")
        if not recommendations:
            recommendations.append("Code appears to have minimal obfuscation")

        return recommendations


class CodeStructureAnalyzer:
    """Analyzes code structure and complexity"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_structure(self, code: str) -> Dict[str, any]:
        return {
            'functions': self._analyze_functions(code),
            'variables': self._analyze_variables(code),
            'complexity': self._analyze_complexity(code),
            'dependencies': self._analyze_dependencies(code)
        }

    def _analyze_functions(self, code: str) -> Dict[str, any]:
        func_defs = re.findall(r'function\s+(\w+)\s*\([^)]*\)', code)
        local_func_defs = re.findall(r'local\s+function\s+(\w+)\s*\([^)]*\)', code)
        func_calls = re.findall(r'(\w+)\s*\([^)]*\)', code)

        return {
            'definitions': func_defs + local_func_defs,
            'calls': func_calls,
            'definition_count': len(func_defs + local_func_defs),
            'call_count': len(func_calls),
            'call_frequency': Counter(func_calls)
        }

    def _analyze_variables(self, code: str) -> Dict[str, any]:
        local_vars = re.findall(r'local\s+(\w+)', code)
        global_vars = re.findall(r'^(\w+)\s*=', code, re.MULTILINE)

        var_usage = defaultdict(int)
        all_vars = set(local_vars + global_vars)

        for var in all_vars:
            var_usage[var] = len(re.findall(rf'\b{var}\b', code))

        return {
            'local_variables': local_vars,
            'global_variables': global_vars,
            'usage_frequency': dict(var_usage),
            'unused_variables': [var for var, count in var_usage.items() if count <= 1]
        }

    def _analyze_complexity(self, code: str) -> Dict[str, any]:
        lines = code.split('\n')
        decision_points = len(re.findall(r'\b(if|while|for|repeat|until)\b', code))
        nesting_depth = self._calculate_max_nesting(code)

        return {
            'cyclomatic_complexity': decision_points + 1,
            'nesting_depth': nesting_depth,
            'line_complexity': len([l for l in lines if len(l) > 100]),
            'decision_points': decision_points
        }

    def _calculate_max_nesting(self, code: str) -> int:
        current_depth = 0
        max_depth = 0
        for line in code.split('\n'):
            line = line.strip()
            if re.search(r'\b(if|while|for|repeat|function|do)\b', line):
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            if re.search(r'\b(end|until)\b', line):
                current_depth = max(0, current_depth - 1)
        return max_depth


def analyze_file(path: str) -> Dict[str, any]:
    """Convenience wrapper to analyze a file on disk."""
    content = safe_read_file(path)
    if content is None:
        return {}
    detector = ObfuscationDetector()
    return detector.analyze_code(content)


    def _analyze_dependencies(self, code: str) -> Dict[str, any]:
        requires = re.findall(r'require\s*\(\s*["\']([^"\']+)["\']', code)
        loadstrings = len(re.findall(r'loadstring\s*\(', code))
        external_calls = []
        lua_builtins = ['print', 'type', 'tostring', 'tonumber', 'pairs', 'ipairs', 'next']

        for builtin in lua_builtins:
            if re.search(rf'\b{builtin}\s*\(', code):
                external_calls.append(builtin)

        return {
            'requires': requires,
            'loadstring_calls': loadstrings,
            'builtin_usage': external_calls,
            'has_external_dependencies': len(requires) > 0 or loadstrings > 0
        }


class StringAnalyzer:
    """Analyzes string patterns and potential obfuscation"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze_strings(self, code: str) -> Dict[str, any]:
        strings = self._extract_strings(code)

        return {
            'total_strings': len(strings),
            'encoded_strings': self._count_encoded_strings(strings),
            'suspicious_strings': self._find_suspicious_strings(strings),
            'string_patterns': self._analyze_string_patterns(strings),
            'encryption_indicators': self._detect_encryption_indicators(code)
        }

    def _extract_strings(self, code: str) -> List[str]:
        """Extract all string literals from code"""
        pattern = r'(["\'])(?:(?=(\\?))\2.)*?\1'
        return re.findall(pattern, code)  # returns tuples
        # Flatten results
        # return [m[0] for m in re.findall(pattern, code)]

    def _count_encoded_strings(self, strings: List[str]) -> int:
        encoded_count = 0
        for string in strings:
            if re.search(r'\\x[0-9a-fA-F]{2}', string) or \
               re.search(r'\\[0-9]{1,3}', string) or \
               re.search(r'[A-Za-z0-9+/]{20,}=*$', string) or \
               len(string) > 100 and ' ' not in string:
                encoded_count += 1
        return encoded_count

    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        suspicious = []
        for string in strings:
            clean_string = string.strip('\'"')
            if len(clean_string) > 50 and not any(c.isspace() for c in clean_string) and \
               sum(1 for c in clean_string if c.isalnum()) / len(clean_string) > 0.8:
                suspicious.append(string)
        return suspicious

    def _analyze_string_patterns(self, strings: List[str]) -> Dict[str, int]:
        patterns = {
            'hex_encoded': 0,
            'base64_like': 0,
            'long_strings': 0,
            'repeated_chars': 0
        }

        for string in strings:
            clean = string.strip('\'"')
            if re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) > 10:
                patterns['hex_encoded'] += 1
            if re.match(r'^[A-Za-z0-9+/]+=*$', clean) and len(clean) > 20:
                patterns['base64_like'] += 1
            if len(clean) > 100:
                patterns['long_strings'] += 1
            if len(set(clean)) < len(clean) * 0.3 and len(clean) > 10:
                patterns['repeated_chars'] += 1

        return patterns

    def _detect_encryption_indicators(self, code: str) -> List[str]:
        indicators = []
        encryption_patterns = {
            'xor_operations': r'\^',
            'bit_operations': r'\b(bit\.|band|bor|bxor|bnot|lshift|rshift)\b',
            'char_manipulation': r'string\.char\s*\(',
            'byte_operations': r'string\.byte\s*\(',
            'math_random': r'math\.random\s*\(',
        }
        for indicator, pattern in encryption_patterns.items():
            if re.search(pattern, code):
                indicators.append(indicator)
        return indicators
