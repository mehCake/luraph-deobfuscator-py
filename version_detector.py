import re
from typing import List, Dict

class EnhancedLuraphDetector:
    """Improved detection of Luraph obfuscation versions and variants"""

    def __init__(self):
        # Additional patterns for more robust detection
        self.extra_patterns = {
            'v1.x': [
                r'eval\(',  # dynamic eval
                r'function\s*\(\s*\)',  # anonymous functions
                r'_G\[["\']\w+["\']\]'  # global table access
            ],
            'v2.x': [
                r'bit\.32\.',  # bit32 operations
                r'load\(',  # alternative loader
                r'coroutine\.resume'  # coroutine usage
            ],
            'v3.x': [
                r'debug\.setupvalue',
                r'debug\.getupvalue',
                r'setmetatable\s*\(.*, __index'
            ],
            'v4.x': [
                r'pcall\s*\(function',
                r'rawget\s*\(_ENV',
                r'checksum|hash',  # anti-tamper
            ],
            'v5.x': [
                r'debug\.getlocal',
                r'custom_cipher',
                r'math\.randomseed',
                r'unpack\s*\('
            ]
        }
        # Extra variant patterns
        self.extra_variant_patterns = {
            'standard': r'_G|_ENV',
            'premium': r'getfenv|setfenv',
            'enterprise': r'coroutine|thread|yield',
            'custom': r'__[A-Z]{3,}__|_[a-z]+_'
        }

    def detect_version(self, content: str) -> Dict[str, int]:
        """Score detection based on extra patterns"""
        scores = {v: 0 for v in self.extra_patterns.keys()}
        for version, patterns in self.extra_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                scores[version] += len(matches)
        return scores

    def detect_variant(self, content: str) -> Dict[str, int]:
        """Score variant detection"""
        scores = {v: 0 for v in self.extra_variant_patterns.keys()}
        for variant, pattern in self.extra_variant_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            scores[variant] += len(matches)
        return scores

    def most_likely(self, scores: Dict[str, int]) -> str:
        """Return key with highest score or unknown"""
        if not scores or max(scores.values()) == 0:
            return "unknown"
        return max(scores, key=scores.get)

# Example usage:
# detector = EnhancedLuraphDetector()
# version_scores = detector.detect_version(lua_code_content)
# variant_scores = detector.detect_variant(lua_code_content)
# most_likely_version = detector.most_likely(version_scores)
# most_likely_variant = detector.most_likely(variant_scores)
