import re
import logging
from typing import Dict, Any, List, Optional
from utils import hex_to_bytes, calculate_entropy


class LuraphVersionDetector:
    """Detects Luraph obfuscation version and variant"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Version signatures and patterns
        self.version_patterns = {
            'v1.x': {
                'patterns': [
                    r'superflow_bytecode_ext\d+',
                    r'loadstring\s*\(\s*(["\']).*?\1\s*\)',
                    r'string\.char\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)'
                ],
                'hex_format': 'simple',
                'vm_type': 'basic',
                'encryption': 'xor'
            },
            'v2.x': {
                'patterns': [
                    r'lPH_\w+',
                    r'bit32\.',
                    r'table\.unpack',
                    r'getfenv\s*\(\s*\d+\s*\)'
                ],
                'hex_format': 'lph',
                'vm_type': 'extended',
                'encryption': 'complex_xor'
            },
            'v3.x': {
                'patterns': [
                    r'lPH_[A-F0-9]{8,}',
                    r'debug\.getupvalue',
                    r'setmetatable\s*\([^)]+__index',
                    r'coroutine\.wrap'
                ],
                'hex_format': 'advanced_lph',
                'vm_type': 'vm_protected',
                'encryption': 'aes_like'
            },
            'v4.x': {
                'patterns': [
                    r'lPH_[A-F0-9]{16,}',
                    r'debug\.setupvalue',
                    r'rawget\s*\(\s*_ENV',
                    r'pcall\s*\(\s*function\s*\(\s*\)',
                    r'select\s*\(\s*["\']#["\']'
                ],
                'hex_format': 'encrypted_lph',
                'vm_type': 'full_vm',
                'encryption': 'multi_layer'
            },
            'v5.x': {
                'patterns': [
                    r'lPH_[A-F0-9]{32,}',
                    r'debug\.getlocal',
                    r'_G\s*\[\s*["\'][^"\']+["\']\s*\]',
                    r'unpack\s*\(\s*{[^}]+}\s*,\s*\d+\s*,\s*\d+\s*\)',
                    r'math\.randomseed'
                ],
                'hex_format': 'obfuscated_lph',
                'vm_type': 'anti_debug',
                'encryption': 'custom_cipher'
            }
        }
        
        # Variant detection patterns
        self.variant_patterns = {
            'standard': r'loadstring|string\.char',
            'premium': r'debug\.|getfenv|setfenv',
            'enterprise': r'coroutine\.|thread|yield',
            'custom': r'_[A-Z]{3,}_|__[a-z]+__'
        }
    
    def detect_version(self, content: str) -> Dict[str, Any]:
        """
        Detect Luraph version and characteristics
        """
        version_scores = {}
        detected_patterns = []
        
        # Test against each version pattern
        for version, info in self.version_patterns.items():
            score = 0
            version_patterns = []
            
            for pattern in info['patterns']:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    score += len(matches)
                    version_patterns.append({
                        'pattern': pattern,
                        'matches': len(matches),
                        'samples': matches[:3]  # First 3 matches
                    })
            
            if score > 0:
                version_scores[version] = score
                detected_patterns.extend(version_patterns)
        
        # Determine most likely version
        if not version_scores:
            detected_version = 'unknown'
            confidence = 0.0
        else:
            detected_version = max(version_scores, key=version_scores.get)
            total_score = sum(version_scores.values())
            confidence = version_scores[detected_version] / total_score
        
        # Detect variant
        variant = self._detect_variant(content)
        
        # Extract hex/LPH strings for analysis
        hex_strings = self._extract_hex_strings(content)
        lph_strings = self._extract_lph_strings(content)
        
        # Additional characteristics
        characteristics = self._analyze_characteristics(content, hex_strings, lph_strings)
        
        version_info = {
            'version': detected_version,
            'variant': variant,
            'confidence': confidence,
            'characteristics': characteristics,
            'hex_strings_preview': hex_strings[:5],  # First 5 for preview
            'lph_strings_preview': lph_strings[:5],
            'patterns_found': detected_patterns,
            'config': self.version_patterns.get(detected_version, {})
        }
        
        self.logger.info(f"Version detection completed: {detected_version} ({confidence:.2%} confidence)")
        return version_info
    
    def _detect_variant(self, content: str) -> str:
        """Detect Luraph variant (standard, premium, enterprise, custom)"""
        variant_scores = {}
        
        for variant, pattern in self.variant_patterns.items():
            matches = len(re.findall(pattern, content, re.IGNORECASE))
            if matches > 0:
                variant_scores[variant] = matches
        
        if not variant_scores:
            return 'unknown'
        
        return max(variant_scores, key=variant_scores.get)
    
    def _extract_hex_strings(self, content: str) -> List[str]:
        """Extract potential hex strings"""
        patterns = [
            r'(["\'])([A-Fa-f0-9]{32,})\1',  # Standard hex in quotes
            r'superflow_bytecode_ext\d+\s*=\s*["\']([A-Fa-f0-9]+)["\']',  # Superflow format
            r'\\x([A-Fa-f0-9]{2})+',  # Escaped hex
            r'0x([A-Fa-f0-9]+)',  # Hex literals
        ]
        
        hex_strings = []
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    hex_str = match[-1] if match[-1] else match[0]
                else:
                    hex_str = match
                
                # Validate hex string
                if len(hex_str) >= 8 and all(c in '0123456789ABCDEFabcdef' for c in hex_str):
                    hex_strings.append(hex_str)
        
        return list(set(hex_strings))  # Remove duplicates
    
    def _extract_lph_strings(self, content: str) -> List[str]:
        """Extract LPH (Luraph Hex) strings"""
        patterns = [
            r'lPH_([A-Fa-f0-9]{8,})',  # Standard LPH
            r'LPH_([A-Fa-f0-9]{8,})',  # Uppercase variant
            r'_lph_([A-Fa-f0-9]{8,})',  # Underscore variant
        ]
        
        lph_strings = []
        for pattern in patterns:
            matches = re.findall(pattern, content)
            lph_strings.extend(matches)
        
        return list(set(lph_strings))
    
    def _analyze_characteristics(self, content: str, hex_strings: List[str], lph_strings: List[str]) -> Dict[str, Any]:
        """Analyze obfuscation characteristics"""
        characteristics = {
            'file_size': len(content),
            'entropy': calculate_entropy(content),
            'hex_string_count': len(hex_strings),
            'lph_string_count': len(lph_strings),
            'avg_hex_length': sum(len(s) for s in hex_strings) // len(hex_strings) if hex_strings else 0,
            'avg_lph_length': sum(len(s) for s in lph_strings) // len(lph_strings) if lph_strings else 0,
            'has_debug_protection': bool(re.search(r'debug\s*=\s*nil|debug\s*=\s*{', content)),
            'has_anti_tamper': bool(re.search(r'checksum|hash|verify', content, re.IGNORECASE)),
            'has_vm_detection': bool(re.search(r'getfenv|setfenv|rawget.*_ENV', content)),
            'obfuscation_density': self._calculate_obfuscation_density(content)
        }
        
        return characteristics
    
    def _calculate_obfuscation_density(self, content: str) -> float:
        """Calculate how heavily obfuscated the content is (0.0 to 1.0)"""
        indicators = [
            len(re.findall(r'[A-Fa-f0-9]{16,}', content)),  # Long hex strings
            len(re.findall(r'\\x[A-Fa-f0-9]{2}', content)),  # Escaped hex
            len(re.findall(r'string\.char\s*\(', content)),  # String.char usage
            len(re.findall(r'table\.unpack\s*\(', content)),  # Table.unpack usage
            len(re.findall(r'loadstring\s*\(', content)),  # Dynamic loading
            len(re.findall(r'getfenv\s*\(', content)),  # Environment manipulation
        ]
        
        total_indicators = sum(indicators)
        content_lines = len(content.split('\n'))
        
        if content_lines == 0:
            return 0.0
        
        density = min(total_indicators / content_lines, 1.0)
        return density