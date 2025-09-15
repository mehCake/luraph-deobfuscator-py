"""
Pattern Recognition Module
Handles detection and analysis of various obfuscation patterns
"""

import re
from typing import Dict, List, Any
from dataclasses import dataclass
from .utils import safe_read_file

@dataclass
class PatternMatch:
    """Represents a pattern match with metadata"""
    pattern_name: str
    category: str
    match_text: str
    start_pos: int
    end_pos: int
    confidence: float
    context: str

class PatternAnalyzer:
    """Advanced pattern analyzer for obfuscated Lua code"""

    def __init__(self):
        self.patterns = self._load_comprehensive_patterns()
        self.vm_signatures = self._load_vm_signatures()

    def _load_comprehensive_patterns(self) -> Dict[str, List[Dict]]:
        """Load comprehensive obfuscation patterns"""
        return {
            'luraph_v12': [
                {
                    'name': 'vm_call_v12',
                    'pattern': r'Luraph_\w+\[(\d+)\]\(([^)]*)\)',
                    'description': 'Luraph v12+ VM calls',
                    'confidence': 0.9
                },
                {
                    'name': 'constant_pool_v12',
                    'pattern': r'local\s+\w+\s*=\s*\{[^}]*"[A-Za-z0-9+/=]+"\s*,?[^}]*\}',
                    'description': 'Luraph v12 constant pool',
                    'confidence': 0.85
                },
                {
                    'name': 'instruction_decode_v12',
                    'pattern': r'local\s+\w+\s*=\s*string\.char\((\d+(?:\s*,\s*\d+)*)\)',
                    'description': 'Luraph v12 instruction decoding',
                    'confidence': 0.8
                }
            ],
            'luraph_legacy': [
                {
                    'name': 'vm_call_legacy',
                    'pattern': r'VM\[(\d+)\]\(([^)]*)\)',
                    'description': 'Legacy Luraph VM calls',
                    'confidence': 0.85
                },
                {
                    'name': 'decrypt_legacy',
                    'pattern': r'Decrypt\("([A-Za-z0-9+/=]+)"\)',
                    'description': 'Legacy Luraph string decryption',
                    'confidence': 0.8
                }
            ],
            'fps_unlocker': [
                {
                    'name': 'setfpscap_call',
                    'pattern': r'setfpscap\s*\(\s*(\d+)\s*\)',
                    'description': 'FPS cap modification',
                    'confidence': 0.95
                },
                {
                    'name': 'remote_execution',
                    'pattern': r'loadstring\s*\(\s*game:HttpGet\s*\(\s*["\']([^"\']+)["\']\s*\)\s*\)\s*\(\s*\)',
                    'description': 'Remote script execution',
                    'confidence': 0.9
                },
                {
                    'name': 'rendering_modification',
                    'pattern': r'game\.RunService\.RenderStepped:Connect\([^)]+\)',
                    'description': 'Rendering loop modification',
                    'confidence': 0.7
                }
            ],
            'generic_obfuscation': [
                {
                    'name': 'string_obfuscation',
                    'pattern': r'string\.char\s*\(\s*(\d+(?:\s*,\s*\d+)*)\s*\)',
                    'description': 'Character-based string obfuscation',
                    'confidence': 0.6
                },
                {
                    'name': 'base64_encoding',
                    'pattern': r'["\']([A-Za-z0-9+/]{4,}={0,2})["\']',
                    'description': 'Base64 encoded content',
                    'confidence': 0.4
                },
                {
                    'name': 'variable_name_obfuscation',
                    'pattern': r'local\s+([a-zA-Z_]\w{15,}|[a-zA-Z_]{1,2})\s*=',
                    'description': 'Obfuscated variable names',
                    'confidence': 0.3
                },
                {
                    'name': 'control_flow_obfuscation',
                    'pattern': r'if\s+[a-zA-Z_]\w*\s+then\s+return\s+[a-zA-Z_]\w*\s+else\s+return\s+[a-zA-Z_]\w*\s+end',
                    'description': 'Control flow obfuscation',
                    'confidence': 0.5
                }
            ],
            'ironbrew': [
                {
                    'name': 'ironbrew_signature',
                    'pattern': r'local\s+\w+\s*=\s*loadstring\s*\(\s*game:HttpGet\s*\([^)]+\)\s*\)\s*\(\s*\)',
                    'description': 'IronBrew obfuscation signature',
                    'confidence': 0.8
                },
                {
                    'name': 'ironbrew_vm',
                    'pattern': r'local\s+\w+\s*=\s*\{\s*\[0\]\s*=\s*function\([^)]*\)',
                    'description': 'IronBrew VM structure',
                    'confidence': 0.75
                }
            ]
        }

    def _load_vm_signatures(self) -> Dict[str, Dict]:
        """Load virtual machine signatures for different obfuscators"""
        return {
            'luraph': {
                'instructions': ['MOVE', 'LOADK', 'LOADBOOL', 'LOADNIL', 'GETUPVAL', 'GETGLOBAL'],
                'vm_pattern': r'local\s+\w+\s*=\s*\{(?:[^{}]*\{[^{}]*\}[^{}]*)*\}',
                'confidence': 0.8
            },
            'ironbrew': {
                'instructions': ['Inst', 'Stk', 'Env', 'Upv'],
                'vm_pattern': r'local\s+\w+,\s*\w+,\s*\w+,\s*\w+\s*=',
                'confidence': 0.7
            },
            'prometheus': {
                'instructions': ['Proto', 'Const', 'Inst'],
                'vm_pattern': r'local\s+\w+\s*=\s*{Const\s*=\s*{',
                'confidence': 0.75
            }
        }

    def analyze_content(self, content: str) -> Dict[str, Any]:
        """Comprehensive content analysis"""
        matches = []
        categories_found = set()

        for category, patterns in self.patterns.items():
            for pattern_info in patterns:
                pattern_matches = self._find_pattern_matches(content, pattern_info, category)
                matches.extend(pattern_matches)
                if pattern_matches:
                    categories_found.add(category)

        category_scores = self._calculate_category_scores(matches)
        primary_type = self._determine_primary_type(category_scores)

        analysis = {
            'primary_type': primary_type,
            'categories_detected': list(categories_found),
            'total_matches': len(matches),
            'confidence_scores': category_scores,
            'matches': [self._match_to_dict(m) for m in matches],
            'complexity_score': self._calculate_complexity(matches),
            'deobfuscation_difficulty': self._assess_difficulty(matches),
            'recommendations': self._generate_recommendations(category_scores)
        }

        return analysis

    def _find_pattern_matches(self, content: str, pattern_info: Dict, category: str) -> List[PatternMatch]:
        matches = []
        pattern = pattern_info['pattern']

        for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
            context_start = max(0, match.start() - 50)
            context_end = min(len(content), match.end() + 50)
            context = content[context_start:context_end]

            pattern_match = PatternMatch(
                pattern_name=pattern_info['name'],
                category=category,
                match_text=match.group(0),
                start_pos=match.start(),
                end_pos=match.end(),
                confidence=pattern_info.get('confidence', 0.5),
                context=context
            )
            matches.append(pattern_match)

        return matches

    def _calculate_category_scores(self, matches: List[PatternMatch]) -> Dict[str, float]:
        category_scores = {}

        for match in matches:
            category = match.category
            category_scores.setdefault(category, 0.0)
            category_scores[category] += match.confidence

        for category in category_scores:
            category_matches = [m for m in matches if m.category == category]
            if category_matches:
                category_scores[category] = min(1.0, category_scores[category] / len(category_matches))

        return category_scores

    def _determine_primary_type(self, category_scores: Dict[str, float]) -> str:
        if not category_scores:
            return 'unknown'
        primary_category = max(category_scores, key=category_scores.get)
        return primary_category if category_scores[primary_category] >= 0.3 else 'unknown'

    def _calculate_complexity(self, matches: List[PatternMatch]) -> float:
        if not matches:
            return 0.0
        unique_patterns = len(set(m.pattern_name for m in matches))
        avg_confidence = sum(m.confidence for m in matches) / len(matches)
        match_density = min(1.0, len(matches) / 10.0)
        complexity = (unique_patterns / 10.0) * 0.4 + avg_confidence * 0.3 + match_density * 0.3
        return min(1.0, complexity)

    def _assess_difficulty(self, matches: List[PatternMatch]) -> str:
        complexity = self._calculate_complexity(matches)
        if complexity < 0.3:
            return 'easy'
        elif complexity < 0.6:
            return 'medium'
        elif complexity < 0.8:
            return 'hard'
        else:
            return 'very_hard'

    def _generate_recommendations(self, category_scores: Dict[str, float]) -> List[str]:
        recommendations = []
        sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
        if not sorted_categories:
            return ["No specific obfuscation patterns detected. Try generic deobfuscation methods."]

        primary_category, confidence = sorted_categories[0]

        if primary_category.startswith('luraph'):
            recommendations.extend([
                "Detected Luraph obfuscation. Use Luraph-specific deobfuscation methods.",
                "Focus on VM instruction decoding and constant pool extraction.",
                "Consider using updated Luraph deobfuscation tools."
            ])
        elif primary_category == 'fps_unlocker':
            recommendations.extend([
                "Detected FPS unlocker patterns. Clean up game service modifications.",
                "Remove or comment out FPS cap modifications for analysis.",
                "Be cautious of remote script execution."
            ])
        elif primary_category == 'ironbrew':
            recommendations.extend([
                "Detected IronBrew obfuscation. Use IronBrew-specific tools.",
                "Focus on VM structure reconstruction."
            ])
        else:
            recommendations.append(f"Detected {primary_category} patterns. Use appropriate deobfuscation methods.")

        if confidence < 0.5:
            recommendations.append("Low confidence detection. Consider manual analysis.")

        return recommendations

    def _match_to_dict(self, match: PatternMatch) -> Dict[str, Any]:
        return {
            'pattern_name': match.pattern_name,
            'category': match.category,
            'match_text': match.match_text[:100] + '...' if len(match.match_text) > 100 else match.match_text,
            'position': f"{match.start_pos}-{match.end_pos}",
            'confidence': match.confidence
        }

    def get_pattern_statistics(self, content: str) -> Dict[str, Any]:
        analysis = self.analyze_content(content)
        return {
            'total_patterns_searched': sum(len(patterns) for patterns in self.patterns.values()),
            'patterns_found': analysis['total_matches'],
            'categories_detected': len(analysis['categories_detected']),
            'primary_obfuscation_type': analysis['primary_type'],
            'complexity_assessment': analysis['deobfuscation_difficulty'],
            'detection_confidence': max(analysis['confidence_scores'].values()) if analysis['confidence_scores'] else 0.0
        }


def analyze_file(path: str) -> Dict[str, Any]:
    """Analyze the file at ``path`` for known obfuscation patterns."""
    content = safe_read_file(path)
    if content is None:
        return {}
    analyzer = PatternAnalyzer()
    return analyzer.analyze_content(content)
