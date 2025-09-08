import re
import logging
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict, Counter

class PatternAnalyzer:
    """
    Advanced opcode pattern analyzer for detecting custom opcode sequences
    and inferring high-level operations in obfuscated Lua scripts.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.opcode_patterns = {}
        self.sequence_map = {}
        self.high_level_operations = {}
        
        # Initialize known patterns
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize known opcode patterns and their meanings."""
        
        # Common Lua opcodes and their variations
        self.standard_opcodes = {
            'MOVE', 'LOADK', 'LOADBOOL', 'LOADNIL', 'GETUPVAL', 'GETGLOBAL',
            'GETTABLE', 'SETGLOBAL', 'SETUPVAL', 'SETTABLE', 'NEWTABLE',
            'SELF', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW', 'UNM',
            'NOT', 'LEN', 'CONCAT', 'JMP', 'EQ', 'LT', 'LE', 'TEST',
            'TESTSET', 'CALL', 'TAILCALL', 'RETURN', 'FORLOOP', 'FORPREP',
            'TFORLOOP', 'SETLIST', 'CLOSE', 'CLOSURE', 'VARARG'
        }
        
        # Known high-level operation patterns
        self.known_patterns = {
            'function_call': [
                ['LOADK', 'CALL'],
                ['GETGLOBAL', 'LOADK', 'CALL'],
                ['GETTABLE', 'LOADK', 'CALL'],
                ['SELF', 'LOADK', 'CALL']
            ],
            'table_access': [
                ['GETTABLE', 'LOADK'],
                ['SETTABLE', 'LOADK'],
                ['NEWTABLE', 'SETTABLE']
            ],
            'string_concat': [
                ['LOADK', 'LOADK', 'CONCAT'],
                ['GETGLOBAL', 'LOADK', 'CONCAT']
            ],
            'arithmetic': [
                ['LOADK', 'LOADK', 'ADD'],
                ['LOADK', 'LOADK', 'SUB'],
                ['LOADK', 'LOADK', 'MUL'],
                ['LOADK', 'LOADK', 'DIV']
            ],
            'control_flow': [
                ['TEST', 'JMP'],
                ['TESTSET', 'JMP'],
                ['EQ', 'JMP'],
                ['LT', 'JMP'],
                ['LE', 'JMP']
            ]
        }
    
    def extract_opcodes(self, content: str) -> List[str]:
        """Extract potential opcodes from the content."""
        opcodes = []
        
        # Look for opcode-like patterns
        patterns = [
            r'\b[A-Z][A-Z_]{2,}\b',  # All caps words
            r'OP_[A-Z_]+',           # OP_ prefixed opcodes
            r'\b[A-Z]{3,}\d*\b',     # Caps with optional numbers
            r'vm_[a-z_]+',           # VM operations
            r'lua_[a-z_]+',          # Lua API calls
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            opcodes.extend(matches)
        
        return opcodes
    
    def detect_sequences(self, opcodes: List[str], min_length: int = 2, max_length: int = 6) -> Dict[str, List[Tuple]]:
        """Detect repeated opcode sequences."""
        sequences = defaultdict(list)
        
        for length in range(min_length, max_length + 1):
            for i in range(len(opcodes) - length + 1):
                sequence = tuple(opcodes[i:i + length])
                sequences[length].append(sequence)
        
        # Count occurrences and filter frequent sequences
        frequent_sequences = {}
        for length, seq_list in sequences.items():
            counter = Counter(seq_list)
            # Only keep sequences that appear at least twice
            frequent = {seq: count for seq, count in counter.items() if count >= 2}
            if frequent:
                frequent_sequences[length] = frequent
        
        return frequent_sequences
    
    def infer_operation_type(self, sequence: Tuple[str]) -> Optional[str]:
        """Infer the high-level operation type from an opcode sequence."""
        sequence_list = list(sequence)
        
        # Check against known patterns
        for operation, patterns in self.known_patterns.items():
            for pattern in patterns:
                if self._matches_pattern(sequence_list, pattern):
                    return operation
        
        # Heuristic inference
        if 'CALL' in sequence_list:
            return 'function_call'
        elif 'CONCAT' in sequence_list:
            return 'string_operation'
        elif any(op in sequence_list for op in ['ADD', 'SUB', 'MUL', 'DIV', 'MOD']):
            return 'arithmetic'
        elif any(op in sequence_list for op in ['JMP', 'TEST', 'EQ', 'LT', 'LE']):
            return 'control_flow'
        elif any(op in sequence_list for op in ['GETTABLE', 'SETTABLE', 'NEWTABLE']):
            return 'table_operation'
        elif 'LOADK' in sequence_list:
            return 'constant_loading'
        
        return 'unknown'
    
    def _matches_pattern(self, sequence: List[str], pattern: List[str]) -> bool:
        """Check if a sequence matches a pattern (allowing wildcards)."""
        if len(sequence) != len(pattern):
            return False
        
        for seq_op, pat_op in zip(sequence, pattern):
            if pat_op != '*' and seq_op != pat_op:
                return False
        
        return True
    
    def detect_custom_opcodes(self, opcodes: List[str]) -> Dict[str, int]:
        """Detect custom/non-standard opcodes."""
        custom_opcodes = {}
        
        for opcode in set(opcodes):
            if opcode not in self.standard_opcodes:
                # Check if it looks like a custom opcode
                if (len(opcode) >= 3 and 
                    opcode.isupper() and 
                    not opcode.startswith(('VM_', 'LUA_', 'DEBUG_'))):
                    custom_opcodes[opcode] = opcodes.count(opcode)
        
        return custom_opcodes
    
    def analyze_control_flow(self, content: str) -> Dict[str, Any]:
        """Analyze control flow patterns."""
        control_flow = {
            'jumps': [],
            'loops': [],
            'conditions': [],
            'function_calls': []
        }
        
        # Detect jump patterns
        jump_patterns = [
            r'JMP\s+(\d+)',
            r'goto\s+(\w+)',
            r'if.*?then.*?goto\s+(\w+)',
            r'while.*?do.*?goto\s+(\w+)'
        ]
        
        for pattern in jump_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                control_flow['jumps'].append({
                    'type': 'jump',
                    'target': match.group(1),
                    'position': match.start()
                })
        
        # Detect loop patterns
        loop_patterns = [
            r'for\s+.*?do',
            r'while\s+.*?do',
            r'repeat.*?until',
            r'FORLOOP\s+\d+',
            r'FORPREP\s+\d+'
        ]
        
        for pattern in loop_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                control_flow['loops'].append({
                    'type': 'loop',
                    'pattern': match.group(0),
                    'position': match.start()
                })
        
        return control_flow
    
    def build_opcode_map(self, sequences: Dict[str, Dict[Tuple, int]]) -> Dict[str, str]:
        """Build a map from opcode sequences to high-level operations."""
        opcode_map = {}
        
        for length, seq_dict in sequences.items():
            for sequence, count in seq_dict.items():
                operation = self.infer_operation_type(sequence)
                key = ' -> '.join(sequence)
                opcode_map[key] = {
                    'operation': operation,
                    'frequency': count,
                    'confidence': min(count / 10.0, 1.0)  # Normalize confidence
                }
        
        return opcode_map
    
    def detect_encryption_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Detect potential encryption/decryption patterns."""
        patterns = []
        
        # XOR patterns
        xor_patterns = [
            r'(\w+)\s*=\s*(\w+)\s*\^\s*(\w+)',
            r'bit\.bxor\(([^)]+)\)',
            r'bit32\.bxor\(([^)]+)\)'
        ]
        
        for pattern in xor_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                patterns.append({
                    'type': 'xor',
                    'pattern': match.group(0),
                    'position': match.start()
                })
        
        # String manipulation patterns
        str_patterns = [
            r'string\.char\(([^)]+)\)',
            r'string\.byte\(([^)]+)\)',
            r'table\.concat\(([^)]+)\)',
            r'string\.sub\(([^)]+)\)'
        ]
        
        for pattern in str_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                patterns.append({
                    'type': 'string_manipulation',
                    'pattern': match.group(0),
                    'position': match.start()
                })
        
        return patterns
    
    def analyze(self, content: str) -> Dict[str, Any]:
        """Perform comprehensive pattern analysis."""
        self.logger.info("Starting comprehensive pattern analysis...")
        
        # Extract opcodes
        opcodes = self.extract_opcodes(content)
        self.logger.info(f"Extracted {len(opcodes)} potential opcodes")
        
        # Detect sequences
        sequences = self.detect_sequences(opcodes)
        total_sequences = sum(len(seq_dict) for seq_dict in sequences.values())
        self.logger.info(f"Detected {total_sequences} frequent sequences")
        
        # Build opcode map
        opcode_map = self.build_opcode_map(sequences)
        
        # Detect custom opcodes
        custom_opcodes = self.detect_custom_opcodes(opcodes)
        self.logger.info(f"Found {len(custom_opcodes)} custom opcodes")
        
        # Analyze control flow
        control_flow = self.analyze_control_flow(content)
        
        # Detect encryption patterns
        encryption_patterns = self.detect_encryption_patterns(content)
        self.logger.info(f"Found {len(encryption_patterns)} encryption patterns")
        
        return {
            'opcodes': list(set(opcodes)),
            'sequences': sequences,
            'opcode_map': opcode_map,
            'custom_opcodes': custom_opcodes,
            'control_flow': control_flow,
            'encryption_patterns': encryption_patterns,
            'analysis_summary': {
                'total_opcodes': len(opcodes),
                'unique_opcodes': len(set(opcodes)),
                'frequent_sequences': total_sequences,
                'custom_opcodes': len(custom_opcodes),
                'control_structures': sum(len(v) for v in control_flow.values()),
                'encryption_patterns': len(encryption_patterns)
            }
        }