import logging
import re
from typing import List, Dict

class OpcodeLifter:
    def __init__(self):
        """
        Initialize Opcode Lifter with logging and preprocessing.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if not self.logger.hasHandlers():
            logging.basicConfig(level=logging.INFO)
        self.logger.info("OpcodeLifter initialized")

        # Patterns for common obfuscation
        self.obfuscation_patterns = {
            'temp_var': re.compile(r'^local temp\d+'),
            'const_table': re.compile(r'^local const_table'),
            'hex_string': re.compile(r'0x[0-9a-fA-F]+'),
            'goto_label': re.compile(r'^::label\d+::'),
            'goto_instr': re.compile(r'^goto label\d+'),
            'encoded_string': re.compile(r'\[==?\[.*?\]==?\]'),  # multiline brackets
        }

    def lift(self, instructions: List[str]) -> str:
        """
        Lift and reconstruct control flow from instructions.

        :param instructions: List of low-level instructions
        :return: Reconstructed Lua code
        """
        reconstructed_code = []

        # Preprocess instructions
        instructions = self._preprocess_obfuscation(instructions)

        # Build label mapping
        label_map = self._map_labels(instructions)

        index = 0
        while index < len(instructions):
            instr = instructions[index]

            # Handle goto jumps
            goto_match = self.obfuscation_patterns['goto_instr'].match(instr)
            if goto_match:
                label = instr.split()[1]
                if label in label_map:
                    self.logger.debug(f"Jumping to {label} at index {label_map[label]}")
                    index = label_map[label]
                    continue

            lifted_instruction = self._lift_instruction(instr)
            if lifted_instruction:
                reconstructed_code.append(lifted_instruction)

            index += 1

        self.logger.info(f"Lifted {len(reconstructed_code)} instructions")
        return '\n'.join(reconstructed_code)

    def _preprocess_obfuscation(self, instructions: List[str]) -> List[str]:
        """
        Detect and normalize common obfuscation patterns.

        :param instructions: List of low-level instructions
        :return: Preprocessed instructions
        """
        preprocessed = []
        for instr in instructions:
            original = instr

            # Normalize temp variables
            if self.obfuscation_patterns['temp_var'].match(instr):
                instr = re.sub(r'temp\d+', 'temp', instr)
                self.logger.debug(f"Normalized temp variable: '{original}' -> '{instr}'")

            # Normalize constant tables
            if self.obfuscation_patterns['const_table'].match(instr):
                instr = 'local const_table = {...} -- normalized'
                self.logger.debug(f"Normalized const table: '{original}' -> '{instr}'")

            # Convert hex strings to decimal if possible
            hex_match = self.obfuscation_patterns['hex_string'].search(instr)
            if hex_match:
                hex_value = hex_match.group(0)
                try:
                    decimal_value = str(int(hex_value, 16))
                    instr = instr.replace(hex_value, decimal_value)
                    self.logger.debug(f"Converted hex '{hex_value}' -> '{decimal_value}'")
                except ValueError:
                    pass  # leave as is if invalid

            preprocessed.append(instr)
        return preprocessed

    def _map_labels(self, instructions: List[str]) -> Dict[str, int]:
        """
        Map label names to instruction indices for goto reconstruction.

        :param instructions: List of instructions
        :return: Dictionary of label -> index
        """
        label_map = {}
        for i, instr in enumerate(instructions):
            label_match = self.obfuscation_patterns['goto_label'].match(instr)
            if label_match:
                label_name = instr.strip(':')
                label_map[label_name] = i
                self.logger.debug(f"Found label '{label_name}' at index {i}")
        return label_map

    def _lift_instruction(self, instruction: str) -> str:
        """
        Lift a single instruction to a more readable form.

        :param instruction: Low-level instruction
        :return: Lifted instruction
        """
        if instruction.startswith('local temp'):
            return f"-- Temporary variable assignment: {instruction}"

        if instruction.startswith('local const'):
            return f"-- Constant load: {instruction}"

        if instruction.startswith('local result'):
            return f"-- Computation result: {instruction}"

        if instruction.startswith('local const_table'):
            return f"-- Constant table: {instruction}"

        if self.obfuscation_patterns['goto_label'].match(instruction):
            return f"-- Label: {instruction}"

        if self.obfuscation_patterns['goto_instr'].match(instruction):
            return f"-- Goto jump: {instruction}"

        # Catch-all for unknown instructions
        self.logger.debug(f"Unrecognized instruction: {instruction}")
        return f"-- [UNKNOWN] {instruction}"
