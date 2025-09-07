import os
import logging
import re
from typing import List, Dict, Any

def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """
    Setup logging configuration
    
    :param log_level: Logging level
    :return: Configured logger
    """
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('luraph_deobfuscator.log')
        ]
    )
    return logging.getLogger('LuraphDeobfuscator')

def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes
    
    :param hex_str: Hex-encoded string
    :return: Decoded bytes
    """
    # Remove any non-hex characters
    hex_str = re.sub(r'[^0-9a-fA-F]', '', hex_str)
    return bytes.fromhex(hex_str)

def find_hex_patterns(text: str) -> List[str]:
    """
    Find potential hex-encoded patterns in text
    
    :param text: Input text to search
    :return: List of matched hex patterns
    """
    # Regex to match hex-like strings, including LPH patterns
    hex_pattern = r'(superflow_bytecode_ext\d+|[a-fA-F0-9]{16,})'
    return re.findall(hex_pattern, text)

def safe_exec(code: str, globals_dict: Dict[str, Any] = None) -> Any:
    """
    Safely execute a piece of code with optional global context
    
    :param code: Code to execute
    :param globals_dict: Optional global variables
    :return: Execution result
    """
    try:
        globals_dict = globals_dict or {}
        return eval(code, globals_dict)
    except Exception as e:
        logging.error(f"Safe execution failed: {e}")
        return None