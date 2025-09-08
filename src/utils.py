import os
import logging
from pathlib import Path
from typing import Optional

def setup_logging(level: int = logging.INFO) -> None:
    """Setup logging configuration"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug("Logging setup complete.")

def validate_file(filepath: str) -> bool:
    """Validate that a file exists and is readable"""
    path = Path(filepath)
    try:
        result = path.exists() and path.is_file() and os.access(path, os.R_OK)
        logging.debug(f"Validating file '{filepath}': {result}")
        return result
    except Exception as e:
        logging.error(f"Error validating file '{filepath}': {e}")
        return False

def create_output_path(input_path: str, suffix: str = "_deobfuscated") -> str:
    """Create output path based on input path"""
    path = Path(input_path)
    parent = path.parent
    new_name = path.stem + suffix + path.suffix
    output_path = str(parent / new_name)
    logging.debug(f"Created output path '{output_path}' from input '{input_path}'")
    return output_path

def safe_write_file(filepath: str, content: str, encoding: str = 'utf-8') -> bool:
    """Safely write content to file with logging"""
    path = Path(filepath)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding=encoding) as f:
            f.write(content)
        logging.debug(f"Successfully wrote to file '{filepath}'")
        return True
    except Exception as e:
        logging.error(f"Failed to write file '{filepath}': {e}")
        return False

def safe_read_file(filepath: str, encoding: str = 'utf-8') -> Optional[str]:
    """Safely read content from file with logging"""
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        logging.warning(f"File does not exist or is not a file: '{filepath}'")
        return None
    try:
        with open(path, 'r', encoding=encoding, errors='ignore') as f:
            content = f.read()
        logging.debug(f"Successfully read file '{filepath}' ({len(content)} bytes)")
        return content
    except Exception as e:
        logging.error(f"Failed to read file '{filepath}': {e}")
        return None
