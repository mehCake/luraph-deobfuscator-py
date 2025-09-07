import re
import base64
from typing import Optional

class StringDecryptor:
    def __init__(self):
        """
        Initialize String Decryptor
        """
        pass
    
    def decrypt(self, code: str) -> str:
        """
        Decrypt strings in the provided code
        
        :param code: Input code with potentially encrypted strings
        :return: Code with decrypted strings
        """
        # Detect and decrypt base64 encoded strings
        decrypted_code = self._decrypt_base64_strings(code)
        
        # Detect and decrypt XOR encoded strings
        decrypted_code = self._decrypt_xor_strings(decrypted_code)
        
        return decrypted_code
    
    def _decrypt_base64_strings(self, code: str) -> str:
        """
        Decrypt base64 encoded strings
        
        :param code: Input code
        :return: Code with base64 strings decoded
        """
        base64_pattern = r'base64\.decode\([\'"]([^\'"]*)[\'"]\)'
        
        def replace_base64(match):
            try:
                return f"'{base64.b64decode(match.group(1)).decode('utf-8')}'"
            except Exception:
                return match.group(0)
        
        return re.sub(base64_pattern, replace_base64, code)
    
    def _decrypt_xor_strings(self, code: str) -> str:
        """
        Decrypt XOR encoded strings
        
        :param code: Input code
        :return: Code with XOR strings decoded
        """
        xor_pattern = r'xor_decrypt\([\'"]([^\'"]*)[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\)'
        
        def replace_xor(match):
            encrypted_text = match.group(1)
            key = match.group(2)
            return f"'{self._xor_decrypt(encrypted_text, key)}'"
        
        return re.sub(xor_pattern, replace_xor, code)
    
    def _xor_decrypt(self, text: str, key: str) -> Optional[str]:
        """
        XOR decryption utility
        
        :param text: Encrypted text
        :param key: Decryption key
        :return: Decrypted text or None
        """
        try:
            decrypted = ''.join(
                chr(ord(c) ^ ord(key[i % len(key)])) 
                for i, c in enumerate(text)
            )
            return decrypted
        except Exception:
            return None