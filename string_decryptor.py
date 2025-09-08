import re
import base64

class StringDecryptor:
    def __init__(self):
        """
        Initialize String Decryptor
        """
        pass
    
    def decrypt(self, code: str) -> str:
        """
        Recursively decrypt strings in the provided code
        """
        previous_code = None
        current_code = code
        
        # Keep decrypting until no more changes
        while current_code != previous_code:
            previous_code = current_code
            current_code = self._decrypt_base64_strings(current_code)
            current_code = self._decrypt_xor_strings(current_code)
            current_code = self._decode_lua_hex_escapes(current_code)
            current_code = self._decode_lua_unicode_escapes(current_code)
            current_code = self._decrypt_loadstring(current_code)
        
        return current_code
    
    def _decrypt_base64_strings(self, code: str) -> str:
        base64_pattern = r'base64\.decode\([\'"]([^\'"]*)[\'"]\)'

        def replace_base64(match):
            try:
                decoded_bytes = base64.b64decode(match.group(1))
                decoded_text = decoded_bytes.decode('utf-8', errors='replace')
                return f"'{decoded_text}'"
            except Exception:
                return match.group(0)

        return re.sub(base64_pattern, replace_base64, code)
    
    def _decrypt_xor_strings(self, code: str) -> str:
        xor_pattern = r'xor_decrypt\([\'"]([^\'"]*)[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]\)'

        def replace_xor(match):
            encrypted_text = match.group(1)
            key = match.group(2)
            decrypted = self._xor_decrypt(encrypted_text, key)
            return f"'{decrypted}'"

        return re.sub(xor_pattern, replace_xor, code)
    
    def _xor_decrypt(self, text: str, key: str) -> str:
        try:
            return ''.join(
                chr(ord(c) ^ ord(key[i % len(key)]))
                for i, c in enumerate(text)
            )
        except Exception:
            return text
    
    def _decode_lua_hex_escapes(self, code: str) -> str:
        hex_pattern = r'\\x([0-9A-Fa-f]{2})'

        def replace_hex(match):
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        return re.sub(hex_pattern, replace_hex, code)
    
    def _decode_lua_unicode_escapes(self, code: str) -> str:
        unicode_pattern = r'\\u\{([0-9A-Fa-f]+)\}'

        def replace_unicode(match):
            try:
                return chr(int(match.group(1), 16))
            except Exception:
                return match.group(0)

        return re.sub(unicode_pattern, replace_unicode, code)
    
    def _decrypt_loadstring(self, code: str) -> str:
        """
        Detect and decode Lua loadstring/load calls
        """
        loadstring_pattern = r'(?:loadstring|load)\([\'"]([^\'"]*)[\'"]\)'

        def replace_loadstring(match):
            inner_code = match.group(1)
            # Recursively decrypt the inner code
            decrypted_inner = self.decrypt(inner_code)
            return f"'{decrypted_inner}'"

        return re.sub(loadstring_pattern, replace_loadstring, code)
