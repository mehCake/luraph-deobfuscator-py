import re
import logging
import base64
import zlib

# Logger setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LuaDeobfuscator:
    def __init__(self):
        # Patterns for string decoding
        self.string_patterns = {
            'hex': r'\\x[0-9a-fA-F]{2}',
            'decimal': r'\\(\d{1,3})',
            'unicode': r'\\u[0-9a-fA-F]{4}',
        }

        # Patterns for detecting obfuscation
        self.patterns = {
            'luraph': [r'pcall\(function\)', r'local function \w+\(\)'],
            'ironbrew': [r'local \w+=\{.+\}', r'setfenv'],
            'generic': [r'loadstring', r'function\(.+\).*end']
        }

        # Statistics
        self.stats = {
            'strings_decrypted': 0,
            'variables_renamed': 0,
            'patterns_detected': 0,
            'constants_reconstructed': 0
        }

    # =========================
    # Main deobfuscation methods
    # =========================
    def decode_string(self, s):
        try:
            # Hex decoding
            s = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)
            # Decimal escapes
            s = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))), s)
            # Unicode
            s = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
            self.stats['strings_decrypted'] += 1
            return s
        except Exception as e:
            logger.warning(f"String decoding failed: {e}")
            return s

    def deobfuscate_loadstring(self, code):
        try:
            # Replace loadstring calls containing string literals
            def repl(match):
                content = match.group(1)
                return content
            code = re.sub(r'loadstring\s*\(\s*"([^"]+)"\s*\)\s*\(\s*\)', repl, code)
            return code
        except Exception as e:
            logger.warning(f"Loadstring deobfuscation failed: {e}")
            return code

    def rename_variables(self, code):
        # Placeholder: implement smart variable renaming if needed
        return code

    # =========================
    # Analysis and detection
    # =========================
    def analyze_code(self, code):
        logger.info("Analyzing patterns...")
        results = {}
        for method, patterns in self.patterns.items():
            detected = 0
            for pattern in patterns:
                if re.search(pattern, code):
                    detected += 1
            results[method] = detected
            if detected > 0:
                self.stats['patterns_detected'] += detected
        logger.info(f"Analysis complete: {results}")
        return results

    # =========================
    # Main driver
    # =========================
    def deobfuscate(self, code):
        logger.info("Starting deobfuscation steps...")
        # Step 1: Analyze
        self.analyze_code(code)

        # Step 2: Decode strings
        code = self.decode_string(code)

        # Step 3: Deobfuscate loadstring
        code = self.deobfuscate_loadstring(code)

        # Step 4: Rename variables
        code = self.rename_variables(code)

        logger.info(f"Deobfuscation complete. Stats: {self.stats}")
        return code

# =========================
# Command-line interface
# =========================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Lua Deobfuscator - Luraph/Generic")
    parser.add_argument("--file", "-f", required=True, help="Input Lua file to deobfuscate")
    parser.add_argument("--output", "-o", default=None, help="Output file path")
    parser.add_argument("--method", choices=["auto", "luraph", "fps"], default="auto", help="Deobfuscation method")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--analyze", action="store_true", help="Run analysis only, no deobfuscation")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    input_path = args.file
    output_path = args.output or input_path.replace(".lua", "_deobfuscated.lua")

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception as e:
        logger.error(f"Failed to read input file: {e}")
        exit(1)

    deob = LuaDeobfuscator()

    if args.analyze:
        deob.analyze_code(code)
    else:
        result = deob.deobfuscate(code)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result)
            logger.info(f"Deobfuscated file saved to: {output_path}")
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")
