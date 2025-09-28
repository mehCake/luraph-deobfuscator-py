# Lua chunk decoder environment

This directory contains a standalone Lua 5.4 script that mirrors the initv4
bootstrapper pipeline so payload chunks from `Obfuscated.json` can be decoded
without relying on Python helpers.

## Usage

```bash
lua lua_env/decode_chunk.lua Obfuscated.json 1 Deobfuscated_chunk1.lua \
    zkzhqwk4b58pjnudvikpf initv4.lua
```

The script performs the following steps:

1. Parses the JSON payload using a tiny pure-Lua JSON reader.
2. Skips the metadata bootstrap entry (if present) and selects the requested
   chunk index (1-based).
3. Attempts ascii85 decoding with an automatic Z85 fallback before trying the
   initv4 basE91 alphabet recovered from `initv4.lua`.
4. Reapplies the script-key XOR followed by the index XOR mixing from the
   bootstrapper.
5. Writes printable payloads directly; binary payloads are rendered as a
   formatted hex dump to keep the result readable.

All decode output is written to the path provided on the command line, allowing
chunk-by-chunk deobfuscation directly from Lua.
