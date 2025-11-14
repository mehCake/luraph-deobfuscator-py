# Secure Session Key Entry Guidance

Maintaining session key confidentiality is critical when analysing Luraph-obfuscated payloads. This guide outlines safe, in-memory techniques for supplying the session key during tooling runs while avoiding any repository or filesystem persistence.

## Core Principles

- **Never write the session key to disk.** Avoid committing, logging, or saving the key to configuration files, environment snapshots, or transcripts.
- **Limit the key's lifetime in memory.** Use temporary buffers and explicitly overwrite them once the operation completes.
- **Scope keys to their intended target.** For Luraph v14.4.2 (e.g., `Obfuscated3.lua`), only apply the session key where explicitly required and do not reuse it for other payloads or bootstrap variants.

## Supplying Keys via Standard Input

Many CLI utilities in this repository accept a `--key` flag or read from standard input. Prefer piping the key from a prompt that does not echo input.

```bash
python -m src.tools.run_all_detection tests/samples/Obfuscated3.lua --use-key --debug <<'KEY'
TINY-XXXXXX
KEY
```

Alternatively, use Python's `getpass` module to request the key securely:

```python
import getpass

key = getpass.getpass("Session key for Obfuscated3.lua (v14.4.2): ")
try:
    run_pipeline(session_key=key)  # pass directly to tooling
finally:
    # Overwrite the key buffer to minimise residue in memory
    key_overwriter = "\0" * len(key)
    key = key_overwriter
```

The `finally` block ensures the original value is overwritten with null bytes before the variable goes out of scope.

## Temporary Memory Buffers

When lower-level APIs require `bytes`, convert the key immediately before use and zero the buffer afterwards:

```python
key_input = getpass.getpass("Key: ")
key_bytes = bytearray(key_input, "utf-8")
try:
    result = apply_prga(payload_bytes, key_bytes, params)
finally:
    # Zero memory in-place where possible
    for i in range(len(key_bytes)):
        key_bytes[i: i + 1] = b"\0"
```

If the buffer is immutable (e.g., Python `bytes`), wrap it in a `bytearray` to allow explicit zeroing.

## Secure Prompt Helpers

The repository's CLI tools that accept keys implement wiping helpers. When building new scripts, reuse `src.tools.ensure_no_keys` and the existing key-scrubbing utilities to validate outputs before writing them to disk.

## Logging and Diagnostic Output

- Disable verbose logging before providing keys.
- Inspect generated artefacts under `out/` using `python -m src.tools.ensure_no_keys out/` to confirm no key material is present.
- Rotate or delete terminal history if the key was entered interactively.

## Summary Checklist

1. Read the session key via secure prompt (stdin or `getpass`).
2. Pass the key directly to the required function or CLI flag.
3. Overwrite any buffer or variable holding the key immediately after use.
4. Run `src.tools.ensure_no_keys` on output directories.
5. Only apply the session key to `Obfuscated3.lua` (Luraph v14.4.2) as instructed.

Adhering to these practices keeps the session key confined to volatile memory during analysis and ensures repository artefacts remain free of sensitive material.
