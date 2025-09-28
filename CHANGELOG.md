# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added
- Documented support for the Luraph v14.4.1 ``initv4`` bootstrap, including
  the requirement to pass ``--script-key`` when decoding scripts protected with
  user-specific keys.
- Added maintainer notes and inline documentation for the payload decoder and
  devirtualiser paths touched by the new version.
- Introduced a changelog so future updates can be tracked alongside version
  support.
- Expanded the CLI help with ``--allow-lua-run``, ``--alphabet`` and
  ``--opcode-map-json`` overrides to improve bootstrapper recovery workflows.
- Implemented Roblox oriented post-processing helpers that repair string
  fragments, provide ``classifyLoot`` heuristics, and expose configurable UI
  toggles for ESP/QoL features.
- Added a regression test (``tests/test_initv4.py``) that drives the CLI
  against the bundled initv4 sample using the scripted key.

### Changed
- The bootstrap decoder now performs basE91 decoding without third-party
  dependencies and validates both pre/post XOR transform orders before falling
  back to Lua emulation.
- Deobfuscation iterations honour ``--max-iterations`` and stop when nested
  payloads are exhausted, ensuring fixpoint decoding for JSON-wrapped blobs.
- Pruned the legacy ``luraph_deobfuscator.py`` entry point in favour of the
  modular ``src/`` architecture to avoid import ambiguity.

