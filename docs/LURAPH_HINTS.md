# Luraph 14.4.x Transform Hints

This reference summarises the transform pipeline patterns we have observed
across Luraph releases 14.4.1, 14.4.2, and 14.4.3. It is intended as a quick
lookup when triaging a new payload: each section lists the transforms typically
seen, the files in this repository that implement reversible helpers, and quick
heuristics you can use to confirm what variant you are dealing with.

The snippets below are safe, deterministic examples that rely solely on the
static tooling shipped in this repository—no untrusted Lua code is executed.

## Common Transform Families

| Transform | Reversible Helper | Notes |
|-----------|-------------------|-------|
| Loader normalisation | `src/io/loader.py` | Emits `out/raw_manifest.json` with escaped strings, numeric tables, and chunk offsets. |
| LPH byte mask / permutation | `src/decoders/lph_reverse.py` | Handles mask removal, block rotation, block permutations, and XOR remixing. |
| initv4 PRGA parity | `src/decoders/initv4_prga.py` (parity only) | Python implementation guarded to parity-test the initv4 bootstrap chain. |
| Bootstrap analysis | `src/bootstrap/extract_bootstrap.py` | Uses manifest-driven heuristics to locate `load`, `loadstring`, and `string.char` payloads. |
| Pipeline inference | `src/tools/collector.py` | Consolidates loader + extractor metadata into pipeline candidate traces. |
| Opcode recovery | `src/vm/opcode_map.py`, `src/vm/opcode_proposer.py` | Proposes mnemonic maps from handler signatures and disassembly usage. |

### Example: Reversing an LPH block

```python
from pathlib import Path
from src.decoders.lph_reverse import reverse_lph, COMMON_PARAMETER_PRESETS

encoded = Path("out/bytes/bootstrap_main.bin").read_bytes()
params = COMMON_PARAMETER_PRESETS["v14.4.2-default"]
decoded = reverse_lph(encoded, params)
Path("out/intermediate/lph_decoded.bin").write_bytes(decoded)
```

### Example: Running the initv4 PRGA parity harness

```bash
python -m src.tools.parity_test tests/parity/sample_lph.bin \
    --compare-first 64 --report out/parity_report.md
```

## Version Profiles

### Luraph 14.4.1

* **Typical pipeline**: escaped string literal → LPH mask/permutation → initv4
  PRGA (default variant) → VM unpack.
* **LPH traits**: 32-byte blocks with a single right rotation and XOR mask.
* **Detection cues**:
  * `collector` confidence spikes when `looks_like_perm_table` finds ascending
    tables of length 256.
  * `hypothesis_scoring` English-likeliness scores hover around 0.55 once the
    PRGA parameters are correct.
* **Notes**: opcode maps often keep Lua 5.1 ordering—`MOVE` handlers reference
  two registers followed by an inline constant compare.

### Luraph 14.4.2 (Obfuscated3.lua)

* **Typical pipeline**: manifest string.char payload → LPH block rotation →
  XOR remix → PRGA (default or `alt` variant) → VM unpack/dispatcher.
* **Common rotate amounts**: `rotate_right(5)` on block indices, followed by a
  per-byte `rotate_left(3)` before XOR.
* **Permutation sizes**: 64- or 128-byte chunks, frequently split into
  sub-permutations of 16 bytes that repeat every other block.
* **Detection cues**:
  * `looks_like_prga` confidence ≥ 0.7 when the candidate rotation is 3 or 5.
  * `likely_lph_variant` prefers `v14.4.2-alt` when `collector` observes
    alternating block XOR masks.
  * `parser_tracer` identifies dispatcher handlers of the form
    `if opcode == 0x1B then handler_jump()`—feed these into
    `src/vm/opcode_proposer.py` for mnemonic guesses.
* **Reverse/Parity snippet**:
  ```python
  from src.decoders.lph_reverse import try_parameter_presets
  from src.decoders.initv4_prga import apply_prga

  payload = Path("out/bytes/bootstrap_main.bin").read_bytes()
  best = max(try_parameter_presets(payload), key=lambda c: c.score)
  decoded = reverse_lph(payload, best.params)
  prga = apply_prga(decoded, key=b"\x00\x01demo-key", params={"variant": "alt"})
  ```
* **Permutation inspection**: run `python -m src.vm.disassembler --profile
  v14_4_2 out/vm_stream.bin` to emit operand stats before lifting.

### Luraph 14.4.3

* **Typical pipeline**: chained LPH stages → double PRGA mix → opcode handlers
  with merged arithmetic and comparison flows.
* **New heuristics**:
  * `looks_like_vm_dispatch` highlights two-level dispatchers; expect handlers
    to inline trap blocks that need manual annotation.
  * `likely_lph_variant` surfaces the `v14.4.3` preset when rotations cycle
    through `[1, 5, 7]` and permutation block size exceeds 128 bytes.
* **Recommended workflow**:
  1. Use `src/tools/fuzzy_param_search.py` to brute-force the second PRGA
     rotation window (`--max-tries 500 --timeout 30`).
  2. Lift with `src/vm/lifter.py` and immediately run
     `src/pretty/reflow_controlflow.py` to split merged handlers.
  3. Feed the result into `src/pretty/comment_injector.py` to highlight opaque
     predicates before manual review.

## Detecting Transforms Quickly

1. **Run the loader**: `python -m src.io.loader Obfuscated3.lua --out-dir out`.
   Review `out/raw_manifest.json`—large string literals (`type == "escaped-string"`)
   and numeric arrays indicate candidates for LPH reversal.
2. **Execute the detection pipeline**: `python -m src.tools.run_all_detection \
   Obfuscated3.lua --use-key --debug`. This orchestrates the extractor, collector,
   mapping detectors, snapshotter, and produces `out/detection_report.md`.
3. **Inspect heuristic hints**: `out/pipeline_candidates.json` lists the inferred
   transform sequence and heuristic scores (`hypothesis_score`). Confidence > 0.65
   usually means the candidate is ready for parity verification.
4. **Verify parity**: use the parity harness and `src/tools/sanity_checks.py`
   to ensure reversing and reapplying transforms yields the original payload.

## Safety Reminders

* **Key handling**: always provide the session key via CLI flags or stdin when
  using parity or PRGA parity helpers, and never commit the key. Modules such as
  `transform_profile` and `backup_manager` will refuse to persist fields named
  `key`.
* **Snapshots & reports**: artefacts saved under `out/` (snapshots, manifests,
  recommendations, reports) are safe to archive with `src/tools/export_results_zip.py`
  because they scrub key material automatically.
* **Manual tooling**: the interactive map editor and visual inspector provide
  undo and export confirmations—use them to refine opcode maps without risking
  accidental changes to source payloads.

Keep this sheet up to date as new heuristics or transform variants are added.
