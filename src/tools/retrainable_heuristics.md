# Retrainable Heuristics Guide

This document explains how the heuristic system in `src/tools/heuristics.py` is structured and how to extend it safely for new Luraph samples, with emphasis on the 14.4.2 family currently targeted by the pipeline.

## Architectural overview

* The module exposes lightweight data classes such as `HeuristicSignal`, `ChecksumResult`, and `VMStyleScore` that encapsulate detection results without tying callers to implementation details.
* Each public function is listed in `__all__`, making it easy to import selected helpers while keeping the module import side effects minimal.
* Helper utilities (`_normalise_operation`, `_operation_name`, `_operation_args`) translate heterogeneous inputs into canonical forms so new heuristics can share argument parsing logic.
* Confidence values are normalised to the range `[0.0, 1.0]`. The pipeline treats anything above `0.6` as a strong indicator and aggregates weaker signals using the hypothesis scoring helpers.

## Adding a new heuristic

1. **Identify reusable helpers** – scan the existing private helpers near the top of the module to avoid duplicating parsing or scoring code.
2. **Return `HeuristicSignal`** – structure your result with a short `name`, a numeric `confidence`, and bullet-point `reasons`. Include an optional `version_hint` such as `"v14.4.2"` when the signal is version-specific.
3. **Document behaviour** – add a docstring describing the heuristic, expected inputs, and corner cases. Mention any version assumptions directly in the docstring.
4. **Register exports** – append the new function name to the `__all__` list so downstream tooling can import it lazily through `src.tools`.
5. **Update tests** – add coverage under `tests/test_tools_heuristics.py` mirroring the structure of existing tests. Use synthetic payloads to avoid shipping sensitive data.

## Working with version-specific rules

For Luraph v14.4.2, several helpers already encode useful defaults:

* `likely_lph_variant` emphasises rotate amounts of 11/13 bits and permutation block sizes of 16 or 32 bytes observed in 14.4.2 loaders.
* `detect_vm_style` distinguishes register-heavy VMs (common in 14.4.2) from stack-based variants seen in older releases.
* `detect_checksums` recognises CRC32 and additive trailers frequently appended to 14.4.2 payloads, emitting a `ChecksumResult` with human-readable status hints.

When introducing new rules for other versions, keep 14.4.2 accuracy in mind by guarding version hints (e.g. `version_hint="v14.4.3?"`) and ensuring the rule degrades gracefully if earlier signals already reached high confidence.

## Example: scoring a new permutation detector

```python
from src.tools import heuristics

# Synthetic permutation table captured from the bootstrap collector.
perm_table = list(range(256))

signal = heuristics.score_permutation_sequence(perm_table)
if signal.confidence >= 0.7:
    print("Likely VM permutation", signal.reasons)
```

If you create a new helper such as `score_rotate_patterns`, mirror this style: accept plain Python containers, compute normalised confidence, and return a `HeuristicSignal` describing the rationale.

## Reviewing heuristic output

Use the following tooling to verify changes:

* `python -m src.tools.run_all_detection tests/samples/Obfuscated3.lua --debug` – end-to-end run that surfaces heuristic signals in the detection report and parity summary.
* `python -m src.tools.hypothesis_scoring --explain out/pipeline_candidates.json` – (if available) dumps the contribution of each heuristic to final confidence.

Ensure that any new heuristic:

* Emits deterministic results for the same input to keep pipelines reproducible.
* Avoids parsing or executing untrusted code directly; rely on pre-parsed manifests from the loader and collector stages.
* Does **not** require knowledge of session keys—the heuristics operate on public artefacts only.

By following these guidelines, you can safely retrain or augment detection logic while maintaining compatibility with existing v14.4.2-focused workflows.
