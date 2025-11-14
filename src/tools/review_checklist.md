# Deobfuscation Run Review Checklist

This checklist helps human reviewers validate the outputs of the automated Luraph analysis pipeline before sharing artefacts externally. It focuses on session hygiene, suspicious constructs, and pipeline coverage for Luraph versions 14.4.1 through 14.4.3, with explicit attention to the current v14.4.2 workflow used for `Obfuscated3.lua`.

## 1. Session & Key Handling
- [ ] Confirm the session key was supplied only via CLI flag or secure stdin prompt and **never** stored in repository files, configs, or artefacts.
- [ ] Inspect `out/` JSON, Markdown, and manifest files (or run `python -m src.tools.ensure_no_keys`) to ensure no fields named `key`, `secret`, or `token` contain values.
- [ ] Verify the parity / detection commands scrubbed in-memory key buffers after use (see `docs/USAGE.md` and `src/tools/secure_key_entry.md`).
- [ ] For v14.4.2 reviews (`Obfuscated3.lua`), double-check that the key was scoped only to this payload and not reused for other artefacts.

## 2. Artefact Backups & Provenance
- [ ] Confirm `src/tools/backup_manager.py` captured a snapshot under `out/backups/` for the run and that backups omit sensitive material.
- [ ] Ensure the run manifest (`out/runs/*.manifest.json`) and provenance header in `out/deobfuscated_pretty.lua` reference the correct timestamp and pipeline steps.
- [ ] Review `out/metrics/`, `out/intermediate/`, and backup directories for unexpected extractions; remove stale data with `python -m src.tools.cleanup_temp` if necessary.

## 3. Pipeline Coverage & Confidence
- [ ] Open `out/detection_report.md` and `out/final_report.md` to confirm the reported pipeline matches expectations (PRGA → permute → VM unpack → lifter, etc.).
- [ ] Check `out/hypothesis_scores.json` or collector outputs for confidence metrics; flag low-confidence hypotheses for further investigation.
- [ ] For v14.4.2, ensure PRGA parameters (rotate amounts, block sizes) align with values documented in `docs/LURAPH_HINTS.md`.

## 4. Ambiguous Operations & Handlers
- [ ] Read `out/ambiguous.md` and confirm suggested dynamic tests (`src/tools/resolve_with_testcases.py`, handler harnesses) were executed or scheduled.
- [ ] Review handler suggestions (`out/handler_suggestions.json`) and opcode proposals (`out/opcode_proposals.json`) for unresolved or conflicting mnemonics.
- [ ] If ambiguity remains, document manual follow-up steps in `out/final_report.md` and notify the team.

## 5. Suspicious I/O & Security Checks
- [ ] Run `python -m src.tools.replace_insecure_patterns out/deobfuscated_pretty.lua` (or review `out/warnings.txt`) to ensure no lingering calls like `os.execute`, `io.open`, or network usage remain.
- [ ] Inspect inline comments from `src/pretty/comment_injector.py` for flagged offsets (e.g., `-- AMBIGUOUS_OPCODE`, `-- SUGGESTED_MNEMONIC`).
- [ ] Confirm snapshot artefacts (`out/snapshots/`) and traces (`out/traces/`) exclude key material and do not include file-system or network access attempts.

## 6. Reviewer Sign-off
- [ ] Ensure CI helpers (`ci/parity_check.sh`, `python -m src.tools.ci_runner`) pass without storing keys or secrets.
- [ ] Archive reviewer notes, parity reports, and prettified output using `python -m src.tools.export_for_reviewers` or `src/tools/export_results_zip.py` with dry-run to confirm included files.
- [ ] Record unresolved questions or manual investigations in `src/tools/review_checklist.md` (append below or link to issue tracker).

---
**Reviewer:** ____________________  
**Date:** ____________________
