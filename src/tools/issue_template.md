# Pull Request Template for Decoder & Heuristic Contributions

This template helps contributors share the right context when improving the Luraph
analysis tooling (versions 14.4.1 – 14.4.3). Copy the headings below into your pull
request description and fill them out before requesting review.

## Summary
- _Briefly describe the new decoder, heuristic, or tooling change._
- _Explain how the change impacts support for the targeted Luraph version(s)._ 

## Testing
- _List the automated tests you added or updated._
- _Document any manual validation steps, including command invocations and sample
  payloads (synthetic payloads only)._ 

## Artefacts
- [ ] Added or updated synthetic samples in `tests/samples/` when behaviour
      depends on new payload shapes.
- [ ] Recorded relevant outputs in `out/` directories **without** committing
      session keys or sensitive data.
- [ ] Updated documentation (`docs/`, `docs/examples/`, or generated guides) when
      user-facing workflows change.

## Security & Key Handling Checklist (Luraph 14.4.x)
- [ ] Confirm no permanent keys, secrets, or tokens are stored in source files,
      test fixtures, or artefacts.
- [ ] Ensure any scripts that require a session key read it from CLI arguments or
      stdin and wipe in-memory buffers after use.
- [ ] Verify `src/tools/ensure_no_keys.py` passes locally before submission.

## Additional Notes
- _Share follow-up tasks or potential improvements for future contributors._
- _Mention any coordination required with opcode maps, VM lifter updates, or
  parity harness adjustments._

### Reviewer Tips
- _Highlight specific files or functions that deserve extra attention (e.g.,
  `src/decoders/lph_reverse.py`, `src/tools/heuristics.py`)._
- _Point to any new configuration knobs or CLI flags that need documentation or
  testing._

---
**Reminder:** Session keys are provided per task. Use them only in-memory for the
current run and never commit them to the repository or artefacts.
