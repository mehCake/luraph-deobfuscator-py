# Manual Review Prompt Generator

This note explains how to craft precise follow-up questions for human reviewers when
ambiguities remain after running the automated Luraph analysis pipeline.  The goal is
to turn low-confidence opcode mappings or unclear handler behaviour into targeted
questions that a subject-matter expert can answer quickly without re-reading the
entire payload.

## When to Generate Questions

Use this checklist whenever one or more of the following artefacts highlights
uncertainty:

- `out/ambiguous.md` or the JSON emitted by `python -m src.tools.ambiguous_reporter`
  lists opcodes or IR nodes below the configured confidence thresholds.
- `out/opcode_proposals.json` contains multiple candidates with scores within 0.15
  of each other, or any entry marked as `resolvable: false`.
- Handler tests generated via `python -m src.tools.generate_handler_tests` produce
  incomplete traces or unexpected return values.
- Runtime traces gathered with `python -m src.tools.trace_recorder` show repeated
  patterns that the static lifter did not assign a mnemonic to.

For the current v14.4.2 `Obfuscated3.lua` workflow, focus on handlers that manipulate
PRGA state, VM register shuffles, or custom checksum routines—these tend to drive the
remaining manual work once the automated heuristics have run.

## Building Prompt Stubs

1. **Identify the artefact** where the ambiguity surfaced.  Record the source
   (e.g., pipeline candidate ID, handler function name, or CFG block label) so the
   reviewer can navigate directly to the relevant JSON or prettified Lua snippet.
2. **Summarise the observed behaviour** using neutral language drawn from the
   tooling output.  Quote register names, stack indices, or operands exactly as
   shown in the reports.
3. **Specify the unknown**: describe the semantic gap you need answered.  Examples:
   “Does handler `H_12` write back to register `R5` or only read it?” or “Is the
   checksum accumulator rotated before or after the XOR with `state[i]`?”
4. **Suggest a verification method** whenever possible—point to existing harnesses
   (handler tests, sandbox resolvers, or the trace recorder) and propose concrete
   inputs.  This keeps reviewers aligned with safe, key-less execution paths.
5. **Remind reviewers about key hygiene**: reiterate that any test should request the
   session key interactively and never persist it.  For v14.4.2, note that
   `TINY-<…>` keys apply solely to `Obfuscated3.lua` and must not be reused.

## Prompt Templates

Use or adapt the following templates when drafting questions.  Replace the bracketed
fields with real artefact identifiers.

### Opcode Behaviour

- "For opcode `0x[NN]` (candidate `[mnemonic]`, confidence `[score]`), the trace
  shows it touching registers `[R?]` and stack slots `[S?]`.  Can you confirm whether
  it **writes** to `[register/stack]` or only reads it?"
- "Opcode `0x[NN]` currently maps to `[mnemonic]` because it mirrors the `luac`
  pattern `[reference]`.  Could you compare the lifted IR in block `[block-id]` with
  known Lua VM handlers and state whether this is actually `[alt mnemonic]`?"

### Handler Side Effects

- "Handler function `[name]` (from `out/handler_suggestions.json`) calls helper
  `[helper name]` and manipulates table `[table id]`.  What side effects does it have
  on register `[R?]` or the VM call frame?"
- "During the handler test `[test-id]`, the stack depth changes by `[delta]`.
  Should we treat this as part of a CALL/RETURN pair or is it allocating a
  temporary closure?"

### Checksum / PRGA Questions (v14.4.2 focus)

- "Bootstrap chunk `[chunk-id]` applies rotate `[amount]` followed by XOR with
  `state[i]`.  Does the reviewer observe any additional masking before the rotate in
  the original Lua snippet?"
- "The inferred permutation table has size `[N]`, but the runtime trace suggests a
  second pass over `[subset]`.  Could you confirm whether this matches the known
  v14.4.2 double-permutation pattern?"

### Control-Flow Reconstruction

- "Structured block `[block-id]` contains a `while` loop with a TODO comment.  Based
  on the prettified output, is this actually an `if` guard around a VM dispatch?"
- "Block `[block-id]` jumps to `[target]` when register `[R?]` equals zero.  Should we
  treat this as the VM’s error trap or a legitimate branch?"

## Documenting Answers

- Capture reviewer responses in `out/final_report.md` under a dedicated
  "Manual Follow-up" subsection and link back to the original artefact (e.g., a line
  number in `out/deobfuscated_pretty.lua`).
- Update opcode maps or handler annotations using `python -m src.tools.interactive_map_editor`
  or `src.tools.ambiguous_reporter` notes after clarification.
- If new heuristics are warranted, log them in `src/tools/retrainable_heuristics.md`
  and add regression samples via the synthetic generator in `tests/samples/`.

Consistently applying these prompts keeps the manual review tight, auditable, and in
line with the repository’s key-handling and Luraph v14.4.x safety requirements.
