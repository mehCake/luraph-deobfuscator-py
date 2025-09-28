# Luraph v14.4.1 Implementation Status

This repository snapshot still lacks the infrastructure required to implement the
full deobfuscation pipeline outlined in the latest request.

## Outstanding Gaps

- Verified unpackedData capture hooks that operate on the real initv4 bootstrap
  and payload without manual tweaking.
- A trustworthy opcode inference framework that can map VM handlers to the 38
  Lua 5.1 opcodes in an automated, regression-tested way.
- Reference fixtures that confirm bytecode reconstruction works across
  permutations of bootstrap metadata (opcode maps, alphabets, script key order
  variations).

## Recommended Next Steps

1. Finalise the Lua sandbox so it deterministically intercepts
   `LuraphInterpreter(unpackedData, env)` during bootstrap execution.
2. Extend the VM lifter to rebuild Lua 5.1 bytecode from `unpackedData[4]`
   using the official instruction layout (A/B/C/Bx/sBx fields).
3. Add regression fixtures (bootstrap, payload, expected Lua) so automated tests
   validate decoding, lifting, and post-processing end-to-end.

Until these prerequisites are met, implementing the requested plan would risk
regressions across existing versions and user workflows.
