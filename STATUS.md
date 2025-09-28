# Implementation Status: Luraph v14.4.1 Plan

The latest user request requires a full Luraph v14.4.1 virtual machine lifting
pipeline including:

* precise decoding of ``LPH_String`` payloads with repeater/index-mix
  semantics
* programmatic capture of ``unpackedData`` from the bootstrapper via Lua
  instrumentation
* automated opcode handler inference for the VM
* reconstruction of Lua 5.1 bytecode from the captured tables
* Roblox-specific post-processing of the lifted script

At present the repository does not ship the required Lua runtime hooks or VM
reconstruction components, and none of the sample fixtures expose verified
expected outputs. Implementing these features reliably would require a
significant design effort (Lua sandbox, opcode semantics database, bytecode
assembler, Roblox heuristics) that exceeds the current scope and available
turnaround time. Without those reference artefacts we cannot validate new
opcode-mapping automation or bytecode reconstruction logic.

Consequently this update documents the blockers instead of making partial,
unverifiable changes that would risk regressions. Once the project provides a
trusted fixture (decoded bytecode, opcode map, unpacked tables) we can iterate
on an implementation that matches the requested pipeline.
