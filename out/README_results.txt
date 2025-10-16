Luraph Deobfuscation Pipeline Outputs
=====================================

This directory contains the human-readable artefacts produced by
``python -m src.sandbox_runner``.  Each run captures the virtual machine payload,
analyses its instructions, and writes progressively richer summaries.

Key artefacts
-------------

* ``unpacked_dump.json`` / ``unpacked_dump.lua`` – raw ``unpackedData`` table
  emitted by the initv4 bootstrapper.
* ``lift_ir.json`` / ``lift_ir.lua`` – intermediate representation of each
  instruction with operand hints.
* ``opcode_candidates.json`` and ``opcode_map.v14_4_1.verified.json`` –
  heuristic opcode guesses and high-confidence validations.  Entries tagged as
  ``status": "unverified" still require manual analysis.
* ``deobfuscated.partNN.lua`` (and ``deobfuscated.full.lua`` when small) –
  readable scaffolds reconstructed from verified opcodes.
* ``summary.json`` – run metadata and counters; check the ``status`` field to
  confirm success.
* ``shim_usage.txt`` – names of shimmed globals that the bootstrap accessed
  while running under the LuaJIT wrapper.

Re-running the pipeline
-----------------------

To repeat the capture with a different key, run:

.. code-block:: console

   python -m src.sandbox_runner \
       --init initv4.lua \
       --json Obfuscated.json \
       --key <SCRIPT_KEY> \
       --out out \
       --run-lifter

When ``lupa`` or ``luajit`` are unavailable the runner aborts with a
``failure_report.txt`` explaining the missing dependency.  To fall back to an
existing dump explicitly, add ``--use-fixtures``.

