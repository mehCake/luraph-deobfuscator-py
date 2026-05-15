# Lua Deobfuscator (Active development is still ongoing join the discord server for updates
# Dev #ishowgoat on discord
# For questions and answers go to my discord server: discord.gg/ScqDg85hsP


Utilities for decoding Lua scripts obfuscated with Luraph/Luarmor styles.  The
project ships a small command line interface together with a handful of helper
modules located under `src/`.  A tiny stack based virtual machine is included
for experimenting with devirtualisation of custom bytecode formats.  The VM is
implemented in a modular fashion under `src/vm/` with separate files for state
management, opcode handlers and the emulator itself.  It is not a full
re‑implementation of Luraph's VM but provides a foundation for further work.
Building on top of the VM, the `src/passes/devirtualizer.py` module illustrates
how control‑flow graphs, taint tracking and symbolic execution can be combined
to reconstruct readable Lua from simple bytecode traces.

# NOT WORKING, CURRENTLY BEING WORKED ON, SEE MORE AT MY DISCORD SERVER IN THE TOP
