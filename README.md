Advanced Lua Deobfuscator

A comprehensive Python-based tool for deobfuscating Lua code, with specialized support for various obfuscation methods including Luraph, string obfuscation, and generic pattern-based obfuscation.

Repository (reference): https://github.com/mehCake/luraph-deobfuscator-py

Note: If the repository link is not available or private, use the local project copy at C:\Users\mende\luraph-deobfuscator-py.

Features

Multi-Method Support: Supports Luraph, generic string obfuscation, and pattern-based deobfuscation.

Intelligent Analysis: Automatically detects obfuscation methods and complexity.

Comprehensive Transformations: Many deobfuscation techniques (string decoding, var renaming, control flow simplification, etc.).

Modular Architecture: Separate modules for detection, transformations, utilities and CLI.

Command-Line Interface: Easy-to-use CLI with options for analysis, method selection, verbosity, and output.

Interactive Mode: Terminal interactive UI for step-by-step usage.

Logging: Configurable logging to file and console.

Prerequisites

Python 3.6+ (3.7+ recommended).

No required third-party pip packages for basic use (the project uses only standard library modules by default).

Optional: pyinstaller to build a standalone executable.

If you plan to create a Windows .exe, install PyInstaller:

pip install pyinstaller

Project Layout
luraph-deobfuscator-py/                # project root (local copy path e.g. C:\Users\mende\luraph-deobfuscator-py)
├── main.py                           # Primary CLI + interactive entrypoint (root)
├── run.py                            # Alternative entrypoint (older name / alias)
├── README.md
├── requirements.txt                  # Optional (list only pip installs needed)
└── src/
    ├── deobfuscator.py               # Core deobfuscator class
    ├── patterns.py                   # Pattern detection & matcher
    ├── transformations.py            # Transformations and cleaners
    ├── utils.py                      # helpers: logging, file helpers
    ├── gui.py                        # Terminal interactive GUI handler
    ├── normalizer.py                 # Code normalization utilities
    └── ...                           # other modules (string extractor, vm simulator, etc.)


Note about two main.py files: Some branches or setups include both a main.py in the project root and another CLI/entrypoint inside src/. Use the root main.py for normal usage and interactive mode. The src entrypoint (if present) is typically for library/demo usage; README commands below assume root main.py is the intended entry.

Quickstart — Command-line usage

Open a terminal and cd to your project folder (e.g. C:\Users\mende\luraph-deobfuscator-py).

Basic deobfuscation:

python main.py path/to/obfuscated.lua


Specify an output file:

python main.py path/to/obfuscated.lua -o path/to/clean.lua


Choose deobfuscation method:

python main.py path/to/obfuscated.lua -m luraph
python main.py path/to/obfuscated.lua -m generic


Analyze only (no transformations):

python main.py path/to/obfuscated.lua --analyze


Verbose logging / debug mode:

python main.py path/to/obfuscated.lua -v


Options summary

input_file — Path to the obfuscated Lua file.

-o, --output — Output file path.

-m, --method — auto (default), luraph, generic.

-v, --verbose — Enable verbose logging.

-a, --analyze — Only analyze; don’t write deobfuscated output.

Interactive Mode (Terminal GUI)

If you run the CLI without a filename, an interactive terminal GUI is available:

python main.py
# or
python main.py --interactive


Interactive flow:

Welcome screen and main menu.

Select 1. Select Lua file to enter a path.

Configure options (deobfuscation and output settings).

Start deobfuscation and view statistics and generated output file.

Interactive UI features:

File selection (validates extension .lua, .luac, .txt).

Toggleable options:

Remove junk code

Decrypt strings

Resolve function calls

Simplify expressions

Beautify output

Rename variables

Indent size

Saves results to <input>_deobfuscated.lua by default, shows renaming report and stats.

Building a Standalone Windows Executable

Install PyInstaller:

pip install pyinstaller


From project root:

pyinstaller --onefile --name LuaDeobfuscator main.py


The built executable will be in dist\LuaDeobfuscator.exe.

If you have custom data files (like config.json) referenced at runtime, pass --add-data options to PyInstaller and ensure the executable can locate them (or embed defaults in code).

Logging & Output

Default log file: deobfuscator.log (configurable via src/utils.py).

Use -v/--verbose for console debug output and stack traces.

Output modes: JSON (machine-readable) or plain text (formatted report).

How the Tool Works (high-level)

Phase 1 — Analysis

Detect obfuscation type & variants (Luraph, IronBrew, generic).

Gather heuristics: hex strings, long encoded strings, VM signatures, control-flow obfuscation.

Phase 2 — Transformation

Decode strings (hex, escapes, base64).

Reconstruct constant pools (string.char tables, concatenations).

Replace and simplify obfuscated expressions.

Rename variables and functions heuristically.

Remove traps, junk code and dummy wrappers.

Attempt VM instruction decoding where possible.

Phase 3 — Optimization & Output

Beautify code (indentation, spacing).

Create backups and optional rollbacks.

Generate statistics & renaming reports.

Notes & Limitations

Heuristics: The tool uses pattern matching and heuristics. It does not run untrusted Lua code; VM simulation is static and conservative.

Not guaranteed: Complex, custom, or multi-stage obfuscations may not be fully recovered automatically.

Lua versions: Primary testing targets are Lua 5.1–5.4; some obfuscators use version-specific bytecode or features.

Safety: Do not use the tool to automatically run unknown code in your environment.

Examples

Analyze a file:

python main.py suspicious.lua --analyze


Deobfuscate and save output:

python main.py obfuscated.lua -o obfuscated_deobfuscated.lua -v


Interactive quick use:

python main.py
# Follow prompts: select file -> adjust settings -> start deobfuscation

Troubleshooting

File not found: Specify full path or cd into the directory containing the file.

Permission errors: Ensure you have read/write permissions for input and output directories.

Executable build fails: Install pyinstaller and re-run; ensure file paths and --add-data paths are correct.

Low confidence detection: Try using -m generic, increase --verbose, or analyze with --analyze to get a patterns report.

Contributing

To contribute:

Add new detection patterns to src/patterns.py.

Add transformation functions to src/transformations.py.

Update src/deobfuscator.py to call them in the pipeline.

Include unit tests in tests/ and update README.md where needed.

License & Usage

This tool is provided for educational and research purposes. Respect license obligations for third-party code. Use responsibly and ethically.

Contact / Repository

Reference repo: https://github.com/mehCake/luraph-deobfuscator-py
If the repo is unavailable, use your local copy at C:\Users\mende\luraph-deobfuscator-py.