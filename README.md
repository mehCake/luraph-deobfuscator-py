Advanced Lua Deobfuscator

A comprehensive Python-based tool for deobfuscating Lua code, with specialized support for various obfuscation methods including Luraph, string obfuscation, and generic pattern-based obfuscation.

Features

Multi-Method Support: Supports Luraph, generic string obfuscation, and pattern-based deobfuscation.

Intelligent Analysis: Automatically detects obfuscation methods and complexity.

Comprehensive Transformations: Over 20 different deobfuscation techniques.

Modular Architecture: Clean, extensible codebase with separate modules.

Command-Line & Interactive Interface: Works with CLI options or prompts for input.

Detailed Logging: Verbose output for debugging and analysis.

Installation

Clone or download this repository.

Ensure Python 3.6+ is installed.

Remove any obsolete pathlib package if installed:

python -m pip uninstall pathlib


Install PyInstaller to build the EXE (optional):

python -m pip install pyinstaller

Usage
1️⃣ Command-Line (CLI) Mode

Run directly with Python:

# Basic deobfuscation
python main.py --file obfuscated.lua

# Specify output file
python main.py --file obfuscated.lua --output clean.lua

# Use Luraph-specific normalization
python main.py --file obfuscated.lua --method luraph

# Enable verbose logging
python main.py --file obfuscated.lua --verbose

# Analyze only
python main.py --file obfuscated.lua --analyze


Short options:

-f   --file      Input Lua file
-o   --output    Output file (default: adds _deobfuscated)
-m   --method    Normalization method (default/luraph)
-v   --verbose   Enable detailed logging
--analyze        Analyze only, no modifications

2️⃣ Interactive Mode

If you run the EXE without any arguments:

LuaDeobfuscator.exe


The program will prompt you step by step:

Enter path to Lua file:
Enter output file path (leave blank for default):
Normalization method (default/luraph) [default]:
Analyze only? (y/N):
Enable verbose logging? (y/N):


After entering the options, the tool will process the file and display results in the console.

3️⃣ Building an EXE

To create a standalone executable:

pyinstaller --onefile --name "LuaDeobfuscator" --console main.py


--onefile → produces a single EXE.

--name → sets the executable name.

--console → keeps the terminal open for interactive prompts and logs.

The resulting EXE will be in:

dist/LuaDeobfuscator.exe

4️⃣ Project Structure
lua-deobfuscator/
├── main.py                # Main entry point
├── README.md              # This file
└── src/
    ├── hex_number_normalizer.py  # Core normalization logic
    ├── patterns.py                # Pattern detection and matching
    └── transformations.py         # Transformation functions

5️⃣ How It Works

Analysis Phase: Detects obfuscation method, complexity, and patterns.

Transformation Phase: Applies string decoding, variable restoration, control flow simplification, dead code removal, and other transformations.

Optimization Phase: Formats and normalizes the final Lua code.

6️⃣ Supported Obfuscation Methods

Luraph: Removes padding, dummy arithmetic, and obfuscation patterns.

Generic String Obfuscation: Base64/hex decoding, escape sequence processing, character code conversion.

Pattern-Based: Regex-based pattern detection and automated replacement.

7️⃣ Examples
Analyze a file
python main.py --file suspicious.lua --analyze --verbose

Deobfuscate a file with Luraph method
python main.py --file obfuscated.lua --output clean.lua --method luraph --verbose

Interactive EXE usage
LuaDeobfuscator.exe

8️⃣ Troubleshooting

"Required file not found" → check file path and permissions.

"Syntax error in output" → try a different method or use --analyze.

EXE closes immediately → ensure --console is used when building with PyInstaller or run from a terminal.

9️⃣ Contributing

Add patterns in src/patterns.py.

Implement transformations in src/transformations.py.

Update detection logic in src/hex_number_normalizer.py.

10️⃣ License

This tool is for educational and research purposes only. Respect original authors’ intentions when deobfuscating code.
