Advanced Lua Deobfuscator (Python)

Description:
Advanced Lua Deobfuscator normalizes numbers, strings, and Luraph-specific obfuscation in Lua code. Supports both command-line and interactive mode.

Requirements

Python 3.10+

Only standard library modules (no extra pip installs required)

If building an EXE, make sure the pathlib backport is not installed, as it conflicts with PyInstaller.

Installation

Clone the repository:

git clone C:\Users\mende\luraph-deobfuscator-py
cd luraph-deobfuscator-py


Optionally, create an EXE:

pip uninstall pathlib      # Remove incompatible backport if installed
pyinstaller --onefile --name "LuaDeobfuscator" main.py


The EXE will be generated in dist/LuaDeobfuscator.exe.

Usage
1. Command-Line Interface (CLI)
python main.py --file obfuscated.lua --output deobfuscated.lua --verbose --method luraph --analyze


Arguments:

Option	Shortcut	Description
--file	-f	Path to input Lua file (required)
--output	-o	Output Lua file (default: _deobfuscated.lua)
--verbose	-v	Enable verbose logging
--analyze		Analyze only, do not modify the code
--method		Normalization method: default or luraph (default: default)

Example:

python main.py -f obfuscated.lua -o output.lua -v --method luraph

2. Interactive Mode (EXE or Python)

If you run without --file, the program opens interactive prompts:

python main.py


or after building the EXE:

dist\LuaDeobfuscator.exe


You’ll be prompted for:

Input Lua file path

Output file path (optional)

Normalization method (default / luraph)

Analyze-only mode (y/N)

Verbose logging (y/N)

The program will keep running until you complete the prompts and generate the output.

Notes

EXE mode is ideal for interactive use since it prevents the program from closing immediately.

CLI mode is recommended for automation and batch processing.

Luraph-specific normalizations remove dummy functions and unnecessary empty string concatenations.