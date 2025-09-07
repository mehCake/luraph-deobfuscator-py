# Lua Deobfuscator

A comprehensive Python tool for analyzing and deobfuscating Lua scripts. This tool helps reverse engineers and security researchers understand obfuscated Lua code by applying various deobfuscation techniques.

## Features

- **Code Analysis**: Identifies obfuscation patterns and suspicious constructs
- **String Deobfuscation**: Decodes various string encoding methods
- **Variable Renaming**: Replaces meaningless variable names with readable ones  
- **Code Beautification**: Applies proper formatting and indentation
- **Modular Design**: Each component can be used independently

## Installation

1. Clone or download the project
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
# Analyze and deobfuscate a Lua file
python src/main.py input.lua

# Save to a specific output file
python src/main.py input.lua -o output.lua
```

### Advanced Options

```bash
# Only analyze the code (no output file)
python src/main.py input.lua --analyze-only

# Only beautify the code
python src/main.py input.lua --beautify-only

# Only rename variables
python src/main.py input.lua --rename-only

# Skip specific steps
python src/main.py input.lua --skip-beautify
python src/main.py input.lua --skip-rename

# Adjust indentation size
python src/main.py input.lua --indent-size 4

# Set logging level
python src/main.py input.lua --log-level DEBUG
```

## Components

### Deobfuscator (`deobfuscator.py`)
- Analyzes code for obfuscation patterns
- Decodes string literals
- Removes junk code and unnecessary complexity
- Provides detailed analysis reports

### Beautifier (`beautifier.py`) 
- Applies proper indentation and formatting
- Normalizes whitespace and line endings
- Formats functions, tables, and control structures
- Adds appropriate spacing around operators

### Variable Renamer (`variable_renamer.py`)
- Identifies obfuscated variable and function names
- Generates meaningful replacement names based on context
- Provides mapping reports showing all changes

## Example

Input (obfuscated):
```lua
local a=function(b,c)local d=""for e=1,#b do d=d..string.char(string.byte(b,e)~c)end return d end
local f=a("\x1b\x0f\x0c\x0c\x11\x68\x75\x11\x16\x0c\x08",23)
print(f)
```

Output (deobfuscated):
```lua
local function_1 = function(text, value)
  local content = ""
  for index = 1, #text do
    content = content .. string.char(string.byte(text, index) ~ value)
  end
  return content
end

local message = "Hello World"
print(message)
```

## Logging

The tool provides detailed logging at different levels:
- **INFO**: General progress information
- **DEBUG**: Detailed processing information  
- **WARNING**: Potential issues or unusual patterns
- **ERROR**: Errors that prevent processing

## Limitations

- Complex control flow obfuscation may require manual analysis
- Some advanced obfuscation techniques may not be fully handled
- Variable context detection is heuristic-based and may not always be accurate

## Contributing

This tool is designed to be extensible. New deobfuscation techniques can be added by:
1. Adding new methods to the `LuaDeobfuscator` class
2. Implementing additional pattern recognition in the analyzer
3. Extending the variable renamer with better context detection

## License

This project is provided for educational and research purposes.

