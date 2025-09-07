#!/usr/bin/env python3
"""
Example input file for demonstrating code normalization.
This file contains various numeric and string representations that can be normalized.
"""

# Hexadecimal numbers
hex_value1 = 0xFF
hex_value2 = 0xDEADBEEF
hex_value3 = 0x10

# Scientific notation
sci_value1 = 1e3
sci_value2 = 2.5E-2
sci_value3 = 6.02e23

# Float values with unnecessary decimals
float_val1 = 10.0
float_val2 = 0.0
float_val3 = 42.0

# String with hex escapes
hex_string = "\x48\x65\x6C\x6C\x6F\x20\x57\x6F\x72\x6C\x64"  # "Hello World"

# String with unicode escapes
unicode_string = "\u0048\u0065\u006C\u006C\u006F"  # "Hello"

# String with octal escapes
octal_string = "\110\145\154\154\157"  # "Hello"

# Mixed whitespace
def    example_function(  ):
	result  =   42


	return result

# Complex example combining multiple patterns
data = {
    'hex': 0xABCD,
    'sci': 1.23e4,
    'string': "\x44\x61\x74\x61",
    'float': 3.0
}