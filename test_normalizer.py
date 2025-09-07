#!/usr/bin/env python3
"""
Unit tests for the CodeNormalizer class.
"""

import unittest
from code_normalizer import CodeNormalizer

class TestCodeNormalizer(unittest.TestCase):
    
    def setUp(self):
        self.normalizer = CodeNormalizer()
    
    def test_normalize_hex_number(self):
        # Test basic hex conversion
        self.assertEqual(self.normalizer.normalize_hex_number("A"), "10")
        self.assertEqual(self.normalizer.normalize_hex_number("FF"), "255")
        self.assertEqual(self.normalizer.normalize_hex_number("10"), "16")
        
        # Test case insensitivity
        self.assertEqual(self.normalizer.normalize_hex_number("ff"), "255")
        self.assertEqual(self.normalizer.normalize_hex_number("aB"), "171")
    
    def test_normalize_scientific_notation(self):
        self.assertEqual(self.normalizer.normalize_scientific_notation("1e3"), "1000.0")
        self.assertEqual(self.normalizer.normalize_scientific_notation("2.5e2"), "250.0")
        self.assertEqual(self.normalizer.normalize_scientific_notation("1E-2"), "0.01")
        self.assertEqual(self.normalizer.normalize_scientific_notation("3.14e0"), "3.14")
    
    def test_normalize_hex_string(self):
        # Test printable ASCII
        self.assertEqual(self.normalizer.normalize_hex_string("41"), "A")  # 0x41 = 'A'
        self.assertEqual(self.normalizer.normalize_hex_string("20"), " ")  # 0x20 = space
        
        # Test non-printable (should remain as hex)
        self.assertEqual(self.normalizer.normalize_hex_string("00"), "\\x00")
        self.assertEqual(self.normalizer.normalize_hex_string("1F"), "\\x1F")
        
        # Test quotes and backslash (should remain escaped)
        self.assertEqual(self.normalizer.normalize_hex_string("22"), "\\x22")  # "
        self.assertEqual(self.normalizer.normalize_hex_string("27"), "\\x27")  # '
        self.assertEqual(self.normalizer.normalize_hex_string("5C"), "\\x5C")  # \
    
    def test_normalize_unicode_escape(self):
        # Test basic ASCII characters
        self.assertEqual(self.normalizer.normalize_unicode_escape("0041"), "A")
        self.assertEqual(self.normalizer.normalize_unicode_escape("0020"), " ")
        
        # Test quotes and backslash (should remain escaped)
        self.assertEqual(self.normalizer.normalize_unicode_escape("0022"), "\\u0022")
        self.assertEqual(self.normalizer.normalize_unicode_escape("0027"), "\\u0027")
        self.assertEqual(self.normalizer.normalize_unicode_escape("005C"), "\\u005C")
        
        # Test non-printable
        self.assertEqual(self.normalizer.normalize_unicode_escape("0000"), "\\u0000")
    
    def test_normalize_octal_escape(self):
        # Test printable ASCII
        self.assertEqual(self.normalizer.normalize_octal_escape("101"), "A")  # 101 octal = 65 decimal = 'A'
        self.assertEqual(self.normalizer.normalize_octal_escape("040"), " ")  # 40 octal = 32 decimal = space
        
        # Test quotes and backslash
        self.assertEqual(self.normalizer.normalize_octal_escape("042"), "\\\"")  # 42 octal = 34 decimal = '"'
        self.assertEqual(self.normalizer.normalize_octal_escape("047"), "\\'")   # 47 octal = 39 decimal = "'"
        self.assertEqual(self.normalizer.normalize_octal_escape("134"), "\\\\")  # 134 octal = 92 decimal = '\'
        
        # Test non-printable
        self.assertEqual(self.normalizer.normalize_octal_escape("000"), "\\000")
    
    def test_normalize_whitespace(self):
        test_code = "a = 1\n\n\n    b = 2\t\t\tc = 3"
        expected = "a = 1\n\nb = 2 c = 3"
        result = self.normalizer.normalize_whitespace(test_code)
        self.assertEqual(result, expected)
    
    def test_normalize_all_numbers_integration(self):
        test_code = """
        x = 0xFF  # hex
        y = 1e3   # scientific
        z = "\\x41\\u0042"  # string escapes
        w = 5.0   # float
        """
        
        result = self.normalizer.normalize_all_numbers(test_code)
        
        # Check that hex was converted
        self.assertIn("255", result)
        self.assertNotIn("0xFF", result)
        
        # Check that scientific notation was converted
        self.assertIn("1000", result)
        self.assertNotIn("1e3", result)
        
        # Check that string escapes were converted
        self.assertIn("AB", result)
        
        # Check that unnecessary .0 was removed
        self.assertIn("5", result)
        self.assertNotIn("5.0", result)

if __name__ == "__main__":
    unittest.main()