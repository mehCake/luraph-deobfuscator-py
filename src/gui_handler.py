"""
Interactive GUI Handler - Terminal-based interface
"""

import os
import sys
from typing import Dict, Any, Optional
from pathlib import Path

# Fixed import syntax for relative imports
from .utils import colorize_text, clear_screen, get_user_input
from .deobfuscator import LuaDeobfuscator


class GUIHandler:
    """Interactive terminal-based GUI for the Lua deobfuscator"""
    
    def __init__(self):
        self.deobfuscator = None
        self.config: Dict[str, Any] = {}
        self.current_file: Optional[str] = None
        
    def run(self):
        """Main GUI loop"""
        clear_screen()
        self._show_welcome()
        
        while True:
            try:
                choice = self._show_main_menu()
                
                if choice == '1':
                    self._handle_file_selection()
                elif choice == '2':
                    self._handle_configuration()
                elif choice == '3':
                    self._handle_deobfuscation()
                elif choice == '4':
                    self._show_help()
                elif choice == '5':
                    self._show_about()
                elif choice == '6' or choice.lower() == 'q':
                    print(colorize_text("\nGoodbye!", "green"))
                    break
                else:
                    print(colorize_text("Invalid choice. Please try again.", "red"))
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                print(colorize_text("\n\nExiting...", "yellow"))
                break
            except Exception as e:
                print(colorize_text(f"An error occurred: {e}", "red"))
                input("Press Enter to continue...")
    
    def _show_welcome(self):
        """Show welcome screen"""
        print(colorize_text("=" * 60, "blue"))
        print(colorize_text("     LUA DEOBFUSCATOR - Interactive Terminal GUI", "cyan", bold=True))
        print(colorize_text("=" * 60, "blue"))
        print()
        print("Welcome to the Lua Deobfuscator!")
        print("This tool helps you deobfuscate Lua scripts.")
        print()
    
    def _show_main_menu(self) -> str:
        """Show main menu and get user choice"""
        clear_screen()
        print(colorize_text("MAIN MENU", "cyan", bold=True))
        print("=" * 30)
        print()
        
        # Show current status
        if self.current_file:
            print(f"Current file: {colorize_text(self.current_file, 'green')}")
        else:
            print(f"Current file: {colorize_text('None selected', 'red')}")
        
        print()
        print("1. Select Lua file")
        print("2. Configuration")
        print("3. Start deobfuscation")
        print("4. Help")
        print("5. About")
        print("6. Exit")
        print()
        
        return get_user_input("Choose an option (1-6): ")
    
    def _handle_file_selection(self):
        """Handle file selection"""
        clear_screen()
        print(colorize_text("FILE SELECTION", "cyan", bold=True))
        print("=" * 30)
        print()
        
        while True:
            file_path = get_user_input("Enter the path to your Lua file (or 'back' to return): ")
            
            if file_path.lower() == 'back':
                return
            
            if not file_path:
                print(colorize_text("Please enter a file path.", "red"))
                continue
            
            path = Path(file_path)
            if not path.exists():
                print(colorize_text("File does not exist. Please try again.", "red"))
                continue
            
            if not path.is_file():
                print(colorize_text("Path is not a file. Please try again.", "red"))
                continue
            
            if path.suffix.lower() not in ['.lua', '.luac', '.txt']:
                confirm = get_user_input("File doesn't have a Lua extension. Continue anyway? (y/n): ")
                if confirm.lower() != 'y':
                    continue
            
            self.current_file = str(path.absolute())
            print(colorize_text(f"File selected: {self.current_file}", "green"))
            input("Press Enter to continue...")
            break
    
    def _handle_configuration(self):
        """Handle configuration settings"""
        clear_screen()
        print(colorize_text("CONFIGURATION", "cyan", bold=True))
        print("=" * 30)
        print()
        
        # Initialize default config if not exists
        if not self.config:
            self.config = {
                'deobfuscation': {
                    'remove_junk': True,
                    'decrypt_strings': True,
                    'resolve_calls': True,
                    'simplify_expressions': True,
                    'max_iterations': 3
                },
                'output': {
                    'beautify': True,
                    'rename_variables': True,
                    'indent_size': 2,
                    'add_comments': True
                }
            }
        
        while True:
            self._show_config_menu()
            choice = get_user_input("Choose an option (1-3): ")
            
            if choice == '1':
                self._configure_deobfuscation()
            elif choice == '2':
                self._configure_output()
            elif choice == '3':
                break
            else:
                print(colorize_text("Invalid choice.", "red"))
                input("Press Enter to continue...")
    
    def _show_config_menu(self):
        """Show configuration menu"""
        clear_screen()
        print(colorize_text("CONFIGURATION MENU", "cyan", bold=True))
        print("=" * 30)
        print()
        print("1. Deobfuscation settings")
        print("2. Output settings")
        print("3. Back to main menu")
        print()
    
    def _configure_deobfuscation(self):
        """Configure deobfuscation settings"""
        clear_screen()
        print(colorize_text("DEOBFUSCATION SETTINGS", "cyan", bold=True))
        print("=" * 30)
        print()
        
        settings = self.config['deobfuscation']
        
        print("Current settings:")
        for key, value in settings.items():
            status = colorize_text("ON", "green") if value else colorize_text("OFF", "red")
            print(f"  {key.replace('_', ' ').title()}: {status}")
        
        print()
        print("1. Toggle remove junk code")
        print("2. Toggle decrypt strings")
        print("3. Toggle resolve function calls")
        print("4. Toggle simplify expressions")
        print("5. Set max iterations")
        print("6. Back")
        print()
        
        choice = get_user_input("Choose setting to modify (1-6): ")
        
        if choice == '1':
            settings['remove_junk'] = not settings['remove_junk']
        elif choice == '2':
            settings['decrypt_strings'] = not settings['decrypt_strings']
        elif choice == '3':
            settings['resolve_calls'] = not settings['resolve_calls']
        elif choice == '4':
            settings['simplify_expressions'] = not settings['simplify_expressions']
        elif choice == '5':
            try:
                iterations = int(get_user_input("Enter max iterations (1-10): "))
                if 1 <= iterations <= 10:
                    settings['max_iterations'] = iterations
                else:
                    print(colorize_text("Invalid range. Using default.", "red"))
            except ValueError:
                print(colorize_text("Invalid number. Using default.", "red"))
        elif choice == '6':
            return
        
        if choice != '6':
            print(colorize_text("Setting updated!", "green"))
            input("Press Enter to continue...")
    
    def _configure_output(self):
        """Configure output settings"""
        clear_screen()
        print(colorize_text("OUTPUT SETTINGS", "cyan", bold=True))
        print("=" * 30)
        print()
        
        settings = self.config['output']
        
        print("Current settings:")
        for key, value in settings.items():
            if key == 'indent_size':
                print(f"  Indent size: {colorize_text(str(value), 'green')}")
            else:
                status = colorize_text("ON", "green") if value else colorize_text("OFF", "red")
                print(f"  {key.replace('_', ' ').title()}: {status}")
        
        print()
        print("1. Toggle code beautification")
        print("2. Toggle variable renaming")
        print("3. Set indent size")
        print("4. Toggle add comments")
        print("5. Back")
        print()
        
        choice = get_user_input("Choose setting to modify (1-5): ")
        
        if choice == '1':
            settings['beautify'] = not settings['beautify']
        elif choice == '2':
            settings['rename_variables'] = not settings['rename_variables']
        elif choice == '3':
            try:
                indent = int(get_user_input("Enter indent size (2, 4, or 8): "))
                if indent in [2, 4, 8]:
                    settings['indent_size'] = indent
                else:
                    print(colorize_text("Invalid size. Using default.", "red"))
            except ValueError:
                print(colorize_text("Invalid number. Using default.", "red"))
        elif choice == '4':
            settings['add_comments'] = not settings['add_comments']
        elif choice == '5':
            return
        
        if choice != '5':
            print(colorize_text("Setting updated!", "green"))
            input("Press Enter to continue...")
    
    def _handle_deobfuscation(self):
        """Handle the deobfuscation process"""
        clear_screen()
        print(colorize_text("DEOBFUSCATION", "cyan", bold=True))
        print("=" * 30)
        print()
        
        if not self.current_file:
            print(colorize_text("No file selected. Please select a file first.", "red"))
            input("Press Enter to continue...")
            return
        
        if not self.config:
            print("Using default configuration...")
            self.config = {
                'deobfuscation': {
                    'remove_junk': True,
                    'decrypt_strings': True,
                    'resolve_calls': True,
                    'simplify_expressions': True,
                    'max_iterations': 3
                },
                'output': {
                    'beautify': True,
                    'rename_variables': True,
                    'indent_size': 2,
                    'add_comments': True
                }
            }
        
        try:
            # Initialize deobfuscator
            self.deobfuscator = LuaDeobfuscator(config=self.config)
            
            print(f"Processing file: {colorize_text(self.current_file, 'green')}")
            print("Starting deobfuscation...")
            print()
            
            # Start deobfuscation
            result = self.deobfuscator.deobfuscate_file(self.current_file)
            
            if result:
                print(colorize_text("Deobfuscation completed successfully!", "green"))
                print()
                
                # Show statistics
                stats = self.deobfuscator.get_statistics()
                print("Statistics:")
                for key, value in stats.items():
                    print(f"  {key.replace('_', ' ').title()}: {colorize_text(str(value), 'cyan')}")
                
                print()
                output_file = self.current_file.replace('.lua', '_deobfuscated.lua')
                print(f"Output saved to: {colorize_text(output_file, 'green')}")
                
            else:
                print(colorize_text("Deobfuscation failed. Check the logs for details.", "red"))
            
        except Exception as e:
            print(colorize_text(f"Error during deobfuscation: {e}", "red"))
        
        input("\nPress Enter to continue...")
    
    def _show_help(self):
        """Show help information"""
        clear_screen()
        print(colorize_text("HELP", "cyan", bold=True))
        print("=" * 30)
        print()
        
        help_text = """
How to use the Lua Deobfuscator:

1. Select a Lua file:
   - Choose option 1 from the main menu
   - Enter the full path to your obfuscated Lua file
   - Supported extensions: .lua, .luac, .txt

2. Configure settings (optional):
   - Choose option 2 from the main menu
   - Adjust deobfuscation and output settings
   - Default settings work well for most cases

3. Start deobfuscation:
   - Choose option 3 from the main menu
   - The tool will process your file automatically
   - Output will be saved with '_deobfuscated' suffix

Deobfuscation Features:
- Remove junk/dead code
- Decrypt obfuscated strings
- Resolve function calls
- Simplify complex expressions
- Variable renaming for clarity
- Code beautification

Supported Obfuscation Types:
- Basic string obfuscation
- Function call obfuscation
- Variable name mangling
- Dead code injection
- Control flow obfuscation

Tips:
- Make a backup of your original file
- Try different settings if first attempt fails
- Check the output file for any remaining issues
        """
        
        print(help_text)
        input("Press Enter to continue...")
    
    def _show_about(self):
        """Show about information"""
        clear_screen()
        print(colorize_text("ABOUT", "cyan", bold=True))
        print("=" * 30)
        print()
        
        about_text = """
Lua Deobfuscator v1.0
=====================

A powerful tool for deobfuscating Lua scripts with support for
various obfuscation techniques commonly used in:
- Game scripts
- Malware analysis
- Reverse engineering
- Code recovery

Features:
✓ Interactive terminal GUI
✓ Multiple deobfuscation techniques
✓ Configurable settings
✓ Progress tracking
✓ Statistics reporting
✓ Code beautification
✓ Variable renaming

Author: AI Assistant
License: Open Source
        """
        
        print(about_text)
        input("Press Enter to continue...")


def run_gui():
    """Entry point for the GUI"""
    try:
        gui = GUIHandler()
        gui.run()
    except Exception as e:
        print(f"GUI Error: {e}")
        sys.exit(1)
