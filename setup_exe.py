#!/usr/bin/env python3
"""
Automated Setup Script for Creating Lua Deobfuscator Executable
This script handles dependency installation and executable creation.
"""

import os
import sys
import subprocess
from pathlib import Path
import platform

def print_header():
    """Print setup header."""
    print("=" * 60)
    print("    Advanced Lua Deobfuscator - Executable Setup")
    print("=" * 60)
    print()

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required!")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")

def ensure_pyinstaller():
    """Check if PyInstaller is installed, and install it if missing."""
    try:
        subprocess.check_call([sys.executable, "-m", "pyinstaller", "--version"], stdout=subprocess.DEVNULL)
        print("✅ PyInstaller is installed")
    except subprocess.CalledProcessError:
        print("❌ PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✅ PyInstaller installed successfully")

def install_requirements():
    """Install required packages."""
    print("\n📦 Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ All packages installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing packages: {e}")
        return False

def create_executable():
    """Create standalone executable using PyInstaller."""
    print("\n🔧 Creating standalone executable...")

    # Cross-platform --add-data separator
    add_data_sep = ";" if platform.system() == "Windows" else ":"
    add_data_arg = f"config.json{add_data_sep}."

    cmd = [
        "pyinstaller",
        "--onefile",
        "--console",
        "--name", "LuaDeobfuscator",
        "--add-data", add_data_arg,
        "--hidden-import", "colorama",
        "--hidden-import", "pyfiglet",
        "--hidden-import", "tqdm",
        "--hidden-import", "rich",
        "--hidden-import", "inquirer",
        "run.py"
    ]

    try:
        subprocess.check_call(cmd)
        print("✅ Executable created successfully!")

        exe_name = "LuaDeobfuscator.exe" if platform.system() == "Windows" else "LuaDeobfuscator"
        exe_path = Path("dist") / exe_name

        if exe_path.exists():
            print(f"📁 Executable location: {exe_path.absolute()}")
            return True
        else:
            print("❌ Executable not found after creation")
            return False

    except subprocess.CalledProcessError as e:
        print(f"❌ Error creating executable: {e}")
        return False

def create_batch_installer():
    """Create batch file for easy installation (Windows only)."""
    batch_content = '''@echo off
echo Installing Lua Deobfuscator...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH!
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

REM Install requirements
echo Installing Python packages...
pip install -r requirements.txt

REM Create executable
echo Creating executable...
python setup_exe.py

echo.
echo Setup complete! Check the dist folder for LuaDeobfuscator.exe
pause
'''

    with open("install.bat", "w") as f:
        f.write(batch_content)

    print("✅ Created install.bat for Windows users")

def main():
    """Main setup function."""
    print_header()
    check_python_version()
    ensure_pyinstaller()  # <-- New: ensure PyInstaller is installed

    print("\nSetup Options:")
    print("1. Install requirements only")
    print("2. Create executable only (requires packages)")
    print("3. Full setup (install + create exe)")
    if platform.system() == "Windows":
        print("4. Create installer batch file")

    while True:
        try:
            choice = input("\nEnter your choice: ").strip()
            if choice in ['1', '2', '3'] or (choice == '4' and platform.system() == "Windows"):
                break
            print("Please enter a valid choice")
        except (KeyboardInterrupt, EOFError):
            print("\n\nSetup cancelled by user.")
            return 1

    success = True

    if choice in ['1', '3']:
        success = install_requirements()
        if not success:
            print("\n❌ Setup failed during package installation")
            return 1

    if choice in ['2', '3'] and success:
        success = create_executable()
        if not success:
            print("\n❌ Setup failed during executable creation")
            return 1

    if choice == '4' and platform.system() == "Windows":
        create_batch_installer()

    if success and choice in ['2', '3']:
        print("\n🎉 Setup completed successfully!")
        print("\nYou can now:")
        print("1. Run the executable from dist/ folder")
        print("2. Copy the executable to any location")
        print("3. Share the executable (no Python required on target machine)")

        try:
            test = input("\nTest the executable now? (y/n): ").lower().strip()
        except EOFError:
            test = 'n'

        if test in ['y', 'yes']:
            exe_name = "LuaDeobfuscator.exe" if platform.system() == "Windows" else "LuaDeobfuscator"
            exe_path = Path("dist") / exe_name
            if exe_path.exists():
                try:
                    subprocess.Popen([str(exe_path)])
                except Exception as e:
                    print(f"❌ Error running executable: {e}")
            else:
                print("❌ Executable not found")

    return 0

if __name__ == "__main__":
    sys.exit(main())
