#!/usr/bin/env python3
"""
Build script to create standalone executable
Automatically detects main.py in root or src directory
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_pyinstaller():
    """Check if PyInstaller is available"""
    try:
        import PyInstaller
        return True
    except ImportError:
        return False

def install_pyinstaller():
    """Install PyInstaller"""
    print("Installing PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        return True
    except subprocess.CalledProcessError:
        print("Failed to install PyInstaller")
        return False

def detect_main_py() -> Path:
    """Detect the main.py file to use for building"""
    root_main = Path("main.py")
    src_main = Path("src") / "main.py"
    
    if root_main.exists():
        print("Detected main.py in root directory.")
        return root_main
    elif src_main.exists():
        print("Detected main.py in src/ directory.")
        return src_main
    else:
        print("Error: main.py not found in root or src/ directory.")
        sys.exit(1)

def build_executable(main_path: Path):
    """Build the executable using PyInstaller"""
    print("Building executable...")
    
    # Determine platform-specific path separator
    sep = ";" if sys.platform.startswith("win") else ":"
    
    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",
        "--console",
        "--name", "lua-deobfuscator",
        "--add-data", f"config.json{sep}.",
        "--add-data", f"requirements.txt{sep}.",
        "--hidden-import", "src.deobfuscator",
        "--hidden-import", "utils",
        "--hidden-import", "colorama",
        "--hidden-import", "pyfiglet",
        "--hidden-import", "tqdm",
        "--hidden-import", "requests",
        "--paths", ".",
        str(main_path)
    ]
    
    try:
        subprocess.check_call(cmd)
        print("✓ Executable built successfully!")
        
        # Move executable to root directory
        dist_path = Path("dist") / ("lua-deobfuscator.exe" if sys.platform.startswith("win") else "lua-deobfuscator")
        if dist_path.exists():
            shutil.move(str(dist_path), str(Path.cwd() / dist_path.name))
            print(f"✓ Executable moved to root directory: {dist_path.name}")
        
        # Cleanup
        for folder in ["build", "dist"]:
            if Path(folder).exists():
                shutil.rmtree(folder)
        spec_file = Path("lua-deobfuscator.spec")
        if spec_file.exists():
            spec_file.unlink()
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Build failed: {e}")
        return False

def main():
    """Main build process"""
    print("Lua Deobfuscator - Build Script")
    print("=" * 40)
    
    # Check PyInstaller
    if not check_pyinstaller():
        if not install_pyinstaller():
            sys.exit(1)
    
    # Detect main.py
    main_path = detect_main_py()
    
    # Build executable
    if build_executable(main_path):
        print("\n✓ Build completed successfully!")
        exe_name = "lua-deobfuscator.exe" if sys.platform.startswith("win") else "lua-deobfuscator"
        print(f"You can now run: {exe_name}")
    else:
        print("\n✗ Build failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
