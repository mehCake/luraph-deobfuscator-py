#!/usr/bin/env python3
"""
Legacy main entry point - redirects to new run.py
"""

import sys
import os

# Determine the absolute path to run.py
# This assumes run.py is in the parent directory of src/
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
run_path = os.path.join(parent_dir, "run.py")

# Add the parent directory to sys.path so Python can import run
sys.path.insert(0, parent_dir)

def main():
    """Redirect to new main entry point"""
    try:
        import run
        if hasattr(run, "main"):
            return run.main()
        else:
            print("Error: run.py does not have a 'main' function.")
            return 1
    except ImportError as e:
        print(f"Error importing run.py: {e}")
        print("Please use 'python run.py' instead of 'python src/main.py'")
        return 1

if __name__ == "__main__":
    sys.exit(main())
