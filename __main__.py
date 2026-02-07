"""
ETHICAL Malware Analysis Toolkit (E-MAT)
Main Entry Point - Thin wrapper for python -m support

All logic lives in emat.py. This file just delegates to it.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from emat import main


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
