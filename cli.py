#!/usr/bin/env python3
"""CLI entry point for D1 Memory Forensics."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "firmware"))
from mem_forensics import main

if __name__ == "__main__":
    main()
