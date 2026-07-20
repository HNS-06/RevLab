#!/usr/bin/env python3
"""
RevLab - Static Binary Analysis Toolkit
Main launcher script.
"""
import sys
import os

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from revlab.cli.main import app

if __name__ == "__main__":
    app()
