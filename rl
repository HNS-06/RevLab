#!/usr/bin/env python3
"""
RevLab Linux/macOS Launcher Script
"""
import sys
import os

# Ensure workspace directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from revlab.cli.main import app

if __name__ == "__main__":
    app()
