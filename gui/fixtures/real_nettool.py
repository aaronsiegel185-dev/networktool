#!/usr/bin/env python3
"""Run the real CLI from the repo, for screenshots of tabs that need live data."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from toolbox.cli import main
sys.exit(main(sys.argv[1:]))
