import os
import sys

# Ensure aegis package is importable when tests are discovered from any directory
core_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if core_dir not in sys.path:
    sys.path.insert(0, core_dir)
