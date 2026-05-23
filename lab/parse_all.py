"""Parse every Python file in a tree."""

import os
import sys

from coverage.parser import PythonParser

for root, dirnames, filenames in os.walk(sys.argv[1]):
    for filename in filenames:
        if filename.endswith(".py"):
            filename = os.path.join(root, filename)
            print(f":: {filename}")
            try:
                par = PythonParser(filename=filename)
                par.parse_source()
                par.arcs()
            except Exception as exc:
                print(f"  ** {exc}")
