# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
Use this to copy some indented code from the coverage.py test suite into a
standalone file for deeper testing, or writing bug reports.

Give it a file name and a line number, and it will find the indented
multi-line string containing that line number, and output the dedented
contents of the string.

If tests/test_arcs.py has this (partial) content::

    1630	    def test_partial_generators(self):
    1631	        # https://github.com/coveragepy/coveragepy/issues/475
    1632	        # Line 2 is executed completely.
    1633	        # Line 3 is started but not finished, because zip ends before it finishes.
    1634	        # Line 4 is never started.
    1635	        cov = self.check_coverage('''\
    1636	            def f(a, b):
    1637	                c = (i for i in a)          # 2
    1638	                d = (j for j in b)          # 3
    1639	                e = (k for k in b)          # 4
    1640	                return dict(zip(c, d))
    1641
    1642	            f(['a', 'b'], [1, 2, 3])
    1643	            ''',
    1644	            arcz=".1 17 7.  .2 23 34 45 5.  -22 2-2  -33 3-3  -44 4-4",
    1645	            arcz_missing="3-3 -44 4-4",
    1646	        )

then you can do::

    % python lab/extract_code.py tests/test_arcs.py 1637
    def f(a, b):
        c = (i for i in a)          # 2
        d = (j for j in b)          # 3
        e = (k for k in b)          # 4
        return dict(zip(c, d))

    f(['a', 'b'], [1, 2, 3])
    %

"""

import sys
import textwrap

if len(sys.argv) == 2:
    fname, lineno = sys.argv[1].split(":")
else:
    fname, lineno = sys.argv[1:]
lineno = int(lineno)

with open(fname, encoding="utf-8") as code_file:
    lines = ["", *code_file]

# Find opening triple-quote
for start in range(lineno, 0, -1):
    line = lines[start]
    if "'''" in line or '"""' in line:
        break

for end in range(lineno + 1, len(lines)):
    line = lines[end]
    if "'''" in line or '"""' in line:
        break

code = "".join(lines[start + 1 : end])
code = textwrap.dedent(code)

print(code, end="")
