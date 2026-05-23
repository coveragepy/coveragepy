# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
Pick lines from the standard input.  Blank or commented lines are ignored.

Used to subset lists of tests to run.  Use with the --select-cmd pytest plugin
option.

The first command line argument is a mode for selection. Other arguments depend
on the mode.  Only one mode is currently implemented: sample.

Modes:

    - ``sample``: randomly sample N lines from the input.

        - the first argument is N, the number of lines you want.

        - the second argument is optional: a seed for the randomizer.
          Using the same seed will produce the same output.

Examples:

Get a list of test nodes::

    pytest --collect-only | grep :: > tests.txt

Use like this::

    pytest --cache-clear --select-cmd="python pick.py sample 10 < tests.txt"

For coverage.py specifically::

    tox -q -e py311 -- -n 0 --cache-clear --select-cmd="python lab/pick.py sample 10 < tests.txt"

or::

    for n in $(seq 1 100); do \
        echo seed=$n; \
        tox -q -e py311 -- -n 0 --cache-clear --select-cmd="python lab/pick.py sample 3 $n < tests.txt"; \
    done

More about this: https://nedbatchelder.com/blog/202401/randomly_subsetting_test_suites.html

"""

import random
import sys

args = sys.argv[1:][::-1]
next_arg = args.pop

lines = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    if line.startswith("#"):
        continue
    lines.append(line)

mode = next_arg()
if mode == "sample":
    number = int(next_arg())
    if args:
        random.seed(next_arg())
    lines = random.sample(lines, number)
else:
    raise ValueError(f"Don't know {mode=}")

for line in lines:
    print(line)
