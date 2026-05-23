# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Run a simple trace function on a file of Python code."""

import os, sys

nest = 0


def trace(frame, event, arg):
    global nest

    if nest is None:
        # This can happen when Python is shutting down.
        return None

    if the_program in frame.f_code.co_filename:
        print(
            "%s%s %s %d @%d"
            % (
                "    " * nest,
                event,
                os.path.basename(frame.f_code.co_filename),
                frame.f_lineno,
                frame.f_lasti,
            )
        )

    if event == "call":
        nest += 1
    if event == "return":
        nest -= 1

    return trace


print(sys.version)
the_program = sys.argv[1]

code = open(the_program, encoding="utf-8").read()
code_obj = compile(code, the_program, mode="exec")
sys.settrace(trace)
exec(code_obj)
