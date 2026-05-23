# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Run sys.monitoring on a file of Python code."""

import functools
import sys

print(sys.version)
the_program = sys.argv[1]

code = compile(open(the_program, encoding="utf-8").read(), filename=the_program, mode="exec")

my_id = sys.monitoring.COVERAGE_ID
sys.monitoring.use_tool_id(my_id, "run_sysmon.py")
register = functools.partial(sys.monitoring.register_callback, my_id)
events = sys.monitoring.events


def bytes_to_lines(code):
    """Make a dict mapping byte code offsets to line numbers."""
    b2l = {}
    cur_line = 0
    for bstart, bend, lineno in code.co_lines():
        for boffset in range(bstart, bend, 2):
            b2l[boffset] = lineno
    return b2l


MY_EVENTS = (
    events.PY_RETURN
    | events.PY_RESUME
    | events.LINE
    | events.BRANCH_RIGHT
    | events.BRANCH_LEFT
    | events.JUMP
)


def show_off(label, code, instruction_offset):
    if code.co_filename == the_program:
        b2l = bytes_to_lines(code)
        print(f"{label}: {code.co_filename}@{instruction_offset} #{b2l[instruction_offset]}")


def show_line(label, code, line_number):
    if code.co_filename == the_program:
        print(f"{label}: {code.co_filename} #{line_number}")


def show_off_off(label, code, instruction_offset, destination_offset):
    if code.co_filename == the_program:
        b2l = bytes_to_lines(code)
        print(
            f"{label}: {code.co_filename}@{instruction_offset}->{destination_offset} "
            + f"#{b2l[instruction_offset]}->{b2l[destination_offset]}"
        )


def sysmon_py_start(code, instruction_offset):
    show_off("PY_START", code, instruction_offset)
    sys.monitoring.set_local_events(
        my_id,
        code,
        MY_EVENTS,
    )


def sysmon_py_resume(code, instruction_offset):
    show_off("PY_RESUME", code, instruction_offset)
    return sys.monitoring.DISABLE


def sysmon_py_return(code, instruction_offset, retval):
    show_off("PY_RETURN", code, instruction_offset)
    return sys.monitoring.DISABLE


def sysmon_line(code, line_number):
    show_line("LINE", code, line_number)
    return sys.monitoring.DISABLE


def sysmon_branch(code, instruction_offset, destination_offset):
    show_off_off("BRANCH", code, instruction_offset, destination_offset)
    return sys.monitoring.DISABLE


def sysmon_branch_right(code, instruction_offset, destination_offset):
    show_off_off("BRANCH_RIGHT", code, instruction_offset, destination_offset)
    return sys.monitoring.DISABLE


def sysmon_branch_left(code, instruction_offset, destination_offset):
    show_off_off("BRANCH_LEFT", code, instruction_offset, destination_offset)
    return sys.monitoring.DISABLE


def sysmon_jump(code, instruction_offset, destination_offset):
    show_off_off("JUMP", code, instruction_offset, destination_offset)
    return sys.monitoring.DISABLE


if 1:
    sys.monitoring.set_events(
        my_id,
        events.PY_START | events.PY_UNWIND,
    )
    register(events.PY_START, sysmon_py_start)
    register(events.PY_RESUME, sysmon_py_resume)
    register(events.PY_RETURN, sysmon_py_return)
    # register(events.PY_UNWIND, sysmon_py_unwind_arcs)
    register(events.LINE, sysmon_line)
    register(events.BRANCH, sysmon_branch)
    register(events.BRANCH_RIGHT, sysmon_branch_right)
    register(events.BRANCH_LEFT, sysmon_branch_left)
    register(events.JUMP, sysmon_jump)

exec(code)
