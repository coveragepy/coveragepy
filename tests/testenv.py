# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Environment settings affecting tests."""

from __future__ import annotations

import os

from coverage import env

REQUESTED_CORE = os.getenv("COVERAGE_CORE", "ctrace")

REQUESTED_TRACER_CLASS = {
    "ctrace": "CTracer",
    "pytrace": "PyTracer",
    "sysmon": "SysMonitor",
    "csysmon": "CSysMonitor",
}[REQUESTED_CORE]

# Are we testing the C-implemented trace function?
C_TRACER = REQUESTED_CORE == "ctrace"

# Are we testing the Python-implemented trace function?
PY_TRACER = REQUESTED_CORE == "pytrace"

# Are we testing the sys.monitoring implementation?
SYS_MON = REQUESTED_CORE == "sysmon"

# Are we testing the C sys.monitoring implementation?
C_SYS_MON = REQUESTED_CORE == "csysmon"

# Are we using a settrace function as a core?
SETTRACE_CORE = C_TRACER or PY_TRACER
SYSMON_CORE = SYS_MON or C_SYS_MON

# Are plugins supported during these tests?
PLUGINS = C_TRACER

# Are dynamic contexts supported during these tests?
DYN_CONTEXTS = C_TRACER or PY_TRACER

# Can we measure threads?
CAN_MEASURE_THREADS = not SYSMON_CORE

# Can we measure branches?
CAN_MEASURE_BRANCHES = env.PYBEHAVIOR.branch_right_left
