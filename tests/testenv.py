# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Environment settings affecting tests."""

from __future__ import annotations

import os

from coverage import env

# What core are we using, either requested or defaulted?
CORE = os.getenv("COVERAGE_CORE", "sysmon" if env.SYSMON_DEFAULT else "ctrace")

TRACER_CLASS = {
    "ctrace": "CTracer",
    "pytrace": "PyTracer",
    "sysmon": "SysMonitor",
}[CORE]

# Are we testing the C-implemented trace function?
C_TRACER = CORE == "ctrace"

# Are we testing the Python-implemented trace function?
PY_TRACER = CORE == "pytrace"

# Are we testing the sys.monitoring implementation?
SYS_MON = CORE == "sysmon"

# Are we using a settrace function as a core?
SETTRACE_CORE = C_TRACER or PY_TRACER

# Are plugins supported during these tests?
PLUGINS = C_TRACER

# Are dynamic contexts supported during these tests?
DYN_CONTEXTS = C_TRACER or PY_TRACER

# Can we measure threads?
CAN_MEASURE_THREADS = not SYS_MON

# Can we measure branches?
CAN_MEASURE_BRANCHES = env.PYBEHAVIOR.branch_right_left
