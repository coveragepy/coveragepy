# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
A smoke test to verify that the binary tracer module can be imported.
This is not a test used by pytest, it's run by cibuildwheel.
"""

# pragma: exclude file from coverage

# Sometimes CTracer is importable when pylint runs and sometime it isn't.
# So we have to suppress import errors when it can't be imported, and suppress
# warnings about useless suppressions when it can!
# pylint: disable=import-error, no-name-in-module, useless-suppression

from coverage.tracer import CTracer


assert hasattr(CTracer(), "start")
print("CTracer OK!")
