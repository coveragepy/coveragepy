# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

# pylint: disable=missing-module-docstring
# This will become the .pth file for subprocesses.

print("zzz_coverage.pth file loaded")
try:
    import coverage
except:  # pylint: disable=bare-except
    pass
else:
    coverage.process_startup()
