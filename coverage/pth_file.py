# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

# pylint: disable=missing-module-docstring
# This will become the .pth file for subprocesses.

print("zzz_coverage.pth file loaded")
try:
    import coverage
except Exception as e:  # pylint: disable=bare-except
    print(f"zzz_coverage.pth: coverage import failed: {e}")

else:
    # coverage.process_startup()
    print("zzz_coverage.pth: coverage imported successfully")
