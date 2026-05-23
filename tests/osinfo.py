# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""OS information for testing."""

from __future__ import annotations

import sys


if sys.platform == "win32":
    # Windows implementation
    def process_ram() -> int:
        """How much RAM is this process using? (Windows)"""
        import ctypes
        from ctypes import wintypes

        # From: http://lists.ubuntu.com/archives/bazaar-commits/2009-February/011990.html
        # Updated from: https://stackoverflow.com/a/16204942/14343
        class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
            """Used by GetProcessMemoryInfo"""

            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
                ("PrivateUsage", ctypes.c_size_t),
            ]

        GetProcessMemoryInfo = ctypes.windll.psapi.GetProcessMemoryInfo
        GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
            wintypes.DWORD,
        ]
        GetProcessMemoryInfo.restype = wintypes.BOOL

        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.argtypes = []
        GetCurrentProcess.restype = wintypes.HANDLE

        counters = PROCESS_MEMORY_COUNTERS_EX()
        ret = GetProcessMemoryInfo(
            GetCurrentProcess(),
            ctypes.byref(counters),
            ctypes.sizeof(counters),
        )
        if not ret:  # pragma: part covered
            return 0  # pragma: cant happen
        return counters.PrivateUsage

elif sys.platform.startswith("linux"):
    # Linux implementation
    import os

    _scale = {"kb": 1024, "mb": 1024 * 1024}

    def _VmB(key: str) -> int:
        """Read the /proc/PID/status file to find memory use."""
        try:
            # Get pseudo file /proc/<pid>/status
            with open(f"/proc/{os.getpid()}/status", encoding="utf-8") as t:
                v = t.read()
        except OSError:  # pragma: cant happen
            return 0  # non-Linux?
        # Get VmKey line e.g. 'VmRSS:  9999  kB\n ...'
        i = v.index(key)
        vp = v[i:].split(None, 3)
        if len(vp) < 3:  # pragma: part covered
            return 0  # pragma: cant happen
        # Convert Vm value to bytes.
        return int(float(vp[1]) * _scale[vp[2].lower()])

    def process_ram() -> int:
        """How much RAM is this process using? (Linux implementation)"""
        return _VmB("VmRSS")

else:
    # Generic implementation.
    def process_ram() -> int:
        """How much RAM is this process using? (stdlib implementation)"""
        import resource

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
