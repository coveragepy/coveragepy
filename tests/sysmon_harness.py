# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Replay harness for testing SysMonitor with recorded monitoring events.

This module provides SysMonitorHarness, which feeds pre-recorded
sys.monitoring event sequences through SysMonitor's callback methods.
It allows testing SysMonitor's event-processing logic in isolation,
without needing a live Python execution.

The recordings come from the monitoring-probe tool, which captures
real CPython sys.monitoring events for small code snippets.
"""

from __future__ import annotations

import dis
import json
import sys
from pathlib import Path
from types import CodeType
from typing import Any
from unittest.mock import MagicMock

from coverage import env
from coverage.disposition import FileDisposition
from coverage.sysmon import SysMonitor


class SysMonitorHarness:
    """Replay recorded monitoring events through SysMonitor.

    This harness:
    - Compiles the source code to get real CodeType objects
    - Configures a SysMonitor instance with stubs for external deps
    - Patches sys_monitoring calls to no-ops (we drive events manually)
    - Feeds events into SysMonitor's callback methods
    - Returns the collected coverage data for assertion
    """

    def __init__(
        self,
        source: str,
        filename: str = "target.py",
        trace_arcs: bool = False,
    ) -> None:
        self.source = source
        self.filename = filename
        self.trace_arcs = trace_arcs

        # Compile source to get code objects for this Python version
        self.code = compile(source, filename, "exec")
        self.code_map = self._build_code_map(self.code)

        # Create and configure SysMonitor with stubs
        self.monitor = SysMonitor(tool_id=1)
        self.monitor.data = {}
        self.monitor.trace_arcs = trace_arcs
        self.monitor.should_trace_cache = {
            filename: self._make_disposition(filename)
        }
        self.monitor.lock_data = lambda: None
        self.monitor.unlock_data = lambda: None
        self.monitor.warn = lambda msg, slug="", once=False: None

        # Patch the module-level sys_monitoring reference in sysmon.py
        # so set_local_events, use_tool_id, etc. are no-ops during replay
        import coverage.sysmon as sysmon_module

        self._orig_sys_monitoring = sysmon_module.sys_monitoring
        mock_monitoring = MagicMock()
        mock_monitoring.DISABLE = None
        sysmon_module.sys_monitoring = mock_monitoring

    def cleanup(self) -> None:
        """Restore the original sys_monitoring reference."""
        import coverage.sysmon as sysmon_module

        sysmon_module.sys_monitoring = self._orig_sys_monitoring

    def replay(self, events: list[dict[str, Any]]) -> dict[str, set[Any]]:
        """Feed recorded events into SysMonitor's callbacks.

        Args:
            events: List of event dicts from a recording JSON file.

        Returns:
            The monitor's data dict mapping filenames to sets of
            line numbers (line mode) or arcs (arc mode).
        """
        # Only dispatch event types that SysMonitor would actually receive
        # in the current mode. In line-only mode, SysMonitor only registers
        # PY_START (global) and LINE (local). In arc mode, it additionally
        # registers PY_RETURN, and BRANCH_RIGHT/LEFT.
        arc_only_types = {"PY_RETURN", "BRANCH_RIGHT", "BRANCH_LEFT"}

        try:
            for ev in events:
                code = self._resolve_code(ev)
                if code is None:
                    continue

                event_type = ev["type"]

                if not self.trace_arcs and event_type in arc_only_types:
                    continue

                if event_type == "PY_START":
                    self.monitor.sysmon_py_start(code, ev["offset"])
                elif event_type == "LINE":
                    if self.trace_arcs:
                        self.monitor.sysmon_line_arcs(code, ev["line"])
                    else:
                        self.monitor.sysmon_line_lines(code, ev["line"])
                elif event_type == "PY_RETURN":
                    self.monitor.sysmon_py_return(
                        code, ev["offset"], None
                    )
                elif event_type in ("BRANCH_RIGHT", "BRANCH_LEFT"):
                    self.monitor.sysmon_branch_either(
                        code, ev["offset"], ev["dest"]
                    )
                # PY_RESUME events are recorded but SysMonitor doesn't
                # have a callback for them — they're handled by CPython's
                # local event delivery automatically.
        finally:
            self.cleanup()

        return self.monitor.data

    def verify_offsets(self, events: list[dict[str, Any]]) -> bool:
        """Check that recorded offsets match the current Python's bytecodes.

        If bytecodes changed between the recording Python version and
        the current one, the recorded offsets won't be valid.
        """
        valid_offsets: dict[str, set[int]] = {}
        for name, code in self.code_map.items():
            valid_offsets[name] = {
                inst.offset for inst in dis.get_instructions(code)
            }

        for ev in events:
            offset = ev.get("offset")
            if offset is not None and offset != 0:
                code_key = self._code_key(ev)
                if offset not in valid_offsets.get(code_key, set()):
                    return False

            dest = ev.get("dest")
            if dest is not None:
                code_key = self._code_key(ev)
                if dest not in valid_offsets.get(code_key, set()):
                    return False

        return True

    def _build_code_map(self, code: CodeType) -> dict[str, CodeType]:
        """Build a map of (name, firstlineno) -> CodeType for all nested code objects."""
        code_map: dict[str, CodeType] = {}
        stack = [code]
        while stack:
            c = stack.pop()
            key = self._code_key_from_code(c)
            code_map[key] = c
            for const in c.co_consts:
                if isinstance(const, CodeType):
                    stack.append(const)
        return code_map

    def _resolve_code(self, ev: dict[str, Any]) -> CodeType | None:
        """Find the code object matching an event."""
        key = self._code_key(ev)
        return self.code_map.get(key)

    def _code_key(self, ev: dict[str, Any]) -> str:
        """Make a lookup key from an event dict."""
        return f"{ev['code_name']}:{ev['code_firstlineno']}"

    def _code_key_from_code(self, code: CodeType) -> str:
        """Make a lookup key from a code object."""
        return f"{code.co_name}:{code.co_firstlineno}"

    @staticmethod
    def _make_disposition(filename: str) -> FileDisposition:
        """Create a FileDisposition that says 'trace this file'."""
        disp = FileDisposition()
        disp.original_filename = filename
        disp.canonical_filename = filename
        disp.source_filename = filename
        disp.trace = True
        disp.reason = ""
        disp.file_tracer = None
        disp.has_dynamic_filename = False
        return disp
