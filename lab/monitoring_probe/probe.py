"""MonitoringProbe: record sys.monitoring events from CPython."""

from __future__ import annotations

import dis
import functools
import sys
import textwrap
from dataclasses import dataclass, field
from types import CodeType


@dataclass
class MonitoringEvent:
    """One event recorded from sys.monitoring."""

    event_type: str
    code_name: str
    code_filename: str
    code_firstlineno: int
    instruction_offset: int
    line_number: int | None = None
    destination_offset: int | None = None


@dataclass
class MonitoringRecording:
    """Complete recording of monitoring events for a code execution."""

    python_version: tuple[int, ...]
    source_code: str
    filename: str
    events: list[MonitoringEvent] = field(default_factory=list)
    code_objects: dict[int, CodeType] = field(default_factory=dict)

    # Ground truth derived from raw events
    lines_executed: set[int] = field(default_factory=set)
    arcs_executed: set[tuple[int, int]] = field(default_factory=set)

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict (no code objects)."""
        return {
            "python_version": list(self.python_version),
            "source_code": self.source_code,
            "filename": self.filename,
            "events": [
                {
                    "type": ev.event_type,
                    "code_name": ev.code_name,
                    "code_filename": ev.code_filename,
                    "code_firstlineno": ev.code_firstlineno,
                    "offset": ev.instruction_offset,
                    "line": ev.line_number,
                    "dest": ev.destination_offset,
                }
                for ev in self.events
            ],
            "expected_lines": sorted(self.lines_executed),
            "expected_arcs": sorted(self.arcs_executed),
        }

    @classmethod
    def from_dict(cls, data: dict) -> MonitoringRecording:
        """Deserialize from a JSON-compatible dict."""
        rec = cls(
            python_version=tuple(data["python_version"]),
            source_code=data["source_code"],
            filename=data["filename"],
            lines_executed=set(data["expected_lines"]),
            arcs_executed={tuple(a) for a in data["expected_arcs"]},
        )
        rec.events = [
            MonitoringEvent(
                event_type=ev["type"],
                code_name=ev["code_name"],
                code_filename=ev["code_filename"],
                code_firstlineno=ev["code_firstlineno"],
                instruction_offset=ev["offset"],
                line_number=ev.get("line"),
                destination_offset=ev.get("dest"),
            )
            for ev in data["events"]
        ]
        return rec


def bytes_to_lines(code: CodeType) -> dict[int, int]:
    """Map bytecode offsets to line numbers."""
    b2l = {}
    for bstart, bend, lineno in code.co_lines():
        if lineno is not None:
            for boffset in range(bstart, bend, 2):
                b2l[boffset] = lineno
    return b2l


def resolve_branch_line(
    b2l: dict[int, int],
    from_offset: int,
    dest_offset: int,
) -> int | None:
    """Resolve the effective destination line for a branch event.

    When a branch destination offset maps to the same line as the source,
    walk forward through subsequent offsets to find the next distinct line.
    This mirrors what SysMonitor's branch_trails does via bytecode analysis.

    We limit the forward walk to a small window to avoid walking past
    the logical scope of the branch (e.g., past a loop exit into unrelated
    code). SysMonitor uses the full branch_trails analysis with jump
    following; this is a lightweight approximation.
    """
    from_line = b2l.get(from_offset)
    to_line = b2l.get(dest_offset)
    if from_line is None or to_line is None:
        return to_line
    if from_line != to_line:
        return to_line
    # Same line — walk forward to find the next different line.
    # Limit the walk: only check offsets in a reasonable range.
    # Beyond ~20 instructions (40 bytes) we're likely past the scope.
    max_offset = dest_offset + 40
    is_backward = dest_offset < from_offset
    sorted_offsets = sorted(o for o in b2l if dest_offset < o <= max_offset)
    for next_offset in sorted_offsets:
        next_line = b2l[next_offset]
        if next_line != from_line:
            if is_backward:
                # Backward branches (loop back-edges) can go to earlier lines
                return next_line
            elif next_line > from_line:
                # Forward branches should only resolve to later lines
                return next_line
    return None


def walk_code_objects(code: CodeType) -> list[CodeType]:
    """Collect all code objects nested within `code`, including itself."""
    result = []
    stack = [code]
    while stack:
        c = stack.pop()
        result.append(c)
        for const in c.co_consts:
            if isinstance(const, CodeType):
                stack.append(const)
    return result


class MonitoringProbe:
    """Record all sys.monitoring events fired during execution of a snippet.

    Uses its own tool_id (default 2) so it doesn't conflict with coverage.py
    (which uses 1 or 3).
    """

    def __init__(self, tool_id: int = 2) -> None:
        if not hasattr(sys, "monitoring"):
            raise RuntimeError(
                "sys.monitoring not available (requires Python 3.12+)"
            )
        self.tool_id = tool_id
        self._monitoring = sys.monitoring
        self._events_cls = sys.monitoring.events

        # Available event types depend on Python version
        self._has_branch_right_left = hasattr(self._events_cls, "BRANCH_RIGHT")

    def record(
        self,
        source: str,
        filename: str = "probe_target.py",
    ) -> MonitoringRecording:
        """Execute source under monitoring and record all events.

        Args:
            source: Python source code to execute.
            filename: Filename to use when compiling the source.

        Returns:
            A MonitoringRecording with all events and derived ground truth.
        """
        source = textwrap.dedent(source)
        code = compile(source, filename, "exec")

        recording = MonitoringRecording(
            python_version=sys.version_info[:5],
            source_code=source,
            filename=filename,
        )

        # Keep references to all code objects to prevent GC (preserves id() stability)
        all_code_objects = walk_code_objects(code)
        for c in all_code_objects:
            recording.code_objects[id(c)] = c

        # Pre-compute bytes-to-lines for all code objects
        b2l_maps: dict[int, dict[int, int]] = {}
        for c in all_code_objects:
            b2l_maps[id(c)] = bytes_to_lines(c)

        # Build callbacks that capture events
        def _make_event(
            event_type: str,
            code: CodeType,
            instruction_offset: int,
            line_number: int | None = None,
            destination_offset: int | None = None,
        ) -> MonitoringEvent | None:
            if code.co_filename != filename:
                return None
            # Track any new code objects we encounter
            cid = id(code)
            if cid not in recording.code_objects:
                recording.code_objects[cid] = code
                b2l_maps[cid] = bytes_to_lines(code)
            return MonitoringEvent(
                event_type=event_type,
                code_name=code.co_name,
                code_filename=code.co_filename,
                code_firstlineno=code.co_firstlineno,
                instruction_offset=instruction_offset,
                line_number=line_number,
                destination_offset=destination_offset,
            )

        local_events = (
            self._events_cls.PY_RETURN
            | self._events_cls.PY_RESUME
            | self._events_cls.LINE
        )
        if self._has_branch_right_left:
            local_events |= (
                self._events_cls.BRANCH_RIGHT | self._events_cls.BRANCH_LEFT
            )

        def on_py_start(code: CodeType, instruction_offset: int) -> None:
            ev = _make_event("PY_START", code, instruction_offset)
            if ev is not None:
                recording.events.append(ev)
                # Enable all local events on this code object
                self._monitoring.set_local_events(
                    self.tool_id, code, local_events
                )

        def on_py_resume(code: CodeType, instruction_offset: int) -> None:
            ev = _make_event("PY_RESUME", code, instruction_offset)
            if ev is not None:
                recording.events.append(ev)

        def on_py_return(
            code: CodeType, instruction_offset: int, retval: object
        ) -> None:
            ev = _make_event("PY_RETURN", code, instruction_offset)
            if ev is not None:
                recording.events.append(ev)

        def on_line(code: CodeType, line_number: int) -> None:
            ev = _make_event(
                "LINE", code, instruction_offset=0, line_number=line_number
            )
            if ev is not None:
                recording.events.append(ev)

        def on_branch_right(
            code: CodeType,
            instruction_offset: int,
            destination_offset: int,
        ) -> None:
            ev = _make_event(
                "BRANCH_RIGHT",
                code,
                instruction_offset,
                destination_offset=destination_offset,
            )
            if ev is not None:
                recording.events.append(ev)

        def on_branch_left(
            code: CodeType,
            instruction_offset: int,
            destination_offset: int,
        ) -> None:
            ev = _make_event(
                "BRANCH_LEFT",
                code,
                instruction_offset,
                destination_offset=destination_offset,
            )
            if ev is not None:
                recording.events.append(ev)

        # Register callbacks
        self._monitoring.use_tool_id(self.tool_id, "monitoring-probe")
        register = functools.partial(
            self._monitoring.register_callback, self.tool_id
        )
        try:
            self._monitoring.set_events(
                self.tool_id, self._events_cls.PY_START
            )
            register(self._events_cls.PY_START, on_py_start)
            register(self._events_cls.PY_RESUME, on_py_resume)
            register(self._events_cls.PY_RETURN, on_py_return)
            register(self._events_cls.LINE, on_line)
            if self._has_branch_right_left:
                register(self._events_cls.BRANCH_RIGHT, on_branch_right)
                register(self._events_cls.BRANCH_LEFT, on_branch_left)
            self._monitoring.restart_events()

            # Execute the code
            exec(code, {"__name__": "__main__"})  # noqa: S102
        finally:
            self._monitoring.set_events(self.tool_id, 0)
            self._monitoring.free_tool_id(self.tool_id)

        # Derive ground truth from recorded events
        self._derive_ground_truth(recording, b2l_maps)

        # Cross-validate against coverage.py if available.
        # The probe's arc ground truth is approximate — it uses a
        # lightweight forward-walk that can miss arcs produced by
        # SysMonitor's branch_trails bytecode analysis (e.g., loop
        # back-edges in for/else constructs). When coverage.py is
        # importable, we run the same source under it and adopt its
        # arc results as the authoritative ground truth.
        self._cross_validate(recording, source, filename)
        return recording

    def _cross_validate(
        self,
        recording: MonitoringRecording,
        source: str,
        filename: str,
    ) -> None:
        """Adjust ground truth using coverage.py if available."""
        try:
            import coverage  # type: ignore[import-untyped]
        except ImportError:
            return

        cov = coverage.Coverage(branch=True, source=["."])
        cov.start()
        try:
            exec(  # noqa: S102
                compile(source, filename, "exec"),
                {"__name__": "__main__"},
            )
        finally:
            cov.stop()

        data = cov.get_data()
        for measured_file in data.measured_files():
            if filename in measured_file:
                cov_lines = data.lines(measured_file)
                cov_arcs = data.arcs(measured_file)
                if cov_lines is not None:
                    recording.lines_executed = set(cov_lines)
                if cov_arcs is not None:
                    recording.arcs_executed = set(cov_arcs)
                break

    def _derive_ground_truth(
        self,
        recording: MonitoringRecording,
        b2l_maps: dict[int, dict[int, int]],
    ) -> None:
        """Compute lines_executed and arcs_executed from raw events.

        This produces TWO views of the data:

        lines_executed: set of line numbers from LINE events.

        arcs_executed: arcs in the same format SysMonitor stores them:
          - LINE events → self-arc (line, line)
          - BRANCH events → (from_line, to_line) via bytes_to_lines
          - PY_RETURN events → (return_line, -firstlineno) exit arc

        This matches what SysMonitor.data should contain after processing
        the same event sequence, making replay comparison straightforward.
        """
        for ev in recording.events:
            if ev.event_type == "LINE" and ev.line_number is not None:
                recording.lines_executed.add(ev.line_number)
                # SysMonitor's sysmon_line_arcs records (line, line) self-arcs
                recording.arcs_executed.add((ev.line_number, ev.line_number))

            elif ev.event_type == "PY_RETURN":
                code_id = self._find_code_id(
                    recording, ev.code_name, ev.code_firstlineno
                )
                b2l = b2l_maps.get(code_id, {})
                ret_line = b2l.get(ev.instruction_offset)
                if ret_line is not None:
                    code = recording.code_objects.get(code_id)
                    if code is not None:
                        # SysMonitor's sysmon_py_return records exit arcs
                        recording.arcs_executed.add(
                            (ret_line, -code.co_firstlineno)
                        )

            elif ev.event_type in ("BRANCH_RIGHT", "BRANCH_LEFT"):
                code_id = self._find_code_id(
                    recording, ev.code_name, ev.code_firstlineno
                )
                b2l = b2l_maps.get(code_id, {})
                from_line = b2l.get(ev.instruction_offset)
                if from_line is not None and ev.destination_offset is not None:
                    to_line = resolve_branch_line(
                        b2l, ev.instruction_offset, ev.destination_offset
                    )
                    if to_line is not None:
                        # SysMonitor's sysmon_branch_either records branch arcs
                        recording.arcs_executed.add((from_line, to_line))

    def _find_code_id(
        self,
        recording: MonitoringRecording,
        code_name: str,
        firstlineno: int,
    ) -> int:
        """Find the id of a code object by name and firstlineno."""
        for cid, code in recording.code_objects.items():
            if code.co_name == code_name and code.co_firstlineno == firstlineno:
                return cid
        return 0


def format_recording(recording: MonitoringRecording) -> str:
    """Format a recording for human-readable display."""
    lines = []
    lines.append(f"Recording: {recording.filename}")
    lines.append(f"Python: {'.'.join(str(v) for v in recording.python_version[:3])}")
    lines.append(f"Events: {len(recording.events)}")
    lines.append("")

    # Show source with line numbers
    lines.append("Source:")
    for i, src_line in enumerate(recording.source_code.splitlines(), 1):
        marker = "*" if i in recording.lines_executed else " "
        lines.append(f"  {marker} {i:3d} | {src_line}")
    lines.append("")

    # Show events
    lines.append("Events:")
    for ev in recording.events:
        parts = [f"  {ev.event_type:<14s}"]
        parts.append(f"code={ev.code_name}")
        if ev.line_number is not None:
            parts.append(f"line={ev.line_number}")
        parts.append(f"offset={ev.instruction_offset}")
        if ev.destination_offset is not None:
            parts.append(f"dest={ev.destination_offset}")
        lines.append(" ".join(parts))
    lines.append("")

    # Show ground truth
    lines.append(f"Lines executed: {sorted(recording.lines_executed)}")
    lines.append(f"Arcs executed:  {sorted(recording.arcs_executed)}")

    return "\n".join(lines)
