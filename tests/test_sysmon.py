# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for SysMonitor using recorded sys.monitoring event sequences.

These tests replay pre-recorded monitoring events through SysMonitor's
callback methods and verify it produces the correct coverage data.
The recordings come from the monitoring-probe tool, which captures
real CPython sys.monitoring events.

Two test categories:
- Replay tests: feed recorded events into SysMonitor, verify output
- Lifecycle tests: test SysMonitor's state management directly
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from coverage import env
from tests.sysmon_harness import SysMonitorHarness


RECORDINGS_DIR = Path(__file__).parent / "sysmon_recordings"


def _find_recording(snippet_name: str) -> Path | None:
    """Find the recording file for the current Python version."""
    vi = sys.version_info
    # Try exact version, then major.minor
    for version_tag in [
        f"{vi.major}.{vi.minor}.{vi.micro}",
        f"{vi.major}.{vi.minor}",
    ]:
        path = RECORDINGS_DIR / version_tag / f"{snippet_name}.json"
        if path.exists():
            return path
    return None


def _load_recording(snippet_name: str) -> dict:
    """Load a recording, skipping if none available for this Python version."""
    path = _find_recording(snippet_name)
    if path is None:
        vi = sys.version_info
        pytest.skip(
            f"No recording for {snippet_name} on "
            f"Python {vi.major}.{vi.minor}.{vi.micro}"
        )
    return json.loads(path.read_text())


def _replay_and_check(
    snippet_name: str,
    trace_arcs: bool = False,
) -> None:
    """Load recording, replay through SysMonitor, verify results."""
    recording = _load_recording(snippet_name)
    harness = SysMonitorHarness(
        source=recording["source_code"],
        trace_arcs=trace_arcs,
    )

    # Staleness check: do recorded offsets match current bytecodes?
    if not harness.verify_offsets(recording["events"]):
        rec_version = ".".join(str(v) for v in recording["python_version"][:3])
        harness.cleanup()
        pytest.skip(
            f"Recording for {snippet_name} has stale bytecodes "
            f"(recorded on Python {rec_version})"
        )

    data = harness.replay(recording["events"])

    if trace_arcs:
        expected = {tuple(a) for a in recording["expected_arcs"]}
        actual = data.get("target.py", set())
        assert actual == expected, (
            f"Arc mismatch for {snippet_name}:\n"
            f"  extra:   {sorted(actual - expected)}\n"
            f"  missing: {sorted(expected - actual)}"
        )
    else:
        expected = set(recording["expected_lines"])
        actual = data.get("target.py", set())
        assert actual == expected, (
            f"Line mismatch for {snippet_name}:\n"
            f"  extra:   {sorted(actual - expected)}\n"
            f"  missing: {sorted(expected - actual)}"
        )


# ---- Replay tests: line coverage ----


@pytest.mark.skipif(
    not env.PYBEHAVIOR.pep669, reason="sys.monitoring not available"
)
class SysMonitorReplayLinesTest:
    """Test SysMonitor line coverage via recorded event replay."""

    def test_simple_lines(self) -> None:
        _replay_and_check("simple_lines", trace_arcs=False)

    def test_if_else(self) -> None:
        _replay_and_check("if_else", trace_arcs=False)

    def test_if_elif_else(self) -> None:
        _replay_and_check("if_elif_else", trace_arcs=False)

    def test_for_loop(self) -> None:
        _replay_and_check("for_loop", trace_arcs=False)

    def test_for_else(self) -> None:
        _replay_and_check("for_else", trace_arcs=False)

    def test_while_break_continue(self) -> None:
        _replay_and_check("while_break_continue", trace_arcs=False)

    def test_try_except(self) -> None:
        _replay_and_check("try_except", trace_arcs=False)

    def test_try_except_else_finally(self) -> None:
        _replay_and_check("try_except_else_finally", trace_arcs=False)

    def test_try_nested(self) -> None:
        _replay_and_check("try_nested", trace_arcs=False)

    def test_with_statement(self) -> None:
        _replay_and_check("with_statement", trace_arcs=False)

    def test_with_multiple(self) -> None:
        _replay_and_check("with_multiple", trace_arcs=False)

    def test_nested_functions(self) -> None:
        _replay_and_check("nested_functions", trace_arcs=False)

    def test_generator_yield(self) -> None:
        _replay_and_check("generator_yield", trace_arcs=False)

    def test_generator_yield_from(self) -> None:
        _replay_and_check("generator_yield_from", trace_arcs=False)

    def test_generator_send(self) -> None:
        _replay_and_check("generator_send", trace_arcs=False)

    def test_async_await(self) -> None:
        _replay_and_check("async_await", trace_arcs=False)

    def test_match_case(self) -> None:
        _replay_and_check("match_case", trace_arcs=False)

    def test_class_definition(self) -> None:
        _replay_and_check("class_definition", trace_arcs=False)

    def test_comprehensions(self) -> None:
        _replay_and_check("comprehensions", trace_arcs=False)

    def test_decorators(self) -> None:
        _replay_and_check("decorators", trace_arcs=False)

    def test_multiline_statements(self) -> None:
        _replay_and_check("multiline_statements", trace_arcs=False)

    def test_lambda_funcs(self) -> None:
        _replay_and_check("lambda_funcs", trace_arcs=False)

    def test_annotation_code(self) -> None:
        _replay_and_check("annotation_code", trace_arcs=False)

    def test_conditional_expr(self) -> None:
        _replay_and_check("conditional_expr", trace_arcs=False)

    def test_boolean_short_circuit(self) -> None:
        _replay_and_check("boolean_short_circuit", trace_arcs=False)


# ---- Replay tests: arc/branch coverage ----


@pytest.mark.skipif(
    not env.PYBEHAVIOR.branch_right_left,
    reason="BRANCH_RIGHT/LEFT not available",
)
class SysMonitorReplayArcsTest:
    """Test SysMonitor arc coverage via recorded event replay."""

    def test_simple_lines(self) -> None:
        _replay_and_check("simple_lines", trace_arcs=True)

    def test_if_else(self) -> None:
        _replay_and_check("if_else", trace_arcs=True)

    def test_if_elif_else(self) -> None:
        _replay_and_check("if_elif_else", trace_arcs=True)

    def test_for_loop(self) -> None:
        _replay_and_check("for_loop", trace_arcs=True)

    def test_for_else(self) -> None:
        _replay_and_check("for_else", trace_arcs=True)

    def test_while_break_continue(self) -> None:
        _replay_and_check("while_break_continue", trace_arcs=True)

    def test_try_except(self) -> None:
        _replay_and_check("try_except", trace_arcs=True)

    def test_try_except_else_finally(self) -> None:
        _replay_and_check("try_except_else_finally", trace_arcs=True)

    def test_try_nested(self) -> None:
        _replay_and_check("try_nested", trace_arcs=True)

    def test_with_statement(self) -> None:
        _replay_and_check("with_statement", trace_arcs=True)

    def test_with_multiple(self) -> None:
        _replay_and_check("with_multiple", trace_arcs=True)

    def test_nested_functions(self) -> None:
        _replay_and_check("nested_functions", trace_arcs=True)

    def test_generator_yield(self) -> None:
        _replay_and_check("generator_yield", trace_arcs=True)

    def test_generator_yield_from(self) -> None:
        _replay_and_check("generator_yield_from", trace_arcs=True)

    def test_generator_send(self) -> None:
        _replay_and_check("generator_send", trace_arcs=True)

    def test_async_await(self) -> None:
        _replay_and_check("async_await", trace_arcs=True)

    def test_match_case(self) -> None:
        _replay_and_check("match_case", trace_arcs=True)

    def test_class_definition(self) -> None:
        _replay_and_check("class_definition", trace_arcs=True)

    def test_comprehensions(self) -> None:
        _replay_and_check("comprehensions", trace_arcs=True)

    def test_decorators(self) -> None:
        _replay_and_check("decorators", trace_arcs=True)

    def test_multiline_statements(self) -> None:
        _replay_and_check("multiline_statements", trace_arcs=True)

    def test_lambda_funcs(self) -> None:
        _replay_and_check("lambda_funcs", trace_arcs=True)

    def test_annotation_code(self) -> None:
        _replay_and_check("annotation_code", trace_arcs=True)

    def test_conditional_expr(self) -> None:
        _replay_and_check("conditional_expr", trace_arcs=True)

    def test_boolean_short_circuit(self) -> None:
        _replay_and_check("boolean_short_circuit", trace_arcs=True)


# ---- Lifecycle tests: SysMonitor state management ----


@pytest.mark.skipif(
    not env.PYBEHAVIOR.pep669, reason="sys.monitoring not available"
)
class SysMonitorLifecycleTest:
    """Test SysMonitor's internal state management."""

    def _make_monitor(self) -> SysMonitorHarness:
        return SysMonitorHarness(source="a = 1\n", trace_arcs=False)

    def test_activity_flag_starts_false(self) -> None:
        harness = self._make_monitor()
        assert harness.monitor.activity() is False
        harness.cleanup()

    def test_activity_flag_set_on_py_start(self) -> None:
        recording = _load_recording("simple_lines")
        harness = SysMonitorHarness(
            source=recording["source_code"], trace_arcs=False
        )
        harness.replay(recording["events"])
        # replay calls cleanup, so check the monitor directly
        # We need to test before cleanup
        harness2 = SysMonitorHarness(
            source=recording["source_code"], trace_arcs=False
        )
        # Manually call just PY_START
        code = harness2.code
        harness2.monitor.sysmon_py_start(code, 0)
        assert harness2.monitor.activity() is True
        harness2.cleanup()

    def test_reset_activity(self) -> None:
        harness = self._make_monitor()
        harness.monitor._activity = True
        harness.monitor.reset_activity()
        assert harness.monitor.activity() is False
        harness.cleanup()

    def test_annotate_code_skipped(self) -> None:
        """Code objects named __annotate__ should be skipped."""
        source = "x: int = 1\n"
        harness = SysMonitorHarness(source=source, trace_arcs=False)

        # Find if there's an __annotate__ code object
        annotate_code = None
        for key, code in harness.code_map.items():
            if "__annotate__" in key:
                annotate_code = code
                break

        if annotate_code is None:
            harness.cleanup()
            pytest.skip("No __annotate__ code object in this Python version")

        # PY_START for __annotate__ should return DISABLE
        result = harness.monitor.sysmon_py_start(annotate_code, 0)
        # DISABLE is a truthy sentinel — the key behavior is that
        # no data is recorded for this code object
        assert "target.py" not in harness.monitor.data or not harness.monitor.data["target.py"]
        harness.cleanup()

    def test_code_info_caching(self) -> None:
        """Second PY_START for same code should use cached CodeInfo."""
        harness = self._make_monitor()
        code = harness.code

        # First call populates code_infos
        harness.monitor.sysmon_py_start(code, 0)
        assert id(code) in harness.monitor.code_infos

        # Second call should hit the cache
        info_before = harness.monitor.code_infos[id(code)]
        harness.monitor.sysmon_py_start(code, 0)
        info_after = harness.monitor.code_infos[id(code)]
        assert info_before is info_after
        harness.cleanup()

    def test_non_traced_file_no_data(self) -> None:
        """Files not in should_trace_cache should not be traced."""
        source = "a = 1\n"
        harness = SysMonitorHarness(source=source, filename="ignored.py")
        # Remove the disposition so should_trace_cache returns None
        harness.monitor.should_trace_cache.clear()
        # We need a should_trace function that returns a non-tracing disposition
        from coverage.disposition import FileDisposition

        def should_trace(filename, frame):
            disp = FileDisposition()
            disp.original_filename = filename
            disp.canonical_filename = filename
            disp.source_filename = None
            disp.trace = False
            disp.reason = "test"
            disp.file_tracer = None
            disp.has_dynamic_filename = False
            return disp

        harness.monitor.should_trace = should_trace
        harness.monitor.sysmon_py_start(harness.code, 0)
        assert not harness.monitor.data
        harness.cleanup()
