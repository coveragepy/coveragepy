# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for the sys.monitoring core in coverage/sysmon.py."""

from __future__ import annotations

from typing import cast
from unittest import mock

import pytest

from coverage import env
from coverage.bytecode import BranchArcResolver
from coverage.sysmon import CodeInfo, SysMonitor, compute_multiline_map
from coverage.types import TArc
from tests.coveragetest import CoverageTest

MULTI_PY = "x = (\n    1 +\n    2\n)\ny = 5\n"
MULTI_MAP = {1: 1, 2: 1, 3: 1, 4: 1}


def pending_arcs_of(ci: CodeInfo) -> list[TArc] | None:
    """Return ci.pending_arcs.

    The callbacks mutate the CodeInfo they find via id(code), which mypy
    can't see; reading through this helper gives the declared type instead
    of a stale narrowed one.

    """
    return ci.pending_arcs


class ComputeMultilineMapTest(CoverageTest):
    """Tests of compute_multiline_map."""

    def test_python_file(self) -> None:
        self.make_file("multi.py", MULTI_PY)
        assert compute_multiline_map("multi.py") == MULTI_MAP

    def test_missing_file(self) -> None:
        # A code object can name a file that doesn't exist on disk.
        assert compute_multiline_map("no_such_file.py") == {}

    def test_non_python_file(self) -> None:
        # A code object can point at non-Python source, as with compiled
        # template files.  Tokenizing fails, and the map is empty.
        self.make_file(
            "widget.html",
            # The unbalanced paren makes this untokenizable as Python.
            "<div class=(widget>\n    {% if widget.name %}\n</div>\n",
        )
        assert compute_multiline_map("widget.html") == {}

    def test_indentation_error(self) -> None:
        self.make_file("bad.py", "def f():\n        pass\n  huh = 3\n")
        assert compute_multiline_map("bad.py") == {}


@pytest.mark.skipif(not env.PYBEHAVIOR.pep669, reason="SysMonitor needs sys.monitoring")
class MultilineMapCacheTest(CoverageTest):
    """Tests of SysMonitor's per-tracer multiline map cache."""

    def test_each_file_computed_at_most_once(self) -> None:
        self.make_file("multi.py", MULTI_PY)
        self.make_file("other.py", "a = [1,\n    2]\n")
        tracer = SysMonitor()
        with mock.patch(
            "coverage.sysmon.compute_multiline_map",
            side_effect=compute_multiline_map,
        ) as computer:
            map1 = tracer.get_multiline_map("multi.py")
            map2 = tracer.get_multiline_map("multi.py")
            other = tracer.get_multiline_map("other.py")
        assert computer.call_count == 2
        assert map1 is map2
        assert map1 == MULTI_MAP
        assert other == {1: 1, 2: 1}

    def test_cache_dies_with_the_tracer(self) -> None:
        # The cache is per-instance: a new tracer re-reads the file, so a
        # source file changed between runs can't serve a stale map, the way
        # a module-level cache could.
        self.make_file("multi.py", MULTI_PY)
        tracer = SysMonitor()
        assert tracer.get_multiline_map("multi.py") == MULTI_MAP
        self.make_file("multi.py", "x = 1\ny = (2 +\n    3)\n")
        assert tracer.get_multiline_map("multi.py") == MULTI_MAP  # cached
        assert SysMonitor().get_multiline_map("multi.py") == {2: 2, 3: 2}


@pytest.mark.skipif(not env.PYBEHAVIOR.pep669, reason="SysMonitor needs sys.monitoring")
class PendingBranchArcTest(CoverageTest):
    """Direct unit tests for deferred branch arcs (issue 2303)."""

    def make_tracer(self) -> SysMonitor:
        """Make a SysMonitor configured for branch arcs."""
        tracer = SysMonitor()
        tracer.trace_arcs = True
        return tracer

    def make_code_info(
        self,
        tracer: SysMonitor,
        code: object,
    ) -> tuple[CodeInfo, set[TArc]]:
        """Make and register a CodeInfo with an arc set for the test."""
        file_data: set[TArc] = set()
        ci = CodeInfo(
            tracing=True,
            file_data=file_data,
            byte_to_line={},
            branch_resolver=None,
        )
        tracer.code_infos[id(code)] = ci
        return ci, file_data

    def test_add_branch_arc_negative_destination_is_immediate(self) -> None:
        tracer = self.make_tracer()
        ci, file_data = self.make_code_info(tracer, object())
        tracer._add_branch_arc(ci, (8, -1))
        assert (8, -1) in file_data
        assert ci.pending_arcs is None

    def test_add_branch_arc_positive_destination_is_deferred(self) -> None:
        tracer = self.make_tracer()
        ci, file_data = self.make_code_info(tracer, object())
        tracer._add_branch_arc(ci, (8, 10))
        assert (8, 10) not in file_data
        assert ci.pending_arcs == [(8, 10)]
        tracer._add_branch_arc(ci, (8, 12))
        assert ci.pending_arcs == [(8, 10), (8, 12)]

    def test_line_arcs_flushes_matching_destination(self) -> None:
        tracer = self.make_tracer()
        code = object()
        ci, file_data = self.make_code_info(tracer, code)
        ci.pending_arcs = [(8, 10), (9, 10), (8, 12)]
        tracer.sysmon_line_arcs(code, 10)
        assert (8, 10) in file_data
        assert (9, 10) in file_data
        assert (8, 12) not in file_data
        assert ci.pending_arcs == [(8, 12)]
        # The line-identity arc is always recorded.
        assert (10, 10) in file_data

    def test_line_arcs_without_pending_is_plain(self) -> None:
        tracer = self.make_tracer()
        code = object()
        ci, file_data = self.make_code_info(tracer, code)
        tracer.sysmon_line_arcs(code, 20)
        assert file_data == {(20, 20)}
        assert ci.pending_arcs is None

    def test_line_arcs_no_match_leaves_pending(self) -> None:
        tracer = self.make_tracer()
        code = object()
        ci, file_data = self.make_code_info(tracer, code)
        ci.pending_arcs = [(8, 10)]
        tracer.sysmon_line_arcs(code, 20)
        assert (8, 10) not in file_data
        assert ci.pending_arcs == [(8, 10)]

    def test_py_return_flushes_all_pending(self) -> None:
        tracer = self.make_tracer()
        code = compile("x = 1", "<t>", "exec")
        ci, file_data = self.make_code_info(tracer, code)
        ci.byte_to_line = {100: 5}
        ci.pending_arcs = [(8, 10), (9, 10)]
        tracer.sysmon_py_return(code, 100, retval=None)
        assert (8, 10) in file_data
        assert (9, 10) in file_data
        assert pending_arcs_of(ci) is None
        # The frame-exit arc is still recorded.
        assert (5, -code.co_firstlineno) in file_data

    def test_py_return_without_pending_only_records_exit_arc(self) -> None:
        tracer = self.make_tracer()
        code = compile("x = 1", "<t>", "exec")
        ci, file_data = self.make_code_info(tracer, code)
        ci.byte_to_line = {100: 7}
        tracer.sysmon_py_return(code, 100, retval=None)
        assert (7, -code.co_firstlineno) in file_data
        assert ci.pending_arcs is None

    def test_py_unwind_discards_pending(self) -> None:
        tracer = self.make_tracer()
        code = object()
        ci, file_data = self.make_code_info(tracer, code)
        ci.pending_arcs = [(8, 10)]
        tracer.sysmon_py_unwind(code, 0, ValueError("boom"))
        assert pending_arcs_of(ci) is None
        assert (8, 10) not in file_data

    def test_py_unwind_unknown_code_is_noop(self) -> None:
        tracer = self.make_tracer()
        tracer.sysmon_py_unwind(object(), 0, ValueError("boom"))

    def test_start_registers_py_unwind_globally(self) -> None:
        import sys

        tracer = self.make_tracer()
        with mock.patch("coverage.sysmon.sys_monitoring") as sm:
            sm.COVERAGE_ID = 5
            tracer.start()
        # PY_UNWIND must be a global event: it can't be set per-code.
        py_unwind = sys.monitoring.events.PY_UNWIND
        _, global_events = sm.set_events.call_args.args
        assert global_events & py_unwind
        registered = [c.args[1] for c in sm.register_callback.call_args_list]
        assert py_unwind in registered

    def test_branch_either_adds_resolved_arc(self) -> None:
        tracer = self.make_tracer()
        code = object()
        ci, file_data = self.make_code_info(tracer, code)
        resolver = mock.Mock()
        resolver.resolve.return_value = (8, 10)
        ci.branch_resolver = cast(BranchArcResolver, resolver)
        tracer.sysmon_branch_either(code, 100, 200)
        assert ci.pending_arcs == [(8, 10)]
        assert (8, 10) not in file_data

    def test_branch_either_fallback_unforeseen_arc(self) -> None:
        tracer = self.make_tracer()
        code = object()
        ci, file_data = self.make_code_info(tracer, code)
        resolver = mock.Mock()
        resolver.resolve.return_value = None
        ci.branch_resolver = cast(BranchArcResolver, resolver)
        ci.byte_to_line = {100: 8, 200: 10}
        tracer.sysmon_branch_either(code, 100, 200)
        assert ci.pending_arcs == [(8, 10)]
        assert (8, 10) not in file_data
