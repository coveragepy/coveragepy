# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for the sys.monitoring core in coverage/sysmon.py."""

from __future__ import annotations

import sys
from unittest import mock

import pytest

from coverage import Coverage, env
from coverage.collector import Collector
from coverage.files import abs_file
from coverage.sysmon import SysMonitor, compute_multiline_map
from tests.coveragetest import CoverageTest
from tests.testenv import SYS_MON

MULTI_PY = "x = (\n    1 +\n    2\n)\ny = 5\n"
MULTI_MAP = {1: 1, 2: 1, 3: 1, 4: 1}


@pytest.mark.skipif(
    not SYS_MON or not env.PYBEHAVIOR.branch_right_left,
    reason="Requires branch coverage with SysMonitor",
)
class SysMonitorArcsTest(CoverageTest):
    """Tests of arcs recorded by SysMonitor."""

    def test_exception_exit_does_not_link_calls(self) -> None:
        filename = self.make_file(
            "unwind.py",
            """\
            def f(mode):
                if mode == 0:
                    raise ValueError
                if mode == 1:
                    result = 1
                else:
                    result = 2
                return result

            for mode in (0, 1, 2):
                try:
                    f(mode)
                except ValueError:
                    pass
            """,
        )
        cov = Coverage(branch=True)
        unwind = SysMonitor.sysmon_py_unwind
        # Keep metacov running alongside this collector and allow it to trace
        # the unwind callback, where Python normally suppresses tracing.
        with (
            mock.patch.object(Collector, "_collectors", []),
            mock.patch.object(
                SysMonitor,
                "sysmon_py_unwind",
                lambda *args: sys.call_tracing(unwind, args),
            ),
        ):
            self.start_import_stop(cov, "unwind")
        arcs = cov.get_data().arcs(abs_file(filename))
        assert arcs is not None
        assert (2, 3) in arcs
        assert (2, 4) in arcs
        assert (3, 4) not in arcs


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
