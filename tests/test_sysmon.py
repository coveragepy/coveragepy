# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for the sys.monitoring core in coverage/sysmon.py."""

from __future__ import annotations

from unittest import mock

import pytest

from coverage import env
from coverage.sysmon import SysMonitor, compute_multiline_map

from tests.coveragetest import CoverageTest

MULTI_PY = "x = (\n    1 +\n    2\n)\ny = 5\n"
MULTI_MAP = {1: 1, 2: 1, 3: 1, 4: 1}


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
