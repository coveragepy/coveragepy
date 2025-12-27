# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.data, and coverage.sqldata."""

from __future__ import annotations

import glob
import os
import os.path
import re
import sqlite3
import threading

from collections.abc import Callable, Collection, Iterable, Mapping
from typing import Any, TypeVar
from unittest import mock

import pytest

from coverage.data import CoverageData, DataFileClassifier, combine_parallel_data
from coverage.data import add_data_to_hash, line_counts
from coverage.exceptions import DataError, NoDataError
from coverage.files import PathAliases, canonical_filename
from coverage.types import FilePathClasses, FilePathType, TArc, TLineNo

from tests.coveragetest import CoverageTest
from tests.helpers import DebugControlString, assert_count_equal


LINES_1 = {
    "a.py": {1, 2},
    "b.py": {3},
}
SUMMARY_1 = {"a.py": 2, "b.py": 1}
MEASURED_FILES_1 = ["a.py", "b.py"]
A_PY_LINES_1 = [1, 2]
B_PY_LINES_1 = [3]

LINES_2 = {
    "a.py": {1, 5},
    "c.py": {17},
}
SUMMARY_1_2 = {"a.py": 3, "b.py": 1, "c.py": 1}
MEASURED_FILES_1_2 = ["a.py", "b.py", "c.py"]

ARCS_3 = {
    "x.py": {(-1, 1), (1, 2), (2, 3), (3, -1)},
    "y.py": {(-1, 17), (17, 23), (23, -1)},
}
X_PY_ARCS_3 = [(-1, 1), (1, 2), (2, 3), (3, -1)]
Y_PY_ARCS_3 = [(-1, 17), (17, 23), (23, -1)]
SUMMARY_3 = {"x.py": 3, "y.py": 2}
MEASURED_FILES_3 = ["x.py", "y.py"]
X_PY_LINES_3 = [1, 2, 3]
Y_PY_LINES_3 = [17, 23]

ARCS_4 = {
    "x.py": {(-1, 2), (2, 5), (5, -1)},
    "z.py": {(-1, 1000), (1000, -1)},
}
SUMMARY_3_4 = {"x.py": 4, "y.py": 2, "z.py": 1}
MEASURED_FILES_3_4 = ["x.py", "y.py", "z.py"]


def DebugCoverageData(*args: Any, **kwargs: Any) -> CoverageData:
    """Factory for CovergeData instances with debugging turned on.

    This lets us exercise the debugging lines in sqldata.py.  We don't make
    any assertions about the debug output, but at least we can know that they
    execute successfully, and they won't be marked as distracting missing
    lines in our coverage reports.

    In the tests in this file, we usually use DebugCoverageData, but sometimes
    a plain CoverageData, and some tests are parameterized to run once with each
    so that we have a mix of debugging or not.
    """
    assert "debug" not in kwargs
    options = ["dataio", "dataop", "sql"]
    if kwargs:
        # There's no logical reason kwargs should imply sqldata debugging.
        # This is just a way to get a mix of debug options across the tests.
        options.extend(["dataop2", "sqldata"])
    debug = DebugControlString(options=options)
    return CoverageData(*args, debug=debug, **kwargs)  # type: ignore[misc]


TCoverageData = Callable[..., CoverageData]


def assert_line_counts(
    covdata: CoverageData,
    counts: Mapping[str, int],
    fullpath: bool = False,
) -> None:
    """Check that the line_counts of `covdata` is `counts`."""
    assert line_counts(covdata, fullpath) == counts


def assert_measured_files(covdata: CoverageData, measured: Iterable[str]) -> None:
    """Check that `covdata`'s measured files are `measured`."""
    assert_count_equal(covdata.measured_files(), measured)


def assert_lines1_data(covdata: CoverageData) -> None:
    """Check that `covdata` has the data from LINES1."""
    assert_line_counts(covdata, SUMMARY_1)
    assert_measured_files(covdata, MEASURED_FILES_1)
    assert_count_equal(covdata.lines("a.py"), A_PY_LINES_1)
    assert not covdata.has_arcs()


def assert_arcs3_data(covdata: CoverageData) -> None:
    """Check that `covdata` has the data from ARCS3."""
    assert_line_counts(covdata, SUMMARY_3)
    assert_measured_files(covdata, MEASURED_FILES_3)
    assert_count_equal(covdata.lines("x.py"), X_PY_LINES_3)
    assert_count_equal(covdata.arcs("x.py"), X_PY_ARCS_3)
    assert_count_equal(covdata.lines("y.py"), Y_PY_LINES_3)
    assert_count_equal(covdata.arcs("y.py"), Y_PY_ARCS_3)
    assert covdata.has_arcs()


TData = TypeVar("TData", bound=TLineNo | TArc)


def dicts_from_sets(file_data: dict[str, set[TData]]) -> dict[str, dict[TData, None]]:
    """Convert a dict of sets into a dict of dicts.

    Before 6.0, file data was a dict with None as the values.  In 6.0, file
    data is a set.  SqlData all along only cared that it was an iterable.
    This function helps us test that the old dict format still works.
    """
    return {k: dict.fromkeys(v) for k, v in file_data.items()}


class CoverageDataTest(CoverageTest):
    """Test cases for CoverageData."""

    def test_empty_data_is_false(self) -> None:
        covdata = DebugCoverageData()
        assert not covdata
        self.assert_doesnt_exist(".coverage")

    def test_empty_data_is_false_when_read(self) -> None:
        covdata = DebugCoverageData()
        covdata.read()
        assert not covdata
        self.assert_doesnt_exist(".coverage")

    def test_line_data_is_true(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        assert covdata

    def test_arc_data_is_true(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        assert covdata

    def test_empty_line_data_is_false(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines({})
        assert not covdata

    def test_empty_arc_data_is_false(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs({})
        assert not covdata

    @pytest.mark.parametrize("lines", [LINES_1, dicts_from_sets(LINES_1)])
    def test_adding_lines(self, lines: Mapping[str, Collection[TLineNo]]) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(lines)
        assert_lines1_data(covdata)

    @pytest.mark.parametrize("arcs", [ARCS_3, dicts_from_sets(ARCS_3)])
    def test_adding_arcs(self, arcs: Mapping[str, Collection[TArc]]) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(arcs)
        assert_arcs3_data(covdata)

    def test_ok_to_add_lines_twice(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        covdata.add_lines(LINES_2)
        assert_line_counts(covdata, SUMMARY_1_2)
        assert_measured_files(covdata, MEASURED_FILES_1_2)

    def test_ok_to_add_arcs_twice(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.add_arcs(ARCS_4)
        assert_line_counts(covdata, SUMMARY_3_4)
        assert_measured_files(covdata, MEASURED_FILES_3_4)

    def test_ok_to_add_empty_arcs(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.add_arcs(ARCS_4)
        covdata.add_arcs(dict.fromkeys(ARCS_3, set()))
        assert_line_counts(covdata, SUMMARY_3_4)
        assert_measured_files(covdata, MEASURED_FILES_3_4)

    @pytest.mark.parametrize("klass", [CoverageData, DebugCoverageData])
    def test_cant_add_arcs_with_lines(self, klass: TCoverageData) -> None:
        covdata = klass()
        covdata.add_lines(LINES_1)
        msg = "Can't add branch measurements to existing line data"
        with pytest.raises(DataError, match=msg):
            covdata.add_arcs(ARCS_3)

    @pytest.mark.parametrize("klass", [CoverageData, DebugCoverageData])
    def test_cant_add_lines_with_arcs(self, klass: TCoverageData) -> None:
        covdata = klass()
        covdata.add_arcs(ARCS_3)
        msg = "Can't add line measurements to existing branch data"
        with pytest.raises(DataError, match=msg):
            covdata.add_lines(LINES_1)

    def test_touch_file_with_lines(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        covdata.touch_file("zzz.py")
        assert_measured_files(covdata, MEASURED_FILES_1 + ["zzz.py"])

    def test_touch_file_with_arcs(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.touch_file("zzz.py")
        assert_measured_files(covdata, MEASURED_FILES_3 + ["zzz.py"])

    def test_set_query_contexts(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_a")
        covdata.add_lines(LINES_1)
        covdata.set_query_contexts(["te.*a"])
        assert covdata.lines("a.py") == [1, 2]
        covdata.set_query_contexts(["other"])
        assert covdata.lines("a.py") == []

    def test_no_lines_vs_unmeasured_file(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        covdata.touch_file("zzz.py")
        assert covdata.lines("zzz.py") == []
        assert covdata.lines("no_such_file.py") is None

    def test_lines_with_contexts(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_a")
        covdata.add_lines(LINES_1)
        assert covdata.lines("a.py") == [1, 2]
        covdata.set_query_contexts(["test"])
        assert covdata.lines("a.py") == [1, 2]
        covdata.set_query_contexts(["other"])
        assert covdata.lines("a.py") == []

    def test_contexts_by_lineno_with_lines(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_a")
        covdata.add_lines(LINES_1)
        expected = {1: ["test_a"], 2: ["test_a"]}
        assert covdata.contexts_by_lineno("a.py") == expected

    @pytest.mark.parametrize("lines", [LINES_1, dicts_from_sets(LINES_1)])
    def test_no_duplicate_lines(self, lines: Mapping[str, Collection[TLineNo]]) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("context1")
        covdata.add_lines(lines)
        covdata.set_context("context2")
        covdata.add_lines(lines)
        assert covdata.lines("a.py") == A_PY_LINES_1

    @pytest.mark.parametrize("arcs", [ARCS_3, dicts_from_sets(ARCS_3)])
    def test_no_duplicate_arcs(self, arcs: Mapping[str, Collection[TArc]]) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("context1")
        covdata.add_arcs(arcs)
        covdata.set_context("context2")
        covdata.add_arcs(arcs)
        assert covdata.arcs("x.py") == X_PY_ARCS_3

    def test_no_arcs_vs_unmeasured_file(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.touch_file("zzz.py")
        assert covdata.lines("zzz.py") == []
        assert covdata.lines("no_such_file.py") is None
        assert covdata.arcs("zzz.py") == []
        assert covdata.arcs("no_such_file.py") is None

    def test_arcs_with_contexts(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_x")
        covdata.add_arcs(ARCS_3)
        assert covdata.arcs("x.py") == [(-1, 1), (1, 2), (2, 3), (3, -1)]
        covdata.set_query_contexts(["test_.$"])
        assert covdata.arcs("x.py") == [(-1, 1), (1, 2), (2, 3), (3, -1)]
        covdata.set_query_contexts(["other"])
        assert covdata.arcs("x.py") == []

    def test_contexts_by_lineno_with_arcs(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_x")
        covdata.add_arcs(ARCS_3)
        expected = {1: ["test_x"], 2: ["test_x"], 3: ["test_x"]}
        assert covdata.contexts_by_lineno("x.py") == expected

    def test_contexts_by_lineno_with_unknown_file(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_x")
        covdata.add_arcs(ARCS_3)
        assert covdata.contexts_by_lineno("xyz.py") == {}

    def test_context_by_lineno_with_query_contexts_with_lines(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_1")
        covdata.add_lines(LINES_1)
        covdata.set_context("test_2")
        covdata.add_lines(LINES_2)
        covdata.set_query_context("test_1")
        assert covdata.contexts_by_lineno("a.py") == dict.fromkeys([1, 2], ["test_1"])

    def test_context_by_lineno_with_query_contexts_with_arcs(self) -> None:
        covdata = DebugCoverageData()
        covdata.set_context("test_1")
        covdata.add_arcs(ARCS_3)
        covdata.set_context("test_2")
        covdata.add_arcs(ARCS_4)
        covdata.set_query_context("test_1")
        assert covdata.contexts_by_lineno("x.py") == dict.fromkeys([1, 2, 3], ["test_1"])

    def test_file_tracer_name(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(
            {
                "p1.foo": [1, 2, 3],
                "p2.html": [10, 11, 12],
                "main.py": [20],
            }
        )
        covdata.add_file_tracers({"p1.foo": "p1.plugin", "p2.html": "p2.plugin"})
        assert covdata.file_tracer("p1.foo") == "p1.plugin"
        assert covdata.file_tracer("p2.html") == "p2.plugin"
        assert covdata.file_tracer("main.py") == ""
        assert covdata.file_tracer("p3.not_here") is None

    def test_ok_to_repeat_file_tracer(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(
            {
                "p1.foo": [1, 2, 3],
                "p2.html": [10, 11, 12],
            }
        )
        covdata.add_file_tracers({"p1.foo": "p1.plugin", "p2.html": "p2.plugin"})
        covdata.add_file_tracers({"p1.foo": "p1.plugin"})
        assert covdata.file_tracer("p1.foo") == "p1.plugin"

    def test_ok_to_set_empty_file_tracer(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(
            {
                "p1.foo": [1, 2, 3],
                "p2.html": [10, 11, 12],
                "main.py": [20],
            }
        )
        covdata.add_file_tracers({"p1.foo": "p1.plugin", "main.py": ""})
        assert covdata.file_tracer("p1.foo") == "p1.plugin"
        assert covdata.file_tracer("main.py") == ""

    def test_cant_change_file_tracer_name(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines({"p1.foo": [1, 2, 3]})
        covdata.add_file_tracers({"p1.foo": "p1.plugin"})

        msg = "Conflicting file tracer name for 'p1.foo': 'p1.plugin' vs 'p1.plugin.foo'"
        with pytest.raises(DataError, match=msg):
            covdata.add_file_tracers({"p1.foo": "p1.plugin.foo"})

    def test_update_lines(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines(LINES_1)

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_lines(LINES_2)

        covdata3 = DebugCoverageData(suffix="3")
        covdata3.update(covdata1)
        covdata3.update(covdata2)

        assert_line_counts(covdata3, SUMMARY_1_2)
        assert_measured_files(covdata3, MEASURED_FILES_1_2)

    def test_update_arcs(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_arcs(ARCS_3)

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_arcs(ARCS_4)

        covdata3 = DebugCoverageData(suffix="3")
        covdata3.update(covdata1)
        covdata3.update(covdata2)

        assert_line_counts(covdata3, SUMMARY_3_4)
        assert_measured_files(covdata3, MEASURED_FILES_3_4)

    def test_update_cant_mix_lines_and_arcs(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines(LINES_1)

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_arcs(ARCS_3)

        msg = "Can't combine branch coverage data with statement data"
        with pytest.raises(DataError, match=msg):
            covdata1.update(covdata2)

        msg = "Can't combine statement coverage data with branch data"
        with pytest.raises(DataError, match=msg):
            covdata2.update(covdata1)

    def test_update_file_tracers(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines(
            {
                "p1.html": [1, 2, 3, 4],
                "p2.html": [5, 6, 7],
                "main.py": [10, 11, 12],
            }
        )
        covdata1.add_file_tracers(
            {
                "p1.html": "html.plugin",
                "p2.html": "html.plugin2",
            }
        )

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_lines(
            {
                "p1.html": [3, 4, 5, 6],
                "p2.html": [7, 8, 9],
                "p3.foo": [1000, 1001],
                "main.py": [10, 11, 12],
            }
        )
        covdata2.add_file_tracers(
            {
                "p1.html": "html.plugin",
                "p2.html": "html.plugin2",
                "p3.foo": "foo_plugin",
            }
        )

        covdata3 = DebugCoverageData(suffix="3")
        covdata3.update(covdata1)
        covdata3.update(covdata2)
        assert covdata3.file_tracer("p1.html") == "html.plugin"
        assert covdata3.file_tracer("p2.html") == "html.plugin2"
        assert covdata3.file_tracer("p3.foo") == "foo_plugin"
        assert covdata3.file_tracer("main.py") == ""

    def test_update_conflicting_file_tracers(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines({"p1.html": [1, 2, 3]})
        covdata1.add_file_tracers({"p1.html": "html.plugin"})

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_lines({"p1.html": [1, 2, 3]})
        covdata2.add_file_tracers({"p1.html": "html.other_plugin"})

        msg = "Conflicting file tracer name for 'p1.html': 'html.plugin' vs 'html.other_plugin'"
        with pytest.raises(DataError, match=msg):
            covdata1.update(covdata2)

        msg = "Conflicting file tracer name for 'p1.html': 'html.other_plugin' vs 'html.plugin'"
        with pytest.raises(DataError, match=msg):
            covdata2.update(covdata1)

    def test_update_file_tracer_vs_no_file_tracer(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines({"p1.html": [1, 2, 3]})
        covdata1.add_file_tracers({"p1.html": "html.plugin"})

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_lines({"p1.html": [1, 2, 3]})

        msg = "Conflicting file tracer name for 'p1.html': 'html.plugin' vs ''"
        with pytest.raises(DataError, match=msg):
            covdata1.update(covdata2)

        msg = "Conflicting file tracer name for 'p1.html': '' vs 'html.plugin'"
        with pytest.raises(DataError, match=msg):
            covdata2.update(covdata1)

    def test_update_lines_empty(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines(LINES_1)

        covdata2 = DebugCoverageData(suffix="2")
        covdata1.update(covdata2)
        assert_line_counts(covdata1, SUMMARY_1)

    def test_update_arcs_empty(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_arcs(ARCS_3)

        covdata2 = DebugCoverageData(suffix="2")
        covdata1.update(covdata2)
        assert_line_counts(covdata1, SUMMARY_3)

    def test_asking_isnt_measuring(self) -> None:
        # Asking about an unmeasured file shouldn't make it seem measured.
        covdata = DebugCoverageData()
        assert_measured_files(covdata, [])
        assert covdata.arcs("missing.py") is None
        assert_measured_files(covdata, [])

    def test_add_to_hash_with_lines(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        hasher = mock.Mock()
        add_data_to_hash(covdata, "a.py", hasher)
        assert hasher.method_calls == [
            mock.call.update([1, 2]),  # lines
            mock.call.update(""),  # file_tracer name
        ]

    def test_add_to_hash_with_arcs(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.add_file_tracers({"y.py": "hologram_plugin"})
        hasher = mock.Mock()
        add_data_to_hash(covdata, "y.py", hasher)
        assert hasher.method_calls == [
            mock.call.update([(-1, 17), (17, 23), (23, -1)]),  # arcs
            mock.call.update("hologram_plugin"),  # file_tracer name
        ]

    def test_add_to_lines_hash_with_missing_file(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/403
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        hasher = mock.Mock()
        add_data_to_hash(covdata, "missing.py", hasher)
        assert hasher.method_calls == [
            mock.call.update([]),
            mock.call.update(None),
        ]

    def test_add_to_arcs_hash_with_missing_file(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/403
        covdata = DebugCoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.add_file_tracers({"y.py": "hologram_plugin"})
        hasher = mock.Mock()
        add_data_to_hash(covdata, "missing.py", hasher)
        assert hasher.method_calls == [
            mock.call.update([]),
            mock.call.update(None),
        ]

    def test_empty_lines_are_still_lines(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines({})
        covdata.touch_file("abc.py")
        assert not covdata.has_arcs()

    def test_empty_arcs_are_still_arcs(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_arcs({})
        covdata.touch_file("abc.py")
        assert covdata.has_arcs()

    def test_cant_touch_in_empty_data(self) -> None:
        covdata = DebugCoverageData()
        msg = "Can't touch files in an empty CoverageData"
        with pytest.raises(DataError, match=msg):
            covdata.touch_file("abc.py")

    def test_read_and_write_are_opposites(self) -> None:
        covdata1 = DebugCoverageData()
        covdata1.add_arcs(ARCS_3)
        covdata1.write()

        covdata2 = DebugCoverageData()
        covdata2.read()
        assert_arcs3_data(covdata2)

    def test_thread_stress(self) -> None:
        covdata = DebugCoverageData()
        exceptions = []

        def thread_main() -> None:
            """Every thread will try to add the same data."""
            try:
                covdata.add_lines(LINES_1)
            except Exception as ex:  # pragma: only failure
                exceptions.append(ex)

        threads = [threading.Thread(target=thread_main) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert_lines1_data(covdata)
        assert not exceptions

    def test_purge_files_lines(self) -> None:
        covdata = DebugCoverageData()
        covdata.add_lines(LINES_1)
        covdata.add_lines(LINES_2)
        assert_line_counts(covdata, SUMMARY_1_2)
        covdata.purge_files(["a.py", "b.py"])
        assert_line_counts(covdata, {"a.py": 0, "b.py": 0, "c.py": 1})
        covdata.purge_files(["c.py"])
        assert_line_counts(covdata, {"a.py": 0, "b.py": 0, "c.py": 0})
        # It's OK to "purge" a file that wasn't measured.
        covdata.purge_files(["xyz.py"])
        assert_line_counts(covdata, {"a.py": 0, "b.py": 0, "c.py": 0})

    def test_purge_files_arcs(self) -> None:
        covdata = CoverageData()
        covdata.add_arcs(ARCS_3)
        covdata.add_arcs(ARCS_4)
        assert_line_counts(covdata, SUMMARY_3_4)
        covdata.purge_files(["x.py", "y.py"])
        assert_line_counts(covdata, {"x.py": 0, "y.py": 0, "z.py": 1})
        covdata.purge_files(["z.py"])
        assert_line_counts(covdata, {"x.py": 0, "y.py": 0, "z.py": 0})

    def test_cant_purge_in_empty_data(self) -> None:
        covdata = DebugCoverageData()
        msg = "Can't purge files in an empty CoverageData"
        with pytest.raises(DataError, match=msg):
            covdata.purge_files(["abc.py"])


class CoverageDataInTempDirTest(CoverageTest):
    """Tests of CoverageData that need a temporary directory to make files."""

    @pytest.mark.parametrize("file_class", FilePathClasses)
    def test_read_write_lines(self, file_class: FilePathType) -> None:
        self.assert_doesnt_exist("lines.dat")
        covdata1 = DebugCoverageData(file_class("lines.dat"))
        covdata1.add_lines(LINES_1)
        covdata1.write()
        self.assert_exists("lines.dat")

        covdata2 = DebugCoverageData("lines.dat")
        covdata2.read()
        assert_lines1_data(covdata2)

    def test_read_write_arcs(self) -> None:
        covdata1 = DebugCoverageData("arcs.dat")
        covdata1.add_arcs(ARCS_3)
        covdata1.write()

        covdata2 = DebugCoverageData("arcs.dat")
        covdata2.read()
        assert_arcs3_data(covdata2)

    def test_read_errors(self) -> None:
        self.make_file("xyzzy.dat", "xyzzy")
        with pytest.raises(DataError, match=r"Couldn't .* '.*[/\\]xyzzy.dat': \S+"):
            covdata = DebugCoverageData("xyzzy.dat")
            covdata.read()
        assert not covdata

    def test_hard_read_error(self) -> None:
        self.make_file("noperms.dat", "go away")
        os.chmod("noperms.dat", 0)
        with pytest.raises(DataError, match=r"Couldn't .* '.*[/\\]noperms.dat': \S+"):
            covdata = DebugCoverageData("noperms.dat")
            covdata.read()

    @pytest.mark.parametrize("klass", [CoverageData, DebugCoverageData])
    def test_error_when_closing(self, klass: TCoverageData) -> None:
        msg = r"Couldn't .* '.*[/\\]flaked.dat': \S+"
        with pytest.raises(DataError, match=msg):
            covdata = klass("flaked.dat")
            covdata.add_lines(LINES_1)
            # I don't know how to make a real error, so let's fake one.
            sqldb = list(covdata._dbs.values())[0]
            sqldb.close = lambda: 1 / 0  # type: ignore
            covdata.add_lines(LINES_1)

    def test_wrong_schema_version(self) -> None:
        with sqlite3.connect("wrong_schema.db") as con:
            con.execute("create table coverage_schema (version integer)")
            con.execute("insert into coverage_schema (version) values (99)")
        msg = r"Couldn't .* '.*[/\\]wrong_schema.db': wrong schema: 99 instead of \d+"
        with pytest.raises(DataError, match=msg):
            covdata = DebugCoverageData("wrong_schema.db")
            covdata.read()
        assert not covdata

    def test_wrong_schema_schema(self) -> None:
        with sqlite3.connect("wrong_schema_schema.db") as con:
            con.execute("create table coverage_schema (xyzzy integer)")
            con.execute("insert into coverage_schema (xyzzy) values (99)")
        msg = r"Data file .* isn't a coverage data file: .* no such column"
        with pytest.raises(DataError, match=msg):
            covdata = DebugCoverageData("wrong_schema_schema.db")
            covdata.read()
        assert not covdata


class CoverageDataFilesTest(CoverageTest):
    """Tests of CoverageData file handling."""

    def test_reading_missing(self) -> None:
        self.assert_doesnt_exist(".coverage")
        covdata = DebugCoverageData()
        covdata.read()
        assert_line_counts(covdata, {})

    def test_writing_and_reading(self) -> None:
        covdata1 = DebugCoverageData()
        covdata1.add_lines(LINES_1)
        covdata1.write()

        covdata2 = DebugCoverageData()
        covdata2.read()
        assert_line_counts(covdata2, SUMMARY_1)

    def test_debug_output_with_debug_option(self) -> None:
        # With debug option dataio, we get debug output about reading and
        # writing files.
        debug = DebugControlString(options=["dataio"])
        covdata1 = CoverageData(debug=debug)
        covdata1.add_lines(LINES_1)
        covdata1.write()

        covdata2 = CoverageData(debug=debug)
        covdata2.read()
        assert_line_counts(covdata2, SUMMARY_1)

        print(debug.get_output())

        assert re.search(
            r"^"
            + r"Closing dbs, force=False: {}\n"
            + r"Erasing data file '.*\.coverage' \(does not exist\)\n"
            + r"Opening data file '.*\.coverage' \(does not exist\)\n"
            + r"Initing data file '.*\.coverage' \(0 bytes, modified [-:. 0-9]+\)\n"
            + r"Writing \(no-op\) data file '.*\.coverage' \(\d+ bytes, modified [-:. 0-9]+\)\n"
            + r"Opening data file '.*\.coverage' \(\d+ bytes, modified [-:. 0-9]+\)\n"
            + r"$",
            debug.get_output(),
        )

    def test_debug_output_without_debug_option(self) -> None:
        # With a debug object, but not the dataio option, we don't get debug
        # output.
        debug = DebugControlString(options=[])
        covdata1 = CoverageData(debug=debug)
        covdata1.add_lines(LINES_1)
        covdata1.write()

        covdata2 = CoverageData(debug=debug)
        covdata2.read()
        assert_line_counts(covdata2, SUMMARY_1)

        assert debug.get_output() == ""

    def test_explicit_suffix(self) -> None:
        self.assert_doesnt_exist(".coverage.SUFFIX")
        covdata = DebugCoverageData(suffix="SUFFIX")
        covdata.add_lines(LINES_1)
        covdata.write()
        self.assert_exists(".coverage.SUFFIX")
        self.assert_doesnt_exist(".coverage")

    def test_true_suffix(self) -> None:
        self.assert_file_count(".coverage.*", 0)

        # suffix=True will make a randomly named data file.
        covdata1 = DebugCoverageData(suffix=True)
        covdata1.add_lines(LINES_1)
        covdata1.write()
        self.assert_doesnt_exist(".coverage")
        data_files1 = glob.glob(".coverage.*")
        assert len(data_files1) == 1

        # Another suffix=True will choose a different name.
        covdata2 = DebugCoverageData(suffix=True)
        covdata2.add_lines(LINES_1)
        covdata2.write()
        self.assert_doesnt_exist(".coverage")
        data_files2 = glob.glob(".coverage.*")
        assert len(data_files2) == 2

        # In addition to being different, the suffixes have the pid in them.
        assert all(str(os.getpid()) in fn for fn in data_files2)

    def test_combining(self) -> None:
        self.assert_file_count(".coverage.*", 0)

        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines(LINES_1)
        covdata1.write()
        self.assert_exists(".coverage.1")
        self.assert_file_count(".coverage.*", 1)

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_lines(LINES_2)
        covdata2.write()
        self.assert_exists(".coverage.2")
        self.assert_file_count(".coverage.*", 2)

        covdata3 = DebugCoverageData()
        combine_parallel_data(covdata3)
        assert_line_counts(covdata3, SUMMARY_1_2)
        assert_measured_files(covdata3, MEASURED_FILES_1_2)
        self.assert_file_count(".coverage.*", 0)

    def test_erasing(self) -> None:
        covdata1 = DebugCoverageData()
        covdata1.add_lines(LINES_1)
        covdata1.write()

        covdata1.erase()
        assert_line_counts(covdata1, {})

        covdata2 = DebugCoverageData()
        covdata2.read()
        assert_line_counts(covdata2, {})

    def test_erasing_parallel(self) -> None:
        self.make_file("datafile.1")
        self.make_file("datafile.2")
        self.make_file(".coverage")
        data = DebugCoverageData("datafile")
        data.erase(parallel=True)
        self.assert_file_count("datafile.*", 0)
        self.assert_exists(".coverage")

    def test_combining_with_aliases(self) -> None:
        covdata1 = DebugCoverageData(suffix="1")
        covdata1.add_lines(
            {
                "/home/ned/proj/src/a.py": {1, 2},
                "/home/ned/proj/src/sub/b.py": {3},
                "/home/ned/proj/src/template.html": {10},
            }
        )
        covdata1.add_file_tracers(
            {
                "/home/ned/proj/src/template.html": "html.plugin",
            }
        )
        covdata1.write()

        covdata2 = DebugCoverageData(suffix="2")
        covdata2.add_lines(
            {
                r"c:\ned\test\a.py": {4, 5},
                r"c:\ned\test\sub\b.py": {3, 6},
            }
        )
        covdata2.write()

        self.assert_file_count(".coverage.*", 2)

        self.make_file("a.py", "")
        self.make_file("sub/b.py", "")
        self.make_file("template.html", "")
        covdata3 = DebugCoverageData()
        aliases = PathAliases()
        aliases.add("/home/ned/proj/src/", "./")
        aliases.add(r"c:\ned\test", "./")
        combine_parallel_data(covdata3, aliases=aliases)
        self.assert_file_count(".coverage.*", 0)
        self.assert_exists(".coverage")

        apy = canonical_filename("./a.py")
        sub_bpy = canonical_filename("./sub/b.py")
        template_html = canonical_filename("./template.html")

        assert_line_counts(covdata3, {apy: 4, sub_bpy: 2, template_html: 1}, fullpath=True)
        assert_measured_files(covdata3, [apy, sub_bpy, template_html])
        assert covdata3.file_tracer(template_html) == "html.plugin"

    def test_combining_from_different_directories(self) -> None:
        os.makedirs("cov1")
        covdata1 = DebugCoverageData("cov1/.coverage.1")
        covdata1.add_lines(LINES_1)
        covdata1.write()

        os.makedirs("cov2")
        covdata2 = DebugCoverageData("cov2/.coverage.2")
        covdata2.add_lines(LINES_2)
        covdata2.write()

        # This data won't be included.
        covdata_xxx = DebugCoverageData(".coverage.xxx")
        covdata_xxx.add_arcs(ARCS_3)
        covdata_xxx.write()

        covdata3 = DebugCoverageData()
        combine_parallel_data(covdata3, data_paths=["cov1", "cov2"])

        assert_line_counts(covdata3, SUMMARY_1_2)
        assert_measured_files(covdata3, MEASURED_FILES_1_2)
        self.assert_doesnt_exist("cov1/.coverage.1")
        self.assert_doesnt_exist("cov2/.coverage.2")
        self.assert_exists(".coverage.xxx")

    def test_combining_from_files(self) -> None:
        os.makedirs("cov1")
        covdata1 = DebugCoverageData("cov1/.coverage.1")
        covdata1.add_lines(LINES_1)
        covdata1.write()

        # Journal files should never be included in the combining.
        self.make_file("cov1/.coverage.1-journal", "xyzzy")

        os.makedirs("cov2")
        covdata2 = DebugCoverageData("cov2/.coverage.2")
        covdata2.add_lines(LINES_2)
        covdata2.write()

        # This data won't be included.
        covdata_xxx = DebugCoverageData(".coverage.xxx")
        covdata_xxx.add_arcs(ARCS_3)
        covdata_xxx.write()

        covdata_2xxx = DebugCoverageData("cov2/.coverage.xxx")
        covdata_2xxx.add_arcs(ARCS_3)
        covdata_2xxx.write()

        covdata3 = DebugCoverageData()
        combine_parallel_data(covdata3, data_paths=["cov1", "cov2/.coverage.2"])

        assert_line_counts(covdata3, SUMMARY_1_2)
        assert_measured_files(covdata3, MEASURED_FILES_1_2)
        self.assert_doesnt_exist("cov1/.coverage.1")
        self.assert_doesnt_exist("cov2/.coverage.2")
        self.assert_exists(".coverage.xxx")
        self.assert_exists("cov2/.coverage.xxx")

    def test_combining_from_nonexistent_directories(self) -> None:
        covdata = DebugCoverageData()
        msg = "Couldn't combine from non-existent path 'xyzzy'"
        with pytest.raises(NoDataError, match=msg):
            combine_parallel_data(covdata, data_paths=["xyzzy"])

    def test_interleaved_erasing_bug716(self) -> None:
        # pytest-cov could produce this scenario. #716
        covdata1 = DebugCoverageData()
        covdata2 = DebugCoverageData()
        # this used to create the .coverage database file..
        covdata2.set_context("")
        # then this would erase it all..
        covdata1.erase()
        # then this would try to use tables that no longer exist.
        # "no such table: meta"
        covdata2.add_lines(LINES_1)

    @pytest.mark.parametrize(
        "dpart, fpart",
        [
            ("", "[b-a]"),
            ("[3-1]", ""),
            ("[3-1]", "[b-a]"),
        ],
    )
    def test_combining_with_crazy_filename(self, dpart: str, fpart: str) -> None:
        dirname = f"py{dpart}"
        basename = f"{dirname}/.coverage{fpart}"
        os.makedirs(dirname)

        covdata1 = CoverageData(basename=basename, suffix="1")
        covdata1.add_lines(LINES_1)
        covdata1.write()

        covdata2 = CoverageData(basename=basename, suffix="2")
        covdata2.add_lines(LINES_2)
        covdata2.write()

        covdata3 = CoverageData(basename=basename)
        combine_parallel_data(covdata3)
        assert_line_counts(covdata3, SUMMARY_1_2)
        assert_measured_files(covdata3, MEASURED_FILES_1_2)
        self.assert_file_count(glob.escape(basename) + ".*", 0)

    def test_meta_data(self) -> None:
        # TODO: do we care about this?
        # The metadata written to the data file shouldn't interfere with
        # hashing to remove duplicates, except for debug=process, which
        # writes debugging info as metadata.
        debug = DebugControlString(options=[])
        covdata1 = CoverageData(basename="meta.1", debug=debug)
        covdata1.add_lines(LINES_1)
        covdata1.write()
        with sqlite3.connect("meta.1") as con:
            data = {k for (k,) in con.execute("select key from meta")}
        assert {"has_arcs", "version"} <= data

        debug = DebugControlString(options=["process"])
        covdata2 = CoverageData(basename="meta.2", debug=debug)
        covdata2.add_lines(LINES_1)
        covdata2.write()
        with sqlite3.connect("meta.2") as con:
            data = {k for (k,) in con.execute("select key from meta")}
        assert {"has_arcs", "sys_argv", "version", "when"} <= data

    def make_data_files(self, spec: str, arcs: bool) -> list[CoverageData]:
        """Make a number data files.

        `spec` is a string dictating the data for each file. Same characters
        in spec produce identical data in the corresponding files.
        """
        datas = []
        for ifile, c in enumerate(spec):
            files_lines = {f"code_{i}.py": list(range(1, 100)) for i in range(10)}
            files_lines[f"more_code_{c}.py"] = list(range(1, 10, 2))
            if arcs:
                files_arcs = {
                    fname: [(l, 1000) for l in lines] for fname, lines in files_lines.items()
                }
                kwargs: dict[str, Any] = {"arcs": files_arcs}
            else:
                kwargs = {"lines": files_lines}
            datas.append(self.make_data_file(".coverage", suffix=str(ifile), **kwargs))
        return datas

    @pytest.mark.parametrize(
        "spec, combine_or_skip",
        [
            ("abcdef", "cccccc"),
            ("aaaaaa", "csssss"),
            ("ababac", "ccsssc"),
            ("aaaaab", "cssssc"),
        ],
    )
    @pytest.mark.parametrize("arcs", [False, True])
    def test_skipping_duplicates(self, spec: str, combine_or_skip: str, arcs: bool) -> None:
        # Check that DataFileClassifier correctly notices when data is
        # duplicated, and tells us to combine new data and skip duplicates.
        datas = self.make_data_files(spec, arcs=arcs)
        classifier = DataFileClassifier()
        for data_file, c_or_s in zip(datas, combine_or_skip):
            file_action = classifier.classify(data_file.data_filename())
            assert file_action[0] == c_or_s


class DumpsLoadsTest(CoverageTest):
    """Tests of CoverageData.dumps and loads."""

    run_in_temp_dir = False

    @pytest.mark.parametrize("klass", [CoverageData, DebugCoverageData])
    def test_serialization(self, klass: TCoverageData) -> None:
        covdata1 = klass(no_disk=True)
        covdata1.add_lines(LINES_1)
        covdata1.add_lines(LINES_2)
        serial = covdata1.dumps()

        covdata2 = klass(no_disk=True)
        covdata2.loads(serial)
        assert_line_counts(covdata2, SUMMARY_1_2)
        assert_measured_files(covdata2, MEASURED_FILES_1_2)

    def test_misfed_serialization(self) -> None:
        covdata = CoverageData(no_disk=True)
        bad_data = b"Hello, world!\x07 " + b"z" * 100
        msg = r"Unrecognized serialization: {} \(head of {} bytes\)".format(
            re.escape(repr(bad_data[:40])),
            len(bad_data),
        )
        with pytest.raises(DataError, match=msg):
            covdata.loads(bad_data)


class NoDiskTest(CoverageTest):
    """Tests of in-memory CoverageData."""

    run_in_temp_dir = False

    def test_updating(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1323
        a = CoverageData(no_disk=True)
        a.add_lines({"foo.py": [10, 20, 30]})
        assert a.measured_files() == {"foo.py"}

        b = CoverageData(no_disk=True)
        b.update(a)
        assert b.measured_files() == {"foo.py"}
