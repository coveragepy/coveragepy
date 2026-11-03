# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of coverage/collector.py and other collectors."""

from __future__ import annotations

import os.path

import coverage
from tests.coveragetest import CoverageTest
from tests.helpers import CheckUniqueFilenames


class CollectorTest(CoverageTest):
    """Test specific aspects of the collection process."""

    def test_should_trace_cache(self) -> None:
        # The tracers should only invoke should_trace once for each file name.

        # Make some files that invoke each other.
        self.make_file(
            "f1.py",
            """\
            def f1(x, f):
                return f(x)
            """,
        )

        self.make_file(
            "f2.py",
            """\
            import f1

            def func(x):
                return f1.f1(x, otherfunc)

            def otherfunc(x):
                return x*x

            for i in range(10):
                func(i)
            """,
        )

        # Trace one file, but not the other. CheckUniqueFilenames will assert
        # that _should_trace hasn't been called twice for the same file.
        cov = coverage.Coverage(include=["f1.py"])
        should_trace_hook = CheckUniqueFilenames.hook(cov, "_should_trace")

        # Import the Python file, executing it.
        self.start_import_stop(cov, "f2")

        # Double-check that our files were checked.
        abs_files = {os.path.abspath(f) for f in should_trace_hook.filenames}
        assert os.path.abspath("f1.py") in abs_files
        assert os.path.abspath("f2.py") in abs_files

    def test_clear_data_when_a_file_is_recorded_while_clearing(self) -> None:
        # Clearing the per-file data runs traced code: the GC can call a
        # __del__ or a gc.callbacks hook, and that code is measured, so a
        # tracer can record a new file name in self.data while we are in the
        # middle of clearing.  _clear_data() has to iterate a snapshot of the
        # values, not the live dict.
        cov = coverage.Coverage(include=["f1.py"])
        cov.start()
        try:
            collector = cov._collector
            assert collector is not None
            data = collector.data

            class GrowingSet(set[int]):
                """A per-file data set that records another file when cleared."""

                def clear(self) -> None:
                    data["added.py"] = set()
                    super().clear()

            data["stale.py"] = GrowingSet({1})
            collector._clear_data()

            assert data["stale.py"] == set()
            assert data["added.py"] == set()
        finally:
            cov.stop()
