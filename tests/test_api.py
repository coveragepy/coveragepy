# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.py's API."""

from __future__ import annotations

import fnmatch
import glob
import io
import os
import os.path
import re
import shutil
import sys
import textwrap

from collections.abc import Callable, Iterable
from typing import cast

import pytest

import coverage
from coverage import Coverage, env
from coverage.data import line_counts, sorted_lines
from coverage.exceptions import ConfigError, CoverageException, NoDataError, NoSource
from coverage.files import abs_file, relative_filename
from coverage.misc import import_local_file
from coverage.types import FilePathClasses, FilePathType, TCovKwargs

from tests import testenv
from tests.coveragetest import CoverageTest, TESTS_DIR, UsingModulesMixin
from tests.helpers import (
    assert_count_equal,
    assert_coverage_warnings,
    change_dir,
    get_coverage_warnings,
    nice_file,
    os_sep,
)

BAD_SQLITE_REGEX = r"file( is encrypted or)? is not a database"


class ApiTest(CoverageTest):
    """Api-oriented tests for coverage.py."""

    def clean_files(self, files: list[str], pats: list[str]) -> list[str]:
        """Remove names matching `pats` from `files`, a list of file names."""
        good = []
        for f in files:
            for pat in pats:
                if fnmatch.fnmatch(f, pat):
                    break
            else:
                good.append(f)
        return good

    def assertFiles(self, files: list[str]) -> None:
        """Assert that the files here are `files`, ignoring the usual junk."""
        here = os.listdir(".")
        here = self.clean_files(here, ["*.pyc", "__pycache__", "*$py.class"])
        assert_count_equal(here, files)

    def test_unexecuted_file(self) -> None:
        cov = coverage.Coverage()

        self.make_file(
            "mycode.py",
            """\
            a = 1
            b = 2
            if b == 3:
                c = 4
            d = 5
            """,
        )

        self.make_file(
            "not_run.py",
            """\
            fooey = 17
            """,
        )

        # Import the Python file, executing it.
        self.start_import_stop(cov, "mycode")

        _, statements, missing, _ = cov.analysis("not_run.py")
        assert statements == [1]
        assert missing == [1]

    def test_filenames(self) -> None:
        self.make_file(
            "mymain.py",
            """\
            import mymod
            a = 1
            """,
        )

        self.make_file(
            "mymod.py",
            """\
            fooey = 17
            """,
        )

        # Import the Python file, executing it.
        cov = coverage.Coverage()
        self.start_import_stop(cov, "mymain")

        filename, _, _, _ = cov.analysis("mymain.py")
        assert os.path.basename(filename) == "mymain.py"
        filename, _, _, _ = cov.analysis("mymod.py")
        assert os.path.basename(filename) == "mymod.py"

        filename, _, _, _ = cov.analysis(sys.modules["mymain"])
        assert os.path.basename(filename) == "mymain.py"
        filename, _, _, _ = cov.analysis(sys.modules["mymod"])
        assert os.path.basename(filename) == "mymod.py"

        # Import the Python file, executing it again, once it's been compiled
        # already.
        cov = coverage.Coverage()
        self.start_import_stop(cov, "mymain")

        filename, _, _, _ = cov.analysis("mymain.py")
        assert os.path.basename(filename) == "mymain.py"
        filename, _, _, _ = cov.analysis("mymod.py")
        assert os.path.basename(filename) == "mymod.py"

        filename, _, _, _ = cov.analysis(sys.modules["mymain"])
        assert os.path.basename(filename) == "mymain.py"
        filename, _, _, _ = cov.analysis(sys.modules["mymod"])
        assert os.path.basename(filename) == "mymod.py"

    @pytest.mark.parametrize("cover_pylib", [False, True])
    def test_stdlib(self, cover_pylib: bool) -> None:
        self.make_file(
            "mymain.py",
            """\
            import colorsys
            a = 1
            hls = colorsys.rgb_to_hls(1.0, 0.5, 0.0)
            """,
        )

        # Measure without the stdlib.
        cov1 = coverage.Coverage(cover_pylib=cover_pylib)
        self.start_import_stop(cov1, "mymain")

        _, statements, missing, _ = cov1.analysis("mymain.py")
        assert statements == [1, 2, 3]
        assert missing == []
        # but none were in colorsys.py
        _, statements, missing, _ = cov1.analysis("colorsys.py")
        if cover_pylib:
            assert statements != missing
        else:
            assert statements == missing

    def test_include_can_measure_stdlib(self) -> None:
        self.make_file(
            "mymain.py",
            """\
            import colorsys, random
            a = 1
            r, g, b = [random.random() for _ in range(3)]
            hls = colorsys.rgb_to_hls(r, g, b)
            """,
        )

        # Measure without the stdlib, but include colorsys.
        cov1 = coverage.Coverage(cover_pylib=False, include=["*/colorsys.py"])
        self.start_import_stop(cov1, "mymain")

        # some statements were marked executed in colorsys.py
        _, statements, missing, _ = cov1.analysis("colorsys.py")
        assert statements != missing
        # but none were in random.py
        _, statements, missing, _ = cov1.analysis("random.py")
        assert statements == missing

    def test_exclude_list(self) -> None:
        cov = coverage.Coverage()
        cov.clear_exclude()
        assert cov.get_exclude_list() == []
        cov.exclude("foo")
        assert cov.get_exclude_list() == ["foo"]
        cov.exclude("bar")
        assert cov.get_exclude_list() == ["foo", "bar"]
        assert cov._exclude_regex("exclude") == "(?:foo)|(?:bar)"
        cov.clear_exclude()
        assert cov.get_exclude_list() == []

    def test_exclude_partial_list(self) -> None:
        cov = coverage.Coverage()
        cov.clear_exclude(which="partial")
        assert cov.get_exclude_list(which="partial") == []
        cov.exclude("foo", which="partial")
        assert cov.get_exclude_list(which="partial") == ["foo"]
        cov.exclude("bar", which="partial")
        assert cov.get_exclude_list(which="partial") == ["foo", "bar"]
        assert cov._exclude_regex(which="partial") == "(?:foo)|(?:bar)"
        cov.clear_exclude(which="partial")
        assert cov.get_exclude_list(which="partial") == []

    def test_exclude_and_partial_are_separate_lists(self) -> None:
        cov = coverage.Coverage()
        cov.clear_exclude(which="partial")
        cov.clear_exclude(which="exclude")
        cov.exclude("foo", which="partial")
        assert cov.get_exclude_list(which="partial") == ["foo"]
        assert cov.get_exclude_list(which="exclude") == []
        cov.exclude("bar", which="exclude")
        assert cov.get_exclude_list(which="partial") == ["foo"]
        assert cov.get_exclude_list(which="exclude") == ["bar"]
        cov.exclude("p2", which="partial")
        cov.exclude("e2", which="exclude")
        assert cov.get_exclude_list(which="partial") == ["foo", "p2"]
        assert cov.get_exclude_list(which="exclude") == ["bar", "e2"]
        cov.clear_exclude(which="partial")
        assert cov.get_exclude_list(which="partial") == []
        assert cov.get_exclude_list(which="exclude") == ["bar", "e2"]
        cov.clear_exclude(which="exclude")
        assert cov.get_exclude_list(which="partial") == []
        assert cov.get_exclude_list(which="exclude") == []

    def test_datafile_default(self) -> None:
        # Default data file behavior: it's .coverage
        self.make_file(
            "datatest1.py",
            """\
            fooey = 17
            """,
        )

        self.assertFiles(["datatest1.py"])
        cov = coverage.Coverage()
        self.start_import_stop(cov, "datatest1")
        cov.save()
        self.assertFiles(["datatest1.py", ".coverage"])

    @pytest.mark.parametrize("file_class", FilePathClasses)
    def test_datafile_specified(self, file_class: FilePathType) -> None:
        # You can specify the data file name.
        self.make_file(
            "datatest2.py",
            """\
            fooey = 17
            """,
        )

        self.assertFiles(["datatest2.py"])
        cov = coverage.Coverage(data_file=file_class("cov.data"))
        self.start_import_stop(cov, "datatest2")
        cov.save()
        self.assertFiles(["datatest2.py", "cov.data"])

    @pytest.mark.parametrize("file_class", FilePathClasses)
    def test_datafile_and_suffix_specified(self, file_class: FilePathType) -> None:
        # You can specify the data file name and suffix.
        self.make_file(
            "datatest3.py",
            """\
            fooey = 17
            """,
        )

        self.assertFiles(["datatest3.py"])
        cov = coverage.Coverage(data_file=file_class("cov.data"), data_suffix="14")
        self.start_import_stop(cov, "datatest3")
        cov.save()
        self.assertFiles(["datatest3.py", "cov.data.14"])

    def test_datafile_from_rcfile(self) -> None:
        # You can specify the data file name in the .coveragerc file
        self.make_file(
            "datatest4.py",
            """\
            fooey = 17
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            data_file = mydata.dat
            """,
        )

        self.assertFiles(["datatest4.py", ".coveragerc"])
        cov = coverage.Coverage()
        self.start_import_stop(cov, "datatest4")
        cov.save()
        self.assertFiles(["datatest4.py", ".coveragerc", "mydata.dat"])

    def test_deep_datafile(self) -> None:
        self.make_file("datatest5.py", "fooey = 17")
        self.assertFiles(["datatest5.py"])
        cov = coverage.Coverage(data_file="deep/sub/cov.data")
        self.start_import_stop(cov, "datatest5")
        cov.save()
        self.assertFiles(["datatest5.py", "deep"])
        self.assert_exists("deep/sub/cov.data")

    def test_datafile_none(self) -> None:
        cov = coverage.Coverage(data_file=None)

        def f1() -> None:  # pragma: nested
            a = 1  # pylint: disable=unused-variable

        one_line_number = f1.__code__.co_firstlineno + 1
        lines = []

        def run_one_function(f: Callable[[], None]) -> None:
            cov.erase()
            with cov.collect():
                f()

            fs = cov.get_data().measured_files()
            lines.append(cov.get_data().lines(list(fs)[0]))

        run_one_function(f1)
        run_one_function(f1)
        run_one_function(f1)
        assert lines == [[one_line_number]] * 3
        self.assert_doesnt_exist(".coverage")
        assert os.listdir(".") == []

    def test_empty_reporting(self) -> None:
        # empty summary reports raise exception, just like the xml report
        cov = coverage.Coverage()
        cov.erase()
        with pytest.raises(NoDataError, match="No data to report."):
            cov.report()

    def test_completely_zero_reporting(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/884
        # If nothing was measured, the file-touching didn't happen properly.
        self.make_file("foo/bar.py", "print('Never run')")
        self.make_file("test.py", "assert True")
        with pytest.warns(Warning) as warns:
            cov = coverage.Coverage(source=["foo"])
            self.start_import_stop(cov, "test")
            cov.report()
        assert_coverage_warnings(warns, "No data was collected. (no-data-collected)")
        # Name         Stmts   Miss  Cover
        # --------------------------------
        # foo/bar.py       1      1     0%
        # --------------------------------
        # TOTAL            1      1     0%

        last = self.last_line_squeezed(self.stdout())
        assert "TOTAL 1 1 0%" == last

    def make_code1_code2(self) -> None:
        """Create the code1.py and code2.py files."""
        self.make_file(
            "code1.py",
            """\
            code1 = 1
            """,
        )
        self.make_file(
            "code2.py",
            """\
            code2 = 1
            code2 = 2
            """,
        )

    def check_code1_code2(self, cov: Coverage) -> None:
        """Check the analysis is correct for code1.py and code2.py."""
        _, statements, missing, _ = cov.analysis("code1.py")
        assert statements == [1]
        assert missing == []
        _, statements, missing, _ = cov.analysis("code2.py")
        assert statements == [1, 2]
        assert missing == []

    def test_start_stop_start_stop(self) -> None:
        self.make_code1_code2()
        cov = coverage.Coverage()
        self.start_import_stop(cov, "code1")
        cov.save()
        self.start_import_stop(cov, "code2")
        self.check_code1_code2(cov)

    def test_start_save_stop(self) -> None:
        self.make_code1_code2()
        cov = coverage.Coverage()
        with cov.collect():
            import_local_file("code1")
            cov.save()
            import_local_file("code2")
        self.check_code1_code2(cov)

    def test_start_save_nostop(self) -> None:
        self.make_code1_code2()
        cov = coverage.Coverage()
        with cov.collect():
            import_local_file("code1")
            cov.save()
            import_local_file("code2")
            self.check_code1_code2(cov)

    def test_two_getdata_only_warn_once(self) -> None:
        self.make_code1_code2()
        cov = coverage.Coverage(source=["."], omit=["code1.py"])
        with cov.collect():
            import_local_file("code1")
        # We didn't collect any data, so we should get a warning.
        with self.assert_warnings(cov, ["No data was collected"]):
            cov.get_data()
        # But calling get_data a second time with no intervening activity
        # won't make another warning.
        with self.assert_warnings(cov, []):
            cov.get_data()

    def test_two_getdata_warn_twice(self) -> None:
        self.make_code1_code2()
        cov = coverage.Coverage(source=["."], omit=["code1.py", "code2.py"])
        with cov.collect():
            import_local_file("code1")
            # We didn't collect any data, so we should get a warning.
            with self.assert_warnings(cov, ["No data was collected"]):
                cov.save()
            import_local_file("code2")
            # Calling get_data a second time after tracing some more will warn again.
            with self.assert_warnings(cov, ["No data was collected"]):
                cov.get_data()

    def make_good_data_files(self) -> None:
        """Make some good data files."""
        self.make_code1_code2()
        cov = coverage.Coverage(data_suffix=True)
        self.start_import_stop(cov, "code1")
        cov.save()

        cov = coverage.Coverage(data_suffix=True)
        self.start_import_stop(cov, "code2")
        cov.save()
        self.assert_file_count(".coverage.*", 2)

    def test_combining_corrupt_data(self) -> None:
        # If you combine a corrupt data file, then you will get a warning,
        # and the file will remain.
        self.make_good_data_files()
        self.make_file(".coverage.foo", """La la la, this isn't coverage data!""")
        cov = coverage.Coverage()
        warning_regex = r"Couldn't use data file '.*\.coverage\.foo': " + BAD_SQLITE_REGEX
        with self.assert_warnings(cov, [warning_regex]):
            cov.combine()

        # We got the results from code1 and code2 properly.
        self.check_code1_code2(cov)

        # The bad file still exists, but it's the only parallel data file left.
        self.assert_exists(".coverage.foo")
        self.assert_file_count(".coverage.*", 1)

    def test_combining_twice(self) -> None:
        self.make_good_data_files()
        cov1 = coverage.Coverage()
        cov1.combine()
        assert self.stdout() == ""
        cov1.save()
        self.check_code1_code2(cov1)
        self.assert_file_count(".coverage.*", 0)
        self.assert_exists(".coverage")

        cov2 = coverage.Coverage()
        with pytest.raises(NoDataError, match=r"No data to combine"):
            cov2.combine(strict=True, keep=False)

        cov3 = coverage.Coverage()
        cov3.combine()
        assert self.stdout() == ""
        # Now the data is empty!
        _, statements, missing, _ = cov3.analysis("code1.py")
        assert statements == [1]
        assert missing == [1]
        _, statements, missing, _ = cov3.analysis("code2.py")
        assert statements == [1, 2]
        assert missing == [1, 2]

    def test_combining_with_a_used_coverage(self) -> None:
        # Can you use a coverage object to run one shard of a parallel suite,
        # and then also combine the data?
        self.make_code1_code2()
        cov = coverage.Coverage(data_suffix=True)
        self.start_import_stop(cov, "code1")
        cov.save()

        cov = coverage.Coverage(data_suffix=True)
        self.start_import_stop(cov, "code2")
        cov.save()

        cov.combine()
        assert self.stdout() == ""
        self.check_code1_code2(cov)

    def test_ordered_combine(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/649
        # The order of the [paths] setting used to matter. Now the
        # resulting path must exist, so the order doesn't matter.
        def make_files() -> None:
            self.make_file("plugins/p1.py", "")
            self.make_file("girder/g1.py", "")
            self.make_data_file(
                basename=".coverage.1",
                lines={
                    abs_file("ci/girder/g1.py"): range(10),
                    abs_file("ci/girder/plugins/p1.py"): range(10),
                },
            )

        def get_combined_filenames() -> set[str]:
            cov = coverage.Coverage()
            cov.combine()
            assert self.stdout() == ""
            cov.save()
            data = cov.get_data()
            filenames = {relative_filename(f).replace("\\", "/") for f in data.measured_files()}
            return filenames

        # Case 1: get the order right.
        make_files()
        self.make_file(
            ".coveragerc",
            """\
            [paths]
            plugins =
                plugins/
                ci/girder/plugins/
            girder =
                girder/
                ci/girder/
            """,
        )
        assert get_combined_filenames() == {"girder/g1.py", "plugins/p1.py"}

        # Case 2: get the order "wrong".
        make_files()
        self.make_file(
            ".coveragerc",
            """\
            [paths]
            girder =
                girder/
                ci/girder/
            plugins =
                plugins/
                ci/girder/plugins/
            """,
        )
        assert get_combined_filenames() == {"girder/g1.py", "plugins/p1.py"}

    def test_warnings(self) -> None:
        self.make_file(
            "hello.py",
            """\
            import sys, os
            print("Hello")
            """,
        )
        with pytest.warns(Warning) as warns:
            cov = coverage.Coverage(source=["sys", "xyzzy", "quux"])
            self.start_import_stop(cov, "hello")
            cov.get_data()

        assert "Hello\n" == self.stdout()
        assert_coverage_warnings(
            warns,
            "Module sys has no Python source. (module-not-python)",
            "Module xyzzy was never imported. (module-not-imported)",
            "Module quux was never imported. (module-not-imported)",
            "No data was collected. (no-data-collected)",
        )

    def test_warnings_suppressed(self) -> None:
        self.make_file(
            "hello.py",
            """\
            import sys, os
            print("Hello")
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            disable_warnings = no-data-collected, module-not-imported
            """,
        )
        with pytest.warns(Warning) as warns:
            cov = coverage.Coverage(source=["sys", "xyzzy", "quux"])
            self.start_import_stop(cov, "hello")
            cov.get_data()

        assert "Hello\n" == self.stdout()
        assert_coverage_warnings(warns, "Module sys has no Python source. (module-not-python)")
        # No "module-not-imported" in warns
        # No "no-data-collected" in warns

    def test_warn_once(self) -> None:
        with pytest.warns(Warning) as warns:
            cov = coverage.Coverage()
            cov.load()
            cov._warn("Warning, warning 1!", slug="bot", once=True)
            cov._warn("Warning, warning 2!", slug="bot", once=True)

        assert_coverage_warnings(warns, "Warning, warning 1! (bot)")
        # No "Warning, warning 2!" in warns
        assert len(get_coverage_warnings(warns)) == 1

    def test_warnings_with_urls(self) -> None:
        with pytest.warns(Warning) as warns:
            cov = coverage.Coverage()
            cov.load()
            cov._warn("Warning Will Robinson", slug="will-rob")
            cov._warn("Warning, warning 2!", slug="second-one")
        warnings = get_coverage_warnings(warns)

        def url(slug: str) -> str:
            return (
                f"https://coverage.readthedocs.io/en/{coverage.__version__}"
                + f"/messages.html#warning-{slug}"
            )

        assert warnings == [
            f"Warning Will Robinson (will-rob); see {url('will-rob')}",
            f"Warning, warning 2! (second-one); see {url('second-one')}",
        ]

    def test_source_and_include_dont_conflict(self) -> None:
        # A bad fix made this case fail: https://github.com/coveragepy/coveragepy/issues/541
        self.make_file("a.py", "import b\na = 1")
        self.make_file("b.py", "b = 1")
        self.make_file(
            ".coveragerc",
            """\
            [run]
            source = .
            """,
        )

        # Just like: coverage run a.py
        cov = coverage.Coverage()
        self.start_import_stop(cov, "a")
        cov.save()

        # Run the equivalent of: coverage report --include=b.py
        cov = coverage.Coverage(include=["b.py"])
        cov.load()
        # There should be no exception. At one point, report() threw:
        # CoverageException: --include and --source are mutually exclusive
        cov.report()
        expected = textwrap.dedent("""\
            Name    Stmts   Miss  Cover
            ---------------------------
            b.py        1      0   100%
            ---------------------------
            TOTAL       1      0   100%
            """)
        assert expected == self.stdout()

    def test_config_crash(self) -> None:
        # The internal '[run] _crash' setting can be used to artificially raise
        # exceptions from inside Coverage.
        cov = coverage.Coverage()
        cov.set_option("run:_crash", "test_config_crash")
        with pytest.raises(Exception, match="Crashing because called by test_config_crash"):
            cov.start()

    def test_config_crash_no_crash(self) -> None:
        # '[run] _crash' really checks the call stack.
        cov = coverage.Coverage()
        cov.set_option("run:_crash", "not_my_caller")
        cov.start()
        cov.stop()

    def test_run_debug_sys(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/907
        cov = coverage.Coverage()
        with cov.collect():
            d = dict(cov.sys_info())
        assert cast(str, d["data_file"]).endswith(".coverage")


@pytest.mark.skipif(not testenv.DYN_CONTEXTS, reason="No dynamic contexts with this core.")
class SwitchContextTest(CoverageTest):
    """Tests of the .switch_context() method."""

    def make_test_files(self) -> None:
        """Create a simple file representing a method with two tests."""
        self.make_file(
            "testsuite.py",
            """\
            def timestwo(x):
                return x*2

            def test_multiply_zero():
                assert timestwo(0) == 0

            def test_multiply_six():
                assert timestwo(6) == 12
            """,
        )

    def test_switch_context_testrunner(self) -> None:
        # This test simulates a coverage-aware test runner,
        # measuring labeled coverage via public API
        self.make_test_files()

        # Test runner starts
        cov = coverage.Coverage()
        with cov.collect():
            # Imports the test suite
            suite = import_local_file("testsuite")

            # Measures test case 1
            cov.switch_context("multiply_zero")
            suite.test_multiply_zero()

            # Measures test case 2
            cov.switch_context("multiply_six")
            suite.test_multiply_six()

            # Runner finishes
            cov.save()

        # Labeled data is collected
        data = cov.get_data()
        assert ["", "multiply_six", "multiply_zero"] == sorted(data.measured_contexts())

        filenames = self.get_measured_filenames(data)
        suite_filename = filenames["testsuite.py"]

        data.set_query_context("multiply_six")
        assert [2, 8] == sorted_lines(data, suite_filename)
        data.set_query_context("multiply_zero")
        assert [2, 5] == sorted_lines(data, suite_filename)

    def test_switch_context_with_static(self) -> None:
        # This test simulates a coverage-aware test runner,
        # measuring labeled coverage via public API,
        # with static label prefix.
        self.make_test_files()

        # Test runner starts
        cov = coverage.Coverage(context="mysuite")
        with cov.collect():
            # Imports the test suite
            suite = import_local_file("testsuite")

            # Measures test case 1
            cov.switch_context("multiply_zero")
            suite.test_multiply_zero()

            # Measures test case 2
            cov.switch_context("multiply_six")
            suite.test_multiply_six()

            # Runner finishes
            cov.save()

        # Labeled data is collected
        data = cov.get_data()
        expected = ["mysuite", "mysuite|multiply_six", "mysuite|multiply_zero"]
        assert expected == sorted(data.measured_contexts())

        filenames = self.get_measured_filenames(data)
        suite_filename = filenames["testsuite.py"]

        data.set_query_context("mysuite|multiply_six")
        assert [2, 8] == sorted_lines(data, suite_filename)
        data.set_query_context("mysuite|multiply_zero")
        assert [2, 5] == sorted_lines(data, suite_filename)

    def test_dynamic_context_conflict(self) -> None:
        cov = coverage.Coverage(source=["."])
        cov.set_option("run:dynamic_context", "test_function")
        with cov.collect():
            with pytest.warns(Warning) as warns:
                # Switch twice, but only get one warning.
                cov.switch_context("test1")
                cov.switch_context("test2")
        assert_coverage_warnings(warns, "Conflicting dynamic contexts (dynamic-conflict)")

    def test_unknown_dynamic_context(self) -> None:
        cov = coverage.Coverage()
        cov.set_option("run:dynamic_context", "no-idea")
        with pytest.raises(Exception, match="Don't understand dynamic_context setting: 'no-idea'"):
            cov.start()

    def test_switch_context_unstarted(self) -> None:
        # Coverage must be started to switch context
        msg = "Cannot switch context, coverage is not started"
        cov = coverage.Coverage()
        with pytest.raises(CoverageException, match=msg):
            cov.switch_context("test1")

        with cov.collect():
            cov.switch_context("test2")

        with pytest.raises(CoverageException, match=msg):
            cov.switch_context("test3")


class CurrentInstanceTest(CoverageTest):
    """Tests of Coverage.current()."""

    run_in_temp_dir = False

    def assert_current_is_none(self, current: Coverage | None) -> None:
        """Assert that a current we expect to be None is correct."""
        # During meta-coverage, the None answers will be wrong because the
        # overall coverage measurement will still be on the current-stack.
        # Since we know they will be wrong, and we have non-meta test runs
        # also, don't assert them.
        if not env.METACOV:
            assert current is None

    def test_current(self) -> None:
        cur0 = coverage.Coverage.current()
        self.assert_current_is_none(cur0)
        # Making an instance doesn't make it current.
        cov = coverage.Coverage()
        cur1 = coverage.Coverage.current()
        self.assert_current_is_none(cur1)
        assert cur0 is cur1
        # Starting the instance makes it current.
        with cov.collect():
            cur2 = coverage.Coverage.current()
            assert cur2 is cov
            # Stopping the instance makes current None again.

        cur3 = coverage.Coverage.current()
        self.assert_current_is_none(cur3)
        assert cur0 is cur3


class NamespaceModuleTest(UsingModulesMixin, CoverageTest):
    """Test PEP-420 namespace modules."""

    def test_explicit_namespace_module(self) -> None:
        self.make_file("main.py", "import namespace_420\n")

        cov = coverage.Coverage()
        self.start_import_stop(cov, "main")

        with pytest.raises(CoverageException, match=r"Module .* has no file"):
            cov.analysis(sys.modules["namespace_420"])

    def test_bug_572(self) -> None:
        self.make_file("main.py", "import namespace_420\n")

        # Use source=namespace_420 to trigger the check that used to fail,
        # and use source=main so that something is measured.
        cov = coverage.Coverage(source=["namespace_420", "main"])
        with self.assert_warnings(cov, []):
            self.start_import_stop(cov, "main")
            cov.report()


class IncludeOmitTestsMixin(UsingModulesMixin, CoverageTest):
    """Test methods for coverage methods taking include and omit."""

    # An abstract method for subclasses to define, to appease mypy.
    def coverage_usepkgs(self, **kwargs_unused: TCovKwargs) -> Iterable[str]:
        """Run coverage on usepkgs, return a line summary. kwargs are for Coverage(**kwargs)."""
        raise NotImplementedError()  # pragma: not covered

    def filenames_in(self, summary: Iterable[str], filenames: str) -> None:
        """Assert the `filenames` are in the `summary`."""
        for filename in filenames.split():
            assert filename in summary

    def filenames_not_in(self, summary: Iterable[str], filenames: str) -> None:
        """Assert the `filenames` are not in the `summary`."""
        for filename in filenames.split():
            assert filename not in summary

    def test_nothing_specified(self) -> None:
        result = self.coverage_usepkgs()
        self.filenames_in(result, "p1a p1b p2a p2b othera otherb osa osb")
        self.filenames_not_in(result, "p1c")
        # Because there was no source= specified, we don't search for
        # un-executed files.

    def test_include(self) -> None:
        result = self.coverage_usepkgs(include=["*/p1a.py"])
        self.filenames_in(result, "p1a")
        self.filenames_not_in(result, "p1b p1c p2a p2b othera otherb osa osb")

    def test_include_2(self) -> None:
        result = self.coverage_usepkgs(include=["*a.py"])
        self.filenames_in(result, "p1a p2a othera osa")
        self.filenames_not_in(result, "p1b p1c p2b otherb osb")

    def test_include_as_string(self) -> None:
        result = self.coverage_usepkgs(include="*a.py")
        self.filenames_in(result, "p1a p2a othera osa")
        self.filenames_not_in(result, "p1b p1c p2b otherb osb")

    def test_omit(self) -> None:
        result = self.coverage_usepkgs(omit=["*/p1a.py"])
        self.filenames_in(result, "p1b p2a p2b")
        self.filenames_not_in(result, "p1a p1c")

    def test_omit_2(self) -> None:
        result = self.coverage_usepkgs(omit=["*a.py"])
        self.filenames_in(result, "p1b p2b otherb osb")
        self.filenames_not_in(result, "p1a p1c p2a othera osa")

    def test_omit_as_string(self) -> None:
        result = self.coverage_usepkgs(omit="*a.py")
        self.filenames_in(result, "p1b p2b otherb osb")
        self.filenames_not_in(result, "p1a p1c p2a othera osa")

    def test_omit_and_include(self) -> None:
        result = self.coverage_usepkgs(include=["*/p1*"], omit=["*/p1a.py"])
        self.filenames_in(result, "p1b")
        self.filenames_not_in(result, "p1a p1c p2a p2b")


class SourceIncludeOmitTest(IncludeOmitTestsMixin, CoverageTest):
    """Test using `source`, `include`, and `omit` when measuring code."""

    def setUp(self) -> None:
        super().setUp()

        # These tests use the TESTS_DIR/modules files, but they cd into it. To
        # keep tests from cross-contaminating, we make a copy of the files.
        # Since we need to import from there, we also add it to the beginning
        # of sys.path.

        shutil.copytree(
            nice_file(TESTS_DIR, "modules"),
            "tests_dir_modules",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        sys.path.insert(0, abs_file("tests_dir_modules"))

    def coverage_usepkgs_counts(self, **kwargs: TCovKwargs) -> dict[str, int]:
        """Run coverage on usepkgs and return a line summary.

        Arguments are passed to the `coverage.Coverage` constructor.

        """
        cov = coverage.Coverage(**kwargs)
        with cov.collect():
            import usepkgs  # pylint: disable=import-error, unused-import
        with self.assert_warnings(cov, []):
            data = cov.get_data()
        summary = line_counts(data)
        for k, v in list(summary.items()):
            assert k.endswith(".py")
            summary[k[:-3]] = v
        return summary

    def coverage_usepkgs(self, **kwargs: TCovKwargs) -> Iterable[str]:
        summary = self.coverage_usepkgs_counts(**kwargs)
        return list(summary)

    def test_source_include_exclusive(self) -> None:
        cov = coverage.Coverage(source=["pkg1"], include=["pkg2"])
        with self.assert_warnings(cov, ["--include is ignored because --source is set"]):
            cov.start()
        cov.stop()

    def test_source_package_as_package(self) -> None:
        assert not os.path.isdir("pkg1")
        lines = self.coverage_usepkgs_counts(source=["pkg1"])
        self.filenames_in(list(lines), "p1a p1b")
        self.filenames_not_in(list(lines), "p2a p2b othera otherb osa osb")
        # Because source= was specified, we do search for un-executed files.
        assert lines["p1c"] == 0

    def test_source_package_as_dir(self) -> None:
        os.chdir("tests_dir_modules")
        assert os.path.isdir("pkg1")
        lines = self.coverage_usepkgs_counts(source=["pkg1"])
        self.filenames_in(list(lines), "p1a p1b")
        self.filenames_not_in(list(lines), "p2a p2b othera otherb osa osb")
        # Because source= was specified, we do search for un-executed files.
        assert lines["p1c"] == 0

    def test_source_package_dotted_sub(self) -> None:
        lines = self.coverage_usepkgs_counts(source=["pkg1.sub"])
        self.filenames_not_in(list(lines), "p2a p2b othera otherb osa osb")
        # Because source= was specified, we do search for un-executed files.
        assert lines["runmod3"] == 0

    def test_source_package_dotted_p1b(self) -> None:
        lines = self.coverage_usepkgs_counts(source=["pkg1.p1b"])
        self.filenames_in(list(lines), "p1b")
        self.filenames_not_in(list(lines), "p1a p1c p2a p2b othera otherb osa osb")

    def test_source_package_part_omitted(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/218
        # Used to be if you omitted something executed and inside the source,
        # then after it was executed but not recorded, it would be found in
        # the search for un-executed files, and given a score of 0%.

        # The omit arg is by path, so need to be in the modules directory.
        os.chdir("tests_dir_modules")
        lines = self.coverage_usepkgs_counts(source=["pkg1"], omit=["pkg1/p1b.py"])
        self.filenames_in(list(lines), "p1a")
        self.filenames_not_in(list(lines), "p1b")
        assert lines["p1c"] == 0

    def test_source_package_as_package_part_omitted(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/638
        lines = self.coverage_usepkgs_counts(source=["pkg1"], omit=["*/p1b.py"])
        self.filenames_in(list(lines), "p1a")
        self.filenames_not_in(list(lines), "p1b")
        assert lines["p1c"] == 0

    def test_ambiguous_source_package_as_dir(self) -> None:
        # pkg1 is a directory and a pkg, since we cd into tests_dir_modules/ambiguous
        os.chdir("tests_dir_modules/ambiguous")
        # pkg1 defaults to directory because tests_dir_modules/ambiguous/pkg1 exists
        lines = self.coverage_usepkgs_counts(source=["pkg1"])
        self.filenames_in(list(lines), "ambiguous")
        self.filenames_not_in(list(lines), "p1a p1b p1c")

    def test_ambiguous_source_package_as_package(self) -> None:
        # pkg1 is a directory and a pkg, since we cd into tests_dir_modules/ambiguous
        os.chdir("tests_dir_modules/ambiguous")
        lines = self.coverage_usepkgs_counts(source_pkgs=["pkg1"])
        self.filenames_in(list(lines), "p1a p1b")
        self.filenames_not_in(list(lines), "p2a p2b othera otherb osa osb ambiguous")
        # Because source= was specified, we do search for un-executed files.
        assert lines["p1c"] == 0

    def test_source_dirs(self) -> None:
        os.chdir("tests_dir_modules")
        assert os.path.isdir("pkg1")
        lines = self.coverage_usepkgs_counts(source_dirs=["pkg1"])
        self.filenames_in(list(lines), "p1a p1b")
        self.filenames_not_in(list(lines), "p2a p2b othera otherb osa osb")
        # Because source_dirs= was specified, we do search for un-executed files.
        assert lines["p1c"] == 0

    def test_non_existent_source_dir(self) -> None:
        with pytest.raises(
            ConfigError,
            match=re.escape("Source dir is not a directory: 'i-do-not-exist'"),
        ):
            self.coverage_usepkgs_counts(source_dirs=["i-do-not-exist"])


class ReportIncludeOmitTest(IncludeOmitTestsMixin, CoverageTest):
    """Tests of the report include/omit functionality."""

    def coverage_usepkgs(self, **kwargs: TCovKwargs) -> Iterable[str]:
        """Try coverage.report()."""
        cov = coverage.Coverage()
        with cov.collect():
            import usepkgs  # pylint: disable=import-error, unused-import
        report = io.StringIO()
        cov.report(file=report, **kwargs)
        return report.getvalue()


class XmlIncludeOmitTest(IncludeOmitTestsMixin, CoverageTest):
    """Tests of the XML include/omit functionality.

    This also takes care of the HTML and annotate include/omit, by virtue
    of the structure of the code.

    """

    def coverage_usepkgs(self, **kwargs: TCovKwargs) -> Iterable[str]:
        """Try coverage.xml_report()."""
        cov = coverage.Coverage()
        with cov.collect():
            import usepkgs  # pylint: disable=import-error, unused-import
        cov.xml_report(outfile="-", **kwargs)
        return self.stdout()


class AnalysisTest(CoverageTest):
    """Test the numerical analysis of results."""

    def test_many_missing_branches(self) -> None:
        cov = coverage.Coverage(branch=True)

        self.make_file(
            "missing.py",
            """\
            def fun1(x):
                if x == 1:
                    print("one")
                else:
                    print("not one")
                print("done")           # pragma: nocover

            def fun2(x):
                if x:
                    print("x")
                else:
                    print("not x")

            fun2(3)
            """,
        )

        # Import the Python file, executing it.
        self.start_import_stop(cov, "missing")

        nums = cov._analyze("missing.py").numbers
        assert nums.n_files == 1
        assert nums.n_statements == 9
        assert nums.n_excluded == 1
        assert nums.n_missing == 4
        assert nums.n_branches == 4
        assert nums.n_partial_branches == 1
        assert nums.n_missing_branches == 3

        filename, statements, excluded, missing, missing_formatted = cov.analysis2("missing.py")
        assert os.path.relpath(filename) == "missing.py"
        assert statements == [1, 2, 3, 5, 8, 9, 10, 12, 14]
        assert excluded == [6]
        assert missing == [2, 3, 5, 12]
        assert missing_formatted == "2-5, 12"

        branch_stats = cov.branch_stats("missing.py")
        assert branch_stats == {2: (2, 0), 9: (2, 1)}


class TestRunnerPluginTest(CoverageTest):
    """Test that the API works properly the way various third-party plugins call it.

    We don't actually use the plugins, but these tests call the API the same
    way they do.

    """

    @pytest.mark.parametrize("erase, cd", [(False, False), (True, False), (False, True)])
    def test_pretend_to_be_nose_with_cover(self, erase: bool, cd: bool) -> None:
        """This is what the nose --with-cover plugin does."""
        self.make_file(
            "no_biggie.py",
            """\
            a = 1
            b = 2
            if b == 1:
                c = 4
            """,
        )
        self.make_file("sub/hold.txt", "")

        cov = coverage.Coverage()
        if erase:
            cov.combine()
            cov.erase()
        cov.load()
        self.start_import_stop(cov, "no_biggie")
        if cd:
            os.chdir("sub")
        cov.combine()
        cov.save()
        cov.report(["no_biggie.py"], show_missing=True)
        assert self.stdout() == textwrap.dedent("""\
            Name           Stmts   Miss  Cover   Missing
            --------------------------------------------
            no_biggie.py       4      1    75%   4
            --------------------------------------------
            TOTAL              4      1    75%
            """)
        if cd:
            os.chdir("..")

    @pytest.mark.parametrize("append", [False, True])
    def test_pretend_to_be_pytestcov(self, append: bool) -> None:
        """Act like pytest-cov."""
        self.make_file(
            "prog.py",
            """\
            a = 1
            b = 2
            if b == 1:
                c = 4
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            parallel = True
            source = .
            """,
        )

        cov = coverage.Coverage(source=None, branch=None, config_file=".coveragerc")
        if append:
            cov.load()
        else:
            cov.erase()
        self.start_import_stop(cov, "prog")
        cov.combine()
        cov.save()
        report = io.StringIO()
        cov.report(
            show_missing=None, ignore_errors=True, file=report, skip_covered=None, skip_empty=None
        )
        assert report.getvalue() == textwrap.dedent("""\
            Name      Stmts   Miss  Cover
            -----------------------------
            prog.py       4      1    75%
            -----------------------------
            TOTAL         4      1    75%
            """)
        self.assert_file_count(".coverage", 0)
        self.assert_file_count(".coverage.*", 1)


class ImmutableConfigTest(CoverageTest):
    """Check that reporting methods don't permanently change the configuration."""

    def test_config_doesnt_change(self) -> None:
        self.make_file("simple.py", "a = 1")
        cov = coverage.Coverage()
        self.start_import_stop(cov, "simple")
        assert cov.get_option("report:show_missing") is False
        cov.report(show_missing=True)
        assert cov.get_option("report:show_missing") is False


class RelativePathTest(CoverageTest):
    """Tests of the relative_files setting."""

    def test_moving_stuff(self) -> None:
        # When using absolute file names, moving the source around results in
        # "No source for code" errors while reporting.
        self.make_file("foo.py", "a = 1")
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "foo")
        res = cov.report()
        assert res == 100

        expected = re.escape("No source for code: '{}'.".format(abs_file("foo.py")))
        os.remove("foo.py")
        self.make_file("new/foo.py", "a = 1")
        shutil.move(".coverage", "new/.coverage")
        with change_dir("new"):
            cov = coverage.Coverage()
            cov.load()
            with pytest.raises(NoSource, match=expected):
                cov.report()

    def test_moving_stuff_with_relative(self) -> None:
        # When using relative file names, moving the source around is fine.
        self.make_file("foo.py", "a = 1")
        self.make_file(
            ".coveragerc",
            """\
            [run]
            relative_files = true
            """,
        )
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "foo")
        res = cov.report()
        assert res == 100

        os.remove("foo.py")
        self.make_file("new/foo.py", "a = 1")
        shutil.move(".coverage", "new/.coverage")
        shutil.move(".coveragerc", "new/.coveragerc")
        with change_dir("new"):
            cov = coverage.Coverage()
            cov.load()
            res = cov.report()
            assert res == 100

    def test_combine_relative(self) -> None:
        self.make_file(
            "foo.py",
            """\
            import mod
            a = 1
            """,
        )
        self.make_file("lib/mod/__init__.py", "x = 1")
        self.make_file(
            ".coveragerc",
            """\
            [run]
            relative_files = true
            """,
        )
        sys.path.append("lib")
        cov = coverage.Coverage(source=["."], data_suffix=True)
        self.start_import_stop(cov, "foo")
        cov.save()

        self.make_file("dir2/bar.py", "a = 1")
        self.make_file(
            "dir2/.coveragerc",
            """\
            [run]
            relative_files = true
            """,
        )
        with change_dir("dir2"):
            cov = coverage.Coverage(source=["."], data_suffix=True)
            self.start_import_stop(cov, "bar")
            cov.save()
            shutil.move(glob.glob(".coverage.*")[0], "..")

        self.make_file("foo.py", "a = 1")
        self.make_file("bar.py", "a = 1")
        self.make_file("modsrc/__init__.py", "x = 1")

        self.make_file(
            ".coveragerc",
            """\
            [run]
            relative_files = true
            [paths]
            source =
                modsrc
                */mod
            """,
        )
        cov = coverage.Coverage()
        cov.combine()
        cov.save()

        cov = coverage.Coverage()
        cov.load()
        files = cov.get_data().measured_files()
        assert files == {"foo.py", "bar.py", os_sep("modsrc/__init__.py")}
        res = cov.report()
        assert res == 100

    def test_combine_no_suffix_multiprocessing(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [run]
            branch = True
            """,
        )
        cov = coverage.Coverage(
            config_file=".coveragerc",
            concurrency="multiprocessing",
            data_suffix=False,
        )
        cov.start()
        cov.stop()
        # The warning isn't the point of this test, but suppress it.
        with pytest.warns(Warning) as warns:
            cov.combine()
        assert_coverage_warnings(warns, "No data was collected. (no-data-collected)")
        cov.save()
        self.assert_file_count(".coverage.*", 0)
        self.assert_exists(".coverage")

    def test_files_up_one_level(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1280
        self.make_file(
            "src/mycode.py",
            """\
            def foo():
                return 17
            """,
        )
        self.make_file(
            "test/test_it.py",
            """\
            from src.mycode import foo
            assert foo() == 17
            """,
        )
        self.make_file(
            "test/.coveragerc",
            """\
            [run]
            parallel = True
            relative_files = True

            [paths]
            source =
                ../src/
                */src
            """,
        )
        os.chdir("test")
        sys.path.insert(0, "..")
        cov1 = coverage.Coverage()
        self.start_import_stop(cov1, "test_it")
        cov1.save()
        cov2 = coverage.Coverage()
        cov2.combine()
        cov3 = coverage.Coverage()
        cov3.load()
        report = self.get_report(cov3)
        assert self.last_line_squeezed(report) == "TOTAL 4 0 100%"


class CombiningTest(CoverageTest):
    """More tests of combining data."""

    B_LINES = {"b_or_c.py": [1, 2, 3, 4, 8, 9]}
    C_LINES = {"b_or_c.py": [1, 2, 3, 6, 7, 8, 9]}

    def make_b_or_c_py(self) -> None:
        """Create b_or_c.py, used in a few of these tests."""
        # "b_or_c.py b" will run 6 lines.
        # "b_or_c.py c" will run 7 lines.
        # Together, they run 8 lines.
        self.make_file(
            "b_or_c.py",
            """\
            import sys
            a = 2
            if sys.argv[1] == 'b':
                b = 4
            else:
                c = 6
                c2 = 7
            d = 8
            print('done')
            """,
        )

    def test_combine_parallel_data(self) -> None:
        self.make_b_or_c_py()
        self.make_data_file(".coverage.b", lines=self.B_LINES)
        self.make_data_file(".coverage.c", lines=self.C_LINES)

        # Combine the parallel coverage data files into .coverage .
        cov = coverage.Coverage()
        cov.combine(strict=True)
        self.assert_exists(".coverage")

        # After combining, there should be only the .coverage file.
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage file and see that b_or_c.py has all 8 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

        # Running combine again should fail, because there are no parallel data
        # files to combine.
        cov = coverage.Coverage()
        with pytest.raises(NoDataError, match=r"No data to combine"):
            cov.combine(strict=True)

        # And the originally combined data is still there.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

    def test_combine_parallel_data_with_a_corrupt_file(self) -> None:
        self.make_b_or_c_py()
        self.make_data_file(".coverage.b", lines=self.B_LINES)
        self.make_data_file(".coverage.c", lines=self.C_LINES)

        # Make a bogus data file.
        self.make_file(".coverage.bad", "This isn't a coverage data file.")

        # Combine the parallel coverage data files into .coverage .
        cov = coverage.Coverage()
        with pytest.warns(Warning) as warns:
            cov.combine(strict=True)
        assert_coverage_warnings(
            warns,
            re.compile(
                r"Couldn't use data file '.*[/\\]\.coverage\.bad': " + BAD_SQLITE_REGEX,
            ),
        )

        # After combining, those two should be the only data files.
        self.assert_exists(".coverage")
        self.assert_exists(".coverage.bad")
        self.assert_file_count(".coverage.*", 1)

        # Read the coverage file and see that b_or_c.py has all 8 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

    def test_combine_no_usable_files(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/629
        self.make_b_or_c_py()
        self.make_data_file(".coverage", lines=self.B_LINES)

        # Make bogus data files.
        self.make_file(".coverage.bad1", "This isn't a coverage data file.")
        self.make_file(".coverage.bad2", "This isn't a coverage data file either.")

        # Combine the parallel coverage data files into .coverage, but nothing is readable.
        cov = coverage.Coverage()
        with pytest.warns(Warning) as warns:
            with pytest.raises(NoDataError, match=r"No usable data files"):
                cov.combine(strict=True)

        warn_rx = re.compile(
            r"Couldn't use data file '.*[/\\]\.coverage\.bad[12]': " + BAD_SQLITE_REGEX,
        )
        assert_coverage_warnings(warns, warn_rx, warn_rx)

        # After combining, we should have a main file and two parallel files.
        self.assert_exists(".coverage")
        self.assert_exists(".coverage.bad1")
        self.assert_exists(".coverage.bad2")
        self.assert_file_count(".coverage.*", 2)

        # Read the coverage file and see that b_or_c.py has 6 lines
        # executed (we only did b, not c).
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 6

    def test_combine_parallel_data_in_two_steps(self) -> None:
        self.make_b_or_c_py()
        self.make_data_file(".coverage.b", lines=self.B_LINES)

        # Combine the (one) parallel coverage data file into .coverage .
        cov = coverage.Coverage()
        cov.combine(strict=True)

        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        self.make_data_file(".coverage.c", lines=self.C_LINES)
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 1)

        # Combine the parallel coverage data files into .coverage .
        cov = coverage.Coverage()
        cov.load()
        cov.combine(strict=True)

        # After combining, there should be only the .coverage file.
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage file and see that b_or_c.py has all 8 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

    def test_combine_parallel_data_no_append(self) -> None:
        self.make_b_or_c_py()
        self.make_data_file(".coverage.b", lines=self.B_LINES)

        # Combine the (one) parallel coverage data file into .coverage .
        cov = coverage.Coverage()
        cov.combine(strict=True)
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        self.make_data_file(".coverage.c", lines=self.C_LINES)

        # Combine the parallel coverage data files into .coverage, but don't
        # use the data in .coverage already.
        cov = coverage.Coverage()
        cov.combine(strict=True)

        # After combining, there should be only the .coverage file.
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage file and see that b_or_c.py has only 7 lines
        # because we didn't keep the data from running b.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 7

    def test_combine_parallel_data_keep(self) -> None:
        self.make_b_or_c_py()
        self.make_data_file(".coverage.b", lines=self.B_LINES)
        self.make_data_file(".coverage.c", lines=self.C_LINES)

        # Combine the parallel coverage data files into .coverage with the keep flag.
        cov = coverage.Coverage()
        cov.combine(strict=True, keep=True)

        # After combining, the .coverage file & the original combined file should still be there.
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 2)

    @pytest.mark.parametrize("abs_order, rel_order", [(1, 2), (2, 1)])
    def test_combine_absolute_then_relative_1752(self, abs_order: int, rel_order: int) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1752
        # If we're combining a relative data file and an absolute data file,
        # the absolutes were made relative only if the relative file name was
        # encountered first.  Test combining in both orders and check that the
        # absolute file name is properly relative in either order.
        FILE = "sub/myprog.py"
        self.make_file(FILE, "a = 1")

        self.make_data_file(suffix=f"{abs_order}.abs", lines={abs_file(FILE): [1]})
        self.make_data_file(suffix=f"{rel_order}.rel", lines={FILE: [1]})

        self.make_file(".coveragerc", "[run]\nrelative_files = True\n")
        cov = coverage.Coverage()
        cov.combine()
        data = coverage.CoverageData()
        data.read()
        assert {os_sep("sub/myprog.py")} == data.measured_files()
