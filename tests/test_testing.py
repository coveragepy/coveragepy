# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests that our test infrastructure is really working!"""

from __future__ import annotations

import datetime
import os
import re
import sys
import warnings


import pytest

import coverage
from coverage.exceptions import CoverageWarning
from coverage.files import actual_path
from coverage.types import TArc

from tests.coveragetest import CoverageTest
from tests.helpers import (
    CheckUniqueFilenames,
    FailingProxy,
    all_our_source_files,
    arcz_to_arcs,
    assert_count_equal,
    assert_coverage_warnings,
    re_lines,
    re_lines_text,
    re_line,
)


def test_assert_count_equal() -> None:
    assert_count_equal(set(), set())
    assert_count_equal({"a": 1, "b": 2}, ["b", "a"])
    with pytest.raises(AssertionError):
        assert_count_equal({1, 2, 3}, set())
    with pytest.raises(AssertionError):
        assert_count_equal({1, 2, 3}, {4, 5, 6})


class CoverageTestTest(CoverageTest):
    """Test the methods in `CoverageTest`."""

    def test_file_exists(self) -> None:
        self.make_file("whoville.txt", "We are here!")
        self.assert_exists("whoville.txt")
        self.assert_doesnt_exist("shadow.txt")
        msg = "File 'whoville.txt' shouldn't exist"
        with pytest.raises(AssertionError, match=msg):
            self.assert_doesnt_exist("whoville.txt")
        msg = "File 'shadow.txt' should exist"
        with pytest.raises(AssertionError, match=msg):
            self.assert_exists("shadow.txt")

    def test_file_count(self) -> None:
        self.make_file("abcde.txt", "abcde")
        self.make_file("axczz.txt", "axczz")
        self.make_file("afile.txt", "afile")
        self.assert_file_count("a*.txt", 3)
        self.assert_file_count("*c*.txt", 2)
        self.assert_file_count("afile.*", 1)
        self.assert_file_count("*.q", 0)
        msg = re.escape(
            "There should be 13 files matching 'a*.txt', but there are these: "
            + "['abcde.txt', 'afile.txt', 'axczz.txt']",
        )
        with pytest.raises(AssertionError, match=msg):
            self.assert_file_count("a*.txt", 13)
        msg = re.escape(
            "There should be 12 files matching '*c*.txt', but there are these: "
            + "['abcde.txt', 'axczz.txt']",
        )
        with pytest.raises(AssertionError, match=msg):
            self.assert_file_count("*c*.txt", 12)
        msg = re.escape(
            "There should be 11 files matching 'afile.*', but there are these: ['afile.txt']",
        )
        with pytest.raises(AssertionError, match=msg):
            self.assert_file_count("afile.*", 11)
        msg = re.escape(
            "There should be 10 files matching '*.q', but there are these: []",
        )
        with pytest.raises(AssertionError, match=msg):
            self.assert_file_count("*.q", 10)

    def test_assert_recent_datetime(self) -> None:
        def now_delta(seconds: int) -> datetime.datetime:
            """Make a datetime `seconds` seconds from now."""
            return datetime.datetime.now() + datetime.timedelta(seconds=seconds)

        # Default delta is 10 seconds.
        self.assert_recent_datetime(now_delta(0))
        self.assert_recent_datetime(now_delta(-9))
        with pytest.raises(AssertionError):
            self.assert_recent_datetime(now_delta(-11))
        with pytest.raises(AssertionError):
            self.assert_recent_datetime(now_delta(1))

        # Delta is settable.
        self.assert_recent_datetime(now_delta(0), seconds=120)
        self.assert_recent_datetime(now_delta(-100), seconds=120)
        with pytest.raises(AssertionError):
            self.assert_recent_datetime(now_delta(-1000), seconds=120)
        with pytest.raises(AssertionError):
            self.assert_recent_datetime(now_delta(1), seconds=120)

    def test_assert_warnings(self) -> None:
        cov = coverage.Coverage()

        # Make a warning, it should catch it properly.
        with self.assert_warnings(cov, ["Hello there!"]):
            cov._warn("Hello there!")

        # The expected warnings are regexes.
        with self.assert_warnings(cov, ["Hello.*!"]):
            cov._warn("Hello there!")

        # There can be a bunch of actual warnings.
        with self.assert_warnings(cov, ["Hello.*!"]):
            cov._warn("You there?")
            cov._warn("Hello there!")

        # There can be a bunch of expected warnings.
        with self.assert_warnings(cov, ["Hello.*!", "You"]):
            cov._warn("You there?")
            cov._warn("Hello there!")

        # But if there are a bunch of expected warnings, they have to all happen.
        warn_regex = r"Didn't find warning 'You' in \['Hello there!'\]"
        with pytest.raises(AssertionError, match=warn_regex):
            with self.assert_warnings(cov, ["Hello.*!", "You"]):
                cov._warn("Hello there!")

        # Make a different warning than expected, it should raise an assertion.
        warn_regex = r"Didn't find warning 'Not me' in \['Hello there!'\]"
        with pytest.raises(AssertionError, match=warn_regex):
            with self.assert_warnings(cov, ["Not me"]):
                cov._warn("Hello there!")

        # Try checking a warning that shouldn't appear: happy case.
        with self.assert_warnings(cov, ["Hi"], not_warnings=["Bye"]):
            cov._warn("Hi")

        # But it should fail if the unexpected warning does appear.
        warn_regex = r"Found warning 'Bye' in \['Hi', 'Bye'\]"
        with pytest.raises(AssertionError, match=warn_regex):
            with self.assert_warnings(cov, ["Hi"], not_warnings=["Bye"]):
                cov._warn("Hi")
                cov._warn("Bye")

        # assert_warnings shouldn't hide a real exception.
        with pytest.raises(ZeroDivisionError, match="oops"):
            with self.assert_warnings(cov, ["Hello there!"]):
                raise ZeroDivisionError("oops")

    def test_assert_no_warnings(self) -> None:
        cov = coverage.Coverage()

        # Happy path: no warnings.
        with self.assert_warnings(cov, []):
            pass

        # If you said there would be no warnings, and there were, fail!
        warn_regex = r"Unexpected warnings: \['Watch out!'\]"
        with pytest.raises(AssertionError, match=warn_regex):
            with self.assert_warnings(cov, []):
                cov._warn("Watch out!")

    def test_sub_python_is_this_python(self) -> None:
        # Try it with a Python command.
        self.set_environ("COV_FOOBAR", "XYZZY")
        self.make_file(
            "showme.py",
            """\
            import os, sys
            print(sys.executable)
            print(os.__file__)
            print(os.environ['COV_FOOBAR'])
            """,
        )
        out_lines = self.run_command("python showme.py").splitlines()
        assert actual_path(out_lines[0]) == actual_path(sys.executable)
        assert out_lines[1] == os.__file__
        assert out_lines[2] == "XYZZY"

        # Try it with a "coverage debug sys" command.
        out = self.run_command("coverage debug sys")

        executable = re_line("executable:", out)
        executable = executable.split(":", 1)[1].strip()
        assert _same_python_executable(executable, sys.executable)

        # "environment: COV_FOOBAR = XYZZY" or "COV_FOOBAR = XYZZY"
        environ = re_line("COV_FOOBAR", out)
        _, _, environ = environ.rpartition(":")
        assert environ.strip() == "COV_FOOBAR = XYZZY"

    def test_run_command_stdout_stderr(self) -> None:
        # run_command should give us both stdout and stderr.
        self.make_file(
            "outputs.py",
            """\
            import sys
            sys.stderr.write("StdErr\\n")
            print("StdOut")
            """,
        )
        out = self.run_command("python outputs.py")
        assert "StdOut\n" in out
        assert "StdErr\n" in out

    def test_stdout(self) -> None:
        # stdout is captured.
        print("This is stdout")
        print("Line 2")
        assert self.stdout() == "This is stdout\nLine 2\n"
        # When we grab stdout(), it's reset.
        print("Some more")
        assert self.stdout() == "Some more\n"


class CheckUniqueFilenamesTest(CoverageTest):
    """Tests of CheckUniqueFilenames."""

    run_in_temp_dir = False

    class Stub:
        """A stand-in for the class we're checking."""

        def __init__(self, x: int) -> None:
            self.x = x

        def method(
            self,
            filename: str,
            a: int = 17,
            b: str = "hello",
        ) -> tuple[int, str, int, str]:
            """The method we'll wrap, with args to be sure args work."""
            return (self.x, filename, a, b)

    def test_detect_duplicate(self) -> None:
        stub = self.Stub(23)
        CheckUniqueFilenames.hook(stub, "method")

        # Two method calls with different names are fine.
        assert stub.method("file1") == (23, "file1", 17, "hello")
        assert stub.method("file2", 1723, b="what") == (23, "file2", 1723, "what")

        # A duplicate file name trips an assertion.
        with pytest.raises(AssertionError):
            stub.method("file1")


class CheckCoverageTest(CoverageTest):
    """Tests of the failure assertions in check_coverage."""

    CODE = """\
        a, b = 1, 1
        def oops(x):
            if x % 2:
                raise Exception("odd")
        try:
            a = 6
            oops(1)
            a = 8
        except:
            b = 10
        assert a == 6 and b == 10
        """
    BRANCHZ = "34 3-2"
    BRANCHZ_MISSING = "3-2"

    def test_check_coverage_possible_branches(self) -> None:
        msg = "Wrong possible branches: [(7, -2), (7, 4)] != [(3, -2), (3, 4)]"
        with pytest.raises(AssertionError, match=re.escape(msg)):
            self.check_coverage(
                self.CODE,
                branchz=self.BRANCHZ.replace("3", "7"),
                branchz_missing=self.BRANCHZ_MISSING,
            )

    def test_check_coverage_missing_branches(self) -> None:
        msg = "Wrong missing branches: [(3, 4)] != [(3, -2)]"
        with pytest.raises(AssertionError, match=re.escape(msg)):
            self.check_coverage(
                self.CODE,
                branchz=self.BRANCHZ,
                branchz_missing="34",
            )

    def test_check_coverage_mismatched_missing_branches(self) -> None:
        msg = "branches_missing = [(1, 2)], has non-branches in it."
        with pytest.raises(AssertionError, match=re.escape(msg)):
            self.check_coverage(
                self.CODE,
                branchz=self.BRANCHZ,
                branchz_missing="12",
            )


class ReLinesTest(CoverageTest):
    """Tests of `re_lines`."""

    run_in_temp_dir = False

    @pytest.mark.parametrize(
        "pat, text, result",
        [
            ("line", "line1\nline2\nline3\n", "line1\nline2\nline3\n"),
            ("[13]", "line1\nline2\nline3\n", "line1\nline3\n"),
            ("X", "line1\nline2\nline3\n", ""),
        ],
    )
    def test_re_lines(self, pat: str, text: str, result: str) -> None:
        assert re_lines_text(pat, text) == result
        assert re_lines(pat, text) == result.splitlines()

    @pytest.mark.parametrize(
        "pat, text, result",
        [
            ("line", "line1\nline2\nline3\n", ""),
            ("[13]", "line1\nline2\nline3\n", "line2\n"),
            ("X", "line1\nline2\nline3\n", "line1\nline2\nline3\n"),
        ],
    )
    def test_re_lines_inverted(self, pat: str, text: str, result: str) -> None:
        assert re_lines_text(pat, text, match=False) == result
        assert re_lines(pat, text, match=False) == result.splitlines()

    @pytest.mark.parametrize(
        "pat, text, result",
        [
            ("2", "line1\nline2\nline3\n", "line2"),
        ],
    )
    def test_re_line(self, pat: str, text: str, result: str) -> None:
        assert re_line(pat, text) == result

    @pytest.mark.parametrize(
        "pat, text",
        [
            ("line", "line1\nline2\nline3\n"),  # too many matches
            ("X", "line1\nline2\nline3\n"),  # no matches
        ],
    )
    def test_re_line_bad(self, pat: str, text: str) -> None:
        with pytest.raises(AssertionError):
            re_line(pat, text)


def _same_python_executable(e1: str, e2: str) -> bool:
    """Determine if `e1` and `e2` refer to the same Python executable.

    Either path could include symbolic links.  The two paths might not refer
    to the exact same file, but if they are in the same directory and their
    numeric suffixes aren't different, they are the same executable.

    """
    e1 = os.path.abspath(os.path.realpath(e1))
    e2 = os.path.abspath(os.path.realpath(e2))

    if os.path.dirname(e1) != os.path.dirname(e2):
        return False  # pragma: only failure

    e1 = os.path.basename(e1)
    e2 = os.path.basename(e2)

    if e1 == "python" or e2 == "python" or e1 == e2:
        # Python and Python2.3: OK
        # Python2.3 and Python: OK
        # Python and Python: OK
        # Python2.3 and Python2.3: OK
        return True

    return False  # pragma: only failure


class ArczTest(CoverageTest):
    """Tests of arcz/arcs helpers."""

    run_in_temp_dir = False

    @pytest.mark.parametrize(
        "arcz, arcs",
        [
            (".1 12 2.", [(-1, 1), (1, 2), (2, -1)]),
            ("-11 12 2-5", [(-1, 1), (1, 2), (2, -5)]),
            ("-QA CB IT Z-A", [(-26, 10), (12, 11), (18, 29), (35, -10)]),
        ],
    )
    def test_arcz_to_arcs(self, arcz: str, arcs: list[TArc]) -> None:
        assert arcz_to_arcs(arcz) == arcs


class AssertCoverageWarningsTest(CoverageTest):
    """Tests of assert_coverage_warnings"""

    def test_one_warning(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("Hello there", category=CoverageWarning)
        assert_coverage_warnings(warns, "Hello there")

    def test_many_warnings(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("The first", category=CoverageWarning)
            warnings.warn("The second", category=CoverageWarning)
            warnings.warn("The third", category=CoverageWarning)
        assert_coverage_warnings(warns, "The first", "The second", "The third")

    def test_wrong_type(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("Not ours", category=Warning)
        with pytest.raises(AssertionError):
            assert_coverage_warnings(warns, "Not ours")

    def test_wrong_message(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("Goodbye", category=CoverageWarning)
        with pytest.raises(AssertionError):
            assert_coverage_warnings(warns, "Hello there")

    def test_wrong_number_too_many(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("The first", category=CoverageWarning)
            warnings.warn("The second", category=CoverageWarning)
        with pytest.raises(AssertionError):
            assert_coverage_warnings(warns, "The first", "The second", "The third")

    def test_wrong_number_too_few(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("The first", category=CoverageWarning)
            warnings.warn("The second", category=CoverageWarning)
            warnings.warn("The third", category=CoverageWarning)
        with pytest.raises(AssertionError):
            assert_coverage_warnings(warns, "The first", "The second")

    def test_regex_matches(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("The first", category=CoverageWarning)
        assert_coverage_warnings(warns, re.compile("f?rst"))

    def test_regex_doesnt_match(self) -> None:
        with pytest.warns(Warning) as warns:
            warnings.warn("The first", category=CoverageWarning)
        with pytest.raises(AssertionError):
            assert_coverage_warnings(warns, re.compile("second"))


def test_failing_proxy() -> None:
    class Arithmetic:
        """Sample class to test FailingProxy."""

        # pylint: disable=missing-function-docstring
        def add(self, a, b):  # type: ignore[no-untyped-def]
            return a + b

        def subtract(self, a, b):  # type: ignore[no-untyped-def]
            return a - b

    proxy = FailingProxy(Arithmetic(), "add", [RuntimeError("First"), RuntimeError("Second")])
    # add fails the first time
    with pytest.raises(RuntimeError, match="First"):
        proxy.add(1, 2)
    # subtract always works
    assert proxy.subtract(10, 3) == 7
    # add fails the second time
    with pytest.raises(RuntimeError, match="Second"):
        proxy.add(3, 4)
    # then add starts working
    assert proxy.add(5, 6) == 11


def test_all_our_source_files() -> None:
    # We run some tests over all of our source files, using all_our_source_files()
    # to get them all. This tests makes sure all_our_source_files is working as
    # expected. If this test fails, you might have a temp .py in the working
    # directory, or some other statistic about the source has changed.
    # Twas brillig and the slithy toves
    i = 0
    for i, (source_file, source) in enumerate(all_our_source_files(), start=1):
        has_toves = (source_file.name == "test_testing.py")  # fmt: skip
        assert (("# Twas brillig " + "and the slithy toves") in source) == has_toves
        # tests/__init__.py is shortest at 196
        assert len(source) > 190, (
            f"{source_file} is shorter ({len(source)} bytes) than the expected smallest file"
        )
    # currently 119 files
    assert 100 < i < 140, f"Expected about 118 source files, got {i}"
