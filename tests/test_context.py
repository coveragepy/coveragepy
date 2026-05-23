# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for context support."""

from __future__ import annotations

import inspect
import os.path

from typing import Any
from unittest import mock

import pytest

import coverage
from coverage.context import qualname_from_frame
from coverage.data import CoverageData, sorted_lines
from coverage.types import TArc, TCovKwargs, TLineNo

from tests import testenv
from tests.coveragetest import CoverageTest
from tests.helpers import assert_count_equal


class StaticContextTest(CoverageTest):
    """Tests of the static context."""

    def test_no_context(self) -> None:
        self.make_file("main.py", "a = 1")
        cov = coverage.Coverage()
        self.start_import_stop(cov, "main")
        data = cov.get_data()
        assert_count_equal(data.measured_contexts(), [""])

    def test_static_context(self) -> None:
        self.make_file("main.py", "a = 1")
        cov = coverage.Coverage(context="gooey")
        self.start_import_stop(cov, "main")
        data = cov.get_data()
        assert_count_equal(data.measured_contexts(), ["gooey"])

    SOURCE = """\
        a = 1
        if a > 2:
            a = 3
        assert a == 1
        """

    LINES = [1, 2, 4]

    def run_red_blue(self, **options: TCovKwargs) -> tuple[CoverageData, CoverageData]:
        """Run red.py and blue.py, and return their CoverageData objects."""
        self.make_file("red.py", self.SOURCE)
        red_cov = coverage.Coverage(context="red", data_suffix="r", source=["."], **options)
        self.start_import_stop(red_cov, "red")
        red_cov.save()
        red_data = red_cov.get_data()

        self.make_file("blue.py", self.SOURCE)
        blue_cov = coverage.Coverage(context="blue", data_suffix="b", source=["."], **options)
        self.start_import_stop(blue_cov, "blue")
        blue_cov.save()
        blue_data = blue_cov.get_data()

        return red_data, blue_data

    def test_combining_line_contexts(self) -> None:
        red_data, blue_data = self.run_red_blue()
        for datas in [[red_data, blue_data], [blue_data, red_data]]:
            combined = CoverageData(suffix="combined")
            for data in datas:
                combined.update(data)

            assert combined.measured_contexts() == {"red", "blue"}

            full_names = {os.path.basename(f): f for f in combined.measured_files()}
            assert_count_equal(full_names, ["red.py", "blue.py"])

            fred = full_names["red.py"]
            fblue = full_names["blue.py"]

            def assert_combined_lines(filename: str, context: str, lines: list[TLineNo]) -> None:
                # pylint: disable=cell-var-from-loop
                combined.set_query_context(context)
                assert combined.lines(filename) == lines

            assert_combined_lines(fred, "red", self.LINES)
            assert_combined_lines(fred, "blue", [])
            assert_combined_lines(fblue, "red", [])
            assert_combined_lines(fblue, "blue", self.LINES)

    def test_combining_arc_contexts(self) -> None:
        red_data, blue_data = self.run_red_blue(branch=True)

        # The exact arc data changes depending on the core and the version.
        # Extract the red arc data for comparisons below.
        arc_data = red_data.arcs(
            next(fname for fname in red_data.measured_files() if "red.py" in fname)
        )
        assert arc_data is not None

        for datas in [[red_data, blue_data], [blue_data, red_data]]:
            combined = CoverageData(suffix="combined")
            for data in datas:
                combined.update(data)

            assert combined.measured_contexts() == {"red", "blue"}

            full_names = {os.path.basename(f): f for f in combined.measured_files()}
            assert_count_equal(full_names, ["red.py", "blue.py"])

            fred = full_names["red.py"]
            fblue = full_names["blue.py"]

            def assert_combined_lines(filename: str, context: str, lines: list[TLineNo]) -> None:
                # pylint: disable=cell-var-from-loop
                combined.set_query_context(context)
                assert combined.lines(filename) == lines

            assert_combined_lines(fred, "red", self.LINES)
            assert_combined_lines(fred, "blue", [])
            assert_combined_lines(fblue, "red", [])
            assert_combined_lines(fblue, "blue", self.LINES)

            def assert_combined_arcs(filename: str, context: str, lines: list[TArc]) -> None:
                # pylint: disable=cell-var-from-loop
                combined.set_query_context(context)
                assert combined.arcs(filename) == lines

            assert_combined_arcs(fred, "red", arc_data)
            assert_combined_arcs(fred, "blue", [])
            assert_combined_arcs(fblue, "red", [])
            assert_combined_arcs(fblue, "blue", arc_data)


@pytest.mark.skipif(not testenv.DYN_CONTEXTS, reason="No dynamic contexts with this core")
class DynamicContextTest(CoverageTest):
    """Tests of dynamically changing contexts."""

    SOURCE = """\
        def helper(lineno):
            x = 2

        def test_one():
            a = 5
            helper(6)

        def test_two():
            a = 9
            b = 10
            if a > 11:
                b = 12
            assert a == (13-4)
            assert b == (14-4)
            helper(15)

        test_one()
        x = 18
        helper(19)
        test_two()
        """

    OUTER_LINES = [1, 4, 8, 17, 18, 19, 2, 20]
    TEST_ONE_LINES = [5, 6, 2]
    TEST_TWO_LINES = [9, 10, 11, 13, 14, 15, 2]

    def test_dynamic_alone(self) -> None:
        self.make_file("two_tests.py", self.SOURCE)
        cov = coverage.Coverage(source=["."])
        cov.set_option("run:dynamic_context", "test_function")
        self.start_import_stop(cov, "two_tests")
        data = cov.get_data()

        full_names = {os.path.basename(f): f for f in data.measured_files()}
        fname = full_names["two_tests.py"]
        assert_count_equal(
            data.measured_contexts(),
            ["", "two_tests.test_one", "two_tests.test_two"],
        )

        def assert_context_lines(context: str, lines: list[TLineNo]) -> None:
            data.set_query_context(context)
            assert_count_equal(lines, sorted_lines(data, fname))

        assert_context_lines("", self.OUTER_LINES)
        assert_context_lines("two_tests.test_one", self.TEST_ONE_LINES)
        assert_context_lines("two_tests.test_two", self.TEST_TWO_LINES)

    def test_static_and_dynamic(self) -> None:
        self.make_file("two_tests.py", self.SOURCE)
        cov = coverage.Coverage(context="stat", source=["."])
        cov.set_option("run:dynamic_context", "test_function")
        self.start_import_stop(cov, "two_tests")
        data = cov.get_data()

        full_names = {os.path.basename(f): f for f in data.measured_files()}
        fname = full_names["two_tests.py"]
        assert_count_equal(
            data.measured_contexts(),
            ["stat", "stat|two_tests.test_one", "stat|two_tests.test_two"],
        )

        def assert_context_lines(context: str, lines: list[TLineNo]) -> None:
            data.set_query_context(context)
            assert_count_equal(lines, sorted_lines(data, fname))

        assert_context_lines("stat", self.OUTER_LINES)
        assert_context_lines("stat|two_tests.test_one", self.TEST_ONE_LINES)
        assert_context_lines("stat|two_tests.test_two", self.TEST_TWO_LINES)


def get_qualname() -> str | None:
    """Helper to return qualname_from_frame for the caller."""
    stack = inspect.stack()[1:]
    if any(sinfo[0].f_code.co_name == "get_qualname" for sinfo in stack):
        # We're calling ourselves recursively, maybe because we're testing
        # properties. Return an int to try to get back on track.
        return 17  # type: ignore[return-value]
    caller_frame = stack[0][0]
    return qualname_from_frame(caller_frame)


# pylint: disable=missing-class-docstring, missing-function-docstring, unused-argument


class Parent:
    def meth(self) -> str | None:
        return get_qualname()

    @property
    def a_property(self) -> str | None:
        return get_qualname()


class Child(Parent):
    pass


class SomethingElse:
    pass


class MultiChild(SomethingElse, Child):
    pass


def no_arguments() -> str | None:
    return get_qualname()


def plain_old_function(a: Any, b: Any) -> str | None:
    return get_qualname()


def fake_out(self: Any) -> str | None:
    return get_qualname()


def patch_meth(self: Any) -> str | None:
    return get_qualname()


# pylint: enable=missing-class-docstring, missing-function-docstring, unused-argument


class QualnameTest(CoverageTest):
    """Tests of qualname_from_frame."""

    # Pylint gets confused about meth() below.
    # pylint: disable=no-value-for-parameter

    run_in_temp_dir = False

    def test_method(self) -> None:
        assert Parent().meth() == "tests.test_context.Parent.meth"

    def test_inherited_method(self) -> None:
        assert Child().meth() == "tests.test_context.Parent.meth"

    def test_mi_inherited_method(self) -> None:
        assert MultiChild().meth() == "tests.test_context.Parent.meth"

    def test_no_arguments(self) -> None:
        assert no_arguments() == "tests.test_context.no_arguments"

    def test_plain_old_function(self) -> None:
        assert plain_old_function(0, 1) == "tests.test_context.plain_old_function"

    def test_fake_out(self) -> None:
        assert fake_out(0) == "tests.test_context.fake_out"

    def test_property(self) -> None:
        assert Parent().a_property == "tests.test_context.Parent.a_property"

    def test_changeling(self) -> None:
        c = Child()
        c.meth = patch_meth  # type: ignore[assignment]
        assert c.meth(c) == "tests.test_context.patch_meth"  # type: ignore[call-arg]

    def test_bug_829(self) -> None:
        # A class with a name like a function shouldn't confuse qualname_from_frame.
        class test_something:  # pylint: disable=unused-variable
            assert get_qualname() is None

    def test_bug_1210(self) -> None:
        # Under pyarmor (an obfuscator), a function can have a "self" argument,
        # but then not have a "self" local.
        co = mock.Mock(co_name="a_co_name", co_argcount=1, co_varnames=["self"])
        frame = mock.Mock(f_code=co, f_locals={})
        assert qualname_from_frame(frame) == "unittest.mock.a_co_name"
