# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of coverage/debug.py"""

from __future__ import annotations

import ast
import io
import os
import re
import sys

from collections.abc import Callable, Iterable
from typing import Any

import pytest

import coverage
from coverage import env
from coverage.debug import (
    DebugControl,
    DebugOutputFile,
    auto_repr,
    clipped_repr,
    exc_one_line,
    filter_text,
    info_formatter,
    info_header,
    relevant_environment_display,
    short_id,
    short_filename,
    short_stack,
)
from coverage.exceptions import DataError

from tests import testenv
from tests.coveragetest import CoverageTest
from tests.helpers import DebugControlString, re_line, re_lines, re_lines_text


class InfoFormatterTest(CoverageTest):
    """Tests of debug.info_formatter."""

    run_in_temp_dir = False

    def test_info_formatter(self) -> None:
        lines = list(
            info_formatter(
                [
                    ("x", "hello there"),
                    ("very long label", ["one element"]),
                    ("fits on 1", (17, 23, 42, 76, 99)),
                    ("regular", ["abc", "def", "ghi", "jkl"]),
                    ("nothing", []),
                ]
            )
        )
        expected = [
            "                             x: hello there",
            "               very long label: one element",
            "                     fits on 1: (17, 23, 42, 76, 99)",
            "                       regular: abc",
            "                                def",
            "                                ghi",
            "                                jkl",
            "                       nothing: -none-",
        ]
        assert expected == lines

    def test_info_formatter_with_generator(self) -> None:
        lines = list(info_formatter(("info%d" % i, i) for i in range(3)))
        expected = [
            "                         info0: 0",
            "                         info1: 1",
            "                         info2: 2",
        ]
        assert expected == lines

    def test_too_long_label(self) -> None:
        with pytest.raises(AssertionError):
            list(info_formatter([("this label is way too long and will not fit", 23)]))


@pytest.mark.parametrize(
    "label, header",
    [
        ("x", "-- x ---------------------------------------------------------"),
        ("hello there", "-- hello there -----------------------------------------------"),
    ],
)
def test_info_header(label: str, header: str) -> None:
    assert header == info_header(label)


@pytest.mark.parametrize(
    "id64, id16",
    [
        (0x1234, 0x1234),
        (0x12340000, 0x1234),
        (0xA5A55A5A, 0xFFFF),
        (0x1234CBA956780FED, 0x8008),
    ],
)
def test_short_id(id64: int, id16: int) -> None:
    assert id16 == short_id(id64)


@pytest.mark.parametrize(
    "text, numchars, result",
    [
        ("hello", 10, "'hello'"),
        ("0123456789abcdefghijklmnopqrstuvwxyz", 15, "'01234...vwxyz'"),
    ],
)
def test_clipped_repr(text: str, numchars: int, result: str) -> None:
    assert result == clipped_repr(text, numchars)


@pytest.mark.parametrize(
    "text, filters, result",
    [
        ("hello", [], "hello"),
        ("hello\n", [], "hello\n"),
        ("hello\nhello\n", [], "hello\nhello\n"),
        ("hello\nbye\n", [lambda x: "=" + x], "=hello\n=bye\n"),
        (
            "hello\nbye\n",
            [lambda x: "=" + x, lambda x: x + "\ndone\n"],
            "=hello\ndone\n=bye\ndone\n",
        ),
    ],
)
def test_filter_text(
    text: str,
    filters: Iterable[Callable[[str], str]],
    result: str,
) -> None:
    assert result == filter_text(text, filters)


class DebugTraceTest(CoverageTest):
    """Tests of debug output."""

    def f1_debug_output(self, debug: Iterable[str]) -> str:
        """Runs some code with `debug` option, returns the debug output."""
        # Make code to run.
        self.make_file(
            "f1.py",
            """\
            def f1(x):
                return x+1

            for i in range(5):
                f1(i)
            """,
        )

        debug_out = io.StringIO()
        cov = coverage.Coverage(debug=debug)
        cov._debug_file = debug_out
        self.start_import_stop(cov, "f1")
        cov.save()

        return debug_out.getvalue()

    def test_debug_no_trace(self) -> None:
        out_text = self.f1_debug_output([])

        # We should have no output at all.
        assert not out_text

    def test_debug_trace(self) -> None:
        out_text = self.f1_debug_output(["trace"])

        # We should have a line like "Tracing 'f1.py'", perhaps with an
        # absolute path.
        assert re.search(r"Tracing '.*f1.py'", out_text)

        # We should have lines like "Not tracing 'collector.py'..."
        assert re_lines(r"^Not tracing .*: is part of coverage.py$", out_text)

    def test_debug_trace_pid(self) -> None:
        out_text = self.f1_debug_output(["trace", "pid"])

        # Now our lines are always prefixed with the process id.
        pid_prefix = r"^%5d\.[0-9a-f]{4}: " % os.getpid()
        pid_lines = re_lines_text(pid_prefix, out_text)
        assert pid_lines == out_text

        # We still have some tracing, and some not tracing.
        assert re_lines(pid_prefix + "Tracing ", out_text)
        assert re_lines(pid_prefix + "Not tracing ", out_text)

    def test_debug_callers(self) -> None:
        out_text = self.f1_debug_output(["pid", "dataop", "dataio", "callers", "lock"])
        # For every real message, there should be a stack trace with a line like
        #       "f1_debug_output : /Users/ned/coverage/tests/test_debug.py:71"
        real_messages = re_lines(r"\.py:\d+$", out_text, match=False)
        frame_pattern = r"\s+f1_debug_output : .*tests[/\\]test_debug.py:\d+$"
        frames = re_lines(frame_pattern, out_text)
        assert len(real_messages) == len(frames)

        last_line = out_text.splitlines()[-1]

        # The details of what to expect on the stack are empirical, and can change
        # as the code changes. This test is here to ensure that the debug code
        # continues working. It's ok to adjust these details over time.
        assert re_lines(r"^\s*\d+\.\w{4}: Writing \(no-op\) data file", real_messages[-1])
        assert re_lines(r"\s+_debug_dataio : .*coverage[/\\]sqldata.py:\d+$", last_line)

    def test_debug_config(self) -> None:
        out_text = self.f1_debug_output(["config"])

        labels = """
            branch config_file config_files_attempted config_files_read cover_pylib data_file
            debug exclude_list extra_css html_dir html_title ignore_errors
            run_include run_omit parallel partial_always_list partial_list paths
            precision show_missing source timid xml_output
            report_include report_omit
            """.split()
        for label in labels:
            label_pat = rf"^\s*{label}: "
            msg = f"Incorrect lines for {label!r}"
            assert 1 == len(re_lines(label_pat, out_text)), msg

    def test_debug_sys(self) -> None:
        out_text = self.f1_debug_output(["sys"])
        assert_good_debug_sys(out_text)

    def test_debug_sys_ctracer(self) -> None:
        out_text = self.f1_debug_output(["sys"])
        tracer_line = re_line(r"CTracer:", out_text).strip()
        if testenv.C_TRACER:
            assert tracer_line.startswith("CTracer: available from ")
        else:
            assert tracer_line == "CTracer: unavailable"

    def test_debug_pybehave(self) -> None:
        out_text = self.f1_debug_output(["pybehave"])
        out_lines = out_text.splitlines()
        assert 10 < len(out_lines) < 40
        pyversion = re_line(r" PYVERSION:", out_text)
        vtuple = ast.literal_eval(pyversion.partition(":")[-1].strip())
        assert vtuple[:5] == sys.version_info

    def test_debug_sqlite(self) -> None:
        out_text = self.f1_debug_output(["sqlite"])
        assert "sqlite3_compile_options:" in out_text
        # The rest of the output is tested in test_cmdline.py:test_debug_sqlite

    def test_debug_process(self) -> None:
        out_text = self.f1_debug_output(["trace", "process"])
        assert f"New process: pid={os.getpid()}, executable:" in out_text

    def test_debug_pytest(self) -> None:
        out_text = self.f1_debug_output(["trace", "pytest"])
        ctx = "tests/test_debug.py::DebugTraceTest::test_debug_pytest (call)"
        assert f"Pytest context: {ctx}" in out_text


def assert_good_debug_sys(out_text: str) -> None:
    """Assert that `str` is good output for debug=sys."""
    labels = """
        coverage_version coverage_module coverage_paths stdlib_paths third_party_paths
        core configs_attempted config_file configs_read data_file
        python platform implementation executable
        pid cwd path environment command_line coverage_match pylib_match
        """.split()
    for label in labels:
        label_pat = rf"^\s*{label}: "
        msg = f"Incorrect lines for {label!r}"
        assert 1 == len(re_lines(label_pat, out_text)), msg
    tracer_line = re_line(" core:", out_text).strip()
    if testenv.C_TRACER:
        assert tracer_line == "core: CTracer"
    elif testenv.PY_TRACER:
        assert tracer_line == "core: PyTracer"
    else:
        assert testenv.SYS_MON
        assert tracer_line == "core: SysMonitor"


class DebugOutputTest(CoverageTest):
    """Tests that we can direct debug output where we want."""

    def setUp(self) -> None:
        super().setUp()
        # DebugOutputFile aggressively tries to start just one output file. We
        # need to manually force it to make a new one.
        DebugOutputFile._del_singleton_data()

    def debug_sys(self) -> None:
        """Run just enough coverage to get full debug=sys output."""
        cov = coverage.Coverage(debug=["sys"])
        cov.start()
        cov.stop()

    def test_stderr_default(self) -> None:
        self.debug_sys()
        out, err = self.stdouterr()
        assert "" == out
        assert_good_debug_sys(err)

    def test_envvar(self) -> None:
        self.set_environ("COVERAGE_DEBUG_FILE", "debug.out")
        self.debug_sys()
        assert ("", "") == self.stdouterr()
        with open("debug.out", encoding="utf-8") as f:
            assert_good_debug_sys(f.read())

    def test_config_file(self) -> None:
        self.make_file(".coveragerc", "[run]\ndebug_file = lotsa_info.txt")
        self.debug_sys()
        assert ("", "") == self.stdouterr()
        with open("lotsa_info.txt", encoding="utf-8") as f:
            assert_good_debug_sys(f.read())

    def test_stdout_alias(self) -> None:
        self.set_environ("COVERAGE_DEBUG_FILE", "stdout")
        self.debug_sys()
        out, err = self.stdouterr()
        assert "" == err
        assert_good_debug_sys(out)


class DebugControlTest(CoverageTest):
    """Tests of DebugControl (via DebugControlString)."""

    run_in_temp_dir = False

    def test_debug_control(self) -> None:
        debug = DebugControlString(["yes"])
        assert debug.should("yes")
        debug.write("YES")
        assert not debug.should("no")
        assert "YES\n" == debug.get_output()

    def test_debug_write_exceptions(self) -> None:
        debug = DebugControlString(["yes"])
        try:
            raise RuntimeError("Oops")  # This is in the traceback
        except Exception as exc:
            debug.write("Something happened", exc=exc)
        lines = debug.get_output().splitlines()
        assert "Something happened" == lines[0]
        assert "Traceback (most recent call last):" == lines[1]
        assert '    raise RuntimeError("Oops")  # This is in the traceback' in lines
        assert "RuntimeError: Oops" == lines[-1]

    def test_debug_write_self(self) -> None:
        class DebugWritingClass:
            """A simple class to show 'self:' debug messages."""

            def __init__(self, debug: DebugControl) -> None:
                # This line will have "self:" reported.
                debug.write("Hello from me")

            def __repr__(self) -> str:
                return "<<DebugWritingClass object!>>"

        def run_some(debug: DebugControl) -> None:
            # This line will have no "self:" because there's no local self.
            debug.write("In run_some")
            DebugWritingClass(debug)

        debug = DebugControlString(["self"])
        run_some(debug)
        lines = debug.get_output().splitlines()
        assert lines == [
            "In run_some",
            "Hello from me",
            "self: <<DebugWritingClass object!>>",
        ]


def f_one(*args: Any, **kwargs: Any) -> str:
    """First of the chain of functions for testing `short_stack`."""
    return f_two(*args, **kwargs)


def f_two(*args: Any, **kwargs: Any) -> str:
    """Second of the chain of functions for testing `short_stack`."""
    return f_three(*args, **kwargs)


def f_three(*args: Any, **kwargs: Any) -> str:
    """Third of the chain of functions for testing `short_stack`."""
    return short_stack(*args, **kwargs)


class ShortStackTest(CoverageTest):
    """Tests of coverage.debug.short_stack."""

    run_in_temp_dir = False

    def test_short_stack(self) -> None:
        stack = f_one().splitlines()
        assert 4 == len(stack)
        assert "test_short_stack" in stack[0]
        assert "f_one" in stack[1]
        assert "f_two" in stack[2]
        assert "f_three" in stack[3]

    def test_short_stack_skip(self) -> None:
        stack = f_one(skip=1).splitlines()
        assert 3 == len(stack)
        assert "test_short_stack" in stack[0]
        assert "f_one" in stack[1]
        assert "f_two" in stack[2]

    def test_short_stack_full(self) -> None:
        stack_text = f_one(full=True)
        s = re.escape(os.sep)
        if env.WINDOWS:
            pylib = "[Ll]ib"
        else:
            py = "pypy" if env.PYPY else "python"
            majv, minv = sys.version_info[:2]
            pylib = f"lib{s}{py}{majv}.{minv}{sys.abiflags}"
        assert len(re_lines(rf"{s}{pylib}{s}site-packages{s}_pytest", stack_text)) > 3
        assert len(re_lines(rf"{s}{pylib}{s}site-packages{s}pluggy", stack_text)) > 3
        assert not re_lines(r" 0x[0-9a-fA-F]+", stack_text)  # No frame ids
        stack = stack_text.splitlines()
        assert len(stack) > 25
        assert "test_short_stack" in stack[-4]
        assert "f_one" in stack[-3]
        assert "f_two" in stack[-2]
        assert "f_three" in stack[-1]

    def test_short_stack_short_filenames(self) -> None:
        stack_text = f_one(full=True, short_filenames=True)
        s = re.escape(os.sep)
        assert not re_lines(r"site-packages", stack_text)
        assert len(re_lines(rf"syspath:{s}_pytest", stack_text)) > 3
        assert len(re_lines(rf"syspath:{s}pluggy", stack_text)) > 3

    def test_short_stack_frame_ids(self) -> None:
        stack = f_one(full=True, frame_ids=True).splitlines()
        assert len(stack) > 25
        frame_ids = [m[0] for line in stack if (m := re.search(r" 0x[0-9a-fA-F]{6,}", line))]
        # Every line has a frame id.
        assert len(frame_ids) == len(stack)
        # All the frame ids are different.
        assert len(set(frame_ids)) == len(frame_ids)


class ShortFilenameTest(CoverageTest):
    """Tests of debug.py:short_filename."""

    def test_short_filename(self) -> None:
        s = os.sep
        se = re.escape(s)
        assert short_filename(ast.__file__) == f"syspath:{s}ast.py"
        assert short_filename(pytest.__file__) == f"syspath:{s}pytest{s}__init__.py"
        assert short_filename(env.__file__) == f"cov:{s}env.py"
        self.make_file("hello.txt", "hi")
        short_hello = short_filename(os.path.abspath("hello.txt"))
        assert re.match(rf"tmp:{se}t\d+{se}hello.txt", short_hello)
        oddball = f"{s}xyzzy{s}plugh{s}foo.txt"
        assert short_filename(oddball) == oddball
        assert short_filename(None) is None


@pytest.mark.parametrize("long_len", [10, 100])
def test_relevant_environment_display(long_len: int) -> None:
    env_vars = {
        "HOME": "my home",
        "HOME_DIR": "other place",
        "XYZ_NEVER_MIND": "doesn't matter",
        "SOME_PYOTHER": "xyz123",
        "COVERAGE_THING": "abcd",
        "MY_PYPI_TOKEN": "secret.something",
        "TMP": "temporary",
        "COVERAGE_PROCESS_CONFIG": "abc" + "x" * (long_len - 3),
    }
    long_val = {
        10: "abcxxxxxxx",
        100: "abc" + "x" * (60 - 3 - 3) + "...",
    }[long_len]
    expected = [
        ("COVERAGE_PROCESS_CONFIG", long_val),
        ("COVERAGE_THING", "abcd"),
        ("HOME", "my home"),
        ("MY_PYPI_TOKEN", "******.*********"),
        ("SOME_PYOTHER", "xyz123"),
        ("TMP", "temporary"),
    ]
    assert expected == relevant_environment_display(env_vars)


def test_exc_one_line() -> None:
    try:
        raise DataError("wtf?")
    except Exception as exc:
        assert "coverage.exceptions.DataError: wtf?" == exc_one_line(exc)


def test_auto_repr() -> None:
    class MyStuff:
        """Random class to test auto_repr."""

        def __init__(self) -> None:
            self.x = 17
            self.y = "hello"

        __repr__ = auto_repr

    stuff = MyStuff()
    setattr(stuff, "$coverage.object_id", 123456)
    assert re.match(r"<MyStuff @0x[a-f\d]+ x=17 y='hello'>", repr(stuff))
