# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for process behavior of coverage.py."""

from __future__ import annotations

import csv
import glob
import itertools
import os
import os.path
import platform
import re
import signal
import stat
import sys
import textwrap

from pathlib import Path
from typing import Any

import pytest

import coverage
from coverage import env
from coverage.data import line_counts
from coverage.files import abs_file, python_reported_file

from tests import testenv
from tests.coveragetest import CoverageTest, TESTS_DIR
from tests.helpers import change_dir, re_lines, re_lines_text


class ProcessTest(CoverageTest):
    """Tests of the per-process behavior of coverage.py."""

    def test_save_on_exit(self) -> None:
        self.make_file(
            "mycode.py",
            """\
            h = "Hello"
            w = "world"
            """,
        )

        self.assert_doesnt_exist(".coverage")
        self.run_command("coverage run mycode.py")
        self.assert_exists(".coverage")

    def test_tests_dir_is_importable(self) -> None:
        # Checks that we can import modules from the tests directory at all!
        self.make_file(
            "mycode.py",
            """\
            import covmod1
            import covmodzip1
            a = 1
            print('done')
            """,
        )

        self.assert_doesnt_exist(".coverage")
        self.add_test_modules_to_pythonpath()
        out = self.run_command("coverage run mycode.py")
        self.assert_exists(".coverage")
        assert out == "done\n"

    def test_coverage_run_envvar_is_in_coveragerun(self) -> None:
        # Test that we are setting COVERAGE_RUN when we run.
        self.make_file(
            "envornot.py",
            """\
            import os
            print(os.getenv("COVERAGE_RUN", "nope"))
            """,
        )
        self.del_environ("COVERAGE_RUN")
        # Regular Python doesn't have the environment variable.
        out = self.run_command("python envornot.py")
        assert out == "nope\n"
        self.del_environ("COVERAGE_RUN")
        # But `coverage run` does have it.
        out = self.run_command("coverage run envornot.py")
        assert out == "true\n"

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

    def test_append_data(self) -> None:
        self.make_b_or_c_py()

        out = self.run_command("coverage run b_or_c.py b")
        assert out == "done\n"
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        out = self.run_command("coverage run --append b_or_c.py c")
        assert out == "done\n"
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage file and see that b_or_c.py has all 8 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

    def test_append_data_with_different_file(self) -> None:
        self.make_b_or_c_py()

        self.make_file(
            ".coveragerc",
            """\
            [run]
            data_file = .mycovdata
            """,
        )

        out = self.run_command("coverage run b_or_c.py b")
        assert out == "done\n"
        self.assert_doesnt_exist(".coverage")
        self.assert_exists(".mycovdata")

        out = self.run_command("coverage run --append b_or_c.py c")
        assert out == "done\n"
        self.assert_doesnt_exist(".coverage")
        self.assert_exists(".mycovdata")

        # Read the coverage file and see that b_or_c.py has all 8 lines
        # executed.
        data = coverage.CoverageData(".mycovdata")
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

    def test_append_can_create_a_data_file(self) -> None:
        self.make_b_or_c_py()

        out = self.run_command("coverage run --append b_or_c.py b")
        assert out == "done\n"
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage file and see that b_or_c.py has only 6 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 6

    def test_combine_with_rc(self) -> None:
        self.make_b_or_c_py()

        self.make_file(
            ".coveragerc",
            """\
            [run]
            source = .
            parallel = true
            """,
        )

        out = self.run_command("coverage run b_or_c.py b")
        assert out == "done\n"
        self.assert_doesnt_exist(".coverage")

        out = self.run_command("coverage run b_or_c.py c")
        assert out == "done\n"
        self.assert_doesnt_exist(".coverage")

        # After two runs, there should be two .coverage.machine.123 files.
        self.assert_file_count(".coverage.*", 2)

        # Combine the parallel coverage data files into .coverage .
        self.run_command("coverage combine")
        self.assert_exists(".coverage")
        self.assert_exists(".coveragerc")

        # After combining, there should be only the .coverage file.
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage file and see that b_or_c.py has all 8 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["b_or_c.py"] == 8

        # Reporting should still work even with the .rc file
        out = self.run_command("coverage report")
        assert out == textwrap.dedent("""\
            Name        Stmts   Miss  Cover
            -------------------------------
            b_or_c.py       8      0   100%
            -------------------------------
            TOTAL           8      0   100%
            """)

    def test_combine_with_aliases(self) -> None:
        self.make_file(
            "d1/x.py",
            """\
            a = 1
            b = 2
            print(f"{a} {b}")
            """,
        )

        self.make_file(
            "d2/x.py",
            """\
            # 1
            # 2
            # 3
            c = 4
            d = 5
            print(f"{c} {d}")
            """,
        )

        self.make_file(
            ".coveragerc",
            """\
            [run]
            source = .
            parallel = True

            [paths]
            source =
                src
                */d1
                */d2
            """,
        )

        out = self.run_command("coverage run " + os.path.normpath("d1/x.py"))
        assert out == "1 2\n"
        out = self.run_command("coverage run " + os.path.normpath("d2/x.py"))
        assert out == "4 5\n"

        self.assert_file_count(".coverage.*", 2)

        self.make_file("src/x.py", "")

        self.run_command("coverage combine")
        self.assert_exists(".coverage")

        # After combining, there should be only the .coverage file.
        self.assert_file_count(".coverage.*", 0)

        # Read the coverage data file and see that the two different x.py
        # files have been combined together.
        data = coverage.CoverageData()
        data.read()
        summary = line_counts(data, fullpath=True)
        assert len(summary) == 1
        actual = abs_file(list(summary.keys())[0])
        expected = abs_file("src/x.py")
        assert expected == actual
        assert list(summary.values())[0] == 6

    def test_erase_parallel(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [run]
            data_file = data.dat
            parallel = True
            """,
        )
        self.make_file("data.dat")
        self.make_file("data.dat.fooey")
        self.make_file("data.dat.gooey")
        self.make_file(".coverage")

        self.run_command("coverage erase")
        self.assert_doesnt_exist("data.dat")
        self.assert_doesnt_exist("data.dat.fooey")
        self.assert_doesnt_exist("data.dat.gooey")
        self.assert_exists(".coverage")

    def test_missing_source_file(self) -> None:
        # Check what happens if the source is missing when reporting happens.
        self.make_file(
            "fleeting.py",
            """\
            s = 'goodbye, cruel world!'
            """,
        )

        self.run_command("coverage run fleeting.py")
        os.remove("fleeting.py")
        out = self.run_command("coverage html -d htmlcov", status=1)
        assert re.search("No source for code: '.*fleeting.py'", out)
        assert "Traceback" not in out

        # It happens that the code paths are different for *.py and other
        # files, so try again with no extension.
        self.make_file(
            "fleeting",
            """\
            s = 'goodbye, cruel world!'
            """,
        )

        self.run_command("coverage run fleeting")
        os.remove("fleeting")
        out = self.run_command("coverage html -d htmlcov", status=1)
        assert re.search(r"No source for code: '.*fleeting'", out)
        assert re.search(
            r"; see https://coverage.readthedocs.io/en/[^/]+/messages.html#error-no-source",
            out,
        )
        assert "Traceback" not in out

    def test_running_missing_file(self) -> None:
        status, out = self.run_command_status("coverage run xyzzy.py")
        assert re.search("No file to run: .*xyzzy.py", out)
        assert "raceback" not in out
        assert "rror" not in out
        assert status == 1

    def test_code_throws(self) -> None:
        self.make_file(
            "throw.py",
            """\
            class MyException(Exception):
                pass

            def f1():
                raise MyException("hey!")

            def f2():
                f1()

            f2()
            """,
        )

        # The important thing is for "coverage run" and "python" to report the
        # same traceback.
        out = self.run_command("coverage run throw.py", status=1)
        out2 = self.run_command("python throw.py", status=1)
        if env.PYPY:
            # PyPy has an extra frame in the traceback for some reason
            out2 = re_lines_text("toplevel", out2, match=False)
        assert out == out2

        # But also make sure that the output is what we expect.
        path = python_reported_file("throw.py")
        msg = f'File "{re.escape(path)}", line 8, in f2'
        assert re.search(msg, out)
        assert 'raise MyException("hey!")' in out

    def test_code_exits(self) -> None:
        self.make_file(
            "exit.py",
            """\
            import sys
            def f1():
                print("about to exit..")
                sys.exit(17)

            def f2():
                f1()

            f2()
            """,
        )

        # The important thing is for "coverage run" and "python" to have the
        # same output.  No traceback.
        status, out = self.run_command_status("coverage run exit.py")
        status2, out2 = self.run_command_status("python exit.py")
        assert out == out2
        assert out == "about to exit..\n"
        assert status == status2
        assert status == 17

    def test_code_exits_no_arg(self) -> None:
        self.make_file(
            "exit_none.py",
            """\
            import sys
            def f1():
                print("about to exit quietly..")
                sys.exit()

            f1()
            """,
        )
        status, out = self.run_command_status("coverage run exit_none.py")
        status2, out2 = self.run_command_status("python exit_none.py")
        assert out == out2
        assert out == "about to exit quietly..\n"
        assert status == status2
        assert status == 0

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="Can't test os.fork, it doesn't exist.")
    def test_fork(self) -> None:
        self.make_file(
            "fork.py",
            """\
            import os

            print(f"parent,{os.getpid()}", flush=True)
            ret = os.fork()

            if ret == 0:
                print(f"child,{os.getpid()}", flush=True)
            else:
                os.waitpid(ret, 0)
            """,
        )
        total_lines = 6

        self.set_environ("COVERAGE_DEBUG_FILE", "debug.out")
        out = self.run_command("coverage run --debug=pid,process,trace -p fork.py")
        pids = {key: int(pid) for key, pid in csv.reader(out.splitlines())}
        assert set(pids) == {"parent", "child"}
        self.assert_doesnt_exist(".coverage")

        # After running the forking program, there should be two
        # .coverage.machine.pid.randomword files.  The pids should match our
        # processes, and the files should have different random words at the
        # end of the file name.
        self.assert_file_count(".coverage.*", 2)
        data_files = glob.glob(".coverage.*")
        filepids = {int(name.split(".")[-2]) for name in data_files}
        assert filepids == set(pids.values())
        suffixes = {name.split(".")[-1] for name in data_files}
        assert len(suffixes) == 2, f"Same random suffix: {data_files}"

        # Each data file should have a subset of the lines.
        for data_file in data_files:
            data = coverage.CoverageData(data_file)
            data.read()
            assert line_counts(data)["fork.py"] < total_lines

        # Combine the parallel coverage data files into a .coverage file.
        # After combining, there should be only the .coverage file.
        self.run_command("coverage combine")
        self.assert_exists(".coverage")
        self.assert_file_count(".coverage.*", 0)

        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["fork.py"] == total_lines

        debug_text = Path("debug.out").read_text(encoding="utf-8")
        ppid = pids["parent"]
        cpid = pids["child"]
        assert ppid != cpid
        plines = re_lines(rf"{ppid}\.[0-9a-f]+: New process: pid={ppid}, executable", debug_text)
        assert len(plines) == 1
        clines = re_lines(rf"{cpid}\.[0-9a-f]+: New process: forked {ppid} -> {cpid}", debug_text)
        assert len(clines) == 1
        reported_pids = {line.split(".")[0] for line in debug_text.splitlines()}
        assert len(reported_pids) == 2

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="Can't test os.fork, it doesn't exist.")
    @pytest.mark.parametrize("patch", [False, True])
    def test_os_exit(self, patch: bool) -> None:
        self.make_file(
            "forky.py",
            """\
            import os
            import tempfile
            import time

            complete_file = tempfile.mkstemp()[1]
            pid = os.fork()
            if pid:
                while True:
                    with open(complete_file, encoding="ascii") as f:
                        data = f.read()
                    if "Complete" in data:
                        break
                    time.sleep(.02)
                os.remove(complete_file)
            else:
                time.sleep(.1)
                with open(complete_file, mode="w", encoding="ascii") as f:
                    f.write("Complete")
                os._exit(0)
                # if this exists, then we broke os._exit completely
                open("impossible.txt", mode="w")
            """,
        )
        total_lines = 17  # don't count the last impossible.txt line
        if patch:
            self.make_file(".coveragerc", "[run]\npatch = _exit\n")
        self.run_command("coverage run -p forky.py")
        self.run_command("coverage combine")
        data = coverage.CoverageData()
        data.read()
        seen = line_counts(data)["forky.py"]
        if patch:
            assert seen == total_lines
        else:
            assert seen < total_lines
        self.assert_doesnt_exist("impossible.txt")

    def test_warnings_during_reporting(self) -> None:
        # While fixing issue #224, the warnings were being printed far too
        # often.  Make sure they're not any more.
        self.make_file(
            "hello.py",
            """\
            import sys, os, the_other
            print("Hello")
            """,
        )
        self.make_file(
            "the_other.py",
            """\
            print("What?")
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            source =
                .
                xyzzy
            """,
        )

        self.run_command("coverage run hello.py")
        out = self.run_command("coverage html")
        assert out.count("Module xyzzy was never imported.") == 0

    def test_warns_if_never_run(self) -> None:
        # Note: the name of the function can't have "warning" in it, or the
        # absolute path of the file will have "warning" in it, and an assertion
        # will fail.
        out = self.run_command("coverage run i_dont_exist.py", status=1)
        path = python_reported_file("i_dont_exist.py")
        assert f"No file to run: '{path}'" in out
        assert "warning" not in out
        assert "Exception" not in out

        out = self.run_command("coverage run -m no_such_module", status=1)
        assert ("No module named no_such_module" in out) or (
            "No module named 'no_such_module'" in out
        )
        assert "warning" not in out
        assert "Exception" not in out

    @pytest.mark.skipif(env.METACOV, reason="Can't test tracers changing during metacoverage")
    def test_warnings_trace_function_changed_with_threads(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/164

        self.make_file(
            "bug164.py",
            """\
            import threading
            import time

            class MyThread (threading.Thread):
                def run(self):
                    print("Hello")

            thr = MyThread()
            thr.start()
            thr.join()
            """,
        )
        out = self.run_command("coverage run --timid bug164.py")

        assert "Hello\n" in out
        assert "warning" not in out

    @pytest.mark.skipif(env.METACOV, reason="Can't test tracers changing during metacoverage")
    def test_warning_trace_function_changed(self) -> None:
        self.make_file(
            "settrace.py",
            """\
            import sys
            print("Hello")
            sys.settrace(None)
            print("Goodbye")
            """,
        )
        out = self.run_command("coverage run --timid settrace.py")
        assert "Hello\n" in out
        assert "Goodbye\n" in out

        assert "Trace function changed" in out

    # When meta-coverage testing, this test doesn't work, because it finds
    # coverage.py's own trace function.
    @pytest.mark.skipif(env.METACOV, reason="Can't test timid during coverage measurement.")
    def test_timid(self) -> None:
        # Test that the --timid command line argument properly swaps the tracer
        # function for a simpler one.
        #
        # This is complicated by the fact that the tests are run twice for each
        # version: once with a compiled C-based trace function, and once without
        # it, to also test the Python trace function.  So this test has to examine
        # an environment variable set in igor.py to know whether to expect to see
        # the C trace function or not.

        self.make_file(
            "showtrace.py",
            """\
            # Show the current frame's trace function, so that we can test what the
            # command-line options do to the trace function used.

            import inspect

            # Show what the trace function is.  If a C-based function is used, then f_trace
            # may be None.
            trace_fn = inspect.currentframe().f_trace
            if trace_fn is None:
                trace_name = "None"
            else:
                # Get the name of the tracer class.
                try:
                    trace_name = trace_fn.__self__.__class__.__name__
                except AttributeError:
                    # A C-based function could also manifest as an f_trace value
                    # which doesn't have __self__.
                    trace_name = trace_fn.__class__.__name__

            print(trace_name)
            """,
        )

        # When running without coverage, no trace function
        py_out = self.run_command("python showtrace.py")
        assert py_out == "None\n"

        cov_out = self.run_command("coverage run showtrace.py")
        if testenv.C_TRACER:
            # If the C trace function is being tested, then regular running should have
            # the C function, which registers itself as f_trace.
            assert cov_out == "CTracer\n"
        elif testenv.SYS_MON:
            assert cov_out == "None\n"
        else:
            # If the Python trace function is being tested, then regular running will
            # also show the Python function.
            assert cov_out == "PyTracer\n"

        # When running timidly, the trace function is always Python.
        timid_out = self.run_command("coverage run --timid showtrace.py")
        assert timid_out == "PyTracer\n"

    def test_warn_preimported(self) -> None:
        self.make_file(
            "hello.py",
            """\
            import goodbye
            import coverage
            cov = coverage.Coverage(include=["good*"], check_preimported=True)
            cov.start()
            print(goodbye.f())
            cov.stop()
            """,
        )
        self.make_file(
            "goodbye.py",
            """\
            def f():
                return "Goodbye!"
            """,
        )
        goodbye_path = os.path.abspath("goodbye.py")

        out = self.run_command("python hello.py")
        assert "Goodbye!" in out

        msg = (
            f"CoverageWarning: Already imported a file that will be measured: {goodbye_path} "
            + "(already-imported)"
        )
        assert msg in out

    # Pypy passes locally, but fails in CI? Perhaps the version of macOS is
    # significant?  https://foss.heptapod.net/pypy/pypy/-/issues/3074
    @pytest.mark.skipif(env.PYPY, reason="PyPy is unreliable with this test")
    def test_lang_c(self) -> None:
        # LANG=C forces getfilesystemencoding on Linux to 'ascii', which causes
        # failures with non-ascii file names. We don't want to make a real file
        # with strange characters, though, because that gets the test runners
        # tangled up.  This will isolate the concerns to the coverage.py code.
        # https://github.com/coveragepy/coveragepy/issues/533
        self.make_file(
            "weird_file.py",
            r"""
            globs = {}
            code = "a = 1\nb = 2\n"
            exec(compile(code, "wut\xe9\xea\xeb\xec\x01\x02.py", 'exec'), globs)
            print(globs['a'])
            print(globs['b'])
            """,
        )
        self.set_environ("LANG", "C")
        out = self.run_command("coverage run weird_file.py")
        assert out == "1\n2\n"

    def test_deprecation_warnings(self) -> None:
        # Test that coverage doesn't trigger deprecation warnings.
        # https://github.com/coveragepy/coveragepy/issues/305
        self.make_file(
            "allok.py",
            """\
            import warnings
            warnings.simplefilter('default')
            import coverage
            print("No warnings!")
            """,
        )

        # Some of our testing infrastructure can issue warnings.
        # Turn it all off for the subprocess.
        self.del_environ("COVERAGE_TESTING")

        out = self.run_command("python allok.py")
        assert out == "No warnings!\n"

    def test_run_twice(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/353
        self.make_file(
            "foo.py",
            """\
            def foo():
                pass
            """,
        )
        self.make_file(
            "run_twice.py",
            """\
            import sys
            import coverage

            for i in [1, 2]:
                sys.stderr.write(f"Run {i}\\n")
                inst = coverage.Coverage(source=['foo'])
                inst.load()
                inst.start()
                import foo
                inst.stop()
                inst.save()
            """,
        )
        out = self.run_command("python run_twice.py")
        # Remove the file location and source line from the warning.
        out = re.sub(r"(?m)^[\\/\w.:~_-]+:\d+: CoverageWarning: ", "f:d: CoverageWarning: ", out)
        out = re.sub(r"(?m)^\s+self.warn.*$\n", "", out)
        out = re.sub(r"; see https://.*$", "", out)
        expected = (
            "Run 1\n"
            + "Run 2\n"
            + "f:d: CoverageWarning: Module foo was previously imported, but not measured "
            + "(module-not-measured)\n"
        )
        assert out == expected

    def test_module_name(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/478
        # Make sure help doesn't show a silly command name when run as a
        # module, like it used to:
        #   $ python -m coverage
        #   Code coverage for Python.  Use '__main__.py help' for help.
        out = self.run_command("python -m coverage")
        assert "Use 'coverage help' for help" in out

    @pytest.mark.skipif(env.WINDOWS, reason="This test is not for Windows")
    def test_save_signal_usr1(self) -> None:
        self.assert_doesnt_exist(".coverage")
        self.make_file(
            "dummy_hello.py",
            """\
            import os
            import signal

            print(f"Sending SIGUSR1 to myself")
            os.kill(os.getpid(), signal.SIGUSR1)
            os.kill(os.getpid(), signal.SIGKILL)

            print("Done and goodbye")
            """,
        )
        out = self.run_command(
            "coverage run --save-signal=USR1 dummy_hello.py",
            status=-signal.SIGKILL,
        )
        # `startswith` because on Linux it also prints "Killed"
        assert out.startswith("Sending SIGUSR1 to myself\nSaving coverage data...\n")
        self.assert_exists(".coverage")
        out = self.run_command("coverage report -m")
        assert out == textwrap.dedent("""\
            Name             Stmts   Miss  Cover   Missing
            ----------------------------------------------
            dummy_hello.py       6      2    67%   6-8
            ----------------------------------------------
            TOTAL                6      2    67%
            """)


TRY_EXECFILE = os.path.join(os.path.dirname(__file__), "modules/process_test/try_execfile.py")


class EnvironmentTest(CoverageTest):
    """Tests using try_execfile.py to test the execution environment."""

    def assert_tryexecfile_output(self, expected: str, actual: str) -> None:
        """Assert that the output we got is a successful run of try_execfile.py.

        `expected` and `actual` must be the same.

        """
        # First, is this even credible try_execfile.py output?
        assert '"DATA": "xyzzy"' in actual
        # If this fails, "+" is actual, and "-" is expected
        assert actual == expected

    def test_coverage_run_is_like_python(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("run_me.py", f.read())
        expected = self.run_command("python run_me.py")
        actual = self.run_command("coverage run run_me.py")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_far_away_is_like_python(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("sub/overthere/prog.py", f.read())
        expected = self.run_command("python sub/overthere/prog.py")
        actual = self.run_command("coverage run sub/overthere/prog.py")
        self.assert_tryexecfile_output(expected, actual)

    @pytest.mark.skipif(not env.WINDOWS, reason="This is about Windows paths")
    def test_coverage_run_far_away_is_like_python_windows(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("sub/overthere/prog.py", f.read())
        expected = self.run_command("python sub\\overthere\\prog.py")
        actual = self.run_command("coverage run sub\\overthere\\prog.py")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dashm_is_like_python_dashm(self) -> None:
        self.add_test_modules_to_pythonpath()
        expected = self.run_command("python -m process_test.try_execfile")
        actual = self.run_command("coverage run -m process_test.try_execfile")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dir_is_like_python_dir(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("with_main/__main__.py", f.read())

        expected = self.run_command("python with_main")
        actual = self.run_command("coverage run with_main")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dashm_dir_no_init_is_like_python(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("with_main/__main__.py", f.read())

        expected = self.run_command("python -m with_main")
        actual = self.run_command("coverage run -m with_main")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dashm_dir_with_init_is_like_python(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("with_main/__main__.py", f.read())
        self.make_file("with_main/__init__.py", "")

        expected = self.run_command("python -m with_main")
        actual = self.run_command("coverage run -m with_main")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dashm_equal_to_doubledashsource(self) -> None:
        """regression test for #328

        When imported by -m, a module's __name__ is __main__, but we need the
        --source machinery to know and respect the original name.
        """
        self.add_test_modules_to_pythonpath()
        expected = self.run_command("python -m process_test.try_execfile")
        actual = self.run_command(
            "coverage run --source process_test.try_execfile -m process_test.try_execfile",
        )
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dashm_superset_of_doubledashsource(self) -> None:
        """Edge case: --source foo -m foo.bar"""
        # Ugh: without this config file, we'll get a warning about
        #   CoverageWarning: Module process_test was previously imported,
        #   but not measured (module-not-measured)
        #
        # This is because process_test/__init__.py is imported while looking
        # for process_test.try_execfile.  That import happens while setting
        # sys.path before start() is called.
        self.make_file(
            ".coveragerc",
            """\
            [run]
            disable_warnings = module-not-measured
            """,
        )
        self.add_test_modules_to_pythonpath()
        expected = self.run_command("python -m process_test.try_execfile")
        actual = self.run_command(
            "coverage run --source process_test -m process_test.try_execfile",
        )
        self.assert_tryexecfile_output(expected, actual)

        st, out = self.run_command_status("coverage report")
        assert st == 0
        assert self.line_count(out) == 6, out

    def test_coverage_run_script_imports_doubledashsource(self) -> None:
        # This file imports try_execfile, which compiles it to .pyc, so the
        # first run will have __file__ == "try_execfile.py" and the second will
        # have __file__ == "try_execfile.pyc", which throws off the comparison.
        # Setting dont_write_bytecode True stops the compilation to .pyc and
        # keeps the test working.
        self.make_file(
            "myscript",
            """\
            import sys; sys.dont_write_bytecode = True
            import process_test.try_execfile
            """,
        )

        self.add_test_modules_to_pythonpath()
        expected = self.run_command("python myscript")
        actual = self.run_command("coverage run --source process_test myscript")
        self.assert_tryexecfile_output(expected, actual)

        st, out = self.run_command_status("coverage report")
        assert st == 0
        assert self.line_count(out) == 6, out

    def test_coverage_run_dashm_is_like_python_dashm_off_path(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/242
        self.make_file("sub/__init__.py", "")
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("sub/run_me.py", f.read())

        expected = self.run_command("python -m sub.run_me")
        actual = self.run_command("coverage run -m sub.run_me")
        self.assert_tryexecfile_output(expected, actual)

    def test_coverage_run_dashm_is_like_python_dashm_with__main__207(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/207
        self.make_file("package/__init__.py", "print('init')")
        self.make_file("package/__main__.py", "print('main')")
        expected = self.run_command("python -m package")
        actual = self.run_command("coverage run -m package")
        assert expected == actual

    def test_coverage_zip_is_like_python(self) -> None:
        # Test running coverage from a zip file itself.  Some environments
        # (windows?) zip up the coverage main to be used as the coverage
        # command.
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("run_me.py", f.read())
        expected = self.run_command("python run_me.py")
        cov_main = os.path.join(TESTS_DIR, "covmain.zip")
        actual = self.run_command(f"python {cov_main} run run_me.py")
        self.assert_tryexecfile_output(expected, actual)

    @pytest.mark.skipif(env.PYVERSION < (3, 11), reason="PYTHONSAFEPATH is new in 3.11")
    @pytest.mark.skipif(
        env.WINDOWS,
        reason="Windows gets this wrong: https://github.com/python/cpython/issues/131484",
    )
    def test_pythonsafepath(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("run_me.py", f.read())
        self.set_environ("PYTHONSAFEPATH", "1")
        expected = self.run_command("python run_me.py")
        actual = self.run_command("coverage run run_me.py")
        self.assert_tryexecfile_output(expected, actual)

    @pytest.mark.skipif(env.PYVERSION < (3, 11), reason="PYTHONSAFEPATH is new in 3.11")
    def test_pythonsafepath_dashm_runme(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("run_me.py", f.read())
        self.set_environ("PYTHONSAFEPATH", "1")
        expected = self.run_command("python run_me.py")
        actual = self.run_command("python -m coverage run run_me.py")
        self.assert_tryexecfile_output(expected, actual)

    @pytest.mark.skipif(env.PYVERSION < (3, 11), reason="PYTHONSAFEPATH is new in 3.11")
    def test_pythonsafepath_dashm(self) -> None:
        with open(TRY_EXECFILE, encoding="utf-8") as f:
            self.make_file("with_main/__main__.py", f.read())

        self.set_environ("PYTHONSAFEPATH", "1")
        expected = self.run_command("python -m with_main", status=1)
        actual = self.run_command("coverage run -m with_main", status=1)
        assert re.search("No module named '?with_main'?", actual)
        assert re.search("No module named '?with_main'?", expected)

    def test_coverage_custom_script(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/678
        # If sys.path[0] isn't the Python default, then coverage.py won't
        # fiddle with it.
        self.make_file(
            "a/b/c/thing.py",
            """\
            SOMETHING = "hello-xyzzy"
            """,
        )
        abc = os.path.abspath("a/b/c")
        self.make_file(
            "run_coverage.py",
            f"""\
            import sys
            sys.path[0:0] = [
                r'{abc}',
                '/Users/somebody/temp/something/eggs/something-4.5.1-py2.7-xxx-10.13-x86_64.egg',
            ]

            import coverage.cmdline

            if __name__ == '__main__':
                sys.exit(coverage.cmdline.main())
            """,
        )
        self.make_file(
            "how_is_it.py",
            """\
            import pprint, sys
            pprint.pprint(sys.path)
            import thing
            print(thing.SOMETHING)
            """,
        )
        # If this test fails, it will be with "can't import thing".
        out = self.run_command("python run_coverage.py run how_is_it.py")
        assert "hello-xyzzy" in out

        out = self.run_command("python -m run_coverage run how_is_it.py")
        assert "hello-xyzzy" in out

    @pytest.mark.skipif(env.WINDOWS, reason="Windows can't make symlinks")
    @pytest.mark.skipif(
        platform.python_version().endswith("+"),
        reason="setuptools barfs on dev versions: https://github.com/pypa/packaging/issues/678",
        # https://github.com/coveragepy/coveragepy/issues/1556
    )
    def test_bug_862(self) -> None:
        # This used to simulate how pyenv and pyenv-virtualenv create the
        # coverage executable.  Now the code shows how venv does it.
        self.make_file(
            "elsewhere/bin/fake-coverage",
            f"""\
            #!{sys.executable}
            import re
            import sys
            from coverage.cmdline import main
            if __name__ == '__main__':
                sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])
                sys.exit(main())
            """,
        )
        os.chmod("elsewhere/bin/fake-coverage", stat.S_IREAD | stat.S_IEXEC)
        os.symlink("elsewhere", "somewhere")
        self.make_file("foo.py", "print('inside foo')")
        self.make_file("bar.py", "import foo")
        out = self.run_command("somewhere/bin/fake-coverage run bar.py")
        assert "inside foo\n" == out

    def test_bug_909(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/909
        # The __init__ files were being imported before measurement started,
        # so the line in __init__.py was being marked as missed, and there were
        # warnings about measured files being imported before start.
        self.make_file("proj/__init__.py", "print('Init')")
        self.make_file("proj/thecode.py", "print('The code')")
        self.make_file("proj/tests/__init__.py", "")
        self.make_file("proj/tests/test_it.py", "import proj.thecode")

        expected = "Init\nThe code\n"
        actual = self.run_command("coverage run --source=proj -m proj.tests.test_it")
        assert expected == actual

        report = self.run_command("coverage report -m")

        # Name                     Stmts   Miss  Cover   Missing
        # ------------------------------------------------------
        # proj/__init__.py             1      0   100%
        # proj/tests/__init__.py       0      0   100%
        # proj/tests/test_it.py        1      0   100%
        # proj/thecode.py              1      0   100%
        # ------------------------------------------------------
        # TOTAL                        3      0   100%

        squeezed = self.squeezed_lines(report)
        assert squeezed[2].replace("\\", "/") == "proj/__init__.py 1 0 100%"


class ExcepthookTest(CoverageTest):
    """Tests of sys.excepthook support."""

    # TODO: do we need these as process tests if we have test_execfile.py:RunFileTest?

    def test_excepthook(self) -> None:
        self.make_file(
            "excepthook.py",
            """\
            import sys

            def excepthook(*args):
                print('in excepthook')
                if maybe == 2:
                    print('definitely')

            sys.excepthook = excepthook

            maybe = 1
            raise RuntimeError('Error Outside')
            """,
        )
        cov_st, cov_out = self.run_command_status("coverage run excepthook.py")
        py_st, py_out = self.run_command_status("python excepthook.py")
        assert cov_st == py_st
        assert cov_st == 1
        assert "in excepthook" in py_out
        assert cov_out == py_out

        # Read the coverage file and see that excepthook.py has 7 lines
        # executed.
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["excepthook.py"] == 7

    @pytest.mark.skipif(
        not env.CPYTHON,
        reason="non-CPython handles excepthook exits differently, punt for now.",
    )
    def test_excepthook_exit(self) -> None:
        self.make_file(
            "excepthook_exit.py",
            """\
            import sys

            def excepthook(*args):
                print('in excepthook')
                sys.exit(0)

            sys.excepthook = excepthook

            raise RuntimeError('Error Outside')
            """,
        )
        cov_st, cov_out = self.run_command_status("coverage run excepthook_exit.py")
        py_st, py_out = self.run_command_status("python excepthook_exit.py")
        assert cov_st == py_st
        assert cov_st == 0

        assert py_out == "in excepthook\n"
        assert cov_out == py_out

    @pytest.mark.skipif(env.PYPY, reason="PyPy handles excepthook throws differently.")
    def test_excepthook_throw(self) -> None:
        self.make_file(
            "excepthook_throw.py",
            """\
            import sys

            def excepthook(*args):
                # Write this message to stderr so that we don't have to deal
                # with interleaved stdout/stderr comparisons in the assertions
                # in the test.
                sys.stderr.write('in excepthook\\n')
                raise RuntimeError('Error Inside')

            sys.excepthook = excepthook

            raise RuntimeError('Error Outside')
            """,
        )
        cov_out = self.run_command("coverage run excepthook_throw.py", status=1)
        py_out = self.run_command("python excepthook_throw.py", status=1)
        assert "in excepthook" in py_out
        assert cov_out == py_out


class AliasedCommandTest(CoverageTest):
    """Tests of the version-specific command aliases."""

    run_in_temp_dir = False

    def test_major_version_works(self) -> None:
        # "coverage3" works on py3
        cmd = "coverage%d" % sys.version_info[0]
        out = self.run_command(cmd)
        assert "Code coverage for Python" in out

    def test_wrong_alias_doesnt_work(self) -> None:
        # "coverage2" doesn't work on py3
        assert sys.version_info[0] == 3  # Let us know when Python 4 is out...
        badcmd = "coverage2"
        status, out = self.run_command_status(badcmd)
        assert "Code coverage for Python" not in out
        assert status != 0

    def test_specific_alias_works(self) -> None:
        # "coverage-3.9" works on py3.9
        cmd = "coverage-%d.%d" % sys.version_info[:2]
        out = self.run_command(cmd)
        assert "Code coverage for Python" in out

    @pytest.mark.parametrize(
        "cmd",
        [
            "coverage",
            "coverage%d" % sys.version_info[0],
            "coverage-%d.%d" % sys.version_info[:2],
        ],
    )
    def test_aliases_used_in_messages(self, cmd: str) -> None:
        out = self.run_command(f"{cmd} foobar", status=1)
        assert "Unknown command: 'foobar'" in out
        assert f"Use '{cmd} help' for help" in out


class PydocTest(CoverageTest):
    """Test that pydoc can get our information."""

    run_in_temp_dir = False

    def assert_pydoc_ok(self, name: str, thing: Any) -> None:
        """Check that pydoc of `name` finds the docstring from `thing`."""
        # Run pydoc.
        out = self.run_command("python -m pydoc " + name)
        # It should say "Help on..", and not have a traceback
        assert out.startswith("Help on ")
        assert "Traceback" not in out

        # All of the lines in the docstring should be there somewhere.
        for line in thing.__doc__.splitlines():
            assert line.strip() in out

    def test_pydoc_coverage(self) -> None:
        self.assert_pydoc_ok("coverage", coverage)

    def test_pydoc_coverage_coverage(self) -> None:
        self.assert_pydoc_ok("coverage.Coverage", coverage.Coverage)


class FailUnderTest(CoverageTest):
    """Tests of the --fail-under switch."""

    def setUp(self) -> None:
        super().setUp()
        self.make_file(
            "forty_two_plus.py",
            """\
            # I have 42.857% (3/7) coverage!
            a = 1
            b = 2
            if a > 3:
                b = 4
                c = 5
                d = 6
                e = 7
            """,
        )
        self.make_data_file(lines={abs_file("forty_two_plus.py"): [2, 3, 4]})

    def test_report_43_is_ok(self) -> None:
        st, out = self.run_command_status("coverage report --fail-under=43")
        assert st == 0
        assert self.last_line_squeezed(out) == "TOTAL 7 4 43%"

    def test_report_43_is_not_ok(self) -> None:
        st, out = self.run_command_status("coverage report --fail-under=44")
        assert st == 2
        expected = "Coverage failure: total of 43 is less than fail-under=44"
        assert expected == self.last_line_squeezed(out)

    def test_report_42p86_is_not_ok(self) -> None:
        self.make_file(".coveragerc", "[report]\nprecision = 2")
        st, out = self.run_command_status("coverage report --fail-under=42.88")
        assert st == 2
        expected = "Coverage failure: total of 42.86 is less than fail-under=42.88"
        assert expected == self.last_line_squeezed(out)

    def test_report_99p9_is_not_ok(self) -> None:
        # A file with 99.9% coverage:
        self.make_file(
            "ninety_nine_plus.py",
            "a = 1\n" + "b = 2\n" * 2000 + "if a > 3:\n" + "    c = 4\n",
        )
        self.make_data_file(lines={abs_file("ninety_nine_plus.py"): range(1, 2002)})
        st, out = self.run_command_status("coverage report --fail-under=100")
        assert st == 2
        expected = "Coverage failure: total of 99 is less than fail-under=100"
        assert expected == self.last_line_squeezed(out)


class FailUnderNoFilesTest(CoverageTest):
    """Test that nothing to report results in an error exit status."""

    def test_report(self) -> None:
        self.make_file(".coveragerc", "[report]\nfail_under = 99\n")
        st, out = self.run_command_status("coverage report")
        assert "No data to report." in out
        assert st == 1


class FailUnderEmptyFilesTest(CoverageTest):
    """Test that empty files produce the proper fail_under exit status."""

    def test_report(self) -> None:
        self.make_file(".coveragerc", "[report]\nfail_under = 99\n")
        self.make_file("empty.py", "")
        st, _ = self.run_command_status("coverage run empty.py")
        assert st == 0
        st, _ = self.run_command_status("coverage report")
        # An empty file is marked as 100% covered, so this is ok.
        assert st == 0


@pytest.mark.skipif(env.WINDOWS, reason="Windows can't delete the directory in use.")
class YankedDirectoryTest(CoverageTest):
    """Tests of what happens when the current directory is deleted."""

    BUG_806 = """\
        import os
        import sys
        import tempfile

        tmpdir = tempfile.mkdtemp()
        os.chdir(tmpdir)
        os.rmdir(tmpdir)
        print(sys.argv[1])
        """

    def test_removing_directory(self) -> None:
        self.make_file("bug806.py", self.BUG_806)
        out = self.run_command("coverage run bug806.py noerror")
        assert out == "noerror\n"

    def test_removing_directory_with_error(self) -> None:
        self.make_file("bug806.py", self.BUG_806)
        out = self.run_command("coverage run bug806.py", status=1)
        path = python_reported_file("bug806.py")
        # Python 3.11 adds an extra line to the traceback.
        # Check that the lines we expect are there.
        lines = textwrap.dedent(f"""\
            Traceback (most recent call last):
              File "{path}", line 8, in <module>
                print(sys.argv[1])
            IndexError: list index out of range
            """).splitlines(keepends=True)
        assert all(line in out for line in lines)


@pytest.mark.skipif(env.METACOV, reason="Can't test subprocess pth file during metacoverage")
@pytest.mark.xdist_group(name="needs_pth")
class ProcessStartupTest(CoverageTest):
    """Test that we can measure coverage in subprocesses."""

    def make_main_and_sub(self) -> None:
        """Create main.py and sub.py."""
        # Main will run sub.py
        self.make_file(
            "main.py",
            """\
            import os, os.path, sys
            ex = os.path.basename(sys.executable)
            os.system(ex + " sub.py")
            """,
        )
        # sub.py will write a few lines.
        self.make_file(
            "sub.py",
            """\
            with open("out.txt", "w", encoding="utf-8") as f:
                f.write("Hello, world!\\n")
            a = 3
            """,
        )

    def test_patch_subprocess(self) -> None:
        self.make_main_and_sub()
        self.make_file(
            ".coveragerc",
            """\
            [run]
            patch = subprocess
            """,
        )
        self.run_command("coverage run main.py")
        self.run_command("coverage combine")
        self.assert_exists(".coverage")
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["main.py"] == 3
        assert line_counts(data)["sub.py"] == 3

    def test_subprocess_with_pth_files(self) -> None:
        # An existing data file should not be read when a subprocess gets
        # measured automatically.  Create the data file here with bogus data in
        # it.
        self.make_main_and_sub()
        data = coverage.CoverageData(".mycovdata")
        data.add_lines({os.path.abspath("sub.py"): range(100)})
        data.write()

        self.make_file(
            "coverage.ini",
            """\
            [run]
            data_file = .mycovdata
            """,
        )
        self.set_environ("COVERAGE_PROCESS_START", "coverage.ini")
        import main  # pylint: disable=unused-import, import-error

        with open("out.txt", encoding="utf-8") as f:
            assert f.read() == "Hello, world!\n"

        # Read the data from .coverage
        self.assert_exists(".mycovdata")
        data = coverage.CoverageData(".mycovdata")
        data.read()
        assert line_counts(data)["sub.py"] == 3

    def test_subprocess_with_pth_files_and_parallel(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/492
        self.make_main_and_sub()
        self.make_file(
            "coverage.ini",
            """\
            [run]
            parallel = true
            """,
        )

        self.set_environ("COVERAGE_PROCESS_START", "coverage.ini")
        self.run_command("coverage run main.py")

        with open("out.txt", encoding="utf-8") as f:
            assert f.read() == "Hello, world!\n"

        self.run_command("coverage combine")

        # assert that the combined .coverage data file is correct
        self.assert_exists(".coverage")
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["sub.py"] == 3

        # assert that there are *no* extra data files left over after a combine
        data_files = glob.glob(os.getcwd() + "/.coverage*")
        msg = (
            "Expected only .coverage after combine, looks like there are "
            + f"extra data files that were not cleaned up: {data_files!r}"
        )
        assert len(data_files) == 1, msg

    def test_subprocess_in_directories(self) -> None:
        # Bug 2025: patch=subprocess didn't find data files from subdirectory
        # subprocesses.
        self.make_file(
            "main.py",
            """\
            import subprocess
            import sys
            print(subprocess.check_output(
                [sys.executable, "subproc.py"],
                cwd="subdir",
                encoding="utf-8",
            ))
            """,
        )
        self.make_file(
            "subdir/subproc.py",
            """\
            with open("readme.txt", encoding="utf-8") as f:
                print(f.read(), end="")
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            patch = subprocess
            data_file = .covdata
            """,
        )
        self.make_file("subdir/readme.txt", "hello")
        out = self.run_command("coverage run main.py")
        assert out == "hello\n"
        self.run_command("coverage combine")
        data = coverage.CoverageData(".covdata")
        data.read()
        assert line_counts(data)["main.py"] == 6
        assert line_counts(data)["subproc.py"] == 2

    @pytest.mark.skipif(
        not testenv.CAN_MEASURE_BRANCHES, reason="Can't measure branches with this core"
    )
    def test_subprocess_gets_nonfile_config(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/2021
        self.make_file(
            "subfunctions.py",
            """\
            import subprocess, sys

            def f1():
                print("function 1")
            def f2():
                print("function 2")

            functions = [f1, f2]

            cases = sys.argv[1:]
            if len(cases) > 1:
                for c in cases:
                    subprocess.call([sys.executable, __file__, c])
            else:
                functions[int(cases[0])]()
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            patch = subprocess
            """,
        )
        out = self.run_command("coverage run --branch subfunctions.py 0 1")
        assert out.endswith("function 1\nfunction 2\n")
        self.run_command("coverage combine")
        data = coverage.CoverageData()
        data.read()
        assert line_counts(data)["subfunctions.py"] == 11

    def test_subprocess_dir_with_source(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1499
        self.make_file("main/d/README", "A sub-directory")
        self.make_file(
            "main/main.py",
            """\
            import os, subprocess, sys
            orig = os.getcwd()
            os.chdir("./d")
            subprocess.run([sys.executable, f"{orig}/sub.py"])
            os.chdir(orig)
            """,
        )
        self.make_file("lib/other.py", "print('Other', flush=True)")
        self.make_file(
            "main/sub.py",
            """
            import other
            print("Hello, world!", flush=True)
            """,
        )
        self.make_file(
            "main/pyproject.toml",
            """\
            [tool.coverage.run]
            patch = ["subprocess"]
            source = [".", "other"]
            disable_warnings = ["module-not-imported"]
            """,
        )
        self.set_environ("PYTHONPATH", os.path.abspath("lib"))
        with change_dir("main"):
            out = self.run_command("coverage run main.py")
            assert out == "Other\nHello, world!\n"
            self.run_command("coverage combine")
            data = coverage.CoverageData()
            data.read()
            assert line_counts(data) == {"main.py": 5, "sub.py": 2, "other.py": 1}


@pytest.mark.skipif(env.WINDOWS, reason="patch=execv isn't supported on Windows")
@pytest.mark.xdist_group(name="needs_pth")
class ExecvTest(CoverageTest):
    """Test that we can measure coverage in subprocesses."""

    @pytest.mark.parametrize(
        "fname",
        [
            base + suffix
            for base, suffix in itertools.product(
                ["exec", "spawn"],
                ["l", "le", "lp", "lpe", "v", "ve", "vp", "vpe"],
            )
        ],
    )
    def test_execv_patch(self, fname: str) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [run]
            patch = subprocess, execv
            """,
        )
        self.make_file(
            "main.py",
            f"""\
            import os, sys
            print("In main")
            args = []
            if "spawn" in {fname!r}:
                args.append(os.P_WAIT)
            args.append(sys.executable)
            prog_args = ["python", {os.path.abspath("other.py")!r}, "cat", "dog"]
            if "l" in {fname!r}:
                args.extend(prog_args)
            else:
                args.append(prog_args)
            if {fname!r}.endswith("e"):
                args.append({{"SUBVAR": "the-sub-var"}})
            os.environ["MAINVAR"] = "the-main-var"
            sys.stdout.flush()
            os.{fname}(*args)
            """,
        )
        self.make_file(
            "other.py",
            """\
            import os, sys
            print(f"MAINVAR = {os.getenv('MAINVAR', 'none')}")
            print(f"SUBVAR = {os.getenv('SUBVAR', 'none')}")
            print(f"{sys.argv[1:] = }")
            """,
        )

        out = self.run_command("coverage run main.py")
        expected = "In main\n"
        if fname.endswith("e"):
            expected += "MAINVAR = none\n"
            expected += "SUBVAR = the-sub-var\n"
        else:
            expected += "MAINVAR = the-main-var\n"
            expected += "SUBVAR = none\n"
        expected += "sys.argv[1:] = ['cat', 'dog']\n"
        assert out == expected

        self.run_command("coverage combine")
        data = coverage.CoverageData()
        data.read()

        main_lines = 12
        if "spawn" in fname:
            main_lines += 1
        if fname.endswith("e"):
            main_lines += 1

        assert line_counts(data)["main.py"] == main_lines
        assert line_counts(data)["other.py"] == 4


class ProcessStartupWithSourceTest(CoverageTest):
    """Show that we can configure {[run]source} during process-level coverage.

    There are three interesting variables, for a total of eight tests:

        1. -m versus a simple script argument (for example, `python myscript`),

        2. filtering for the top-level (main.py) or second-level (sub.py)
           module, and

        3. whether the files are in a package or not.

    """

    @pytest.mark.parametrize("dashm", ["-m", ""])
    @pytest.mark.parametrize("package", ["pkg", ""])
    @pytest.mark.parametrize("source", ["main", "sub"])
    @pytest.mark.xdist_group(name="needs_pth")
    def test_pth_and_source_work_together(
        self,
        dashm: str,
        package: str,
        source: str,
    ) -> None:
        """Run the test for a particular combination of factors.

        The arguments are all strings:

        * `dashm`: Either "" (run the program as a file) or "-m" (run the
          program as a module).

        * `package`: Either "" (put the source at the top level) or a
          package name to use to hold the source.

        * `source`: Either "main" or "sub", which file to use as the
          ``--source`` argument.

        """

        def fullname(modname: str) -> str:
            """What is the full module name for `modname` for this test?"""
            if package and dashm:
                return ".".join((package, modname))
            else:
                return modname

        def path(basename: str) -> str:
            """Where should `basename` be created for this test?"""
            return os.path.join(package, basename)

        # Main will run sub.py.
        self.make_file(
            path("main.py"),
            """\
            import %s
            a = 2
            b = 3
            """
            % fullname("sub"),
        )
        if package:
            self.make_file(path("__init__.py"), "")
        # sub.py will write a few lines.
        self.make_file(
            path("sub.py"),
            """\
            with open("out.txt", "w", encoding="utf-8") as f:
                f.write("Hello, world!")
            a = 3
            """,
        )
        self.make_file(
            "coverage.ini",
            """\
            [run]
            source = %s
            """
            % fullname(source),
        )

        self.set_environ("COVERAGE_PROCESS_START", "coverage.ini")

        if dashm:
            cmd = "python -m %s" % fullname("main")
        else:
            cmd = "python %s" % path("main.py")

        self.run_command(cmd)

        with open("out.txt", encoding="utf-8") as f:
            assert f.read() == "Hello, world!"

        # Read the data from .coverage
        self.assert_exists(".coverage")
        data = coverage.CoverageData()
        data.read()
        summary = line_counts(data)
        assert summary[source + ".py"] == 3
        assert len(summary) == 1
