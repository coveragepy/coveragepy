# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for concurrency libraries."""

from __future__ import annotations

import glob
import multiprocessing
import os
import pathlib
import random
import re
import sys
import threading
import time

from types import ModuleType
from collections.abc import Iterable

import pytest

import coverage
from coverage import env
from coverage.data import line_counts
from coverage.exceptions import ConfigError
from coverage.files import abs_file
from coverage.misc import import_local_file

from tests import testenv
from tests.coveragetest import CoverageTest


# These libraries aren't always available, we'll skip tests if they aren't.

try:
    import eventlet
except ImportError:
    eventlet = None

try:
    import gevent
except ImportError:
    gevent = None

try:
    import greenlet
except ImportError:
    greenlet = None


def measurable_line(l: str) -> bool:
    """Is this a line of code coverage will measure?

    Not blank, not a comment, and not "else"
    """
    l = l.strip()
    if not l:
        return False
    if l.startswith("#"):
        return False
    if l.startswith("else:"):
        return False
    return True


def line_count(s: str) -> int:
    """How many measurable lines are in `s`?"""
    return len(list(filter(measurable_line, s.splitlines())))


def print_simple_annotation(code: str, linenos: Iterable[int]) -> None:
    """Print the lines in `code` with X for each line number in `linenos`."""
    for lineno, line in enumerate(code.splitlines(), start=1):
        print(" {} {}".format("X" if lineno in linenos else " ", line))


class LineCountTest(CoverageTest):
    """Test the helpers here."""

    run_in_temp_dir = False

    def test_line_count(self) -> None:
        CODE = """
            # Hey there!
            x = 1
            if x:
                print("hello")
            else:
                print("bye")

            print("done")
            """

        assert line_count(CODE) == 5


# The code common to all the concurrency models.
SUM_RANGE_Q = """
    # Above this will be imports defining queue and threading.

    class Producer(threading.Thread):
        def __init__(self, limit, q):
            threading.Thread.__init__(self)
            self.limit = limit
            self.q = q

        def run(self):
            for i in range(self.limit):
                self.q.put(i)
            self.q.put(None)

    class Consumer(threading.Thread):
        def __init__(self, q, qresult):
            threading.Thread.__init__(self)
            self.q = q
            self.qresult = qresult

        def run(self):
            sum = 0
            while "no peephole".upper():
                i = self.q.get()
                if i is None:
                    break
                sum += i
            self.qresult.put(sum)

    def sum_range(limit):
        q = queue.Queue()
        qresult = queue.Queue()
        c = Consumer(q, qresult)
        p = Producer(limit, q)
        c.start()
        p.start()

        p.join()
        c.join()
        return qresult.get()

    # Below this will be something using sum_range.
    """

PRINT_SUM_RANGE = """
    print(sum_range({QLIMIT}))
    """

# Import the things to use threads.
THREAD = """
    import threading
    import queue
    """

# Import the things to use eventlet.
EVENTLET = """
    import eventlet.green.threading as threading
    import eventlet.queue as queue
    """

# Import the things to use gevent.
GEVENT = """
    from gevent import monkey
    monkey.patch_thread()
    import threading
    import gevent.queue as queue
    """

# Uncomplicated code that doesn't use any of the concurrency stuff, to test
# the simple case under each of the regimes.
SIMPLE = """
    total = 0
    for i in range({QLIMIT}):
        total += i
    print(total)
    """


def cant_trace_msg(concurrency: str, the_module: ModuleType | None) -> str | None:
    """What might coverage.py say about a concurrency setting and imported module?"""
    # In the concurrency choices, "multiprocessing" doesn't count, so remove it.
    if "multiprocessing" in concurrency:
        parts = concurrency.split(",")
        parts.remove("multiprocessing")
        concurrency = ",".join(parts)

    if testenv.SYS_MON and concurrency:
        expected_out = f"Can't use core=sysmon: it doesn't support concurrency={concurrency}"
    elif the_module is None:
        # We don't even have the underlying module installed, we expect
        # coverage to alert us to this fact.
        expected_out = f"Couldn't trace with concurrency={concurrency}, the module isn't installed."
    elif testenv.C_TRACER or concurrency == "thread" or concurrency == "":
        expected_out = None
    else:
        expected_out = (
            f"Can't support concurrency={concurrency} with {testenv.REQUESTED_TRACER_CLASS}, "
            + "only threads are supported."
        )
    return expected_out


class ConcurrencyTest(CoverageTest):
    """Tests of the concurrency support in coverage.py."""

    QLIMIT = 1000

    def try_some_code(
        self,
        code: str,
        concurrency: str,
        the_module: ModuleType,
        expected_out: str | None = None,
    ) -> None:
        """Run some concurrency testing code and see that it was all covered.

        `code` is the Python code to execute.  `concurrency` is the name of
        the concurrency regime to test it under.  `the_module` is the imported
        module that must be available for this to work at all. `expected_out`
        is the text we expect the code to produce.

        """
        self.make_file("try_it.py", code)

        cmd = f"coverage run --concurrency={concurrency} try_it.py"
        _, out = self.run_command_status(cmd)

        expected_cant_trace = cant_trace_msg(concurrency, the_module)

        if expected_cant_trace is not None:
            assert expected_cant_trace in out
            pytest.skip(f"Can't test: {expected_cant_trace}")
        else:
            # We can fully measure the code if we are using the C tracer, which
            # can support all the concurrency, or if we are using threads.
            if expected_out is None:
                expected_out = "%d\n" % (sum(range(self.QLIMIT)))
            print(code)
            assert out == expected_out

            # Read the coverage file and see that try_it.py has all its lines
            # executed.
            data = coverage.CoverageData(".coverage")
            data.read()

            # If the test fails, it's helpful to see this info:
            fname = abs_file("try_it.py")
            linenos = data.lines(fname)
            assert linenos is not None
            print(f"{len(linenos)}: {linenos}")
            print_simple_annotation(code, linenos)

            lines = line_count(code)
            assert line_counts(data)["try_it.py"] == lines

    @pytest.mark.skipif(
        not testenv.CAN_MEASURE_THREADS, reason="Can't measure threads with this core."
    )
    def test_threads(self) -> None:
        code = (THREAD + SUM_RANGE_Q + PRINT_SUM_RANGE).format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "thread", threading)

    @pytest.mark.skipif(
        not testenv.CAN_MEASURE_THREADS, reason="Can't measure threads with this core."
    )
    def test_threads_simple_code(self) -> None:
        code = SIMPLE.format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "thread", threading)

    def test_eventlet(self) -> None:
        code = (EVENTLET + SUM_RANGE_Q + PRINT_SUM_RANGE).format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "eventlet", eventlet)

    def test_eventlet_simple_code(self) -> None:
        code = SIMPLE.format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "eventlet", eventlet)

    # https://github.com/coveragepy/coveragepy/issues/663
    @pytest.mark.skipif(env.WINDOWS, reason="gevent has problems on Windows: #663")
    def test_gevent(self) -> None:
        code = (GEVENT + SUM_RANGE_Q + PRINT_SUM_RANGE).format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "gevent", gevent)

    def test_gevent_simple_code(self) -> None:
        code = SIMPLE.format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "gevent", gevent)

    def test_greenlet(self) -> None:
        GREENLET = """\
            from greenlet import greenlet

            def test1(x, y):
                z = gr2.switch(x+y)
                print(z)

            def test2(u):
                print(u)
                gr1.switch(42)

            gr1 = greenlet(test1)
            gr2 = greenlet(test2)
            gr1.switch("hello", " world")
            """
        self.try_some_code(GREENLET, "greenlet", greenlet, "hello world\n42\n")

    def test_greenlet_simple_code(self) -> None:
        code = SIMPLE.format(QLIMIT=self.QLIMIT)
        self.try_some_code(code, "greenlet", greenlet)

    def test_bug_330(self) -> None:
        BUG_330 = """\
            from weakref import WeakKeyDictionary
            import eventlet

            def do():
                eventlet.sleep(.01)

            gts = WeakKeyDictionary()
            for _ in range(100):
                gts[eventlet.spawn(do)] = True
                eventlet.sleep(.005)

            eventlet.sleep(.1)
            print(len(gts))
            """
        self.try_some_code(BUG_330, "eventlet", eventlet, "0\n")

    # Sometimes a test fails due to inherent randomness. Try more times.
    @pytest.mark.skipif(
        not testenv.CAN_MEASURE_THREADS, reason="Can't measure threads with this core."
    )
    @pytest.mark.flaky(max_runs=3)
    def test_threads_with_gevent(self) -> None:
        self.make_file(
            "both.py",
            """\
            import queue
            import threading

            import gevent

            def work1(q):
                q.put(1)

            def gwork(q):
                gevent.spawn(work1, q).join()
                q.put(None)
                print("done")

            q = queue.Queue()
            t = threading.Thread(target=gwork, args=(q,))
            t.start()
            t.join()

            answer = q.get()
            assert answer == 1
            """,
        )
        _, out = self.run_command_status("coverage run --concurrency=thread,gevent both.py")
        if gevent is None:
            assert "Couldn't trace with concurrency=gevent, the module isn't installed.\n" in out
            pytest.skip("Can't run test without gevent installed.")
        if not testenv.C_TRACER:
            assert testenv.PY_TRACER
            assert out == (
                "Can't support concurrency=gevent with PyTracer, only threads are supported.\n"
            )
            pytest.skip(f"Can't run gevent with {testenv.REQUESTED_TRACER_CLASS}.")

        assert out == "done\n"

        out = self.run_command("coverage report -m")
        last_line = self.squeezed_lines(out)[-1]
        assert re.search(r"TOTAL \d+ 0 100%", last_line)

    def test_bad_concurrency(self) -> None:
        with pytest.raises(ConfigError, match="Unknown concurrency choices: nothing"):
            self.command_line("run --concurrency=nothing prog.py")

    def test_bad_concurrency_in_config(self) -> None:
        self.make_file(".coveragerc", "[run]\nconcurrency = nothing\n")
        with pytest.raises(ConfigError, match="Unknown concurrency choices: nothing"):
            self.command_line("run prog.py")

    def test_no_multiple_light_concurrency(self) -> None:
        with pytest.raises(ConfigError, match="Conflicting concurrency settings: eventlet, gevent"):
            self.command_line("run --concurrency=gevent,eventlet prog.py")

    def test_no_multiple_light_concurrency_in_config(self) -> None:
        self.make_file(".coveragerc", "[run]\nconcurrency = gevent, eventlet\n")
        with pytest.raises(ConfigError, match="Conflicting concurrency settings: eventlet, gevent"):
            self.command_line("run prog.py")

    def test_multiprocessing_needs_config_file(self) -> None:
        with pytest.raises(ConfigError, match="multiprocessing requires a configuration file"):
            self.command_line("run --concurrency=multiprocessing prog.py")


class WithoutConcurrencyModuleTest(CoverageTest):
    """Tests of what happens if the requested concurrency isn't installed."""

    @pytest.mark.parametrize("module", ["eventlet", "gevent", "greenlet"])
    def test_missing_module(self, module: str) -> None:
        self.make_file("prog.py", "a = 1")
        sys.modules[module] = None  # type: ignore[assignment]
        msg = rf"Couldn't trace with concurrency={module}, the module isn't installed."
        with pytest.raises(ConfigError, match=msg):
            self.command_line(f"run --concurrency={module} prog.py")


SQUARE_OR_CUBE_WORK = """
    def work(x):
        # Use different lines in different subprocesses.
        if x % 2:
            y = x*x
        else:
            y = x*x*x
        return y
    """

SUM_RANGE_WORK = """
    def work(x):
        return sum_range((x+1)*100)
    """

MULTI_CODE = """
    # Above this will be a definition of work().
    import multiprocessing
    import os
    import time
    import sys

    def process_worker_main(args):
        # Need to pause, or the tasks go too quickly, and some processes
        # in the pool don't get any work, and then don't record data.
        ret = work(*args)
        time.sleep(0.1)
        return os.getpid(), ret

    if __name__ == "__main__":      # pragma: no branch
        # This if is on a single line so we can get 100% coverage
        # even if we have no arguments.
        if len(sys.argv) > 1: multiprocessing.set_start_method(sys.argv[1])
        pool = multiprocessing.Pool({NPROCS})
        inputs = [(x,) for x in range({UPTO})]
        outputs = pool.imap_unordered(process_worker_main, inputs)
        pids = set()
        total = 0
        for pid, sq in outputs:
            pids.add(pid)
            total += sq
        print(f"{{len(pids)}} pids, {{total = }}")
        pool.close()
        pool.join()
    """


@pytest.fixture(params=["fork", "spawn"], name="start_method")
def start_method_fixture(request: pytest.FixtureRequest) -> str:
    """Parameterized fixture to choose the start_method for multiprocessing."""
    start_method: str = request.param
    if start_method not in multiprocessing.get_all_start_methods():
        # Windows doesn't support "fork".
        pytest.skip(f"start_method={start_method} not supported here")
    return start_method


# Sometimes a test fails due to inherent randomness. Try more times.
# @pytest.mark.flaky(max_runs=30)
class MultiprocessingTest(CoverageTest):
    """Test support of the multiprocessing module."""

    def try_multiprocessing_code(
        self,
        code: str,
        expected_out: str | None,
        the_module: ModuleType,
        nprocs: int,
        start_method: str,
        concurrency: str = "multiprocessing",
        args: str = "",
    ) -> None:
        """Run code using multiprocessing, it should produce `expected_out`."""
        self.make_file("multi.py", code)
        self.make_file(
            ".coveragerc",
            f"""\
            [run]
            concurrency = {concurrency}
            source = .
            """,
        )

        # Dev mode turns on deprecation warnings that some concurrency
        # libraries issue. We don't need to see those.
        self.del_environ("PYTHONDEVMODE")
        cmd = f"coverage run {args} multi.py {start_method}"
        _, out = self.run_command_status(cmd)
        expected_cant_trace = cant_trace_msg(concurrency, the_module)

        if expected_cant_trace is not None:
            assert expected_cant_trace in out
            pytest.skip(f"Can't test: {expected_cant_trace}")
        else:
            assert out.rstrip() == expected_out
            assert len(glob.glob(".coverage.*")) == nprocs + 1

            out = self.run_command("coverage combine")
            out_lines = out.splitlines()
            assert len(out_lines) == nprocs + 1
            assert all(
                re.fullmatch(
                    r"(Combined data file|Skipping duplicate data) \.coverage\..*\.\d+\.X\w{6}x",
                    line,
                )
                for line in out_lines
            )
            assert len(glob.glob(".coverage.*")) == 0
            out = self.run_command("coverage report -m")

            last_line = self.squeezed_lines(out)[-1]
            assert re.search(r"TOTAL \d+ 0 100%", last_line)

    def test_multiprocessing_simple(self, start_method: str) -> None:
        nprocs = 3
        upto = 30
        code = (SQUARE_OR_CUBE_WORK + MULTI_CODE).format(NPROCS=nprocs, UPTO=upto)
        total = sum(x * x if x % 2 else x * x * x for x in range(upto))
        expected_out = f"{nprocs} pids, {total = }"
        self.try_multiprocessing_code(
            code,
            expected_out,
            threading,
            nprocs,
            start_method=start_method,
        )

    def test_multiprocessing_append(self, start_method: str) -> None:
        nprocs = 3
        upto = 30
        code = (SQUARE_OR_CUBE_WORK + MULTI_CODE).format(NPROCS=nprocs, UPTO=upto)
        total = sum(x * x if x % 2 else x * x * x for x in range(upto))
        expected_out = f"{nprocs} pids, total = {total}"
        self.try_multiprocessing_code(
            code,
            expected_out,
            threading,
            nprocs,
            args="--append",
            start_method=start_method,
        )

    def test_multiprocessing_and_gevent(self, start_method: str) -> None:
        nprocs = 3
        upto = 30
        code = (SUM_RANGE_WORK + EVENTLET + SUM_RANGE_Q + MULTI_CODE).format(
            NPROCS=nprocs, UPTO=upto
        )
        total = sum(sum(range((x + 1) * 100)) for x in range(upto))
        expected_out = f"{nprocs} pids, total = {total}"
        self.try_multiprocessing_code(
            code,
            expected_out,
            eventlet,
            nprocs,
            concurrency="multiprocessing,eventlet",
            start_method=start_method,
        )

    @pytest.mark.skipif(
        not testenv.CAN_MEASURE_BRANCHES, reason="Can't measure branches with this core"
    )
    def test_multiprocessing_with_branching(self, start_method: str) -> None:
        nprocs = 3
        upto = 30
        code = (SQUARE_OR_CUBE_WORK + MULTI_CODE).format(NPROCS=nprocs, UPTO=upto)
        total = sum(x * x if x % 2 else x * x * x for x in range(upto))
        expected_out = f"{nprocs} pids, total = {total}"
        self.make_file("multi.py", code)
        self.make_file(
            "multi.rc",
            """\
            [run]
            concurrency = multiprocessing
            branch = True
            omit = */site-packages/*
            """,
        )

        out = self.run_command(f"coverage run --rcfile=multi.rc multi.py {start_method}")
        assert out.rstrip() == expected_out

        out = self.run_command("coverage combine -q")  # sneak in a test of -q
        assert out == ""
        out = self.run_command("coverage report -m")

        last_line = self.squeezed_lines(out)[-1]
        assert re.search(r"TOTAL \d+ 0 \d+ 0 100%", last_line)

    def test_multiprocessing_bootstrap_error_handling(self) -> None:
        # An exception during bootstrapping will be reported.
        self.make_file(
            "multi.py",
            """\
            import multiprocessing
            if __name__ == "__main__":
                with multiprocessing.Manager():
                    pass
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            concurrency = multiprocessing
            _crash = _bootstrap
            """,
        )
        out = self.run_command("coverage run multi.py", status=1)
        assert "Exception during multiprocessing bootstrap init" in out
        assert "RuntimeError: Crashing because called by _bootstrap" in out

    def test_bug_890(self) -> None:
        # chdir in multiprocessing shouldn't keep us from finding the
        # .coveragerc file.
        self.make_file(
            "multi.py",
            """\
            import multiprocessing, os, os.path
            if __name__ == "__main__":
                if not os.path.exists("./tmp"): os.mkdir("./tmp")
                os.chdir("./tmp")
                with multiprocessing.Manager():
                    pass
                print("ok")
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            concurrency = multiprocessing
            """,
        )
        out = self.run_command("coverage run multi.py")
        assert out.splitlines()[-1] == "ok"


@pytest.mark.skipif(not testenv.SETTRACE_CORE, reason="gettrace is not supported with this core.")
def test_coverage_stop_in_threads() -> None:
    has_started_coverage = []
    has_stopped_coverage = []

    def run_thread() -> None:  # pragma: nested
        """Check that coverage is stopping properly in threads."""
        deadline = time.time() + 5
        ident = threading.current_thread().ident
        if sys.gettrace() is not None:
            has_started_coverage.append(ident)
        while sys.gettrace() is not None:
            # Wait for coverage to stop
            time.sleep(0.01)
            if time.time() > deadline:
                return
        has_stopped_coverage.append(ident)

    cov = coverage.Coverage()
    with cov.collect():
        t = threading.Thread(target=run_thread)
        t.start()

        time.sleep(0.1)
    t.join()

    assert has_started_coverage == [t.ident]
    assert has_stopped_coverage == [t.ident]


def test_thread_safe_save_data(tmp_path: pathlib.Path) -> None:
    # Non-regression test for: https://github.com/coveragepy/coveragepy/issues/581

    # Create some Python modules and put them in the path
    modules_dir = tmp_path / "test_modules"
    modules_dir.mkdir()
    module_names = [f"m{i:03d}" for i in range(1000)]
    for module_name in module_names:
        (modules_dir / (module_name + ".py")).write_text("def f(): pass\n", encoding="utf-8")

    # Shared variables for threads
    should_run = [True]
    imported = []

    old_dir = os.getcwd()
    os.chdir(modules_dir)
    try:
        # Make sure that all dummy modules can be imported.
        for module_name in module_names:
            import_local_file(module_name)

        def random_load() -> None:  # pragma: nested
            """Import modules randomly to stress coverage."""
            while should_run[0]:
                module_name = random.choice(module_names)
                mod = import_local_file(module_name)
                mod.f()
                imported.append(mod)

        # Spawn some threads with coverage enabled and attempt to read the
        # results right after stopping coverage collection with the threads
        #  still running.
        duration = 0.01
        for _ in range(3):
            cov = coverage.Coverage()
            with cov.collect():
                threads = [threading.Thread(target=random_load) for _ in range(10)]
                should_run[0] = True
                for t in threads:
                    t.start()

                time.sleep(duration)

            # The following call used to crash with running background threads.
            cov.get_data()

            # Stop the threads
            should_run[0] = False
            for t in threads:
                t.join()

            if (not imported) and duration < 10:  # pragma: only failure
                duration *= 2

    finally:
        os.chdir(old_dir)
        should_run[0] = False


@pytest.mark.skipif(env.WINDOWS, reason="SIGTERM doesn't work the same on Windows")
@pytest.mark.flaky(max_runs=3)  # Sometimes a test fails due to inherent randomness. Try more times.
class SigtermTest(CoverageTest):
    """Tests of our handling of SIGTERM."""

    @pytest.mark.parametrize("sigterm", [False, True])
    def test_sigterm_multiprocessing_saves_data(self, sigterm: bool) -> None:
        # A terminated process should save its coverage data.
        self.make_file(
            "clobbered.py",
            """\
            import multiprocessing
            import time

            def subproc(x):
                if x.value == 3:
                    print("THREE", flush=True)  # line 6, missed
                else:
                    print("NOT THREE", flush=True)
                x.value = 0
                time.sleep(60)

            if __name__ == "__main__":
                print("START", flush=True)
                x = multiprocessing.Value("L", 1)
                proc = multiprocessing.Process(target=subproc, args=(x,))
                proc.start()
                while x.value != 0:
                    time.sleep(.05)
                proc.terminate()
                print("END", flush=True)
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            parallel = True
            concurrency = multiprocessing
            """
            + ("sigterm = true" if sigterm else ""),
        )
        out = self.run_command("coverage run clobbered.py")
        # Under Linux, things go wrong. Does that matter?
        if env.LINUX and "assert self._collectors" in out:
            lines = out.splitlines(True)
            out = "".join(lines[:3])
        assert out == "START\nNOT THREE\nEND\n"
        self.run_command("coverage combine")
        out = self.run_command("coverage report -m")
        if sigterm:
            expected = "clobbered.py 17 1 94% 6"
        else:
            expected = "clobbered.py 17 5 71% 5-10"
        assert self.squeezed_lines(out)[2] == expected

    def test_sigterm_threading_saves_data(self) -> None:
        # A terminated process should save its coverage data.
        self.make_file(
            "handler.py",
            """\
            import os, signal

            print("START", flush=True)
            print("SIGTERM", flush=True)
            os.kill(os.getpid(), signal.SIGTERM)
            print("NOT HERE", flush=True)
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            # The default concurrency option.
            concurrency = thread
            sigterm = true
            """,
        )
        status, out = self.run_command_status("coverage run handler.py")
        assert status != 0
        out_lines = out.splitlines()
        assert len(out_lines) in [2, 3]
        assert out_lines[:2] == ["START", "SIGTERM"]
        if len(out_lines) == 3:
            assert out_lines[2] == "Terminated"
        out = self.run_command("coverage report -m")
        expected = "handler.py 5 1 80% 6"
        assert self.squeezed_lines(out)[2] == expected

    def test_sigterm_still_runs(self) -> None:
        # A terminated process still runs its own SIGTERM handler.
        self.make_file(
            "handler.py",
            """\
            import multiprocessing
            import signal
            import time

            def subproc(x):
                print("START", flush=True)
                def on_sigterm(signum, frame):
                    print("SIGTERM", flush=True)

                signal.signal(signal.SIGTERM, on_sigterm)
                x.value = 0
                try:
                    time.sleep(.1)
                except OSError: # This happens on PyPy3.11 on Mac
                    pass
                print("END", flush=True)

            if __name__ == "__main__":
                x = multiprocessing.Value("L", 1)
                proc = multiprocessing.Process(target=subproc, args=(x,))
                proc.start()
                while x.value != 0:
                    time.sleep(.02)
                proc.terminate()
            """,
        )
        self.make_file(
            ".coveragerc",
            """\
            [run]
            parallel = True
            concurrency = multiprocessing
            sigterm = True
            """,
        )
        out = self.run_command("coverage run handler.py")
        assert out == "START\nSIGTERM\nEND\n"
