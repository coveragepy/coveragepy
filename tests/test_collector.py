# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of coverage/collector.py and other collectors."""

from __future__ import annotations

import os.path
import queue
import threading
import time

import pytest

import coverage
from coverage.misc import import_local_file
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

    @pytest.mark.parametrize("branch", [False, True])
    def test_in_frame_thread_across_flush(self, branch: bool) -> None:
        # A worker thread that stays inside an already-entered frame across a
        # flush (producing no new call / PY_START event) must not lose lines
        # executed after the flush.
        self.make_file(
            "in_frame.py",
            """\
            def run(lock_ready, lock_go, lock_done, lock_exit):
                x = 1
                lock_ready.release()
                lock_go.acquire()
                y = x + 1
                lock_done.release()
                lock_exit.acquire()
                return y
            """,
        )

        cmd_q: queue.SimpleQueue[str] = queue.SimpleQueue()
        ack_q: queue.SimpleQueue[set[int]] = queue.SimpleQueue()
        cov = coverage.Coverage(branch=branch, include=["in_frame.py"])
        target_file = os.path.abspath("in_frame.py")

        # Flush from a thread started before collection, so it has no tracer.
        # Flushing from a traced thread would set that tracer's activity flag
        # and hide the bug: the flushes need to see every activity flag False.
        def _flusher() -> None:  # pragma: nested
            while True:
                cmd = cmd_q.get()
                if cmd == "quit":
                    return
                data = cov.get_data()
                ack_q.put(set(data.lines(target_file) or ()))

        flusher_thread = threading.Thread(target=_flusher)
        flusher_thread.start()
        try:
            with cov.collect():
                mod = import_local_file("in_frame")
                lock_ready = threading.Lock()
                lock_go = threading.Lock()
                lock_done = threading.Lock()
                lock_exit = threading.Lock()
                lock_ready.acquire()
                lock_go.acquire()
                lock_done.acquire()
                lock_exit.acquire()

                worker = threading.Thread(
                    target=mod.run,
                    args=(lock_ready, lock_go, lock_done, lock_exit),
                )
                worker.start()
                lock_ready.acquire()

                cmd_q.put("flush")
                ack_q.get()
                cmd_q.put("flush")
                ack_q.get()

                lock_go.release()
                lock_done.acquire()

                cmd_q.put("flush")
                mid_run_lines = ack_q.get()

                lock_exit.release()
                worker.join()
        finally:
            cmd_q.put("quit")
            flusher_thread.join()

        # On free-threaded Python, lock_done.release() on line 6 can wake the
        # main thread before the worker advances to line 7; lines 5 and 6 are
        # guaranteed to have executed after the mid-frame flushes.
        assert {1, 2, 3, 4, 5, 6} <= mid_run_lines
        assert set(cov.get_data().lines(target_file) or ()) == {1, 2, 3, 4, 5, 6, 7, 8}

    @pytest.mark.parametrize("branch", [False, True])
    def test_concurrent_threads_during_flush(self, branch: bool) -> None:
        # Lines recorded by another thread while get_data() flushes must all be
        # preserved (#2384).
        num_funcs = 600
        lines = [
            f"def f{i}(x):\n    if x:\n        return {i}\n    return -1\n"
            for i in range(num_funcs)
        ]
        self.make_file("many_funcs.py", "".join(lines))

        cov = coverage.Coverage(data_file=None, branch=branch, include=["many_funcs.py"])
        with cov.collect():
            mod = import_local_file("many_funcs")
            done = threading.Event()

            def _worker() -> None:
                for i in range(num_funcs):
                    getattr(mod, f"f{i}")(True)
                    if i % 30 == 0:
                        time.sleep(0.0005)
                done.set()

            worker = threading.Thread(target=_worker)
            worker.start()
            while not done.is_set():
                cov.get_data()
            worker.join()

        measured = set(cov.get_data().lines(os.path.abspath("many_funcs.py")) or ())
        expected = {4 * i + n for i in range(num_funcs) for n in (1, 2, 3)}
        assert measured == expected

    @pytest.mark.parametrize("branch", [False, True])
    def test_new_files_during_flush(self, branch: bool) -> None:
        # Files first executed by another thread while get_data() flushes must
        # keep all their lines.
        num_mods = 100
        for i in range(num_mods):
            self.make_file(f"newmod{i}.py", "def f():\n    a = 1\n    b = 2\n    return a + b\n")

        # Import before collecting so that the first traced execution of each
        # file is a plain function call.  Importing in the worker does file
        # I/O, and the GIL contention with the flushing loop makes each import
        # take most of a second.
        mods = [import_local_file(f"newmod{i}") for i in range(num_mods)]

        cov = coverage.Coverage(data_file=None, branch=branch, include=["newmod*.py"])
        # The flushing loop can call get_data() before the worker has run.
        cov.set_option("run:disable_warnings", ["no-data-collected"])
        with cov.collect():
            done = threading.Event()

            def _worker() -> None:
                for mod in mods:
                    mod.f()
                done.set()

            worker = threading.Thread(target=_worker)
            worker.start()
            while not done.is_set():
                cov.get_data()
            worker.join()

        data = cov.get_data()
        incomplete = {
            i: lines
            for i in range(num_mods)
            if (lines := set(data.lines(os.path.abspath(f"newmod{i}.py")) or ())) != {2, 3, 4}
        }
        assert incomplete == {}
