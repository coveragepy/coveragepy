# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of coverage/collector.py and other collectors."""

from __future__ import annotations

import os.path
import queue
import threading
import time
from typing import Any, cast

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
    def test_data_added_during_flush(self, branch: bool) -> None:
        # Data added to live per-file sets (or new file entries) while
        # flush_data() is writing to CoverageData must not be cleared, and must
        # still be flushed on the next get_data() even if no new frame call
        # sets tracer._activity.
        self.make_file(
            "prog.py",
            """\
            def f(x):
                if x:
                    return 1
                return 2
            """,
        )
        self.make_file("other.py", "x = 1\n")

        cov = coverage.Coverage(branch=branch, include=["prog.py", "other.py"])
        with cov.collect():
            mod = import_local_file("prog")
            mod.f(True)

        collector = cov._collector
        assert collector is not None
        prog_fname = next(fname for fname in collector.data if fname.endswith("prog.py"))
        other_fname = os.path.join(os.path.dirname(prog_fname), "other.py")
        live_set = cast(set[Any], collector.data[prog_fname])
        assert live_set

        cov._init_data(suffix=None)
        assert cov._data is not None
        injected = False

        if branch:
            orig_add_arcs = cov._data.add_arcs
            extra_prog: Any = (2 | (4 << 28)) if collector.core.packed_arcs else (2, 4)
            extra_other: Any = (
                (1 | (1 << 28) | (1 << 56)) if collector.core.packed_arcs else (-1, 1)
            )

            def hooked_add_arcs(arc_data: Any) -> None:
                nonlocal injected
                orig_add_arcs(arc_data)
                if not injected:
                    injected = True
                    live_set.add(extra_prog)
                    collector.data[other_fname] = {extra_other}

            cov._data.add_arcs = hooked_add_arcs  # type: ignore[method-assign]
        else:
            orig_add_lines = cov._data.add_lines

            def hooked_add_lines(line_data: Any) -> None:
                nonlocal injected
                orig_add_lines(line_data)
                if not injected:
                    injected = True
                    live_set.add(4)
                    collector.data[other_fname] = {1}

            cov._data.add_lines = hooked_add_lines  # type: ignore[method-assign]

        # First flush writes the initial snapshot while hooked_add_* simulates
        # another thread recording into both an existing live set and a new file.
        cov.get_data()
        assert injected
        assert collector.data[prog_fname] is live_set
        assert len(live_set) == 1
        assert all(not tracer.activity() for tracer in collector.tracers)

        # Second flush must still detect the unflushed items even though all
        # tracer activity flags are False, and drain them cleanly.
        data = cov.get_data()
        assert not live_set
        assert not collector.data[other_fname]
        assert set(data.lines(os.path.abspath("prog.py")) or ()) == {1, 2, 3, 4}
        assert set(data.lines(os.path.abspath("other.py")) or ()) == {1}
        if branch:
            assert (2, 4) in (data.arcs(os.path.abspath("prog.py")) or ())

        # With all sets drained and no tracer activity, another flush is a no-op.
        assert not collector.flush_data()

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

        assert {1, 2, 3, 4, 5, 6, 7} <= mid_run_lines
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
        expected = {4 * i + 2 for i in range(num_funcs)} | {4 * i + 3 for i in range(num_funcs)}
        assert expected <= measured
