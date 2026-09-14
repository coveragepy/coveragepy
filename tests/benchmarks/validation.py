# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Untimed checks that benchmark inputs produce their intended work."""

from __future__ import annotations

import pathlib
from coverage import Coverage, CoverageData
from tests import testenv
from tests.benchmarks.helpers import MULTIPROC_WORKERS


def assert_core(cov: Coverage, core: str) -> None:
    """Fail loudly if coverage.py quietly fell back to a different core.

    Mislabeled numbers are worse than missing ones, and the "no-sysmon" warning
    that would otherwise tell us is silenced by tests/conftest.py.

    """
    collector = cov._collector
    assert collector is not None
    assert collector.tracer_name() == testenv.TRACER_CLASSES[core], (
        f"Asked for core={core!r}, got {collector.tracer_name()}"
    )


def validate_multiprocessing(
    workspace: pathlib.Path, combined: bool, workers: int = MULTIPROC_WORKERS
) -> None:
    """A successful command alone doesn't prove that workers saved their data."""
    paths = (
        [workspace / ".coverage.mproc"] if combined else list(workspace.glob(".coverage.mproc.*"))
    )
    if not combined:
        assert len(paths) == workers + 1, paths
    populated = 0
    for path in paths:
        data = CoverageData(basename=str(path))
        data.read()
        modules = [f for f in data.measured_files() if pathlib.Path(f).name.startswith("mod_")]
        if any(len(data.lines(f) or []) > 1 for f in modules):
            populated += 1
            assert len(modules) == 24
            assert all(len(data.lines(f) or []) > 1 for f in modules)
        data.close()
    assert populated == (1 if combined else workers), populated


def page_stamps(directory: pathlib.Path) -> dict[str, int]:
    """Only source pages, excluding indexes that are always rewritten."""
    return {p.name: p.stat().st_mtime_ns for p in directory.glob("*_py.html")}


def assert_one_changed(before: dict[str, int], after: dict[str, int], stem: str) -> None:
    """Catch both missed invalidation and unintended full regeneration."""
    assert before.keys() == after.keys()
    changed = [name for name in before if before[name] != after[name]]
    assert len(changed) == 1 and changed[0].endswith(f"_{stem}_py.html"), changed
