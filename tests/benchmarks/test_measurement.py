# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Benchmarks for measurement-time costs."""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

from coverage import Coverage
from coverage.data import CoverageData, combine_parallel_data

from tests import testenv
from tests.benchmarks.conftest import assert_core
from tests.benchmarks.helpers import (
    Benchmark,
    CALLS_PER_MODULE,
    WORKLOAD_ROUNDS,
    clear_package_modules,
    collect_data,
    import_workload,
    make_coverage,
    measure_workload,
    run_coverage_subprocess,
    subprocess_env,
)

pytestmark = [pytest.mark.benchmark]

CORES = [
    pytest.param("pytrace"),
    pytest.param("ctrace", marks=pytest.mark.skipif(not testenv.HAVE_CTRACE, reason="no CTracer")),
    pytest.param(
        "sysmon",
        marks=pytest.mark.skipif(not testenv.HAVE_SYSMON, reason="no sys.monitoring"),
    ),
]


@pytest.mark.benchmark(group="measure")
@pytest.mark.parametrize("branch", [False, True], ids=["lines", "arcs"])
@pytest.mark.parametrize("core", CORES)
def test_collect(
    benchmark: Benchmark,
    bench_ws: pathlib.Path,
    core: str,
    branch: bool,
) -> None:
    if core == "sysmon" and branch and not testenv.CAN_MEASURE_BRANCHES:
        pytest.skip("sys.monitoring can't measure branches in this version")

    used: list[Coverage] = []

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        # Importing 80 modules is a big chunk of the work and can only happen
        # once per interpreter, so keep it out of the timed region.
        workload = import_workload(bench_ws)
        cov = make_coverage(
            bench_ws,
            core=core,
            branch=branch,
            data_suffix=f"{core}-{'branch' if branch else 'line'}",
        )
        used.append(cov)
        return (cov, workload), {"rounds": WORKLOAD_ROUNDS, "loops": CALLS_PER_MODULE}

    benchmark.pedantic(measure_workload, setup=setup, rounds=5, warmup_rounds=1, iterations=1)

    assert_core(used[-1], core)
    clear_package_modules()


@pytest.mark.benchmark(group="persist")
@pytest.mark.parametrize("branch", [False, True], ids=["lines", "arcs"])
def test_add_data(
    benchmark: Benchmark,
    bench_ws: pathlib.Path,
    tmp_path: pathlib.Path,
    branch: bool,
) -> None:
    cov = collect_data(bench_ws, core="pytrace", branch=branch)
    collector = cov._collector
    assert collector is not None
    measured: Any = {fname: set(values) for fname, values in collector.data.items()}

    db_path = tmp_path / f".coverage.{'arcs' if branch else 'lines'}"

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        # Writing into an existing database is an update, not a create: a whole
        # different code path, and not the one we mean to measure.
        db_path.unlink(missing_ok=True)
        return (CoverageData(basename=str(db_path)),), {}

    def add(data: CoverageData) -> None:
        if branch:
            data.add_arcs(measured)
        else:
            data.add_lines(measured)

    benchmark.pedantic(add, setup=setup, rounds=10, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="measure")
def test_collect_with_large_unused_source_tree(
    benchmark: Benchmark,
    unused_ws: pathlib.Path,
) -> None:
    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        (unused_ws / ".coverage.unused").unlink(missing_ok=True)
        workload = import_workload(unused_ws)
        cov = make_coverage(unused_ws, core="pytrace", branch=True, data_suffix="unused")
        return (cov, workload), {}

    def collect_and_save(cov: Any, workload: Any) -> None:
        measure_workload(cov, workload, rounds=4, loops=10)
        cov.save()

    benchmark.pedantic(collect_and_save, setup=setup, rounds=3, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="measure")
def test_collect_test_function_contexts(
    benchmark: Benchmark,
    bench_ws: pathlib.Path,
) -> None:
    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        workload = import_workload(bench_ws)
        cov = make_coverage(
            bench_ws,
            core="pytrace",
            branch=True,
            data_suffix="contexts",
            dynamic_context="test_function",
        )
        return (cov, workload), {}

    def run_contexts(cov: Any, workload: Any) -> None:
        cov.start()
        try:
            workload.run_contexts()
        finally:
            cov.stop()

    benchmark.pedantic(run_contexts, setup=setup, rounds=5, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="combine")
@pytest.mark.parametrize("branch", [False, True], ids=["lines", "arcs"])
def test_combine_many_files(
    benchmark: Benchmark,
    combine_ws: pathlib.Path,
    branch: bool,
) -> None:
    subdir = "combine_arcs" if branch else "combine_lines"
    base_name = str(combine_ws / subdir / ".coverage")

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        # keep=True leaves the parts in place, but the target accumulates, so
        # without this every round after the first combines into a full database.
        pathlib.Path(base_name).unlink(missing_ok=True)
        return (CoverageData(basename=base_name),), {}

    def combine(target: CoverageData) -> None:
        combine_parallel_data(target, data_paths=[str(combine_ws / subdir)], keep=True)

    benchmark.pedantic(combine, setup=setup, rounds=5, iterations=1)


@pytest.mark.slow
@pytest.mark.benchmark(group="multiprocessing")
@pytest.mark.parametrize("combine", [False, True], ids=["run", "run_and_combine"])
def test_multiprocessing(
    benchmark: Benchmark,
    mproc_ws: pathlib.Path,
    combine: bool,
) -> None:
    # Built once: scrubbing a large environment is harness work, not the
    # multiprocessing cost we're measuring.
    env = subprocess_env()

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        for path in mproc_ws.glob(".coverage.mproc*"):
            path.unlink(missing_ok=True)
        return (), {}

    def run() -> None:
        run_coverage_subprocess(mproc_ws, ["run", "--rcfile=.coveragerc", "run_multiproc.py"], env)
        if combine:
            run_coverage_subprocess(mproc_ws, ["combine", "--rcfile=.coveragerc"], env)

    benchmark.pedantic(run, setup=setup, rounds=2, iterations=1)
