# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tracing, context switching, persistence, and process workloads."""

from __future__ import annotations

import importlib
import pathlib
import sys
from typing import Any

import pytest

from coverage import Coverage, CoverageData
from coverage.data import combine_parallel_data

from tests import testenv
from tests.benchmarks.validation import assert_core, validate_multiprocessing
from tests.benchmarks.datasets import CombineDataset, add_values, make_combine_dataset, read_values
from tests.benchmarks.helpers import (
    Benchmark,
    LARGE_UNUSED_FILE_COUNT,
    MODULE_COUNT,
    MULTIPROC_WORKERS,
    clear_package_modules,
    import_workload,
    make_coverage,
    measure_workload,
    run_coverage_subprocess,
    subprocess_env,
)
from tests.benchmarks.workloads import (
    make_context_workspace,
    make_execution_workspace,
    run_contexts,
    validate_context_data,
)

pytestmark = [pytest.mark.benchmark]

CORES = [
    "pytrace",
    pytest.param("ctrace", marks=pytest.mark.skipif(not testenv.HAVE_CTRACE, reason="no CTracer")),
    pytest.param(
        "sysmon", marks=pytest.mark.skipif(not testenv.HAVE_SYSMON, reason="no sys.monitoring")
    ),
]


@pytest.mark.benchmark(group="measure")
@pytest.mark.parametrize("branch", [False, True], ids=["lines", "arcs"])
@pytest.mark.parametrize("core", CORES)
@pytest.mark.parametrize("scenario", ["loops", "calls", "imports", "resumable"])
def test_collect(
    bench: Benchmark,
    bench_ws: pathlib.Path,
    tmp_path: pathlib.Path,
    core: str,
    branch: bool,
    scenario: str,
) -> None:
    if core == "sysmon" and branch and not testenv.CAN_MEASURE_BRANCHES:
        pytest.skip("sys.monitoring can't measure branches in this version")
    workspace = bench_ws if scenario == "loops" else make_execution_workspace(tmp_path, scenario)
    bench.extra_info.update(core=core, modules=MODULE_COUNT, scenario=scenario)

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        # Fresh code objects matter for sysmon, whose events are disabled once seen.
        workload = import_workload(workspace)
        if scenario == "imports":
            # Warm bytecode files equally, but time imports and first execution.
            clear_package_modules()
            sys.path.insert(0, str(workspace))
        cov = make_coverage(workspace, core=core, branch=branch)
        cov.set_option("run:omit", ["*/excluded.py"])
        return (cov, workload), {}

    def measure(cov: Coverage, workload: Any) -> None:
        if scenario == "imports":
            cov.start()
            try:
                importlib.import_module("benchpkg.workload").main(rounds=1)
            finally:
                cov.stop()
        elif scenario == "resumable":
            cov.start()
            try:
                workload.run_resumable()
            finally:
                cov.stop()
        else:
            measure_workload(cov, workload)

    def validate(cov: Coverage, workload: Any) -> None:
        del workload
        assert_core(cov, core)
        data = cov.get_data()
        assert data.has_arcs() == branch
        modules = [f for f in data.measured_files() if pathlib.Path(f).name.startswith("mod_")]
        assert len(modules) == MODULE_COUNT
        assert all(len(data.lines(f) or []) > 1 for f in modules)
        assert not any(f.endswith("excluded.py") for f in data.measured_files())
        if scenario == "resumable":
            for filename in modules:
                lines = pathlib.Path(filename).read_text(encoding="utf-8").splitlines()
                first_async_line = lines.index("async def compute_async():") + 2
                assert first_async_line in (data.lines(filename) or [])
        data.close()
        if scenario == "imports":
            sys.path.remove(str(workspace))

    try:
        bench.pedantic(measure, setup=setup, teardown=validate)
    finally:
        clear_package_modules()


@pytest.mark.benchmark(group="persist")
@pytest.mark.parametrize("branch", [False, True], ids=["lines", "arcs"])
@pytest.mark.parametrize("mode", ["create", "update"])
@pytest.mark.parametrize("density", ["dense", "sparse"])
def test_add_data(
    bench: Benchmark, tmp_path: pathlib.Path, branch: bool, mode: str, density: str
) -> None:
    names = [str(tmp_path / f"mod_{idx:03d}.py") for idx in range(80)]
    lines = set(range(1, 201)) if density == "dense" else {1, 201, 2001}
    points: set[Any] = {(line, line + 1) for line in lines} if branch else set(lines)
    initial: set[Any] = {(3000, 3001)} if branch else {3000}
    values = {name: points for name in names}
    expected = {name: points | (initial if mode == "update" else set()) for name in names}
    bench.extra_info.update(files=len(names), density=density, mode=mode)

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        data = CoverageData(basename=str(tmp_path / ".coverage"))
        data.erase()
        if mode == "update":
            add_values(data, {name: initial for name in names}, branch)
        return (data,), {}

    def add(data: CoverageData) -> None:
        add_values(data, values, branch)

    def validate(data: CoverageData) -> None:
        assert read_values(data, branch) == expected
        data.close()

    bench.pedantic(add, setup=setup, teardown=validate)


@pytest.mark.benchmark(group="measure")
def test_collect_with_large_unused_source_tree(bench: Benchmark, unused_ws: pathlib.Path) -> None:
    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        (unused_ws / ".coverage.unused").unlink(missing_ok=True)
        workload = import_workload(unused_ws)
        cov = make_coverage(unused_ws, core="pytrace", branch=True, data_suffix="unused")
        return (cov, workload), {}

    def collect_and_save(cov: Coverage, workload: Any) -> None:
        measure_workload(cov, workload, rounds=4, loops=10)
        cov.save()

    def validate(cov: Coverage, workload: Any) -> None:
        del workload
        data = cov.get_data()
        unused = [f for f in data.measured_files() if pathlib.Path(f).name.startswith("unused_")]
        assert len(unused) == LARGE_UNUSED_FILE_COUNT
        assert all(data.lines(f) == [] for f in unused)
        data.close()

    bench.extra_info["unused_files"] = LARGE_UNUSED_FILE_COUNT
    bench.pedantic(collect_and_save, setup=setup, teardown=validate)


@pytest.mark.benchmark(group="contexts")
@pytest.mark.parametrize("core", CORES[:2])
@pytest.mark.parametrize("explicit", [False, True], ids=["automatic", "api"])
@pytest.mark.parametrize("count", [10, 500])
def test_collect_contexts(
    bench: Benchmark, tmp_path: pathlib.Path, core: str, explicit: bool, count: int
) -> None:
    workspace = make_context_workspace(tmp_path, count)
    bench.extra_info.update(
        core=core, contexts=count, context_method="api" if explicit else "test_function"
    )

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        cov = make_coverage(
            workspace, core=core, dynamic_context=None if explicit else "test_function"
        )
        cov.erase()
        return (cov, import_workload(workspace), explicit), {}

    def validate(cov: Coverage, workload: Any, api: bool) -> None:
        del workload, api
        assert_core(cov, core)
        validate_context_data(cov, count)
        cov.get_data().close()

    bench.pedantic(run_contexts, setup=setup, teardown=validate)


@pytest.fixture(scope="session", name="combine_dataset")
def prepared_combine_dataset(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> CombineDataset:
    """Prepare each immutable input only once per session."""
    profile, branch = request.param
    return make_combine_dataset(tmp_path_factory.mktemp("combine"), profile, branch)


@pytest.mark.benchmark(group="combine")
@pytest.mark.parametrize(
    "combine_dataset",
    [(p, b) for p in ["dense", "contexts_sparse", "remap"] for b in [False, True]],
    ids=[
        f"{p}-{kind}" for p in ["dense", "contexts_sparse", "remap"] for kind in ["lines", "arcs"]
    ],
    indirect=True,
)
def test_combine_many_files(
    bench: Benchmark, combine_dataset: CombineDataset, tmp_path: pathlib.Path
) -> None:
    dataset = combine_dataset
    bench.extra_info.update(shards=dataset.shard_count, contexts=len(dataset.expected))

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        data = CoverageData(basename=str(tmp_path / ".coverage"))
        data.erase()
        return (data,), {}

    def combine(target: CoverageData) -> CoverageData:
        combine_parallel_data(
            target,
            data_paths=[str(pathlib.Path(dataset.basename).parent)],
            aliases=dataset.aliases,
            keep=True,
            strict=True,
        )
        return target

    result = bench.pedantic(combine, setup=setup, teardown=lambda data: data.close())
    dataset.validate(result)
    result.close()


@pytest.mark.slow
@pytest.mark.benchmark(group="multiprocessing")
@pytest.mark.skipif(not testenv.HAVE_CTRACE, reason="multiprocessing workload requires CTracer")
@pytest.mark.parametrize("combine", [False, True], ids=["run", "run_and_combine"])
def test_multiprocessing(bench: Benchmark, mproc_ws: pathlib.Path, combine: bool) -> None:
    env = subprocess_env()
    bench.extra_info.update(core="ctrace", workers=MULTIPROC_WORKERS, tasks=32)

    def setup() -> None:
        for path in mproc_ws.glob(".coverage.mproc*"):
            path.unlink(missing_ok=True)

    def run() -> None:
        run_coverage_subprocess(mproc_ws, ["run", "--rcfile=.coveragerc", "run_multiproc.py"], env)
        if combine:
            run_coverage_subprocess(mproc_ws, ["combine", "--rcfile=.coveragerc"], env)

    bench.pedantic(run, setup=setup, teardown=lambda: validate_multiprocessing(mproc_ws, combine))
