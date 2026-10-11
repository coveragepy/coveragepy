# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Fixtures for the coverage.py benchmarks.

The benchmarks are only collected when --benchmarks is given.  Without that
gate they would run three times per interpreter in the regular test suite (once
per core), which costs minutes and produces no measurements at all: with xdist
active, pytest-benchmark disables itself but still *executes* every benchmark.

"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator, Callable
from typing import Any

import pytest

from coverage import Coverage, env

from tests.benchmarks.helpers import (
    LARGE_UNUSED_FILE_COUNT,
    PACKAGE_NAME,
    collect_data,
    clear_package_modules,
    make_coverage,
    make_multiprocessing_project,
    make_workspace,
)

from tests.benchmarks.workloads import (
    collect_contexts,
    make_report_workspace,
    validate_report_data,
    validate_context_data,
)

WORKLOAD_VERSION = 2


class BenchmarkRunner:
    """Apply consistent rounds, smoke semantics, and workload identity."""

    def __init__(self, fixture: Any, request: pytest.FixtureRequest) -> None:
        self.fixture = fixture
        self.smoke = bool(request.config.getoption("--bench-smoke") or fixture.disabled)
        if self.smoke:
            fixture.disabled = True
        self.rounds = request.config.getoption("--bench-rounds") or (
            5 if request.node.get_closest_marker("slow") else 10
        )
        self.extra_info: dict[str, Any] = fixture.extra_info
        self.extra_info.update(workload_version=WORKLOAD_VERSION, smoke=self.smoke)
        # Prevent accidental comparison against the original workload under the same id.
        fixture.name += f"[workload-v{WORKLOAD_VERSION}]"
        fixture.fullname += f"[workload-v{WORKLOAD_VERSION}]"

    def __call__(self, function_to_benchmark: Callable[..., Any], /) -> Any:
        return self.fixture(function_to_benchmark)

    def pedantic(
        self,
        target: Callable[..., Any],
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        setup: Callable[[], Any] | None = None,
        teardown: Callable[..., Any] | None = None,
    ) -> Any:
        """Control samples while keeping preparation and assertions untimed."""
        if self.smoke:
            if setup:
                prepared = setup()
                if prepared is not None:
                    args, kwargs = prepared
            try:
                return self.fixture(lambda: target(*args, **(kwargs or {})))
            finally:
                if teardown:
                    teardown(*args, **(kwargs or {}))
        return self.fixture.pedantic(
            target,
            args=args,
            kwargs=kwargs,
            setup=setup,
            teardown=teardown,
            rounds=self.rounds,
            warmup_rounds=1,
            iterations=1,
        )


@pytest.fixture(name="bench")
def controlled_benchmark(benchmark: Any, request: pytest.FixtureRequest) -> BenchmarkRunner:
    """Wrap the plugin fixture without timing setup or workload assertions."""
    if request.config.getoption("numprocesses", default=0):
        pytest.fail("Benchmarks require -n0; xdist disables timing.")
    rounds = request.config.getoption("--bench-rounds")
    if rounds is not None and rounds < 1:
        pytest.fail("--bench-rounds must be positive")
    return BenchmarkRunner(benchmark, request)


def pytest_ignore_collect(collection_path: pathlib.Path, config: pytest.Config) -> bool | None:
    """Skip this directory entirely unless --benchmarks was given."""
    del collection_path
    return True if not config.getoption("--benchmarks") else None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Drop benchmarks that got collected by being named on the command line.

    pytest doesn't consult pytest_ignore_collect for a path given as an initial
    argument, so `pytest -m benchmark tests/benchmarks/test_thing.py` would slip
    past the hook above and run without --benchmarks.

    """
    if config.getoption("--benchmarks"):
        if not config.getoption("--bench-real"):
            for item in items:
                if item.get_closest_marker("real_project"):
                    item.add_marker(
                        pytest.mark.skip(reason="Use make bench-prepare, then make bench-real")
                    )
        return
    here = pathlib.Path(__file__).parent
    keeping: list[pytest.Item] = []
    dropping: list[pytest.Item] = []
    for item in items:
        (dropping if here in pathlib.Path(item.path).parents else keeping).append(item)
    if dropping:
        config.hook.pytest_deselected(items=dropping)
        items[:] = keeping


@pytest.fixture(scope="session", name="bench_ws")
def bench_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """The standard synthetic project: 80 modules of branchy code."""
    return make_workspace(tmp_path_factory.mktemp("bench_ws"))


@pytest.fixture(scope="session", name="large_ws")
def large_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A synthetic project with one very large module."""
    return make_workspace(tmp_path_factory.mktemp("large_ws"), large_module=True)


@pytest.fixture(scope="session", name="unused_ws")
def unused_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A synthetic project that is mostly files which are never executed."""
    return make_workspace(
        tmp_path_factory.mktemp("unused_ws"),
        unused_file_count=LARGE_UNUSED_FILE_COUNT,
    )


@pytest.fixture(scope="session", name="mproc_ws")
def mproc_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A workspace set up to be measured across multiprocessing workers."""
    workspace = make_workspace(
        tmp_path_factory.mktemp("mproc_ws"),
        module_count=24,
        calls_per_module=36,
    )
    make_multiprocessing_project(workspace)
    return workspace


@pytest.fixture(scope="session", name="measured_ws")
def measured_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A synthetic project that has already been measured, for reporting."""
    workspace = make_report_workspace(tmp_path_factory.mktemp("measured_ws"))
    measured = collect_data(
        workspace,
        core="pytrace",
        branch=True,
        rounds=1,
    )
    measured.save()
    validate_report_data(measured)
    return workspace


@pytest.fixture(scope="session", name="measured_large_ws")
def measured_large_workspace(large_ws: pathlib.Path) -> pathlib.Path:
    """The large-module project, already measured."""
    measured = collect_data(
        large_ws,
        core="pytrace",
        branch=True,
        rounds=1,
        loops=40,
    )
    measured.save()
    return large_ws


@pytest.fixture(scope="session", name="measured_contexts_ws")
def measured_contexts_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A synthetic project measured with dynamic contexts turned on."""
    workspace = tmp_path_factory.mktemp("contexts_ws")
    measured = collect_contexts(workspace)
    validate_context_data(measured, 500)
    return workspace


def _loaded(workspace: pathlib.Path, suffix: str) -> Coverage:
    """Load previously-collected data for reporting."""
    cov = make_coverage(
        workspace,
        core="pytrace",
        branch=True,
        data_suffix=suffix,
        source=[],
    )
    cov.load()
    return cov


@pytest.fixture(name="report_cov")
def report_coverage(measured_ws: pathlib.Path) -> Coverage:
    """A fresh Coverage with the standard project's data loaded.

    Function-scoped on purpose: the reporting benchmarks call set_option(), and
    a shared object would carry those settings into their neighbors.

    """
    return _loaded(measured_ws, "pytrace-branch")


@pytest.fixture(name="large_cov")
def large_coverage(measured_large_ws: pathlib.Path) -> Coverage:
    """A fresh Coverage with the large-module project's data loaded."""
    return _loaded(measured_large_ws, "pytrace-branch")


@pytest.fixture(name="contexts_cov")
def contexts_coverage(measured_contexts_ws: pathlib.Path) -> Coverage:
    """A fresh Coverage with context-annotated data loaded."""
    cov = Coverage(
        data_file=str(measured_contexts_ws / ".coverage.contexts"),
        config_file=False,
        source=[],
        branch=True,
    )
    cov.set_option("html:show_contexts", True)
    cov.load()
    return cov


@pytest.fixture(name="source_files")
def measured_source_files(measured_ws: pathlib.Path) -> list[pathlib.Path]:
    """The synthetic project's source files, for analysis benchmarks."""
    return sorted((measured_ws / PACKAGE_NAME).glob("*.py"))


@pytest.fixture(autouse=True)
def no_test_harness_influence() -> Iterator[None]:
    """Refuse to produce numbers that aren't comparable to anyone else's.

    COVERAGE_TESTING makes the parser do a per-AST-node check, and metacov is
    measuring coverage.py while we measure it measuring something else.

    """
    if env.TESTING:
        pytest.skip("Benchmarks measure the wrong thing under COVERAGE_TESTING")
    if env.METACOV:
        pytest.skip("Benchmarks measure the wrong thing under metacov")
    try:
        yield
    finally:
        clear_package_modules()


@pytest.fixture(scope="session", name="many_ws")
def many_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A larger project for whole-report scaling and peak memory."""
    workspace = make_report_workspace(tmp_path_factory.mktemp("many_ws"), module_count=400)
    measured = collect_data(workspace, rounds=1, loops=1)
    measured.save()
    validate_report_data(measured)
    return workspace
