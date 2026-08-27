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
from collections.abc import Iterator

import pytest

from coverage import Coverage, env

from tests import testenv
from tests.benchmarks.helpers import (
    LARGE_UNUSED_FILE_COUNT,
    PACKAGE_NAME,
    REPORT_WORKLOAD_ROUNDS,
    collect_context_data,
    collect_data,
    make_coverage,
    make_multiprocessing_project,
    make_parallel_data_files,
    make_workspace,
)


def pytest_ignore_collect(collection_path: pathlib.Path, config: pytest.Config) -> bool | None:
    """Skip this directory entirely unless --benchmarks was given."""
    del collection_path
    return True if not config.getoption("--benchmarks") else None


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


@pytest.fixture(scope="session", name="combine_ws")
def combine_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A workspace holding many parallel data files, ready to be combined."""
    workspace = tmp_path_factory.mktemp("combine_ws")
    make_parallel_data_files(workspace, branch=True, subdir="combine_arcs")
    make_parallel_data_files(workspace, branch=False, subdir="combine_lines")
    return workspace


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
    workspace = make_workspace(tmp_path_factory.mktemp("measured_ws"))
    measured = collect_data(
        workspace,
        core="pytrace",
        branch=True,
        rounds=REPORT_WORKLOAD_ROUNDS,
    )
    measured.save()
    return workspace


@pytest.fixture(scope="session", name="measured_large_ws")
def measured_large_workspace(large_ws: pathlib.Path) -> pathlib.Path:
    """The large-module project, already measured."""
    measured = collect_data(
        large_ws,
        core="pytrace",
        branch=True,
        rounds=REPORT_WORKLOAD_ROUNDS,
        loops=40,
    )
    measured.save()
    return large_ws


@pytest.fixture(scope="session", name="measured_contexts_ws")
def measured_contexts_workspace(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    """A synthetic project measured with dynamic contexts turned on."""
    workspace = make_workspace(tmp_path_factory.mktemp("contexts_ws"))
    measured = collect_context_data(workspace)
    measured.save()
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
    yield
