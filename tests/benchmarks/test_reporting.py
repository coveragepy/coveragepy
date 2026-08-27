# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Benchmarks for analysis and reporting costs."""

from __future__ import annotations

import io
import itertools
import pathlib
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import pytest

from coverage import Coverage

from tests.benchmarks.helpers import fresh_html_dir

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

pytestmark = [pytest.mark.benchmark]


def _html_setup(workspace: pathlib.Path) -> Any:
    """A pedantic setup that hands the timed function an empty output directory.

    Reporting into a populated htmlcov takes the incremental path, so without
    this every round after the first would measure something else entirely.

    """

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        return (fresh_html_dir(workspace),), {}

    return setup


@pytest.mark.benchmark(group="analysis", warmup=True)
def test_analysis2_all_files(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    source_files: list[pathlib.Path],
) -> None:
    def analyze() -> None:
        for filename in source_files:
            report_cov.analysis2(str(filename))

    benchmark(analyze)


@pytest.mark.benchmark(group="report")
def test_report_text(benchmark: BenchmarkFixture, report_cov: Coverage) -> None:
    benchmark(lambda: report_cov.report(file=io.StringIO()))


@pytest.mark.benchmark(group="report")
def test_xml_report(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    benchmark(lambda: report_cov.xml_report(outfile=str(tmp_path / "coverage.xml")))


@pytest.mark.benchmark(group="report")
def test_json_report(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    benchmark(lambda: report_cov.json_report(outfile=str(tmp_path / "coverage.json")))


@pytest.mark.benchmark(group="report")
def test_lcov_report(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    benchmark(lambda: report_cov.lcov_report(outfile=str(tmp_path / "coverage.lcov")))


@pytest.mark.benchmark(group="html")
def test_html_report(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    def report(html_dir: pathlib.Path) -> None:
        report_cov.html_report(directory=str(html_dir))

    benchmark.pedantic(report, setup=_html_setup(tmp_path), rounds=5, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="report")
def test_report_then_html_same_process(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    # The benchmark fixture can only be used once per test, so both reports have
    # to happen inside one callable.
    def report(html_dir: pathlib.Path) -> None:
        report_cov.report(file=io.StringIO())
        report_cov.html_report(directory=str(html_dir))

    benchmark.pedantic(report, setup=_html_setup(tmp_path), rounds=5, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="html")
def test_html_report_with_contexts(
    benchmark: BenchmarkFixture,
    contexts_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    def report(html_dir: pathlib.Path) -> None:
        contexts_cov.html_report(directory=str(html_dir), show_contexts=True)

    benchmark.pedantic(report, setup=_html_setup(tmp_path), rounds=3, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="html")
def test_html_report_with_filtered_contexts(
    benchmark: BenchmarkFixture,
    contexts_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    # Set the option here rather than in the timed function: it permanently
    # changes the Coverage object, and timing a set_option call is pointless.
    contexts_cov.set_option("report:contexts", ["test_context_alpha"])

    def report(html_dir: pathlib.Path) -> None:
        contexts_cov.html_report(directory=str(html_dir), show_contexts=True)

    benchmark.pedantic(report, setup=_html_setup(tmp_path), rounds=3, warmup_rounds=1, iterations=1)


@pytest.mark.benchmark(group="html")
def test_html_report_large_module(
    benchmark: BenchmarkFixture,
    large_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    def report(html_dir: pathlib.Path) -> None:
        large_cov.html_report(directory=str(html_dir))

    benchmark.pedantic(report, setup=_html_setup(tmp_path), rounds=3, warmup_rounds=1, iterations=1)


@pytest.fixture(name="warm_html_dir")
def warm_html_directory(report_cov: Coverage, tmp_path: pathlib.Path) -> pathlib.Path:
    """An htmlcov directory that has already had a report written into it."""
    html_dir = fresh_html_dir(tmp_path)
    report_cov.html_report(directory=str(html_dir))
    return html_dir


@pytest.mark.benchmark(group="html")
def test_html_report_unchanged(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    warm_html_dir: pathlib.Path,
) -> None:
    # The one HTML benchmark that wants a warm directory: nothing has changed,
    # so every file should be skipped, and that is what we're measuring.
    benchmark(lambda: report_cov.html_report(directory=str(warm_html_dir)))


@pytest.fixture(name="changing_source")
def changing_source_file(source_files: list[pathlib.Path]) -> Iterator[pathlib.Path]:
    """One source file that a benchmark may rewrite, restored afterwards."""
    path = source_files[0]
    original = path.read_text(encoding="utf-8")
    try:
        yield path
    finally:
        path.write_text(original, encoding="utf-8")


@pytest.mark.benchmark(group="html")
def test_html_report_single_source_change(
    benchmark: BenchmarkFixture,
    report_cov: Coverage,
    warm_html_dir: pathlib.Path,
    changing_source: pathlib.Path,
) -> None:
    original = changing_source.read_text(encoding="utf-8")
    changed = original + "\n# incremental benchmark change\n"
    # Alternate, so that every round really does find one stale file. Writing
    # the same text each time would leave nothing stale after the first round.
    sources = itertools.cycle([changed, original])

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        changing_source.write_text(next(sources), encoding="utf-8")
        return (), {}

    def report() -> None:
        report_cov.html_report(directory=str(warm_html_dir))

    benchmark.pedantic(report, setup=setup, rounds=6, iterations=1)
