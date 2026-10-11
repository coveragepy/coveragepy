# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Benchmarks for analysis and reporting costs."""

from __future__ import annotations

import io
import itertools
import pathlib
from collections.abc import Iterator
from typing import Any

import pytest

from coverage import Coverage

from tests.benchmarks.helpers import Benchmark, fresh_html_dir
from tests.benchmarks.workloads import validate_report_data
from tests.benchmarks.validation import page_stamps, assert_one_changed

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
    bench: Benchmark,
    report_cov: Coverage,
    source_files: list[pathlib.Path],
) -> None:
    def analyze() -> None:
        for filename in source_files:
            report_cov.analysis2(str(filename))

    bench(analyze)


@pytest.mark.benchmark(group="report")
def test_report_text(bench: Benchmark, report_cov: Coverage) -> None:
    bench(lambda: report_cov.report(file=io.StringIO()))


@pytest.mark.benchmark(group="report")
def test_xml_report(
    bench: Benchmark,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    bench(lambda: report_cov.xml_report(outfile=str(tmp_path / "coverage.xml")))


@pytest.mark.benchmark(group="report")
def test_json_report(
    bench: Benchmark,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    bench(lambda: report_cov.json_report(outfile=str(tmp_path / "coverage.json")))


@pytest.mark.benchmark(group="report")
def test_lcov_report(
    bench: Benchmark,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    bench(lambda: report_cov.lcov_report(outfile=str(tmp_path / "coverage.lcov")))


@pytest.mark.benchmark(group="html")
def test_html_report(
    bench: Benchmark,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    def report(html_dir: pathlib.Path) -> None:
        report_cov.html_report(directory=str(html_dir))

    bench.pedantic(report, setup=_html_setup(tmp_path))


@pytest.mark.benchmark(group="report")
def test_report_then_html_same_process(
    bench: Benchmark,
    report_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    # The benchmark fixture can only be used once per test, so both reports have
    # to happen inside one callable.
    def report(html_dir: pathlib.Path) -> None:
        report_cov.report(file=io.StringIO())
        report_cov.html_report(directory=str(html_dir))

    bench.pedantic(report, setup=_html_setup(tmp_path))


@pytest.mark.benchmark(group="html")
def test_html_report_with_contexts(
    bench: Benchmark,
    contexts_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    def report(html_dir: pathlib.Path) -> None:
        contexts_cov.html_report(directory=str(html_dir), show_contexts=True)

    bench.pedantic(report, setup=_html_setup(tmp_path))


@pytest.mark.benchmark(group="html")
def test_html_report_with_filtered_contexts(
    bench: Benchmark,
    contexts_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    # Set the option here rather than in the timed function: it permanently
    # changes the Coverage object, and timing a set_option call is pointless.
    contexts_cov.set_option("report:contexts", ["test_context_0000$"])

    def report(html_dir: pathlib.Path) -> None:
        contexts_cov.html_report(directory=str(html_dir), show_contexts=True)

    bench.pedantic(report, setup=_html_setup(tmp_path))


@pytest.mark.benchmark(group="html")
def test_html_report_large_module(
    bench: Benchmark,
    large_cov: Coverage,
    tmp_path: pathlib.Path,
) -> None:
    def report(html_dir: pathlib.Path) -> None:
        large_cov.html_report(directory=str(html_dir))

    bench.pedantic(report, setup=_html_setup(tmp_path))


@pytest.fixture(name="warm_html_dir")
def warm_html_directory(report_cov: Coverage, tmp_path: pathlib.Path) -> pathlib.Path:
    """An htmlcov directory that has already had a report written into it."""
    html_dir = fresh_html_dir(tmp_path)
    report_cov.html_report(directory=str(html_dir))
    return html_dir


@pytest.mark.benchmark(group="html")
def test_html_report_unchanged(
    bench: Benchmark,
    report_cov: Coverage,
    warm_html_dir: pathlib.Path,
) -> None:
    # The one HTML benchmark that wants a warm directory: nothing has changed,
    # so every file should be skipped, and that is what we're measuring.
    before = page_stamps(warm_html_dir)
    bench(lambda: report_cov.html_report(directory=str(warm_html_dir)))
    assert page_stamps(warm_html_dir) == before


@pytest.fixture(name="changing_source")
def changing_source_file(source_files: list[pathlib.Path]) -> Iterator[pathlib.Path]:
    """One source file that a benchmark may rewrite, restored afterwards."""
    path = [path for path in source_files if path.name == "mod_004.py"][0]
    original = path.read_text(encoding="utf-8")
    try:
        yield path
    finally:
        path.write_text(original, encoding="utf-8")


@pytest.mark.benchmark(group="html")
def test_html_report_single_source_change(
    bench: Benchmark,
    report_cov: Coverage,
    warm_html_dir: pathlib.Path,
    changing_source: pathlib.Path,
) -> None:
    assert report_cov._analyze(str(changing_source)).numbers.n_statements > 0
    original = changing_source.read_text(encoding="utf-8")
    changed = original + "\n# incremental benchmark change\n"
    # Alternate, so that every round really does find one stale file. Writing
    # the same text each time would leave nothing stale after the first round.
    sources = itertools.cycle([changed, original])

    before: dict[str, int] = {}

    def setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        before.clear()
        before.update(page_stamps(warm_html_dir))
        changing_source.write_text(next(sources), encoding="utf-8")
        return (), {}

    def report() -> None:
        report_cov.html_report(directory=str(warm_html_dir))

    def validate() -> None:
        assert_one_changed(before, page_stamps(warm_html_dir), changing_source.stem)

    bench.pedantic(report, setup=setup, teardown=validate)


@pytest.mark.benchmark(group="html")
def test_html_report_single_data_change(
    bench: Benchmark,
    report_cov: Coverage,
    warm_html_dir: pathlib.Path,
    source_files: list[pathlib.Path],
) -> None:
    """Alternate two databases; source text remains byte-for-byte identical."""
    from coverage import CoverageData

    original = report_cov.get_data()
    snapshots = [
        CoverageData(basename=str(warm_html_dir.parent / f".coverage.snapshot{idx}"))
        for idx in range(2)
    ]
    for snapshot in snapshots:
        snapshot.update(original)
    path = next(p for p in source_files if p.name == "mod_004.py")
    analysis = report_cov._analyze(str(path))
    assert analysis.arcs_missing()
    snapshots[1].add_arcs({str(path.resolve()): analysis.arcs_missing()})
    payloads = itertools.cycle([snapshots[1], snapshots[0]])
    before: dict[str, int] = {}
    source = path.read_bytes()

    def setup() -> None:
        original.erase()
        original.update(next(payloads))
        before.clear()
        before.update(page_stamps(warm_html_dir))

    def report() -> None:
        report_cov.html_report(directory=str(warm_html_dir))

    def validate() -> None:
        assert path.read_bytes() == source
        assert_one_changed(before, page_stamps(warm_html_dir), path.stem)

    try:
        bench.pedantic(report, setup=setup, teardown=validate)
    finally:
        original.erase()
        original.update(snapshots[0])
        for snapshot in snapshots:
            snapshot.close()


@pytest.mark.slow
@pytest.mark.benchmark(group="report-scale")
@pytest.mark.parametrize("format_name", ["html", "json"])
def test_report_many_modules(
    bench: Benchmark, many_ws: pathlib.Path, tmp_path: pathlib.Path, format_name: str
) -> None:
    cov = Coverage(data_file=str(many_ws / ".coverage.pytrace-branch"), config_file=False)
    cov.load()
    bench.extra_info.update(validate_report_data(cov))

    def setup() -> None:
        fresh_html_dir(tmp_path)

    def report() -> float:
        if format_name == "html":
            return cov.html_report(directory=str(tmp_path / "htmlcov"))
        return cov.json_report(outfile=str(tmp_path / "coverage.json"))

    percentage = bench.pedantic(report, setup=setup)
    assert 0 < percentage < 100


@pytest.mark.slow
@pytest.mark.benchmark(group="report-memory")
@pytest.mark.parametrize("format_name", ["html", "json"])
def test_report_peak_memory(
    bench: Benchmark, many_ws: pathlib.Path, tmp_path: pathlib.Path, format_name: str
) -> None:
    """Fresh-process timings plus separate memory samples for a large project."""
    import json
    import sys
    from tests.benchmarks.helpers import run_subprocess, subprocess_env
    from tests.benchmarks.memory import memory_samples

    rcfile = tmp_path / "benchmark.coveragerc"
    rcfile.write_text(
        f"[run]\ndata_file = {many_ws / '.coverage.pytrace-branch'}\n"
        f"[html]\ndirectory = {tmp_path / 'htmlcov'}\n"
        f"[json]\noutput = {tmp_path / 'coverage.json'}\n",
        encoding="utf-8",
    )
    result = tmp_path / "result.json"
    command = [
        sys.executable,
        str(pathlib.Path(__file__).with_name("process_runner.py")),
        "report",
        "--format",
        format_name,
        "--rcfile",
        str(rcfile),
        "--result",
        str(result),
    ]
    env = subprocess_env()
    bench.extra_info.update(modules=400, report_format=format_name)

    def setup() -> None:
        fresh_html_dir(tmp_path)
        (tmp_path / "coverage.json").unlink(missing_ok=True)
        result.unlink(missing_ok=True)

    def run() -> str:
        return run_subprocess(command, tmp_path, env)

    def validate() -> None:
        assert json.loads(result.read_text(encoding="utf-8"))["exit_status"] == 0
        if format_name == "html":
            assert len(list((tmp_path / "htmlcov").glob("*_py.html"))) >= 400
        else:
            assert (
                len(json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8"))["files"])
                >= 400
            )

    bench.pedantic(run, setup=setup, teardown=validate)
    if not bench.extra_info["smoke"]:
        bench.extra_info["peak_rss_bytes"] = memory_samples(
            [*command, "--rss"], tmp_path, env, result, setup, validate
        )
