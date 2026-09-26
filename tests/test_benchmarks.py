# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Small correctness checks for benchmark workloads, without collecting timings."""

from __future__ import annotations

import pathlib
import subprocess
import sys
from collections.abc import Iterator

import pytest

from coverage import CoverageData
from coverage.data import combine_parallel_data
from tests import testenv
from tests.benchmarks.datasets import make_combine_dataset
from tests.benchmarks.helpers import (
    REPO_ROOT,
    collect_data,
    clear_package_modules,
    import_workload,
    make_coverage,
    make_multiprocessing_project,
    make_workspace,
    run_coverage_subprocess,
    subprocess_env,
)
from tests.benchmarks.process_runner import rss_bytes
from tests.benchmarks.validation import assert_one_changed, page_stamps, validate_multiprocessing
from tests.benchmarks.workloads import (
    make_context_workspace,
    make_report_workspace,
    run_contexts,
    validate_context_data,
    validate_report_data,
)


class BenchmarkWorkloadsTest:
    """Exercise the invariants whose absence previously allowed empty work.

    Use the suite's selected core so nested collection also works under metacov.
    The opt-in benchmarks independently exercise each available core.
    """

    @pytest.fixture(autouse=True)
    def clean_generated_modules(self) -> Iterator[None]:
        """Keep these correctness checks isolated from ordinary suite imports."""
        try:
            yield
        finally:
            clear_package_modules()

    def test_unused_files_are_discovered(self, tmp_path: pathlib.Path) -> None:
        workspace = make_workspace(tmp_path, module_count=1, unused_file_count=3)
        cov = collect_data(workspace, core=testenv.CORE, rounds=1, loops=2)
        cov.save()
        data = cov.get_data()
        unused = [f for f in data.measured_files() if pathlib.Path(f).name.startswith("unused_")]
        assert len(unused) == 3
        assert all(data.lines(f) == [] for f in unused)
        data.close()

    def test_reporting_inputs_and_incremental_source(self, tmp_path: pathlib.Path) -> None:
        workspace = make_report_workspace(tmp_path, module_count=16)
        cov = collect_data(workspace, core=testenv.CORE, rounds=1, loops=1)
        counts = validate_report_data(cov)
        assert counts["unexecuted_modules"] == 4
        directory = tmp_path / "htmlcov"
        cov.html_report(directory=str(directory))
        before = page_stamps(directory)
        cov.html_report(directory=str(directory))
        assert page_stamps(directory) == before
        source = workspace / "benchpkg" / "mod_004.py"
        assert cov._analyze(str(source)).numbers.n_statements > 0
        source.write_text(source.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
        cov.html_report(directory=str(directory))
        assert_one_changed(before, page_stamps(directory), "mod_004")
        cov.get_data().close()

    def test_incremental_data_changes_without_source_edit(self, tmp_path: pathlib.Path) -> None:
        workspace = make_report_workspace(tmp_path, module_count=16)
        cov = collect_data(workspace, core=testenv.CORE, rounds=1, loops=1)
        directory = tmp_path / "htmlcov"
        cov.html_report(directory=str(directory))
        before = page_stamps(directory)
        source = workspace / "benchpkg" / "mod_004.py"
        content = source.read_bytes()
        missing = cov._analyze(str(source)).arcs_missing()
        assert missing
        cov.get_data().add_arcs({str(source.resolve()): missing})
        cov.html_report(directory=str(directory))
        assert source.read_bytes() == content
        assert_one_changed(before, page_stamps(directory), "mod_004")
        cov.get_data().close()

    @pytest.mark.parametrize("explicit", [False, True])
    def test_contexts_change_filtered_data(self, tmp_path: pathlib.Path, explicit: bool) -> None:
        if not explicit and not testenv.DYN_CONTEXTS:
            pytest.skip("No dynamic contexts with this core")
        workspace = make_context_workspace(tmp_path, count=10, module_count=8)
        cov = make_coverage(
            workspace, core=testenv.CORE, dynamic_context=None if explicit else "test_function"
        )
        run_contexts(cov, import_workload(workspace), explicit)
        validate_context_data(cov, 10)
        cov.get_data().close()

    @pytest.mark.parametrize("profile", ["dense", "contexts_sparse", "remap"])
    @pytest.mark.parametrize("branch", [False, True])
    def test_combine_profiles(self, tmp_path: pathlib.Path, profile: str, branch: bool) -> None:
        dataset = make_combine_dataset(tmp_path, profile, branch, file_count=4, shards=2)
        target = CoverageData(basename=str(tmp_path / ".coverage"))
        combine_parallel_data(
            target,
            data_paths=[str(tmp_path / "parts")],
            aliases=dataset.aliases,
            strict=True,
            keep=True,
        )
        dataset.validate(target)
        assert len(target.measured_files()) == 4
        assert all(
            pathlib.Path(name).parent == tmp_path.resolve() / "source"
            for name in target.measured_files()
        )
        target.close()

    @pytest.mark.skipif(not testenv.HAVE_CTRACE, reason="no CTracer")
    def test_workers_save_before_combining(self, tmp_path: pathlib.Path) -> None:
        workspace = make_workspace(tmp_path, module_count=24, calls_per_module=36)
        make_multiprocessing_project(workspace, workers=2, tasks=2)
        env = subprocess_env()
        run_coverage_subprocess(workspace, ["run", "--rcfile=.coveragerc", "run_multiproc.py"], env)
        validate_multiprocessing(workspace, combined=False, workers=2)
        run_coverage_subprocess(workspace, ["combine", "--rcfile=.coveragerc"], env)
        validate_multiprocessing(workspace, combined=True, workers=2)

    def test_rss_units(self) -> None:
        # A 1 MiB process is reported in different units by the two kernels.
        assert rss_bytes(1024, "linux") == 1024 * 1024
        assert rss_bytes(1024 * 1024, "darwin") == 1024 * 1024
        assert rss_bytes(1024, "win32") is None

    @pytest.mark.parametrize(
        "target", ["tests/benchmarks", "tests/benchmarks/test_tokenization.py"]
    )
    def test_collection_requires_opt_in(self, target: str) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "--collect-only",
                "-q",
                "-m",
                "benchmark",
                target,
            ],
            cwd=REPO_ROOT,
            env=subprocess_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert result.returncode == 5, result.stdout + result.stderr
        assert "test_source_token_lines[" not in result.stdout

    def test_corrupt_corpus_is_rejected(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import shutil
        from tests.benchmarks import corpora

        shutil.copytree(corpora.CORPUS_DIR, tmp_path / "corpus")
        monkeypatch.setattr(corpora, "CORPUS_DIR", tmp_path / "corpus")
        source = corpora.CORPUS_DIR / "phystokens.tok"
        source.write_bytes(source.read_bytes() + b"\n# changed input\n")
        with pytest.raises(AssertionError, match="phystokens.tok"):
            corpora.load_corpus("phystokens")

    def test_missing_real_preparation_is_actionable(self, tmp_path: pathlib.Path) -> None:
        from tests.benchmarks.real_project import verify_prepared

        with pytest.raises(RuntimeError, match="make bench-prepare"):
            verify_prepared(tmp_path)
