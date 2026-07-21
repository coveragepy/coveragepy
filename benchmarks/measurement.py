"""Benchmarks for measurement-time costs."""

from __future__ import annotations

from coverage import Coverage
from coverage.data import combine_parallel_data
from coverage.sqldata import CoverageData

from benchmarks.helpers import (
    CALLS_PER_MODULE,
    LARGE_UNUSED_FILE_COUNT,
    MEASUREMENT_ROUNDS,
    MULTIPROC_TASKS,
    MULTIPROC_WORKERS,
    collect_context_data,
    collect_data,
    core_available,
    make_coverage,
    make_multiprocessing_project,
    make_parallel_data_files,
    make_workspace,
    run_coverage_subprocess,
)


class TimeMeasurement:
    """Measure tracing overhead during execution."""

    params = (["pytrace", "ctrace", "sysmon"], [False, True])
    param_names = ["core", "branch"]

    def setup(self, core: str, branch: bool) -> None:
        if not core_available(core):
            raise NotImplementedError(f"core={core!r} is not available here")
        self.workspace = make_workspace()

    def teardown(self, core: str, branch: bool) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def time_collect(self, core: str, branch: bool) -> None:
        cov = collect_data(
            self.workspace,
            core=core,
            branch=branch,
            rounds=MEASUREMENT_ROUNDS,
            loops=CALLS_PER_MODULE,
        )
        del cov


class TimePersistence:
    """Measure persistence costs in CoverageData."""

    def setup(self) -> None:
        self.workspace = make_workspace()
        line_cov = collect_data(self.workspace, core="pytrace", branch=False)
        arc_cov = collect_data(self.workspace, core="pytrace", branch=True)
        line_collector = line_cov._collector
        arc_collector = arc_cov._collector
        assert line_collector is not None
        assert arc_collector is not None
        self.line_data = {
            fname: linenos.copy()
            for fname, linenos in line_collector.data.copy().items()
        }
        self.arc_data = {
            fname: arcs.copy()
            for fname, arcs in arc_collector.data.copy().items()
        }
        self.line_db = self.workspace / ".coverage.lines.bench"
        self.arc_db = self.workspace / ".coverage.arcs.bench"

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def time_add_lines(self) -> None:
        self.line_db.unlink(missing_ok=True)
        data = CoverageData(basename=str(self.line_db))
        data.add_lines(self.line_data)

    def time_add_arcs(self) -> None:
        self.arc_db.unlink(missing_ok=True)
        data = CoverageData(basename=str(self.arc_db))
        data.add_arcs(self.arc_data)


class TimeSourceTree:
    """Measure runs with large source trees that are mostly unexecuted."""

    def setup(self) -> None:
        self.workspace = make_workspace(unused_file_count=LARGE_UNUSED_FILE_COUNT)
        self.pkg_root = self.workspace / "benchpkg"

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def time_collect_with_large_unused_source_tree(self) -> None:
        cov = Coverage(
            data_file=str(self.workspace / ".coverage.unused"),
            config_file=False,
            source=[str(self.pkg_root)],
            branch=True,
        )
        from benchmarks.helpers import clear_package_modules, sys_path_entry

        clear_package_modules()
        with sys_path_entry(self.workspace):
            cov.start()
            try:
                workload = __import__("benchpkg.workload", fromlist=["main"])
                workload.main(rounds=4, loops=10)
            finally:
                cov.stop()
        cov.save()


class TimeDynamicContexts:
    """Measure collection overhead with dynamic contexts enabled."""

    def setup(self) -> None:
        self.workspace = make_workspace()

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def time_collect_test_function_contexts(self) -> None:
        cov = collect_context_data(self.workspace)
        del cov


class TimeCombine:
    """Measure combining many coverage data files."""

    def setup(self) -> None:
        self.workspace = make_workspace()
        self.arc_base_name, self.arc_parts = make_parallel_data_files(
            self.workspace, branch=True, subdir="combine_arcs"
        )
        self.line_base_name, self.line_parts = make_parallel_data_files(
            self.workspace, branch=False, subdir="combine_lines"
        )

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def time_combine_many_files_with_contexts(self) -> None:
        target = CoverageData(basename=self.arc_base_name)
        combine_parallel_data(target, data_paths=[str(self.workspace / "combine_arcs")], keep=True)

    def time_combine_many_files_line_only(self) -> None:
        target = CoverageData(basename=self.line_base_name)
        combine_parallel_data(target, data_paths=[str(self.workspace / "combine_lines")], keep=True)


class TimeMultiprocessing:
    """Measure real multiprocessing collection and subsequent combine."""

    def setup(self) -> None:
        self.workspace = make_workspace(module_count=24, calls_per_module=36)
        self.rcfile, self.script = make_multiprocessing_project(
            self.workspace,
            workers=MULTIPROC_WORKERS,
            tasks=MULTIPROC_TASKS,
        )

    def teardown(self) -> None:
        import shutil

        shutil.rmtree(self.workspace, ignore_errors=True)

    def _clean_data(self) -> None:
        for path in self.workspace.glob(".coverage.mproc*"):
            path.unlink(missing_ok=True)

    def _collect_parallel_files(self) -> None:
        self._clean_data()
        run_coverage_subprocess(
            self.workspace,
            ["run", f"--rcfile={self.rcfile.name}", self.script.name],
        )

    def time_multiprocessing_run(self) -> None:
        self._collect_parallel_files()

    def time_multiprocessing_run_and_combine(self) -> None:
        self._collect_parallel_files()
        run_coverage_subprocess(
            self.workspace,
            ["combine", f"--rcfile={self.rcfile.name}"],
        )
