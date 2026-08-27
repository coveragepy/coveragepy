# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Shared helpers for the coverage.py benchmarks.

These build synthetic Python packages at runtime so the benchmarks exercise the
same code paths on every machine, without depending on any third-party project.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import shutil
import subprocess
import sys
from collections.abc import Callable
from types import ModuleType
from typing import Any, Protocol

from coverage import Coverage
from coverage.data import CoverageData


class Benchmark(Protocol):
    """The part of pytest-benchmark's fixture that we use.

    pytest-benchmark ships py.typed but leaves BenchmarkFixture itself
    unannotated, so mypy --strict rejects every call into it.  Describing the
    two entry points we use keeps our call sites checked, and doesn't go stale
    whenever upstream does or doesn't get around to annotating them.

    """

    def __call__(self, function_to_benchmark: Callable[..., Any], /) -> Any: ...

    def pedantic(
        self,
        target: Callable[..., Any],
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        setup: Callable[[], Any] | None = None,
        teardown: Callable[..., Any] | None = None,
        rounds: int = 1,
        warmup_rounds: int = 0,
        iterations: int = 1,
    ) -> Any:
        """Time `target`, re-running `setup` untimed before each round."""


PACKAGE_NAME = "benchpkg"
MODULE_COUNT = 80
CALLS_PER_MODULE = 80
# How many times the synthetic workload loops. Not to be confused with
# pytest-benchmark's "rounds", which is how many times a benchmark is timed.
WORKLOAD_ROUNDS = 20
REPORT_WORKLOAD_ROUNDS = 28
LARGE_FUNCTION_COUNT = 320
LARGE_UNUSED_FILE_COUNT = 800
COMBINE_FILE_COUNT = 48
COMBINE_CONTEXT_COUNT = 24
MULTIPROC_WORKERS = 8
MULTIPROC_TASKS = 32
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def clear_package_modules() -> None:
    """Forget generated benchmark modules so workloads can be re-imported."""
    doomed = [
        name for name in sys.modules if name == PACKAGE_NAME or name.startswith(f"{PACKAGE_NAME}.")
    ]
    for name in doomed:
        sys.modules.pop(name, None)
    importlib.invalidate_caches()


def import_workload(workspace: pathlib.Path) -> ModuleType:
    """Freshly import the synthetic workload package from `workspace`.

    `sys.path` is left as it was found, so this is safe to call from a
    session-scoped fixture.

    """
    clear_package_modules()
    path_str = str(workspace)
    sys.path.insert(0, path_str)
    try:
        return importlib.import_module(f"{PACKAGE_NAME}.workload")
    finally:
        try:
            sys.path.remove(path_str)
        except ValueError:
            pass


def _module_source(calls_per_module: int) -> str:
    """Source for one small synthetic module of branchy code."""
    return "\n".join(
        [
            f"def compute(seed: int, loops: int = {calls_per_module}) -> int:",
            "    total = 0",
            "    for outer in range(loops):",
            "        branch = (seed + outer) % 7",
            "        if branch in (0, 3):",
            "            total += outer * 2",
            "        elif branch in (1, 4):",
            "            total += outer + seed",
            "        elif branch == 2:",
            "            total -= outer",
            "        else:",
            "            total += outer // 2",
            "    return total",
            "",
        ]
    )


def _workload_source(
    imported: list[str],
    call_lines: list[str],
    *,
    calls_per_module: int,
) -> str:
    """Source for the module that drives all the others."""
    workload_lines = [
        *imported,
        "",
        f"def main(rounds: int = {WORKLOAD_ROUNDS}, loops: int = {calls_per_module}) -> int:",
        "    total = 0",
        "    for seed in range(rounds):",
        *call_lines,
        "    return total",
        "",
        "def test_context_alpha(loops: int = 30) -> int:",
        "    return main(rounds=6, loops=loops)",
        "",
        "def test_context_beta(loops: int = 30) -> int:",
        "    return main(rounds=8, loops=loops)",
        "",
        "def run_contexts() -> int:",
        "    total = 0",
        "    total += test_context_alpha()",
        "    total += test_context_beta()",
        "    return total",
        "",
    ]
    return "\n".join(workload_lines)


def _large_module_source(function_count: int) -> str:
    """Source for one very large module, for report-time benchmarks."""
    lines = [
        '"""Large synthetic module for report-time benchmarks."""',
        "",
        "class Root:",
        "    def __init__(self, seed: int) -> None:",
        "        self.seed = seed",
        "",
    ]
    for idx in range(function_count):
        lines.extend(
            [
                f"class Group{idx}:",
                "    def __init__(self, base: int) -> None:",
                "        self.base = base",
                "",
                "    def value(self, limit: int) -> int:",
                "        total = 0",
                "        for i in range(limit):",
                f"            if (i + self.base + {idx}) % 5 == 0:",
                "                total += i * 2",
                f"            elif (i + {idx}) % 3 == 0:",
                "                total -= i",
                "            else:",
                "                total += i // 2",
                "        return total",
                "",
                f"def func_{idx}(seed: int, loops: int = 40) -> int:",
                f"    worker = Group{idx}(seed + {idx})",
                "    return worker.value(loops)",
                "",
            ]
        )
    lines.extend(
        [
            "def main(rounds: int = 10) -> int:",
            "    total = 0",
            "    for seed in range(rounds):",
        ]
    )
    for idx in range(function_count):
        lines.append(f"        total += func_{idx}(seed)")
    lines.extend(["    return total", ""])
    return "\n".join(lines)


def make_workspace(
    root: pathlib.Path,
    *,
    module_count: int = MODULE_COUNT,
    calls_per_module: int = CALLS_PER_MODULE,
    large_module: bool = False,
    large_function_count: int = LARGE_FUNCTION_COUNT,
    unused_file_count: int = 0,
) -> pathlib.Path:
    """Create a synthetic project under `root`, and return `root`."""
    pkg = root / PACKAGE_NAME
    pkg.mkdir()

    (pkg / "__init__.py").write_text(
        '"""Synthetic package for coverage.py benchmarks."""\n',
        encoding="utf-8",
    )

    if large_module:
        large_path = pkg / "large_module.py"
        large_path.write_text(
            _large_module_source(large_function_count),
            encoding="utf-8",
        )
        workload = pkg / "workload.py"
        workload.write_text(
            "\n".join(
                [
                    "from . import large_module",
                    "",
                    f"def main(rounds: int = {REPORT_WORKLOAD_ROUNDS}, loops: int = 40) -> int:",
                    "    del loops",
                    "    return large_module.main(rounds)",
                    "",
                    "def test_context_alpha() -> int:",
                    "    return main(4)",
                    "",
                    "def test_context_beta() -> int:",
                    "    return main(6)",
                    "",
                    "def run_contexts() -> int:",
                    "    return test_context_alpha() + test_context_beta()",
                    "",
                ]
            ),
            encoding="utf-8",
        )
    else:
        imported = []
        call_lines = []
        for mod_num in range(module_count):
            mod_name = f"mod_{mod_num:03d}"
            imported.append(f"from . import {mod_name}")
            call_lines.append(f"        total += {mod_name}.compute(seed + {mod_num}, loops=loops)")
            mod_path = pkg / f"{mod_name}.py"
            mod_path.write_text(_module_source(calls_per_module), encoding="utf-8")

        workload = pkg / "workload.py"
        workload.write_text(
            _workload_source(imported, call_lines, calls_per_module=calls_per_module),
            encoding="utf-8",
        )

    if unused_file_count:
        extra = pkg / "unused_tree"
        extra.mkdir()
        for idx in range(unused_file_count):
            source = extra / f"unused_{idx:04d}.py"
            source.write_text(
                "\n".join(
                    [
                        f"def never_run_{idx}(value: int) -> int:",
                        "    total = 0",
                        "    for i in range(25):",
                        "        if i % 2:",
                        "            total += value + i",
                        "        else:",
                        "            total -= value - i",
                        "    return total",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

    return root


def make_coverage(
    workspace: pathlib.Path,
    *,
    core: str = "pytrace",
    branch: bool = True,
    data_suffix: str = "bench",
    source: list[str] | None = None,
    dynamic_context: str | None = None,
) -> Coverage:
    """Construct a Coverage object aimed at the synthetic project.

    The core is chosen with the ``run:core`` option rather than the
    ``COVERAGE_CORE`` environment variable, so that whatever core the test suite
    happens to be running under can't leak in here.

    """
    data_file = workspace / f".coverage.{data_suffix}"
    cov = Coverage(
        data_file=str(data_file),
        config_file=False,
        source=[str(workspace / PACKAGE_NAME)] if source is None else source,
        branch=branch,
    )
    cov.set_option("run:core", core)
    if dynamic_context is not None:
        cov.set_option("run:dynamic_context", dynamic_context)
    return cov


def measure_workload(
    cov: Coverage,
    workload: ModuleType,
    *,
    rounds: int = WORKLOAD_ROUNDS,
    loops: int = CALLS_PER_MODULE,
) -> None:
    """Run an already-imported workload under `cov`. This is a timed region."""
    cov.start()
    try:
        workload.main(rounds=rounds, loops=loops)
    finally:
        cov.stop()


def collect_data(
    workspace: pathlib.Path,
    *,
    core: str = "pytrace",
    branch: bool = True,
    rounds: int = WORKLOAD_ROUNDS,
    loops: int = CALLS_PER_MODULE,
) -> Coverage:
    """Run the synthetic workload under coverage and return the Coverage.

    The workload is imported while measurement is running, so the collected data
    covers module-level code too.

    """
    cov = make_coverage(
        workspace,
        core=core,
        branch=branch,
        data_suffix=f"{core}-{'branch' if branch else 'line'}",
    )
    clear_package_modules()
    path_str = str(workspace)
    sys.path.insert(0, path_str)
    try:
        cov.start()
        try:
            workload = importlib.import_module(f"{PACKAGE_NAME}.workload")
            workload.main(rounds=rounds, loops=loops)
        finally:
            cov.stop()
    finally:
        try:
            sys.path.remove(path_str)
        except ValueError:
            pass
    clear_package_modules()
    return cov


def collect_context_data(workspace: pathlib.Path, *, core: str = "pytrace") -> Coverage:
    """Collect data using dynamic contexts."""
    measured = make_coverage(
        workspace,
        core=core,
        branch=True,
        data_suffix="contexts",
        dynamic_context="test_function",
    )
    workload = import_workload(workspace)
    measured.start()
    try:
        workload.run_contexts()
    finally:
        measured.stop()
    clear_package_modules()
    return measured


def make_parallel_data_files(
    workspace: pathlib.Path,
    *,
    file_count: int = COMBINE_FILE_COUNT,
    context_count: int = COMBINE_CONTEXT_COUNT,
    branch: bool = True,
    subdir: str | None = None,
) -> tuple[str, list[str]]:
    """Create many coverage data files for combine benchmarks."""
    if subdir is None:
        subdir = "combine_arcs" if branch else "combine_lines"
    data_root = workspace / subdir
    data_root.mkdir()
    base_name = str(data_root / ".coverage")
    file_names = [f"{PACKAGE_NAME}/mod_{idx:03d}.py" for idx in range(24)]
    paths = []

    for data_idx in range(file_count):
        data = CoverageData(basename=base_name, suffix=f"part{data_idx:03d}")
        for ctx_idx in range(context_count):
            data.set_context(f"ctx_{ctx_idx:03d}")
            if branch:
                arc_data = {}
                for file_idx, filename in enumerate(file_names):
                    start = 10 * (ctx_idx + 1) + data_idx + file_idx
                    arc_data[filename] = {
                        (-start, start),
                        (start, start + 1),
                        (start + 1, start + 3),
                        (start + 1, start + 4),
                    }
                data.add_arcs(arc_data)
            else:
                line_data = {}
                for file_idx, filename in enumerate(file_names):
                    start = 10 * (ctx_idx + 1) + data_idx + file_idx
                    line_data[filename] = {start, start + 1, start + 2, start + 3}
                data.add_lines(line_data)
        data.write()
        paths.append(data.data_filename())

    return base_name, paths


def fresh_html_dir(workspace: pathlib.Path) -> pathlib.Path:
    """Create an empty HTML output directory.

    Only ever call this from a fixture or a ``benchmark.pedantic`` setup: an HTML
    report into a populated directory takes the incremental path, and the
    ``rmtree`` here is not something we want to time.

    """
    html_dir = workspace / "htmlcov"
    shutil.rmtree(html_dir, ignore_errors=True)
    html_dir.mkdir()
    return html_dir


def make_multiprocessing_project(
    workspace: pathlib.Path,
    *,
    workers: int = MULTIPROC_WORKERS,
    tasks: int = MULTIPROC_TASKS,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Create files for a multiprocessing coverage benchmark."""
    rcfile = workspace / ".coveragerc"
    rcfile.write_text(
        "\n".join(
            [
                "[run]",
                "branch = true",
                "parallel = true",
                "concurrency = multiprocessing",
                f"data_file = {workspace / '.coverage.mproc'}",
                f"source_dirs = {workspace / PACKAGE_NAME}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    script = workspace / "run_multiproc.py"
    script.write_text(
        "\n".join(
            [
                "import multiprocessing",
                f"from {PACKAGE_NAME} import workload",
                "",
                "def worker(seed: int) -> int:",
                "    return workload.main(rounds=4 + (seed % 3), loops=18 + (seed % 5))",
                "",
                "def main() -> int:",
                f"    with multiprocessing.Pool({workers}) as pool:",
                f"        values = pool.map(worker, range({tasks}))",
                "    return sum(values)",
                "",
                'if __name__ == "__main__":',
                "    main()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return rcfile, script


def run_coverage_subprocess(workspace: pathlib.Path, args: list[str]) -> None:
    """Run `python -m coverage ...` inside `workspace`.

    The child's environment is scrubbed of the variables our own test suite sets,
    so a benchmark measures plain coverage.py and never inherits metacov's
    ``COVERAGE_PROCESS_START`` or the core the suite happens to be testing.

    """
    env = os.environ.copy()
    for name in ["COVERAGE_PROCESS_START", "COVERAGE_TESTING", "COVERAGE_CORE", "COVERAGE_FILE"]:
        env.pop(name, None)
    # So that `python -m coverage` finds this checkout even if it isn't installed.
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(REPO_ROOT), env.get("PYTHONPATH")]))
    subprocess.run(
        [sys.executable, "-m", "coverage", *args],
        cwd=workspace,
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
