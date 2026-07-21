"""Shared helpers for ASV benchmarks."""

from __future__ import annotations

import importlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from typing import Iterator

from coverage import Coverage
from coverage.core import CTRACER_FILE
from coverage.sqldata import CoverageData

PACKAGE_NAME = "benchpkg"
MODULE_COUNT = 80
CALLS_PER_MODULE = 80
MEASUREMENT_ROUNDS = 20
REPORT_ROUNDS = 28
LARGE_FUNCTION_COUNT = 320
LARGE_UNUSED_FILE_COUNT = 800
COMBINE_FILE_COUNT = 48
COMBINE_CONTEXT_COUNT = 24
MULTIPROC_WORKERS = 8
MULTIPROC_TASKS = 32
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def core_available(core: str) -> bool:
    """Whether `core` can be used in this environment."""
    if core == "ctrace":
        return CTRACER_FILE is not None
    if core == "sysmon":
        return sys.version_info >= (3, 12)
    return True


@contextmanager
def set_env(**values: str | None) -> Iterator[None]:
    """Temporarily set environment variables."""
    old = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextmanager
def sys_path_entry(path: pathlib.Path) -> Iterator[None]:
    """Temporarily put `path` at the front of sys.path."""
    path_str = str(path)
    sys.path.insert(0, path_str)
    try:
        yield
    finally:
        try:
            sys.path.remove(path_str)
        except ValueError:
            pass


def clear_package_modules() -> None:
    """Forget generated benchmark modules so workloads can be re-imported."""
    doomed = [
        name for name in sys.modules
        if name == PACKAGE_NAME or name.startswith(f"{PACKAGE_NAME}.")
    ]
    for name in doomed:
        sys.modules.pop(name, None)


def _module_source(calls_per_module: int) -> str:
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
    workload_lines = [
        *imported,
        "",
        f"def main(rounds: int = {MEASUREMENT_ROUNDS}, loops: int = {calls_per_module}) -> int:",
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
    *,
    module_count: int = MODULE_COUNT,
    calls_per_module: int = CALLS_PER_MODULE,
    large_module: bool = False,
    large_function_count: int = LARGE_FUNCTION_COUNT,
    unused_file_count: int = 0,
) -> pathlib.Path:
    """Create a synthetic project for ASV benchmarks."""
    root = pathlib.Path(tempfile.mkdtemp(prefix="coveragepy-asv-"))
    pkg = root / PACKAGE_NAME
    pkg.mkdir()

    (pkg / "__init__.py").write_text(
        '"""Synthetic package for ASV benchmarks."""\n',
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
                    f"def main(rounds: int = {REPORT_ROUNDS}, loops: int = 40) -> int:",
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
) -> Coverage:
    """Construct a Coverage object aimed at the synthetic project."""
    data_file = workspace / f".coverage.{data_suffix}"
    with set_env(COVERAGE_CORE=core, COVERAGE_FILE=str(data_file)):
        cov = Coverage(
            data_file=str(data_file),
            config_file=False,
            source=[str(workspace / PACKAGE_NAME)] if source is None else source,
            branch=branch,
        )
    return cov


def collect_data(
    workspace: pathlib.Path,
    *,
    core: str = "pytrace",
    branch: bool = True,
    rounds: int = MEASUREMENT_ROUNDS,
    loops: int = CALLS_PER_MODULE,
) -> Coverage:
    """Run the synthetic workload under coverage and return the Coverage."""
    if not core_available(core):
        raise NotImplementedError(f"core={core!r} is not available here")

    cov = make_coverage(
        workspace,
        core=core,
        branch=branch,
        data_suffix=f"{core}-{'branch' if branch else 'line'}",
    )
    clear_package_modules()
    with sys_path_entry(workspace):
        cov.start()
        try:
            workload = importlib.import_module(f"{PACKAGE_NAME}.workload")
            workload.main(rounds=rounds, loops=loops)
        finally:
            cov.stop()
    clear_package_modules()
    return cov


def collect_context_data(workspace: pathlib.Path) -> Coverage:
    """Collect data using dynamic contexts."""
    measured = Coverage(
        data_file=str(workspace / ".coverage.contexts"),
        config_file=False,
        source=[str(workspace / PACKAGE_NAME)],
        branch=True,
    )
    measured.set_option("run:dynamic_context", "test_function")
    clear_package_modules()
    with sys_path_entry(workspace):
        workload = __import__(f"{PACKAGE_NAME}.workload", fromlist=["main"])
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
    """Create an empty HTML output directory."""
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


def run_coverage_subprocess(
    workspace: pathlib.Path,
    args: list[str],
    *,
    env: dict[str, str] | None = None,
) -> None:
    """Run `python -m coverage ...` inside `workspace`."""
    base_env = os.environ.copy()
    existing_pythonpath = base_env.get("PYTHONPATH")
    repo_pythonpath = str(REPO_ROOT)
    if existing_pythonpath:
        base_env["PYTHONPATH"] = os.pathsep.join([repo_pythonpath, existing_pythonpath])
    else:
        base_env["PYTHONPATH"] = repo_pythonpath
    if env:
        base_env.update(env)
    subprocess.run(
        [sys.executable, "-m", "coverage", *args],
        cwd=workspace,
        env=base_env,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
