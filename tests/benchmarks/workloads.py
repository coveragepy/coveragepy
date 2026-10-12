# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Deterministic workloads with deliberately different execution shapes."""

from __future__ import annotations

import pathlib
import textwrap
from types import ModuleType

from coverage import Coverage

from tests.benchmarks.helpers import PACKAGE_NAME, import_workload, make_coverage

REPORT_TEMPLATES = [
    """\
class Calculator:
    def apply(self, value):
        if value < 0:
            return -value
        elif value == 0:
            return 10
        return value * 2

def compute(seed, loops=1):
    return Calculator().apply(seed)
""",
    """\
def compute(seed, loops=1):
    values = [value * 2 for value in range(6) if value % 2]
    mapping = {value: str(value) for value in values}
    if seed < 0:
        return sum(values)
    return len(mapping)
""",
    """\
from contextlib import nullcontext

def compute(seed, loops=1):
    with nullcontext(seed) as value:
        try:
            result = 12 // value
        except ZeroDivisionError:
            result = 0
        finally:
            value = abs(value)
    if value > 1:
        return result + value
    return result
""",
    """\
def values(seed):
    yield seed
    yield from range(3)

def compute(seed, loops=1):
    match seed:
        case -1:
            return sum(values(seed))
        case 0:
            return 0
        case _:
            return max(values(seed))
""",
]


def make_report_workspace(root: pathlib.Path, module_count: int = 80) -> pathlib.Path:
    """Cross four source shapes with full, partial, unused, and excluded code."""
    pkg = root / PACKAGE_NAME
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    imports, calls = [], []
    for idx in range(module_count):
        name = f"mod_{idx:03d}"
        mode = (idx // 4) % 4
        source = REPORT_TEMPLATES[idx % 4]
        if mode == 3:
            source += '\nif False:  # pragma: no cover\n    raise RuntimeError("excluded")\n'
        (pkg / f"{name}.py").write_text(source, encoding="utf-8")
        if mode != 2:
            imports.append(f"from . import {name}")
            seeds = [1] if mode == 1 else [-1, 0, 1, 2, 3]
            calls.append(f"    total += sum({name}.compute(seed) for seed in {seeds!r})")
    driver = imports + [
        "",
        "def main(rounds=1, loops=1):",
        "    total = 0",
        *calls,
        "    return total",
        "",
    ]
    (pkg / "workload.py").write_text("\n".join(driver), encoding="utf-8")
    return root


def validate_report_data(cov: Coverage) -> dict[str, int]:
    """Check that mixed coverage really reaches the report's nontrivial paths."""
    analyses = [
        cov._analyze(f) for f in cov.get_data().measured_files() if "/mod_" in f.replace("\\", "/")
    ]
    counts = {
        "modules": len(analyses),
        "missing_lines": sum(len(a.missing) for a in analyses),
        "missing_branches": sum(a.numbers.n_missing_branches for a in analyses),
        "excluded_lines": sum(len(a.excluded) for a in analyses),
        "unexecuted_modules": sum(a.numbers.n_missing == a.numbers.n_statements for a in analyses),
        "fully_covered_modules": sum(
            not a.missing and not a.numbers.n_missing_branches for a in analyses
        ),
    }
    assert all(value > 0 for value in counts.values()), counts
    return counts


def make_context_workspace(root: pathlib.Path, count: int, module_count: int = 80) -> pathlib.Path:
    """Tests visit small overlapping groups, with different branch selections."""
    pkg = root / PACKAGE_NAME
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    imports = []
    for idx in range(module_count):
        name = f"mod_{idx:03d}"
        (pkg / f"{name}.py").write_text(
            "def compute(seed):\n    if seed % 2:\n        return seed + 1\n    return seed - 1\n",
            encoding="utf-8",
        )
        imports.append(f"from . import {name}")
    lines = [*imports, ""]
    for idx in range(count):
        modules = [(idx + offset) % module_count for offset in range(4)]
        lines.extend(
            [
                f"def test_context_{idx:04d}():",
                "    return " + " + ".join(f"mod_{m:03d}.compute({idx})" for m in modules),
                "",
            ]
        )
    lines.append("TESTS = [" + ", ".join(f"test_context_{idx:04d}" for idx in range(count)) + "]")
    (pkg / "workload.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return root


def run_contexts(cov: Coverage, workload: ModuleType, explicit: bool) -> None:
    """Measure automatic context discovery or the API used by test runners."""
    cov.start()
    try:
        for idx, function in enumerate(workload.TESTS):
            if explicit:
                cov.switch_context(f"test_context_{idx:04d}")
            function()
    finally:
        cov.stop()


def collect_contexts(root: pathlib.Path, count: int = 500) -> Coverage:
    """Prepare a context-rich report dataset, outside benchmark timing."""
    make_context_workspace(root, count)
    workload = import_workload(root)
    cov = make_coverage(root, data_suffix="contexts")
    run_contexts(cov, workload, explicit=True)
    cov.save()
    return cov


def validate_context_data(cov: Coverage, count: int) -> None:
    """Ensure contexts exist and selecting one changes populated modules."""
    data = cov.get_data()
    contexts = data.measured_contexts() - {""}
    assert len(contexts) == count, contexts
    before = {f: set(data.arcs(f) or []) for f in data.measured_files()}
    data.set_query_contexts(["test_context_0000$"])
    after = {f: set(data.arcs(f) or []) for f in data.measured_files()}
    assert any(after.values())
    assert any(before[f] and before[f] != after[f] for f in before)
    assert all(after[f] <= before[f] for f in before)
    data.set_query_contexts(None)


def make_execution_workspace(
    root: pathlib.Path, scenario: str, module_count: int = 80
) -> pathlib.Path:
    """Complement hot loops with imports, frequent calls, and resumable code."""
    pkg = root / PACKAGE_NAME
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "excluded.py").write_text(
        "def helper(value):\n    return abs(value)\n", encoding="utf-8"
    )
    imports, calls = [], []
    for idx in range(module_count):
        name = f"mod_{idx:03d}"
        source = textwrap.dedent("""\
            from .excluded import helper

            def leaf(value):
                if value % 2:
                    return helper(-value)
                return value + 1

            def compute():
                return sum(leaf(value) for value in range(20))
            """)
        if scenario == "resumable":
            source += textwrap.dedent("""\

                async def async_values():
                    for value in range(4):
                        yield leaf(value)

                async def compute_async():
                    total = 0
                    async for value in async_values():
                        total += value
                    return total
                """)
        (pkg / f"{name}.py").write_text(source, encoding="utf-8")
        imports.append(f"from . import {name}")
        calls.append(f"        total += {name}.compute()")
    driver = [
        *imports,
        "import asyncio",
        "",
        "def main(rounds=20, loops=1):",
        "    total = 0",
        "    for _ in range(rounds):",
        *calls,
        "    return total",
        "",
    ]
    if scenario == "resumable":
        driver += ["async def async_main():", "    total = 0"]
        driver += [
            f"    total += await mod_{idx:03d}.compute_async()" for idx in range(module_count)
        ]
        driver += [
            "    return total",
            "",
            "def run_resumable():",
            "    return main() + asyncio.run(async_main())",
            "",
        ]
    (pkg / "workload.py").write_text("\n".join(driver), encoding="utf-8")
    return root
