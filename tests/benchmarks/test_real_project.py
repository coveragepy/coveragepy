# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""An opt-in test-and-report workflow over a pinned real Python project."""

from __future__ import annotations

import compileall
import json
import os
import pathlib
import shutil
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

import pytest

from coverage import CoverageData
from tests import testenv
from tests.benchmarks.helpers import Benchmark, REPO_ROOT, run_subprocess, subprocess_env
from tests.benchmarks.real_project import (
    EXPECTED_TESTS,
    PREPARED_ROOT,
    prepared_python,
    verify_prepared,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.slow, pytest.mark.real_project]
PROCESS_RUNNER = pathlib.Path(__file__).with_name("process_runner.py")


@dataclass
class RealProject:
    """Per-test output paths and an isolated, verified project copy."""

    root: pathlib.Path
    python: pathlib.Path
    metadata: dict[str, Any]

    def env(self) -> dict[str, str]:
        """Use the benchmarked coverage checkout and pinned Jinja2 source."""
        env = subprocess_env()
        env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT), str(self.root / "src")])
        return env

    def configure(self, core: str = "ctrace", branch: bool = True) -> None:
        """Keep output and source selection independent of user configuration."""
        config = (
            f"[run]\ncore = {core}\nbranch = {branch}\nsource = {self.root / 'src' / 'jinja2'}\n"
            f"data_file = {self.root / '.coverage'}\n"
            f"[html]\ndirectory = {self.root / 'htmlcov'}\n"
            f"[json]\noutput = {self.root / 'coverage.json'}\n"
        )
        (self.root / "benchmark.coveragerc").write_text(config, encoding="utf-8")

    def clean_outputs(self, *, data: bool = True) -> None:
        """Preserve the uniformly precompiled input; clear only benchmark output."""
        shutil.rmtree(self.root / "htmlcov", ignore_errors=True)
        names = ["coverage.json", "result.json", "tests.xml"]
        if data:
            names.append(".coverage")
        for name in names:
            (self.root / name).unlink(missing_ok=True)

    def command(self, mode: str, format_name: str = "report", rss: bool = False) -> list[str]:
        """Keep command construction out of the timed region."""
        command = [
            str(self.python),
            str(PROCESS_RUNNER),
            mode,
            "--rcfile",
            str(self.root / "benchmark.coveragerc"),
            "--result",
            str(self.root / "result.json"),
            "--junit",
            str(self.root / "tests.xml"),
            "--format",
            format_name,
        ]
        if rss:
            command.append("--rss")
        return command

    def validate_tests(self, core: str | None, branch: bool = True) -> list[tuple[str, str]]:
        """Fail on missing tests, unexpected skips, or silently missing coverage."""
        tree = ET.parse(self.root / "tests.xml")
        cases = list(tree.iter("testcase"))
        assert len(cases) == EXPECTED_TESTS
        assert (
            not list(tree.iter("failure"))
            and not list(tree.iter("error"))
            and not list(tree.iter("skipped"))
        )
        result = json.loads((self.root / "result.json").read_text(encoding="utf-8"))
        assert result["exit_status"] == 0
        if core:
            assert result["actual_cores"] == [testenv.TRACER_CLASSES[core]]
            self.validate_data(branch)
        else:
            assert result["actual_cores"] == []
            assert not (self.root / ".coverage").exists()
        return sorted((case.get("classname", ""), case.get("name", "")) for case in cases)

    def validate_data(self, branch: bool) -> None:
        """Ensure the project, not just pytest startup, was actually measured."""
        data = CoverageData(basename=str(self.root / ".coverage"))
        data.read()
        assert data.has_arcs() == branch
        files = data.measured_files()
        assert len(files) >= 20
        assert all("/jinja2/" in f.replace("\\", "/") for f in files)
        assert sum(len(data.lines(f) or []) for f in files) > 1000
        data.close()


@pytest.fixture(scope="session", name="prepared_real")
def prepared_real_project(request: pytest.FixtureRequest) -> dict[str, Any]:
    """Ordinary benchmarks never prepare or download external inputs."""
    if not request.config.getoption("--bench-real"):
        pytest.skip("Use make bench-prepare, then make bench-real")
    if sys.version_info[:2] != (3, 14):
        pytest.skip("The pinned real-project environment is validated on Python 3.14")
    return verify_prepared()


@pytest.fixture(name="real_project")
def real_project_copy(prepared_real: dict[str, Any], tmp_path: pathlib.Path) -> RealProject:
    """Copy verified input and warm bytecode equally for all process samples."""
    root = tmp_path / "jinja2"
    shutil.copytree(PREPARED_ROOT / "jinja2-3.1.6", root)
    compileall.compile_dir(root / "src", quiet=2)
    compileall.compile_dir(root / "tests", quiet=2)
    metadata = {
        key: prepared_real[key]
        for key in [
            "project",
            "version",
            "project_revision",
            "archive_sha256",
            "requirements_sha256",
            "packages",
        ]
    }
    project = RealProject(root, prepared_python(), metadata)
    project.configure()
    return project


@pytest.fixture(name="reference_tests")
def reference_test_identities(real_project: RealProject) -> list[tuple[str, str]]:
    """Establish identities outside timing, not just an expected count."""
    run_subprocess(real_project.command("pytest"), real_project.root, real_project.env())
    return real_project.validate_tests(None)


@pytest.mark.benchmark(group="real-tests")
@pytest.mark.parametrize(
    "core,branch",
    [(None, False), *[(c, b) for c in ["pytrace", "ctrace", "sysmon"] for b in [False, True]]],
    ids=[
        "baseline",
        *[f"{c}-{kind}" for c in ["pytrace", "ctrace", "sysmon"] for kind in ["lines", "arcs"]],
    ],
)
def test_jinja_suite(
    bench: Benchmark,
    real_project: RealProject,
    reference_tests: list[tuple[str, str]],
    core: str | None,
    branch: bool,
) -> None:
    project = real_project
    project.configure(core or "ctrace", branch)
    command = project.command("run" if core else "pytest")
    env = project.env()
    bench.extra_info.update(project.metadata, core=core, branch=branch, tests=EXPECTED_TESTS)

    def run() -> None:
        run_subprocess(command, project.root, env)

    def validate() -> None:
        assert project.validate_tests(core, branch) == reference_tests

    bench.pedantic(run, setup=project.clean_outputs, teardown=validate)


@pytest.mark.benchmark(group="real-report")
@pytest.mark.parametrize("format_name", ["report", "html", "json"])
def test_jinja_report(
    bench: Benchmark,
    real_project: RealProject,
    reference_tests: list[tuple[str, str]],
    format_name: str,
) -> None:
    from tests.benchmarks.memory import memory_samples

    project = real_project
    project.clean_outputs()
    run_subprocess(project.command("run"), project.root, project.env())
    assert project.validate_tests("ctrace") == reference_tests
    command = project.command("report", format_name)
    env = project.env()
    bench.extra_info.update(project.metadata, report_format=format_name)

    def setup() -> None:
        project.clean_outputs(data=False)

    def run() -> str:
        return run_subprocess(command, project.root, env)

    def validate() -> None:
        result = json.loads((project.root / "result.json").read_text(encoding="utf-8"))
        assert result["exit_status"] == 0
        if format_name == "html":
            assert len(list((project.root / "htmlcov").glob("*_py.html"))) >= 20
        elif format_name == "json":
            report = json.loads((project.root / "coverage.json").read_text(encoding="utf-8"))
            assert report["totals"]["covered_lines"] > 1000

    output = bench.pedantic(run, setup=setup, teardown=validate)
    if format_name == "report":
        assert "TOTAL" in output
    if not bench.extra_info["smoke"]:
        bench.extra_info["peak_rss_bytes"] = memory_samples(
            project.command("report", format_name, rss=True),
            project.root,
            env,
            project.root / "result.json",
            setup,
            validate,
        )
