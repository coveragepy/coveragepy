# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests about understanding how third-party code is installed."""

from __future__ import annotations

import os
import os.path
import shutil

from pathlib import Path
from typing import cast
from collections.abc import Iterable

import pytest

from coverage import env

from tests import testenv
from tests.coveragetest import CoverageTest, COVERAGE_INSTALL_ARGS
from tests.helpers import change_dir, make_file
from tests.helpers import re_lines, run_command


def run_in_venv(cmd: str) -> str:
    r"""Run `cmd` in the virtualenv at `venv`.

    The first word of the command will be adjusted to run it from the
    venv/bin or venv\Scripts directory.

    Returns the text output of the command.
    """
    words = cmd.split()
    if env.WINDOWS:
        words[0] = rf"venv\Scripts\{words[0]}.exe"
    else:
        words[0] = rf"venv/bin/{words[0]}"
    status, output = run_command(" ".join(words))
    # Print the output so if it fails, we can tell what happened.
    print(output)
    assert status == 0
    return output


@pytest.fixture(scope="session", name="venv_world")
def venv_world_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a virtualenv with a few test packages for VirtualenvTest to use.

    Returns the directory containing the "venv" virtualenv.
    """

    venv_world = tmp_path_factory.mktemp("venv_world")
    with change_dir(venv_world):
        # Create a virtualenv.
        run_command("python -m venv venv")

        # A third-party package that installs a few different packages.
        make_file(
            "third_pkg/third/__init__.py",
            """\
            import fourth
            def third(x):
                return 3 * x
            """,
        )
        # Use plugin2.py as third.plugin
        with open(os.path.join(os.path.dirname(__file__), "plugin2.py"), encoding="utf-8") as f:
            make_file("third_pkg/third/plugin.py", f.read())
        # A render function for plugin2 to use for dynamic file names.
        make_file(
            "third_pkg/third/render.py",
            """\
            def render(filename, linenum):
                return "HTML: {}@{}".format(filename, linenum)
            """,
        )
        # Another package that third can use.
        make_file(
            "third_pkg/fourth/__init__.py",
            """\
            def fourth(x):
                return 4 * x
            """,
        )
        # Some namespace packages.
        make_file(
            "third_pkg/nspkg/fifth/__init__.py",
            """\
            def fifth(x):
                return 5 * x
            """,
        )
        # The setup.py to install everything.
        make_file(
            "third_pkg/setup.py",
            """\
            import setuptools
            setuptools.setup(
                name="third",
                packages=["third", "fourth", "nspkg.fifth"],
            )
            """,
        )

        # Some namespace packages.
        make_file(
            "another_pkg/nspkg/sixth/__init__.py",
            """\
            def sixth(x):
                return 6 * x
            """,
        )
        make_file(
            "another_pkg/setup.py",
            """\
            import setuptools
            setuptools.setup(
                name="another",
                packages=["nspkg.sixth"],
            )
            """,
        )

        # Bug888 code.
        make_file(
            "bug888/app/setup.py",
            """\
            from setuptools import setup
            setup(
                name='testcov',
                packages=['testcov'],
            )
            """,
        )
        # https://packaging.python.org/en/latest/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages
        make_file(
            "bug888/app/testcov/__init__.py",
            """\
            __path__ = __import__('pkgutil').extend_path(__path__, __name__)
            """,
        )
        get_plugins = "entry_points.select(group='plugins')"
        make_file(
            "bug888/app/testcov/main.py",
            f"""\
            import importlib.metadata
            entry_points = importlib.metadata.entry_points()
            for entry_point in {get_plugins}:
                entry_point.load()()
            """,
        )
        make_file(
            "bug888/plugin/setup.py",
            """\
            from setuptools import setup
            setup(
                name='testcov-plugin',
                packages=['testcov'],
                entry_points={'plugins': ['testp = testcov.plugin:testp']},
            )
            """,
        )
        # https://packaging.python.org/en/latest/guides/packaging-namespace-packages/#pkgutil-style-namespace-packages
        make_file(
            "bug888/plugin/testcov/__init__.py",
            """\
            __path__ = __import__('pkgutil').extend_path(__path__, __name__)
            """,
        )
        make_file(
            "bug888/plugin/testcov/plugin.py",
            """\
            def testp():
                print("Plugin here")
            """,
        )

        # Install everything.
        run_in_venv(
            "python -m pip install "
            + "./third_pkg "
            + "-e ./another_pkg "
            + "-e ./bug888/app -e ./bug888/plugin "
            + COVERAGE_INSTALL_ARGS,
        )
        shutil.rmtree("third_pkg")

    return venv_world


@pytest.fixture(
    params=[
        "coverage",
        "python -m coverage",
    ],
    name="coverage_command",
)
def coverage_command_fixture(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture to use multiple forms of "coverage" command."""
    return cast(str, request.param)


@pytest.mark.xdist_group(name="virtualenv_test")
@pytest.mark.skipif(
    bool(os.getenv("COVERAGE_PIP_ARGS")),
    reason="COVERAGE_PIP_ARGS setting means we shouldn't try pip",
)
class VirtualenvTest(CoverageTest):
    """Tests of virtualenv considerations."""

    expected_stdout = "33\n110\n198\n1.5\n"

    @pytest.fixture(autouse=True)
    def in_venv_world_fixture(self, venv_world: Path) -> Iterable[None]:
        """For running tests inside venv_world, and cleaning up made files."""
        with change_dir(venv_world):
            self.make_file(
                "myproduct.py",
                """\
                import colorsys
                import third
                import nspkg.fifth
                import nspkg.sixth
                print(third.third(11))
                print(nspkg.fifth.fifth(22))
                print(nspkg.sixth.sixth(33))
                print(sum(colorsys.rgb_to_hls(1, 0, 0)))
                """,
            )

            self.del_environ("COVERAGE_TESTING")  # To get realistic behavior
            self.set_environ("COVERAGE_DEBUG_FILE", "debug_out.txt")
            self.set_environ("COVERAGE_DEBUG", "trace")

            yield

            for fname in os.listdir("."):
                if fname not in {"venv", "another_pkg", "bug888"}:
                    os.remove(fname)

    def get_trace_output(self) -> str:
        """Get the debug output of coverage.py"""
        with open("debug_out.txt", encoding="utf-8") as f:
            return f.read()

    @pytest.mark.parametrize("install_source_in_venv", [True, False])
    def test_third_party_venv_isnt_measured(
        self,
        coverage_command: str,
        install_source_in_venv: bool,
    ) -> None:
        if install_source_in_venv:
            make_file(
                "setup.py",
                """\
                import setuptools
                setuptools.setup(
                    name="myproduct",
                    py_modules = ["myproduct"],
                )
                """,
            )
            try:
                run_in_venv("python -m pip install .")
            finally:
                shutil.rmtree("build", ignore_errors=True)
                shutil.rmtree("myproduct.egg-info", ignore_errors=True)
            # Ensure that coverage doesn't run the non-installed module.
            os.remove("myproduct.py")
            out = run_in_venv(coverage_command + " run --source=.,myproduct -m myproduct")
        else:
            out = run_in_venv(coverage_command + " run --source=. myproduct.py")
        # In particular, this warning doesn't appear:
        # Already imported a file that will be measured: .../coverage/__main__.py
        assert out == self.expected_stdout

        # Check that our tracing was accurate. Files are mentioned because
        # --source refers to a file.
        debug_out = self.get_trace_output()
        assert re_lines(
            r"^Not tracing .*\bexecfile.py': inside --source, but is third-party",
            debug_out,
        )
        assert re_lines(r"^Tracing .*\bmyproduct.py", debug_out)
        assert re_lines(
            r"^Not tracing .*\bcolorsys.py': (module 'colorsys' |)?falls outside the --source spec",
            debug_out,
        )

        out = run_in_venv(coverage_command + " report")
        assert "myproduct.py" in out
        assert "third" not in out
        assert "coverage" not in out
        assert "colorsys" not in out

    def test_us_in_venv_isnt_measured(self, coverage_command: str) -> None:
        out = run_in_venv(coverage_command + " run --source=third myproduct.py")
        assert out == self.expected_stdout

        # Check that our tracing was accurate. Modules are mentioned because
        # --source refers to a module.
        debug_out = self.get_trace_output()
        assert re_lines(
            r"^Not tracing .*\bexecfile.py': "
            + "module 'coverage.execfile' falls outside the --source spec",
            debug_out,
        )
        assert re_lines(
            r"^Not tracing .*\bmyproduct.py': module 'myproduct' falls outside the --source spec",
            debug_out,
        )
        assert re_lines(
            r"^Not tracing .*\bcolorsys.py': module 'colorsys' falls outside the --source spec",
            debug_out,
        )

        out = run_in_venv(coverage_command + " report")
        assert "myproduct.py" not in out
        assert "third" in out
        assert "coverage" not in out
        assert "colorsys" not in out

    def test_venv_isnt_measured(self, coverage_command: str) -> None:
        out = run_in_venv(coverage_command + " run myproduct.py")
        assert out == self.expected_stdout

        debug_out = self.get_trace_output()
        assert re_lines(r"^Not tracing .*\bexecfile.py': is part of coverage.py", debug_out)
        assert re_lines(r"^Tracing .*\bmyproduct.py", debug_out)
        assert re_lines(r"^Not tracing .*\bcolorsys.py': is in the stdlib", debug_out)

        out = run_in_venv(coverage_command + " report")
        assert "myproduct.py" in out
        assert "third" not in out
        assert "coverage" not in out
        assert "colorsys" not in out

    @pytest.mark.skipif(not testenv.C_TRACER, reason="No plugins with this core.")
    def test_venv_with_dynamic_plugin(self, coverage_command: str) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1150
        # Django coverage plugin was incorrectly getting warnings:
        # "Already imported: ... django/template/blah.py"
        # It happened because coverage imported the plugin, which imported
        # Django, and then the Django files were reported as traceable.
        self.make_file(".coveragerc", "[run]\nplugins=third.plugin\n")
        self.make_file(
            "myrender.py",
            """\
            import third.render
            print(third.render.render("hello.html", 1723))
            """,
        )
        out = run_in_venv(coverage_command + " run --source=. myrender.py")
        # The output should not have this warning:
        # Already imported a file that will be measured: ...third/render.py (already-imported)
        assert out == "HTML: hello.html@1723\n"

    def test_installed_namespace_packages(self, coverage_command: str) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1231
        # When namespace packages were installed, they were considered
        # third-party packages.  Test that isn't still happening.
        out = run_in_venv(coverage_command + " run --source=nspkg myproduct.py")
        # In particular, this warning doesn't appear:
        # Already imported a file that will be measured: .../coverage/__main__.py
        assert out == self.expected_stdout

        # Check that our tracing was accurate. Files are mentioned because
        # --source refers to a file.
        debug_out = self.get_trace_output()
        assert re_lines(
            r"^Not tracing .*\bexecfile.py': "
            + "module 'coverage.execfile' falls outside the --source spec",
            debug_out,
        )
        assert re_lines(
            r"^Not tracing .*\bmyproduct.py': module 'myproduct' falls outside the --source spec",
            debug_out,
        )
        assert re_lines(
            r"^Not tracing .*\bcolorsys.py': module 'colorsys' falls outside the --source spec",
            debug_out,
        )

        out = run_in_venv(coverage_command + " report")

        # Name                                                       Stmts   Miss  Cover
        # ------------------------------------------------------------------------------
        # another_pkg/nspkg/sixth/__init__.py                            2      0   100%
        # venv/lib/python3.9/site-packages/nspkg/fifth/__init__.py       2      0   100%
        # ------------------------------------------------------------------------------
        # TOTAL                                                          4      0   100%

        assert "myproduct.py" not in out
        assert "third" not in out
        assert "coverage" not in out
        assert "colorsys" not in out
        assert "fifth" in out
        assert "sixth" in out

    def test_bug_888(self, coverage_command: str) -> None:
        out = run_in_venv(
            coverage_command + " run --source=bug888/app,bug888/plugin bug888/app/testcov/main.py",
        )
        # When the test fails, the output includes "Already imported a file that will be measured"
        assert out == "Plugin here\n"
