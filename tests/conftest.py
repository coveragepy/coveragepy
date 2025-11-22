# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
Pytest auto configuration.

This module is run automatically by pytest, to define and enable fixtures.
"""

from __future__ import annotations

import os
import sys
import warnings

from collections.abc import Iterable

import pytest

from coverage.files import set_relative_directory

from tests import testenv


# Pytest will rewrite assertions in test modules, but not elsewhere.
# This tells pytest to also rewrite assertions in these files:
pytest.register_assert_rewrite("tests.coveragetest")
pytest.register_assert_rewrite("tests.helpers")

# Pytest can take additional options:
# $set_env.py: PYTEST_ADDOPTS - Extra arguments to pytest.

pytest_plugins = [
    "tests.select_plugin",
]


@pytest.fixture(autouse=True)
def set_warnings() -> None:
    """Configure warnings to show while running tests."""
    warnings.simplefilter("default")
    warnings.simplefilter("once", DeprecationWarning)

    # Warnings to suppress:
    # How come these warnings are successfully suppressed here, but not in pyproject.toml??

    # Note: when writing the regex for the message, it's matched with re.match,
    # so it has to match the beginning of the message.  Add ".*" to make it
    # match something in the middle of the message.

    # Don't warn about unclosed SQLite connections.
    # We don't close ":memory:" databases because we don't have a way to connect
    # to them more than once if we close them.  In real coverage.py uses, there
    # are only a couple of them, but our test suite makes many and we get warned
    # about them all.
    # Python3.13 added this warning, but the behavior has been the same all along,
    # without any reported problems, so just quiet the warning.
    # https://github.com/python/cpython/issues/105539
    warnings.filterwarnings("ignore", r"unclosed database", category=ResourceWarning)

    # We have a test that has a return in a finally: test_bug_1891.
    warnings.filterwarnings("ignore", "'return' in a 'finally' block", category=SyntaxWarning)

    # For when our own tests can't use sysmon though it was requested.
    warnings.filterwarnings("ignore", r".*no-sysmon")
    if testenv.REQUESTED_CORE != "ctrace":
        warnings.filterwarnings("ignore", r".*no-ctracer")


@pytest.fixture(autouse=True)
def reset_sys_path() -> Iterable[None]:
    """Clean up sys.path changes around every test."""
    sys_path = list(sys.path)
    yield
    sys.path[:] = sys_path


@pytest.fixture(autouse=True)
def reset_environment() -> Iterable[None]:
    """Make sure a test setting an envvar doesn't leak into another test."""
    old_environ = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(old_environ)


@pytest.fixture(autouse=True)
def reset_filesdotpy_globals() -> None:
    """coverage/files.py has some unfortunate globals. Reset them every test."""
    set_relative_directory()


@pytest.fixture(autouse=True)
def force_local_pyc_files() -> None:
    """Ensure that .pyc files are written next to source files."""
    # For some tests, we need .pyc files written in the current directory,
    # so override any local setting.
    sys.pycache_prefix = None
