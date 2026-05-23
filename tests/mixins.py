# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
Test class mixins

Some of these are transitional while working toward pure-pytest style.
"""

from __future__ import annotations

import importlib
import os
import os.path
import sys

from collections.abc import Callable, Iterable
from typing import Any, cast

import pytest

from coverage.misc import SysModuleSaver
from tests.helpers import change_dir, make_file, remove_tree


class PytestBase:
    """A base class to connect to pytest in a test class hierarchy."""

    @pytest.fixture(autouse=True)
    def connect_to_pytest(
        self,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Captures pytest facilities for use by other test helpers."""
        # pylint: disable=attribute-defined-outside-init
        self._pytest_request = request
        self._monkeypatch = monkeypatch
        self.setUp()

    def setUp(self) -> None:
        """Per-test initialization. Override this as you wish."""
        pass

    def addCleanup(self, fn: Callable[..., None], *args: Any) -> None:
        """Like unittest's addCleanup: code to call when the test is done."""
        self._pytest_request.addfinalizer(lambda: fn(*args))

    def set_environ(self, name: str, value: str) -> None:
        """Set an environment variable `name` to be `value`."""
        self._monkeypatch.setenv(name, value)

    def del_environ(self, name: str) -> None:
        """Delete an environment variable, unless we set it."""
        self._monkeypatch.delenv(name, raising=False)


class TempDirMixin:
    """Provides temp dir and data file helpers for tests."""

    # Our own setting: most of these tests run in their own temp directory.
    # Set this to False in your subclass if you don't want a temp directory
    # created.
    run_in_temp_dir = True

    @pytest.fixture(autouse=True)
    def _temp_dir(self, tmp_path_factory: pytest.TempPathFactory) -> Iterable[None]:
        """Create a temp dir for the tests, if they want it."""
        if self.run_in_temp_dir:
            tmpdir = tmp_path_factory.mktemp("t")
            self.temp_dir = str(tmpdir)
            with change_dir(self.temp_dir):
                # Modules should be importable from this temp directory.  We don't
                # use '' because we make lots of different temp directories and
                # nose's caching importer can get confused.  The full path prevents
                # problems.
                sys.path.insert(0, os.getcwd())
                yield
        else:
            yield

    def make_file(
        self,
        filename: str,
        text: str = "",
        bytes: bytes = b"",
        newline: str | None = None,
    ) -> str:
        """Make a file. See `tests.helpers.make_file`"""
        # pylint: disable=redefined-builtin     # bytes
        assert self.run_in_temp_dir, "Only use make_file when running in a temp dir"
        return make_file(filename, text, bytes, newline)


class RestoreModulesMixin:
    """Auto-restore the imported modules at the end of each test."""

    @pytest.fixture(autouse=True)
    def _module_saving(self) -> Iterable[None]:
        """Remove modules we imported during the test."""
        self._sys_module_saver = SysModuleSaver()
        try:
            yield
        finally:
            self._sys_module_saver.restore()

    def clean_local_file_imports(self) -> None:
        """Clean up the results of calls to `import_local_file`.

        Use this if you need to `import_local_file` the same file twice in
        one test.

        """
        # So that we can re-import files, clean them out first.
        self._sys_module_saver.restore()

        # Also have to clean out the .pyc files, since the time stamp
        # resolution is only one second, a changed file might not be
        # picked up.
        remove_tree("__pycache__")
        importlib.invalidate_caches()


class StdStreamCapturingMixin:
    """
    Adapter from the pytest capsys fixture to more convenient methods.

    This doesn't also output to the real stdout, so we probably want to move
    to "real" capsys when we can use fixtures in test methods.

    Once you've used one of these methods, the capturing is reset, so another
    invocation will only return the delta.

    """

    @pytest.fixture(autouse=True)
    def _capcapsys(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Grab the fixture so our methods can use it."""
        self.capsys = capsys

    def stdouterr(self) -> tuple[str, str]:
        """Returns (out, err), two strings for stdout and stderr."""
        return cast(tuple[str, str], self.capsys.readouterr())

    def stdout(self) -> str:
        """Returns a string, the captured stdout."""
        return self.capsys.readouterr().out

    def stderr(self) -> str:
        """Returns a string, the captured stderr."""
        return self.capsys.readouterr().err
