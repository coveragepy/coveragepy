# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of code in tests/mixins.py"""

from __future__ import annotations

import pytest

from coverage.misc import import_local_file

from tests.mixins import TempDirMixin, RestoreModulesMixin


class TempDirMixinTest(TempDirMixin):
    """Test the methods in TempDirMixin."""

    def file_text(self, fname: str) -> str:
        """Return the text read from a file."""
        with open(fname, "rb") as f:
            return f.read().decode("ascii")

    def test_make_file(self) -> None:
        # A simple file.
        self.make_file("fooey.boo", "Hello there")
        assert self.file_text("fooey.boo") == "Hello there"
        # A file in a sub-directory
        self.make_file("sub/another.txt", "Another")
        assert self.file_text("sub/another.txt") == "Another"
        # A second file in that sub-directory
        self.make_file("sub/second.txt", "Second")
        assert self.file_text("sub/second.txt") == "Second"
        # A deeper directory
        self.make_file("sub/deeper/evenmore/third.txt")
        assert self.file_text("sub/deeper/evenmore/third.txt") == ""
        # Dedenting
        self.make_file(
            "dedented.txt",
            """\
            Hello
            Bye
            """,
        )
        assert self.file_text("dedented.txt") == "Hello\nBye\n"

    def test_make_file_newline(self) -> None:
        self.make_file("unix.txt", "Hello\n")
        assert self.file_text("unix.txt") == "Hello\n"
        self.make_file("dos.txt", "Hello\n", newline="\r\n")
        assert self.file_text("dos.txt") == "Hello\r\n"
        self.make_file("mac.txt", "Hello\n", newline="\r")
        assert self.file_text("mac.txt") == "Hello\r"

    def test_make_file_non_ascii(self) -> None:
        self.make_file("unicode.txt", "tablo: «ταБℓσ»")
        with open("unicode.txt", "rb") as f:
            text = f.read()
        assert text == b"tablo: \xc2\xab\xcf\x84\xce\xb1\xd0\x91\xe2\x84\x93\xcf\x83\xc2\xbb"

    def test_make_bytes_file(self) -> None:
        self.make_file("binary.dat", bytes=b"\x99\x33\x66hello\0")
        with open("binary.dat", "rb") as f:
            data = f.read()
        assert data == b"\x99\x33\x66hello\0"


class RestoreModulessMixinTest(TempDirMixin, RestoreModulesMixin):
    """Tests of SysPathModulesMixin."""

    @pytest.mark.parametrize("val", [17, 42])
    def test_module_independence(self, val: int) -> None:
        self.make_file("xyzzy.py", f"A = {val}")
        import xyzzy  # pylint: disable=import-error

        assert xyzzy.A == val

    def test_cleanup_and_reimport(self) -> None:
        self.make_file("xyzzy.py", "A = 17")
        xyzzy = import_local_file("xyzzy")
        assert xyzzy.A == 17

        self.clean_local_file_imports()

        self.make_file("xyzzy.py", "A = 42")
        xyzzy = import_local_file("xyzzy")
        assert xyzzy.A == 42
