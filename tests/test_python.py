# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of coverage/python.py"""

from __future__ import annotations

import pathlib
import sys

import pytest

from coverage import env
from coverage.python import get_zip_bytes, source_for_file

from tests.coveragetest import CoverageTest
from tests.helpers import os_sep


@pytest.mark.xdist_group(name="get_zip_bytes_test")
class GetZipBytesTest(CoverageTest):
    """Tests of `get_zip_bytes`."""

    run_in_temp_dir = False

    @pytest.mark.parametrize(
        "encoding",
        ["utf-8", "gb2312", "hebrew", "shift_jis", "cp1252"],
    )
    def test_get_encoded_zip_files(self, encoding: str) -> None:
        # See igor.py, do_zipmods, for the text of these files.
        zip_file = "tests/zipmods.zip"
        sys.path.append(zip_file)  # So we can import the files.
        filename = zip_file + "/encoded_" + encoding + ".py"
        filename = os_sep(filename)
        zip_data = get_zip_bytes(filename)
        assert zip_data is not None
        zip_text = zip_data.decode(encoding)
        assert "All OK" in zip_text
        # Run the code to see that we really got it encoded properly.
        mod = __import__("encoded_" + encoding)
        assert mod.encoding == encoding


def test_source_for_file(tmp_path: pathlib.Path) -> None:
    src = str(tmp_path / "a.py")
    assert source_for_file(src) == src
    assert source_for_file(src + "c") == src
    assert source_for_file(src + "o") == src
    unknown = src + "FOO"
    assert source_for_file(unknown) == unknown


@pytest.mark.skipif(not env.WINDOWS, reason="not windows")
def test_source_for_file_windows(tmp_path: pathlib.Path) -> None:
    a_py = tmp_path / "a.py"
    src = str(a_py)

    # On windows if a pyw exists, it is an acceptable source
    path_windows = tmp_path / "a.pyw"
    path_windows.write_text("", encoding="utf-8")
    assert str(path_windows) == source_for_file(src + "c")

    # If both pyw and py exist, py is preferred
    a_py.write_text("", encoding="utf-8")
    assert source_for_file(src + "c") == src


class RunpyTest(CoverageTest):
    """Tests using runpy."""

    @pytest.mark.parametrize("convert_to", ["str", "Path"])
    def test_runpy_path(self, convert_to: str) -> None:
        # Ensure runpy.run_path(path) works when path is pathlib.Path or str.
        #
        # runpy.run_path(pathlib.Path(...)) causes __file__ to be a Path,
        # which may make source_for_file() stumble (#1819) with:
        #
        #    AttributeError: 'PosixPath' object has no attribute 'endswith'

        self.check_coverage(f"""\
            import runpy
            from pathlib import Path
            pyfile = Path('script.py')
            pyfile.write_text('', encoding='utf-8')
            runpy.run_path({convert_to}(pyfile))
        """)
