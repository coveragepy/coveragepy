# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for FileReporters"""

from __future__ import annotations

import sys

from coverage.plugin import FileReporter
from coverage.python import PythonFileReporter

from tests.coveragetest import CoverageTest, UsingModulesMixin
from tests.helpers import os_sep

# pylint: disable=import-error
# Unable to import 'aa' (No module named aa)


class FileReporterTest(UsingModulesMixin, CoverageTest):
    """Tests for FileReporter classes."""

    run_in_temp_dir = False

    def test_filenames(self) -> None:
        acu = PythonFileReporter("aa/afile.py")
        bcu = PythonFileReporter("aa/bb/bfile.py")
        ccu = PythonFileReporter("aa/bb/cc/cfile.py")
        assert acu.relative_filename() == "aa/afile.py"
        assert bcu.relative_filename() == "aa/bb/bfile.py"
        assert ccu.relative_filename() == "aa/bb/cc/cfile.py"
        assert acu.source() == "# afile.py\n"
        assert bcu.source() == "# bfile.py\n"
        assert ccu.source() == "# cfile.py\n"

    def test_odd_filenames(self) -> None:
        acu = PythonFileReporter("aa/afile.odd.py")
        bcu = PythonFileReporter("aa/bb/bfile.odd.py")
        b2cu = PythonFileReporter("aa/bb.odd/bfile.py")
        assert acu.relative_filename() == "aa/afile.odd.py"
        assert bcu.relative_filename() == "aa/bb/bfile.odd.py"
        assert b2cu.relative_filename() == "aa/bb.odd/bfile.py"
        assert acu.source() == "# afile.odd.py\n"
        assert bcu.source() == "# bfile.odd.py\n"
        assert b2cu.source() == "# bfile.py\n"

    def test_modules(self) -> None:
        import aa
        import aa.bb
        import aa.bb.cc

        acu = PythonFileReporter(aa)
        bcu = PythonFileReporter(aa.bb)
        ccu = PythonFileReporter(aa.bb.cc)
        assert acu.relative_filename() == os_sep("aa/__init__.py")
        assert bcu.relative_filename() == os_sep("aa/bb/__init__.py")
        assert ccu.relative_filename() == os_sep("aa/bb/cc/__init__.py")
        assert acu.source() == "# aa\n"
        assert bcu.source() == "# bb\n"
        assert ccu.source() == ""  # yes, empty

    def test_module_files(self) -> None:
        import aa.afile
        import aa.bb.bfile
        import aa.bb.cc.cfile

        acu = PythonFileReporter(aa.afile)
        bcu = PythonFileReporter(aa.bb.bfile)
        ccu = PythonFileReporter(aa.bb.cc.cfile)
        assert acu.relative_filename() == os_sep("aa/afile.py")
        assert bcu.relative_filename() == os_sep("aa/bb/bfile.py")
        assert ccu.relative_filename() == os_sep("aa/bb/cc/cfile.py")
        assert acu.source() == "# afile.py\n"
        assert bcu.source() == "# bfile.py\n"
        assert ccu.source() == "# cfile.py\n"

    def test_comparison(self) -> None:
        acu = FileReporter("aa/afile.py")
        acu2 = FileReporter("aa/afile.py")
        zcu = FileReporter("aa/zfile.py")
        bcu = FileReporter("aa/bb/bfile.py")
        assert acu == acu2 and acu <= acu2 and acu >= acu2  # pylint: disable=chained-comparison
        assert acu < zcu and acu <= zcu and acu != zcu
        assert zcu > acu and zcu >= acu and zcu != acu
        assert acu < bcu and acu <= bcu and acu != bcu
        assert bcu > acu and bcu >= acu and bcu != acu

    def test_zipfile(self) -> None:
        sys.path.append("tests/zip1.zip")

        # Test that we can get files out of zipfiles, and read their source files.
        # The zip1 module is installed by an action in igor.py.
        import zip1
        import zip1.zip1

        # Verify that we really imported from an zipfile.  If we did, then the
        # __file__ won't be an actual file, because one of the "directories"
        # in the path is actually the zip file.
        self.assert_doesnt_exist(zip1.__file__)

        z1 = PythonFileReporter(zip1)
        z1z1 = PythonFileReporter(zip1.zip1)
        assert z1.source() == ""
        assert "# My zip file!" in z1z1.source().splitlines()
