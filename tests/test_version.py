# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of version.py."""

from __future__ import annotations

import coverage
from coverage.version import _make_version

from tests.coveragetest import CoverageTest


class VersionTest(CoverageTest):
    """Tests of version.py"""

    run_in_temp_dir = False

    def test_version_info(self) -> None:
        # Make sure we didn't screw up the version_info tuple.
        assert isinstance(coverage.version_info, tuple)
        assert [type(d) for d in coverage.version_info] == [int, int, int, str, int]
        assert coverage.version_info[3] in {"alpha", "beta", "candidate", "final"}

    def test_make_version(self) -> None:
        assert _make_version(4, 0, 0, "alpha") == "4.0.0a0"
        assert _make_version(4, 0, 0, "alpha", 1) == "4.0.0a1"
        assert _make_version(4, 0, 0, "final") == "4.0.0"
        assert _make_version(4, 1, 0) == "4.1.0"
        assert _make_version(4, 1, 2, "beta", 3) == "4.1.2b3"
        assert _make_version(4, 1, 2) == "4.1.2"
        assert _make_version(5, 10, 2, "candidate", 7) == "5.10.2rc7"
        assert _make_version(5, 10, 2, "candidate", 7, 3) == "5.10.2rc7.dev3"
