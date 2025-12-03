# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of miscellaneous stuff."""

from __future__ import annotations

import sys

from typing import cast

import pytest

import coverage
from coverage import env

from tests.coveragetest import CoverageTest


class SetupPyTest(CoverageTest):
    """Tests of setup.py"""

    run_in_temp_dir = False

    def setUp(self) -> None:
        super().setUp()
        # Force the most restrictive interpretation.
        self.set_environ("LC_ALL", "C")

    def test_metadata(self) -> None:
        status, output = self.run_command_status(
            "python setup.py --description --version --url --author",
        )
        assert status == 0
        out = output.splitlines()
        assert "measurement" in out[0]
        assert coverage.__version__ == out[1]
        assert "github.com/coveragepy/coveragepy" in out[2]
        assert "Ned Batchelder" in out[3]

    @pytest.mark.skipif(
        env.PYVERSION[3:5] == ("alpha", 0),
        reason="don't expect classifiers until labelled builds",
    )
    def test_more_metadata(self) -> None:
        # Let's be sure we pick up our own setup.py
        # CoverageTest restores the original sys.path for us.
        sys.path.insert(0, "")
        from setup import setup_args

        classifiers = cast(list[str], setup_args["classifiers"])
        assert len(classifiers) > 7
        assert classifiers[0].startswith("Development Status ::")
        assert "Programming Language :: Python :: %d" % sys.version_info[:1] in classifiers
        assert "Programming Language :: Python :: %d.%d" % sys.version_info[:2] in classifiers

        long_description = cast(str, setup_args["long_description"]).splitlines()
        assert len(long_description) > 7
        assert long_description[0].strip() != ""
        assert long_description[-1].strip() != ""
