# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for helpers in report.py"""

from __future__ import annotations

from typing import IO
from collections.abc import Iterable

import pytest

from coverage.exceptions import CoverageException
from coverage.report_core import render_report
from coverage.types import TMorf, TMorfs

from tests.coveragetest import CoverageTest


class FakeReporter:
    """A fake implementation of a one-file reporter."""

    report_type = "fake report file"

    def __init__(self, output: str = "", error: type[Exception] | None = None) -> None:
        self.output = output
        self.error = error
        self.morfs: Iterable[TMorf] | None = None

    def report(self, morfs: TMorfs, outfile: IO[str]) -> float:
        """Fake."""
        self.morfs = morfs
        outfile.write(self.output)
        if self.error:
            raise self.error("You asked for it!")
        return 17.25


class RenderReportTest(CoverageTest):
    """Tests of render_report."""

    def test_stdout(self) -> None:
        fake = FakeReporter(output="Hello!\n")
        msgs: list[str] = []
        res = render_report("-", fake, [pytest, "coverage"], msgs.append)
        assert res == 17.25
        assert fake.morfs == [pytest, "coverage"]
        assert self.stdout() == "Hello!\n"
        assert not msgs

    def test_file(self) -> None:
        fake = FakeReporter(output="Gréètings!\n")
        msgs: list[str] = []
        res = render_report("output.txt", fake, [], msgs.append)
        assert res == 17.25
        assert self.stdout() == ""
        with open("output.txt", "rb") as f:
            assert f.read().rstrip() == b"Gr\xc3\xa9\xc3\xa8tings!"
        assert msgs == ["Wrote fake report file to output.txt"]

    @pytest.mark.parametrize("error", [CoverageException, ZeroDivisionError])
    def test_exception(self, error: type[Exception]) -> None:
        fake = FakeReporter(error=error)
        msgs: list[str] = []
        with pytest.raises(error, match="You asked for it!"):
            render_report("output.txt", fake, [], msgs.append)
        assert self.stdout() == ""
        self.assert_doesnt_exist("output.txt")
        assert not msgs
