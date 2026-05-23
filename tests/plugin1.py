# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""A file tracer plugin for test_plugins.py to import."""

from __future__ import annotations

import os.path

from types import FrameType
from typing import Any

from coverage import CoveragePlugin, FileReporter, FileTracer
from coverage.plugin_support import Plugins
from coverage.types import TLineNo


class Plugin(CoveragePlugin):
    """A file tracer plugin to import, so that it isn't in the test's current directory."""

    def file_tracer(self, filename: str) -> FileTracer | None:
        """Trace only files named xyz.py"""
        if "xyz.py" in filename:
            return MyFileTracer(filename)
        return None

    def file_reporter(self, filename: str) -> FileReporter | str:
        return MyFileReporter(filename)


class MyFileTracer(FileTracer):
    """A FileTracer emulating a simple static plugin."""

    def __init__(self, filename: str) -> None:
        """Claim that */*xyz.py was actually sourced from /src/*ABC.zz"""
        self._filename = filename
        self._source_filename = os.path.join(
            "/src",
            os.path.basename(filename.replace("xyz.py", "ABC.zz")),
        )

    def source_filename(self) -> str:
        return self._source_filename

    def line_number_range(self, frame: FrameType) -> tuple[TLineNo, TLineNo]:
        """Map the line number X to X05,X06,X07."""
        lineno = frame.f_lineno
        return lineno * 100 + 5, lineno * 100 + 7


class MyFileReporter(FileReporter):
    """Dead-simple FileReporter."""

    def lines(self) -> set[TLineNo]:
        return {105, 106, 107, 205, 206, 207}


def coverage_init(
    reg: Plugins,
    options: Any,  # pylint: disable=unused-argument
) -> None:
    """Called by coverage to initialize the plugins here."""
    reg.add_file_tracer(Plugin())
