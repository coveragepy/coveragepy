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

try:
    import third.render  # pylint: disable=unused-import
except ImportError:
    # This plugin is used in a few tests. One of them has the third.render
    # module, but most don't. We need to import it but not use it, so just
    # try importing it and it's OK if the module doesn't exist.
    pass


class Plugin(CoveragePlugin):
    """A file tracer plugin for testing."""

    def file_tracer(self, filename: str) -> FileTracer | None:
        if "render.py" in filename:
            return RenderFileTracer()
        return None

    def file_reporter(self, filename: str) -> FileReporter:
        return MyFileReporter(filename)


class RenderFileTracer(FileTracer):
    """A FileTracer using information from the caller."""

    def has_dynamic_source_filename(self) -> bool:
        return True

    def dynamic_source_filename(
        self,
        filename: str,
        frame: FrameType,
    ) -> str | None:
        if frame.f_code.co_name != "render":
            return None
        source_filename: str = os.path.abspath(frame.f_locals["filename"])
        return source_filename

    def line_number_range(self, frame: FrameType) -> tuple[TLineNo, TLineNo]:
        lineno = frame.f_locals["linenum"]
        return lineno, lineno + 1


class MyFileReporter(FileReporter):
    """A goofy file reporter."""

    def lines(self) -> set[TLineNo]:
        # Goofy test arrangement: claim that the file has as many lines as the
        # number in its name.
        num = os.path.basename(self.filename).split(".")[0].split("_")[1]
        return set(range(1, int(num) + 1))


def coverage_init(
    reg: Plugins,
    options: Any,  # pylint: disable=unused-argument
) -> None:
    """Called by coverage to initialize the plugins here."""
    reg.add_file_tracer(Plugin())
