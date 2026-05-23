"""A plugin for tests to reference."""

from __future__ import annotations

from typing import Any

from coverage import CoveragePlugin
from coverage.plugin_support import Plugins


class Plugin(CoveragePlugin):
    pass


def coverage_init(
    reg: Plugins,
    options: Any,  # pylint: disable=unused-argument
) -> None:
    reg.add_file_tracer(Plugin())
