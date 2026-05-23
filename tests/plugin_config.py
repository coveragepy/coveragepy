# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""A configuring plugin for test_plugins.py to import."""

from __future__ import annotations

from typing import Any, cast

import coverage
from coverage.plugin_support import Plugins
from coverage.types import TConfigurable


class Plugin(coverage.CoveragePlugin):
    """A configuring plugin for testing."""

    def configure(self, config: TConfigurable) -> None:
        """Configure all the things!"""
        opt_name = "report:exclude_lines"
        exclude_lines = cast(list[str], config.get_option(opt_name))
        exclude_lines.append(r"pragma: custom")
        exclude_lines.append(r"pragma: or whatever")
        config.set_option(opt_name, exclude_lines)


def coverage_init(
    reg: Plugins,
    options: Any,  # pylint: disable=unused-argument
) -> None:
    """Called by coverage to initialize the plugins here."""
    reg.add_configurer(Plugin())
