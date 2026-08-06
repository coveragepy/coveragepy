# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Exceptions coverage.py can raise."""

from __future__ import annotations

from typing import Any


class CoverageException(Exception):
    """The base class of all exceptions raised by Coverage.py."""

    def __init__(
        self,
        *args: Any,
        slug: str | None = None,
    ) -> None:
        """Create an exception.

        Args:
            slug: A short string identifying the exception, will be used for
                linking to documentation.
        """

        super().__init__(*args)
        self.slug = slug


class ConfigError(CoverageException):
    """A problem with a config file, or a value in one."""


class DataError(CoverageException):
    """An error in using a data file."""


class NoDataError(CoverageException):
    """We didn't have data to work with."""


class NoSource(CoverageException):
    """We couldn't find the source for a module."""


class NoCode(NoSource):
    """We couldn't find any code at all."""


class NotPython(CoverageException):
    """A source file turned out not to be parsable Python."""


class PluginError(CoverageException):
    """A plugin misbehaved."""


class _ExceptionDuringRun(CoverageException):
    """An exception happened while running customer code.

    Construct it with three arguments, the values from `sys.exc_info`.

    """


class CoverageWarning(Warning):
    """A warning from Coverage.py."""
