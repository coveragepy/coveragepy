# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""A Hypothesis wrapper so we can turn it off completely in environments it doesn't support."""

from __future__ import annotations

from typing import Any

import pytest

from tests import testenv

# pylint: disable=useless-import-alias
# pylint: disable=unused-import

if testenv.USE_HYPOTHESIS:
    from hypothesis import (
        example as example,
        given as given,
        settings as settings,
    )
    from hypothesis.strategies import (
        integers as integers,
        sets as sets,
    )
else:

    def _skip(*_args: Any, **_kwargs: Any) -> Any:
        """A dummy decorator to skip hypothesis tests."""
        return pytest.mark.skip("Hypothesis isn't supported in this environment")

    example = given = settings = _skip  # type: ignore[misc,assignment]

    def _dummy(*_args: Any, **_kwargs: Any) -> None:
        """Replace Hypothesis tools with nothing."""
        return None

    integers = sets = _dummy  # type: ignore[assignment]
