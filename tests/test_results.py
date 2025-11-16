# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.py's results analysis."""

from __future__ import annotations

import math

from typing import cast
from collections.abc import Iterable

import pytest

from coverage.exceptions import ConfigError
from coverage.results import Numbers, display_covered, format_lines, should_fail_under
from coverage.types import TLineNo

from tests.coveragetest import CoverageTest


class NumbersTest(CoverageTest):
    """Tests for coverage.py's numeric measurement summaries."""

    run_in_temp_dir = False

    def test_basic(self) -> None:
        n1 = Numbers(n_files=1, n_statements=200, n_missing=20)
        assert n1.n_statements == 200
        assert n1.n_executed == 180
        assert n1.n_missing == 20
        assert n1.pc_covered == 90

    def test_addition(self) -> None:
        n1 = Numbers(n_files=1, n_statements=200, n_missing=20)
        n2 = Numbers(n_files=1, n_statements=10, n_missing=8)
        n3 = n1 + n2
        assert n3.n_files == 2
        assert n3.n_statements == 210
        assert n3.n_executed == 182
        assert n3.n_missing == 28
        assert math.isclose(n3.pc_covered, 86.666666666)

    def test_sum(self) -> None:
        n1 = Numbers(n_files=1, n_statements=200, n_missing=20)
        n2 = Numbers(n_files=1, n_statements=10, n_missing=8)
        n3 = cast(Numbers, sum([n1, n2]))
        assert n3.n_files == 2
        assert n3.n_statements == 210
        assert n3.n_executed == 182
        assert n3.n_missing == 28
        assert math.isclose(n3.pc_covered, 86.666666666)

    @pytest.mark.parametrize(
        "kwargs, res",
        [
            (dict(n_files=1, n_statements=1000, n_missing=0), "100"),
            (dict(n_files=1, n_statements=1000, n_missing=1), "99"),
            (dict(n_files=1, n_statements=1000, n_missing=999), "1"),
            (dict(n_files=1, n_statements=1000, n_missing=1000), "0"),
            (dict(precision=1, n_files=1, n_statements=10000, n_missing=0), "100.0"),
            (dict(precision=1, n_files=1, n_statements=10000, n_missing=1), "99.9"),
            (dict(precision=1, n_files=1, n_statements=10000, n_missing=9999), "0.1"),
            (dict(precision=1, n_files=1, n_statements=10000, n_missing=10000), "0.0"),
        ],
    )
    def test_pc_covered_str(self, kwargs: dict[str, int], res: str) -> None:
        assert Numbers(**kwargs).pc_covered_str == res

    @pytest.mark.parametrize(
        "prec, pc, res",
        [
            (0, 47.87, "48"),
            (1, 47.87, "47.9"),
            (0, 99.995, "99"),
            (2, 99.99995, "99.99"),
        ],
    )
    def test_display_covered(self, prec: int, pc: float, res: str) -> None:
        assert display_covered(pc, prec) == res

    def test_covered_ratio(self) -> None:
        n = Numbers(n_files=1, n_statements=200, n_missing=47)
        assert n.ratio_covered == (153, 200)

        n = Numbers(
            n_files=1,
            n_statements=200,
            n_missing=47,
            n_branches=10,
            n_missing_branches=3,
            n_partial_branches=1000,
        )
        assert n.ratio_statements == (153, 200)
        assert n.ratio_branches == (7, 10)
        assert n.ratio_covered == (160, 210)


@pytest.mark.parametrize(
    "total, fail_under, precision, result",
    [
        # fail_under==0 means anything is fine!
        (0, 0, 0, False),
        (0.001, 0, 0, False),
        # very small fail_under is possible to fail.
        (0.001, 0.01, 0, True),
        # Rounding should work properly.
        (42.1, 42, 0, False),
        (42.1, 43, 0, True),
        (42.857, 42, 0, False),
        (42.857, 43, 0, False),
        (42.857, 44, 0, True),
        (42.857, 42.856, 3, False),
        (42.857, 42.858, 3, True),
        # If you don't specify precision, your fail-under is rounded.
        (42.857, 42.856, 0, False),
        # Values near 100 should only be treated as 100 if they are 100.
        (99.8, 100, 0, True),
        (100.0, 100, 0, False),
        (99.8, 99.7, 1, False),
        (99.88, 99.90, 2, True),
        (99.999, 100, 1, True),
        (99.999, 100, 2, True),
        (99.999, 100, 3, True),
    ],
)
def test_should_fail_under(total: float, fail_under: float, precision: int, result: bool) -> None:
    assert should_fail_under(float(total), float(fail_under), precision) == result


def test_should_fail_under_invalid_value() -> None:
    with pytest.raises(ConfigError, match=r"fail_under=101"):
        should_fail_under(100.0, 101, 0)


@pytest.mark.parametrize(
    "statements, lines, result",
    [
        ({1, 2, 3, 4, 5, 10, 11, 12, 13, 14}, {1, 2, 5, 10, 11, 13, 14}, "1-2, 5-11, 13-14"),
        (
            [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 98, 99],
            [1, 2, 5, 10, 11, 13, 14, 99],
            "1-2, 5-11, 13-14, 99",
        ),
        (
            [1, 2, 3, 4, 98, 99, 100, 101, 102, 103, 104],
            [1, 2, 99, 102, 103, 104],
            "1-2, 99, 102-104",
        ),
        ([17], [17], "17"),
        ([90, 91, 92, 93, 94, 95], [90, 91, 92, 93, 94, 95], "90-95"),
        ([1, 2, 3, 4, 5], [], ""),
        ([1, 2, 3, 4, 5], [4], "4"),
    ],
)
def test_format_lines(
    statements: Iterable[TLineNo],
    lines: Iterable[TLineNo],
    result: str,
) -> None:
    assert format_lines(statements, lines) == result


@pytest.mark.parametrize(
    "statements, lines, arcs, result",
    [
        (
            {1, 2, 3, 4, 5, 10, 11, 12, 13, 14},
            {1, 2, 5, 10, 11, 13, 14},
            (),
            "1-2, 5-11, 13-14",
        ),
        (
            [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 98, 99],
            [1, 2, 5, 10, 11, 13, 14, 99],
            [(3, [4]), (5, [10, 11]), (98, [100, -1])],
            "1-2, 3->4, 5-11, 13-14, 98->100, 98->exit, 99",
        ),
        (
            [1, 2, 3, 4, 98, 99, 100, 101, 102, 103, 104],
            [1, 2, 99, 102, 103, 104],
            [(3, [4]), (104, [-1])],
            "1-2, 3->4, 99, 102-104",
        ),
    ],
)
def test_format_lines_with_arcs(
    statements: Iterable[TLineNo],
    lines: Iterable[TLineNo],
    arcs: Iterable[tuple[TLineNo, list[TLineNo]]],
    result: str,
) -> None:
    assert format_lines(statements, lines, arcs) == result
