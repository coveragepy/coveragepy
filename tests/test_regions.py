# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage/regions.py."""

from __future__ import annotations

import collections
import textwrap
from pathlib import Path

import pytest

from coverage.plugin import CodeRegion
from coverage.regions import code_regions

from tests.helpers import all_our_source_files


def test_code_regions() -> None:
    regions = code_regions(
        textwrap.dedent("""\
            # Numbers in this code are the line number.
            '''Module docstring'''

            CONST = 4
            class MyClass:
                class_attr = 6

                def __init__(self):
                    self.x = 9

                def method_a(self):
                    self.x = 12
                    def inmethod():
                        self.x = 14
                        class DeepInside:
                            def method_b():
                                self.x = 17
                            class Deeper:
                                def bb():
                                    self.x = 20
                    self.y = 21

                class InnerClass:
                    constant = 24
                    def method_c(self):
                        self.x = 26

            def func():
                x = 29
                y = 30
                def inner():
                    z = 32
                    def inner_inner():
                        w = 34

                class InsideFunc:
                    def method_d(self):
                        self.x = 38

                return 40

            async def afunc():
                x = 43
        """)
    )

    F = "function"
    C = "class"

    assert sorted(regions) == sorted(
        [
            CodeRegion(F, "MyClass.__init__", start=8, lines={9}),
            CodeRegion(F, "MyClass.method_a", start=11, lines={12, 13, 21}),
            CodeRegion(F, "MyClass.method_a.inmethod", start=13, lines={14, 15, 16, 18, 19}),
            CodeRegion(F, "MyClass.method_a.inmethod.DeepInside.method_b", start=16, lines={17}),
            CodeRegion(F, "MyClass.method_a.inmethod.DeepInside.Deeper.bb", start=19, lines={20}),
            CodeRegion(F, "MyClass.InnerClass.method_c", start=25, lines={26}),
            CodeRegion(F, "func", start=28, lines={29, 30, 31, 35, 36, 37, 39, 40}),
            CodeRegion(F, "func.inner", start=31, lines={32, 33}),
            CodeRegion(F, "func.inner.inner_inner", start=33, lines={34}),
            CodeRegion(F, "func.InsideFunc.method_d", start=37, lines={38}),
            CodeRegion(F, "afunc", start=42, lines={43}),
            CodeRegion(C, "MyClass", start=5, lines={9, 12, 13, 14, 15, 16, 18, 19, 21}),
            CodeRegion(C, "MyClass.method_a.inmethod.DeepInside", start=15, lines={17}),
            CodeRegion(C, "MyClass.method_a.inmethod.DeepInside.Deeper", start=18, lines={20}),
            CodeRegion(C, "MyClass.InnerClass", start=23, lines={26}),
            CodeRegion(C, "func.InsideFunc", start=36, lines={38}),
        ]
    )


def test_real_code_regions() -> None:
    # Run code_regions on most of the coverage source code, checking that it
    # succeeds and there are no overlaps.

    any_fails = False
    for source_file, source in all_our_source_files():
        regions = code_regions(source)
        for kind in ["function", "class"]:
            kind_regions = [reg for reg in regions if reg.kind == kind]
            line_counts = collections.Counter(lno for reg in kind_regions for lno in reg.lines)
            overlaps = [line for line, count in line_counts.items() if count > 1]
            if overlaps:  # pragma: only failure
                print(
                    f"{kind.title()} overlaps in {source_file.relative_to(Path.cwd())}: "
                    + f"{overlaps}"
                )
                any_fails = True

    if any_fails:
        pytest.fail("Overlaps were found")  # pragma: only failure
