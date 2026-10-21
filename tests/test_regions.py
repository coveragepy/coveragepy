# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage/regions.py."""

from __future__ import annotations

import ast
import collections
import textwrap
import typing
from pathlib import Path

import pytest

from coverage import env
from coverage.plugin import CodeRegion
from coverage.regions import STATEMENT_FIELDS, code_regions
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

            class Prop:
                @property
                def x(self):
                    return 48

                @x.setter
                def x(self, value):
                    self.v = 52

            if CONST:
                def if_body():
                    x = 56
            else:
                def if_else():
                    x = 59

            for i in range(3):
                pass
            else:
                def for_else():
                    x = 65

            while CONST:
                break
            else:
                def while_else():
                    x = 71

            try:
                def try_body():
                    x = 75
            except ValueError:
                def try_except():
                    x = 78
            else:
                def try_else():
                    x = 81
            finally:
                def try_finally():
                    x = 84

            try:
                pass
            except* ValueError:
                def trystar_except():
                    x = 90

            match CONST:
                case 4:
                    def match_case():
                        x = 95

            def outer():
                if CONST:
                    x = 99
                else:
                    def outer_else():
                        x = 102
                return 103

            async def afunc2():
                async for x in y:
                    pass
                else:
                    def afor_else():
                        x = 110

            class Cond:
                if CONST:
                    def m(self):
                        x = 115
                else:
                    def m(self):
                        x = 118
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
            CodeRegion(F, "Prop.x", start=47, lines={48}),
            CodeRegion(F, "Prop.x", start=51, lines={52}),
            CodeRegion(F, "if_body", start=55, lines={56}),
            CodeRegion(F, "if_else", start=58, lines={59}),
            CodeRegion(F, "for_else", start=64, lines={65}),
            CodeRegion(F, "while_else", start=70, lines={71}),
            CodeRegion(F, "try_body", start=74, lines={75}),
            CodeRegion(F, "try_except", start=77, lines={78}),
            CodeRegion(F, "try_else", start=80, lines={81}),
            CodeRegion(F, "try_finally", start=83, lines={84}),
            CodeRegion(F, "trystar_except", start=89, lines={90}),
            CodeRegion(F, "match_case", start=94, lines={95}),
            CodeRegion(F, "outer", start=97, lines={98, 99, 100, 101, 103}),
            CodeRegion(F, "outer.outer_else", start=101, lines={102}),
            CodeRegion(F, "afunc2", start=105, lines={106, 107, 108, 109}),
            CodeRegion(F, "afunc2.afor_else", start=109, lines={110}),
            CodeRegion(F, "Cond.m", start=114, lines={115}),
            CodeRegion(F, "Cond.m", start=117, lines={118}),
            CodeRegion(C, "MyClass", start=5, lines={9, 12, 13, 14, 15, 16, 18, 19, 21}),
            CodeRegion(C, "MyClass.method_a.inmethod.DeepInside", start=15, lines={17}),
            CodeRegion(C, "MyClass.method_a.inmethod.DeepInside.Deeper", start=18, lines={20}),
            CodeRegion(C, "MyClass.InnerClass", start=23, lines={26}),
            CodeRegion(C, "func.InsideFunc", start=36, lines={38}),
            CodeRegion(C, "Prop", start=45, lines={48, 52}),
            CodeRegion(C, "Cond", start=112, lines={115, 118}),
        ]
    )


# PYVERSIONS: use the highest supported released Python version.
@pytest.mark.skipif(
    env.PYVERSION < (3, 15),
    reason="only need to check for new syntax on the latest Python version",
)
def test_statement_fields() -> None:
    # RegionFinder has to look in every field that can hold statements, or it
    # will miss functions and classes.  Check that STATEMENT_FIELDS names all
    # of them, so that new Python syntax won't silently go unexamined.

    def node_classes() -> list[type[ast.AST]]:
        classes = []
        for name in dir(ast):
            cls = getattr(ast, name)
            if isinstance(cls, type) and issubclass(cls, ast.AST):
                classes.append(cls)
        return classes

    def list_fields(cls: type[ast.AST]) -> dict[str, type]:
        """The fields of `cls` that are lists of nodes, mapped to the node type."""
        fields = {}
        for field, ftype in getattr(cls, "_field_types", {}).items():
            if typing.get_origin(ftype) is list:
                (elt_type,) = typing.get_args(ftype)
                assert isinstance(elt_type, type), f"Expected a type, got {elt_type}"
                fields[field] = elt_type
        return fields

    def holds_statements(elt_type: type) -> bool:
        if issubclass(elt_type, ast.stmt):
            return True
        # ExceptHandler and match_case aren't statements, but have statements
        # in their own bodies.
        return any(
            issubclass(sub_elt, ast.stmt)
            for cls in node_classes()
            if issubclass(cls, elt_type)
            for sub_elt in list_fields(cls).values()
        )

    actual = {
        field
        for cls in node_classes()
        for field, elt_type in list_fields(cls).items()
        if holds_statements(elt_type)
    }
    assert actual == set(STATEMENT_FIELDS)


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
