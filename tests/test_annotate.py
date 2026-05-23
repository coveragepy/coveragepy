# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for annotation from coverage.py."""

from __future__ import annotations

import coverage

from tests.coveragetest import CoverageTest
from tests.goldtest import compare, gold_path


class AnnotationGoldTest(CoverageTest):
    """Test the annotate feature with gold files."""

    def make_multi(self) -> None:
        """Make a few source files we need for the tests."""
        self.make_file(
            "multi.py",
            """\
            import a.a
            import b.b

            a.a.a(1)
            b.b.b(2)
            """,
        )
        self.make_file("a/__init__.py")
        self.make_file(
            "a/a.py",
            """\
            def a(x):
                if x == 1:
                    print("x is 1")
                else:
                    print("x is not 1")
            """,
        )
        self.make_file("b/__init__.py")
        self.make_file(
            "b/b.py",
            """\
            def b(x):
                msg = f"x is {x}"
                print(msg)
            """,
        )

    def test_multi(self) -> None:
        self.make_multi()
        cov = coverage.Coverage()
        self.start_import_stop(cov, "multi")
        cov.annotate()
        compare(gold_path("annotate/multi"), ".", "*,cover")

    def test_annotate_dir(self) -> None:
        self.make_multi()
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "multi")
        cov.annotate(directory="out_anno_dir")
        compare(gold_path("annotate/anno_dir"), "out_anno_dir", "*,cover")

    def test_encoding(self) -> None:
        self.make_file(
            "utf8.py",
            """\
            # -*- coding: utf-8 -*-
            # This comment has an accent: é

            print("spam eggs")
            """,
        )
        cov = coverage.Coverage()
        self.start_import_stop(cov, "utf8")
        cov.annotate()
        compare(gold_path("annotate/encodings"), ".", "*,cover")

    def test_white(self) -> None:
        self.make_file(
            "white.py",
            """\
            # A test case sent to me by Steve White

            def f(self):
                if self==1:
                    pass
                elif self.m('fred'):
                    pass
                elif (g==1) and (b==2):
                    pass
                elif self.m('fred')==True:
                    pass
                elif ((g==1) and (b==2))==True:
                    pass
                else:
                    pass

            def g(x):
                if x == 1:
                    a = 1
                else:
                    a = 2

            g(1)

            def h(x):
                if 0:   #pragma: no cover
                    pass
                if x == 1:
                    a = 1
                else:
                    a = 2

            h(2)
            """,
        )

        cov = coverage.Coverage()
        self.start_import_stop(cov, "white")
        cov.annotate()
        compare(gold_path("annotate/white"), ".", "*,cover")

    def test_missing_after_else(self) -> None:
        self.make_file(
            "mae.py",
            """\
            def f(x):
                if x == 1:
                    print("1")
                else:
                    print("2")

            if f(1):
                print("nope")
            if f(2):
                print("nope")
            """,
        )

        cov = coverage.Coverage()
        self.start_import_stop(cov, "mae")
        cov.annotate()
        assert self.stdout() == "1\n2\n"
        compare(gold_path("annotate/mae"), ".", "*,cover")
