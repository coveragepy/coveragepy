# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.py."""

from __future__ import annotations

import pytest

import coverage
from coverage import env
from coverage.exceptions import NoDataError

from tests.coveragetest import CoverageTest


class TestCoverageTest(CoverageTest):
    """Make sure our complex self.check_coverage method works."""

    def test_successful_coverage(self) -> None:
        # The simplest run possible.
        self.check_coverage(
            """\
            a = 1
            b = 2
            """,
            lines=[1, 2],
        )
        # You can specify missing lines.
        self.check_coverage(
            """\
            a = 1
            if a == 2:
                a = 3
            """,
            lines=[1, 2, 3],
            missing="3",
        )

    def test_failed_coverage(self) -> None:
        # If the lines are wrong, the message shows right and wrong.
        with pytest.raises(AssertionError, match=r"\[1, 2] != \[1]"):
            self.check_coverage(
                """\
                a = 1
                b = 2
                """,
                lines=[1],
            )
        # If the missing lines are wrong, the message shows right and wrong.
        with pytest.raises(AssertionError, match=r"'3' != '37'"):
            self.check_coverage(
                """\
                a = 1
                if a == 2:
                    a = 3
                """,
                lines=[1, 2, 3],
                missing="37",
            )

    def test_exceptions_really_fail(self) -> None:
        # An assert in the checked code will really raise up to us.
        with pytest.raises(AssertionError, match="This is bad"):
            self.check_coverage(
                """\
                a = 1
                assert a == 99, "This is bad"
                """,
            )
        # Other exceptions too.
        with pytest.raises(ZeroDivisionError, match="division"):
            self.check_coverage(
                """\
                a = 1
                assert a == 1, "This is good"
                a/0
                """,
            )


class BasicCoverageTest(CoverageTest):
    """The simplest tests, for quick smoke testing of fundamental changes."""

    def test_simple(self) -> None:
        self.check_coverage(
            """\
            a = 1
            b = 2

            c = 4
            # Nothing here
            d = 6
            """,
            lines=[1, 2, 4, 6],
            report="4 0 0 0 100%",
        )

    def test_indentation_wackiness(self) -> None:
        # Partial final lines are OK.
        self.check_coverage(
            """\
            import sys
            if not sys.path:
                a = 1
                """,  # indented last line
            lines=[1, 2, 3],
            missing="3",
        )

    def test_multiline_initializer(self) -> None:
        self.check_coverage(
            """\
            d = {
                'foo': 1+2,
                'bar': (lambda x: x+1)(1),
                'baz': str(1),
            }

            e = { 'foo': 1, 'bar': 2 }
            """,
            lines=[1, 7],
            missing="",
        )

    def test_list_comprehension(self) -> None:
        self.check_coverage(
            """\
            l = [
                2*i for i in range(10)
                if i > 5
                ]
            assert l == [12, 14, 16, 18]
            """,
            lines=[1, 5],
            missing="",
        )


class SimpleStatementTest(CoverageTest):
    """Testing simple single-line statements."""

    def test_expression(self) -> None:
        # Bare expressions as statements are tricky: some implementations
        # optimize some of them away.  All implementations seem to count
        # the implicit return at the end as executable.
        self.check_coverage(
            """\
            12
            23
            """,
            lines=[1, 2],
            missing="",
        )
        self.check_coverage(
            """\
            12
            23
            a = 3
            """,
            lines=[1, 2, 3],
            missing="",
        )
        self.check_coverage(
            """\
            1 + 2
            1 + \\
                2
            """,
            lines=[1, 2],
            missing="",
        )
        self.check_coverage(
            """\
            1 + 2
            1 + \\
                2
            a = 4
            """,
            lines=[1, 2, 4],
            missing="",
        )

    def test_assert(self) -> None:
        self.check_coverage(
            """\
            assert (1 + 2)
            assert (1 +
                2)
            assert (1 + 2), 'the universe is broken'
            assert (1 +
                2), \\
                'something is amiss'
            """,
            lines=[1, 2, 4, 5],
            missing="",
        )

    def test_assignment(self) -> None:
        # Simple variable assignment
        self.check_coverage(
            """\
            a = (1 + 2)
            b = (1 +
                2)
            c = \\
                1
            """,
            lines=[1, 2, 4],
            missing="",
        )

    def test_assign_tuple(self) -> None:
        self.check_coverage(
            """\
            a = 1
            a,b,c = 7,8,9
            assert a == 7 and b == 8 and c == 9
            """,
            lines=[1, 2, 3],
            missing="",
        )

    def test_more_assignments(self) -> None:
        self.check_coverage(
            """\
            x = []
            d = {}
            d[
                4 + len(x)
                + 5
            ] = \\
            d[
                8 ** 2
            ] = \\
                9
            """,
            lines=[1, 2, 3],
            missing="",
        )

    def test_attribute_assignment(self) -> None:
        # Attribute assignment
        self.check_coverage(
            """\
            class obj: pass
            o = obj()
            o.foo = (1 + 2)
            o.foo = (1 +
                2)
            o.foo = \\
                1
            """,
            lines=[1, 2, 3, 4, 6],
            missing="",
        )

    def test_list_of_attribute_assignment(self) -> None:
        self.check_coverage(
            """\
            class obj: pass
            o = obj()
            o.a, o.b = (1 + 2), 3
            o.a, o.b = (1 +
                2), (3 +
                4)
            o.a, o.b = \\
                1, \\
                2
            """,
            lines=[1, 2, 3, 4, 7],
            missing="",
        )

    def test_augmented_assignment(self) -> None:
        self.check_coverage(
            """\
            a = 1
            a += 1
            a += (1 +
                2)
            a += \\
                1
            """,
            lines=[1, 2, 3, 5],
            missing="",
        )

    def test_triple_string_stuff(self) -> None:
        self.check_coverage(
            """\
            a = '''
                a multiline
                string.
                '''
            b = '''
                long expression
                ''' + '''
                on many
                lines.
                '''
            c = len('''
                long expression
                ''' +
                '''
                on many
                lines.
                ''')
            """,
            lines=[1, 5, 11],
            missing="",
        )

    def test_pass(self) -> None:
        # pass is tricky: if it's the only statement in a block, then it is
        # "executed". But if it is not the only statement, then it is not.
        self.check_coverage(
            """\
            if 1==1:
                pass
            """,
            lines=[1, 2],
            missing="",
        )
        self.check_coverage(
            """\
            def foo():
                pass
            foo()
            """,
            lines=[1, 2, 3],
            missing="",
        )
        self.check_coverage(
            """\
            def foo():
                "doc"
                pass
            foo()
            """,
            lines=[1, 3, 4],
            missing="",
        )
        self.check_coverage(
            """\
            class Foo:
                def foo(self):
                    pass
            Foo().foo()
            """,
            lines=[1, 2, 3, 4],
            missing="",
        )
        self.check_coverage(
            """\
            class Foo:
                def foo(self):
                    "Huh?"
                    pass
            Foo().foo()
            """,
            lines=[1, 2, 4, 5],
            missing="",
        )

    def test_del(self) -> None:
        self.check_coverage(
            """\
            d = { 'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1 }
            del d['a']
            del d[
                'b'
                ]
            del d['c'], \\
                d['d'], \\
                d['e']
            assert(len(d.keys()) == 0)
            """,
            lines=[1, 2, 3, 6, 9],
            missing="",
        )

    def test_raise(self) -> None:
        self.check_coverage(
            """\
            try:
                raise Exception(
                    "hello %d" %
                    17)
            except:
                pass
            """,
            lines=[1, 2, 5, 6],
            missing="",
        )

    def test_raise_followed_by_statement(self) -> None:
        self.check_coverage(
            """\
            try:
                raise Exception("hello")
                a = 3
            except:
                pass
            """,
            lines=[1, 2, 4, 5],
            missing="",
        )

    def test_return(self) -> None:
        self.check_coverage(
            """\
            def fn():
                a = 1
                return a

            x = fn()
            assert(x == 1)
            """,
            lines=[1, 2, 3, 5, 6],
            missing="",
        )
        self.check_coverage(
            """\
            def fn():
                a = 1
                return (
                    a +
                    1)

            x = fn()
            assert(x == 2)
            """,
            lines=[1, 2, 3, 7, 8],
            missing="",
        )
        self.check_coverage(
            """\
            def fn():
                a = 1
                return (a,
                    a + 1,
                    a + 2)

            x,y,z = fn()
            assert x == 1 and y == 2 and z == 3
            """,
            lines=[1, 2, 3, 7, 8],
            missing="",
        )

    def test_return_followed_by_statement(self) -> None:
        self.check_coverage(
            """\
            def fn():
                a = 2
                return a
                a = 4

            x = fn()
            assert(x == 2)
            """,
            lines=[1, 2, 3, 6, 7],
            missing="",
        )

    def test_yield(self) -> None:
        self.check_coverage(
            """\
            def gen():
                yield 1
                yield (2+
                    3+
                    4)
                yield 1, \\
                    2
            a,b,c = gen()
            assert a == 1 and b == 9 and c == (1,2)
            """,
            lines=[1, 2, 3, 6, 8, 9],
            missing="",
        )

    def test_break(self) -> None:
        self.check_coverage(
            """\
            for x in range(10):
                a = 2 + x
                break
                a = 4
            assert a == 2
            """,
            lines=[1, 2, 3, 5],
            missing="",
        )

    def test_continue(self) -> None:
        self.check_coverage(
            """\
            for x in range(10):
                a = 2 + x
                continue
                a = 4
            assert a == 11
            """,
            lines=[1, 2, 3, 5],
            missing="",
        )

    def test_strange_unexecuted_continue(self) -> None:
        # This used to be true, but no longer is:
        # Peephole optimization of jumps to jumps can mean that some statements
        # never hit the line tracer.  The behavior is different in different
        # versions of Python, so be careful when running this test.
        self.check_coverage(
            """\
            a = b = c = 0
            for n in range(100):
                if n % 2:
                    if n % 4:
                        a += 1
                    continue    # <-- This line may not be hit.
                else:
                    b += 1
                c += 1
            assert a == 50 and b == 50 and c == 50

            a = b = c = 0
            for n in range(100):
                if n % 2:
                    if n % 3:
                        a += 1
                    continue    # <-- This line is always hit.
                else:
                    b += 1
                c += 1
            assert a == 33 and b == 50 and c == 50
            """,
            lines=[1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15, 16, 17, 19, 20, 21],
            missing="",
        )

    def test_import(self) -> None:
        self.check_coverage(
            """\
            import string
            from sys import path
            a = 1
            """,
            lines=[1, 2, 3],
            missing="",
        )
        self.check_coverage(
            """\
            import string
            if 1 == 2:
                from sys import path
            a = 1
            """,
            lines=[1, 2, 3, 4],
            missing="3",
        )
        self.check_coverage(
            """\
            import string, \\
                os, \\
                re
            from sys import path, \\
                stdout
            a = 1
            """,
            lines=[1, 4, 6],
            missing="",
        )
        self.check_coverage(
            """\
            import sys, sys as s
            assert s.path == sys.path
            """,
            lines=[1, 2],
            missing="",
        )
        self.check_coverage(
            """\
            import sys, \\
                sys as s
            assert s.path == sys.path
            """,
            lines=[1, 3],
            missing="",
        )
        self.check_coverage(
            """\
            from sys import path, \\
                path as p
            assert p == path
            """,
            lines=[1, 3],
            missing="",
        )
        self.check_coverage(
            """\
            from sys import \\
                *
            assert len(path) > 0
            """,
            lines=[1, 3],
            missing="",
        )

    def test_global(self) -> None:
        self.check_coverage(
            """\
            g = h = i = 1
            def fn():
                global g
                global h, \\
                    i
                g = h = i = 2
            fn()
            assert g == 2 and h == 2 and i == 2
            """,
            lines=[1, 2, 6, 7, 8],
            missing="",
        )
        self.check_coverage(
            """\
            g = h = i = 1
            def fn():
                global g; g = 2
            fn()
            assert g == 2 and h == 1 and i == 1
            """,
            lines=[1, 2, 3, 4, 5],
            missing="",
        )

    def test_exec(self) -> None:
        self.check_coverage(
            """\
            a = b = c = 1
            exec("a = 2")
            exec("b = " +
                "c = " +
                "2")
            assert a == 2 and b == 2 and c == 2
            """,
            lines=[1, 2, 3, 6],
            missing="",
        )
        self.check_coverage(
            """\
            vars = {'a': 1, 'b': 1, 'c': 1}
            exec("a = 2", vars)
            exec("b = " +
                "c = " +
                "2", vars)
            assert vars['a'] == 2 and vars['b'] == 2 and vars['c'] == 2
            """,
            lines=[1, 2, 3, 6],
            missing="",
        )
        self.check_coverage(
            """\
            globs = {}
            locs = {'a': 1, 'b': 1, 'c': 1}
            exec("a = 2", globs, locs)
            exec("b = " +
                "c = " +
                "2", globs, locs)
            assert locs['a'] == 2 and locs['b'] == 2 and locs['c'] == 2
            """,
            lines=[1, 2, 3, 4, 7],
            missing="",
        )

    def test_extra_doc_string(self) -> None:
        self.check_coverage(
            """\
            a = 1
            "An extra docstring, should be a comment."
            b = 3
            assert (a,b) == (1,3)
            """,
            lines=[1, 2, 3, 4],
            missing="",
        )
        self.check_coverage(
            """\
            a = 1
            "An extra docstring, should be a comment."
            b = 3
            123 # A number for some reason: ignored
            1+1 # An expression: executed.
            c = 6
            assert (a,b,c) == (1,3,6)
            """,
            lines=[1, 2, 3, 4, 5, 6, 7],
            missing="",
        )

    def test_nonascii(self) -> None:
        self.check_coverage(
            """\
            # coding: utf-8
            a = 2
            b = 3
            """,
            lines=[2, 3],
        )

    def test_module_docstring(self) -> None:
        self.check_coverage(
            """\
            '''I am a module docstring.'''
            a = 2
            b = 3
            """,
            lines=[2, 3],
        )
        self.check_coverage(
            """\
            # Start with a comment, even though it doesn't change the behavior.
            '''I am a module docstring.'''
            a = 3
            b = 4
            """,
            lines=[3, 4],
        )


class CompoundStatementTest(CoverageTest):
    """Testing coverage of multi-line compound statements."""

    def test_statement_list(self) -> None:
        self.check_coverage(
            """\
            a = 1;
            b = 2; c = 3
            d = 4; e = 5;

            assert (a,b,c,d,e) == (1,2,3,4,5)
            """,
            lines=[1, 2, 3, 5],
            missing="",
        )

    def test_if(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if a == 1:
                x = 3
            assert x == 3
            if (a ==
                1):
                x = 7
            assert x == 7
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="",
        )
        self.check_coverage(
            """\
            a = 1
            if a == 1:
                x = 3
            else:
                y = 5
            assert x == 3
            """,
            lines=[1, 2, 3, 5, 6],
            missing="5",
        )
        self.check_coverage(
            """\
            a = 1
            if a != 1:
                x = 3
            else:
                y = 5
            assert y == 5
            """,
            lines=[1, 2, 3, 5, 6],
            missing="3",
        )
        self.check_coverage(
            """\
            a = 1; b = 2
            if a == 1:
                if b == 2:
                    x = 4
                else:
                    y = 6
            else:
                z = 8
            assert x == 4
            """,
            lines=[1, 2, 3, 4, 6, 8, 9],
            missing="6-8",
        )

    def test_elif(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a == 1:
                x = 3
            elif b == 2:
                y = 5
            else:
                z = 7
            assert x == 3
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="4-7",
            report="7 3 4 1 45% 4-7",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a != 1:
                x = 3
            elif b == 2:
                y = 5
            else:
                z = 7
            assert y == 5
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="3, 7",
            report="7 2 4 2 64% 3, 7",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a != 1:
                x = 3
            elif b != 2:
                y = 5
            else:
                z = 7
            assert z == 7
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="3, 5",
            report="7 2 4 2 64% 3, 5",
        )

    def test_elif_no_else(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a == 1:
                x = 3
            elif b == 2:
                y = 5
            assert x == 3
            """,
            lines=[1, 2, 3, 4, 5, 6],
            missing="4-5",
            report="6 2 4 1 50% 4-5",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a != 1:
                x = 3
            elif b == 2:
                y = 5
            assert y == 5
            """,
            lines=[1, 2, 3, 4, 5, 6],
            missing="3",
            report="6 1 4 2 70% 3, 4->6",
        )

    def test_elif_bizarre(self) -> None:
        self.check_coverage(
            """\
            def f(self):
                if self==1:
                    x = 3
                elif self.m('fred'):
                    x = 5
                elif (g==1) and (b==2):
                    x = 7
                elif self.m('fred')==True:
                    x = 9
                elif ((g==1) and (b==2))==True:
                    x = 11
                else:
                    x = 13
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13],
            missing="2-13",
        )

    def test_split_if(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if \\
                a == 1:
                x = 3
            elif \\
                b == 2:
                y = 5
            else:
                z = 7
            assert x == 3
            """,
            lines=[1, 2, 4, 5, 7, 9, 10],
            missing="5-9",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if \\
                a != 1:
                x = 3
            elif \\
                b == 2:
                y = 5
            else:
                z = 7
            assert y == 5
            """,
            lines=[1, 2, 4, 5, 7, 9, 10],
            missing="4, 9",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if \\
                a != 1:
                x = 3
            elif \\
                b != 2:
                y = 5
            else:
                z = 7
            assert z == 7
            """,
            lines=[1, 2, 4, 5, 7, 9, 10],
            missing="4, 7",
        )

    def test_pathological_split_if(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if (
                a == 1
                ):
                x = 3
            elif (
                b == 2
                ):
                y = 5
            else:
                z = 7
            assert x == 3
            """,
            lines=[1, 2, 5, 6, 9, 11, 12],
            missing="6-11",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if (
                a != 1
                ):
                x = 3
            elif (
                b == 2
                ):
                y = 5
            else:
                z = 7
            assert y == 5
            """,
            lines=[1, 2, 5, 6, 9, 11, 12],
            missing="5, 11",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if (
                a != 1
                ):
                x = 3
            elif (
                b != 2
                ):
                y = 5
            else:
                z = 7
            assert z == 7
            """,
            lines=[1, 2, 5, 6, 9, 11, 12],
            missing="5, 9",
        )

    def test_absurd_split_if(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a == 1 \\
                :
                x = 3
            elif b == 2 \\
                :
                y = 5
            else:
                z = 7
            assert x == 3
            """,
            lines=[1, 2, 4, 5, 7, 9, 10],
            missing="5-9",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a != 1 \\
                :
                x = 3
            elif b == 2 \\
                :
                y = 5
            else:
                z = 7
            assert y == 5
            """,
            lines=[1, 2, 4, 5, 7, 9, 10],
            missing="4, 9",
        )
        self.check_coverage(
            """\
            a = 1; b = 2; c = 3;
            if a != 1 \\
                :
                x = 3
            elif b != 2 \\
                :
                y = 5
            else:
                z = 7
            assert z == 7
            """,
            lines=[1, 2, 4, 5, 7, 9, 10],
            missing="4, 7",
        )

    def test_constant_if(self) -> None:
        self.check_coverage(
            """\
            if 1:
                a = 2
            assert a == 2
            """,
            lines=[1, 2, 3],
            missing="",
        )

    def test_while(self) -> None:
        self.check_coverage(
            """\
            a = 3; b = 0
            while a:
                b += 1
                a -= 1
            assert a == 0 and b == 3
            """,
            lines=[1, 2, 3, 4, 5],
            missing="",
        )
        self.check_coverage(
            """\
            a = 3; b = 0
            while a:
                b += 1
                break
            assert a == 3 and b == 1
            """,
            lines=[1, 2, 3, 4, 5],
            missing="",
        )

    def test_while_else(self) -> None:
        # Take the else branch.
        self.check_coverage(
            """\
            a = 3; b = 0
            while a:
                b += 1
                a -= 1
            else:
                b = 99
            assert a == 0 and b == 99
            """,
            lines=[1, 2, 3, 4, 6, 7],
            missing="",
        )
        # Don't take the else branch.
        self.check_coverage(
            """\
            a = 3; b = 0
            while a:
                b += 1
                a -= 1
                break
            else:
                b = 99
            assert a == 2 and b == 1
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="7",
        )

    def test_split_while(self) -> None:
        self.check_coverage(
            """\
            a = 3; b = 0
            while \\
                a:
                b += 1
                a -= 1
            assert a == 0 and b == 3
            """,
            lines=[1, 2, 4, 5, 6],
            missing="",
        )
        self.check_coverage(
            """\
            a = 3; b = 0
            while (
                a
                ):
                b += 1
                a -= 1
            assert a == 0 and b == 3
            """,
            lines=[1, 2, 5, 6, 7],
            missing="",
        )

    def test_for(self) -> None:
        self.check_coverage(
            """\
            a = 0
            for i in [1,2,3,4,5]:
                a += i
            assert a == 15
            """,
            lines=[1, 2, 3, 4],
            missing="",
        )
        self.check_coverage(
            """\
            a = 0
            for i in [1,
                2,3,4,
                5]:
                a += i
            assert a == 15
            """,
            lines=[1, 2, 5, 6],
            missing="",
        )
        self.check_coverage(
            """\
            a = 0
            for i in [1,2,3,4,5]:
                a += i
                break
            assert a == 1
            """,
            lines=[1, 2, 3, 4, 5],
            missing="",
        )

    def test_for_else(self) -> None:
        self.check_coverage(
            """\
            a = 0
            for i in range(5):
                a += i+1
            else:
                a = 99
            assert a == 99
            """,
            lines=[1, 2, 3, 5, 6],
            missing="",
        )
        self.check_coverage(
            """\
            a = 0
            for i in range(5):
                a += i+1
                break
            else:
                a = 123
            assert a == 1
            """,
            lines=[1, 2, 3, 4, 6, 7],
            missing="6",
        )

    def test_split_for(self) -> None:
        self.check_coverage(
            """\
            a = 0
            for \\
                i in [1,2,3,4,5]:
                a += i
            assert a == 15
            """,
            lines=[1, 2, 4, 5],
            missing="",
        )
        self.check_coverage(
            """\
            a = 0
            for \\
                i in [1,
                2,3,4,
                5]:
                a += i
            assert a == 15
            """,
            lines=[1, 2, 6, 7],
            missing="",
        )

    def test_try_except(self) -> None:
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
            except:
                a = 99
            assert a == 1
            """,
            lines=[1, 2, 3, 4, 5, 6],
            missing="4-5",
        )
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
                raise Exception("foo")
            except:
                a = 99
            assert a == 99
            """,
            lines=[1, 2, 3, 4, 5, 6, 7],
            missing="",
        )
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
                raise Exception("foo")
            except ImportError:
                a = 99
            except:
                a = 123
            assert a == 123
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9],
            missing="6",
        )
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
                raise IOError("foo")
            except ImportError:
                a = 99
            except IOError:
                a = 17
            except:
                a = 123
            assert a == 17
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            missing="6, 9-10",
        )
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
            except:
                a = 99
            else:
                a = 123
            assert a == 123
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="4-5",
            branchz="",
            branchz_missing="",
        )

    def test_try_except_stranded_else(self) -> None:
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
                raise Exception("foo")
            except:
                a = 99
            else:
                a = 123
            assert a == 99
            """,
            lines=[1, 2, 3, 4, 5, 6, 9],
            missing="",
            branchz="",
            branchz_missing="",
        )

    def test_try_finally(self) -> None:
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
            finally:
                a = 99
            assert a == 99
            """,
            lines=[1, 2, 3, 5, 6],
            missing="",
        )
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
                try:
                    raise Exception("foo")
                finally:
                    b = 123
            except:
                a = 99
            assert a == 99 and b == 123
            """,
            lines=[1, 2, 3, 4, 5, 7, 8, 9, 10],
            missing="",
        )

    def test_function_def(self) -> None:
        self.check_coverage(
            """\
            a = 99
            def foo():
                ''' docstring
                '''
                return 1

            a = foo()
            assert a == 1
            """,
            lines=[1, 2, 5, 7, 8],
            missing="",
        )
        self.check_coverage(
            """\
            def foo(
                a,
                b
                ):
                ''' docstring
                '''
                return a+b

            x = foo(17, 23)
            assert x == 40
            """,
            lines=[1, 7, 9, 10],
            missing="",
        )
        self.check_coverage(
            """\
            def foo(
                a = (lambda x: x*2)(10),
                b = (
                    lambda x:
                        x+1
                    )(1)
                ):
                ''' docstring
                '''
                return a+b

            x = foo()
            assert x == 22
            """,
            lines=[1, 10, 12, 13],
            missing="",
        )

    def test_class_def(self) -> None:
        self.check_coverage(
            """\
            # A comment.
            class theClass:
                ''' the docstring.
                    Don't be fooled.
                '''
                def __init__(self):
                    ''' Another docstring. '''
                    self.a = 1

                def foo(self):
                    return self.a

            x = theClass().foo()
            assert x == 1
            """,
            lines=[2, 6, 8, 10, 11, 13, 14],
            missing="",
            branchz="",
            branchz_missing="",
        )


class AnnotationTest(CoverageTest):
    """Tests specific to annotations."""

    def test_attribute_annotation(self) -> None:
        if env.PYBEHAVIOR.deferred_annotations:
            lines = [1, 3]
        else:
            lines = [1, 2, 3]
        self.check_coverage(
            """\
            class X:
                x: int
                y = 1
            """,
            lines=lines,
            missing="",
        )

    def test_attribute_annotation_from_future(self) -> None:
        self.check_coverage(
            """\
            from __future__ import annotations
            class X:
                x: int
                y = 1
            """,
            lines=[1, 2, 3, 4],
            missing="",
        )


class ExcludeTest(CoverageTest):
    """Tests of the exclusion feature to mark lines as not covered."""

    def test_default(self) -> None:
        # A number of forms of pragma comment are accepted.
        self.check_coverage(
            """\
            a = 1
            b = 2   # pragma: no cover
            c = 3
            d = 4   #pragma NOCOVER
            e = 5
            f = 6#\tpragma:\tno cover
            g = 7
            ...
            i = 9
            ...     # we don't care about this line
            k = 11
            def foo12(): ...  # do nothing
            async def bar13():   ...
            def method14(self) ->None: ...
            def method15(   # 15
                self,
                some_arg: str = "Hello",
            ): ...
            def method19(self): return a[1,...]
            def method20(
                self,
                some_args,
            ) -> int: ...
            x = 24
            def method25(
                self,
            ):  return a[1,...]
            def f28(): print("(well): ... #2 false positive!")
            """,
            lines=[1, 3, 5, 7, 9, 11, 19, 24, 25],
        )

    def test_default_ellipsis_exclusion_ignores_multiline_strings(self) -> None:
        self.check_coverage(
            '''\
            YAML_LITERAL = """\\
            ---
            version: 1.2.3
            ...
            """
            after = 1
            ''',
            lines=[1, 6],
        )

    def test_default_ellipsis_exclusion_ignores_single_line_strings(self) -> None:
        self.check_coverage(
            '''\
            pattern = "literal ..."
            skipped = "literal ..."  # pragma: no cover
            after = 1
            ''',
            lines=[1, 3],
        )

    def test_two_excludes(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2

            if a == 99:
                a = 4   # -cc
                b = 5
                c = 6   # -xx
            assert a == 1 and b == 2
            """,
            lines=[1, 3, 5, 7],
            missing="5",
            excludes=["-cc", "-xx"],
        )

    def test_excluding_elif_suites(self) -> None:
        self.check_coverage(
            """\
            a = 1; b = 2

            if 1==1:
                a = 4
                b = 5
                c = 6
            elif 1==0:          #pragma: NO COVER
                a = 8
                b = 9
            else:
                a = 11
                b = 12
            assert a == 4 and b == 5 and c == 6
            """,
            lines=[1, 3, 4, 5, 6, 11, 12, 13],
            missing="11-12",
            excludes=["#pragma: NO COVER"],
        )

    def test_excluding_try_except(self) -> None:
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
            except:       #pragma: NO COVER
                a = 99
            else:
                a = 123
            assert a == 123
            """,
            lines=[1, 2, 3, 7, 8],
            missing="",
            excludes=["#pragma: NO COVER"],
            branchz="",
            branchz_missing="",
        )

    def test_excluding_try_except_stranded_else(self) -> None:
        self.check_coverage(
            """\
            a = 0
            try:
                a = 1
                raise Exception("foo")
            except:
                a = 99
            else:              #pragma: NO COVER
                x = 2
            assert a == 99
            """,
            lines=[1, 2, 3, 4, 5, 6, 9],
            missing="",
            excludes=["#pragma: NO COVER"],
            branchz="",
            branchz_missing="",
        )

    def test_excluded_comprehension_branches(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1271
        self.check_coverage(
            """\
            x, y = [0], [1]
            if x == [2]:
                raise NotImplementedError   # NOCOVPLZ
            if all(_ == __ for _, __ in zip(x, y)):
                raise NotImplementedError   # NOCOVPLZ
            """,
            lines=[1, 2, 4],
            missing="",
            excludes=["# NOCOVPLZ"],
            branchz="23 24 45 4.",
            branchz_missing="",
        )


class Py24Test(CoverageTest):
    """Tests of new syntax in Python 2.4."""

    def test_function_decorators(self) -> None:
        self.check_coverage(
            """\
            def require_int(func):
                def wrapper(arg):
                    assert isinstance(arg, int)
                    return func(arg)

                return wrapper

            @require_int
            def p1(arg):
                return arg*2

            assert p1(10) == 20
            """,
            lines=[1, 2, 3, 4, 6, 8, 9, 10, 12],
            missing="",
        )

    def test_function_decorators_with_args(self) -> None:
        self.check_coverage(
            """\
            def boost_by(extra):
                def decorator(func):
                    def wrapper(arg):
                        return extra*func(arg)
                    return wrapper
                return decorator

            @boost_by(10)
            def boosted(arg):
                return arg*2

            assert boosted(10) == 200
            """,
            lines=[1, 2, 3, 4, 5, 6, 8, 9, 10, 12],
            missing="",
        )

    def test_double_function_decorators(self) -> None:
        self.check_coverage(
            """\
            def require_int(func):
                def wrapper(arg):
                    assert isinstance(arg, int)
                    return func(arg)
                return wrapper

            def boost_by(extra):
                def decorator(func):
                    def wrapper(arg):
                        return extra*func(arg)
                    return wrapper
                return decorator

            @require_int
            @boost_by(10)
            def boosted1(arg):
                return arg*2

            assert boosted1(10) == 200

            @boost_by(10)
            @require_int
            def boosted2(arg):
                return arg*2

            assert boosted2(10) == 200
            """,
            lines=[1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17, 19, 21, 22, 23, 24, 26],
            missing="",
        )


class Py25Test(CoverageTest):
    """Tests of new syntax in Python 2.5."""

    def test_with_statement(self) -> None:
        self.check_coverage(
            """\
            class Managed:
                def __enter__(self):
                    desc = "enter"

                def __exit__(self, type, value, tb):
                    desc = "exit"

            m = Managed()
            with m:
                desc = "block1a"
                desc = "block1b"

            try:
                with m:
                    desc = "block2"
                    raise Exception("Boo!")
            except:
                desc = "caught"
            """,
            lines=[1, 2, 3, 5, 6, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18],
            missing="",
        )

    def test_try_except_finally(self) -> None:
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
            except:
                a = 99
            finally:
                b = 2
            assert a == 1 and b == 2
            """,
            lines=[1, 2, 3, 4, 5, 7, 8],
            missing="4-5",
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
                raise Exception("foo")
            except:
                a = 99
            finally:
                b = 2
            assert a == 99 and b == 2
            """,
            lines=[1, 2, 3, 4, 5, 6, 8, 9],
            missing="",
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
                raise Exception("foo")
            except ImportError:
                a = 99
            except:
                a = 123
            finally:
                b = 2
            assert a == 123 and b == 2
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 10, 11],
            missing="6",
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
                raise IOError("foo")
            except ImportError:
                a = 99
            except IOError:
                a = 17
            except:
                a = 123
            finally:
                b = 2
            assert a == 17 and b == 2
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13],
            missing="6, 9-10",
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
            except:
                a = 99
            else:
                a = 123
            finally:
                b = 2
            assert a == 123 and b == 2
            """,
            lines=[1, 2, 3, 4, 5, 7, 9, 10],
            missing="4-5",
            branchz="",
            branchz_missing="",
        )

    def test_try_except_finally_stranded_else(self) -> None:
        self.check_coverage(
            """\
            a = 0; b = 0
            try:
                a = 1
                raise Exception("foo")
            except:
                a = 99
            else:
                a = 123
            finally:
                b = 2
            assert a == 99 and b == 2
            """,
            # The else can't be reached because the try ends with a raise.
            lines=[1, 2, 3, 4, 5, 6, 10, 11],
            missing="",
            branchz="",
            branchz_missing="",
        )


class ModuleTest(CoverageTest):
    """Tests for the module-level behavior of the `coverage` module."""

    run_in_temp_dir = False

    def test_not_singleton(self) -> None:
        # You *can* create another coverage object.
        coverage.Coverage()
        coverage.Coverage()

    def test_old_name_and_new_name(self) -> None:
        assert coverage.coverage is coverage.Coverage


class ReportingTest(CoverageTest):
    """Tests of some reporting behavior."""

    def test_no_data_to_report_on_annotate(self) -> None:
        # Reporting with no data produces a nice message and no output
        # directory.
        with pytest.raises(NoDataError, match="No data to report."):
            self.command_line("annotate -d ann")
        self.assert_doesnt_exist("ann")

    def test_no_data_to_report_on_html(self) -> None:
        # Reporting with no data produces a nice message and no output
        # directory.
        with pytest.raises(NoDataError, match="No data to report."):
            self.command_line("html -d htmlcov")
        self.assert_doesnt_exist("htmlcov")

    def test_no_data_to_report_on_xml(self) -> None:
        # Reporting with no data produces a nice message.
        with pytest.raises(NoDataError, match="No data to report."):
            self.command_line("xml")
        self.assert_doesnt_exist("coverage.xml")
