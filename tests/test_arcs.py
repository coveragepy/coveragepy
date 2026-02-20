# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for coverage.py's arc measurement."""

from __future__ import annotations

import textwrap
from unittest import mock

import pytest

from tests.coveragetest import CoverageTest
from tests.helpers import assert_count_equal

import coverage
import coverage.python
from coverage import env
from coverage.data import sorted_lines
from coverage.files import abs_file


class SimpleArcTest(CoverageTest):
    """Tests for coverage.py's arc measurement."""

    def test_simple_sequence(self) -> None:
        self.check_coverage(
            """\
            a = 1
            b = 2
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a = 1

            b = 3
            """,
            branchz="",
        )
        self.check_coverage(
            """\

            a = 2
            b = 3

            c = 5
            """,
            branchz="",
        )

    def test_function_def(self) -> None:
        self.check_coverage(
            """\
            def foo():
                a = 2

            foo()
            """,
            branchz="",
        )

    def test_if(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if len([]) == 0:
                a = 3
            assert a == 3
            """,
            branchz="23 24",
            branchz_missing="24",
        )
        self.check_coverage(
            """\
            a = 1
            if len([]) == 1:
                a = 3
            assert a == 1
            """,
            branchz="23 24",
            branchz_missing="23",
        )

    def test_if_else(self) -> None:
        self.check_coverage(
            """\
            if len([]) == 0:
                a = 2
            else:
                a = 4
            assert a == 2
            """,
            branchz="12 14",
            branchz_missing="14",
        )
        self.check_coverage(
            """\
            if len([]) == 1:
                a = 2
            else:
                a = 4
            assert a == 4
            """,
            branchz="12 14",
            branchz_missing="12",
        )

    def test_compact_if(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if len([]) == 0: a = 2
            assert a == 2
            """,
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            def fn(x):
                if x % 2: return True
                return False
            a = fn(1)
            assert a is True
            """,
            branchz="2. 23",
            branchz_missing="23",
        )

    def test_multiline(self) -> None:
        self.check_coverage(
            """\
            a = (
                2 +
                3
                )
            b = \\
                6
            """,
            branchz="",
        )

    def test_if_return(self) -> None:
        self.check_coverage(
            """\
            def if_ret(a):
                if a:
                    return 3
                b = 4
                return 5
            x = if_ret(0) + if_ret(1)
            assert x == 8
            """,
            branchz="23 24",
            branchz_missing="",
        )

    def test_dont_confuse_exit_and_else(self) -> None:
        self.check_coverage(
            """\
            def foo():
                if foo:
                    a = 3
                else:
                    a = 5
                return a
            assert foo() == 3 # 7
            """,
            branchz="23 25",
            branchz_missing="25",
        )
        self.check_coverage(
            """\
            def foo():
                if foo:
                    a = 3
                else:
                    a = 5
            foo() # 6
            """,
            branchz="23 25",
            branchz_missing="25",
        )

    def test_bug_1184(self) -> None:
        self.check_coverage(
            """\
            def foo(x):
                if x:
                    try:
                        1/(x - 1)
                    except ZeroDivisionError:
                        pass
                return x        # 7

            for i in range(3):  # 9
                foo(i)
            """,
            branchz="23 27 9A 9.",
            branchz_missing="",
        )

    def test_bug_1991(self) -> None:
        # A bytecode was missing a line number, causing a KeyError in sysmon.py.
        self.check_coverage(
            """\
            def func(x, y):
                for size in (x or ()) if y else ():
                    print(size)

            func([5], True)
            """,
            branchz="2-1 23",
            branchz_missing="",
        )
        assert self.stdout() == "5\n"

    def test_bug_576(self) -> None:
        self.check_coverage(
            """\
            foo = True

            if foo == True:
                foo = False
            else:  # pragma: no cover
                pass

            if foo == False:
                foo = True
            else:  # pragma: no cover
                None

            print("Done")
            """,
            branchz="34 36 89 8B",
            branchz_missing="",
        )
        assert self.stdout() == "Done\n"


class WithTest(CoverageTest):
    """Arc-measuring tests involving context managers."""

    def test_with(self) -> None:
        self.check_coverage(
            """\
            def example():
                with open("test", "w", encoding="utf-8") as f:
                    f.write("3")
                    a = 4

            example()
            """,
            branchz="",
            branchz_missing="",
        )

    def test_with_return(self) -> None:
        self.check_coverage(
            """\
            def example():
                with open("test", "w", encoding="utf-8") as f:
                    f.write("3")
                    return 4

            example()
            """,
            branchz="",
            branchz_missing="",
        )

    def test_bug_146(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/146
        self.check_coverage(
            """\
            for i in range(2):
                with open("test", "w", encoding="utf-8") as f:
                    print(3)
                print(4)
            print(5)
            """,
            branchz="12 15",
            branchz_missing="",
        )
        assert self.stdout() == "3\n4\n3\n4\n5\n"

    def test_nested_with_return(self) -> None:
        self.check_coverage(
            """\
            def example(x):
                with open("test", "w", encoding="utf-8") as f2:
                    a = 3
                    with open("test2", "w", encoding="utf-8") as f4:
                        f2.write("5")
                        return 6

            example(8)
            """,
            branchz="",
            branchz_missing="",
        )

    def test_break_through_with(self) -> None:
        self.check_coverage(
            """\
            for i in range(1+1):
                with open("test", "w", encoding="utf-8") as f:
                    print(3)
                    break
            print(5)
            """,
            branchz="12 15",
            branchz_missing="15",
        )

    def test_continue_through_with(self) -> None:
        self.check_coverage(
            """\
            for i in range(1+1):
                with open("test", "w", encoding="utf-8") as f:
                    print(3)
                    continue
            print(5)
            """,
            branchz="12 15",
            branchz_missing="",
        )

    # https://github.com/coveragepy/coveragepy/issues/1270
    def test_raise_through_with(self) -> None:
        cov = self.check_coverage(
            """\
            from contextlib import nullcontext
            def f(x):
                with nullcontext():
                    print(4)
                    raise Exception("Boo6")
                print(6)
            try:
                f(8)
            except Exception:
                print("oops 10")
            """,
            branchz="",
            branchz_missing="",
        )
        expected = "line 3 didn't jump to the function exit"
        assert self.get_missing_arc_description(cov, 3, -2) == expected

    def test_untaken_if_through_with(self) -> None:
        cov = self.check_coverage(
            """\
            from contextlib import nullcontext
            def f(x):
                with nullcontext():
                    print(4)
                    if x == 5:
                        print(6)
                print(7)
            f(8)
            """,
            branchz="56 57",
            branchz_missing="56",
        )
        assert self.stdout() == "4\n7\n"
        expected = "line 3 didn't jump to the function exit"
        assert self.get_missing_arc_description(cov, 3, -2) == expected

    def test_untaken_raise_through_with(self) -> None:
        cov = self.check_coverage(
            """\
            from contextlib import nullcontext
            def f(x):
                with nullcontext():
                    print(4)
                    if x == 5:
                        raise Exception("Boo6")
                print(7)
            try:
                f(9)
            except Exception:
                print("oops 11")
            """,
            branchz="56 57",
            branchz_missing="56",
        )
        assert self.stdout() == "4\n7\n"
        expected = "line 3 didn't jump to the function exit"
        assert self.get_missing_arc_description(cov, 3, -2) == expected

    def test_leaving_module(self) -> None:
        cov = self.check_coverage(
            """\
            print(a := 1)
            if a == 1:
                print(3)
            """,
            branchz="2. 23",
            branchz_missing="2.",
        )
        assert self.stdout() == "1\n3\n"
        expected = "line 2 didn't exit the module because the condition on line 2 was always true"
        assert self.get_missing_arc_description(cov, 2, -1) == expected

    def test_with_with_lambda(self) -> None:
        self.check_coverage(
            """\
            from contextlib import nullcontext
            with nullcontext(lambda x: 2):
                print(3)
            print(4)
            """,
            branchz="",
            branchz_missing="",
        )

    def test_multiline_with(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1880
        self.check_coverage(
            """\
            import contextlib, itertools
            nums = itertools.count()
            with (
                contextlib.nullcontext() as x,
            ):
                while next(nums) < 6:
                    y = 7
            z = 8
            """,
            branchz="67 68",
            branchz_missing="",
        )

    def test_multi_multiline_with(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1880
        self.check_coverage(
            """\
            import contextlib, itertools
            nums = itertools.count()
            with (
                contextlib.nullcontext() as x,
                contextlib.nullcontext() as y,
                contextlib.nullcontext() as z,
            ):
                while next(nums) < 8:
                    y = 9
            z = 10
            """,
            branchz="89 8A",
            branchz_missing="",
        )

    def test_multi_multiline_with_backslash(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1880
        self.check_coverage(
            """\
            import contextlib, itertools
            nums = itertools.count()
            with contextlib.nullcontext() as x, \\
                contextlib.nullcontext() as y, \\
                contextlib.nullcontext() as z:
                while next(nums) < 6:
                    y = 7
            z = 8
            """,
            branchz="67 68",
            branchz_missing="",
        )


class LoopArcTest(CoverageTest):
    """Arc-measuring tests involving loops."""

    def test_loop(self) -> None:
        self.check_coverage(
            """\
            for i in range(10):
                a = i
            assert a == 9
            """,
            branchz="12 13",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            a = -1
            for i in range(0):
                a = i
            assert a == -1
            """,
            branchz="23 24",
            branchz_missing="23",
        )

    def test_nested_loop(self) -> None:
        self.check_coverage(
            """\
            for i in range(3):
                for j in range(3):
                    a = i + j
            assert a == 4
            """,
            branchz="12 14 23 21",
            branchz_missing="",
        )

    def test_break(self) -> None:
        self.check_coverage(
            """\
            for i in range(10):
                a = i
                break       # 3
                a = 99
            assert a == 0   # 5
            """,
            branchz="12 15",
            branchz_missing="15",
        )

    def test_continue(self) -> None:
        self.check_coverage(
            """\
            for i in range(10):
                a = i
                continue    # 3
                a = 99
            assert a == 9   # 5
            """,
            branchz="12 15",
            branchz_missing="",
        )

    def test_nested_breaks(self) -> None:
        self.check_coverage(
            """\
            for i in range(3):
                for j in range(3):
                    a = i + j
                    break               # 4
                if i == 2:
                    break
            assert a == 2 and i == 2    # 7
            """,
            branchz="12 17 23 25 51 56",
            branchz_missing="17 25",
        )

    def test_if_1(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if not not 1:
                a = 3
            else:
                a = 5
            assert a == 3
            """,
            lines=[1, 2, 3, 6],
            branchz="",
            branchz_missing="",
        )

    def test_while_1(self) -> None:
        # With "while 1", the loop knows it's constant.
        self.check_coverage(
            """\
            a, i = 1, 0
            while 1:
                if i >= 3:
                    a = 4
                    break
                i += 1
            assert a == 4 and i == 3
            """,
            branchz="34 36",
            branchz_missing="",
        )

    def test_while_true(self) -> None:
        self.check_coverage(
            """\
            a, i = 1, 0
            while True:
                if i >= 3:
                    a = 4
                    break
                i += 1
            assert a == 4 and i == 3
            """,
            lines=[1, 2, 3, 4, 5, 6, 7],
            branchz="34 36",
            branchz_missing="",
        )

    def test_while_false(self) -> None:
        self.check_coverage(
            """\
            a, i = 1, 0
            while False:
                1/0
            assert a == 1 and i == 0
            """,
            lines=[1, 2, 4],
            branchz="",
            branchz_missing="",
        )

    def test_while_not_false(self) -> None:
        self.check_coverage(
            """\
            a, i = 1, 0
            while not False:
                if i >= 3:
                    a = 4
                    break
                i += 1
            assert a == 4 and i == 3
            """,
            branchz="34 36",
            branchz_missing="",
        )

    def test_zero_coverage_while_loop(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/502
        self.make_file("main.py", "print('done')")
        self.make_file(
            "zero.py",
            """\
            def method(self):
                while True:
                    return 1
            """,
        )
        cov = coverage.Coverage(source=["."], branch=True)
        self.start_import_stop(cov, "main")
        assert self.stdout() == "done\n"
        expected = "zero.py 3 3 0 0 0% 1-3"
        report = self.get_report(cov, show_missing=True)
        squeezed = self.squeezed_lines(report)
        assert expected in squeezed[3]

    def test_bug_496_continue_in_constant_while(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/496
        self.check_coverage(
            """\
            up = iter('ta')
            while True:
                char = next(up)
                if char == 't':
                    continue
                i = "line 6"
                break
            """,
            branchz="45 46",
            branchz_missing="",
        )

    def test_missing_while_body(self) -> None:
        self.check_coverage(
            """\
            a = 3; b = 0
            if 0:
                while a > 0:
                    a -= 1
            assert a == 3 and b == 0
            """,
            branchz="",
            branchz_missing="",
        )

    def test_for_if_else_for(self) -> None:
        self.check_coverage(
            """\
            def branches_2(l):
                if l:
                    for e in l:
                        a = 4
                else:
                    a = 6

            def branches_3(l):
                for x in l:
                    if x:
                        for e in l:
                            a = 12
                    else:
                        a = 14

            branches_2([0,1])
            branches_3([0,1])
            """,
            branchz="23 26 34 3. 9A 9-8 AB AE BC B9",
            branchz_missing="26",
        )

    def test_for_else(self) -> None:
        self.check_coverage(
            """\
            def forelse(seq):
                for n in seq:
                    if n > 5:
                        break
                else:
                    print('None of the values were greater than 5')
                print('Done')
            forelse([1,2])
            """,
            branchz="23 26 34 32",
            branchz_missing="34",
        )
        self.check_coverage(
            """\
            def forelse(seq):
                for n in seq:
                    if n > 5:
                        break
                else:
                    print('None of the values were greater than 5')
                print('Done')
            forelse([1,6])
            """,
            branchz="23 26 34 32",
            branchz_missing="26",
        )

    def test_split_for(self) -> None:
        self.check_coverage(
            """\
            a = 0
            for (i
                ) in [1,2,3,4,5]:
                a += i
            assert a == 15
            """,
            lines=[1, 2, 4, 5],
            branchz="24 25",
        )

    def test_while_else(self) -> None:
        self.check_coverage(
            """\
            def whileelse(seq):
                while seq:
                    n = seq.pop()
                    if n > 4:
                        break
                else:
                    n = 99
                return n
            assert whileelse([1, 2]) == 99
            """,
            branchz="23 27 45 42",
            branchz_missing="45",
        )
        self.check_coverage(
            """\
            def whileelse(seq):
                while seq:
                    n = seq.pop()
                    if n > 4:
                        break
                else:
                    n = 99
                return n
            assert whileelse([1, 5]) == 5
            """,
            branchz="23 27 45 42",
            branchz_missing="27 42",
        )

    def test_confusing_for_loop_bug_175(self) -> None:
        self.check_coverage(
            """\
            o = [(1,2), (3,4)]
            o = [a for a in o]
            for tup in o:
                x = tup[0]
                y = tup[1]
            """,
            branchz="34 3.",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            o = [(1,2), (3,4)]
            for tup in [a for a in o]:
                x = tup[0]
                y = tup[1]
            """,
            branchz="23 2.",
            branchz_missing="",
        )

    def test_incorrect_loop_exit_bug_1175(self) -> None:
        self.check_coverage(
            """\
            def wrong_loop(x):
                if x:
                    for i in [3, 33]:
                        print(i+4)
                else:
                    pass

            wrong_loop(8)
            """,
            branchz="23 26 34 3.",
            branchz_missing="26",
        )

    # https://bugs.python.org/issue44672
    def test_incorrect_if_bug_1175(self) -> None:
        self.check_coverage(
            """\
            def wrong_loop(x):
                if x:
                    if x:
                        print(4)
                else:
                    pass

            wrong_loop(8)
            """,
            branchz="23 26 34 3.",
            branchz_missing="26 3.",
        )

    def test_generator_expression(self) -> None:
        # Generator expression:
        self.check_coverage(
            """\
            o = ((1,2), (3,4))
            o = (a for a in o)
            for tup in o:
                x = tup[0]
                y = tup[1]
            """,
            branchz="34 3.",
            branchz_missing="",
        )

    def test_generator_expression_another_way(self) -> None:
        # https://bugs.python.org/issue44450
        # Generator expression:
        self.check_coverage(
            """\
            o = ((1,2), (3,4))
            o = (a for
                 a in
                 o)
            for tup in o:
                x = tup[0]
                y = tup[1]
            """,
            branchz="56 5.",
            branchz_missing="",
        )

    def test_other_comprehensions(self) -> None:
        # Set comprehension:
        self.check_coverage(
            """\
            o = ((1,2), (3,4))
            o = {a for a in o}
            for tup in o:
                x = tup[0]
                y = tup[1]
            """,
            branchz="34 3.",
            branchz_missing="",
        )
        # Dict comprehension:
        self.check_coverage(
            """\
            o = ((1,2), (3,4))
            o = {a:1 for a in o}
            for tup in o:
                x = tup[0]
                y = tup[1]
            """,
            branchz="34 3.",
            branchz_missing="",
        )

    def test_multiline_dict_comp(self) -> None:
        # Multiline dict comp:
        self.check_coverage(
            """\
            # comment
            d = \\
                {
                i:
                    str(i)
                for
                    i
                    in
                    range(9)
            }
            x = 11
            """,
            branchz="",
            branchz_missing="",
        )
        # Multi dict comp:
        self.check_coverage(
            """\
            # comment
            d = \\
                {
                (i, j):
                    str(i+j)
                for
                    i
                    in
                    range(9)
                for
                    j
                    in
                    range(13)
            }
            x = 15
            """,
            branchz="",
            branchz_missing="",
        )


class ExceptionArcTest(CoverageTest):
    """Arc-measuring tests involving exception handling."""

    def test_try_except(self) -> None:
        self.check_coverage(
            """\
            a, b = 1, 1
            try:
                a = 3
            except:
                b = 5
            assert a == 3 and b == 1
            """,
            branchz="",
            branchz_missing="",
        )

    def test_raise_followed_by_statement(self) -> None:
        self.check_coverage(
            """\
            a, b = 1, 1
            try:
                a = 3
                raise Exception("Yikes!")
                a = 5
            except:
                b = 7
            assert a == 3 and b == 7
            """,
            branchz="",
            branchz_missing="",
        )

    def test_hidden_raise(self) -> None:
        self.check_coverage(
            """\
            a, b = 1, 1
            def oops(x):
                if x % 2:
                    raise Exception("odd")
            try:
                a = 6
                oops(1)
                a = 8
            except:
                b = 10
            assert a == 6 and b == 10
            """,
            branchz="34 3-2",
            branchz_missing="3-2",
        )

    def test_except_with_type(self) -> None:
        self.check_coverage(
            """\
            a, b = 1, 1
            def oops(x):
                if x % 2:
                    raise ValueError("odd")
            def try_it(x):
                try:
                    a = 7
                    oops(x)
                    a = 9
                except ValueError:
                    b = 11
                return a
            assert try_it(0) == 9   # C
            assert try_it(1) == 7   # D
            """,
            branchz="34 3-2",
            branchz_missing="",
        )

    def test_try_finally(self) -> None:
        self.check_coverage(
            """\
            a, c = 1, 1
            try:
                a = 3
            finally:
                c = 5
            assert a == 3 and c == 5
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a, c, d = 1, 1, 1
            try:
                try:
                    a = 4
                finally:
                    c = 6
            except:
                d = 8
            assert a == 4 and c == 6 and d == 1    # 9
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a, c, d = 1, 1, 1
            try:
                try:
                    a = 4
                    raise Exception("Yikes!")
                    # line 6
                finally:
                    c = 8
            except:
                d = 10                              # A
            assert a == 4 and c == 8 and d == 10    # B
            """,
            branchz="",
        )

    def test_finally_in_loop(self) -> None:
        self.check_coverage(
            """\
            a, c, d, i = 1, 1, 1, 99
            try:
                for i in range(5):
                    try:
                        a = 5
                        if i > 0:
                            raise Exception("Yikes!")
                        a = 8
                    finally:
                        c = 10
            except:
                d = 12                              # C
            assert a == 5 and c == 10 and d == 12   # D
            """,
            branchz="34 3D 67 68",
            branchz_missing="3D",
        )
        self.check_coverage(
            """\
            a, c, d, i = 1, 1, 1, 99
            try:
                for i in range(5):
                    try:
                        a = 5
                        if i > 10:
                            raise Exception("Yikes!")
                        a = 8
                    finally:
                        c = 10
            except:
                d = 12                              # C
            assert a == 8 and c == 10 and d == 1    # D
            """,
            branchz="34 3D 67 68",
            branchz_missing="67",
        )

    def test_break_through_finally(self) -> None:
        self.check_coverage(
            """\
            a, c, d, i = 1, 1, 1, 99
            try:
                for i in range(3):
                    try:
                        a = 5
                        if i > 0:
                            break
                        a = 8
                    finally:
                        c = 10
            except:
                d = 12                              # C
            assert a == 5 and c == 10 and d == 1    # D
            """,
            branchz="34 3D 67 68",
            branchz_missing="3D",
        )

    def test_break_continue_without_finally(self) -> None:
        self.check_coverage(
            """\
            a, c, d, i = 1, 1, 1, 99
            try:
                for i in range(3):
                    try:
                        a = 5
                        if i > 0:
                            break
                        continue
                    except:
                        c = 10
            except:
                d = 12                              # C
            assert a == 5 and c == 1 and d == 1     # D
            """,
            branchz="34 3D 67 68",
            branchz_missing="3D",
        )

    def test_continue_through_finally(self) -> None:
        self.check_coverage(
            """\
            a, b, c, d, i = 1, 1, 1, 1, 99
            try:
                for i in range(3):
                    try:
                        a = 5
                        if i > 0:
                            continue
                        b = 8
                    finally:
                        c = 10
            except:
                d = 12                              # C
            assert (a, b, c, d) == (5, 8, 10, 1)    # D
            """,
            branchz="34 3D 67 68",
            branchz_missing="",
        )

    def test_finally_in_loop_bug_92(self) -> None:
        self.check_coverage(
            """\
            for i in range(5):
                try:
                    j = 3
                finally:
                    f = 5
                g = 6
            h = 7
            """,
            branchz="12 17",
            branchz_missing="",
        )

    def test_bug_212(self) -> None:
        # "except Exception as e" is crucial here.
        # Bug 212 said that the "if exc" line was incorrectly marked as only
        # partially covered.
        self.check_coverage(
            """\
            def b(exc):
                try:
                    while "no peephole".upper():
                        raise Exception(exc)    # 4
                except Exception as e:
                    if exc != 'expected':
                        raise
                    q = 8

            b('expected')
            try:
                b('unexpected')     # C
            except:
                pass
            """,
            branchz="34 3-1 67 68",
            branchz_missing="3-1",
        )

    def test_except_finally(self) -> None:
        self.check_coverage(
            """\
            a, b, c = 1, 1, 1
            try:
                a = 3
            except:
                b = 5
            finally:
                c = 7
            assert a == 3 and b == 1 and c == 7
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a, b, c = 1, 1, 1
            def oops(x):
                if x % 2: raise Exception("odd")
            try:
                a = 5
                oops(1)
                a = 7
            except:
                b = 9
            finally:
                c = 11
            assert a == 5 and b == 9 and c == 11
            """,
            branchz="",
        )

    def test_multiple_except_clauses(self) -> None:
        self.check_coverage(
            """\
            a, b, c = 1, 1, 1
            try:
                a = 3
            except ValueError:
                b = 5
            except IndexError:
                a = 7
            finally:
                c = 9
            assert a == 3 and b == 1 and c == 9
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a, b, c = 1, 1, 1
            try:
                a = int("xyz")  # ValueError
            except ValueError:
                b = 5
            except IndexError:
                a = 7
            finally:
                c = 9
            assert a == 1 and b == 5 and c == 9
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a, b, c = 1, 1, 1
            try:
                a = [1][3]      # IndexError
            except ValueError:
                b = 5
            except IndexError:
                a = 7
            finally:
                c = 9
            assert a == 7 and b == 1 and c == 9
            """,
            branchz="",
        )
        self.check_coverage(
            """\
            a, b, c = 1, 1, 1
            try:
                try:
                    a = 4/0         # ZeroDivisionError
                except ValueError:
                    b = 6
                except IndexError:
                    a = 8
                finally:
                    c = 10
            except ZeroDivisionError:
                pass
            assert a == 1 and b == 1 and c == 10
            """,
            branchz="",
        )

    def test_return_finally(self) -> None:
        self.check_coverage(
            """\
            a = [1]
            def check_token(data):
                if data:
                    try:
                        return 5
                    finally:
                        a.append(7)
                return 8
            assert check_token(False) == 8
            assert a == [1]
            assert check_token(True) == 5
            assert a == [1, 7]
            """,
            branchz="34 38",
            branchz_missing="",
        )

    def test_except_jump_finally(self) -> None:
        self.check_coverage(
            """\
            def func(x):
                a = f = g = 2
                try:
                    for i in range(4):
                        try:
                            6/0
                        except ZeroDivisionError:
                            if x == 'break':
                                a = 9
                                break
                            elif x == 'continue':
                                a = 12
                                continue
                            elif x == 'return':
                                a = 15                      # F
                                return a, f, g, i           # G
                            elif x == 'raise':              # H
                                a = 18                      # I
                                raise ValueError()          # J
                        finally:
                            f = 21                          # L
                except ValueError:                          # M
                    g = 23                                  # N
                return a, f, g, i                           # O

            assert func('break') == (9, 21, 2, 0)           # Q
            assert func('continue') == (12, 21, 2, 3)       # R
            assert func('return') == (15, 2, 2, 0)          # S
            assert func('raise') == (18, 21, 23, 0)         # T
            assert func('other') == (2, 21, 2, 3)           # U 30
            """,
            branchz="45 4O 89 8B BC BE EF EH HI HL",
            branchz_missing="",
        )

    def test_else_jump_finally(self) -> None:
        self.check_coverage(
            """\
            def func(x):
                a = f = g = 2
                try:
                    for i in range(4):
                        try:
                            b = 6
                        except ZeroDivisionError:
                            pass
                        else:
                            if x == 'break':
                                a = 11
                                break
                            elif x == 'continue':
                                a = 14
                                continue
                            elif x == 'return':
                                a = 17                      # H
                                return a, f, g, i           # I
                            elif x == 'raise':              # J
                                a = 20                      # K
                                raise ValueError()          # L
                        finally:
                            f = 23                          # N
                except ValueError:                          # O
                    g = 25                                  # P
                return a, f, g, i                           # Q

            assert func('break') == (11, 23, 2, 0)          # S
            assert func('continue') == (14, 23, 2, 3)       # T
            assert func('return') == (17, 2, 2, 0)          # U
            assert func('raise') == (20, 23, 25, 0)         # V
            assert func('other') == (2, 23, 2, 3)           # W 32
            """,
            branchz="45 4Q AB AD DE DG GH GJ JK JN",
            branchz_missing="",
        )

    @pytest.mark.skipif(env.PYVERSION < (3, 11), reason="ExceptionGroup is new in Python 3.11")
    def test_exception_group(self) -> None:
        # PyPy3.11 traces this incorrectly: https://github.com/pypy/pypy/issues/5354
        if env.PYPY:
            missing = "5, 11"
        else:
            missing = "5-6, 11-12"
        self.check_coverage(
            """\
            a = 1
            try:
                raise ExceptionGroup("Zero!", [ZeroDivisionError()])
            except* ValueError:
                a = 5
                b = 6/0
            except* ZeroDivisionError:
                a = 8
                b = 9
            except* Exception:
                a = 11
                b = 12/0
            assert a == 8
            assert b == 9
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
            missing=missing,
            branchz="",
            branchz_missing="",
        )


class YieldTest(CoverageTest):
    """Arc tests for generators."""

    def test_yield_in_loop(self) -> None:
        self.check_coverage(
            """\
            def gen(inp):
                for n in inp:
                    yield n

            list(gen([1,2,3]))
            """,
            branchz="23 2-1",
            branchz_missing="",
        )

    def test_padded_yield_in_loop(self) -> None:
        self.check_coverage(
            """\
            def gen(inp):
                i = 2
                for n in inp:
                    i = 4
                    yield n
                    i = 6
                i = 7

            list(gen([1,2,3]))
            """,
            branchz="34 37",
            branchz_missing="",
        )

    def test_bug_308(self) -> None:
        self.check_coverage(
            """\
            def run():
                for i in range(10):
                    yield lambda: i

            for f in run():
                print(f())
            """,
            branchz="23 2. 56 5.",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            def run():
                yield lambda: 100
                for i in range(10):
                    yield lambda: i

            for f in run():
                print(f())
            """,
            branchz="34 3. 67 6.",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            def run():
                yield lambda: 100  # no branch miss

            for f in run():
                print(f())
            """,
            branchz="45 4.",
            branchz_missing="",
        )

    def test_bug_324(self) -> None:
        # This code is tricky: the list() call pulls all the values from gen(),
        # but each of them is a generator itself that is never iterated.  As a
        # result, the generator expression on line 3 is never entered or run.
        self.check_coverage(
            """\
            def gen(inp):
                for n in inp:
                    yield (i * 2 for i in range(n))

            list(gen([1,2,3]))
            """,
            branchz="23 2.",
            branchz_missing="",
        )

    def test_coroutines(self) -> None:
        self.check_coverage(
            """\
            def double_inputs():
                while len([1]):     # avoid compiler differences
                    x = yield
                    x *= 2
                    yield x

            gen = double_inputs()
            next(gen)
            print(gen.send(10))
            next(gen)
            print(gen.send(6))
            """,
            branchz="23 2-1",
            branchz_missing="2-1",
        )
        assert self.stdout() == "20\n12\n"

    def test_yield_from(self) -> None:
        self.check_coverage(
            """\
            def gen(inp):
                i = 2
                for n in inp:
                    i = 4
                    yield from range(3)
                    i = 6
                i = 7

            list(gen([1,2,3]))
            """,
            branchz="34 37",
            branchz_missing="",
        )

    def test_abandoned_yield(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/440
        self.check_coverage(
            """\
            def gen():
                print(2)
                yield 3
                print(4)

            print(next(gen()))
            """,
            lines=[1, 2, 3, 4, 6],
            missing="4",
            branchz="",
            branchz_missing="",
        )
        assert self.stdout() == "2\n3\n"


class MatchCaseTest(CoverageTest):
    """Tests of match-case."""

    def test_match_case_with_default(self) -> None:
        self.check_coverage(
            """\
            for command in ["huh", "go home", "go n"]:
                match command.split():
                    case ["go", direction] if direction in "nesw":
                        match = f"go: {direction}"
                    case ["go", _]:
                        match = "no go"
                    case _:
                        match = "default"
                print(match)
            """,
            branchz="12 1-1 34 35 56 57",
            branchz_missing="",
        )
        assert self.stdout() == "default\nno go\ngo: n\n"

    def test_match_case_with_named_default(self) -> None:
        self.check_coverage(
            """\
            for command in ["huh", "go home", "go n"]:
                match command.split():
                    case ["go", direction] if direction in "nesw":
                        match = f"go: {direction}"
                    case ["go", _]:
                        match = "no go"
                    case _ as value:
                        match = "default"
                print(match)
            """,
            branchz="12 1-1 34 35 56 57",
            branchz_missing="",
        )
        assert self.stdout() == "default\nno go\ngo: n\n"

    def test_match_case_with_wildcard(self) -> None:
        self.check_coverage(
            """\
            for command in ["huh", "go home", "go n"]:
                match command.split():
                    case ["go", direction] if direction in "nesw":
                        match = f"go: {direction}"
                    case ["go", _]:
                        match = "no go"
                    case x:
                        match = f"default: {x}"
                print(match)
            """,
            branchz="12 1-1 34 35 56 57",
            branchz_missing="",
        )
        assert self.stdout() == "default: ['huh']\nno go\ngo: n\n"

    def test_match_case_without_wildcard(self) -> None:
        self.check_coverage(
            """\
            match = None
            for command in ["huh", "go home", "go n"]:
                match command.split():
                    case ["go", direction] if direction in "nesw":
                        match = f"go: {direction}"
                    case ["go", _]:
                        match = "no go"
                print(match)
            """,
            branchz="23 2-1 45 46 67 68",
            branchz_missing="",
        )
        assert self.stdout() == "None\nno go\ngo: n\n"

    def test_absurd_wildcards(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1421
        self.check_coverage(
            """\
            def absurd(x):
                match x:
                    case (3 | 99 | (999 | _)):
                        print("default")
            absurd(5)
            """,
            # No branches because 3 always matches.
            branchz="",
            branchz_missing="",
        )
        assert self.stdout() == "default\n"
        self.check_coverage(
            """\
            def absurd(x):
                match x:
                    case (3 | 99 | 999 as y):
                        print("not default")
            absurd(5)
            """,
            branchz="34 3-1",
            branchz_missing="34",
        )
        assert self.stdout() == ""
        self.check_coverage(
            """\
            def absurd(x):
                match x:
                    case (3 | 17 as y):
                        print("not default")
                    case 7: # 5
                        print("also not default")
            absurd(7)
            """,
            branchz="34 35 56 5-1",
            branchz_missing="34 5-1",
        )
        assert self.stdout() == "also not default\n"
        self.check_coverage(
            """\
            def absurd(x):
                match x:
                    case 3:
                        print("not default")
                    case _ if x == 7: # 5
                        print("also not default")
            absurd(7)
            """,
            branchz="34 35 56 5-1",
            branchz_missing="34 5-1",
        )
        assert self.stdout() == "also not default\n"

    def test_split_match_case(self) -> None:
        self.check_coverage(
            """\
            def foo(x):
                match x:
                    case (
                        1
                        | 2
                    ):
                        return "output: 1 or 2"
                    case _:
                        return "output: other"

            print(foo(1))
            print(foo(2))
            print(foo(3))
            """,
            lines=[1, 2, 3, 7, 8, 9, 11, 12, 13],
            missing="",
            branchz="37 38",
            branchz_missing="",
        )
        assert self.stdout() == "output: 1 or 2\noutput: 1 or 2\noutput: other\n"


class OptimizedIfTest(CoverageTest):
    """Tests of if statements being optimized away."""

    def test_optimized_away_if_0(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if len([2]):
                c = 3
            if 0:
                if len([5]):
                    d = 6
            else:
                e = 8
            f = 9
            """,
            lines=[1, 2, 3, 4, 8, 9],
            branchz="23 24",
            branchz_missing="24",
        )

    def test_optimized_away_if_1(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if len([2]):
                c = 3
            if 1:
                if len([5]):
                    d = 6
            else:
                e = 8
            f = 9
            """,
            lines=[1, 2, 3, 4, 5, 6, 9],
            branchz="23 24 56 59",
            branchz_missing="24 59",
        )

    def test_optimized_away_if_1_no_else(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if 1:
                b = 3
                c = 4
            d = 5
            """,
            lines=[1, 2, 3, 4, 5],
            branchz="",
            branchz_missing="",
        )

    def test_optimized_if_nested(self) -> None:
        self.check_coverage(
            """\
            a = 1
            if 0:
                if 0:
                    b = 4
                else:
                    c = 6
            else:
                if 0:
                    d = 9
                else:
                    if 0: e = 11
                    f = 12
                    if 0: g = 13
                    h = 14
            i = 15
            """,
            lines=[1, 2, 8, 11, 12, 13, 14, 15],
            branchz="",
            branchz_missing="",
        )

    def test_dunder_debug(self) -> None:
        # Since some of our tests use __debug__, let's make sure it is true as
        # we expect
        assert __debug__
        # Check that executed code has __debug__
        self.check_coverage(
            """\
            assert __debug__, "assert __debug__"
            """,
        )
        # Check that if it didn't have debug, it would let us know.
        with pytest.raises(AssertionError):
            self.check_coverage(
                """\
                assert not __debug__, "assert not __debug__"
                """,
            )

    def test_if_debug(self) -> None:
        self.check_coverage(
            """\
            for value in [True, False]:
                if value:
                    if __debug__:
                        x = 4
                else:
                    x = 6
            """,
            branchz="12 1. 23 26",
            branchz_missing="",
        )

    def test_if_not_debug(self) -> None:
        self.check_coverage(
            """\
            lines = set()
            for value in [True, False]:
                if value:
                    if not __debug__:
                        lines.add(5)
                else:
                    lines.add(7)
            assert lines == {7}
            """,
            branchz="23 28 34 37",
        )


class MiscArcTest(CoverageTest):
    """Miscellaneous arc-measuring tests."""

    def test_dict_literal(self) -> None:
        self.check_coverage(
            """\
            d = {
                'a': 2,
                'b': 3,
                'c': {
                    'd': 5,
                    'e': 6,
                    }
                }
            assert d
            """,
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            d = \\
                { 'a': 2,
                'b': 3,
                'c': {
                    'd': 5,
                    'e': 6,
                    }
                }
            assert d
            """,
            branchz="",
            branchz_missing="",
        )

    def test_unpacked_literals(self) -> None:
        self.check_coverage(
            """\
            d = {
                'a': 2,
                'b': 3,
            }
            weird = {
                **d,
                **{'c': 7},
                'd': 8,
            }
            assert weird['b'] == 3
            """,
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\
            l = [
                2,
                3,
            ]
            weird = [
                *l,
                *[7],
                8,
            ]
            assert weird[1] == 3
            """,
            branchz="",
            branchz_missing="",
        )

    @pytest.mark.parametrize("n", [10, 50, 100, 500, 1000, 2000, 10000])
    def test_pathologically_long_code_object(self, n: int) -> None:
        # https://github.com/coveragepy/coveragepy/issues/359
        # Long code objects sometimes cause problems. Originally, it was
        # due to EXTENDED_ARG bytes codes.  Then it showed a mistake in
        # line-number packing.
        code = (
            """\
            data = [
            """
            + "".join(
                f"""\
                [
                    {i}, {i}, {i}, {i}, {i}, {i}, {i}, {i}, {i}, {i}],
            """
                for i in range(n)
            )
            + """\
            ]

            print(len(data))
            """
        )
        self.check_coverage(code, branchz="")
        assert self.stdout() == f"{n}\n"

    def test_partial_generators(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/475
        # Line 2 is executed completely.
        # Line 3 is started but not finished, because zip ends before it finishes.
        # Line 4 is never started.
        self.check_coverage(
            """\
            def f(a, b):
                c = (i for i in a)          # 2
                d = (j for j in b)          # 3
                e = (k for k in b)          # 4
                return dict(zip(c, d))

            f(['a', 'b'], [1, 2, 3])
            """,
            branchz="",
            branchz_missing="",
        )

    def test_failing_open(self) -> None:
        with mock.patch.object(coverage.python, "open", side_effect=IOError("Nope")):
            self.make_file(
                "some_branches.py",
                """\
                def forelse(seq):
                    for n in seq:
                        if n > 5:
                            break
                    else:
                        print('None of the values were greater than 5')
                    print('Done')
                forelse([1,2])
                """,
            )
            cov = coverage.Coverage(branch=True)
            self.start_import_stop(cov, "some_branches")
            # No assert: the test passes if it didn't raise an exception.


class DecoratorArcTest(CoverageTest):
    """Tests of arcs with decorators."""

    def test_function_decorator(self) -> None:
        self.check_coverage(
            """\
            def decorator(arg):
                def _dec(f):
                    return f
                return _dec

            @decorator(6)
            @decorator(
                len([8]),
            )
            def my_function(
                a=len([11]),
            ):
                x = 13
            a = 14
            my_function()
            """,
            branchz="",
            branchz_missing="",
        )

    def test_class_decorator(self) -> None:
        self.check_coverage(
            """\
            def decorator(arg):
                def _dec(c):
                    return c
                return _dec

            @decorator(6)
            @decorator(
                len([8]),
            )
            class MyObject(
                object
            ):
                X = 13
            a = 14
            """,
            branchz="",
            branchz_missing="",
        )

    def test_bug_466a(self) -> None:
        # A bad interaction between decorators and multi-line list assignments,
        # believe it or not...!
        # This example makes more sense when considered in tandem with 466b below.
        self.check_coverage(
            """\
            class Parser(object):

                @classmethod
                def parse(cls):
                    formats = [ 5 ]


                    return None

            Parser.parse()
            """,
            branchz="",
            branchz_missing="",
        )

    def test_bug_466b(self) -> None:
        # A bad interaction between decorators and multi-line list assignments,
        # believe it or not...!
        self.check_coverage(
            """\
            class Parser(object):

                @classmethod
                def parse(cls):
                    formats = [
                        6,
                    ]
                    return None

            Parser.parse()
            """,
            branchz="",
            branchz_missing="",
        )


class LambdaArcTest(CoverageTest):
    """Tests of lambdas"""

    def test_multiline_lambda(self) -> None:
        self.check_coverage(
            """\
            fn = (lambda x:
                    x + 2
            )
            assert fn(4) == 6
            """,
            branchz="",
            branchz_missing="",
        )
        self.check_coverage(
            """\

            fn = \\
                (
                lambda
                    x:
                    x
                    +
                    8
            )
            assert fn(10) == 18
            """,
            branchz="",
            branchz_missing="",
        )

    def test_unused_lambdas_are_confusing_bug_90(self) -> None:
        self.check_coverage(
            """\
            a = 1
            fn = lambda x: x
            b = 3
            """,
            branchz="",
            branchz_missing="",
        )

    def test_raise_with_lambda_looks_like_partial_branch(self) -> None:
        self.check_coverage(
            """\
            def ouch(fn):
                2/0
            a = b = c = d = 3
            try:
                a = ouch(lambda: 5)
                if a:
                    b = 7
            except ZeroDivisionError:
                c = 9
            d = 10
            assert (a, b, c, d) == (3, 3, 9, 10)
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            missing="6-7",
            branchz="67 6A",
            branchz_missing="67 6A",
        )

    def test_lambda_in_dict(self) -> None:
        self.check_coverage(
            """\
            x = 1
            x = 2
            d = {
                4: lambda: [],
                5: lambda: [],
                6: lambda: [],
                7: lambda: [],
            }

            for k, v in d.items():          # 10
                if k & 1:
                    v()
            """,
            branchz="AB A. BA BC",
            branchz_missing="",
        )


class AsyncTest(CoverageTest):
    """Tests of the new async and await keywords in Python 3.5"""

    def test_async(self) -> None:
        self.check_coverage(
            """\
            import asyncio

            async def compute(x, y):                        # 3
                print(f"Compute {x} + {y} ...")
                await asyncio.sleep(0.001)
                return x + y                                # 6

            async def print_sum(x, y):                      # 8
                result = (0 +
                            await compute(x, y)             # A
                )
                print(f"{x} + {y} = {result}")

            loop = asyncio.new_event_loop()                 # E
            loop.run_until_complete(print_sum(1, 2))
            loop.close()                                    # G
            """,
            branchz="",
            branchz_missing="",
        )
        assert self.stdout() == "Compute 1 + 2 ...\n1 + 2 = 3\n"

    def test_async_for(self) -> None:
        self.check_coverage(
            """\
            import asyncio

            class AsyncIteratorWrapper:                 # 3
                def __init__(self, obj):                # 4
                    self._it = iter(obj)

                def __aiter__(self):                    # 7
                    return self

                async def __anext__(self):              # A
                    try:
                        return next(self._it)
                    except StopIteration:
                        raise StopAsyncIteration

            async def doit():                           # G
                async for letter in AsyncIteratorWrapper("abc"):
                    print(letter)
                print(".")

            loop = asyncio.new_event_loop()             # L
            loop.run_until_complete(doit())
            loop.close()
            """,
            branchz="HI HJ",
            branchz_missing="",
        )
        assert self.stdout() == "a\nb\nc\n.\n"

    def test_async_with(self) -> None:
        self.check_coverage(
            """\
            async def go():
                async with x:
                    pass
            """,
            branchz="",
            branchz_missing="",
        )

    def test_async_decorator(self) -> None:
        self.check_coverage(
            """\
            def wrap(f):        # 1
                return f

            @wrap               # 4
            async def go():
                return
            """,
            branchz="",
            branchz_missing="",
        )

    # https://github.com/coveragepy/coveragepy/issues/1158
    def test_bug_1158(self) -> None:
        self.check_coverage(
            """\
            import asyncio

            async def async_gen():
                yield 4

            async def async_test():
                global a
                a = 8
                async for i in async_gen():
                    print(i + 10)
                else:
                    a = 12

            asyncio.run(async_test())
            assert a == 12
            """,
            branchz="9A 9C",
            branchz_missing="",
        )
        assert self.stdout() == "14\n"

    # https://github.com/coveragepy/coveragepy/issues/1176
    # https://bugs.python.org/issue44622
    def test_bug_1176(self) -> None:
        self.check_coverage(
            """\
            import asyncio

            async def async_gen():
                yield 4

            async def async_test():
                async for i in async_gen():
                    print(i + 8)

            asyncio.run(async_test())
            """,
            branchz="78 7-6",
            branchz_missing="",
        )
        assert self.stdout() == "12\n"

    # https://github.com/coveragepy/coveragepy/issues/1205
    def test_bug_1205(self) -> None:
        self.check_coverage(
            """\
            def func():
                if T(2):
                    if T(3):
                        if F(4):
                            if X(5):
                                return 6
                    else:
                        return 8
                elif X(9) and Y:
                    return 10

            T, F = (lambda _: True), (lambda _: False)
            func()
            """,
            branchz="23 29 34 38 45 4. 56 5. 9A 9.",
            branchz_missing="29 38 45 56 5. 9A 9.",
        )

    def test_bug_1999(self) -> None:
        self.check_coverage(
            """\
            import asyncio

            async def async_range(number):
                for n in range(number):
                    yield n

            async def do_something(number):
                try:
                    async for n in async_range(number):
                        print(n)
                finally:
                    print("Done.")

            asyncio.run(do_something(3))
            """,
            branchz="4-3 45 9A 9C",
            branchz_missing="",
        )
        assert self.stdout() == "0\n1\n2\nDone.\n"

    def test_bug_2124(self) -> None:
        """Test #2124: Coverage doesn't track lines after awaiting cancelled asyncio tasks."""
        # This test specifically targets the Python 3.11 bug where CALL/LINE events
        # are missing after catching CancelledError from an awaited cancelled task.
        # See https://github.com/python/cpython/issues/106749
        self.check_coverage(
            """\
            import asyncio
            from asyncio import CancelledError, create_task

            class TaskManager:
                def __init__(self):
                    self._tasks = []
                    self.cleanup_completed = False

                async def start_tasks(self, count):
                    for i in range(count):
                        self._tasks.append(create_task(self._long_running_task(i)))

                async def _long_running_task(self, task_id):
                    await asyncio.sleep(10)
                    return f"task_{task_id}_done"

                async def cancel_remaining_tasks(self):
                    for task in self._tasks:
                        if not task.done():
                            task.cancel()
                            try:
                                await task
                            except CancelledError:
                                pass  # Swallow the cancellation
                    self._tasks.clear()

                async def stop(self):
                    if self._tasks:
                        await self.cancel_remaining_tasks()
                        self.cleanup_completed = True  # This line must be covered

            async def main():
                manager = TaskManager()
                await manager.start_tasks(5)
                await asyncio.sleep(0.01)
                await manager.stop()
                assert manager.cleanup_completed, "cleanup_completed should be True"
                print(f"cleanup_completed = {manager.cleanup_completed}")

            asyncio.run(main())
            """,
            missing="",
        )
        assert "cleanup_completed = True" in self.stdout()


class AnnotationTest(CoverageTest):
    """Tests using type annotations."""

    def test_annotations(self) -> None:
        self.check_coverage(
            """\
            def f(x:str, y:int) -> str:
                a:int = 2
                return f"{x}, {y}, {a}, 3"
            print(f("x", 4))
            """,
            branchz="",
            branchz_missing="",
        )
        assert self.stdout() == "x, 4, 2, 3\n"


class ExcludeTest(CoverageTest):
    """Tests of exclusions to indicate known partial branches."""

    def test_default(self) -> None:
        # A number of forms of pragma comment are accepted.
        self.check_coverage(
            """\
            a = 1
            if a:   #pragma: no branch
                b = 3
            c = 4
            if c:   # pragma NOBRANCH
                d = 6
            e = 7
            if e:#\tpragma:\tno branch
                f = 9
            import typing
            if typing.TYPE_CHECKING:    # only for mypy
                g = 12
            else:
                h = 14
            """,
            lines=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14],
            missing="",
            branchz="23 24 56 57 89 8A BC BE",
            branchz_missing="",
        )

    def test_custom_pragmas(self) -> None:
        self.check_coverage(
            """\
            a = 1
            while a:    # [only some]
                c = 3
                break
            assert c == 5-2
            """,
            lines=[1, 2, 3, 4, 5],
            partials=["only some"],
            branchz="23 25",
            branchz_missing="",
        )


class LineDataTest(CoverageTest):
    """Tests that line_data gives us what we expect."""

    def test_branch(self) -> None:
        self.make_file(
            "fun1.py",
            """\
            def fun1(x):
                if x == 1:
                    return

            fun1(3)
            """,
        )

        cov = coverage.Coverage(branch=True)
        self.start_import_stop(cov, "fun1")

        data = cov.get_data()
        fun1_lines = sorted_lines(data, abs_file("fun1.py"))
        assert_count_equal(fun1_lines, [1, 2, 5])


class NonPythonFileTest(CoverageTest):
    """Tools like Jinja run code credited to non-Python files."""

    def test_non_python_file(self) -> None:
        # Make a code object with branches, and claim it came from an HTML file.
        # With sysmon, this used to fail trying to parse the source. #2077
        self.make_file("hello.html", "<h1>Hello!</h1>")
        code = textwrap.dedent("""\
            a = 1
            while a:
                c = 3
                break
            assert c == 5 - 2
            """)
        code_obj = compile(code, filename="hello.html", mode="exec")
        cov = coverage.Coverage(branch=True, debug=["trace"])
        with cov.collect():
            exec(code_obj)
