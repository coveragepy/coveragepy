# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Test LCOV-based summary reporting for coverage.py."""

from __future__ import annotations

import math
import textwrap

import coverage

from tests.coveragetest import CoverageTest


class LcovTest(CoverageTest):
    """Tests of the LCOV reports from coverage.py."""

    def create_initial_files(self) -> None:
        """
        Helper for tests that handles the common ceremony so the tests can
        show the consequences of changes in the setup.
        """
        self.make_file(
            "main_file.py",
            """\
            def cuboid_volume(l):
                return (l*l*l)

            def IsItTrue():
                return True
            """,
        )

        self.make_file(
            "test_file.py",
            """\
            from main_file import cuboid_volume
            import unittest

            class TestCuboid(unittest.TestCase):
                def test_volume(self):
                    self.assertAlmostEqual(cuboid_volume(2),8)
                    self.assertAlmostEqual(cuboid_volume(1),1)
                    self.assertAlmostEqual(cuboid_volume(0),0)
                    self.assertAlmostEqual(cuboid_volume(5.5),166.375)
            """,
        )

    def get_lcov_report_content(self, filename: str = "coverage.lcov") -> str:
        """Return the content of an LCOV report."""
        with open(filename, encoding="utf-8") as file:
            return file.read()

    def test_lone_file(self) -> None:
        # For a single file with a couple of functions, the lcov should cover
        # the function definitions themselves, but not the returns.
        self.make_file(
            "main_file.py",
            """\
            def cuboid_volume(l):
                return (l*l*l)

            def IsItTrue():
                return True
            """,
        )
        expected_result = textwrap.dedent("""\
            SF:main_file.py
            DA:1,1
            DA:2,0
            DA:4,1
            DA:5,0
            LF:4
            LH:2
            FN:1,2,cuboid_volume
            FNDA:0,cuboid_volume
            FN:4,5,IsItTrue
            FNDA:0,IsItTrue
            FNF:2
            FNH:0
            end_of_record
            """)
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main_file")
        pct = cov.lcov_report()
        assert pct == 50.0
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_line_checksums(self) -> None:
        self.make_file(
            "main_file.py",
            """\
            def cuboid_volume(l):
                return (l*l*l)

            def IsItTrue():
                return True
            """,
        )
        self.make_file(".coveragerc", "[lcov]\nline_checksums = true\n")
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main_file")
        pct = cov.lcov_report()
        assert pct == 50.0
        expected_result = textwrap.dedent("""\
            SF:main_file.py
            DA:1,1,7URou3io0zReBkk69lEb/Q
            DA:2,0,Xqj6H1iz/nsARMCAbE90ng
            DA:4,1,ilhb4KUfytxtEuClijZPlQ
            DA:5,0,LWILTcvARcydjFFyo9qM0A
            LF:4
            LH:2
            FN:1,2,cuboid_volume
            FNDA:0,cuboid_volume
            FN:4,5,IsItTrue
            FNDA:0,IsItTrue
            FNF:2
            FNH:0
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_simple_line_coverage_two_files(self) -> None:
        # Test that line coverage is created when coverage is run,
        # and matches the output of the file below.
        self.create_initial_files()
        self.assert_doesnt_exist(".coverage")
        self.make_file(".coveragerc", "[lcov]\noutput = data.lcov\n")
        cov = coverage.Coverage(source=".")
        self.start_import_stop(cov, "test_file")
        pct = cov.lcov_report()
        assert pct == 50.0
        self.assert_exists("data.lcov")
        expected_result = textwrap.dedent("""\
            SF:main_file.py
            DA:1,1
            DA:2,0
            DA:4,1
            DA:5,0
            LF:4
            LH:2
            FN:1,2,cuboid_volume
            FNDA:0,cuboid_volume
            FN:4,5,IsItTrue
            FNDA:0,IsItTrue
            FNF:2
            FNH:0
            end_of_record
            SF:test_file.py
            DA:1,1
            DA:2,1
            DA:4,1
            DA:5,1
            DA:6,0
            DA:7,0
            DA:8,0
            DA:9,0
            LF:8
            LH:4
            FN:5,9,TestCuboid.test_volume
            FNDA:0,TestCuboid.test_volume
            FNF:1
            FNH:0
            end_of_record
            """)
        actual_result = self.get_lcov_report_content(filename="data.lcov")
        assert expected_result == actual_result

    def test_branch_coverage_one_file(self) -> None:
        # Test that the reporter produces valid branch coverage.
        self.make_file(
            "main_file.py",
            """\
            def is_it_x(x):
                if x == 3:
                    return x
                else:
                    return False
            """,
        )
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(branch=True, source=".")
        self.start_import_stop(cov, "main_file")
        pct = cov.lcov_report()
        assert math.isclose(pct, 16.666666666666668)
        self.assert_exists("coverage.lcov")
        expected_result = textwrap.dedent("""\
            SF:main_file.py
            DA:1,1
            DA:2,0
            DA:3,0
            DA:5,0
            LF:4
            LH:1
            FN:1,5,is_it_x
            FNDA:0,is_it_x
            FNF:1
            FNH:0
            BRDA:2,0,jump to line 3,-
            BRDA:2,0,jump to line 5,-
            BRF:2
            BRH:0
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_branch_coverage_two_files(self) -> None:
        # Test that valid branch coverage is generated
        # in the case of two files.
        self.make_file(
            "main_file.py",
            """\
            def is_it_x(x):
                if x == 3:
                    return x
                else:
                    return False
            """,
        )

        self.make_file(
            "test_file.py",
            """\
            from main_file import *
            import unittest

            class TestIsItX(unittest.TestCase):
                def test_is_it_x(self):
                    self.assertEqual(is_it_x(3), 3)
                    self.assertEqual(is_it_x(4), False)
            """,
        )
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(branch=True, source=".")
        self.start_import_stop(cov, "test_file")
        pct = cov.lcov_report()
        assert math.isclose(pct, 41.666666666666664)
        self.assert_exists("coverage.lcov")
        expected_result = textwrap.dedent("""\
            SF:main_file.py
            DA:1,1
            DA:2,0
            DA:3,0
            DA:5,0
            LF:4
            LH:1
            FN:1,5,is_it_x
            FNDA:0,is_it_x
            FNF:1
            FNH:0
            BRDA:2,0,jump to line 3,-
            BRDA:2,0,jump to line 5,-
            BRF:2
            BRH:0
            end_of_record
            SF:test_file.py
            DA:1,1
            DA:2,1
            DA:4,1
            DA:5,1
            DA:6,0
            DA:7,0
            LF:6
            LH:4
            FN:5,7,TestIsItX.test_is_it_x
            FNDA:0,TestIsItX.test_is_it_x
            FNF:1
            FNH:0
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_half_covered_branch(self) -> None:
        # Test that for a given branch that is only half covered,
        # the block numbers remain the same, and produces valid lcov.
        self.make_file(
            "main_file.py",
            """\
            something = True

            if something:
                print("Yes, something")
            else:
                print("No, nothing")
            """,
        )
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(branch=True, source=".")
        self.start_import_stop(cov, "main_file")
        pct = cov.lcov_report()
        assert math.isclose(pct, 66.66666666666667)
        self.assert_exists("coverage.lcov")
        expected_result = textwrap.dedent("""\
            SF:main_file.py
            DA:1,1
            DA:3,1
            DA:4,1
            DA:6,0
            LF:4
            LH:3
            BRDA:3,0,jump to line 4,1
            BRDA:3,0,jump to line 6,0
            BRF:2
            BRH:1
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_empty_init_files(self) -> None:
        # Test that an empty __init__.py still generates a (vacuous)
        # coverage record.
        self.make_file("__init__.py", "")
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(branch=True, source=".")
        self.start_import_stop(cov, "__init__")
        pct = cov.lcov_report()
        assert pct == 0.0
        self.assert_exists("coverage.lcov")
        expected_result = textwrap.dedent("""\
            SF:__init__.py
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_empty_init_file_skipped(self) -> None:
        # Test that the lcov reporter honors skip_empty.  Because skip_empty
        # keys off the overall number of lines of code, the result in this
        # case will be the same regardless of the age of the Python interpreter.
        self.make_file("__init__.py", "")
        self.make_file(".coveragerc", "[report]\nskip_empty = True\n")
        self.assert_doesnt_exist(".coverage")
        cov = coverage.Coverage(branch=True, source=".")
        self.start_import_stop(cov, "__init__")
        pct = cov.lcov_report()
        assert pct == 0.0
        self.assert_exists("coverage.lcov")
        expected_result = ""
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_excluded_lines(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [report]
            exclude_lines = foo
            """,
        )
        self.make_file(
            "runme.py",
            """\
            s = "Hello 1"
            t = "foo is ignored 2"
            if s.upper() == "BYE 3":
                i_am_missing_4()
                foo_is_missing_5()
            print("Done 6")
            # foo 7
            # line 8
            """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "runme")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:runme.py
            DA:1,1
            DA:3,1
            DA:4,0
            DA:6,1
            LF:4
            LH:3
            BRDA:3,0,jump to line 4,0
            BRDA:3,0,jump to line 6,1
            BRF:2
            BRH:1
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_exit_branches(self) -> None:
        self.make_file(
            "runme.py",
            """\
            def foo(a):
                if a:
                    print(f"{a!r} is truthy")
            foo(True)
            foo(False)
            foo([])
            foo([0])
        """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "runme")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:runme.py
            DA:1,1
            DA:2,1
            DA:3,1
            DA:4,1
            DA:5,1
            DA:6,1
            DA:7,1
            LF:7
            LH:7
            FN:1,3,foo
            FNDA:1,foo
            FNF:1
            FNH:1
            BRDA:2,0,jump to line 3,1
            BRDA:2,0,return from function 'foo',1
            BRF:2
            BRH:2
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_genexpr_exit_arcs_pruned_full_coverage(self) -> None:
        self.make_file(
            "runme.py",
            """\
            def foo(a):
                if any(x > 0 for x in a):
                    print(f"{a!r} has positives")
            foo([])
            foo([0])
            foo([0,1])
            foo([0,-1])
        """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "runme")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:runme.py
            DA:1,1
            DA:2,1
            DA:3,1
            DA:4,1
            DA:5,1
            DA:6,1
            DA:7,1
            LF:7
            LH:7
            FN:1,3,foo
            FNDA:1,foo
            FNF:1
            FNH:1
            BRDA:2,0,jump to line 3,1
            BRDA:2,0,return from function 'foo',1
            BRF:2
            BRH:2
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_genexpr_exit_arcs_pruned_never_true(self) -> None:
        self.make_file(
            "runme.py",
            """\
            def foo(a):
                if any(x > 0 for x in a):
                    print(f"{a!r} has positives")
            foo([])
            foo([0])
        """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "runme")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:runme.py
            DA:1,1
            DA:2,1
            DA:3,0
            DA:4,1
            DA:5,1
            LF:5
            LH:4
            FN:1,3,foo
            FNDA:1,foo
            FNF:1
            FNH:1
            BRDA:2,0,jump to line 3,0
            BRDA:2,0,return from function 'foo',1
            BRF:2
            BRH:1
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_genexpr_exit_arcs_pruned_always_true(self) -> None:
        self.make_file(
            "runme.py",
            """\
            def foo(a):
                if any(x > 0 for x in a):
                    print(f"{a!r} has positives")
            foo([1])
            foo([1,2])
        """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "runme")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:runme.py
            DA:1,1
            DA:2,1
            DA:3,1
            DA:4,1
            DA:5,1
            LF:5
            LH:5
            FN:1,3,foo
            FNDA:1,foo
            FNF:1
            FNH:1
            BRDA:2,0,jump to line 3,1
            BRDA:2,0,return from function 'foo',0
            BRF:2
            BRH:1
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_genexpr_exit_arcs_pruned_not_reached(self) -> None:
        self.make_file(
            "runme.py",
            """\
            def foo(a):
                if any(x > 0 for x in a):
                    print(f"{a!r} has positives")
        """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "runme")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:runme.py
            DA:1,1
            DA:2,0
            DA:3,0
            LF:3
            LH:1
            FN:1,3,foo
            FNDA:0,foo
            FNF:1
            FNH:0
            BRDA:2,0,jump to line 3,-
            BRDA:2,0,return from function 'foo',-
            BRF:2
            BRH:0
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_always_raise(self) -> None:
        self.make_file(
            "always_raise.py",
            """\
            try:
                if not_defined:
                    print("Yes")
                else:
                    print("No")
            except Exception:
                pass
        """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "always_raise")
        cov.lcov_report()
        expected_result = textwrap.dedent("""\
            SF:always_raise.py
            DA:1,1
            DA:2,1
            DA:3,0
            DA:5,0
            DA:6,1
            DA:7,1
            LF:6
            LH:4
            BRDA:2,0,jump to line 3,-
            BRDA:2,0,jump to line 5,-
            BRF:2
            BRH:0
            end_of_record
            """)
        actual_result = self.get_lcov_report_content()
        assert expected_result == actual_result

    def test_multiline_conditions(self) -> None:
        self.make_file(
            "multi.py",
            """\
            def fun(x):
                if (
                    x
                ):
                    print("got here")
            """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "multi")
        cov.lcov_report()
        lcov = self.get_lcov_report_content()
        assert "BRDA:2,0,return from function 'fun',-" in lcov

    def test_module_exit(self) -> None:
        self.make_file(
            "modexit.py",
            """\
            #! /usr/bin/env python
            def foo():
                return bar(
                )
            if "x" == "y":  # line 5
                foo()
            """,
        )
        cov = coverage.Coverage(source=".", branch=True)
        self.start_import_stop(cov, "modexit")
        cov.lcov_report()
        lcov = self.get_lcov_report_content()
        print(lcov)
        assert "BRDA:5,0,exit the module,1" in lcov
