# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of behavior common to all reporting."""

from __future__ import annotations

import textwrap

import coverage
from coverage.files import abs_file

from tests.coveragetest import CoverageTest
from tests.goldtest import contains, doesnt_contain
from tests.helpers import arcz_to_arcs, os_sep


class ReportMapsPathsTest(CoverageTest):
    """Check that reporting implicitly maps paths."""

    def make_files(self, data: str, settings: bool = False) -> None:
        """Create the test files we need for line coverage."""
        src = """\
            if VER == 1:
                print("line 2")
            if VER == 2:
                print("line 4")
            if VER == 3:
                print("line 6")
            """
        self.make_file("src/program.py", src)
        self.make_file("ver1/program.py", src)
        self.make_file("ver2/program.py", src)

        if data == "line":
            self.make_data_file(
                lines={
                    abs_file("ver1/program.py"): [1, 2, 3, 5],
                    abs_file("ver2/program.py"): [1, 3, 4, 5],
                },
            )
        else:
            self.make_data_file(
                arcs={
                    abs_file("ver1/program.py"): arcz_to_arcs(".1 12 23 35 5."),
                    abs_file("ver2/program.py"): arcz_to_arcs(".1 13 34 45 5."),
                },
            )

        if settings:
            self.make_file(
                ".coveragerc",
                """\
                [paths]
                source =
                    src
                    ver1
                    ver2
                """,
            )

    def test_map_paths_during_line_report_without_setting(self) -> None:
        self.make_files(data="line")
        cov = coverage.Coverage()
        cov.load()
        cov.report(show_missing=True)
        expected = textwrap.dedent(
            os_sep("""\
            Name              Stmts   Miss  Cover   Missing
            -----------------------------------------------
            ver1/program.py       6      2    67%   4, 6
            ver2/program.py       6      2    67%   2, 6
            -----------------------------------------------
            TOTAL                12      4    67%
            """)
        )
        assert expected == self.stdout()

    def test_map_paths_during_line_report(self) -> None:
        self.make_files(data="line", settings=True)
        cov = coverage.Coverage()
        cov.load()
        cov.report(show_missing=True)
        expected = textwrap.dedent(
            os_sep("""\
            Name             Stmts   Miss  Cover   Missing
            ----------------------------------------------
            src/program.py       6      1    83%   6
            ----------------------------------------------
            TOTAL                6      1    83%
            """)
        )
        assert expected == self.stdout()

    def test_map_paths_during_branch_report_without_setting(self) -> None:
        self.make_files(data="arcs")
        cov = coverage.Coverage(branch=True)
        cov.load()
        cov.report(show_missing=True)
        expected = textwrap.dedent(
            os_sep("""\
            Name              Stmts   Miss Branch BrPart  Cover   Missing
            -------------------------------------------------------------
            ver1/program.py       6      2      6      3    58%   1->3, 4, 6
            ver2/program.py       6      2      6      3    58%   2, 3->5, 6
            -------------------------------------------------------------
            TOTAL                12      4     12      6    58%
            """)
        )
        assert expected == self.stdout()

    def test_map_paths_during_branch_report(self) -> None:
        self.make_files(data="arcs", settings=True)
        cov = coverage.Coverage(branch=True)
        cov.load()
        cov.report(show_missing=True)
        expected = textwrap.dedent(
            os_sep("""\
            Name             Stmts   Miss Branch BrPart  Cover   Missing
            ------------------------------------------------------------
            src/program.py       6      1      6      1    83%   6
            ------------------------------------------------------------
            TOTAL                6      1      6      1    83%
            """)
        )
        assert expected == self.stdout()

    def test_map_paths_during_annotate(self) -> None:
        self.make_files(data="line", settings=True)
        cov = coverage.Coverage()
        cov.load()
        cov.annotate()
        self.assert_exists(os_sep("src/program.py,cover"))
        self.assert_doesnt_exist(os_sep("ver1/program.py,cover"))
        self.assert_doesnt_exist(os_sep("ver2/program.py,cover"))

    def test_map_paths_during_html_report(self) -> None:
        self.make_files(data="line", settings=True)
        cov = coverage.Coverage()
        cov.load()
        cov.html_report()
        contains("htmlcov/index.html", os_sep("src&#8201;/&#8201;program.py"))
        doesnt_contain("htmlcov/index.html", "ver1", "ver2")

    def test_map_paths_during_xml_report(self) -> None:
        self.make_files(data="line", settings=True)
        cov = coverage.Coverage()
        cov.load()
        cov.xml_report()
        contains("coverage.xml", "src/program.py")
        doesnt_contain("coverage.xml", "ver1", "ver2")

    def test_map_paths_during_json_report(self) -> None:
        self.make_files(data="line", settings=True)
        cov = coverage.Coverage()
        cov.load()
        cov.json_report()

        def os_sepj(s: str) -> str:
            return os_sep(s).replace("\\", r"\\")

        contains("coverage.json", os_sepj("src/program.py"))
        doesnt_contain("coverage.json", "ver1", "ver2")

    def test_map_paths_during_lcov_report(self) -> None:
        self.make_files(data="line", settings=True)
        cov = coverage.Coverage()
        cov.load()
        cov.lcov_report()
        contains("coverage.lcov", os_sep("src/program.py"))
        doesnt_contain("coverage.lcov", "ver1", "ver2")


class ReportWithJinjaTest(CoverageTest):
    """Tests of Jinja-like behavior.

    Jinja2 compiles a template into Python code, and then runs the Python code
    to render the template.  But during rendering, it uses the template name
    (for example, "template.j2") as the file name, not the Python code file
    name.  Then during reporting, we will try to parse template.j2 as Python
    code.

    If the file can be parsed, it's included in the report (as a Python file!).
    If it can't be parsed, then it's not included in the report.

    These tests confirm that code doesn't raise an exception (as reported in
    #1553), and that the current (incorrect) behavior remains stable.  Ideally,
    good.j2 wouldn't be listed at all, since we can't report on it accurately.

    See https://github.com/coveragepy/coveragepy/issues/1553 for more detail, and
    https://github.com/coveragepy/coveragepy/issues/1623 for an issue about this
    behavior.

    """

    def make_files(self) -> None:
        """Create test files: two Jinja templates, and data from rendering them."""
        # A Jinja2 file that is syntactically acceptable Python (though it wont run).
        self.make_file(
            "good.j2",
            """\
            {{ data }}
            line2
            line3
            """,
        )
        # A Jinja2 file that is a Python syntax error.
        self.make_file(
            "bad.j2",
            """\
            This is data: {{ data }}.
            line 2
            line 3
            """,
        )
        self.make_data_file(
            lines={
                abs_file("good.j2"): [1, 3, 5, 7, 9],
                abs_file("bad.j2"): [1, 3, 5, 7, 9],
            },
        )

    def test_report(self) -> None:
        self.make_files()
        cov = coverage.Coverage()
        cov.load()
        cov.report(show_missing=True)
        expected = textwrap.dedent("""\
            Name      Stmts   Miss  Cover   Missing
            ---------------------------------------
            good.j2       3      1    67%   2
            ---------------------------------------
            TOTAL         3      1    67%
            """)
        assert expected == self.stdout()

    def test_html(self) -> None:
        self.make_files()
        cov = coverage.Coverage()
        cov.load()
        cov.html_report()
        contains(
            "htmlcov/index.html",
            """\
        <tbody>
            <tr class="region">
                <td class="name"><a href="good_j2.html">good.j2</a></td>
                <td class="spacer">&nbsp;</td>
                <td>3</td>
                <td>1</td>
                <td>0</td>
                <td class="spacer">&nbsp;</td>
                <td data-ratio="2 3">67%</td>
            </tr>
        </tbody>""",
        )
        doesnt_contain("htmlcov/index.html", "bad.j2")

    def test_xml(self) -> None:
        self.make_files()
        cov = coverage.Coverage()
        cov.load()
        cov.xml_report()
        contains("coverage.xml", 'filename="good.j2"')
        contains(
            "coverage.xml",
            '<line number="1" hits="1"/>',
            '<line number="2" hits="0"/>',
            '<line number="3" hits="1"/>',
        )
        doesnt_contain("coverage.xml", 'filename="bad.j2"')
        doesnt_contain("coverage.xml", '<line number="4"')

    def test_json(self) -> None:
        self.make_files()
        cov = coverage.Coverage()
        cov.load()
        cov.json_report()
        contains(
            "coverage.json",
            # Notice the .json report claims lines in good.j2 executed that
            # don't even exist in good.j2...
            '"files": {"good.j2": {"executed_lines": [1, 3, 5, 7, 9], '
            + '"summary": {"covered_lines": 2, "num_statements": 3',
        )
        doesnt_contain("coverage.json", "bad.j2")

    def test_lcov(self) -> None:
        self.make_files()
        cov = coverage.Coverage()
        cov.load()
        cov.lcov_report()
        with open("coverage.lcov", encoding="utf-8") as lcov:
            actual = lcov.read()
        expected = textwrap.dedent("""\
            SF:good.j2
            DA:1,1
            DA:2,0
            DA:3,1
            LF:3
            LH:2
            end_of_record
            """)
        assert expected == actual
