# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Test json-based summary reporting for coverage.py"""

from __future__ import annotations

import json
import os

from datetime import datetime
from typing import Any

import pytest

import coverage
from coverage import Coverage

from tests.coveragetest import UsingModulesMixin, CoverageTest


class JsonReportTest(UsingModulesMixin, CoverageTest):
    """Tests of the JSON reports from coverage.py."""

    def _make_summary(
        self,
        *,
        covered: int,
        missing: int,
        statements: int,
        excluded: int = 0,
        branches: dict[str, int] | None = None,
        precision: int = 0,
    ) -> dict[str, Any]:
        """Build a summary dictionary with consistent formatting."""
        if statements == 0:
            percent_covered = 100.0
            percent_statements_covered = 100.0
        else:
            percent_statements_covered = (covered / statements) * 100
            if branches is None:
                percent_covered = percent_statements_covered
            else:
                total = statements + branches["num_branches"]
                total_covered = covered + branches["covered_branches"]
                percent_covered = (total_covered / total) * 100 if total > 0 else 100.0

        summary: dict[str, Any] = {
            "covered_lines": covered,
            "excluded_lines": excluded,
            "missing_lines": missing,
            "num_statements": statements,
            "percent_covered": percent_covered,
            "percent_covered_display": (
                f"{percent_covered:.{precision}f}"
                if precision > 0
                else str(int(round(percent_covered)))
            ),
            "percent_statements_covered": percent_statements_covered,
            "percent_statements_covered_display": (
                f"{percent_statements_covered:.{precision}f}"
                if precision > 0
                else str(int(round(percent_statements_covered)))
            ),
        }

        if branches is not None:
            num_branches = branches["num_branches"]
            covered_branches = branches["covered_branches"]
            percent_branches_covered = (
                (covered_branches / num_branches * 100) if num_branches > 0 else 100.0
            )

            summary.update(
                {
                    "num_branches": num_branches,
                    "num_partial_branches": branches.get("num_partial_branches", 0),
                    "covered_branches": covered_branches,
                    "missing_branches": branches["missing_branches"],
                    "percent_branches_covered": percent_branches_covered,
                    "percent_branches_covered_display": (
                        f"{percent_branches_covered:.{precision}f}"
                        if precision > 0
                        else str(int(round(percent_branches_covered)))
                    ),
                }
            )

        return summary

    def _make_region(
        self,
        *,
        executed: list[int],
        missing: list[int],
        excluded: list[int],
        start: int,
        branches: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a region (class/function) result dictionary."""
        statements = len(executed) + len(missing)
        covered = len(executed)
        missing_count = len(missing)

        region: dict[str, Any] = {
            "executed_lines": executed,
            "missing_lines": missing,
            "excluded_lines": excluded,
            "start_line": start,
        }

        if branches is not None:
            region["executed_branches"] = branches.get("executed_branches", [])
            region["missing_branches"] = branches.get("missing_branches", [])
            num_branches = len(region["executed_branches"]) + len(region["missing_branches"])
            covered_branches = len(region["executed_branches"])
            summary_branches = {
                "num_branches": num_branches,
                "covered_branches": covered_branches,
                "missing_branches": len(region["missing_branches"]),
                "num_partial_branches": branches.get("num_partial_branches", 0),
            }
        else:
            summary_branches = None

        region["summary"] = self._make_summary(
            covered=covered,
            missing=missing_count,
            statements=statements,
            excluded=len(excluded),
            branches=summary_branches,
        )

        return region

    def _make_file_result(
        self,
        *,
        executed: list[int],
        missing: list[int],
        excluded: list[int],
        regions: dict[str, Any] | None = None,
        branches: dict[str, Any] | None = None,
        contexts: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        """Build a top-level file result dictionary."""
        statements = len(executed) + len(missing)
        covered = len(executed)
        missing_count = len(missing)

        result: dict[str, Any] = {
            "executed_lines": executed,
            "missing_lines": missing,
            "excluded_lines": excluded,
        }

        if branches is not None:
            result["executed_branches"] = branches.get("executed_branches", [])
            result["missing_branches"] = branches.get("missing_branches", [])
            num_branches = len(result["executed_branches"]) + len(result["missing_branches"])
            covered_branches = len(result["executed_branches"])
            summary_branches = {
                "num_branches": num_branches,
                "covered_branches": covered_branches,
                "missing_branches": len(result["missing_branches"]),
                "num_partial_branches": branches.get("num_partial_branches", 0),
            }
        else:
            summary_branches = None

        if contexts is not None:
            result["contexts"] = contexts

        if regions is not None:
            result.update(regions)

        result["summary"] = self._make_summary(
            covered=covered,
            missing=missing_count,
            statements=statements,
            excluded=len(excluded),
            branches=summary_branches,
        )

        return result

    def _assert_json_report(
        self,
        cov: Coverage,
        expected_result: dict[str, Any],
        mod_name: str,
        source_code: str,
    ) -> None:
        """
        Helper that creates a file and compares its JSON report to expected results.
        """
        self.make_file(f"{mod_name}.py", source_code)
        self._compare_json_reports(cov, expected_result, mod_name)

    def _compare_json_reports(
        self,
        cov: Coverage,
        expected_result: dict[str, Any],
        mod_name: str,
    ) -> None:
        """
        Helper that handles common ceremonies, comparing JSON reports that
        it creates to expected results, so tests can clearly show the
        consequences of setting various arguments.
        """
        mod = self.start_import_stop(cov, mod_name)
        output_path = os.path.join(self.temp_dir, f"{mod_name}.json")
        cov.json_report(mod, outfile=output_path)
        with open(output_path, encoding="utf-8") as result_file:
            parsed_result = json.load(result_file)
        self.assert_recent_datetime(
            datetime.strptime(parsed_result["meta"]["timestamp"], "%Y-%m-%dT%H:%M:%S.%f"),
        )
        del parsed_result["meta"]["timestamp"]
        expected_result["meta"].update(
            {
                "version": coverage.__version__,
            }
        )
        assert parsed_result == expected_result

    @pytest.mark.parametrize("branch", [True, False])
    def test_line_and_branch_coverage(self, branch: bool) -> None:
        cov = coverage.Coverage(branch=branch)

        executed_lines = [1, 2, 4, 5, 8]
        missing_lines = [3, 7, 9]

        branch_data = None
        if branch:
            branch_data = {
                "executed_branches": [[2, 4], [4, 5], [8, -1]],
                "missing_branches": [[2, 3], [4, 7], [8, 9]],
                "num_partial_branches": 3,
            }

        a_py_result = self._make_file_result(
            executed=executed_lines,
            missing=missing_lines,
            excluded=[],
            branches=branch_data,
        )

        regions = {
            "classes": {
                "": self._make_region(
                    executed=executed_lines,
                    missing=missing_lines,
                    excluded=[],
                    start=1,
                    branches=branch_data,
                )
            },
            "functions": {
                "": self._make_region(
                    executed=executed_lines,
                    missing=missing_lines,
                    excluded=[],
                    start=1,
                    branches=branch_data,
                )
            },
        }
        if branch:
            regions["classes"][""]["summary"]["percent_covered"] = 57.142857142857146
            regions["functions"][""]["summary"]["percent_covered"] = 57.142857142857146
            a_py_result["summary"]["percent_covered"] = 57.142857142857146
        a_py_result.update(regions)

        totals_branches = None
        if branch:
            totals_branches = {
                "num_branches": 6,
                "covered_branches": 3,
                "missing_branches": 3,
                "num_partial_branches": 3,
            }
        totals = self._make_summary(
            covered=5,
            missing=3,
            statements=8,
            branches=totals_branches,
        )
        if branch:
            totals["percent_covered"] = 57.142857142857146

        expected_result = {
            "meta": {
                "branch_coverage": branch,
                "format": 3,
                "show_contexts": False,
            },
            "files": {"a.py": a_py_result},
            "totals": totals,
        }

        a_py_source = """\
            a = {'b': 1}
            if a.get('a'):
                b = 3
            elif a.get('b'):
                b = 5
            else:
                b = 7
            if not a:
                b = 9
            """

        self._assert_json_report(cov, expected_result, "a", a_py_source)

    @pytest.mark.parametrize("branch", [True, False])
    def test_regions(self, branch: bool) -> None:
        cov = coverage.Coverage(branch=branch)

        d_branch_data: dict[str, Any] | None = None
        empty_branches: dict[str, Any] | None = None
        if branch:
            d_branch_data = {
                "executed_branches": [],
                "missing_branches": [[13, 14], [13, 15]],
            }
            empty_branches = {"executed_branches": [], "missing_branches": []}

        classes = {
            "": self._make_region(
                executed=[2, 4, 8, 9, 11, 12, 16],
                missing=[6],
                excluded=[],
                start=1,
                branches=empty_branches,
            ),
            "C": self._make_region(
                executed=[],
                missing=[],
                excluded=[],
                start=8,
                branches=empty_branches,
            ),
            "D": self._make_region(
                executed=[],
                missing=[13, 14, 15, 17],
                excluded=[],
                start=11,
                branches=d_branch_data,
            ),
        }

        functions = {
            "": self._make_region(
                executed=[2, 4, 8, 9, 11, 12, 16],
                missing=[],
                excluded=[],
                start=1,
                branches=empty_branches,
            ),
            "c": self._make_region(
                executed=[],
                missing=[6],
                excluded=[],
                start=4,
                branches=empty_branches,
            ),
            "D.e": self._make_region(
                executed=[],
                missing=[13, 14, 15],
                excluded=[],
                start=12,
                branches=d_branch_data,
            ),
            "D.f": self._make_region(
                executed=[],
                missing=[17],
                excluded=[],
                start=16,
                branches=empty_branches,
            ),
        }

        file_branch_data = None
        if branch:
            file_branch_data = {
                "executed_branches": [],
                "missing_branches": [[13, 14], [13, 15]],
            }

        b_py_result = self._make_file_result(
            executed=[2, 4, 8, 9, 11, 12, 16],
            missing=[6, 13, 14, 15, 17],
            excluded=[],
            regions={"classes": classes, "functions": functions},
            branches=file_branch_data,
        )

        totals_branches = None
        if branch:
            totals_branches = {
                "num_branches": 2,
                "covered_branches": 0,
                "missing_branches": 2,
                "num_partial_branches": 0,
            }
        totals = self._make_summary(
            covered=7,
            missing=5,
            statements=12,
            branches=totals_branches,
        )

        expected_result = {
            "meta": {
                "branch_coverage": branch,
                "format": 3,
                "show_contexts": False,
            },
            "files": {"b.py": b_py_result},
            "totals": totals,
        }

        b_py_source = """\
            "This is b.py"
            a = {"b": 2}

            def c():
                "This is function c"
                return 6

            class C:
                pass

            class D:
                def e(self):
                    if a.get("a"):
                        return 14
                    return 15
                def f(self):
                    return 17
            """

        self._assert_json_report(cov, expected_result, "b", b_py_source)

    def test_empty_file(self) -> None:
        cov = coverage.Coverage()
        self.make_file("empty.py", "")

        empty_region = self._make_region(executed=[], missing=[], excluded=[], start=1)
        regions = {
            "classes": {"": empty_region},
            "functions": {"": empty_region},
        }

        empty_py_result = self._make_file_result(
            executed=[], missing=[], excluded=[], regions=regions
        )
        totals = self._make_summary(covered=0, missing=0, statements=0)

        expected_result = {
            "meta": {
                "branch_coverage": False,
                "format": 3,
                "show_contexts": False,
            },
            "files": {"empty.py": empty_py_result},
            "totals": totals,
        }

        self._compare_json_reports(cov, expected_result, "empty")

    def run_context_test(self, relative_files: bool) -> None:
        """A helper for context coverage tests."""
        self.make_file(
            "config",
            f"""\
            [run]
            relative_files = {relative_files}

            [report]
            precision = 2

            [json]
            show_contexts = True
            """,
        )
        cov = coverage.Coverage(context="cool_test", config_file="config")

        executed_lines = [1, 2, 4, 5, 8]
        missing_lines = [3, 7, 9]
        contexts = {
            "1": ["cool_test"],
            "2": ["cool_test"],
            "4": ["cool_test"],
            "5": ["cool_test"],
            "8": ["cool_test"],
        }

        a_py_result = self._make_file_result(
            executed=executed_lines,
            missing=missing_lines,
            excluded=[],
            contexts=contexts,
        )

        a_py_result["summary"] = self._make_summary(covered=5, missing=3, statements=8, precision=2)

        region = self._make_region(
            executed=executed_lines, missing=missing_lines, excluded=[], start=1
        )
        region["contexts"] = contexts
        region["summary"] = self._make_summary(covered=5, missing=3, statements=8, precision=2)

        a_py_result["classes"] = {"": region}
        a_py_result["functions"] = {"": region}

        totals = self._make_summary(covered=5, missing=3, statements=8, precision=2)

        expected_result = {
            "meta": {
                "branch_coverage": False,
                "format": 3,
                "show_contexts": True,
            },
            "files": {"a.py": a_py_result},
            "totals": totals,
        }

        a_py_source = """\
            a = {'b': 1}
            if a.get('a'):
                b = 3
            elif a.get('b'):
                b = 5
            else:
                b = 7
            if not a:
                b = 9
            """

        self._assert_json_report(cov, expected_result, "a", a_py_source)

    @pytest.mark.parametrize("relative_files", [True, False])
    def test_context_coverage(self, relative_files: bool) -> None:
        self.run_context_test(relative_files=relative_files)

    def test_l1_equals_l2(self) -> None:
        # In results.py, we had a line checking `if l1 == l2` that was never
        # true.  This test makes it true. The annotations are essential, I
        # don't know why.
        self.make_file(
            "wtf.py",
            """\
            def function(
                x: int,
                y: int,
            ) -> None:
                return x + y

            assert function(3, 5) == 8
            """,
        )
        cov = coverage.Coverage(branch=True)
        mod = self.start_import_stop(cov, "wtf")
        cov.json_report(mod)
