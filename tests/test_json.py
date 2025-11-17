# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Test json-based summary reporting for coverage.py"""

from __future__ import annotations

import copy
import json
import os

from datetime import datetime
from typing import Any

import coverage
from coverage import Coverage

from tests.coveragetest import UsingModulesMixin, CoverageTest


class JsonReportTest(UsingModulesMixin, CoverageTest):
    """Tests of the JSON reports from coverage.py."""

    def _assert_expected_json_report(
        self,
        cov: Coverage,
        expected_result: dict[str, Any],
    ) -> None:
        """
        Helper that creates an example file for most tests.
        """
        self.make_file(
            "a.py",
            """\
            a = {'b': 1}
            if a.get('a'):
                b = 3
            elif a.get('b'):
                b = 5
            else:
                b = 7
            if not a:
                b = 9
            """,
        )
        self._compare_json_reports(cov, expected_result, "a")

    def _assert_expected_json_report_with_regions(
        self,
        cov: Coverage,
        expected_result: dict[str, Any],
    ) -> None:
        """
        Helper that creates an example file for regions tests.
        """
        self.make_file(
            "b.py",
            """\
            a = {"b": 1}

            def c():
                return 4

            class C:
                pass

            class D:
                def e(self):
                    if a.get("a"):
                        return 12
                    return 13
                def f(self):
                    return 15
            """,
        )
        self._compare_json_reports(cov, expected_result, "b")

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

    def test_branch_coverage(self) -> None:
        cov = coverage.Coverage(branch=True)
        a_py_result = {
            "executed_lines": [1, 2, 4, 5, 8],
            "missing_lines": [3, 7, 9],
            "excluded_lines": [],
            "executed_branches": [
                [2, 4],
                [4, 5],
                [8, -1],
            ],
            "missing_branches": [
                [2, 3],
                [4, 7],
                [8, 9],
            ],
            "summary": {
                "missing_lines": 3,
                "covered_lines": 5,
                "num_statements": 8,
                "num_branches": 6,
                "excluded_lines": 0,
                "num_partial_branches": 3,
                "covered_branches": 3,
                "missing_branches": 3,
                "percent_covered": 57.142857142857146,
                "percent_covered_display": "57",
                "percent_statements_covered": 62.5,
                "percent_statements_covered_display": "62",
                "percent_branches_covered": 50.0,
                "percent_branches_covered_display": "50",
            },
        }
        expected_result = {
            "meta": {
                "branch_coverage": True,
                "format": 3,
                "show_contexts": False,
            },
            "files": {
                "a.py": copy.deepcopy(a_py_result),
            },
            "totals": {
                "missing_lines": 3,
                "covered_lines": 5,
                "num_statements": 8,
                "num_branches": 6,
                "excluded_lines": 0,
                "num_partial_branches": 3,
                "percent_covered": 57.142857142857146,
                "percent_covered_display": "57",
                "covered_branches": 3,
                "missing_branches": 3,
                "percent_statements_covered": 62.5,
                "percent_statements_covered_display": "62",
                "percent_branches_covered": 50.0,
                "percent_branches_covered_display": "50",
            },
        }
        # With regions, a lot of data is duplicated.
        expected_result["files"]["a.py"]["classes"] = {"": a_py_result}  # type: ignore[index]
        expected_result["files"]["a.py"]["functions"] = {"": a_py_result}  # type: ignore[index]
        self._assert_expected_json_report(cov, expected_result)

    def test_simple_line_coverage(self) -> None:
        cov = coverage.Coverage()
        a_py_result = {
            "executed_lines": [1, 2, 4, 5, 8],
            "missing_lines": [3, 7, 9],
            "excluded_lines": [],
            "summary": {
                "excluded_lines": 0,
                "missing_lines": 3,
                "covered_lines": 5,
                "num_statements": 8,
                "percent_covered": 62.5,
                "percent_covered_display": "62",
                "percent_statements_covered": 62.5,
                "percent_statements_covered_display": "62",
            },
        }
        expected_result = {
            "meta": {
                "branch_coverage": False,
                "format": 3,
                "show_contexts": False,
            },
            "files": {
                "a.py": copy.deepcopy(a_py_result),
            },
            "totals": {
                "excluded_lines": 0,
                "missing_lines": 3,
                "covered_lines": 5,
                "num_statements": 8,
                "percent_covered": 62.5,
                "percent_covered_display": "62",
                "percent_statements_covered": 62.5,
                "percent_statements_covered_display": "62",
            },
        }
        # With regions, a lot of data is duplicated.
        expected_result["files"]["a.py"]["classes"] = {"": a_py_result}  # type: ignore[index]
        expected_result["files"]["a.py"]["functions"] = {"": a_py_result}  # type: ignore[index]
        self._assert_expected_json_report(cov, expected_result)

    def test_regions_coverage(self) -> None:
        cov = coverage.Coverage()
        expected_result = {
            "files": {
                "b.py": {
                    "classes": {
                        "": {
                            "excluded_lines": [],
                            "executed_lines": [1, 3, 6, 7, 9, 10, 14],
                            "missing_lines": [4],
                            "summary": {
                                "covered_lines": 7,
                                "excluded_lines": 0,
                                "missing_lines": 1,
                                "num_statements": 8,
                                "percent_covered": 87.5,
                                "percent_covered_display": "88",
                                "percent_statements_covered": 87.5,
                                "percent_statements_covered_display": "88",
                            },
                        },
                        "C": {
                            "excluded_lines": [],
                            "executed_lines": [],
                            "missing_lines": [],
                            "summary": {
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_lines": 0,
                                "num_statements": 0,
                                "percent_covered": 100.0,
                                "percent_covered_display": "100",
                                "percent_statements_covered": 100.0,
                                "percent_statements_covered_display": "100",
                            },
                        },
                        "D": {
                            "executed_lines": [],
                            "excluded_lines": [],
                            "missing_lines": [11, 12, 13, 15],
                            "summary": {
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_lines": 4,
                                "num_statements": 4,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                            },
                        },
                    },
                    "executed_lines": [1, 3, 6, 7, 9, 10, 14],
                    "excluded_lines": [],
                    "functions": {
                        "": {
                            "excluded_lines": [],
                            "executed_lines": [1, 3, 6, 7, 9, 10, 14],
                            "missing_lines": [],
                            "summary": {
                                "covered_lines": 7,
                                "excluded_lines": 0,
                                "missing_lines": 0,
                                "num_statements": 7,
                                "percent_covered": 100.0,
                                "percent_covered_display": "100",
                                "percent_statements_covered": 100.0,
                                "percent_statements_covered_display": "100",
                            },
                        },
                        "c": {
                            "executed_lines": [],
                            "excluded_lines": [],
                            "missing_lines": [4],
                            "summary": {
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_lines": 1,
                                "num_statements": 1,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                            },
                        },
                        "D.e": {
                            "executed_lines": [],
                            "excluded_lines": [],
                            "missing_lines": [11, 12, 13],
                            "summary": {
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_lines": 3,
                                "num_statements": 3,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                            },
                        },
                        "D.f": {
                            "executed_lines": [],
                            "excluded_lines": [],
                            "missing_lines": [15],
                            "summary": {
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_lines": 1,
                                "num_statements": 1,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                            },
                        },
                    },
                    "missing_lines": [4, 11, 12, 13, 15],
                    "summary": {
                        "covered_lines": 7,
                        "excluded_lines": 0,
                        "missing_lines": 5,
                        "num_statements": 12,
                        "percent_covered": 58.333333333333336,
                        "percent_covered_display": "58",
                        "percent_statements_covered": 58.333333333333336,
                        "percent_statements_covered_display": "58",
                    },
                },
            },
            "meta": {
                "branch_coverage": False,
                "format": 3,
                "show_contexts": False,
            },
            "totals": {
                "covered_lines": 7,
                "excluded_lines": 0,
                "missing_lines": 5,
                "num_statements": 12,
                "percent_covered": 58.333333333333336,
                "percent_covered_display": "58",
                "percent_statements_covered": 58.333333333333336,
                "percent_statements_covered_display": "58",
            },
        }
        self._assert_expected_json_report_with_regions(cov, expected_result)

    def test_branch_regions_coverage(self) -> None:
        cov = coverage.Coverage(branch=True)
        expected_result = {
            "files": {
                "b.py": {
                    "classes": {
                        "": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [1, 3, 6, 7, 9, 10, 14],
                            "missing_branches": [],
                            "missing_lines": [4],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 7,
                                "excluded_lines": 0,
                                "missing_branches": 0,
                                "missing_lines": 1,
                                "num_branches": 0,
                                "num_partial_branches": 0,
                                "num_statements": 8,
                                "percent_covered": 87.5,
                                "percent_covered_display": "88",
                                "percent_statements_covered": 87.5,
                                "percent_statements_covered_display": "88",
                                "percent_branches_covered": 100.0,
                                "percent_branches_covered_display": "100",
                            },
                        },
                        "C": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [],
                            "missing_branches": [],
                            "missing_lines": [],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_branches": 0,
                                "missing_lines": 0,
                                "num_branches": 0,
                                "num_partial_branches": 0,
                                "num_statements": 0,
                                "percent_covered": 100.0,
                                "percent_covered_display": "100",
                                "percent_statements_covered": 100.0,
                                "percent_statements_covered_display": "100",
                                "percent_branches_covered": 100.0,
                                "percent_branches_covered_display": "100",
                            },
                        },
                        "D": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [],
                            "missing_branches": [[11, 12], [11, 13]],
                            "missing_lines": [11, 12, 13, 15],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_branches": 2,
                                "missing_lines": 4,
                                "num_branches": 2,
                                "num_partial_branches": 0,
                                "num_statements": 4,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                                "percent_branches_covered": 0.0,
                                "percent_branches_covered_display": "0",
                            },
                        },
                    },
                    "excluded_lines": [],
                    "executed_branches": [],
                    "executed_lines": [1, 3, 6, 7, 9, 10, 14],
                    "functions": {
                        "": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [1, 3, 6, 7, 9, 10, 14],
                            "missing_branches": [],
                            "missing_lines": [],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 7,
                                "excluded_lines": 0,
                                "missing_branches": 0,
                                "missing_lines": 0,
                                "num_branches": 0,
                                "num_partial_branches": 0,
                                "num_statements": 7,
                                "percent_covered": 100.0,
                                "percent_covered_display": "100",
                                "percent_statements_covered": 100.0,
                                "percent_statements_covered_display": "100",
                                "percent_branches_covered": 100.0,
                                "percent_branches_covered_display": "100",
                            },
                        },
                        "D.e": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [],
                            "missing_branches": [[11, 12], [11, 13]],
                            "missing_lines": [11, 12, 13],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_branches": 2,
                                "missing_lines": 3,
                                "num_branches": 2,
                                "num_partial_branches": 0,
                                "num_statements": 3,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                                "percent_branches_covered": 0.0,
                                "percent_branches_covered_display": "0",
                            },
                        },
                        "D.f": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [],
                            "missing_branches": [],
                            "missing_lines": [15],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_branches": 0,
                                "missing_lines": 1,
                                "num_branches": 0,
                                "num_partial_branches": 0,
                                "num_statements": 1,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                                "percent_branches_covered": 100.0,
                                "percent_branches_covered_display": "100",
                            },
                        },
                        "c": {
                            "excluded_lines": [],
                            "executed_branches": [],
                            "executed_lines": [],
                            "missing_branches": [],
                            "missing_lines": [4],
                            "summary": {
                                "covered_branches": 0,
                                "covered_lines": 0,
                                "excluded_lines": 0,
                                "missing_branches": 0,
                                "missing_lines": 1,
                                "num_branches": 0,
                                "num_partial_branches": 0,
                                "num_statements": 1,
                                "percent_covered": 0.0,
                                "percent_covered_display": "0",
                                "percent_statements_covered": 0.0,
                                "percent_statements_covered_display": "0",
                                "percent_branches_covered": 100.0,
                                "percent_branches_covered_display": "100",
                            },
                        },
                    },
                    "missing_branches": [[11, 12], [11, 13]],
                    "missing_lines": [4, 11, 12, 13, 15],
                    "summary": {
                        "covered_branches": 0,
                        "covered_lines": 7,
                        "excluded_lines": 0,
                        "missing_branches": 2,
                        "missing_lines": 5,
                        "num_branches": 2,
                        "num_partial_branches": 0,
                        "num_statements": 12,
                        "percent_covered": 50.0,
                        "percent_covered_display": "50",
                        "percent_statements_covered": 58.333333333333336,
                        "percent_statements_covered_display": "58",
                        "percent_branches_covered": 0.0,
                        "percent_branches_covered_display": "0",
                    },
                },
            },
            "meta": {
                "branch_coverage": True,
                "format": 3,
                "show_contexts": False,
            },
            "totals": {
                "covered_branches": 0,
                "covered_lines": 7,
                "excluded_lines": 0,
                "missing_branches": 2,
                "missing_lines": 5,
                "num_branches": 2,
                "num_partial_branches": 0,
                "num_statements": 12,
                "percent_covered": 50.0,
                "percent_covered_display": "50",
                "percent_statements_covered": 58.333333333333336,
                "percent_statements_covered_display": "58",
                "percent_branches_covered": 0.0,
                "percent_branches_covered_display": "0",
            },
        }
        self._assert_expected_json_report_with_regions(cov, expected_result)

    def run_context_test(self, relative_files: bool) -> None:
        """A helper for two tests below."""
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
        a_py_result = {
            "executed_lines": [1, 2, 4, 5, 8],
            "missing_lines": [3, 7, 9],
            "excluded_lines": [],
            "contexts": {
                "1": ["cool_test"],
                "2": ["cool_test"],
                "4": ["cool_test"],
                "5": ["cool_test"],
                "8": ["cool_test"],
            },
            "summary": {
                "excluded_lines": 0,
                "missing_lines": 3,
                "covered_lines": 5,
                "num_statements": 8,
                "percent_covered": 62.5,
                "percent_covered_display": "62.50",
                "percent_statements_covered": 62.5,
                "percent_statements_covered_display": "62.50",
            },
        }
        expected_result = {
            "meta": {
                "branch_coverage": False,
                "format": 3,
                "show_contexts": True,
            },
            "files": {
                "a.py": copy.deepcopy(a_py_result),
            },
            "totals": {
                "excluded_lines": 0,
                "missing_lines": 3,
                "covered_lines": 5,
                "num_statements": 8,
                "percent_covered": 62.5,
                "percent_covered_display": "62.50",
                "percent_statements_covered": 62.5,
                "percent_statements_covered_display": "62.50",
            },
        }
        # With regions, a lot of data is duplicated.
        expected_result["files"]["a.py"]["classes"] = {"": a_py_result}  # type: ignore[index]
        expected_result["files"]["a.py"]["functions"] = {"": a_py_result}  # type: ignore[index]
        self._assert_expected_json_report(cov, expected_result)

    def test_context_non_relative(self) -> None:
        self.run_context_test(relative_files=False)

    def test_context_relative(self) -> None:
        self.run_context_test(relative_files=True)

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
