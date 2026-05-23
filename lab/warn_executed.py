# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
$ python warn_executed.py <coverage_data_file> <config_file>

Find lines that were excluded by "warn-executed" regex patterns
but were actually executed according to coverage data.

The config_file is a TOML file with "warn-executed" and "warn-not-partial"
patterns like:

    warn-executed = [
        "pragma: no cover",
        "# debug",
        "raise NotImplemented",
        ]

    warn-not-partial = [
        "if TYPE_CHECKING:",
    ]

These should be patterns that you excluded as lines or partial branches.

Warning: this program uses internal undocumented private classes from
coverage.py.  This is an unsupported proof-of-concept.

I wrote a blog post about this:
https://nedbatchelder.com/blog/202508/finding_unneeded_pragmas.html

"""

import linecache
import os
import sys
import tomllib

from coverage.parser import PythonParser
from coverage.sqldata import CoverageData
from coverage.results import Analysis


def read_warn_patterns(config_file: str) -> tuple[list[str], list[str]]:
    """Read "warn-executed" and "warn-not-partial" patterns from a TOML config file."""
    with open(config_file, "rb") as f:
        config = tomllib.load(f)

    warn_executed = []
    warn_not_partial = []

    if "warn-executed" in config:
        warn_executed.extend(config["warn-executed"])
    if "warn-not-partial" in config:
        warn_not_partial.extend(config["warn-not-partial"])

    return warn_executed, warn_not_partial


def find_executed_excluded_lines(
    source_file: str,
    coverage_data: CoverageData,
    warn_patterns: list[str],
) -> set[int]:
    """
    Find lines that match warn-executed patterns but were actually executed.

    Args:
        source_file: Path to the Python source file to analyze
        coverage_data: The coverage data object
        warn_patterns: List of regex patterns that should warn if executed

    Returns:
        Set of executed line numbers that matched any pattern
    """
    executed_lines = coverage_data.lines(source_file)
    if executed_lines is None:
        return set()

    executed_lines = set(executed_lines)

    try:
        with open(source_file, "r", encoding="utf-8") as f:
            source_text = f.read()
    except Exception:
        return set()

    parser = PythonParser(text=source_text, filename=source_file)
    parser.parse_source()

    all_executed_excluded = set()
    for pattern in warn_patterns:
        matched_lines = parser.lines_matching(pattern)
        all_executed_excluded.update(matched_lines & executed_lines)

    return all_executed_excluded


def find_not_partial_lines(
    source_file: str,
    coverage_data: CoverageData,
    warn_patterns: list[str],
) -> set[int]:
    """
    Find lines that match warn-not-partial patterns but had both code paths executed.

    Args:
        source_file: Path to the Python source file to analyze
        coverage_data: The coverage data object
        warn_patterns: List of regex patterns for lines expected to be partial

    Returns:
        Set of line numbers that matched patterns but weren't partial
    """
    if not coverage_data.has_arcs():
        return set()

    all_arcs = coverage_data.arcs(source_file)
    if all_arcs is None:
        return set()

    try:
        with open(source_file, "r", encoding="utf-8") as f:
            source_text = f.read()
    except Exception:
        return set()

    parser = PythonParser(text=source_text, filename=source_file)
    parser.parse_source()

    all_possible_arcs = set(parser.arcs())
    executed_arcs = set(all_arcs)

    # Lines with some missing arcs are partial branches
    partial_lines = set()
    for start_line in {arc[0] for arc in all_possible_arcs if arc[0] > 0}:
        possible_from_line = {arc for arc in all_possible_arcs if arc[0] == start_line}
        executed_from_line = {arc for arc in executed_arcs if arc[0] == start_line}
        if executed_from_line and possible_from_line != executed_from_line:
            partial_lines.add(start_line)

    all_not_partial = set()
    for pattern in warn_patterns:
        matched_lines = parser.lines_matching(pattern)
        not_partial = matched_lines - partial_lines
        all_not_partial.update(not_partial)

    return all_not_partial


def analyze_warnings(coverage_file: str, config_file: str) -> dict[str, set[int]]:
    """
    Find lines that match warn-executed or warn-not-partial patterns.

    Args:
        coverage_file: Path to the coverage data file (.coverage)
        config_file: Path to TOML config file with warning patterns

    Returns:
        Dictionary mapping filenames to sets of problematic line numbers
    """
    warn_executed_patterns, warn_not_partial_patterns = read_warn_patterns(config_file)

    if not warn_executed_patterns and not warn_not_partial_patterns:
        return {}

    coverage_data = CoverageData(coverage_file)
    coverage_data.read()

    measured_files = sorted(coverage_data.measured_files())

    all_results = {}
    for source_file in measured_files:
        problem_lines = set()

        if warn_executed_patterns:
            executed_excluded = find_executed_excluded_lines(
                source_file,
                coverage_data,
                warn_executed_patterns,
            )
            problem_lines.update(executed_excluded)

        if warn_not_partial_patterns:
            not_partial = find_not_partial_lines(
                source_file,
                coverage_data,
                warn_not_partial_patterns,
            )
            problem_lines.update(not_partial)

        if problem_lines:
            all_results[source_file] = problem_lines

    return all_results


def main():
    if len(sys.argv) != 3:
        print(__doc__.rstrip())
        return 1

    coverage_file, config_file = sys.argv[1:]
    results = analyze_warnings(coverage_file, config_file)

    for source_file in sorted(results.keys()):
        problem_lines = results[source_file]
        for line_num in sorted(problem_lines):
            line_text = linecache.getline(source_file, line_num).rstrip()
            print(f"{source_file}:{line_num}: {line_text}")


if __name__ == "__main__":
    sys.exit(main())
