# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""A test base class for tests based on gold file comparison."""

from __future__ import annotations

import difflib
import filecmp
import fnmatch
import os
import os.path
import re
import xml.etree.ElementTree

from collections.abc import Iterable

from tests.coveragetest import TESTS_DIR
from tests.helpers import os_sep


def gold_path(path: str) -> str:
    """Get a path to a gold file for comparison."""
    return os.path.join(TESTS_DIR, "gold", path)


def compare(
    expected_dir: str,
    actual_dir: str,
    file_pattern: str | None = None,
    actual_extra: bool = False,
    scrubs: list[tuple[str, str]] | None = None,
) -> None:
    """Compare files matching `file_pattern` in `expected_dir` and `actual_dir`.

    `actual_extra` true means `actual_dir` can have extra files in it
    without triggering an assertion.

    `scrubs` is a list of pairs: regexes to find and replace to scrub the
    files of unimportant differences.

    If a comparison fails, a message will be written to stdout, the original
    unscrubbed output of the test will be written to an "/actual/" directory
    alongside the "/gold/" directory, and an assertion will be raised.

    """
    __tracebackhide__ = True  # pytest, please don't show me this function.
    assert os_sep("/gold/") in expected_dir
    assert os.path.exists(actual_dir)
    os.makedirs(expected_dir, exist_ok=True)

    dc = filecmp.dircmp(expected_dir, actual_dir)
    diff_files = _fnmatch_list(dc.diff_files, file_pattern)
    expected_only = _fnmatch_list(dc.left_only, file_pattern)
    actual_only = _fnmatch_list(dc.right_only, file_pattern)

    def save_mismatch(f: str) -> None:
        """Save a mismatched result to tests/actual."""
        save_path = expected_dir.replace(os_sep("/gold/"), os_sep("/actual/"))
        os.makedirs(save_path, exist_ok=True)
        save_file = os.path.join(save_path, f)
        with open(save_file, "w", encoding="utf-8") as savef:
            with open(os.path.join(actual_dir, f), encoding="utf-8") as readf:
                savef.write(readf.read())
                print(os_sep(f"Saved actual output to '{save_file}': see tests/gold/README.rst"))

    # filecmp only compares in binary mode, but we want text mode.  So
    # look through the list of different files, and compare them
    # ourselves.
    text_diff = []
    for f in diff_files:
        expected_file = os.path.join(expected_dir, f)
        with open(expected_file, encoding="utf-8") as fobj:
            expected = fobj.read()
        if expected_file.endswith(".xml"):
            expected = canonicalize_xml(expected)

        actual_file = os.path.join(actual_dir, f)
        with open(actual_file, encoding="utf-8") as fobj:
            actual = fobj.read()
        if actual_file.endswith(".xml"):
            actual = canonicalize_xml(actual)

        if scrubs:
            expected = scrub(expected, scrubs)
            actual = scrub(actual, scrubs)
        if expected != actual:
            text_diff.append(f"{expected_file} != {actual_file}")
            expected_lines = expected.splitlines()
            actual_lines = actual.splitlines()
            print(f":::: diff '{expected_file}' and '{actual_file}'")
            print("\n".join(difflib.Differ().compare(expected_lines, actual_lines)))
            print(f":::: end diff '{expected_file}' and '{actual_file}'")
            print(f"==== expected output in '{os.path.abspath(expected_dir)}'")
            print(f"==== actual output in '{os.path.abspath(actual_dir)}'")
            save_mismatch(f)

    if not actual_extra:
        for f in actual_only:
            save_mismatch(f)

    assert not text_diff, "Files differ: " + "\n".join(text_diff)

    assert not expected_only, f"Files in {os.path.abspath(expected_dir)} only: {expected_only}"
    if not actual_extra:
        assert not actual_only, f"Files in {os.path.abspath(actual_dir)} only: {actual_only}"


def contains(filename: str, *strlist: str) -> None:
    """Check that the file contains all of a list of strings.

    An assert will be raised if one of the arguments in `strlist` is
    missing in `filename`.

    """
    __tracebackhide__ = True  # pytest, please don't show me this function.
    with open(filename, encoding="utf-8") as fobj:
        text = fobj.read()
    for s in strlist:
        assert s in text, f"Missing content in {filename}: {s!r}"


def contains_rx(filename: str, *rxlist: str) -> None:
    """Check that the file has lines that re.search all of the regexes.

    An assert will be raised if one of the regexes in `rxlist` doesn't match
    any lines in `filename`.

    """
    __tracebackhide__ = True  # pytest, please don't show me this function.
    with open(filename, encoding="utf-8") as fobj:
        lines = fobj.readlines()
    for rx in rxlist:
        assert any(re.search(rx, line) for line in lines), f"Missing regex in {filename}: r{rx!r}"


def contains_any(filename: str, *strlist: str) -> None:
    """Check that the file contains at least one of a list of strings.

    An assert will be raised if none of the arguments in `strlist` is in
    `filename`.

    """
    __tracebackhide__ = True  # pytest, please don't show me this function.
    with open(filename, encoding="utf-8") as fobj:
        text = fobj.read()
    for s in strlist:
        if s in text:
            return

    assert False, f"Missing content in {filename}: {strlist[0]!r} [1 of {len(strlist)}]"


def doesnt_contain(filename: str, *strlist: str) -> None:
    """Check that the file contains none of a list of strings.

    An assert will be raised if any of the strings in `strlist` appears in
    `filename`.

    """
    __tracebackhide__ = True  # pytest, please don't show me this function.
    with open(filename, encoding="utf-8") as fobj:
        text = fobj.read()
    for s in strlist:
        assert s not in text, f"Forbidden content in {filename}: {s!r}"


# Helpers


def canonicalize_xml(xtext: str) -> str:
    """Canonicalize some XML text."""
    root = xml.etree.ElementTree.fromstring(xtext)
    for node in root.iter():
        node.attrib = dict(sorted(node.items()))
    return xml.etree.ElementTree.tostring(root).decode("utf-8")


def _fnmatch_list(files: list[str], file_pattern: str | None) -> list[str]:
    """Filter the list of `files` to only those that match `file_pattern`.
    If `file_pattern` is None, then return the entire list of files.
    Returns a list of the filtered files.
    """
    if file_pattern:
        files = [f for f in files if fnmatch.fnmatch(f, file_pattern)]
    return files


def scrub(strdata: str, scrubs: Iterable[tuple[str, str]]) -> str:
    """Scrub uninteresting data from the payload in `strdata`.
    `scrubs` is a list of (find, replace) pairs of regexes that are used on
    `strdata`.  A string is returned.
    """
    for rx_find, rx_replace in scrubs:
        strdata = re.sub(rx_find, rx_replace, strdata)
    return strdata
