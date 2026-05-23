# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of the helpers in goldtest.py"""

from __future__ import annotations

import os.path
import re

import pytest

from tests.coveragetest import CoverageTest, TESTS_DIR
from tests.goldtest import compare, gold_path
from tests.goldtest import contains, contains_any, contains_rx, doesnt_contain
from tests.helpers import os_sep, re_line, remove_tree

GOOD_GETTY = """\
Four score and seven years ago our fathers brought forth upon this continent, a
new nation, conceived in Liberty, and dedicated to the proposition that all men
are created equal.
11/19/9999, Gettysburg, Pennsylvania
"""

BAD_GETTY = """\
Five score and seven years ago our fathers brought forth upon this continent, a
new nation, conceived in Liberty, and dedicated to the proposition that all men
are created equal.
333/4444/55555, Gabcdef, Pennsylvania
"""

SCRUBS = [
    # Numbers don't matter when comparing.
    (r"\d+", "D"),
    (r"G\w+", "Gxxx"),
]


def path_regex(path: str) -> str:
    """Convert a file path into a regex that will match that path on any OS."""
    return re.sub(r"[/\\]", r"[/\\\\]", path.replace(".", "[.]"))


ACTUAL_DIR = os.path.join(TESTS_DIR, "actual/testing")
ACTUAL_GETTY_FILE = os.path.join(ACTUAL_DIR, "getty/gettysburg.txt")
GOLD_GETTY_FILE = os.path.join(TESTS_DIR, "gold/testing/getty/gettysburg.txt")
GOLD_GETTY_FILE_RX = path_regex(GOLD_GETTY_FILE)

GOLD_PATH_RX = path_regex("/tests/gold/testing/getty/gettysburg.txt")
OUT_PATH_RX = path_regex("out/gettysburg.txt")


@pytest.mark.xdist_group(name="compare_test")
class CompareTest(CoverageTest):
    """Tests of goldtest.py:compare()"""

    def setUp(self) -> None:
        super().setUp()
        self.addCleanup(remove_tree, ACTUAL_DIR)

    def test_good(self) -> None:
        self.make_file("out/gettysburg.txt", GOOD_GETTY)
        compare(gold_path("testing/getty"), "out", scrubs=SCRUBS)
        self.assert_doesnt_exist(ACTUAL_GETTY_FILE)

    def test_bad(self) -> None:
        self.make_file("out/gettysburg.txt", BAD_GETTY)

        # compare() raises an assertion.
        msg = rf"Files differ: .*{GOLD_PATH_RX} != {OUT_PATH_RX}"
        with pytest.raises(AssertionError, match=msg):
            compare(gold_path("testing/getty"), "out", scrubs=SCRUBS)

        # Stdout has a description of the diff.  The diff shows the scrubbed content.
        stdout = self.stdout()
        assert "- Four score" in stdout
        assert "+ Five score" in stdout
        assert re_line(rf"^:::: diff '.*{GOLD_PATH_RX}' and '{OUT_PATH_RX}'", stdout)
        assert re_line(rf"^:::: end diff '.*{GOLD_PATH_RX}' and '{OUT_PATH_RX}'", stdout)
        assert os_sep(
            f"Saved actual output to '{ACTUAL_GETTY_FILE}': see tests/gold/README.rst"
        ) in os_sep(stdout)
        assert "  D/D/D, Gxxx, Pennsylvania" in stdout

        # The actual file was saved.
        with open(ACTUAL_GETTY_FILE, encoding="utf-8") as f:
            saved = f.read()
        assert saved == BAD_GETTY

    def test_good_needs_scrubs(self) -> None:
        # Comparing the "good" result without scrubbing the variable parts will fail.
        self.make_file("out/gettysburg.txt", GOOD_GETTY)

        # compare() raises an assertion.
        msg = rf"Files differ: .*{GOLD_PATH_RX} != {OUT_PATH_RX}"
        with pytest.raises(AssertionError, match=msg):
            compare(gold_path("testing/getty"), "out")

        stdout = self.stdout()
        assert "- 11/19/1863, Gettysburg, Pennsylvania" in stdout
        assert "+ 11/19/9999, Gettysburg, Pennsylvania" in stdout

    def test_actual_extra(self) -> None:
        self.make_file("out/gettysburg.txt", GOOD_GETTY)
        self.make_file("out/another.more", "hi")

        # Extra files in the output are ok with actual_extra=True.
        compare(gold_path("testing/getty"), "out", scrubs=SCRUBS, actual_extra=True)

        # But not without it:
        # (test output is in files like /tmp/pytest-of-user/pytest-0/popen-gw3/t76/out)
        msg = r"Files in .*[/\\]t\d+[/\\]out only: \['another.more'\]"
        with pytest.raises(AssertionError, match=msg):
            compare(gold_path("testing/getty"), "out", scrubs=SCRUBS)
        self.assert_exists(os.path.join(TESTS_DIR, "actual/testing/getty/another.more"))

        # But only the files matching the file_pattern are considered.
        compare(gold_path("testing/getty"), "out", file_pattern="*.txt", scrubs=SCRUBS)

    def test_xml_good(self) -> None:
        self.make_file(
            "out/output.xml",
            """\
            <?xml version="1.0" ?>
            <the_root c="three" b="222" a="one">
                <also z="nine" x="seven" y="888">
                    Goodie
                </also>
            </the_root>
            """,
        )
        compare(gold_path("testing/xml"), "out", scrubs=SCRUBS)

    def test_xml_bad(self) -> None:
        self.make_file(
            "out/output.xml",
            """\
            <?xml version="1.0" ?>
            <the_root c="nine" b="2" a="one">
                <also z="three" x="seven" y="8">
                    Goodbye
                </also>
            </the_root>
            """,
        )

        # compare() raises an exception.
        gold_rx = path_regex(gold_path("testing/xml/output.xml"))
        out_rx = path_regex("out/output.xml")
        msg = rf"Files differ: .*{gold_rx} != {out_rx}"
        with pytest.raises(AssertionError, match=msg):
            compare(gold_path("testing/xml"), "out", scrubs=SCRUBS)

        # Stdout has a description of the diff.  The diff shows the
        # canonicalized and scrubbed content.
        stdout = self.stdout()
        assert '- <the_root a="one" b="D" c="three">' in stdout
        assert '+ <the_root a="one" b="D" c="nine">' in stdout


class ContainsTest(CoverageTest):
    """Tests of the various "contains" functions in goldtest.py"""

    run_in_temp_dir = False

    def test_contains(self) -> None:
        contains(GOLD_GETTY_FILE, "Four", "fathers", "dedicated")
        msg = rf"Missing content in {GOLD_GETTY_FILE_RX}: 'xyzzy'"
        with pytest.raises(AssertionError, match=msg):
            contains(GOLD_GETTY_FILE, "Four", "fathers", "xyzzy", "dedicated")

    def test_contains_rx(self) -> None:
        contains_rx(GOLD_GETTY_FILE, r"Fo.r", r"f[abc]thers", "dedi[cdef]ated")
        msg = rf"Missing regex in {GOLD_GETTY_FILE_RX}: r'm\[opq\]thers'"
        with pytest.raises(AssertionError, match=msg):
            contains_rx(GOLD_GETTY_FILE, r"Fo.r", r"m[opq]thers")

    def test_contains_any(self) -> None:
        contains_any(GOLD_GETTY_FILE, "Five", "Four", "Three")
        msg = rf"Missing content in {GOLD_GETTY_FILE_RX}: 'One' \[1 of 3\]"
        with pytest.raises(AssertionError, match=msg):
            contains_any(GOLD_GETTY_FILE, "One", "Two", "Three")

    def test_doesnt_contain(self) -> None:
        doesnt_contain(GOLD_GETTY_FILE, "One", "Two", "Three")
        msg = rf"Forbidden content in {GOLD_GETTY_FILE_RX}: 'Four'"
        with pytest.raises(AssertionError, match=msg):
            doesnt_contain(GOLD_GETTY_FILE, "Three", "Four", "Five")
