# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of miscellaneous stuff."""

from __future__ import annotations

import sys
from unittest import mock

import pytest

from coverage.exceptions import CoverageException
from coverage.misc import file_be_gone
from coverage.misc import Hasher, substitute_variables, import_third_party
from coverage.misc import human_sorted, human_sorted_items, stdout_link

from tests.coveragetest import CoverageTest


class HasherTest(CoverageTest):
    """Test our wrapper of fingerprint hashing."""

    run_in_temp_dir = False

    def test_string_hashing(self) -> None:
        h1 = Hasher()
        h1.update("Hello, world!")
        h2 = Hasher()
        h2.update("Goodbye!")
        h3 = Hasher()
        h3.update("Hello, world!")
        assert h1.hexdigest() != h2.hexdigest()
        assert h1.hexdigest() == h3.hexdigest()

    def test_bytes_hashing(self) -> None:
        h1 = Hasher()
        h1.update(b"Hello, world!")
        h2 = Hasher()
        h2.update(b"Goodbye!")
        assert h1.hexdigest() != h2.hexdigest()

    def test_unicode_hashing(self) -> None:
        h1 = Hasher()
        h1.update("Hello, world! \N{SNOWMAN}")
        h2 = Hasher()
        h2.update("Goodbye!")
        assert h1.hexdigest() != h2.hexdigest()

    def test_dict_hashing(self) -> None:
        h1 = Hasher()
        h1.update({"a": 17, "b": 23})
        h2 = Hasher()
        h2.update({"b": 23, "a": 17})
        assert h1.hexdigest() == h2.hexdigest()

    def test_dict_collision(self) -> None:
        h1 = Hasher()
        h1.update({"a": 17, "b": {"c": 1, "d": 2}})
        h2 = Hasher()
        h2.update({"a": 17, "b": {"c": 1}, "d": 2})
        assert h1.hexdigest() != h2.hexdigest()

    def test_tap(self) -> None:
        h1 = Hasher()
        h2 = Hasher()
        d1 = [1, 2, 3, ["hi", "what"], "hello"]
        d2 = []
        for v in h1.tap(d1):
            h2.update(v)
            d2.append(v)
        assert d1 == d2
        assert h1.hexdigest() == h2.hexdigest()


class RemoveFileTest(CoverageTest):
    """Tests of misc.file_be_gone."""

    def test_remove_nonexistent_file(self) -> None:
        # It's OK to try to remove a file that doesn't exist.
        file_be_gone("not_here.txt")

    def test_remove_actual_file(self) -> None:
        # It really does remove a file that does exist.
        self.make_file("here.txt", "We are here, we are here, we are here!")
        file_be_gone("here.txt")
        self.assert_doesnt_exist("here.txt")

    def test_actual_errors(self) -> None:
        # Errors can still happen.
        # ". is a directory" on Unix, or "Access denied" on Windows
        with pytest.raises(OSError):
            file_be_gone(".")


VARS = {
    "FOO": "fooey",
    "BAR": "xyzzy",
}


@pytest.mark.parametrize(
    "before, after",
    [
        ("Nothing to do", "Nothing to do"),
        ("Dollar: $$", "Dollar: $"),
        ("Simple: $FOO is fooey", "Simple: fooey is fooey"),
        ("Braced: X${FOO}X.", "Braced: XfooeyX."),
        ("Missing: x${NOTHING}y is xy", "Missing: xy is xy"),
        ("Multiple: $$ $FOO $BAR ${FOO}", "Multiple: $ fooey xyzzy fooey"),
        ("Ill-formed: ${%5} ${{HI}} ${", "Ill-formed: ${%5} ${{HI}} ${"),
        ("Strict: ${FOO?} is there", "Strict: fooey is there"),
        ("Defaulted: ${WUT-missing}!", "Defaulted: missing!"),
        ("Defaulted empty: ${WUT-}!", "Defaulted empty: !"),
    ],
)
def test_substitute_variables(before: str, after: str) -> None:
    assert substitute_variables(before, VARS) == after


@pytest.mark.parametrize(
    "text",
    [
        "Strict: ${NOTHING?} is an error",
    ],
)
def test_substitute_variables_errors(text: str) -> None:
    with pytest.raises(CoverageException) as exc_info:
        substitute_variables(text, VARS)
    assert text in str(exc_info.value)
    assert "Variable NOTHING is undefined" in str(exc_info.value)


class ImportThirdPartyTest(CoverageTest):
    """Test import_third_party."""

    run_in_temp_dir = False

    def test_success(self) -> None:
        # Make sure we don't have pytest in sys.modules before we start.
        del sys.modules["pytest"]
        # Import pytest
        mod, has = import_third_party("pytest")
        assert has
        # Yes, it's really pytest:
        assert mod.__name__ == "pytest"
        print(dir(mod))
        assert all(hasattr(mod, name) for name in ["skip", "mark", "raises", "warns"])
        # But it's not in sys.modules:
        assert "pytest" not in sys.modules

    def test_failure(self) -> None:
        _, has = import_third_party("xyzzy")
        assert not has
        assert "xyzzy" not in sys.modules


HUMAN_DATA = [
    ("z1 a2z a01 a2a a3 a1", "a01 a1 a2a a2z a3 z1"),
    ("a10 a9 a100 a1", "a1 a9 a10 a100"),
    ("4.0 3.10-win 3.10-mac 3.9-mac 3.9-win", "3.9-mac 3.9-win 3.10-mac 3.10-win 4.0"),
]


@pytest.mark.parametrize("words, ordered", HUMAN_DATA)
def test_human_sorted(words: str, ordered: str) -> None:
    assert " ".join(human_sorted(words.split())) == ordered


@pytest.mark.parametrize("words, ordered", HUMAN_DATA)
def test_human_sorted_items(words: str, ordered: str) -> None:
    keys = words.split()
    # Check that we never try to compare the values in the items
    human_sorted_items([(k, object()) for k in keys])
    items = [(k, 1) for k in keys] + [(k, 2) for k in keys]
    okeys = ordered.split()
    oitems = [(k, v) for k in okeys for v in [1, 2]]
    assert human_sorted_items(items) == oitems
    assert human_sorted_items(items, reverse=True) == oitems[::-1]


def test_stdout_link_tty() -> None:
    with mock.patch.object(sys.stdout, "isatty", lambda: True):
        link = stdout_link("some text", "some url")
    assert link == "\033]8;;some url\asome text\033]8;;\a"


def test_stdout_link_not_tty() -> None:
    # Without mocking isatty, it reports False in a pytest suite.
    assert stdout_link("some text", "some url") == "some text"


def test_stdout_link_with_fake_stdout() -> None:
    # If stdout is another object, we should still be ok.
    with mock.patch.object(sys, "stdout", object()):
        link = stdout_link("some text", "some url")
    assert link == "some text"
