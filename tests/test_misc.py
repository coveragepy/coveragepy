# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests of miscellaneous stuff."""

from __future__ import annotations

import sys
from typing import Any
from unittest import mock

import pytest
from hypothesis import example, given, strategies as st

from coverage.exceptions import CoverageException
from coverage.misc import file_be_gone
from coverage.misc import Hasher, substitute_variables, import_third_party
from coverage.misc import human_sorted, human_sorted_items, stdout_link

from tests.coveragetest import CoverageTest
from tests.strategies import nested_data_strategies


# Make two sets which are equal but iterate differently.
numset1 = set(range(20))
numset2 = set(range(20))
for i in range(0, 20, 2):
    numset2.remove(i)
for i in range(0, 20, 2):
    numset2.add(i)


class HasherTest(CoverageTest):
    """Test our wrapper of fingerprint hashing."""

    run_in_temp_dir = False

    def test_scrambled_sets(self) -> None:
        assert numset1 == numset2
        assert list(numset1) != list(numset2)

    # Use nested_data_strategies to generate data schemas, then use it twice in
    # the test to get two chunks of data with the "same shape" but different
    # data.
    @example(([1, None, 2, None], [1, 2]))
    @example(("Hello, world!", "Hello, world!"))
    @example(("Hello", "Goodbye"))
    @example((b"Hello", b"Goodbye"))
    @example(("Hello \N{SNOWMAN}", "Goodbye"))
    @example(({"a": 17, "b": 23}, {"b": 23, "a": 17}))
    @example(({"a": 17, "b": {"c": 1, "d": 2}}, {"a": 17, "b": {"c": 1}, "d": 2}))
    @example((numset1, numset2))
    @example(({(1, 2), (3, 4), (5, 6)}, {(1, 2)}))
    # https://github.com/coveragepy/coveragepy/issues/2108
    @example((["", []], [".<class 'list'>"]))
    @example((["5", []], [".<class 'list'>"]))
    @given(nested_data_strategies.flatmap(lambda s: st.tuples(s, s)))
    def test_equality_matches_hash(self, data_pair: tuple[Any, Any]) -> None:
        data1, data2 = data_pair
        h1 = Hasher()
        h1.update(data1)
        h2 = Hasher()
        h2.update(data2)
        if data1 == data2:
            assert h1.hexdigest() == h2.hexdigest()
            assert h1.digest() == h2.digest()
        else:
            # Strictly speaking, unequal data can produce equal hashes, but
            # it's very unlikely, so test for it anyway.
            assert h1.hexdigest() != h2.hexdigest()
            assert h1.digest() != h2.digest()


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
