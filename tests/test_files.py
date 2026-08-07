# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for files.py"""

from __future__ import annotations

import itertools
import os
import os.path
import re

from typing import Any
from collections.abc import Iterable
from unittest import mock

import pytest

from coverage import env, files
from coverage.exceptions import ConfigError
from coverage.files import (
    GlobMatcher,
    Matcher,
    ModuleMatcher,
    PathAliases,
    TreeMatcher,
    abs_file,
    actual_path,
    find_python_files,
    flat_rootname,
    globs_to_regex,
)

from tests.coveragetest import CoverageTest
from tests.helpers import os_sep


class FilesTest(CoverageTest):
    """Tests of coverage.files."""

    def abs_path(self, p: str) -> str:
        """Return the absolute path for `p`."""
        return os.path.join(abs_file(os.getcwd()), os.path.normpath(p))

    def test_simple(self) -> None:
        self.make_file("hello.py")
        files.set_relative_directory()
        assert files.relative_filename("hello.py") == "hello.py"
        a = self.abs_path("hello.py")
        assert a != "hello.py"
        assert files.relative_filename(a) == "hello.py"

    def test_peer_directories(self) -> None:
        self.make_file("sub/proj1/file1.py")
        self.make_file("sub/proj2/file2.py")
        a1 = self.abs_path("sub/proj1/file1.py")
        a2 = self.abs_path("sub/proj2/file2.py")
        d = os.path.normpath("sub/proj1")
        os.chdir(d)
        files.set_relative_directory()
        assert files.relative_filename(a1) == "file1.py"
        assert files.relative_filename(a2) == a2

    def test_filepath_contains_absolute_prefix_twice(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/194
        # Build a path that has two pieces matching the absolute path prefix.
        # Technically, this test doesn't do that on Windows, but drive
        # letters make that impractical to achieve.
        files.set_relative_directory()
        d = abs_file(os.curdir)
        trick = os.path.splitdrive(d)[1].lstrip(os.path.sep)
        rel = os.path.join("sub", trick, "file1.py")
        assert files.relative_filename(abs_file(rel)) == rel

    def test_canonical_filename_ensure_cache_hit(self) -> None:
        self.make_file("sub/proj1/file1.py")
        d = actual_path(self.abs_path("sub/proj1"))
        os.chdir(d)
        files.set_relative_directory()
        canonical_path = files.canonical_filename("sub/proj1/file1.py")
        assert canonical_path == self.abs_path("file1.py")
        # After the filename has been converted, it should be in the cache.
        assert "sub/proj1/file1.py" in files.CANONICAL_FILENAME_CACHE
        assert files.canonical_filename("sub/proj1/file1.py") == self.abs_path("file1.py")

    @pytest.mark.parametrize(
        "curdir, sep",
        [
            ("/", "/"),
            ("X:\\", "\\"),
        ],
    )
    def test_relative_dir_for_root(self, curdir: str, sep: str) -> None:
        with mock.patch.object(files.os, "curdir", new=curdir):  # type: ignore[attr-defined]
            with mock.patch.object(files.os, "sep", new=sep):  # type: ignore[attr-defined]
                with mock.patch("coverage.files.os.path.normcase", return_value=curdir):
                    files.set_relative_directory()
                    assert files.relative_directory() == curdir

    @pytest.mark.parametrize(
        "to_make, to_check, answer",
        [
            ("a/b/c/foo.py", "a/b/c/foo.py", True),
            ("a/b/c/foo.py", "a/b/c/bar.py", False),
            ("src/files.zip", "src/files.zip/foo.py", True),
            ("src/files.whl", "src/files.whl/foo.py", True),
            ("src/files.egg", "src/files.egg/foo.py", True),
            ("src/files.pex", "src/files.pex/foo.py", True),
            ("src/files.zip", "src/morefiles.zip/foo.py", False),
            ("src/files.pex", "src/files.pex/zipfiles/files.zip/foo.py", True),
        ],
    )
    def test_source_exists(self, to_make: str, to_check: str, answer: bool) -> None:
        # source_exists won't look inside the zipfile, so it's fine to make
        # an empty file with the zipfile name.
        self.make_file(to_make, "")
        assert files.source_exists(to_check) == answer


@pytest.mark.parametrize(
    "original, flat",
    [
        ("abc.py", "abc_py"),
        ("hellothere", "hellothere"),
        ("a/b/c.py", "z_86bbcbe134d28fd2_c_py"),
        ("a/b/defghi.py", "z_86bbcbe134d28fd2_defghi_py"),
        ("/a/b/c.py", "z_bb25e0ada04227c6_c_py"),
        ("/a/b/defghi.py", "z_bb25e0ada04227c6_defghi_py"),
        (r"c:\foo\bar.html", "z_e7c107482373f299_bar_html"),
        (r"d:\foo\bar.html", "z_584a05dcebc67b46_bar_html"),
        ("Montréal/☺/conf.py", "z_c840497a2c647ce0_conf_py"),
        (  # original:
            r"c:\lorem\ipsum\quia\dolor\sit\amet\consectetur\adipisci\velit\sed"
            + r"\quia\non\numquam\eius\modi\tempora\incidunt\ut\labore\et\dolore"
            + r"\magnam\aliquam\quaerat\voluptatem\ut\enim\ad\minima\veniam\quis"
            + r"\nostrum\exercitationem\ullam\corporis\suscipit\laboriosam"
            + r"\Montréal\☺\my_program.py",
            # flat:
            "z_e597dfacb73a23d5_my_program_py",
        ),
    ],
)
def test_flat_rootname(original: str, flat: str) -> None:
    assert flat_rootname(original) == flat


def globs_to_regex_params(
    patterns: Iterable[str],
    case_insensitive: bool = False,
    partial: bool = False,
    matches: Iterable[str] = (),
    nomatches: Iterable[str] = (),
) -> Iterable[Any]:
    """Generate parameters for `test_globs_to_regex`.

    `patterns`, `case_insensitive`, and `partial` are arguments for
    `globs_to_regex`.  `matches` is a list of strings that should match, and
    `nomatches` is a list of strings that should not match.

    Everything is yielded so that `test_globs_to_regex` can call
    `globs_to_regex` once and check one result.

    """
    pat_id = "|".join(patterns)
    for text in matches:
        yield pytest.param(
            patterns,
            case_insensitive,
            partial,
            text,
            True,
            id=f"{pat_id}:ci{case_insensitive}:par{partial}:{text}:match",
        )
    for text in nomatches:
        yield pytest.param(
            patterns,
            case_insensitive,
            partial,
            text,
            False,
            id=f"{pat_id}:ci{case_insensitive}:par{partial}:{text}:nomatch",
        )


@pytest.mark.parametrize(
    "patterns, case_insensitive, partial, text, result",
    list(
        itertools.chain.from_iterable(
            [
                globs_to_regex_params(
                    ["abc", "xyz"],
                    matches=["abc", "xyz", "sub/mod/abc"],
                    nomatches=[
                        "ABC",
                        "xYz",
                        "abcx",
                        "xabc",
                        "axyz",
                        "xyza",
                        "sub/mod/abcd",
                        "sub/abc/more",
                    ],
                ),
                globs_to_regex_params(
                    ["abc", "xyz"],
                    case_insensitive=True,
                    matches=["abc", "xyz", "Abc", "XYZ", "AbC"],
                    nomatches=["abcx", "xabc", "axyz", "xyza"],
                ),
                globs_to_regex_params(
                    ["a*c", "x*z"],
                    matches=["abc", "xyz", "xYz", "azc", "xaz", "axyzc"],
                    nomatches=["ABC", "abcx", "xabc", "axyz", "xyza", "a/c"],
                ),
                globs_to_regex_params(
                    ["a?c", "x?z"],
                    matches=["abc", "xyz", "xYz", "azc", "xaz"],
                    nomatches=["ABC", "abcx", "xabc", "axyz", "xyza", "a/c"],
                ),
                globs_to_regex_params(
                    ["a??d"],
                    matches=["abcd", "azcd", "a12d"],
                    nomatches=["ABCD", "abcx", "axyz", "abcde"],
                ),
                globs_to_regex_params(
                    ["abc/hi.py"],
                    case_insensitive=True,
                    matches=["abc/hi.py", "ABC/hi.py", r"ABC\hi.py"],
                    nomatches=["abc_hi.py", "abc/hi.pyc"],
                ),
                globs_to_regex_params(
                    [r"abc\hi.py"],
                    case_insensitive=True,
                    matches=[r"abc\hi.py", r"ABC\hi.py", "abc/hi.py", "ABC/hi.py"],
                    nomatches=["abc_hi.py", "abc/hi.pyc"],
                ),
                globs_to_regex_params(
                    ["abc/*/hi.py"],
                    case_insensitive=True,
                    matches=["abc/foo/hi.py", r"ABC\foo/hi.py"],
                    nomatches=[
                        "abc/hi.py",
                        "abc/hi.pyc",
                        "ABC/foo/bar/hi.py",
                        r"ABC\foo/bar/hi.py",
                    ],
                ),
                globs_to_regex_params(
                    ["abc/**/hi.py"],
                    case_insensitive=True,
                    matches=[
                        "abc/foo/hi.py",
                        r"ABC\foo/hi.py",
                        "abc/hi.py",
                        "ABC/foo/bar/hi.py",
                        r"ABC\foo/bar/hi.py",
                    ],
                    nomatches=["abc/hi.pyc"],
                ),
                globs_to_regex_params(
                    ["abc/[a-f]*/hi.py"],
                    case_insensitive=True,
                    matches=["abc/foo/hi.py", r"ABC\boo/hi.py"],
                    nomatches=[
                        "abc/zoo/hi.py",
                        "abc/hi.py",
                        "abc/hi.pyc",
                        "abc/foo/bar/hi.py",
                        r"abc\foo/bar/hi.py",
                    ],
                ),
                globs_to_regex_params(
                    ["abc/[a-f]/hi.py"],
                    case_insensitive=True,
                    matches=["abc/f/hi.py", r"ABC\b/hi.py"],
                    nomatches=[
                        "abc/foo/hi.py",
                        "abc/zoo/hi.py",
                        "abc/hi.py",
                        "abc/hi.pyc",
                        "abc/foo/bar/hi.py",
                        r"abc\foo/bar/hi.py",
                    ],
                ),
                globs_to_regex_params(
                    ["abc/"],
                    case_insensitive=True,
                    partial=True,
                    matches=["abc/foo/hi.py", "ABC/foo/bar/hi.py", r"ABC\foo/bar/hi.py"],
                    nomatches=["abcd/foo.py", "xabc/hi.py"],
                ),
                globs_to_regex_params(
                    ["*/foo"],
                    case_insensitive=False,
                    partial=True,
                    matches=["abc/foo/hi.py", "foo/hi.py", "abc/def/foo/hi.py"],
                    nomatches=["abc/xfoo/hi.py"],
                ),
                globs_to_regex_params(
                    ["*c/foo"],
                    case_insensitive=False,
                    partial=True,
                    matches=["abc/foo/hi.py"],
                    nomatches=["abc/xfoo/hi.py", "foo/hi.py", "def/abc/foo/hi.py"],
                ),
                globs_to_regex_params(
                    ["foo/x*"],
                    case_insensitive=False,
                    partial=True,
                    matches=["foo/x", "foo/xhi.py", "foo/x/hi.py"],
                    nomatches=[],
                ),
                globs_to_regex_params(
                    ["foo/x*"],
                    case_insensitive=False,
                    partial=False,
                    matches=["foo/x", "foo/xhi.py"],
                    nomatches=["foo/x/hi.py"],
                ),
                globs_to_regex_params(
                    ["**/foo"],
                    matches=["foo", "hello/foo", "hi/there/foo"],
                    nomatches=["foob", "hello/foob", "hello/Foo"],
                ),
                globs_to_regex_params(
                    ["a+b/foo*", "x{y}z/foo*"],
                    matches=["a+b/foo", "a+b/foobar", "x{y}z/foobar"],
                    nomatches=["aab/foo", "ab/foo", "xyz/foo"],
                ),
            ]
        )
    ),
)
def test_globs_to_regex(
    patterns: Iterable[str],
    case_insensitive: bool,
    partial: bool,
    text: str,
    result: bool,
) -> None:
    regex = globs_to_regex(patterns, case_insensitive=case_insensitive, partial=partial)
    assert bool(regex.match(text)) == result


@pytest.mark.parametrize(
    "pattern, bad_word",
    [
        ("***/foo.py", "***"),
        ("bar/***/foo.py", "***"),
        ("*****/foo.py", "*****"),
        ("Hello]there", "]"),
        ("Hello[there", "["),
        ("x/a**/b.py", "a**"),
        ("x/abcd**/b.py", "abcd**"),
        ("x/**a/b.py", "**a"),
        ("x/**/**/b.py", "**/**"),
    ],
)
def test_invalid_globs(pattern: str, bad_word: str) -> None:
    msg = f"File pattern can't include {bad_word!r}"
    with pytest.raises(ConfigError, match=re.escape(msg)):
        globs_to_regex([pattern])


class MatcherTest(CoverageTest):
    """Tests of file matchers."""

    def setUp(self) -> None:
        super().setUp()
        files.set_relative_directory()

    def assertMatches(self, matcher: Matcher, filepath: str, matches: bool) -> None:
        """The `matcher` should agree with `matches` about `filepath`."""
        canonical = files.canonical_filename(filepath)
        msg = f"File {filepath} should have matched as {matches}"
        assert matches == matcher.match(canonical), msg

    @pytest.mark.parametrize(
        "filepath, expected_match",
        [
            ("sub/file1.py", True),
            ("sub/file2.c", True),
            ("sub2/file3.h", False),
            ("sub3/file4.py", True),
            ("sub3/file5.c", False),
            ("sub4/File5.py", env.WINDOWS),
            ("sub5/file6.py", env.WINDOWS),
        ],
    )
    def test_tree_matcher(self, filepath: str, expected_match: bool) -> None:
        # Create all files that TreeMatcher needs
        self.make_file("sub/file1.py")
        self.make_file("sub/file2.c")
        self.make_file("sub2/file3.h")
        self.make_file("sub3/file4.py")
        self.make_file("sub3/file5.c")
        self.make_file("sub4/File5.py")
        self.make_file("sub5/file6.py")

        trees = [
            files.canonical_filename("sub"),
            files.canonical_filename("sub3/file4.py"),
            files.canonical_filename("sub4/file5.py"),
            files.canonical_filename("SUB5/file6.py"),
        ]
        tm = TreeMatcher(trees)
        assert tm.info() == sorted(trees)
        self.assertMatches(tm, filepath, expected_match)

    @pytest.mark.parametrize(
        "modulename, expected_match",
        [
            ("test", True),
            ("trash", False),
            ("testing", False),
            ("test.x", True),
            ("test.x.y.z", True),
            ("py", False),
            ("py.t", False),
            ("py.test", True),
            ("py.testing", False),
            ("py.test.buz", True),
            ("py.test.buz.baz", True),
            ("__main__", False),
            ("mymain", True),
            ("yourmain", False),
        ],
    )
    def test_module_matcher(self, modulename: str, expected_match: bool) -> None:
        modules = ["test", "py.test", "mymain"]
        mm = ModuleMatcher(modules)
        assert mm.info() == modules
        assert mm.match(modulename) == expected_match, modulename

    @pytest.mark.parametrize(
        "filepath, expected_match",
        [
            ("sub/file1.py", True),
            ("sub/file2.c", False),
            ("sub2/file3.h", True),
            ("sub2/sub/file3.h", True),
            ("sub3/file4.py", True),
            ("sub3/file5.c", False),
        ],
    )
    def test_glob_matcher(self, filepath: str, expected_match: bool) -> None:
        # Create all files that GlobMatcher needs
        self.make_file("sub/file1.py")
        self.make_file("sub/file2.c")
        self.make_file("sub2/file3.h")
        self.make_file("sub2/sub/file3.h")
        self.make_file("sub3/file4.py")
        self.make_file("sub3/file5.c")

        fnm = GlobMatcher(["*.py", "*/sub2/*"])
        assert fnm.info() == ["*.py", "*/sub2/*"]
        self.assertMatches(fnm, filepath, expected_match)

    def test_glob_matcher_overload(self) -> None:
        fnm = GlobMatcher(["*x%03d*.txt" % i for i in range(500)])
        self.assertMatches(fnm, "x007foo.txt", True)
        self.assertMatches(fnm, "x123foo.txt", True)
        self.assertMatches(fnm, "x798bar.txt", False)
        self.assertMatches(fnm, "x499.txt", True)
        self.assertMatches(fnm, "x500.txt", False)

    def test_glob_windows_paths(self) -> None:
        # We should be able to match Windows paths even if we are running on
        # a non-Windows OS.
        fnm = GlobMatcher(["*/foo.py"])
        self.assertMatches(fnm, r"dir\foo.py", True)
        fnm = GlobMatcher([r"*\foo.py"])
        self.assertMatches(fnm, r"dir\foo.py", True)


@pytest.fixture(params=[False, True], name="rel_yn")
def relative_setting(request: pytest.FixtureRequest) -> bool:
    """Parameterized fixture to choose whether PathAliases is relative or not."""
    return request.param  # type: ignore[no-any-return]


class PathAliasesTest(CoverageTest):
    """Tests for coverage/files.py:PathAliases"""

    run_in_temp_dir = False

    def assert_mapped(self, aliases: PathAliases, inp: str, out: str) -> None:
        """Assert that `inp` mapped through `aliases` produces `out`.

        If the aliases are not relative, then `out` is canonicalized first,
        since aliases produce canonicalized paths by default.

        """
        mapped = aliases.map(inp, exists=lambda p: True)
        if aliases.relative:
            expected = out
        else:
            expected = files.canonical_filename(out)
        assert mapped == expected

    def assert_unchanged(self, aliases: PathAliases, inp: str, exists: bool = True) -> None:
        """Assert that `inp` mapped through `aliases` is unchanged."""
        assert aliases.map(inp, exists=lambda p: exists) == inp

    def test_noop(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        self.assert_unchanged(aliases, "/ned/home/a.py")

    def test_nomatch(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("/home/*/src", "./mysrc")
        self.assert_unchanged(aliases, "/home/foo/a.py")

    def test_wildcard(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("/ned/home/*/src", "./mysrc")
        self.assert_mapped(aliases, "/ned/home/foo/src/a.py", "./mysrc/a.py")

        aliases = PathAliases(relative=rel_yn)
        aliases.add("/ned/home/*/src/", "./mysrc")
        self.assert_mapped(aliases, "/ned/home/foo/src/a.py", "./mysrc/a.py")

    def test_no_accidental_match(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("/home/*/src", "./mysrc")
        self.assert_unchanged(aliases, "/home/foo/srcetc")

    def test_no_map_if_not_exist(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("/ned/home/*/src", "./mysrc")
        self.assert_unchanged(aliases, "/ned/home/foo/src/a.py", exists=False)
        self.assert_unchanged(aliases, "foo/src/a.py", exists=False)

    def test_no_dotslash(self, rel_yn: bool) -> None:
        # The result shouldn't start with "./" if the map result didn't.
        aliases = PathAliases(relative=rel_yn)
        aliases.add("*/project", ".")
        self.assert_mapped(aliases, "/ned/home/project/src/a.py", os_sep("src/a.py"))

    def test_relative_pattern(self) -> None:
        aliases = PathAliases(relative=True)
        aliases.add(".tox/*/site-packages", "src")
        self.assert_mapped(
            aliases,
            ".tox/py314/site-packages/proj/a.py",
            os_sep("src/proj/a.py"),
        )

    def test_multiple_patterns(self, rel_yn: bool) -> None:
        # also test the debugfn...
        msgs: list[str] = []
        aliases = PathAliases(debugfn=msgs.append, relative=rel_yn)
        aliases.add("/home/*/src", "./mysrc")
        aliases.add("/lib/*/libsrc", "./mylib")
        self.assert_mapped(aliases, "/home/foo/src/a.py", "./mysrc/a.py")
        self.assert_mapped(aliases, "/lib/foo/libsrc/a.py", "./mylib/a.py")
        if rel_yn:
            assert msgs == [
                "Aliases (relative=True):",
                " Rule: '/home/*/src' -> './mysrc/' using regex "
                + "'[/\\\\\\\\]home[/\\\\\\\\][^/\\\\\\\\]*[/\\\\\\\\]src[/\\\\\\\\]'",
                " Rule: '/lib/*/libsrc' -> './mylib/' using regex "
                + "'[/\\\\\\\\]lib[/\\\\\\\\][^/\\\\\\\\]*[/\\\\\\\\]libsrc[/\\\\\\\\]'",
                "Matched path '/home/foo/src/a.py' to rule '/home/*/src' -> './mysrc/', "
                + "producing './mysrc/a.py'",
                "Matched path '/lib/foo/libsrc/a.py' to rule '/lib/*/libsrc' -> './mylib/', "
                + "producing './mylib/a.py'",
            ]
        else:
            assert msgs == [
                "Aliases (relative=False):",
                " Rule: '/home/*/src' -> './mysrc/' using regex "
                + "'[/\\\\\\\\]home[/\\\\\\\\][^/\\\\\\\\]*[/\\\\\\\\]src[/\\\\\\\\]'",
                " Rule: '/lib/*/libsrc' -> './mylib/' using regex "
                + "'[/\\\\\\\\]lib[/\\\\\\\\][^/\\\\\\\\]*[/\\\\\\\\]libsrc[/\\\\\\\\]'",
                "Matched path '/home/foo/src/a.py' to rule '/home/*/src' -> './mysrc/', "
                + f"producing {files.canonical_filename('./mysrc/a.py')!r}",
                "Matched path '/lib/foo/libsrc/a.py' to rule '/lib/*/libsrc' -> './mylib/', "
                + f"producing {files.canonical_filename('./mylib/a.py')!r}",
            ]

    @pytest.mark.parametrize(
        "badpat",
        [
            "/ned/home/*",
            "/ned/home/*/",
            "/ned/home/*/*/",
        ],
    )
    def test_cant_have_wildcard_at_end(self, badpat: str) -> None:
        aliases = PathAliases()
        msg = "Pattern must not end with wildcards."
        with pytest.raises(ConfigError, match=msg):
            aliases.add(badpat, "fooey")

    def test_no_accidental_munging(self) -> None:
        aliases = PathAliases()
        aliases.add(r"c:\Zoo\boo", "src/")
        aliases.add("/home/ned$", "src/")
        self.assert_mapped(aliases, r"c:\Zoo\boo\foo.py", "src/foo.py")
        self.assert_mapped(aliases, r"/home/ned$/foo.py", "src/foo.py")

    def test_paths_are_os_corrected(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("/home/ned/*/src", "./mysrc")
        aliases.add(r"c:\ned\src", "./mysrc")
        self.assert_mapped(aliases, r"C:\Ned\src\sub\a.py", "./mysrc/sub/a.py")

        aliases = PathAliases(relative=rel_yn)
        aliases.add("/home/ned/*/src", r".\mysrc")
        aliases.add(r"c:\ned\src", r".\mysrc")
        self.assert_mapped(
            aliases,
            r"/home/ned/foo/src/sub/a.py",
            r".\mysrc\sub\a.py",
        )

    # Try the paths in both orders.
    lin = "*/project/module/"
    win = "*\\project\\module\\"
    lin_win_paths = [[lin, win], [win, lin]]

    @pytest.mark.parametrize("paths", lin_win_paths)
    def test_windows_on_linux(self, paths: Iterable[str], rel_yn: bool) -> None:
        # https://github.com/coveragepy/coveragepy/issues/618
        aliases = PathAliases(relative=rel_yn)
        for path in paths:
            aliases.add(path, "project/module")
        self.assert_mapped(
            aliases,
            "C:\\a\\path\\somewhere\\coveragepy_test\\project\\module\\tests\\file.py",
            "project/module/tests/file.py",
        )

    @pytest.mark.parametrize("paths", lin_win_paths)
    def test_linux_on_windows(self, paths: Iterable[str], rel_yn: bool) -> None:
        # https://github.com/coveragepy/coveragepy/issues/618
        aliases = PathAliases(relative=rel_yn)
        for path in paths:
            aliases.add(path, "project\\module")
        self.assert_mapped(
            aliases,
            "C:/a/path/somewhere/coveragepy_test/project/module/tests/file.py",
            "project\\module\\tests\\file.py",
        )

    @pytest.mark.parametrize("paths", lin_win_paths)
    def test_relative_windows_on_linux(self, paths: Iterable[str]) -> None:
        # https://github.com/coveragepy/coveragepy/issues/991
        aliases = PathAliases(relative=True)
        for path in paths:
            aliases.add(path, "project/module")
        self.assert_mapped(
            aliases,
            r"project\module\tests\file.py",
            r"project/module/tests/file.py",
        )

    @pytest.mark.parametrize("paths", lin_win_paths)
    def test_relative_linux_on_windows(self, paths: Iterable[str]) -> None:
        # https://github.com/coveragepy/coveragepy/issues/991
        aliases = PathAliases(relative=True)
        for path in paths:
            aliases.add(path, r"project\module")
        self.assert_mapped(
            aliases,
            r"project/module/tests/file.py",
            r"project\module\tests\file.py",
        )

    @pytest.mark.skipif(env.WINDOWS, reason="This test assumes Unix file system")
    def test_implicit_relative_windows_on_linux(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/991
        aliases = PathAliases(relative=True)
        self.assert_mapped(
            aliases,
            r"project\module\tests\file.py",
            r"project/module/tests/file.py",
        )

    @pytest.mark.skipif(not env.WINDOWS, reason="This test assumes Windows file system")
    def test_implicit_relative_linux_on_windows(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/991
        aliases = PathAliases(relative=True)
        self.assert_mapped(
            aliases,
            r"project/module/tests/file.py",
            r"project\module\tests\file.py",
        )

    def test_multiple_wildcard(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("/home/jenkins/*/a/*/b/*/django", "./django")
        self.assert_mapped(
            aliases,
            "/home/jenkins/xx/a/yy/b/zz/django/foo/bar.py",
            "./django/foo/bar.py",
        )

    def test_windows_root_paths(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("X:\\", "/tmp/src")
        self.assert_mapped(
            aliases,
            "X:\\a\\file.py",
            "/tmp/src/a/file.py",
        )
        self.assert_mapped(
            aliases,
            "X:\\file.py",
            "/tmp/src/file.py",
        )

    def test_leading_wildcard(self, rel_yn: bool) -> None:
        aliases = PathAliases(relative=rel_yn)
        aliases.add("*/d1", "./mysrc1")
        aliases.add("*/d2", "./mysrc2")
        self.assert_mapped(aliases, "/foo/bar/d1/x.py", "./mysrc1/x.py")
        self.assert_mapped(aliases, "/foo/bar/d2/y.py", "./mysrc2/y.py")

    def test_nested_directories_same_name(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/2072
        # When using relative_files=true, paths like "pkg/features/x.py" should
        # not be incorrectly mapped by a rule auto-generated for "features/x.py".
        aliases = PathAliases(relative=True)
        # Map both paths. The auto-generated rules should keep them distinct.
        # First, map features/templates.py - this will auto-generate a rule for "features/"
        result1 = aliases.map("features/templates.py", exists=lambda p: True)
        assert result1 == os_sep("features/templates.py")

        # Now map pkg/features/templates.py - this should NOT match the "features/" rule
        # and should auto-generate its own "pkg/" rule.
        result2 = aliases.map("pkg/features/templates.py", exists=lambda p: True)
        assert result2 == os_sep("pkg/features/templates.py")

        # Verify both paths remain distinct
        assert result1 != result2

    @pytest.mark.parametrize("dirname", [".", "..", "../other", "/"])
    def test_dot(self, dirname: str) -> None:
        if env.WINDOWS and dirname == "/":
            # The root test case was added for the manylinux Docker images,
            # and I'm not sure how it should work on Windows, so skip it.
            pytest.skip("Don't know how to handle root on Windows")
        aliases = PathAliases()
        aliases.add(dirname, "/the/source")
        the_file = os.path.join(dirname, "a.py")
        the_file = os.path.expanduser(the_file)
        the_file = os.path.abspath(os.path.realpath(the_file))

        assert "~" not in the_file  # to be sure the test is pure.
        self.assert_mapped(aliases, the_file, "/the/source/a.py")


class PathAliasesRealFilesTest(CoverageTest):
    """Tests for coverage/files.py:PathAliases using real files."""

    def test_aliasing_zip_files(self) -> None:
        self.make_file("src/zipfiles/code.zip", "fake zip, doesn't matter")
        aliases = PathAliases()
        aliases.add("*/d1", "./src")
        aliases.add("*/d2", "./src")

        expected = files.canonical_filename("src/zipfiles/code.zip/p1.py")
        assert aliases.map("tox/d1/zipfiles/code.zip/p1.py") == expected


class FindPythonFilesTest(CoverageTest):
    """Tests of `find_python_files`."""

    def test_find_python_files(self) -> None:
        self.make_file("sub/a.py")
        self.make_file("sub/b.py")
        self.make_file("sub/x.c")  # nope: not .py
        self.make_file("sub/ssub/__init__.py")
        self.make_file("sub/ssub/s.py")
        self.make_file("sub/ssub/~s.py")  # nope: editor effluvia
        self.make_file("sub/lab/exp.py")  # nope: no __init__.py
        self.make_file("sub/windows.pyw")
        py_files = set(find_python_files("sub", include_namespace_packages=False))
        self.assert_same_files(
            py_files,
            [
                "sub/a.py",
                "sub/b.py",
                "sub/ssub/__init__.py",
                "sub/ssub/s.py",
                "sub/windows.pyw",
            ],
        )

    def test_find_python_files_include_namespace_packages(self) -> None:
        self.make_file("sub/a.py")
        self.make_file("sub/b.py")
        self.make_file("sub/x.c")  # nope: not .py
        self.make_file("sub/ssub/__init__.py")
        self.make_file("sub/ssub/s.py")
        self.make_file("sub/ssub/~s.py")  # nope: editor effluvia
        self.make_file("sub/lab/exp.py")
        self.make_file("sub/windows.pyw")
        py_files = set(find_python_files("sub", include_namespace_packages=True))
        self.assert_same_files(
            py_files,
            [
                "sub/a.py",
                "sub/b.py",
                "sub/ssub/__init__.py",
                "sub/ssub/s.py",
                "sub/lab/exp.py",
                "sub/windows.pyw",
            ],
        )


@pytest.mark.skipif(not env.WINDOWS, reason="Only need to run Windows tests on Windows.")
class WindowsFileTest(CoverageTest):
    """Windows-specific tests of file name handling."""

    run_in_temp_dir = False

    def test_actual_path(self) -> None:
        assert actual_path(r"c:\Windows") == actual_path(r"C:\wINDOWS")
