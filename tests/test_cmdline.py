# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Test cmdline.py for coverage.py."""

from __future__ import annotations

import ast
import os
import pprint
import re
import sys
import textwrap

from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import coverage
import coverage.cmdline
from coverage import env
from coverage.control import DEFAULT_DATAFILE
from coverage.config import CoverageConfig
from coverage.exceptions import _ExceptionDuringRun
from coverage.types import TConfigValueIn, TConfigValueOut
from coverage.version import __url__

from tests import testenv
from tests.coveragetest import CoverageTest, OK, ERR, command_line
from tests.helpers import os_sep, re_line, re_lines


class BaseCmdLineTest(CoverageTest):
    """Tests of execution paths through the command line interpreter."""

    run_in_temp_dir = False

    # Make a dict mapping function names to the default values that cmdline.py
    # uses when calling the function.
    _defaults = mock.Mock()
    _defaults.Coverage().annotate(
        directory=None,
        ignore_errors=None,
        include=None,
        omit=None,
        morfs=[],
        contexts=None,
    )
    _defaults.Coverage().html_report(
        directory=None,
        ignore_errors=None,
        include=None,
        omit=None,
        morfs=[],
        skip_covered=None,
        show_contexts=None,
        title=None,
        contexts=None,
        skip_empty=None,
        precision=None,
    )
    _defaults.Coverage().report(
        ignore_errors=None,
        include=None,
        omit=None,
        morfs=[],
        show_missing=None,
        skip_covered=None,
        contexts=None,
        skip_empty=None,
        precision=None,
        sort=None,
        output_format=None,
    )
    _defaults.Coverage().xml_report(
        ignore_errors=None,
        include=None,
        omit=None,
        morfs=[],
        outfile=None,
        contexts=None,
        skip_empty=None,
    )
    _defaults.Coverage().json_report(
        ignore_errors=None,
        include=None,
        omit=None,
        morfs=[],
        outfile=None,
        contexts=None,
        pretty_print=None,
        show_contexts=None,
    )
    _defaults.Coverage().lcov_report(
        ignore_errors=None,
        include=None,
        omit=None,
        morfs=[],
        outfile=None,
        contexts=None,
    )
    _defaults.Coverage(
        data_file=DEFAULT_DATAFILE,
        cover_pylib=None,
        data_suffix=None,
        timid=None,
        branch=None,
        config_file=True,
        source=None,
        include=None,
        omit=None,
        debug=None,
        concurrency=None,
        check_preimported=True,
        context=None,
        messages=True,
    )

    DEFAULT_KWARGS = {name: kw for name, _, kw in _defaults.mock_calls}

    def model_object(self) -> mock.Mock:
        """Return a Mock suitable for use in CoverageScript."""
        mk = mock.Mock()

        cov = mk.Coverage.return_value

        # The mock needs options.
        mk.config = CoverageConfig()
        cov.get_option = mk.config.get_option
        cov.set_option = mk.config.set_option

        # Get the type right for the result of reporting.
        cov.report.return_value = 50.0
        cov.html_report.return_value = 50.0
        cov.xml_report.return_value = 50.0
        cov.json_report.return_value = 50.0
        cov.lcov_report.return_value = 50.0

        return mk

    # Global names in cmdline.py that will be mocked during the tests.
    MOCK_GLOBALS = ["Coverage", "PyRunner", "show_help"]

    def mock_command_line(
        self,
        args: str,
        options: Mapping[str, TConfigValueIn] | None = None,
    ) -> tuple[mock.Mock, int]:
        """Run `args` through the command line, with a Mock.

        `options` is a dict of names and values to pass to `set_option`.

        Returns the Mock it used and the status code returned.

        """
        mk = self.model_object()

        if options is not None:
            for name, value in options.items():
                mk.config.set_option(name, value)

        patchers = [
            mock.patch("coverage.cmdline." + name, getattr(mk, name)) for name in self.MOCK_GLOBALS
        ]
        for patcher in patchers:
            patcher.start()
        try:
            ret = command_line(args)
        finally:
            for patcher in patchers:
                patcher.stop()

        return mk, ret

    def cmd_executes(
        self,
        args: str,
        code: str,
        ret: int = OK,
        options: Mapping[str, TConfigValueIn] | None = None,
    ) -> None:
        """Assert that the `args` end up executing the sequence in `code`."""
        called, status = self.mock_command_line(args, options=options)
        assert status == ret, f"Wrong status: got {status!r}, wanted {ret!r}"

        # Remove all indentation, and execute with mock globals
        code = textwrap.dedent(code)
        expected = self.model_object()
        globs = {n: getattr(expected, n) for n in self.MOCK_GLOBALS}
        code_obj = compile(code, "<code>", "exec", dont_inherit=True)
        eval(code_obj, globs, {})  # pylint: disable=eval-used

        # Many of our functions take a lot of arguments, and cmdline.py
        # calls them with many.  But most of them are just the defaults, which
        # we don't want to have to repeat in all tests.  For each call, apply
        # the defaults.  This lets the tests just mention the interesting ones.
        for name, _, kwargs in expected.mock_calls:
            for k, v in self.DEFAULT_KWARGS.get(name, {}).items():
                kwargs.setdefault(k, v)

        self.assert_same_mock_calls(expected, called)

    def cmd_executes_same(self, args1: str, args2: str) -> None:
        """Assert that the `args1` executes the same as `args2`."""
        m1, r1 = self.mock_command_line(args1)
        m2, r2 = self.mock_command_line(args2)
        assert r1 == r2
        self.assert_same_mock_calls(m1, m2)

    def assert_same_mock_calls(self, m1: mock.Mock, m2: mock.Mock) -> None:
        """Assert that `m1.mock_calls` and `m2.mock_calls` are the same."""
        # Use a real equality comparison, but if it fails, use a nicer assert
        # so we can tell what's going on.  We have to use the real == first due
        # to CmdOptionParser.__eq__
        if m1.mock_calls != m2.mock_calls:
            pp1 = pprint.pformat(m1.mock_calls)
            pp2 = pprint.pformat(m2.mock_calls)
            assert pp1 + "\n" == pp2 + "\n"

    def cmd_help(
        self,
        args: str,
        help_msg: str | None = None,
        topic: str | None = None,
        ret: int = ERR,
    ) -> None:
        """Run a command line, and check that it prints the right help.

        Only the last function call in the mock is checked, which should be the
        help message that we want to see.

        """
        mk, status = self.mock_command_line(args)
        assert status == ret, f"Wrong status: got {status}, wanted {ret}"
        if help_msg:
            assert mk.mock_calls[-1] == ("show_help", (help_msg,), {})
        else:
            assert mk.mock_calls[-1] == ("show_help", (), {"topic": topic})


class BaseCmdLineTestTest(BaseCmdLineTest):
    """Tests that our BaseCmdLineTest helpers work."""

    def test_cmd_executes_same(self) -> None:
        # All the other tests here use self.cmd_executes_same in successful
        # ways, so here we just check that it fails.
        with pytest.raises(AssertionError):
            self.cmd_executes_same("run", "debug")


class CmdLineTest(BaseCmdLineTest):
    """Tests of the coverage.py command line."""

    def test_annotate(self) -> None:
        # coverage annotate [-d DIR] [-i] [--omit DIR,...] [FILE1 FILE2 ...]
        self.cmd_executes(
            "annotate",
            """\
            cov = Coverage()
            cov.load()
            cov.annotate()
            """,
        )
        self.cmd_executes(
            "annotate -d dir1",
            """\
            cov = Coverage()
            cov.load()
            cov.annotate(directory="dir1")
            """,
        )
        self.cmd_executes(
            "annotate -i",
            """\
            cov = Coverage()
            cov.load()
            cov.annotate(ignore_errors=True)
            """,
        )
        self.cmd_executes(
            "annotate --omit fooey",
            """\
            cov = Coverage(omit=["fooey"])
            cov.load()
            cov.annotate(omit=["fooey"])
            """,
        )
        self.cmd_executes(
            "annotate --omit fooey,booey",
            """\
            cov = Coverage(omit=["fooey", "booey"])
            cov.load()
            cov.annotate(omit=["fooey", "booey"])
            """,
        )
        self.cmd_executes(
            "annotate mod1",
            """\
            cov = Coverage()
            cov.load()
            cov.annotate(morfs=["mod1"])
            """,
        )
        self.cmd_executes(
            "annotate mod1 mod2 mod3",
            """\
            cov = Coverage()
            cov.load()
            cov.annotate(morfs=["mod1", "mod2", "mod3"])
            """,
        )

    def test_combine(self) -> None:
        # coverage combine with args
        self.cmd_executes(
            "combine datadir1",
            """\
            cov = Coverage()
            cov.combine(["datadir1"], strict=True, keep=False)
            cov.save()
            """,
        )
        # coverage combine, appending
        self.cmd_executes(
            "combine --append datadir1",
            """\
            cov = Coverage()
            cov.load()
            cov.combine(["datadir1"], strict=True, keep=False)
            cov.save()
            """,
        )
        # coverage combine without args
        self.cmd_executes(
            "combine",
            """\
            cov = Coverage()
            cov.combine(None, strict=True, keep=False)
            cov.save()
            """,
        )
        # coverage combine quietly
        self.cmd_executes(
            "combine -q",
            """\
            cov = Coverage(messages=False)
            cov.combine(None, strict=True, keep=False)
            cov.save()
            """,
        )
        self.cmd_executes(
            "combine --quiet",
            """\
            cov = Coverage(messages=False)
            cov.combine(None, strict=True, keep=False)
            cov.save()
            """,
        )
        self.cmd_executes(
            "combine --data-file=foo.cov",
            """\
            cov = Coverage(data_file="foo.cov")
            cov.combine(None, strict=True, keep=False)
            cov.save()
            """,
        )

    def test_combine_doesnt_confuse_options_with_args(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/385
        self.cmd_executes(
            "combine --rcfile cov.ini",
            """\
            cov = Coverage(config_file='cov.ini')
            cov.combine(None, strict=True, keep=False)
            cov.save()
            """,
        )
        self.cmd_executes(
            "combine --rcfile cov.ini data1 data2/more",
            """\
            cov = Coverage(config_file='cov.ini')
            cov.combine(["data1", "data2/more"], strict=True, keep=False)
            cov.save()
            """,
        )

    @pytest.mark.parametrize(
        "cmd, output",
        [
            (
                "debug",
                "What information would you like: config, data, sys, premain, pybehave, sqlite?",
            ),
            ("debug foo", "Don't know what you mean by 'foo'"),
            ("debug sys config", "'debug sys' takes no additional arguments"),
        ],
    )
    def test_debug(self, cmd: str, output: str) -> None:
        self.cmd_help(cmd, output)

    def test_debug_sys(self) -> None:
        self.command_line("debug sys")
        out = self.stdout()
        assert "version:" in out
        assert "data_file:" in out

    def test_debug_config(self) -> None:
        self.command_line("debug config")
        out = self.stdout()
        assert "cover_pylib:" in out
        assert "skip_covered:" in out
        assert "skip_empty:" in out

    def test_debug_pybehave(self) -> None:
        self.command_line("debug pybehave")
        out = self.stdout()
        assert " CPYTHON:" in out
        assert " PYVERSION:" in out
        assert " deferred_annotations:" in out

        # Some things that shouldn't appear..
        assert "typing." not in out  # import from typing
        assert ": <" not in out  # objects without a good repr

        # It should report PYVERSION correctly.
        pyversion = re_line(r" PYVERSION:", out)
        vtuple = ast.literal_eval(pyversion.partition(":")[-1].strip())
        assert vtuple[:5] == sys.version_info

    def test_debug_premain(self) -> None:
        self.command_line("debug premain")
        out = self.stdout()
        # -- premain ---------------------------------------------------
        #   ... many lines ...
        #           _multicall : /Users/ned/cov/trunk/.tox/py39/site-packages/pluggy/_callers.py:77
        #   pytest_pyfunc_call : /Users/ned/cov/trunk/.tox/py39/site-packages/_pytest/python.py:183
        #   test_debug_premain : /Users/ned/cov/trunk/tests/test_cmdline.py:284
        #         command_line : /Users/ned/cov/trunk/tests/coveragetest.py:309
        #         command_line : /Users/ned/cov/trunk/tests/coveragetest.py:472
        #         command_line : /Users/ned/cov/trunk/coverage/cmdline.py:592
        #             do_debug : /Users/ned/cov/trunk/coverage/cmdline.py:804
        lines = out.splitlines()
        s = re.escape(os.sep)
        assert lines[0].startswith("-- premain ----")
        assert len(lines) > 25
        assert re.search(rf"{s}site-packages{s}_pytest{s}", out)
        assert re.search(rf"{s}site-packages{s}pluggy{s}", out)
        assert re.search(rf"(?m)^\s+test_debug_premain : .*{s}tests{s}test_cmdline.py:\d+$", out)
        assert re.search(rf"(?m)^\s+command_line : .*{s}coverage{s}cmdline.py:\d+$", out)
        assert re.search(rf"(?m)^\s+do_debug : .*{s}coverage{s}cmdline.py:\d+$", out)
        assert "do_debug : " in lines[-1]

    def test_debug_sqlite(self) -> None:
        self.command_line("debug sqlite")
        out = self.stdout()
        assert "sqlite3_sqlite_version:" in out
        assert "sqlite3_compile_options:" in out
        assert len(out.splitlines()) > 15
        # Lots of lines of indented SQLite compile-time options.
        assert len(re_lines(r"^ {20,35}[A-Z]{3}", out)) > 12

    def test_erase(self) -> None:
        # coverage erase
        self.cmd_executes(
            "erase",
            """\
            cov = Coverage()
            cov.erase()
            """,
        )
        self.cmd_executes(
            "erase --data-file=foo.cov",
            """\
            cov = Coverage(data_file="foo.cov")
            cov.erase()
            """,
        )

    def test_version(self) -> None:
        # coverage --version
        self.cmd_help("--version", topic="version", ret=OK)

    def test_help_option(self) -> None:
        # coverage -h
        self.cmd_help("-h", topic="help", ret=OK)
        self.cmd_help("--help", topic="help", ret=OK)

    def test_help_command(self) -> None:
        self.cmd_executes("help", "show_help(topic='help')")

    def test_cmd_help(self) -> None:
        self.cmd_executes("run --help", "show_help(parser='<CmdOptionParser:run>')")
        self.cmd_executes_same("help run", "run --help")

    def test_html(self) -> None:
        # coverage html -d DIR [-i] [--omit DIR,...] [FILE1 FILE2 ...]
        self.cmd_executes(
            "html",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report()
            """,
        )
        self.cmd_executes(
            "html -d dir1",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report(directory="dir1")
            """,
        )
        self.cmd_executes(
            "html -i",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report(ignore_errors=True)
            """,
        )
        self.cmd_executes(
            "html --omit fooey",
            """\
            cov = Coverage(omit=["fooey"])
            cov.load()
            cov.html_report(omit=["fooey"])
            """,
        )
        self.cmd_executes(
            "html --omit fooey,booey",
            """\
            cov = Coverage(omit=["fooey", "booey"])
            cov.load()
            cov.html_report(omit=["fooey", "booey"])
            """,
        )
        self.cmd_executes(
            "html mod1",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report(morfs=["mod1"])
            """,
        )
        self.cmd_executes(
            "html mod1 mod2 mod3",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report(morfs=["mod1", "mod2", "mod3"])
            """,
        )
        self.cmd_executes(
            "html --precision=3",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report(precision=3)
            """,
        )
        self.cmd_executes(
            "html --title=Hello_there",
            """\
            cov = Coverage()
            cov.load()
            cov.html_report(title='Hello_there')
            """,
        )
        self.cmd_executes(
            "html -q",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.html_report()
            """,
        )
        self.cmd_executes(
            "html --quiet",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.html_report()
            """,
        )

    def test_json(self) -> None:
        # coverage json [-i] [--omit DIR,...] [FILE1 FILE2 ...]
        self.cmd_executes(
            "json",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report()
            """,
        )
        self.cmd_executes(
            "json --pretty-print",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(pretty_print=True)
            """,
        )
        self.cmd_executes(
            "json --pretty-print --show-contexts",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(pretty_print=True, show_contexts=True)
            """,
        )
        self.cmd_executes(
            "json -i",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(ignore_errors=True)
            """,
        )
        self.cmd_executes(
            "json -o myjson.foo",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(outfile="myjson.foo")
            """,
        )
        self.cmd_executes(
            "json -o -",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(outfile="-")
            """,
        )
        self.cmd_executes(
            "json --omit fooey",
            """\
            cov = Coverage(omit=["fooey"])
            cov.load()
            cov.json_report(omit=["fooey"])
            """,
        )
        self.cmd_executes(
            "json --omit fooey,booey",
            """\
            cov = Coverage(omit=["fooey", "booey"])
            cov.load()
            cov.json_report(omit=["fooey", "booey"])
            """,
        )
        self.cmd_executes(
            "json mod1",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(morfs=["mod1"])
            """,
        )
        self.cmd_executes(
            "json mod1 mod2 mod3",
            """\
            cov = Coverage()
            cov.load()
            cov.json_report(morfs=["mod1", "mod2", "mod3"])
            """,
        )
        self.cmd_executes(
            "json -q",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.json_report()
            """,
        )
        self.cmd_executes(
            "json --quiet",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.json_report()
            """,
        )

    def test_lcov(self) -> None:
        # coverage lcov [-i] [--omit DIR,...] [FILE1 FILE2 ...]
        self.cmd_executes(
            "lcov",
            """\
            cov = Coverage()
            cov.load()
            cov.lcov_report()
            """,
        )
        self.cmd_executes(
            "lcov -i",
            """\
            cov = Coverage()
            cov.load()
            cov.lcov_report(ignore_errors=True)
            """,
        )
        self.cmd_executes(
            "lcov -o mylcov.foo",
            """\
            cov = Coverage()
            cov.load()
            cov.lcov_report(outfile="mylcov.foo")
            """,
        )
        self.cmd_executes(
            "lcov -o -",
            """\
            cov = Coverage()
            cov.load()
            cov.lcov_report(outfile="-")
            """,
        )
        self.cmd_executes(
            "lcov --omit fooey",
            """\
            cov = Coverage(omit=["fooey"])
            cov.load()
            cov.lcov_report(omit=["fooey"])
            """,
        )
        self.cmd_executes(
            "lcov --omit fooey,booey",
            """\
            cov = Coverage(omit=["fooey", "booey"])
            cov.load()
            cov.lcov_report(omit=["fooey", "booey"])
            """,
        )
        self.cmd_executes(
            "lcov -q",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.lcov_report()
            """,
        )
        self.cmd_executes(
            "lcov --quiet",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.lcov_report()
            """,
        )

    def test_report(self) -> None:
        # coverage report [-m] [-i] [-o DIR,...] [FILE1 FILE2 ...]
        self.cmd_executes(
            "report",
            """\
            cov = Coverage()
            cov.load()
            cov.report(show_missing=None)
            """,
        )
        self.cmd_executes(
            "report -i",
            """\
            cov = Coverage()
            cov.load()
            cov.report(ignore_errors=True)
            """,
        )
        self.cmd_executes(
            "report -m",
            """\
            cov = Coverage()
            cov.load()
            cov.report(show_missing=True)
            """,
        )
        self.cmd_executes(
            "report --omit fooey",
            """\
            cov = Coverage(omit=["fooey"])
            cov.load()
            cov.report(omit=["fooey"])
            """,
        )
        self.cmd_executes(
            "report --omit fooey,booey",
            """\
            cov = Coverage(omit=["fooey", "booey"])
            cov.load()
            cov.report(omit=["fooey", "booey"])
            """,
        )
        self.cmd_executes(
            "report mod1",
            """\
            cov = Coverage()
            cov.load()
            cov.report(morfs=["mod1"])
            """,
        )
        self.cmd_executes(
            "report mod1 mod2 mod3",
            """\
            cov = Coverage()
            cov.load()
            cov.report(morfs=["mod1", "mod2", "mod3"])
            """,
        )
        self.cmd_executes(
            "report --precision=7",
            """\
            cov = Coverage()
            cov.load()
            cov.report(precision=7)
            """,
        )
        self.cmd_executes(
            "report --skip-covered",
            """\
            cov = Coverage()
            cov.load()
            cov.report(skip_covered=True)
            """,
        )
        self.cmd_executes(
            "report --skip-covered --no-skip-covered",
            """\
            cov = Coverage()
            cov.load()
            cov.report(skip_covered=False)
            """,
        )
        self.cmd_executes(
            "report --no-skip-covered",
            """\
            cov = Coverage()
            cov.load()
            cov.report(skip_covered=False)
            """,
        )
        self.cmd_executes(
            "report --skip-empty",
            """\
            cov = Coverage()
            cov.load()
            cov.report(skip_empty=True)
            """,
        )
        self.cmd_executes(
            "report --contexts=foo,bar",
            """\
            cov = Coverage()
            cov.load()
            cov.report(contexts=["foo", "bar"])
            """,
        )
        self.cmd_executes(
            "report --sort=-foo",
            """\
            cov = Coverage()
            cov.load()
            cov.report(sort='-foo')
            """,
        )
        self.cmd_executes(
            "report --data-file=foo.cov.2",
            """\
            cov = Coverage(data_file="foo.cov.2")
            cov.load()
            cov.report(show_missing=None)
            """,
        )
        self.cmd_executes(
            "report --format=markdown",
            """\
            cov = Coverage()
            cov.load()
            cov.report(output_format="markdown")
            """,
        )

    def test_run(self) -> None:
        # coverage run [-p] [-L] [--timid] MODULE.py [ARG1 ARG2 ...]

        # run calls coverage.erase first.
        self.cmd_executes(
            "run foo.py",
            """\
            cov = Coverage()
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        # run -a combines with an existing data file before saving.
        self.cmd_executes(
            "run -a foo.py",
            """\
            cov = Coverage()
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.load()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        # --timid sets a flag, and program arguments get passed through.
        self.cmd_executes(
            "run --timid foo.py abc 123",
            """\
            cov = Coverage(timid=True)
            runner = PyRunner(['foo.py', 'abc', '123'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        # -L sets a flag, and flags for the program don't confuse us.
        self.cmd_executes(
            "run -p -L foo.py -a -b",
            """\
            cov = Coverage(cover_pylib=True, data_suffix=True)
            runner = PyRunner(['foo.py', '-a', '-b'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --branch foo.py",
            """\
            cov = Coverage(branch=True)
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --rcfile=myrc.rc foo.py",
            """\
            cov = Coverage(config_file="myrc.rc")
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --include=pre1,pre2 foo.py",
            """\
            cov = Coverage(include=["pre1", "pre2"])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --omit=opre1,opre2 foo.py",
            """\
            cov = Coverage(omit=["opre1", "opre2"])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --include=pre1,pre2 --omit=opre1,opre2 foo.py",
            """\
            cov = Coverage(include=["pre1", "pre2"], omit=["opre1", "opre2"])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --source=quux,hi.there,/home/bar foo.py",
            """\
            cov = Coverage(source=["quux", "hi.there", "/home/bar"])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --concurrency=gevent foo.py",
            """\
            cov = Coverage(concurrency=['gevent'])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --concurrency=multiprocessing foo.py",
            """\
            cov = Coverage(concurrency=['multiprocessing'])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --concurrency=gevent,thread foo.py",
            """\
            cov = Coverage(concurrency=['gevent', 'thread'])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --data-file=output.coverage foo.py",
            """\
            cov = Coverage(data_file="output.coverage")
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )

    def test_multiprocessing_needs_config_file(self) -> None:
        # You can't use command-line args to add options to multiprocessing
        # runs, since they won't make it to the subprocesses. You need to use a
        # config file.
        self.command_line("run --concurrency=multiprocessing --branch foo.py", ret=ERR)
        msg = "Options affecting multiprocessing must only be specified in a configuration file."
        _, err = self.stdouterr()
        assert msg in err
        assert "Remove --branch from the command line." in err

    def test_run_debug(self) -> None:
        self.cmd_executes(
            "run --debug=opt1 foo.py",
            """\
            cov = Coverage(debug=["opt1"])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --debug=opt1,opt2 foo.py",
            """\
            cov = Coverage(debug=["opt1","opt2"])
            runner = PyRunner(['foo.py'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )

    def test_run_module(self) -> None:
        self.cmd_executes(
            "run -m mymodule",
            """\
            cov = Coverage()
            runner = PyRunner(['mymodule'], as_module=True)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run -m mymodule -qq arg1 arg2",
            """\
            cov = Coverage()
            runner = PyRunner(['mymodule', '-qq', 'arg1', 'arg2'], as_module=True)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes(
            "run --branch -m mymodule",
            """\
            cov = Coverage(branch=True)
            runner = PyRunner(['mymodule'], as_module=True)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
        )
        self.cmd_executes_same("run -m mymodule", "run --module mymodule")

    def test_run_nothing(self) -> None:
        self.command_line("run", ret=ERR)
        assert "Nothing to do" in self.stderr()

    def test_run_from_config(self) -> None:
        options = {"run:command_line": "myprog.py a 123 'a quoted thing' xyz"}
        self.cmd_executes(
            "run",
            """\
            cov = Coverage()
            runner = PyRunner(['myprog.py', 'a', '123', 'a quoted thing', 'xyz'], as_module=False)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
            options=options,
        )

    def test_run_module_from_config(self) -> None:
        self.cmd_executes(
            "run",
            """\
            cov = Coverage()
            runner = PyRunner(['mymodule', 'thing1', 'thing2'], as_module=True)
            runner.prepare()
            cov.start()
            runner.run()
            cov.stop()
            cov.save()
            """,
            options={"run:command_line": "-m mymodule thing1 thing2"},
        )

    def test_run_from_config_but_empty(self) -> None:
        self.cmd_executes(
            "run",
            """\
            cov = Coverage()
            show_help('Nothing to do.')
            """,
            ret=ERR,
            options={"run:command_line": ""},
        )

    def test_run_dashm_only(self) -> None:
        self.cmd_executes(
            "run -m",
            """\
            cov = Coverage()
            show_help('No module specified for -m')
            """,
            ret=ERR,
        )
        self.cmd_executes(
            "run -m",
            """\
            cov = Coverage()
            show_help('No module specified for -m')
            """,
            ret=ERR,
            options={"run:command_line": "myprog.py"},
        )

    def test_cant_append_parallel(self) -> None:
        self.command_line("run --append --parallel-mode foo.py", ret=ERR)
        assert "Can't append to data files in parallel mode." in self.stderr()

    def test_xml(self) -> None:
        # coverage xml [-i] [--omit DIR,...] [FILE1 FILE2 ...]
        self.cmd_executes(
            "xml",
            """\
            cov = Coverage()
            cov.load()
            cov.xml_report()
            """,
        )
        self.cmd_executes(
            "xml -i",
            """\
            cov = Coverage()
            cov.load()
            cov.xml_report(ignore_errors=True)
            """,
        )
        self.cmd_executes(
            "xml -o myxml.foo",
            """\
            cov = Coverage()
            cov.load()
            cov.xml_report(outfile="myxml.foo")
            """,
        )
        self.cmd_executes(
            "xml -o -",
            """\
            cov = Coverage()
            cov.load()
            cov.xml_report(outfile="-")
            """,
        )
        self.cmd_executes(
            "xml --omit fooey",
            """\
            cov = Coverage(omit=["fooey"])
            cov.load()
            cov.xml_report(omit=["fooey"])
            """,
        )
        self.cmd_executes(
            "xml --omit fooey,booey",
            """\
            cov = Coverage(omit=["fooey", "booey"])
            cov.load()
            cov.xml_report(omit=["fooey", "booey"])
            """,
        )
        self.cmd_executes(
            "xml mod1",
            """\
            cov = Coverage()
            cov.load()
            cov.xml_report(morfs=["mod1"])
            """,
        )
        self.cmd_executes(
            "xml mod1 mod2 mod3",
            """\
            cov = Coverage()
            cov.load()
            cov.xml_report(morfs=["mod1", "mod2", "mod3"])
            """,
        )
        self.cmd_executes(
            "xml -q",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.xml_report()
            """,
        )
        self.cmd_executes(
            "xml --quiet",
            """\
            cov = Coverage(messages=False)
            cov.load()
            cov.xml_report()
            """,
        )

    def test_no_arguments_at_all(self) -> None:
        self.cmd_help("", topic="minimum_help", ret=OK)

    def test_bad_command(self) -> None:
        self.cmd_help("xyzzy", "Unknown command: 'xyzzy'")

    def test_save_signal_wrong(self) -> None:
        self.cmd_help(
            "run --save-signal=XYZ nothing.py",
            "option --save-signal: invalid choice: 'XYZ' (choose from 'USR1', 'USR2')",
        )

    @pytest.mark.skipif(not env.WINDOWS, reason="this is a windows-only error")
    def test_save_signal_windows(self) -> None:
        self.cmd_help(
            "run --save-signal=USR1 nothing.py",
            "--save-signal is not supported on Windows.",
        )


class CmdLineDebugDataTest(BaseCmdLineTest):
    """Test the `debug data` command line."""

    run_in_temp_dir = True

    @pytest.mark.parametrize(
        "filename, ddarg",
        [
            (None, ""),
            ("mydata.dat", "mydata.dat"),
        ],
    )
    def test_debug_data(self, filename: str | None, ddarg: str) -> None:
        data = self.make_data_file(
            basename=filename,
            lines={
                "file1.py": range(1, 18),
                "file2.py": range(1, 24),
            },
            file_tracers={"file1.py": "a_plugin"},
        )

        self.command_line(f"debug data {ddarg}")
        assert self.stdout() == textwrap.dedent(f"""\
            -- data ------------------------------------------------------
            path: {data.data_filename()}
            has_arcs: False
            2 files:
            file1.py: 17 lines [a_plugin]
            file2.py: 23 lines
            """)

    @pytest.mark.parametrize(
        "filename, ddarg",
        [
            (".coverage", ""),
            ("mydata.dat", "mydata.dat"),
        ],
    )
    def test_debug_data_with_no_data_file(self, filename: str, ddarg: str) -> None:
        self.command_line(f"debug data {ddarg}")
        assert self.stdout() == textwrap.dedent(f"""\
            -- data ------------------------------------------------------
            path: {Path(".").resolve() / filename}
            No data collected: file doesn't exist
            """)

    def test_debug_combinable_data(self) -> None:
        data1 = self.make_data_file(lines={"file1.py": range(1, 18), "file2.py": [1]})
        data2 = self.make_data_file(suffix="123", lines={"file2.py": range(1, 10)})

        self.command_line("debug data")
        assert self.stdout() == textwrap.dedent(f"""\
            -- data ------------------------------------------------------
            path: {data1.data_filename()}
            has_arcs: False
            2 files:
            file1.py: 17 lines
            file2.py: 1 line
            -----
            path: {data2.data_filename()}
            has_arcs: False
            1 file:
            file2.py: 9 lines
            """)

    def test_debug_multiple_files(self) -> None:
        data1 = self.make_data_file(
            basename="data1.dat",
            lines={"file11.py": range(1, 38), "file12.py": [1, 2]},
        )
        data2 = self.make_data_file(
            basename="data2.dat",
            lines={"file1.py": range(1, 18), "file2.py": [1]},
        )
        data3 = self.make_data_file(
            basename="data2.dat",
            suffix="123",
            lines={"file2.py": range(1, 10)},
        )

        self.command_line("debug data data1.dat data2.dat")
        assert self.stdout() == textwrap.dedent(f"""\
            -- data ------------------------------------------------------
            path: {data1.data_filename()}
            has_arcs: False
            2 files:
            file11.py: 37 lines
            file12.py: 2 lines
            -- data ------------------------------------------------------
            path: {data2.data_filename()}
            has_arcs: False
            2 files:
            file1.py: 17 lines
            file2.py: 1 line
            -----
            path: {data3.data_filename()}
            has_arcs: False
            1 file:
            file2.py: 9 lines
            """)


class CmdLineStdoutTest(BaseCmdLineTest):
    """Test the command line with real stdout output."""

    def test_minimum_help(self) -> None:
        self.command_line("")
        out = self.stdout()
        assert "Code coverage for Python" in out
        assert out.count("\n") < 4

    def test_version(self) -> None:
        self.command_line("--version")
        out = self.stdout()
        assert "ersion " in out
        if testenv.C_TRACER:
            assert "with C extension" in out
        else:
            assert "without C extension" in out
        assert out.count("\n") < 4

    def test_help_contains_command_name(self) -> None:
        # Command name should be present in help output.
        fake_command_path = os_sep("lorem/ipsum/dolor")
        expected_command_name = "dolor"
        fake_argv = [fake_command_path, "sit", "amet"]
        with mock.patch.object(sys, "argv", new=fake_argv):
            self.command_line("help")
        out = self.stdout()
        assert expected_command_name in out

    def test_help_contains_command_name_from_package(self) -> None:
        # Command package name should be present in help output.
        #
        # When the main module is actually a package's `__main__` module, the resulting command line
        # has the `__main__.py` file's patch as the command name. Instead, the command name should
        # be derived from the package name.

        fake_command_path = os_sep("lorem/ipsum/dolor/__main__.py")
        expected_command_name = "dolor"
        fake_argv = [fake_command_path, "sit", "amet"]
        with mock.patch.object(sys, "argv", new=fake_argv):
            self.command_line("help")
        out = self.stdout()
        assert expected_command_name in out

    def test_help(self) -> None:
        self.command_line("help")
        lines = self.stdout().splitlines()
        assert len(lines) > 10
        assert lines[-1] == f"Full documentation is at {__url__}"

    def test_cmd_help(self) -> None:
        self.command_line("help run")
        out = self.stdout()
        lines = out.splitlines()
        assert "<pyfile>" in lines[0]
        assert "--timid" in out
        assert len(lines) > 20
        assert lines[-1] == f"Full documentation is at {__url__}"

    def test_unknown_topic(self) -> None:
        # Should probably be an ERR return, but meh.
        self.command_line("help foobar")
        lines = self.stdout().splitlines()
        assert lines[0] == "Don't know topic 'foobar'"
        assert lines[-1] == f"Full documentation is at {__url__}"

    def test_error(self) -> None:
        self.command_line("fooey kablooey", ret=ERR)
        err = self.stderr()
        assert "fooey" in err
        assert "help" in err

    def test_option_error(self) -> None:
        self.command_line("run --fooey", ret=ERR)
        err = self.stderr()
        assert "fooey" in err
        assert "help" in err

    def test_doc_url(self) -> None:
        assert __url__.startswith("https://coverage.readthedocs.io")


class CmdMainTest(CoverageTest):
    """Tests of coverage.cmdline.main(), using mocking for isolation."""

    run_in_temp_dir = False

    class CoverageScriptStub:
        """A stub for coverage.cmdline.CoverageScript, used by CmdMainTest."""

        def command_line(self, argv: list[str]) -> int:
            """Stub for command_line, the arg determines what it will do."""
            if argv[0] == "hello":
                print("Hello, world!")
            elif argv[0] == "raise":
                try:
                    raise RuntimeError("oh noes!")
                except:
                    raise _ExceptionDuringRun(*sys.exc_info()) from None
            elif argv[0] == "internalraise":
                raise ValueError("coverage is broken")
            elif argv[0] == "exit":
                sys.exit(23)
            else:
                raise AssertionError(f"Bad CoverageScriptStub: {argv!r}")
            return 0

    def setUp(self) -> None:
        super().setUp()
        old_CoverageScript = coverage.cmdline.CoverageScript
        coverage.cmdline.CoverageScript = self.CoverageScriptStub  # type: ignore
        self.addCleanup(setattr, coverage.cmdline, "CoverageScript", old_CoverageScript)

    def test_normal(self) -> None:
        ret = coverage.cmdline.main(["hello"])
        assert ret == 0
        assert self.stdout() == "Hello, world!\n"

    def test_raise(self) -> None:
        ret = coverage.cmdline.main(["raise"])
        assert ret == 1
        out, err = self.stdouterr()
        assert out == ""
        print(err)
        err_parts = err.splitlines(keepends=True)
        assert err_parts[0] == "Traceback (most recent call last):\n"
        assert '    raise RuntimeError("oh noes!")\n' in err_parts
        assert err_parts[-1] == "RuntimeError: oh noes!\n"

    def test_internalraise(self) -> None:
        with pytest.raises(ValueError, match="coverage is broken"):
            coverage.cmdline.main(["internalraise"])

    def test_exit(self) -> None:
        ret = coverage.cmdline.main(["exit"])
        assert ret == 23


class CoverageReportingFake:
    """A fake Coverage.coverage test double for FailUnderTest methods."""

    # pylint: disable=missing-function-docstring
    def __init__(
        self,
        report_result: float,
        html_result: float = 0,
        xml_result: float = 0,
        json_report: float = 0,
        lcov_result: float = 0,
    ) -> None:
        self.config = CoverageConfig()
        self.report_result = report_result
        self.html_result = html_result
        self.xml_result = xml_result
        self.json_result = json_report
        self.lcov_result = lcov_result

    def set_option(self, optname: str, optvalue: TConfigValueIn) -> None:
        self.config.set_option(optname, optvalue)

    def get_option(self, optname: str) -> TConfigValueOut:
        return self.config.get_option(optname)

    def load(self) -> None:
        pass

    def report(self, *args_unused: Any, **kwargs_unused: Any) -> float:
        return self.report_result

    def html_report(self, *args_unused: Any, **kwargs_unused: Any) -> float:
        return self.html_result

    def xml_report(self, *args_unused: Any, **kwargs_unused: Any) -> float:
        return self.xml_result

    def json_report(self, *args_unused: Any, **kwargs_unused: Any) -> float:
        return self.json_result

    def lcov_report(self, *args_unused: Any, **kwargs_unused: Any) -> float:
        return self.lcov_result


class FailUnderTest(CoverageTest):
    """Tests of the --fail-under handling in cmdline.py."""

    @pytest.mark.parametrize(
        "results, fail_under, cmd, ret",
        [
            # Command-line switch properly checks the result of reporting functions.
            ((20, 30, 40, 50, 60), None, "report --fail-under=19", 0),
            ((20, 30, 40, 50, 60), None, "report --fail-under=21", 2),
            ((20, 30, 40, 50, 60), None, "html --fail-under=29", 0),
            ((20, 30, 40, 50, 60), None, "html --fail-under=31", 2),
            ((20, 30, 40, 50, 60), None, "xml --fail-under=39", 0),
            ((20, 30, 40, 50, 60), None, "xml --fail-under=41", 2),
            ((20, 30, 40, 50, 60), None, "json --fail-under=49", 0),
            ((20, 30, 40, 50, 60), None, "json --fail-under=51", 2),
            ((20, 30, 40, 50, 60), None, "lcov --fail-under=59", 0),
            ((20, 30, 40, 50, 60), None, "lcov --fail-under=61", 2),
            # Configuration file setting properly checks the result of reporting.
            ((20, 30, 40, 50, 60), 19, "report", 0),
            ((20, 30, 40, 50, 60), 21, "report", 2),
            ((20, 30, 40, 50, 60), 29, "html", 0),
            ((20, 30, 40, 50, 60), 31, "html", 2),
            ((20, 30, 40, 50, 60), 39, "xml", 0),
            ((20, 30, 40, 50, 60), 41, "xml", 2),
            ((20, 30, 40, 50, 60), 49, "json", 0),
            ((20, 30, 40, 50, 60), 51, "json", 2),
            ((20, 30, 40, 50, 60), 59, "lcov", 0),
            ((20, 30, 40, 50, 60), 61, "lcov", 2),
            # Command-line overrides configuration.
            ((20, 30, 40, 50, 60), 19, "report --fail-under=21", 2),
        ],
    )
    def test_fail_under(
        self,
        results: tuple[float, float, float, float, float],
        fail_under: float | None,
        cmd: str,
        ret: int,
    ) -> None:
        cov = CoverageReportingFake(*results)
        if fail_under is not None:
            cov.set_option("report:fail_under", fail_under)
        with mock.patch("coverage.cmdline.Coverage", lambda *a, **kw: cov):
            self.command_line(cmd, ret)

    @pytest.mark.parametrize(
        "result, cmd, ret, msg",
        [
            (20.5, "report --fail-under=20.4 --precision=1", 0, ""),
            (
                20.5,
                "report --fail-under=20.6 --precision=1",
                2,
                "Coverage failure: total of 20.5 is less than fail-under=20.6\n",
            ),
            (
                20.12345,
                "report --fail-under=20.1235 --precision=5",
                2,
                "Coverage failure: total of 20.12345 is less than fail-under=20.12350\n",
            ),
            (20.12339, "report --fail-under=20.1234 --precision=4", 0, ""),
        ],
    )
    def test_fail_under_with_precision(self, result: float, cmd: str, ret: int, msg: str) -> None:
        cov = CoverageReportingFake(report_result=result)
        with mock.patch("coverage.cmdline.Coverage", lambda *a, **kw: cov):
            self.command_line(cmd, ret)
        assert self.stdout() == msg
