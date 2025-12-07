# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Test the config file handling for coverage.py"""

from __future__ import annotations

import os
import tempfile

from pathlib import Path
from unittest import mock

import pytest

import coverage
from coverage import Coverage, env
from coverage.config import CoverageConfig, HandyConfigParser
from coverage.exceptions import ConfigError, CoverageWarning
from coverage.tomlconfig import TomlConfigParser
from coverage.types import FilePathClasses, FilePathType

from tests.coveragetest import CoverageTest, UsingModulesMixin


class ConfigTest(CoverageTest):
    """Tests of the different sources of configuration settings."""

    def test_default_config(self) -> None:
        # Just constructing a coverage() object gets the right defaults.
        cov = coverage.Coverage()
        assert not cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == ".coverage"

    def test_arguments(self) -> None:
        # Arguments to the constructor are applied to the configuration.
        cov = coverage.Coverage(timid=True, data_file="fooey.dat", concurrency="multiprocessing")
        assert cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == "fooey.dat"
        assert cov.config.concurrency == ["multiprocessing"]

    def test_config_file(self) -> None:
        # A .coveragerc file will be read into the configuration.
        self.make_file(
            ".coveragerc",
            """\
            # This is just a bogus .rc file for testing.
            [run]
            timid =         True
            data_file =     .hello_kitty.data
            """,
        )
        cov = coverage.Coverage()
        assert cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == ".hello_kitty.data"

    @pytest.mark.parametrize("file_class", FilePathClasses)
    def test_named_config_file(self, file_class: FilePathType) -> None:
        # You can name the config file what you like.
        self.make_file(
            "my_cov.ini",
            """\
            [run]
            timid = True
            ; I wouldn't really use this as a data file...
            data_file = delete.me
            """,
        )
        cov = coverage.Coverage(config_file=file_class("my_cov.ini"))
        assert cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == "delete.me"

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_toml_config_file(self, filename: str) -> None:
        # A pyproject.toml or .coveragerc.toml file will be read into the configuration.
        self.make_file(
            filename,
            """\
            # This is just a bogus toml file for testing.
            [tool.somethingelse]
            authors = ["Joe D'Ávila <joe@gmail.com>"]
            [tool.coverage.run]
            concurrency = ["thread", "eventlet"]
            timid = true
            data_file = ".hello_kitty.data"
            plugins = ["plugins.a_plugin"]
            [tool.coverage.report]
            precision = 3
            fail_under = 90.5
            [tool.coverage.html]
            title = "tabblo & «ταБЬℓσ»"
            [tool.coverage.plugins.a_plugin]
            hello = "world"
            """,
        )
        cov = coverage.Coverage()
        assert cov.config.timid
        assert not cov.config.branch
        assert cov.config.concurrency == ["thread", "eventlet"]
        assert cov.config.data_file == ".hello_kitty.data"
        assert cov.config.plugins == ["plugins.a_plugin"]
        assert cov.config.precision == 3
        assert cov.config.html_title == "tabblo & «ταБЬℓσ»"
        assert cov.config.fail_under == 90.5
        assert cov.config.get_plugin_options("plugins.a_plugin") == {"hello": "world"}

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_toml_ints_can_be_floats(self, filename: str) -> None:
        # Test that our class doesn't reject integers when loading floats
        self.make_file(
            filename,
            """\
            # This is just a bogus toml file for testing.
            [tool.coverage.report]
            fail_under = 90
            """,
        )
        cov = coverage.Coverage()
        assert cov.config.fail_under == 90
        assert isinstance(cov.config.fail_under, float)

    def test_ignored_config_file(self) -> None:
        # You can disable reading the .coveragerc file.
        self.make_file(
            ".coveragerc",
            """\
            [run]
            timid = True
            data_file = delete.me
            """,
        )
        cov = coverage.Coverage(config_file=False)
        assert not cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == ".coverage"

    def test_config_file_then_args(self) -> None:
        # The arguments override the .coveragerc file.
        self.make_file(
            ".coveragerc",
            """\
            [run]
            timid = True
            data_file = weirdo.file
            """,
        )
        cov = coverage.Coverage(timid=False, data_file=".mycov")
        assert not cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == ".mycov"

    def test_data_file_from_environment(self) -> None:
        # There's an environment variable for the data_file.
        self.make_file(
            ".coveragerc",
            """\
            [run]
            timid = True
            data_file = weirdo.file
            """,
        )
        self.set_environ("COVERAGE_FILE", "fromenv.dat")
        cov = coverage.Coverage()
        assert cov.config.data_file == "fromenv.dat"
        # But the constructor arguments override the environment variable.
        cov = coverage.Coverage(data_file="fromarg.dat")
        assert cov.config.data_file == "fromarg.dat"

    def test_debug_from_environment(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [run]
            debug = dataio, pids
            """,
        )
        self.set_environ("COVERAGE_DEBUG", "callers, fooey")
        cov = coverage.Coverage()
        assert cov.config.debug == ["dataio", "pids", "callers", "fooey"]

    def test_rcfile_from_environment(self) -> None:
        self.make_file(
            "here.ini",
            """\
            [run]
            data_file = overthere.dat
            """,
        )
        self.set_environ("COVERAGE_RCFILE", "here.ini")
        cov = coverage.Coverage()
        assert cov.config.data_file == "overthere.dat"

    def test_missing_rcfile_from_environment(self) -> None:
        self.set_environ("COVERAGE_RCFILE", "nowhere.ini")
        msg = "Couldn't read 'nowhere.ini' as a config file"
        with pytest.raises(ConfigError, match=msg):
            coverage.Coverage()

    @pytest.mark.parametrize("force", [False, True])
    def test_force_environment(self, force: bool) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [run]
            debug = dataio, pids
            """,
        )
        self.make_file(
            "force.ini",
            """\
            [run]
            debug = callers, fooey
            """,
        )
        if force:
            self.set_environ("COVERAGE_FORCE_CONFIG", "force.ini")
        cov = coverage.Coverage()
        if force:
            assert cov.config.debug == ["callers", "fooey"]
        else:
            assert cov.config.debug == ["dataio", "pids"]

    @pytest.mark.parametrize(
        "bad_config, msg",
        [
            ("[run]\ntimid = maybe?\n", r"maybe[?]"),
            ("timid = 1\n", r"no section headers"),
            ("[run\n", r"\[run"),
            (
                "[report]\nexclude_lines = foo(\n",
                r"Invalid \[report\].exclude_lines value 'foo\(': "
                + r"(unbalanced parenthesis|missing \))",
            ),
            (
                "[report]\nexclude_also = foo(\n",
                r"Invalid \[report\].exclude_also value 'foo\(': "
                + r"(unbalanced parenthesis|missing \))",
            ),
            (
                "[report]\npartial_branches = foo[\n",
                r"Invalid \[report\].partial_branches value 'foo\[': "
                + r"(unexpected end of regular expression|unterminated character set)",
            ),
            (
                "[report]\npartial_also = foo[\n",
                r"Invalid \[report\].partial_also value 'foo\[': "
                + r"(unexpected end of regular expression|unterminated character set)",
            ),
            (
                "[report]\npartial_branches_always = foo***\n",
                r"Invalid \[report\].partial_branches_always value "
                + r"'foo\*\*\*': "
                + r"multiple repeat",
            ),
        ],
    )
    def test_parse_errors(self, bad_config: str, msg: str) -> None:
        # Im-parsable values raise ConfigError, with details.
        self.make_file(".coveragerc", bad_config)
        with pytest.raises(ConfigError, match=msg):
            coverage.Coverage()

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    @pytest.mark.parametrize(
        "bad_config, msg",
        [
            ('[tool.coverage.run]\ntimid = "maybe?"\n', r"maybe[?]"),
            ("[tool.coverage.run\n", None),
            (
                '[tool.coverage.report]\nexclude_lines = ["foo("]\n',
                r"Invalid \[tool.coverage.report\].exclude_lines value 'foo\(': "
                + r"(unbalanced parenthesis|missing \))",
            ),
            (
                '[tool.coverage.report]\nexclude_also = ["foo("]\n',
                r"Invalid \[tool.coverage.report\].exclude_also value 'foo\(': "
                + r"(unbalanced parenthesis|missing \))",
            ),
            (
                '[tool.coverage.report]\npartial_branches = ["foo["]\n',
                r"Invalid \[tool.coverage.report\].partial_branches value 'foo\[': "
                + r"(unexpected end of regular expression|unterminated character set)",
            ),
            (
                '[tool.coverage.report]\npartial_also = ["foo["]\n',
                r"Invalid \[tool.coverage.report\].partial_also value 'foo\[': "
                + r"(unexpected end of regular expression|unterminated character set)",
            ),
            (
                '[tool.coverage.report]\npartial_branches_always = ["foo***"]\n',
                r"Invalid \[tool.coverage.report\].partial_branches_always value "
                + r"'foo\*\*\*': "
                + r"multiple repeat",
            ),
            ('[tool.coverage.run]\nconcurrency="foo"', "not a list"),
            ("[tool.coverage.report]\nprecision=1.23", "not an integer"),
            ('[tool.coverage.report]\nfail_under="s"', "couldn't convert to a float"),
        ],
    )
    def test_toml_parse_errors(self, filename: str, bad_config: str, msg: str) -> None:
        # Im-parsable values raise ConfigError, with details.
        self.make_file(filename, bad_config)
        with pytest.raises(ConfigError, match=msg):
            coverage.Coverage()

    def test_environment_vars_in_config(self) -> None:
        # Config files can have $envvars in them.
        self.make_file(
            ".coveragerc",
            """\
            [run]
            data_file = $DATA_FILE.fooey
            branch = $OKAY
            [report]
            exclude_lines =
                the_$$one
                another${THING}
                x${THING}y
                x${NOTHING}y
                huh$${X}what
            """,
        )
        self.set_environ("DATA_FILE", "hello-world")
        self.set_environ("THING", "ZZZ")
        self.set_environ("OKAY", "yes")
        cov = coverage.Coverage()
        assert cov.config.data_file == "hello-world.fooey"
        assert cov.config.branch is True
        assert cov.config.exclude_list == ["the_$one", "anotherZZZ", "xZZZy", "xy", "huh${X}what"]

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_environment_vars_in_toml_config(self, filename: str) -> None:
        # Config files can have $envvars in them.
        self.make_file(
            filename,
            """\
            [tool.coverage.run]
            data_file = "$DATA_FILE.fooey"
            branch = "$BRANCH"
            [tool.coverage.report]
            precision = "$DIGITS"
            fail_under = "$FAIL_UNDER"
            exclude_lines = [
                "the_$$one",
                "another${THING}",
                "x${THING}y",
                "x${NOTHING}y",
                "huh$${X}what",
            ]
            [othersection]
            # This reproduces the failure from https://github.com/coveragepy/coveragepy/issues/1481
            # When OTHER has a backslash that isn't a valid escape, like \\z (see below).
            something = "if [ $OTHER ]; then printf '%s\\n' 'Hi'; fi"
            """,
        )
        self.set_environ("BRANCH", "true")
        self.set_environ("DIGITS", "3")
        self.set_environ("FAIL_UNDER", "90.5")
        self.set_environ("DATA_FILE", "hello-world")
        self.set_environ("THING", "ZZZ")
        self.set_environ("OTHER", "hi\\zebra")
        cov = coverage.Coverage()
        assert cov.config.branch is True
        assert cov.config.precision == 3
        assert cov.config.data_file == "hello-world.fooey"
        assert cov.config.exclude_list == ["the_$one", "anotherZZZ", "xZZZy", "xy", "huh${X}what"]

    def test_tilde_in_config(self) -> None:
        # Config entries that are file paths can be tilde-expanded.
        self.make_file(
            ".coveragerc",
            """\
            [run]
            data_file = ~/data.file

            [html]
            directory = ~joe/html_dir

            [json]
            output = ~/json/output.json

            [lcov]
            output = ~/lcov/~foo.lcov

            [xml]
            output = ~/somewhere/xml.out

            [report]
            # Strings that aren't file paths are not tilde-expanded.
            exclude_lines =
                ~/data.file
                ~joe/html_dir

            [paths]
            mapping =
                ~/src
                ~joe/source
            """,
        )

        self.assert_tilde_results()

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_tilde_in_toml_config(self, filename: str) -> None:
        # Config entries that are file paths can be tilde-expanded.
        self.make_file(
            filename,
            """\
            [tool.coverage.run]
            data_file = "~/data.file"

            [tool.coverage.html]
            directory = "~joe/html_dir"

            [tool.coverage.json]
            output = "~/json/output.json"

            [tool.coverage.lcov]
            output = "~/lcov/~foo.lcov"

            [tool.coverage.xml]
            output = "~/somewhere/xml.out"

            [tool.coverage.report]
            # Strings that aren't file paths are not tilde-expanded.
            exclude_lines = [
                "~/data.file",
                "~joe/html_dir",
            ]

            [tool.coverage.paths]
            mapping = [
                "~/src",
                "~joe/source",
            ]
            """,
        )

        self.assert_tilde_results()

    def assert_tilde_results(self) -> None:
        """Common assertions for two tilde tests."""

        def expanduser(s: str) -> str:
            """Fake tilde expansion"""
            s = s.replace("~/", "/Users/me/")
            s = s.replace("~joe/", "/Users/joe/")
            return s

        with mock.patch.object(
            coverage.config.os.path,  # type: ignore[attr-defined]
            "expanduser",
            new=expanduser,
        ):
            cov = coverage.Coverage()
        assert cov.config.data_file == "/Users/me/data.file"
        assert cov.config.html_dir == "/Users/joe/html_dir"
        assert cov.config.json_output == "/Users/me/json/output.json"
        assert cov.config.lcov_output == "/Users/me/lcov/~foo.lcov"
        assert cov.config.xml_output == "/Users/me/somewhere/xml.out"
        assert cov.config.exclude_list == ["~/data.file", "~joe/html_dir"]
        assert cov.config.paths == {"mapping": ["/Users/me/src", "/Users/joe/source"]}

    def test_tweaks_after_constructor(self) -> None:
        # set_option can be used after construction to affect the config.
        cov = coverage.Coverage(timid=True, data_file="fooey.dat")
        cov.set_option("run:timid", False)

        assert not cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == "fooey.dat"

        assert not cov.get_option("run:timid")
        assert not cov.get_option("run:branch")
        assert cov.get_option("run:data_file") == "fooey.dat"

    def test_tweaks_paths_after_constructor(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [paths]
            first =
                /first/1
                /first/2

            second =
                /second/a
                /second/b
            """,
        )
        old_paths = {
            "first": ["/first/1", "/first/2"],
            "second": ["/second/a", "/second/b"],
        }
        cov = coverage.Coverage()
        paths = cov.get_option("paths")
        assert paths == old_paths

        new_paths = {
            "magic": ["src", "ok"],
        }
        cov.set_option("paths", new_paths)

        assert cov.get_option("paths") == new_paths

    def test_tweak_error_checking(self) -> None:
        # Trying to set an unknown config value raises an error.
        cov = coverage.Coverage()
        with pytest.raises(ConfigError, match="No such option: 'run:xyzzy'"):
            cov.set_option("run:xyzzy", 12)
        with pytest.raises(ConfigError, match="No such option: 'xyzzy:foo'"):
            cov.set_option("xyzzy:foo", 12)
        with pytest.raises(ConfigError, match="No such option: 'run:xyzzy'"):
            _ = cov.get_option("run:xyzzy")
        with pytest.raises(ConfigError, match="No such option: 'xyzzy:foo'"):
            _ = cov.get_option("xyzzy:foo")

    def test_tweak_plugin_options(self) -> None:
        # Plugin options have a more flexible syntax.
        cov = coverage.Coverage()
        cov.set_option("run:plugins", ["fooey.plugin", "xyzzy.coverage.plugin"])
        cov.set_option("fooey.plugin:xyzzy", 17)
        cov.set_option("xyzzy.coverage.plugin:plugh", ["a", "b"])
        with pytest.raises(ConfigError, match="No such option: 'no_such.plugin:foo'"):
            cov.set_option("no_such.plugin:foo", 23)

        assert cov.get_option("fooey.plugin:xyzzy") == 17
        assert cov.get_option("xyzzy.coverage.plugin:plugh") == ["a", "b"]
        with pytest.raises(ConfigError, match="No such option: 'no_such.plugin:foo'"):
            _ = cov.get_option("no_such.plugin:foo")

    def test_unknown_option(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [run]
            xyzzy = 17
            """,
        )
        msg = r"Unrecognized option '\[run\] xyzzy=' in config file .coveragerc"
        with pytest.warns(CoverageWarning, match=msg):
            _ = coverage.Coverage()

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_unknown_option_toml(self, filename: str) -> None:
        self.make_file(
            filename,
            """\
            [tool.coverage.run]
            xyzzy = 17
            """,
        )
        msg = rf"Unrecognized option '\[tool.coverage.run\] xyzzy=' in config file {filename}"
        with pytest.warns(CoverageWarning, match=msg):
            _ = coverage.Coverage()

    def test_unknown_patch(self) -> None:
        self.make_file("foo.py", "a = 1")
        self.make_file(
            ".coveragerc",
            """\
            [run]
            patch =
                _exit
                xyzzy
            """,
        )
        msg = "Unknown patch 'xyzzy'"
        with pytest.raises(ConfigError, match=msg):
            cov = coverage.Coverage()
            self.start_import_stop(cov, "foo")

    def test_misplaced_option(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [report]
            branch = True
            """,
        )
        msg = r"Unrecognized option '\[report\] branch=' in config file .coveragerc"
        with pytest.warns(CoverageWarning, match=msg):
            _ = coverage.Coverage()

    def test_unknown_option_in_other_ini_file(self) -> None:
        self.make_file(
            "setup.cfg",
            """\
            [coverage:run]
            huh = what?
            """,
        )
        msg = r"Unrecognized option '\[coverage:run\] huh=' in config file setup.cfg"
        with pytest.warns(CoverageWarning, match=msg):
            _ = coverage.Coverage()

    def test_exceptions_from_missing_things(self) -> None:
        self.make_file(
            "config.ini",
            """\
            [run]
            branch = True
            """,
        )
        config = HandyConfigParser(True)
        config.read(["config.ini"])
        with pytest.raises(ConfigError, match="No section: 'xyzzy'"):
            config.options("xyzzy")
        with pytest.raises(ConfigError, match="No option 'foo' in section: 'xyzzy'"):
            config.get("xyzzy", "foo")

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_exclude_also(self, filename: str) -> None:
        self.make_file(
            filename,
            """\
            [tool.coverage.report]
            exclude_also = ["foobar", "raise .*Error"]
            """,
        )
        cov = coverage.Coverage()

        expected = coverage.config.DEFAULT_EXCLUDE + ["foobar", "raise .*Error"]
        assert cov.config.exclude_list == expected

    def test_partial_also(self) -> None:
        self.make_file(
            "pyproject.toml",
            """\
            [tool.coverage.report]
            partial_also = ["foobar", "raise .*Error"]
            """,
        )
        cov = coverage.Coverage()

        expected = coverage.config.DEFAULT_PARTIAL + ["foobar", "raise .*Error"]
        assert cov.config.partial_list == expected

    def test_core_option(self) -> None:
        # Test that the core option can be set in the configuration file.
        self.del_environ("COVERAGE_CORE")
        cov = coverage.Coverage()
        default_core = cov.config.core
        core_to_set = "ctrace" if default_core == "pytrace" else "pytrace"

        self.make_file(
            ".coveragerc",
            f"""\
            [run]
            core = {core_to_set}
            """,
        )
        cov = coverage.Coverage()
        assert cov.config.core == core_to_set
        os.remove(".coveragerc")

        self.make_file(
            "pyproject.toml",
            f"""\
            [tool.coverage.run]
            core = "{core_to_set}"
            """,
        )

        cov = coverage.Coverage()
        assert cov.config.core == core_to_set


class ConfigFileTest(UsingModulesMixin, CoverageTest):
    """Tests of the config file settings in particular."""

    # This sample file tries to use lots of variation of syntax...
    # The {section} placeholder lets us nest these settings in another file.
    LOTSA_SETTINGS = """\
        # This is a settings file for coverage.py
        [{section}run]
        timid = yes
        data_file = something_or_other.dat
        branch = 1
        cover_pylib = TRUE
        parallel = on
        concurrency = thread
        ; this omit is overridden by the omit from [report]
        omit = twenty
        source = myapp
        source_pkgs = ned
        source_dirs = cooldir
        plugins =
            plugins.a_plugin
            plugins.another
        debug = callers, pids  ,     dataio
        disable_warnings =     abcd  ,  efgh

        [{section}report]
        ; these settings affect reporting.
        exclude_lines =
            if 0:

            pragma:?\\s+no cover
                another_tab

        ignore_errors = TRUE
        omit =
            one, another, some_more,
                yet_more
        include = thirty
        precision = 3

        partial_branches =
            pragma:?\\s+no branch
        partial_branches_always =
            if 0:
            while True:

        show_missing= TruE
        skip_covered = TruE
        skip_empty  =TruE

        include_namespace_packages = TRUE

        [{section}html]

        directory    =     c:\\tricky\\dir.somewhere
        extra_css=something/extra.css
        title = Title & nums # nums!
        [{section}xml]
        output=mycov.xml
        package_depth          =                                17

        [{section}paths]
        source =
            .
            /home/ned/src/

        other = other, /home/ned/other, c:\\Ned\\etc

        [{section}plugins.a_plugin]
        hello = world
        ; comments still work.
        names = Jane/John/Jenny

        [{section}json]
        pretty_print = True
        show_contexts = True
        """

    # Just some sample setup.cfg text from the docs.
    SETUP_CFG = """\
        [bdist_rpm]
        release = 1
        packager = Jane Packager <janep@pysoft.com>
        doc_files = CHANGES.txt
                    README.txt
                    USAGE.txt
                    doc/
                    examples/
        """

    # Just some sample tox.ini text from the docs.
    TOX_INI = """\
        [tox]
        envlist = py{26,27,33,34,35}-{c,py}tracer
        skip_missing_interpreters = True

        [testenv]
        commands =
            # Create tests/zipmods.zip
            python igor.py zip_mods
        """

    def assert_config_settings_are_correct(self, cov: Coverage) -> None:
        """Check that `cov` has all the settings from LOTSA_SETTINGS."""
        assert cov.config.timid
        assert cov.config.data_file == "something_or_other.dat"
        assert cov.config.branch
        assert cov.config.cover_pylib
        assert cov.config.debug == ["callers", "pids", "dataio"]
        assert cov.config.parallel
        assert cov.config.concurrency == ["thread"]
        assert cov.config.source == ["myapp"]
        assert cov.config.source_pkgs == ["ned"]
        assert cov.config.source_dirs == ["cooldir"]
        assert cov.config.disable_warnings == ["abcd", "efgh"]

        assert cov.get_exclude_list() == ["if 0:", r"pragma:?\s+no cover", "another_tab"]
        assert cov.config.ignore_errors
        assert cov.config.run_omit == ["twenty"]
        assert cov.config.report_omit == ["one", "another", "some_more", "yet_more"]
        assert cov.config.report_include == ["thirty"]
        assert cov.config.precision == 3

        assert cov.config.partial_list == [r"pragma:?\s+no branch"]
        assert cov.config.partial_always_list == ["if 0:", "while True:"]
        assert cov.config.plugins == ["plugins.a_plugin", "plugins.another"]
        assert cov.config.show_missing
        assert cov.config.skip_covered
        assert cov.config.skip_empty
        assert cov.config.html_dir == r"c:\tricky\dir.somewhere"
        assert cov.config.extra_css == "something/extra.css"
        assert cov.config.html_title == "Title & nums # nums!"

        assert cov.config.xml_output == "mycov.xml"
        assert cov.config.xml_package_depth == 17

        assert cov.config.paths == {
            "source": [".", "/home/ned/src/"],
            "other": ["other", "/home/ned/other", "c:\\Ned\\etc"],
        }

        assert cov.config.get_plugin_options("plugins.a_plugin") == {
            "hello": "world",
            "names": "Jane/John/Jenny",
        }
        assert cov.config.get_plugin_options("plugins.another") == {}
        assert cov.config.json_show_contexts is True
        assert cov.config.json_pretty_print is True
        assert cov.config.include_namespace_packages is True

    def test_config_file_settings(self) -> None:
        self.make_file(".coveragerc", self.LOTSA_SETTINGS.format(section=""))
        cov = coverage.Coverage()
        self.assert_config_settings_are_correct(cov)

    def check_config_file_settings_in_other_file(self, fname: str, contents: str) -> None:
        """Check config will be read from another file, with prefixed sections."""
        nested = self.LOTSA_SETTINGS.format(section="coverage:")
        fname = self.make_file(fname, nested + "\n" + contents)
        cov = coverage.Coverage()
        self.assert_config_settings_are_correct(cov)

    def test_config_file_settings_in_setupcfg(self) -> None:
        self.check_config_file_settings_in_other_file("setup.cfg", self.SETUP_CFG)

    def test_config_file_settings_in_toxini(self) -> None:
        self.check_config_file_settings_in_other_file("tox.ini", self.TOX_INI)

    def check_other_config_if_coveragerc_specified(self, fname: str, contents: str) -> None:
        """Check that config `fname` is read if .coveragerc is missing, but specified."""
        nested = self.LOTSA_SETTINGS.format(section="coverage:")
        self.make_file(fname, nested + "\n" + contents)
        cov = coverage.Coverage(config_file=".coveragerc")
        self.assert_config_settings_are_correct(cov)

    def test_config_file_settings_in_setupcfg_if_coveragerc_specified(self) -> None:
        self.check_other_config_if_coveragerc_specified("setup.cfg", self.SETUP_CFG)

    def test_config_file_settings_in_tox_if_coveragerc_specified(self) -> None:
        self.check_other_config_if_coveragerc_specified("tox.ini", self.TOX_INI)

    def check_other_not_read_if_coveragerc(self, fname: str) -> None:
        """Check config `fname` is not read if .coveragerc exists."""
        self.make_file(
            ".coveragerc",
            """\
            [run]
            include = foo
            """,
        )
        self.make_file(
            fname,
            """\
            [coverage:run]
            omit = bar
            branch = true
            """,
        )
        cov = coverage.Coverage()
        assert cov.config.run_include == ["foo"]
        assert cov.config.run_omit == []
        assert cov.config.branch is False

    def test_setupcfg_only_if_not_coveragerc(self) -> None:
        self.check_other_not_read_if_coveragerc("setup.cfg")

    def test_toxini_only_if_not_coveragerc(self) -> None:
        self.check_other_not_read_if_coveragerc("tox.ini")

    def check_other_config_need_prefixes(self, fname: str) -> None:
        """Check that `fname` sections won't be read if un-prefixed."""
        self.make_file(
            fname,
            """\
            [run]
            omit = bar
            branch = true
            """,
        )
        cov = coverage.Coverage()
        assert cov.config.run_omit == []
        assert cov.config.branch is False

    def test_setupcfg_only_if_prefixed(self) -> None:
        self.check_other_config_need_prefixes("setup.cfg")

    def test_toxini_only_if_prefixed(self) -> None:
        self.check_other_config_need_prefixes("tox.ini")

    def test_tox_ini_even_if_setup_cfg(self) -> None:
        # There's a setup.cfg, but no coverage settings in it, so tox.ini
        # is read.
        nested = self.LOTSA_SETTINGS.format(section="coverage:")
        self.make_file("tox.ini", self.TOX_INI + "\n" + nested)
        self.make_file("setup.cfg", self.SETUP_CFG)
        cov = coverage.Coverage()
        self.assert_config_settings_are_correct(cov)

    def test_read_prefixed_sections_from_explicit_file(self) -> None:
        # You can point to a tox.ini, and it will find [coverage:run] sections
        nested = self.LOTSA_SETTINGS.format(section="coverage:")
        self.make_file("tox.ini", self.TOX_INI + "\n" + nested)
        cov = coverage.Coverage(config_file="tox.ini")
        self.assert_config_settings_are_correct(cov)

    def test_non_ascii(self) -> None:
        self.make_file(
            ".coveragerc",
            """\
            [report]
            exclude_lines =
                first
                ✘${TOX_ENVNAME}
                third
            [html]
            title = tabblo & «ταБЬℓσ» # numbers
            """,
        )
        self.set_environ("TOX_ENVNAME", "weirdo")
        cov = coverage.Coverage()

        assert cov.config.exclude_list == ["first", "✘weirdo", "third"]
        assert cov.config.html_title == "tabblo & «ταБЬℓσ» # numbers"

    @pytest.mark.parametrize("bad_file", ["nosuchfile.txt", "."])
    def test_unreadable_config(self, bad_file: str) -> None:
        # If a config file is explicitly specified, then it is an error for it
        # to not be readable.
        msg = f"Couldn't read {bad_file!r} as a config file"
        with pytest.raises(ConfigError, match=msg):
            coverage.Coverage(config_file=bad_file)

    def test_nocoveragerc_file_when_specified(self) -> None:
        cov = coverage.Coverage(config_file=".coveragerc")
        assert not cov.config.timid
        assert not cov.config.branch
        assert cov.config.data_file == ".coverage"

    def test_no_toml_installed_no_toml(self) -> None:
        # Can't read a toml file that doesn't exist.
        with mock.patch.object(coverage.tomlconfig, "has_tomllib", False):
            msg = "Couldn't read 'cov.toml' as a config file"
            with pytest.raises(ConfigError, match=msg):
                coverage.Coverage(config_file="cov.toml")

    @pytest.mark.skipif(env.PYVERSION >= (3, 11), reason="Python 3.11 has toml in stdlib")
    def test_no_toml_installed_explicit_toml(self) -> None:
        # Can't specify a toml config file if toml isn't installed.
        self.make_file("cov.toml", "# A toml file!")
        with mock.patch.object(coverage.tomlconfig, "has_tomllib", False):
            msg = "Can't read 'cov.toml' without TOML support"
            with pytest.raises(ConfigError, match=msg):
                coverage.Coverage(config_file="cov.toml")

    @pytest.mark.skipif(env.PYVERSION >= (3, 11), reason="Python 3.11 has toml in stdlib")
    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_no_toml_installed_pyproject_toml(self, filename: str) -> None:
        # Can't have coverage config in pyproject.toml/.coveragerc.toml without toml installed.
        self.make_file(
            filename,
            """\
            # A toml file!
            [tool.coverage.run]
            xyzzy = 17
            """,
        )
        with mock.patch.object(coverage.tomlconfig, "has_tomllib", False):
            msg = f"Can't read '{filename}' without TOML support"
            with pytest.raises(ConfigError, match=msg):
                coverage.Coverage()

    @pytest.mark.skipif(env.PYVERSION >= (3, 11), reason="Python 3.11 has toml in stdlib")
    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_no_toml_installed_pyproject_toml_shorter_syntax(self, filename: str) -> None:
        # Can't have coverage config in pyproject.toml/.coveragerc.toml without toml installed.
        self.make_file(
            filename,
            """\
            # A toml file!
            [tool.coverage]
            run.parallel = true
            """,
        )
        with mock.patch.object(coverage.tomlconfig, "has_tomllib", False):
            msg = f"Can't read '{filename}' without TOML support"
            with pytest.raises(ConfigError, match=msg):
                coverage.Coverage()

    @pytest.mark.skipif(env.PYVERSION >= (3, 11), reason="Python 3.11 has toml in stdlib")
    def test_no_toml_installed_pyproject_no_coverage(self) -> None:
        # It's ok to have non-coverage pyproject.toml without toml installed.
        self.make_file(
            "pyproject.toml",
            """\
            # A toml file!
            [tool.something]
            xyzzy = 17
            """,
        )
        with mock.patch.object(coverage.tomlconfig, "has_tomllib", False):
            cov = coverage.Coverage()
            # We get default settings:
            assert not cov.config.timid
            assert not cov.config.branch
            assert cov.config.data_file == ".coverage"

    @pytest.mark.parametrize("filename", ["pyproject.toml", ".coveragerc.toml"])
    def test_exceptions_from_missing_toml_things(self, filename: str) -> None:
        self.make_file(
            filename,
            """\
            [tool.coverage.run]
            branch = true
            """,
        )
        config = TomlConfigParser(False)
        config.read(filename)
        with pytest.raises(ConfigError, match="No section: 'xyzzy'"):
            config.options("xyzzy")
        with pytest.raises(ConfigError, match="No section: 'xyzzy'"):
            config.get("xyzzy", "foo")
        with pytest.raises(ConfigError, match="No option 'foo' in section: 'tool.coverage.run'"):
            config.get("run", "foo")

    def test_coveragerc_toml_priority(self) -> None:
        """Test that .coveragerc.toml has priority over pyproject.toml."""
        self.make_file(
            ".coveragerc.toml",
            """\
            [tool.coverage.run]
            timid = true
            data_file = ".toml-data.dat"
            branch = true
            """,
        )

        self.make_file(
            "pyproject.toml",
            """\
            [tool.coverage.run]
            timid = false
            data_file = "pyproject-data.dat"
            branch = false
            """,
        )
        cov = coverage.Coverage()

        assert cov.config.timid is True
        assert cov.config.data_file == ".toml-data.dat"
        assert cov.config.branch is True

    def test_coveragerc_toml_unprefixed_syntax(self) -> None:
        """Test that .coveragerc.toml supports unprefixed section syntax."""
        self.make_file(
            ".coveragerc.toml",
            """\
            [run]
            timid = true
            data_file = ".toml-data.dat"
            branch = true
            
            [report]
            precision = 2
            """,
        )
        cov = coverage.Coverage()

        assert cov.config.timid is True
        assert cov.config.data_file == ".toml-data.dat"
        assert cov.config.branch is True
        assert cov.config.precision == 2

    def test_pyproject_toml_ignores_unprefixed_sections(self) -> None:
        """Test that pyproject.toml ignores unprefixed sections."""
        self.make_file(
            "pyproject.toml",
            """\
            [run]
            timid = true
            data_file = "should-be-ignored.dat"
            branch = true
            
            [tool.coverage.run]
            data_file = "correct-data.dat"
            """,
        )
        cov = coverage.Coverage()

        assert cov.config.timid is False
        assert cov.config.data_file == "correct-data.dat"
        assert cov.config.branch is False


class SerializeConfigTest(CoverageTest):
    """Tests of serializing the configuration for subprocesses."""

    def test_them(self) -> None:
        tmpsrc = str(Path(tempfile.gettempdir()) / "more_source")
        self.make_file(
            ".coveragerc",
            f"""\
            [run]
            timid = True
            data_file = somewhere/the_data.db
            debug_file = somewhere/debug.out
            source = my_src, their_src
            source_dirs = my_src, their_src, {tmpsrc}
            debug = this_thing, that_thing
            """,
        )
        self.make_file("my_src/__init__.py")
        self.make_file("that_thing/__init__.py")
        cov = coverage.Coverage()
        config2 = CoverageConfig.deserialize(cov.config.serialize())
        assert config2.timid
        assert config2.data_file == os.path.abspath("somewhere/the_data.db")
        assert config2.debug_file == os.path.abspath("somewhere/debug.out")
        assert config2.source == [
            os.path.abspath("my_src"),
            "their_src",
        ]
        assert config2.source_dirs == [
            os.path.abspath("my_src"),
            os.path.abspath("their_src"),
            tmpsrc,
        ]
        assert config2.debug == ["this_thing", "that_thing"]
