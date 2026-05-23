# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tests for XML reports from coverage.py."""

from __future__ import annotations

import os
import os.path
import re

from typing import Any
from collections.abc import Iterable
from xml.etree import ElementTree

import pytest

import coverage
import coverage.files
from coverage import Coverage, env
from coverage.exceptions import NoDataError
from coverage.files import abs_file
from coverage.misc import import_local_file

from tests.coveragetest import CoverageTest
from tests.goldtest import compare, gold_path
from tests.helpers import assert_coverage_warnings, change_dir


class XmlTestHelpers(CoverageTest):
    """Methods to use from XML tests."""

    def run_doit(self) -> Coverage:
        """Construct a simple sub-package."""
        self.make_file("sub/__init__.py")
        self.make_file("sub/doit.py", "print('doit!')")
        self.make_file("main.py", "import sub.doit")
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main")
        return cov

    def make_tree(self, width: int, depth: int, curdir: str = ".") -> None:
        """Make a tree of packages.

        Makes `width` directories, named d0 .. d{width-1}. Each directory has
        __init__.py, and `width` files, named f0.py .. f{width-1}.py.  Each
        directory also has `width` sub-directories, in the same fashion, until
        a depth of `depth` is reached.

        """
        if depth == 0:
            return

        def here(p: str) -> str:
            """A path for `p` in our currently interesting directory."""
            return os.path.join(curdir, p)

        for i in range(width):
            next_dir = here(f"d{i}")
            self.make_tree(width, depth - 1, next_dir)
        if curdir != ".":
            self.make_file(here("__init__.py"), "")
            for i in range(width):
                filename = here(f"f{i}.py")
                self.make_file(filename, f"# {filename}\n")

    def assert_source(
        self,
        xmldom: ElementTree.Element | ElementTree.ElementTree,
        src: str,
    ) -> None:
        """Assert that the XML has a <source> element with `src`."""
        src = abs_file(src)
        elts = xmldom.findall(".//sources/source")
        assert any(elt.text == src for elt in elts)


class XmlTestHelpersTest(XmlTestHelpers, CoverageTest):
    """Tests of methods in XmlTestHelpers."""

    run_in_temp_dir = False

    def test_assert_source(self) -> None:
        dom = ElementTree.fromstring(
            """\
            <doc>
                <src>foo</src>
                <sources>
                    <source>{cwd}something</source>
                    <source>{cwd}another</source>
                </sources>
            </doc>
            """.format(cwd=abs_file(".") + os.sep)
        )

        self.assert_source(dom, "something")
        self.assert_source(dom, "another")

        with pytest.raises(AssertionError):
            self.assert_source(dom, "hello")
        with pytest.raises(AssertionError):
            self.assert_source(dom, "foo")
        with pytest.raises(AssertionError):
            self.assert_source(dom, "thing")


class XmlReportTest(XmlTestHelpers, CoverageTest):
    """Tests of the XML reports from coverage.py."""

    def make_mycode_data(self) -> None:
        """Pretend that we ran mycode.py, so we can report on it."""
        self.make_file("mycode.py", "print('hello')\n")
        self.make_data_file(lines={abs_file("mycode.py"): [1]})

    def run_xml_report(self, **kwargs: Any) -> None:
        """Run xml_report()"""
        cov = coverage.Coverage()
        cov.load()
        cov.xml_report(**kwargs)

    def test_default_file_placement(self) -> None:
        self.make_mycode_data()
        self.run_xml_report()
        self.assert_exists("coverage.xml")
        assert self.stdout() == ""

    def test_argument_affects_xml_placement(self) -> None:
        self.make_mycode_data()
        cov = coverage.Coverage(messages=True)
        cov.load()
        cov.xml_report(outfile="put_it_there.xml")
        assert self.stdout() == "Wrote XML report to put_it_there.xml\n"
        self.assert_doesnt_exist("coverage.xml")
        self.assert_exists("put_it_there.xml")

    def test_output_directory_does_not_exist(self) -> None:
        self.make_mycode_data()
        self.run_xml_report(outfile="nonexistent/put_it_there.xml")
        self.assert_doesnt_exist("coverage.xml")
        self.assert_doesnt_exist("put_it_there.xml")
        self.assert_exists("nonexistent/put_it_there.xml")

    def test_config_affects_xml_placement(self) -> None:
        self.make_mycode_data()
        self.make_file(".coveragerc", "[xml]\noutput = xml.out\n")
        self.run_xml_report()
        self.assert_doesnt_exist("coverage.xml")
        self.assert_exists("xml.out")

    def test_no_data(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/210
        with pytest.raises(NoDataError, match="No data to report."):
            self.run_xml_report()
        self.assert_doesnt_exist("coverage.xml")
        self.assert_doesnt_exist(".coverage")

    def test_no_source(self) -> None:
        # Written while investigating a bug, might as well keep it.
        # https://github.com/coveragepy/coveragepy/issues/208
        self.make_file("innocuous.py", "a = 4")
        cov = coverage.Coverage()
        self.start_import_stop(cov, "innocuous")
        os.remove("innocuous.py")
        with pytest.warns(Warning) as warns:
            cov.xml_report(ignore_errors=True)
        assert_coverage_warnings(
            warns,
            re.compile(r"Couldn't parse '.*innocuous.py'. \(couldnt-parse\)"),
        )
        self.assert_exists("coverage.xml")

    def test_filename_format_showing_everything(self) -> None:
        cov = self.run_doit()
        cov.xml_report()
        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//class[@name='doit.py']")
        assert len(elts) == 1
        assert elts[0].get("filename") == "sub/doit.py"

    def test_filename_format_including_filename(self) -> None:
        cov = self.run_doit()
        cov.xml_report(["sub/doit.py"])
        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//class[@name='doit.py']")
        assert len(elts) == 1
        assert elts[0].get("filename") == "sub/doit.py"

    def test_filename_format_including_module(self) -> None:
        cov = self.run_doit()
        import sub.doit  # pylint: disable=import-error

        cov.xml_report([sub.doit])
        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//class[@name='doit.py']")
        assert len(elts) == 1
        assert elts[0].get("filename") == "sub/doit.py"

    def test_reporting_on_nothing(self) -> None:
        # Used to raise a zero division error:
        # https://github.com/coveragepy/coveragepy/issues/250
        self.make_file("empty.py", "")
        cov = coverage.Coverage()
        empty = self.start_import_stop(cov, "empty")
        cov.xml_report([empty])
        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//class[@name='empty.py']")
        assert len(elts) == 1
        assert elts[0].get("filename") == "empty.py"
        assert elts[0].get("line-rate") == "1"

    def test_empty_file_is_100_not_0(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/345
        cov = self.run_doit()
        cov.xml_report()
        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//class[@name='__init__.py']")
        assert len(elts) == 1
        assert elts[0].get("line-rate") == "1"

    def test_empty_file_is_skipped(self) -> None:
        cov = self.run_doit()
        cov.xml_report(skip_empty=True)
        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//class[@name='__init__.py']")
        assert len(elts) == 0

    def test_curdir_source(self) -> None:
        # With no source= option, the XML report should explain that the source
        # is in the current directory.
        cov = self.run_doit()
        cov.xml_report()
        dom = ElementTree.parse("coverage.xml")
        self.assert_source(dom, ".")  # type: ignore[arg-type]
        sources = dom.findall(".//source")
        assert len(sources) == 1

    def test_deep_source(self) -> None:
        # When using source=, the XML report needs to mention those directories
        # in the <source> elements.
        # https://github.com/coveragepy/coveragepy/issues/439
        self.make_file("src/main/foo.py", "a = 1")
        self.make_file("also/over/there/bar.py", "b = 2")

        cov = coverage.Coverage(source=["src/main", "also/over/there", "not/really"])
        with cov.collect():
            mod_foo = import_local_file("foo", "src/main/foo.py")
            mod_bar = import_local_file("bar", "also/over/there/bar.py")

        with pytest.warns(Warning) as warns:
            cov.xml_report([mod_foo, mod_bar])
        assert_coverage_warnings(
            warns,
            "Module not/really was never imported. (module-not-imported)",
        )
        dom = ElementTree.parse("coverage.xml")

        self.assert_source(dom, "src/main")  # type: ignore[arg-type]
        self.assert_source(dom, "also/over/there")  # type: ignore[arg-type]
        sources = dom.findall(".//source")
        assert len(sources) == 2

        foo_class = dom.findall(".//class[@name='foo.py']")
        assert len(foo_class) == 1
        assert foo_class[0].attrib == {
            "branch-rate": "0",
            "complexity": "0",
            "filename": "foo.py",
            "line-rate": "1",
            "name": "foo.py",
        }

        bar_class = dom.findall(".//class[@name='bar.py']")
        assert len(bar_class) == 1
        assert bar_class[0].attrib == {
            "branch-rate": "0",
            "complexity": "0",
            "filename": "bar.py",
            "line-rate": "1",
            "name": "bar.py",
        }

    def test_nonascii_directory(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/573
        self.make_file("테스트/program.py", "a = 1")
        with change_dir("테스트"):
            cov = coverage.Coverage()
            self.start_import_stop(cov, "program")
            cov.xml_report()

    def test_accented_dot_py(self) -> None:
        # Make a file with a non-ascii character in the filename.
        self.make_file("h\xe2t.py", "print('accented')")
        self.make_data_file(lines={abs_file("h\xe2t.py"): [1]})
        cov = coverage.Coverage()
        cov.load()
        cov.xml_report()
        # The XML report is always UTF8-encoded.
        with open("coverage.xml", "rb") as xmlf:
            xml = xmlf.read()
        assert ' filename="h\xe2t.py"'.encode() in xml
        assert ' name="h\xe2t.py"'.encode() in xml

    def test_accented_directory(self) -> None:
        # Make a file with a non-ascii character in the directory name.
        self.make_file("\xe2/accented.py", "print('accented')")
        self.make_data_file(lines={abs_file("\xe2/accented.py"): [1]})

        # The XML report is always UTF8-encoded.
        cov = coverage.Coverage()
        cov.load()
        cov.xml_report()
        with open("coverage.xml", "rb") as xmlf:
            xml = xmlf.read()
        assert b' filename="\xc3\xa2/accented.py"' in xml
        assert b' name="accented.py"' in xml

        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//package[@name='â']")
        assert len(elts) == 1
        assert elts[0].attrib == {
            "branch-rate": "0",
            "complexity": "0",
            "line-rate": "1",
            "name": "â",
        }

    def test_no_duplicate_packages(self) -> None:
        self.make_file(
            "namespace/package/__init__.py",
            "from . import sample; from . import test; from .subpackage import test",
        )
        self.make_file("namespace/package/sample.py", "print('package.sample')")
        self.make_file("namespace/package/test.py", "print('package.test')")
        self.make_file("namespace/package/subpackage/test.py", "print('package.subpackage.test')")

        # no source path passed to coverage!
        # problem occurs when they are dynamically generated during xml report
        cov = coverage.Coverage()
        with cov.collect():
            import_local_file("namespace.package", "namespace/package/__init__.py")

        cov.xml_report()

        dom = ElementTree.parse("coverage.xml")

        # only two packages should be present
        packages = dom.findall(".//package")
        assert len(packages) == 2

        # one of them is namespace.package
        named_package = dom.findall(".//package[@name='namespace.package']")
        assert len(named_package) == 1

        # the other one namespace.package.subpackage
        named_sub_package = dom.findall(".//package[@name='namespace.package.subpackage']")
        assert len(named_sub_package) == 1

    def test_bug_1709(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/1709
        self.make_file("main.py", "import x1y, x01y, x001y")
        self.make_file("x1y.py", "print('x1y')")
        self.make_file("x01y.py", "print('x01y')")
        self.make_file("x001y.py", "print('x001y')")

        cov = coverage.Coverage()
        self.start_import_stop(cov, "main")
        assert self.stdout() == "x1y\nx01y\nx001y\n"
        # This used to raise:
        # TypeError: '<' not supported between instances of 'Element' and 'Element'
        cov.xml_report()


def unbackslash(v: Any) -> Any:
    """Find strings in `v`, and replace backslashes with slashes throughout."""
    if isinstance(v, (tuple, list)):
        return [unbackslash(vv) for vv in v]
    elif isinstance(v, dict):
        return {k: unbackslash(vv) for k, vv in v.items()}
    else:
        assert isinstance(v, str)
        return v.replace("\\", "/")


class XmlPackageStructureTest(XmlTestHelpers, CoverageTest):
    """Tests about the package structure reported in the coverage.xml file."""

    def package_and_class_tags(self, cov: Coverage) -> Iterable[tuple[str, dict[str, Any]]]:
        """Run an XML report on `cov`, and get the package and class tags."""
        cov.xml_report()
        dom = ElementTree.parse("coverage.xml")
        for node in dom.iter():
            if node.tag in ["package", "class"]:
                yield (node.tag, {a: v for a, v in node.items() if a in ["name", "filename"]})

    def assert_package_and_class_tags(self, cov: Coverage, result: Any) -> None:
        """Check the XML package and class tags from `cov` match `result`."""
        assert unbackslash(list(self.package_and_class_tags(cov))) == unbackslash(result)

    def test_package_names(self) -> None:
        self.make_tree(width=1, depth=3)
        self.make_file(
            "main.py",
            """\
            from d0.d0 import f0
            """,
        )
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main")
        self.assert_package_and_class_tags(
            cov,
            [
                ("package", {"name": "."}),
                ("class", {"filename": "main.py", "name": "main.py"}),
                ("package", {"name": "d0"}),
                ("class", {"filename": "d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/f0.py", "name": "f0.py"}),
                ("package", {"name": "d0.d0"}),
                ("class", {"filename": "d0/d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/d0/f0.py", "name": "f0.py"}),
            ],
        )

    def test_package_depth_1(self) -> None:
        self.make_tree(width=1, depth=4)
        self.make_file(
            "main.py",
            """\
            from d0.d0 import f0
            """,
        )
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main")

        cov.set_option("xml:package_depth", 1)
        self.assert_package_and_class_tags(
            cov,
            [
                ("package", {"name": "."}),
                ("class", {"filename": "main.py", "name": "main.py"}),
                ("package", {"name": "d0"}),
                ("class", {"filename": "d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/d0/__init__.py", "name": "d0/__init__.py"}),
                ("class", {"filename": "d0/d0/d0/__init__.py", "name": "d0/d0/__init__.py"}),
                ("class", {"filename": "d0/d0/d0/f0.py", "name": "d0/d0/f0.py"}),
                ("class", {"filename": "d0/d0/f0.py", "name": "d0/f0.py"}),
                ("class", {"filename": "d0/f0.py", "name": "f0.py"}),
            ],
        )

    def test_package_depth_2(self) -> None:
        self.make_tree(width=1, depth=4)
        self.make_file(
            "main.py",
            """\
            from d0.d0 import f0
            """,
        )
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main")

        cov.set_option("xml:package_depth", 2)
        self.assert_package_and_class_tags(
            cov,
            [
                ("package", {"name": "."}),
                ("class", {"filename": "main.py", "name": "main.py"}),
                ("package", {"name": "d0"}),
                ("class", {"filename": "d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/f0.py", "name": "f0.py"}),
                ("package", {"name": "d0.d0"}),
                ("class", {"filename": "d0/d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/d0/d0/__init__.py", "name": "d0/__init__.py"}),
                ("class", {"filename": "d0/d0/d0/f0.py", "name": "d0/f0.py"}),
                ("class", {"filename": "d0/d0/f0.py", "name": "f0.py"}),
            ],
        )

    def test_package_depth_3(self) -> None:
        self.make_tree(width=1, depth=4)
        self.make_file(
            "main.py",
            """\
            from d0.d0 import f0
            """,
        )
        cov = coverage.Coverage(source=["."])
        self.start_import_stop(cov, "main")

        cov.set_option("xml:package_depth", 3)
        self.assert_package_and_class_tags(
            cov,
            [
                ("package", {"name": "."}),
                ("class", {"filename": "main.py", "name": "main.py"}),
                ("package", {"name": "d0"}),
                ("class", {"filename": "d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/f0.py", "name": "f0.py"}),
                ("package", {"name": "d0.d0"}),
                ("class", {"filename": "d0/d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/d0/f0.py", "name": "f0.py"}),
                ("package", {"name": "d0.d0.d0"}),
                ("class", {"filename": "d0/d0/d0/__init__.py", "name": "__init__.py"}),
                ("class", {"filename": "d0/d0/d0/f0.py", "name": "f0.py"}),
            ],
        )

    def test_source_prefix(self) -> None:
        # https://github.com/coveragepy/coveragepy/issues/465
        # https://github.com/coveragepy/coveragepy/issues/526
        self.make_file("src/mod.py", "print(17)")
        cov = coverage.Coverage(source=["src"])
        self.start_import_stop(cov, "mod", modfile="src/mod.py")

        self.assert_package_and_class_tags(
            cov,
            [
                ("package", {"name": "."}),
                ("class", {"filename": "mod.py", "name": "mod.py"}),
            ],
        )
        dom = ElementTree.parse("coverage.xml")
        self.assert_source(dom, "src")  # type: ignore[arg-type]

    @pytest.mark.parametrize("trail", ["", "/", "\\"])
    def test_relative_source(self, trail: str) -> None:
        if trail == "\\" and not env.WINDOWS:
            pytest.skip("trailing backslash is only for Windows")
        self.make_file("src/mod.py", "print(17)")
        cov = coverage.Coverage(source=[f"src{trail}"])
        cov.set_option("run:relative_files", True)
        self.start_import_stop(cov, "mod", modfile="src/mod.py")
        cov.xml_report()

        dom = ElementTree.parse("coverage.xml")
        elts = dom.findall(".//sources/source")
        assert [elt.text for elt in elts] == ["src"]


def compare_xml(expected: str, actual: str, actual_extra: bool = False) -> None:
    """Specialized compare function for our XML files."""
    source_path = coverage.files.relative_directory().rstrip(r"\/")

    scrubs = [
        (r' timestamp="\d+"', ' timestamp="TIMESTAMP"'),
        (r' version="[-.\w]+"', ' version="VERSION"'),
        (r"<source>\s*.*?\s*</source>", "<source>%s</source>" % re.escape(source_path)),
        (r"/coverage\.readthedocs\.io/?[-.\w/]*", "/coverage.readthedocs.io/VER"),
    ]
    compare(expected, actual, scrubs=scrubs, actual_extra=actual_extra)


class XmlGoldTest(CoverageTest):
    """Tests of XML reporting that use gold files."""

    def test_a_xml_1(self) -> None:
        self.make_file(
            "a.py",
            """\
            if 1 < 2:
                # Needed a < to look at HTML entities.
                a = 3
            else:
                a = 4
            """,
        )

        cov = coverage.Coverage()
        a = self.start_import_stop(cov, "a")
        cov.xml_report(a, outfile="coverage.xml")
        compare_xml(gold_path("xml/x_xml"), ".", actual_extra=True)

    def test_a_xml_2(self) -> None:
        self.make_file(
            "a.py",
            """\
            if 1 < 2:
                # Needed a < to look at HTML entities.
                a = 3
            else:
                a = 4
            """,
        )

        self.make_file(
            "run_a_xml_2.ini",
            """\
            # Put all the XML output in xml_2
            [xml]
            output = xml_2/coverage.xml
            """,
        )

        cov = coverage.Coverage(config_file="run_a_xml_2.ini")
        a = self.start_import_stop(cov, "a")
        cov.xml_report(a)
        compare_xml(gold_path("xml/x_xml"), "xml_2")

    def test_y_xml_branch(self) -> None:
        self.make_file(
            "y.py",
            """\
            def choice(x):
                if x < 2:
                    return 3
                else:
                    return 4

            assert choice(1) == 3
            """,
        )

        cov = coverage.Coverage(branch=True)
        y = self.start_import_stop(cov, "y")
        cov.xml_report(y, outfile="y_xml_branch/coverage.xml")
        compare_xml(gold_path("xml/y_xml_branch"), "y_xml_branch")
