# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Code coverage measurement for Python"""

# Setuptools setup for coverage.py
# This file is used unchanged under all versions of Python.

import re
import os
import os.path
import platform
import sys
import textwrap
import zipfile

from pathlib import Path
from typing import Any

from setuptools import Extension, errors, setup
from setuptools.command.build_ext import build_ext
from setuptools.command.editable_wheel import editable_wheel


def get_version_data() -> dict[str, Any]:
    """Get the globals from coverage/version.py."""
    # We exec coverage/version.py so we can avoid importing the product code into setup.py.
    module_globals: dict[str, Any] = {}
    cov_ver_py = os.path.join(os.path.split(__file__)[0], "coverage/version.py")
    with open(cov_ver_py, encoding="utf-8") as version_file:
        # Execute the code in version.py.
        exec(compile(version_file.read(), cov_ver_py, "exec", dont_inherit=True), module_globals)
    return module_globals


def get_long_description(url: str) -> str:
    """Massage README.rst to get the long description."""
    with open("README.rst", encoding="utf-8") as readme:
        readme_text = readme.read()

    url = url.replace("readthedocs", "@@")
    assert "@@" not in readme_text
    long_description = (
        readme_text.replace("https://coverage.readthedocs.io/en/latest", url)
        .replace("https://coverage.readthedocs.io", url)
        .replace("@@", "readthedocs")
    )
    return long_description


def count_contributors() -> int:
    """Read CONTRIBUTORS.txt to count how many people have helped."""
    with open("CONTRIBUTORS.txt", "rb") as contributors:
        paras = contributors.read().split(b"\n\n")
        num_others = len(paras[-1].splitlines())
        num_others += 1  # Count Gareth Rees, who is mentioned in the top paragraph.
    return num_others


# PYVERSIONS
CLASSIFIERS = textwrap.dedent("""\
    Development Status :: 5 - Production/Stable
    Environment :: Console
    Intended Audience :: Developers
    Operating System :: OS Independent
    Programming Language :: Python
    Programming Language :: Python :: 3
    Programming Language :: Python :: 3.10
    Programming Language :: Python :: 3.11
    Programming Language :: Python :: 3.12
    Programming Language :: Python :: 3.13
    Programming Language :: Python :: 3.14
    Programming Language :: Python :: 3.15
    Programming Language :: Python :: Free Threading :: 3 - Stable
    Programming Language :: Python :: Implementation :: CPython
    Programming Language :: Python :: Implementation :: PyPy
    Topic :: Software Development :: Quality Assurance
    Topic :: Software Development :: Testing
""").splitlines()


# The names of .pth files matter because they are read in lexicographic order.
# Editable installs work because of `__editable__*.pth` files, so we need our
# .pth files to come after those. But we want ours to be earlyish in the
# sequence, so we start with `a`. The metacov .pth file should come before the
# coverage .pth file, so we use `a0_metacov.pth` and `a1_coverage.pth`.
PTH_NAME = "a1_coverage.pth"


def make_pth_file() -> None:
    """Make the packaged .pth file used for measuring subprocess coverage."""

    with open("coverage/pth_file.py", encoding="utf-8") as f:
        code = f.read()

    code = re.sub(r"\s*#.*\n", "\n", code)
    code = code.replace("    ", " ")

    # `import sys` is needed because .pth files are executed only if they start
    # with `import `.
    with open(PTH_NAME, "w", encoding="utf-8") as pth_file:
        pth_file.write(f"import sys; exec({code!r})\n")


class EditableWheelWithPth(editable_wheel):  # type: ignore[misc]
    """Override the editable_wheel command to insert our .pth file into the wheel."""

    def run(self) -> None:
        super().run()
        for whl in Path(self.dist_dir).glob("*editable*.whl"):
            with zipfile.ZipFile(whl, "a") as zf:
                zf.write(PTH_NAME, PTH_NAME)


# A replacement for the build_ext command which raises a single exception
# if the build fails, so we can fallback nicely.

ext_errors = (
    errors.CCompilerError,
    errors.ExecError,
    errors.PlatformError,
)
if sys.platform == "win32":
    # IOError can be raised when failing to find the compiler
    ext_errors += (IOError,)


class BuildFailed(Exception):
    """Raise this to indicate the C extension wouldn't build."""

    def __init__(self) -> None:
        Exception.__init__(self)
        self.cause = sys.exc_info()[1]  # work around py 2/3 different syntax


class ve_build_ext(build_ext):  # type: ignore[misc]
    """Build C extensions, but fail with a straightforward exception."""

    def run(self) -> None:
        """Wrap `run` with `BuildFailed`."""
        try:
            build_ext.run(self)
        except errors.PlatformError as exc:
            raise BuildFailed() from exc

    def build_extension(self, ext: Any) -> None:
        """Wrap `build_extension` with `BuildFailed`."""
        if self.compiler.compiler_type == "msvc":
            ext.extra_compile_args = (ext.extra_compile_args or []) + [
                "/std:c11",
                "/experimental:c11atomics",
            ]
        try:
            # Uncomment to test compile failure handling:
            #   raise errors.CCompilerError("OOPS")
            build_ext.build_extension(self, ext)
        except ext_errors as exc:
            raise BuildFailed() from exc
        except ValueError as err:
            # this can happen on Windows 64 bit, see Python issue 7511
            if "'path'" in str(err):  # works with both py 2/3
                raise BuildFailed() from err
            raise


version_data = get_version_data()
make_pth_file()


# Create the keyword arguments for setup()

setup_args = dict(
    name="coverage",
    version=version_data["__version__"],
    packages=[
        "coverage",
    ],
    package_data={
        "coverage": [
            "htmlfiles/*.*",
            "py.typed",
            f"../{PTH_NAME}",
        ],
    },
    entry_points={
        "console_scripts": [
            # Install a script as "coverage".
            "coverage = coverage.cmdline:main",
            # And as "coverage3", and as "coverage-3.7" (or whatever), but deprecated.
            "coverage%d = coverage.cmdline:main_deprecated" % sys.version_info[:1],
            "coverage-%d.%d = coverage.cmdline:main_deprecated" % sys.version_info[:2],
        ],
    },
    extras_require={
        # Enable pyproject.toml support.
        "toml": ['tomli; python_full_version<="3.11.0a6"'],
    },
    cmdclass={
        "build_ext": ve_build_ext,
        "editable_wheel": EditableWheelWithPth,
    },
    # We need to get HTML assets from our htmlfiles directory.
    zip_safe=False,
    author=f"Ned Batchelder and {count_contributors()} others",
    author_email="ned@nedbatchelder.com",
    description=__doc__,
    long_description=get_long_description(url=version_data["__url__"]),
    long_description_content_type="text/x-rst",
    keywords="code coverage testing",
    license="Apache-2.0",
    license_files=["LICENSE.txt"],
    classifiers=CLASSIFIERS,
    url="https://github.com/coveragepy/coveragepy",
    project_urls={
        "Documentation": version_data["__url__"],
        "Funding": (
            "https://tidelift.com/subscription/pkg/pypi-coverage"
            + "?utm_source=pypi-coverage&utm_medium=referral&utm_campaign=pypi"
        ),
        "Issues": "https://github.com/coveragepy/coveragepy/issues",
        "Mastodon": "https://hachyderm.io/@coveragepy",
        "Mastodon (nedbat)": "https://hachyderm.io/@nedbat",
    },
    python_requires=">=3.10",  # minimum of PYVERSIONS
)

# There are a few reasons we might not be able to compile the C extension.
# Figure out if we should attempt the C extension or not. Define
# COVERAGE_DISABLE_EXTENSION in the build environment to explicitly disable the
# extension.

compile_extension = os.getenv("COVERAGE_DISABLE_EXTENSION", None) is None

if platform.python_implementation() == "PyPy":
    # Pypy can't compile C extensions
    compile_extension = False

if compile_extension:
    setup_args.update(
        dict(
            ext_modules=[
                Extension(
                    "coverage.tracer",
                    sources=[
                        "coverage/ctracer/datastack.c",
                        "coverage/ctracer/filedisp.c",
                        "coverage/ctracer/module.c",
                        "coverage/ctracer/sysmon.c",
                        "coverage/ctracer/tracer.c",
                    ],
                ),
            ],
        ),
    )


def main() -> None:
    """Actually invoke setup() with the arguments we built above."""
    # For a variety of reasons, it might not be possible to install the C
    # extension.  Try it with, and if it fails, try it without.
    try:
        setup(**setup_args)
    except BuildFailed as exc:
        msg = "Couldn't install with extension module, trying without it..."
        exc_msg = f"{exc.__class__.__name__}: {exc.cause}"
        print(f"**\n** {msg}\n** {exc_msg}\n**")

        del setup_args["ext_modules"]
        setup(**setup_args)


if __name__ == "__main__":
    main()
