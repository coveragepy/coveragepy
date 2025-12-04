# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""
Functions for use with cog in the documentation.
"""

# For help text in doc/cmd.rst:
# optparse wraps help to the COLUMNS value.  Set it here to be sure it's
# consistent regardless of the environment.  Has to be set before we
# import cmdline.py, which creates the optparse objects.

# pylint: disable=wrong-import-position
import os

os.environ["COLUMNS"] = "80"

import contextlib
import io
import re
import textwrap

import cog  # pylint: disable=import-error

from coverage.cmdline import CoverageScript
from coverage.config import read_coverage_config


def show_help(cmd):
    """
    Insert the help output from a command.
    """
    with contextlib.redirect_stdout(io.StringIO()) as stdout:
        CoverageScript().command_line([cmd, "--help"])
    help_text = stdout.getvalue()
    help_text = help_text.replace("__main__.py", "coverage")
    help_text = re.sub(r"(?m)^Full doc.*$", "", help_text)
    help_text = help_text.rstrip()

    print(".. code::\n")
    print(f"    $ coverage {cmd} --help")
    print(textwrap.indent(help_text, "    "))


def _read_config(text, fname):
    """
    Prep and read configuration text.

    Returns the prepared text, and a dict of the settings.
    """
    # Text will be triple-quoted with an initial ignored newline.
    assert text[0] == "\n"
    text = textwrap.dedent(text[1:])

    os.makedirs("tmp", exist_ok=True)
    with open(f"tmp/{fname}", "w", encoding="utf-8") as f:
        f.write(text)

    config = read_coverage_config(f"tmp/{fname}", warn=cog.error)

    values = {}
    for name, val in vars(config).items():
        if name.startswith("_"):
            continue
        if "config_file" in name:
            continue
        values[name] = val
    return text, values


def show_configs(ini, toml):
    """
    Show configuration text in a tabbed box.

    `ini` is the ini-file syntax, `toml` is the equivalent TOML syntax.
    The equivalence is checked for accuracy, and the process fails if there's
    a mismatch.

    A four-tabbed box will be produced.
    """
    ini, ini_vals = _read_config(ini, "covrc")
    toml, toml_vals = _read_config(toml, "covrc.toml")
    for key, val in ini_vals.items():
        if val != toml_vals[key]:
            cog.error(
                f"Mismatch between configuration tabs in docs for {key = }:\n"
                + f"  ini:  {val!r}\n"
                + f"  toml: {toml_vals[key]!r}"
            )

    ini2 = re.sub(r"(?m)^\[", "[coverage:", ini)
    toml2 = "# You can also use sections like [tool.coverage.run]\n"
    toml2 += toml.replace("[tool.coverage.", "[")

    print()
    print(".. tabs::\n")
    for name, syntax, text in [
        ("pyproject.toml", "toml", toml),
        (".coveragerc", "ini", ini),
        (".coveragerc.toml", "toml", toml2),
        ("setup.cfg or tox.ini", "ini", ini2),
    ]:
        print(f"    .. code-tab:: {syntax}")
        print(f"        :caption: {name}")
        print()
        print(textwrap.indent(text, " " * 8))
