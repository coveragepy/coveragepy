.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to create the tabbed multi-syntax
   configuration examples.  If those are wrong, the quality checks will fail.
   Running "make prebuild" checks them and produces the output.

.. [[[cog
    from cog_helpers import show_configs
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _config:

=======================
Configuration reference
=======================

.. highlight:: ini

Coverage.py options can be specified in a configuration file.  This makes it
easier to re-run coverage.py with consistent settings, and also allows for
specification of options that are otherwise only available in the
:ref:`API <api>`.

Configuration files also make it easier to get coverage testing of spawned
subprocesses.  See :ref:`subprocess` for more details.

The default name for the configuration file is ``.coveragerc``, in the same
directory coverage.py is being run in.  Most of the settings in the
configuration file are tied to your source code and how it should be measured,
so it should be stored with your source, and checked into source control,
rather than put in your home directory.

A different location for the configuration file can be specified with the
``--rcfile=FILE`` command line option or with the ``COVERAGE_RCFILE``
environment variable.

If ``.coveragerc`` doesn't exist and another file hasn't been specified, then
coverage.py will look for settings in other common configuration files, in this
order: :file:`.coveragerc.toml`, :file:`setup.cfg`, :file:`tox.ini`, or
:file:`pyproject.toml`.  The first file found with coverage.py settings will be
used and other files won't be consulted.

Coverage.py will read from "pyproject.toml" if TOML support is available,
either because you are running on Python 3.11 or later, or because you
installed with the ``toml`` extra (``pip install coverage[toml]``).


Syntax
------

The specific syntax of a configuration file depends on what type it is.
All configuration files are assumed to be in INI format, unless their file
extension is .toml, which are TOML.

INI Syntax
..........

A coverage.py configuration file is in classic .ini file format: sections are
introduced by a ``[section]`` header, and contain ``name = value`` entries.
Lines beginning with ``#`` or ``;`` are ignored as comments.

Strings don't need quotes. Multi-valued strings can be created by indenting
values on multiple lines.

Boolean values can be specified as ``on``, ``off``, ``true``, ``false``, ``1``,
or ``0`` and are case-insensitive.

In setup.cfg or tox.ini, the section names have "coverage:" prefixed, so the
``[run]`` options described below will be found in the ``[coverage:run]``
section of the file.

TOML Syntax
...........

`TOML syntax`_ uses explicit lists with brackets, and strings with quotes.
Booleans are ``true`` or ``false``.

Configuration must be within the ``[tool.coverage]`` section, for example,
``[tool.coverage.run]``.  Environment variable expansion in values is
available, but only within quoted strings, even for non-string values.

.. _TOML syntax: https://toml.io


Environment variables
.....................

Environment variables can be substituted in by using dollar signs: ``$WORD``
or ``${WORD}`` will be replaced with the value of ``WORD`` in the environment.
A dollar sign can be inserted with ``$$``.  Special forms can be used to
control what happens if the variable isn't defined in the environment:

- If you want to raise an error if an environment variable is undefined, use a
  question mark suffix: ``${WORD?}``.

- If you want to provide a default for missing variables, use a dash with a
  default value: ``${WORD-default value}``.

- Otherwise, missing environment variables will result in empty strings with no
  error.


Sample file
...........

Here's a sample configuration file, in each syntax:

.. [[[cog
    show_configs(
        ini=r"""
            [run]
            branch = True

            [report]
            ; Regexes for lines to exclude from consideration
            exclude_also =
                ; Don't complain about missing debug-only code:
                def __repr__
                if self\.debug

                ; Don't complain if tests don't hit defensive assertion code:
                raise AssertionError
                raise NotImplementedError

                ; Don't complain if non-runnable code isn't run:
                if 0:
                if __name__ == .__main__.:

                ; Don't complain about abstract methods, they aren't run:
                @(abc\.)?abstractmethod

            ignore_errors = True

            [html]
            directory = coverage_html_report
            """,
        toml=r"""
            [tool.coverage.run]
            branch = true

            [tool.coverage.report]
            # Regexes for lines to exclude from consideration
            exclude_also = [
                # Don't complain about missing debug-only code:
                "def __repr__",
                "if self\\.debug",

                # Don't complain if tests don't hit defensive assertion code:
                "raise AssertionError",
                "raise NotImplementedError",

                # Don't complain if non-runnable code isn't run:
                "if 0:",
                "if __name__ == .__main__.:",

                # Don't complain about abstract methods, they aren't run:
                "@(abc\\.)?abstractmethod",
                ]

            ignore_errors = true

            [tool.coverage.html]
            directory = "coverage_html_report"
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.run]
        branch = true

        [tool.coverage.report]
        # Regexes for lines to exclude from consideration
        exclude_also = [
            # Don't complain about missing debug-only code:
            "def __repr__",
            "if self\\.debug",

            # Don't complain if tests don't hit defensive assertion code:
            "raise AssertionError",
            "raise NotImplementedError",

            # Don't complain if non-runnable code isn't run:
            "if 0:",
            "if __name__ == .__main__.:",

            # Don't complain about abstract methods, they aren't run:
            "@(abc\\.)?abstractmethod",
            ]

        ignore_errors = true

        [tool.coverage.html]
        directory = "coverage_html_report"

    .. code-tab:: ini
        :caption: .coveragerc

        [run]
        branch = True

        [report]
        ; Regexes for lines to exclude from consideration
        exclude_also =
            ; Don't complain about missing debug-only code:
            def __repr__
            if self\.debug

            ; Don't complain if tests don't hit defensive assertion code:
            raise AssertionError
            raise NotImplementedError

            ; Don't complain if non-runnable code isn't run:
            if 0:
            if __name__ == .__main__.:

            ; Don't complain about abstract methods, they aren't run:
            @(abc\.)?abstractmethod

        ignore_errors = True

        [html]
        directory = coverage_html_report

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [run]
        branch = true

        [report]
        # Regexes for lines to exclude from consideration
        exclude_also = [
            # Don't complain about missing debug-only code:
            "def __repr__",
            "if self\\.debug",

            # Don't complain if tests don't hit defensive assertion code:
            "raise AssertionError",
            "raise NotImplementedError",

            # Don't complain if non-runnable code isn't run:
            "if 0:",
            "if __name__ == .__main__.:",

            # Don't complain about abstract methods, they aren't run:
            "@(abc\\.)?abstractmethod",
            ]

        ignore_errors = true

        [html]
        directory = "coverage_html_report"

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:run]
        branch = True

        [coverage:report]
        ; Regexes for lines to exclude from consideration
        exclude_also =
            ; Don't complain about missing debug-only code:
            def __repr__
            if self\.debug

            ; Don't complain if tests don't hit defensive assertion code:
            raise AssertionError
            raise NotImplementedError

            ; Don't complain if non-runnable code isn't run:
            if 0:
            if __name__ == .__main__.:

            ; Don't complain about abstract methods, they aren't run:
            @(abc\.)?abstractmethod

        ignore_errors = True

        [coverage:html]
        directory = coverage_html_report

.. [[[end]]] (sum: qYCtIxMe+3)


The specific configuration settings are described below.  Many sections and
settings correspond roughly to commands and options in the :ref:`command-line
interface <cmd>`.


.. _config_run:

[run]
-----

These settings are generally used when running product code, though some apply
to more than one command.


.. _config_run_branch:

[run] branch
............

(boolean, default False) Whether to measure :ref:`branch coverage <branch>` in
addition to statement coverage.


.. _config_run_command_line:

[run] command_line
..................

(string) The command-line to run your program.  This will be used if you run
``coverage run`` with no further arguments.  Coverage.py options cannot be
specified here, other than ``-m`` to indicate the module to run.

.. versionadded:: 5.0


.. _config_run_concurrency:

[run] concurrency
.................

(multi-string, default "thread") The concurrency libraries in use by the
product code.  If your program uses `multiprocessing`_, `gevent`_, `greenlet`_,
or `eventlet`_, you must name that library in this option, or coverage.py will
produce very wrong results.

.. _multiprocessing: https://docs.python.org/3/library/multiprocessing.html
.. _greenlet: https://greenlet.readthedocs.io/
.. _gevent: https://www.gevent.org/
.. _eventlet: https://eventlet.readthedocs.io/

See :ref:`subprocess` for details of multi-process measurement.

Before version 4.2, this option only accepted a single string.

.. versionadded:: 4.0


.. _config_run_context:

[run] context
.............

(string) The static context to record for this coverage run. See
:ref:`contexts` for more information

.. versionadded:: 5.0


.. _config_run_core:

[run] core
..........

(string, default depends on the Python version) Specify which measurement core
to use. Valid values are:

- ``ctrace``: the C implementation of a sys.settrace function.  This was the
  default until Python 3.13.

- ``sysmon``: the :mod:`sys.monitoring <python:sys.monitoring>` implementation.
  Only available in Python 3.12+, and the default in Python 3.14+.  The sysmon
  core does not yet support plugins, dynamic contexts, or some concurrency
  libraries. In Python 3.12 and 3.13, it does not support branch coverage.

- ``pytrace``: the pure Python implementation of a sys.settrace function.

This setting was previously only available as the COVERAGE_CORE environment
variable.

.. versionadded:: 7.9


.. _config_run_cover_pylib:

[run] cover_pylib
.................

(boolean, default False) Whether to measure the Python standard library.


.. _config_run_data_file:

[run] data_file
...............

(string, default ".coverage") The name of the data file to use for storing or
reporting coverage. This value can include a path to another directory.


.. _config_run_disable_warnings:

[run] disable_warnings
......................

(multi-string) A list of warnings to disable.  Warnings that can be disabled
include a short string at the end, the name of the warning. See
:ref:`cmd_warnings` for specific warnings.


.. _config_run_debug:

[run] debug
...........

(multi-string) A list of debug options.  See :ref:`the run -‍-debug option
<cmd_run_debug>` for details.


.. _config_run_debug_file:

[run] debug_file
................

(string) A file name to write debug output to.  See :ref:`the run -‍-debug
option <cmd_run_debug>` for details.


.. _config_run_dynamic_context:

[run] dynamic_context
.....................

(string) The name of a strategy for setting the dynamic context during
execution.  See :ref:`dynamic_contexts` for details.


.. _config_run_include:

[run] include
.............

(multi-string) A list of file name patterns, the files to include in
measurement or reporting.  Ignored if ``source`` is set.  See :ref:`source` for
details.


.. _config_run_omit:

[run] omit
..........

(multi-string) A list of file name patterns, the files to leave out of
measurement or reporting.  See :ref:`source` for details.


.. _config_run_parallel:

[run] parallel
..............

(boolean, default False) Append the machine name, process id and random number
to the data file name to simplify collecting data from many processes.  See
:ref:`cmd_combine` for more information.


.. _config_run_patch:

[run] patch
...........

(multi-string) A list of patch names that coverage can apply to the runtime
environment to improve coverage measurement.  The available patches correspond
to Python features that could interfere with coverage.  The patch inserts
coverage-specific code to collect the correct data.

These must be requested in the configuration instead of being applied
automatically because they could be invasive and produce undesirable
side-effects.

Available patches:

- ``execv``: The :func:`execv <python:os.execl>` family of functions end the
  current program without giving coverage a chance to write collected data.
  This patch adjusts those functions to save the data before starting the next
  executable. Not available on Windows.

- ``_exit``: The :func:`os._exit() <python:os._exit>` function exits the
  process immediately without calling cleanup handlers.  This patch saves
  coverage data before exiting.

- ``fork``: Forking a process normally continues measuring coverage properly.
  This patch stops the previous coverage and starts a new one in the child
  process for those times when the default handling isn't enough.

- ``subprocess``: Python sub-processes normally won't get coverage measurement.
  This patch configures Python to start coverage automatically, and will apply
  to processes created with :mod:`subprocess`, :func:`os.system`, or one of the
  :func:`execv <python:os.execl>` or :func:`spawnv <python:os.spawnl>` family
  of functions.  If an ``exec*e`` or ``spawn*e`` function is used, the new
  environment must copy over the ``COVERAGE_PROCESS_START`` environment
  variable.

  The ``subprocess`` patch sets :ref:`parallel = True <config_run_parallel>`
  and will require combining data files before reporting.  See
  :ref:`cmd_combine` for more details.

.. versionadded:: 7.10


.. _config_run_plugins:

[run] plugins
.............

(multi-string) A list of plugin package names. See :ref:`plugins` for more
information.


.. _config_run_relative_files:

[run] relative_files
....................

(boolean, default False) store relative file paths in the data file.  This
makes it easier to measure code in one (or multiple) environments, and then
report in another. See :ref:`cmd_combine` for details.

Note that setting ``source`` has to be done in the configuration file rather
than the command line for this option to work, since the reporting commands
need to know the source origin.

.. versionadded:: 5.0


.. _config_run_sigterm:

[run] sigterm
.............

(boolean, default False) if true, register a SIGTERM signal handler to capture
data when the process ends due to a SIGTERM signal.  This includes
:meth:`Process.terminate <python:multiprocessing.Process.terminate>` and other
ways to terminate a process.  This can help when collecting data in usual
situations, but can also introduce problems (see `issue 1310`_).

The signal handler is only registered on Linux and Mac.  On Windows, this
setting has no effect.

.. _issue 1310: https://github.com/coveragepy/coveragepy/issues/1310

.. versionadded:: 6.4 (in 6.3 this was always enabled)


.. _config_run_source:

[run] source
............

(multi-string) A list of packages or directories, the source to measure during
execution.  If set, ``include`` is ignored. See :ref:`source` for details.


.. _config_run_source_pkgs:

[run] source_pkgs
.................

(multi-string) A list of packages, the source to measure during execution.
Operates the same as ``source``, but only names packages, for resolving
ambiguities between packages and directories.

.. versionadded:: 5.3


.. _config_run_source_dirs:

[run] source_dirs
.................

(multi-string) A list of directories, the source to measure during execution.
Operates the same as ``source``, but only names directories, for resolving
ambiguities between packages and directories.

.. versionadded:: 7.8


.. _config_run_timid:

[run] timid
...........

(boolean, default False) Use a simpler but slower trace method.  This uses the
PyTracer trace function core instead of CTracer, and is only needed in very
unusual circumstances.


.. _config_paths:

[paths]
-------

The entries in this section are lists of file paths that should be considered
equivalent when combining data from different machines:

.. [[[cog
    show_configs(
        ini=r"""
            [paths]
            source =
                src/
                /jenkins/build/*/src
                c:\myproj\src
            """,
        toml=r"""
            [tool.coverage.paths]
            source = [
                "src/",
                "/jenkins/build/*/src",
                "c:\\myproj\\src",
                ]
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.paths]
        source = [
            "src/",
            "/jenkins/build/*/src",
            "c:\\myproj\\src",
            ]

    .. code-tab:: ini
        :caption: .coveragerc

        [paths]
        source =
            src/
            /jenkins/build/*/src
            c:\myproj\src

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [paths]
        source = [
            "src/",
            "/jenkins/build/*/src",
            "c:\\myproj\\src",
            ]

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:paths]
        source =
            src/
            /jenkins/build/*/src
            c:\myproj\src

.. [[[end]]] (sum: Aq4877/XV0)


The names of the entries ("source" in this example) are ignored, you may choose
any name that you like.  The value is a list of strings.  When combining data
with the ``combine`` command, two file paths will be combined if they start
with paths from the same list.

The first value must be an actual file path on the machine where the reporting
will happen, so that source code can be found.  The other values can be file
patterns to match against the paths of collected data, or they can be absolute
or relative file paths on the current machine.

In this example, data collected for "/jenkins/build/1234/src/module.py" will be
combined with data for "c:\\myproj\\src\\module.py", and will be reported
against the source file found at "src/module.py".

If you specify more than one list of paths, they will be considered in order.
A file path will only be remapped if the result exists.  If a path matches a
list, but the result doesn't exist, the next list will be tried.  The first
list that has an existing result will be used.

Remapping will also be done during reporting, but only within the single data
file being reported.  Combining multiple files requires the ``combine``
command.

The ``--debug=pathmap`` option can be used to log details of the re-mapping of
paths.  See :ref:`the -‍-debug option <cmd_run_debug>`.

See :ref:`cmd_combine_remapping` and :ref:`source_glob` for more information.


.. _config_report:

[report]
--------

Settings common to many kinds of reporting.


.. _config_report_exclude_also:

[report] exclude_also
.....................

(multi-string) A list of regular expressions.  This setting is similar to
:ref:`config_report_exclude_lines`: it specifies patterns for lines to exclude
from reporting.  This setting is preferred, because it will preserve the
default exclude patterns like ``pragma: no cover`` instead of overwriting them.

See :ref:`config_report_exclude_lines` for further details.

.. versionadded:: 7.2.0


.. _config_report_exclude_lines:

[report] exclude_lines
......................

(multi-string) A list of regular expressions.  Any line of your source code
containing a match for one of these regexes is excluded from being reported as
missing.  More details are in :ref:`excluding`.  If you use this option, you
are replacing all the exclude regexes, so you'll need to also supply the
"pragma: no cover" regex if you still want to use it.  The
:ref:`config_report_exclude_also` setting can be used to specify patterns
without overwriting the default set.

You can exclude lines introducing blocks, and the entire block is excluded. If
you exclude a ``def`` line or decorator line, the entire function is excluded.

Be careful when writing this setting: the values are regular expressions that
only have to match a portion of the line. For example, if you write ``...``,
you'll exclude any line with three or more of any character. If you write
``pass``, you'll also exclude the line ``my_pass="foo"``, and so on.

All of the regexes here and in :ref:`config_report_exclude_also` are combined
into one regex for processing, so you cannot use global flags like ``(?s)`` in
your regexes.  Use the scoped flag form instead: ``(?s:...)``


.. _config_report_fail_under:

[report] fail_under
...................

(float) A target coverage percentage.  If the total coverage measurement is
under this value, then exit with a status code of 2.  If you specify a
non-integral value, you must also set ``[report] precision`` properly to make
use of the decimal places.  A setting of 100 will fail any value under 100,
regardless of the number of decimal places of precision.


.. _config_report_format:

[report] format
...............

(string, default "text") The format to use for the textual report.  The default
is "text" which produces a simple textual table. You can use "markdown" to
produce a Markdown table, or "total" to output only the total coverage
percentage.

.. versionadded:: 7.0


.. _config_report_ignore_errors:

[report] ignore_errors
......................

(boolean, default False) Ignore source code that can't be found, emitting a
warning instead of an exception.


.. _config_report_include:

[report] include
................

(multi-string) A list of file name patterns, the files to include in reporting.
See :ref:`source` for details.


.. _config_include_namespace_packages:

[report] include_namespace_packages
...................................

(boolean, default False) When searching for completely un-executed files,
include directories without ``__init__.py`` files.  These are `implicit
namespace packages`_, and are usually skipped.

.. _implicit namespace packages: https://peps.python.org/pep-0420/

.. versionadded:: 7.0


.. _config_report_omit:

[report] omit
.............

(multi-string) A list of file name patterns, the files to leave out of
reporting.  See :ref:`source` for details.


.. _config_report_partial_also:

[report] partial_also
.....................

(multi-string) A list of regular expressions.  This setting is similar to
:ref:`config_report_partial_branches`: it specifies patterns for branches to
consider fully covered even if they don't exercise both destinations.  This
setting is preferred, because it will preserve the default exclude patterns
like ``pragma: no branch`` instead of overwriting them.

See :ref:`config_report_partial_branches` for further details.

.. versionadded:: 7.10.0


.. _config_report_partial_branches:

[report] partial_branches
.........................

(multi-string) A list of regular expressions.  Any line of code that matches
one of these regexes is excused from being reported as a partial branch.  More
details are in :ref:`branch`.  If you use this option, you are replacing all
the partial branch regexes so you'll need to also supply the "pragma: no
branch" regex if you still want to use it. The
:ref:`config_report_partial_also` setting can be used to specify patterns
without overwriting the default set.


.. _config_report_precision:

[report] precision
..................

(integer) The number of digits after the decimal point to display for reported
coverage percentages.  The default is 0, displaying for example "87%".  A value
of 2 will display percentages like "87.32%".  This setting also affects the
interpretation of the ``fail_under`` setting.


.. _config_report_show_missing:

[report] show_missing
.....................

(boolean, default False) When running a summary report, show missing lines.
See :ref:`cmd_report` for more information.


.. _config_report_skip_covered:

[report] skip_covered
.....................

(boolean, default False) Don't report files that are 100% covered.  This helps
you focus on files that need attention.


.. _config_report_skip_empty:

[report] skip_empty
...................

(boolean, default False) Don't report files that have no executable code (such
as ``__init__.py`` files).


.. _config_report_sort:

[report] sort
.............

(string, default "Name") Sort the text report by the named column.  Allowed
values are "Name", "Stmts", "Miss", "Branch", "BrPart", or "Cover".  Prefix
with ``-`` for descending sort (for example, "-cover").


.. _config_html:

[html]
------

Settings particular to HTML reporting.  The settings in the ``[report]``
section also apply to HTML output, where appropriate.


.. _config_html_directory:

[html] directory
................

(string, default "htmlcov") Where to write the HTML report files.


.. _config_html_extra_css:

[html] extra_css
................

(string) The path to a file of CSS to apply to the HTML report.  The file will
be copied into the HTML output directory.  Don't name it "style.css".  This CSS
is in addition to the CSS normally used, though you can overwrite as many of
the rules as you like.


.. _config_html_show_context:

[html] show_contexts
....................

(boolean) Should the HTML report include an indication on each line of which
contexts executed the line.  See :ref:`dynamic_contexts` for details.


.. _config_html_skip_covered:

[html] skip_covered
...................

(boolean, defaulted from ``[report] skip_covered``) Don't include files in the
report that are 100% covered files. See :ref:`cmd_report` for more information.

.. versionadded:: 5.4


.. _config_html_skip_empty:

[html] skip_empty
.................

(boolean, defaulted from ``[report] skip_empty``) Don't include empty files
(those that have 0 statements) in the report. See :ref:`cmd_report` for more
information.

.. versionadded:: 5.4


.. _config_html_title:

[html] title
............

(string, default "Coverage report") The title to use for the report.
Note this is text, not HTML.


.. _config_xml:

[xml]
-----

Settings particular to XML reporting.  The settings in the ``[report]`` section
also apply to XML output, where appropriate.


.. _config_xml_output:

[xml] output
............

(string, default "coverage.xml") Where to write the XML report.


.. _config_xml_package_depth:

[xml] package_depth
...................

(integer, default 99) Controls which directories are identified as packages in
the report.  Directories deeper than this depth are not reported as packages.
The default is that all directories are reported as packages.


.. _config_json:

[json]
------

Settings particular to JSON reporting.  The settings in the ``[report]``
section also apply to JSON output, where appropriate.

.. versionadded:: 5.0


.. _config_json_output:

[json] output
.............

(string, default "coverage.json") Where to write the JSON file.


.. _config_json_pretty_print:

[json] pretty_print
...................

(boolean, default false) Controls if the JSON is outputted with white space
formatted for human consumption (True) or for minimum file size (False).


.. _config_json_show_contexts:

[json] show_contexts
....................

(boolean, default false) Should the JSON report include an indication of which
contexts executed each line.  See :ref:`dynamic_contexts` for details.


.. _config_lcov:

[lcov]
------

Settings particular to LCOV reporting (see :ref:`cmd_lcov`).

.. versionadded:: 6.3

.. _config_lcov_output:

[lcov] output
.............

(string, default "coverage.lcov") Where to write the LCOV file.

.. _config_lcov_line_checksums:

[lcov] line_checksums
.....................

(boolean, default false) Whether to write per-line checksums as part of the
lcov file.  Because these checksums cover only lines with actual code on
them, and do not verify the ordering of lines, they provide only a weak
assurance that the source code available to analysis tools (e.g. ``genhtml``)
matches the code that was used to generate the coverage data.

.. versionadded:: 7.6.2
