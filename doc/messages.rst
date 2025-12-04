.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_configs
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)

.. _messages:

========
Messages
========

Coverage.py has a number of messages for conditions that could affect
measurement or reporting.


.. _errors:

Errors
------

.. _error_no_source:

No source for code: 'filename.py'
  A source file was traced during execution, but was not found when trying to
  produce a report.  Often this is due to libraries creating temporary source
  files which are deleted after execution.

  You can add :ref:`configuration settings <config>` to avoid the error:

  - Use ":ref:`[run] source=. <config_run_source>`" to prevent measurement of
    code outside of your project.

  - Use ":ref:`[report] omit=$TMPDIR/* <config_report_omit>`" to explicitly
    skip reporting the temporary directory where the files were created.  The
    appropriate environment variable will depend on your system.

  - Use ":ref:`[report] ignore_errors = true <config_report_ignore_errors>`"
    to treat the error as a warning.

.. _error_cant_combine:

Can't combine (branch or statement) coverage data with (statement or branch) data
  You have some data files that measured branch coverage and some data files
  that didn't.  They cannot be combined because the two types of data are
  incompatible.  You'll need to ensure that all of your data files are
  collected with the same settings.


.. _cmd_warnings:
.. _warnings:

Warnings
--------

Warnings are issued for possible problems but don't stop the measurement or
reporting.  See below for the details of each warning, and how to suppress
warnings you don't need to see.

.. _warning_couldnt_parse:

Couldn't parse Python file XXX (couldnt-parse)
  During reporting, a file was thought to be Python, but it couldn't be parsed
  as Python.

.. _warning_trace_changed:

Trace function changed, data is likely wrong: XXX (trace-changed)
  Coverage measurement depends on a Python setting called the trace function.
  Other Python code in your product might change that function, which will
  disrupt coverage.py's measurement.  This warning indicates that has happened.
  The XXX in the message is the new trace function value, which might provide
  a clue to the cause.

.. _warning_module_not_python:

Module XXX has no Python source (module-not-python)
  You asked coverage.py to measure module XXX, but once it was imported, it
  turned out not to have a corresponding .py file.  Without a .py file,
  coverage.py can't report on missing lines.

.. _warning_module_not_imported:

Module XXX was never imported (module-not-imported)
  You asked coverage.py to measure module XXX, but it was never imported by
  your program.

.. _warning_no_data_collected:

No data was collected (no-data-collected)
  Coverage.py ran your program, but didn't measure any lines as executed.
  This could be because you asked to measure only modules that never ran,
  or for other reasons.

  To debug this problem, try using ``run --debug=trace`` to see the tracing
  decision made for each file.

.. _warning_module_not_measured:

Module XXX was previously imported, but not measured (module-not-measured)
  You asked coverage.py to measure module XXX, but it had already been imported
  when coverage started.  This meant coverage.py couldn't monitor its
  execution.

.. _warning_already_imported:

Already imported a file that will be measured: XXX (already-imported)
  File XXX had already been imported when coverage.py started measurement. Your
  setting for ``--source`` or ``--include`` indicates that you wanted to
  measure that file.  Lines will be missing from the coverage report since the
  execution during import hadn't been measured.

.. _warning_include_ignored:

\-\-include is ignored because \-\-source is set (include-ignored)
  Both ``--include`` and ``--source`` were specified while running code.  Both
  are meant to focus measurement on a particular part of your source code, so
  ``--include`` is ignored in favor of ``--source``.

.. _warning_dynamic_conflict:

Conflicting dynamic contexts (dynamic-conflict)
  The ``[run] dynamic_context`` option is set in the configuration file, but
  something (probably a test runner plugin) is also calling the
  :meth:`.Coverage.switch_context` function to change the context. Only one of
  these mechanisms should be in use at a time.

.. _warning_no_ctracer:

Couldn't import C tracer (no-ctracer)
  The core tracer implemented in C should have been used, but couldn't be
  imported.  The reason is included in the warning message.  The Python tracer
  will be used instead.

.. _warning_no_sysmon:

Can't use core=sysmon: sys.monitoring isn't available in this version, using default core (no-sysmon)
  You requested to the sys.monitoring measurement core, but are running on
  Python 3.11 or lower where it isn't available.  A default core will be used
  instead.

Can't use core=sysmon: sys.monitoring can't measure branches in this version, using default core (no-sysmon)
  You requested the sys.monitoring measurement core and also branch coverage.
  This isn't supported until Python 3.14.  A default core will be used instead.

Can't use core=sysmon: it doesn't yet support dynamic contexts, using default core (no-sysmon)
  You requested the sys.monitoring measurement core and also dynamic contexts.
  This isn't supported by coverage.py yet.  A default core will be used
  instead.

Can't use core=sysmon: it doesn't support concurrency=ZZZ, using default core (no-sysmon)
  Your requested the sys.monitoring measurement core and also a particular
  concurrency setting, but that combination isn't supported.  A default core
  will be used instead.


Disabling warnings
------------------

Individual warnings can be disabled with the :ref:`disable_warnings
<config_run_disable_warnings>` configuration setting.  It is a list of the
short parenthetical nicknames in the warning messages.  For example, to silence
"No data was collected (no-data-collected)", add this to your configuration
file:

.. [[[cog
    show_configs(
        ini=r"""
            [run]
            disable_warnings = no-data-collected
            """,
        toml=r"""
            [tool.coverage.run]
            disable_warnings = ["no-data-collected"]
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.run]
        disable_warnings = ["no-data-collected"]

    .. code-tab:: ini
        :caption: .coveragerc

        [run]
        disable_warnings = no-data-collected

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [run]
        disable_warnings = ["no-data-collected"]

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:run]
        disable_warnings = no-data-collected

.. [[[end]]] (sum: 29eQyqSCXt)
