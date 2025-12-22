.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_debug:

Diagnostics: ``coverage debug``
-------------------------------

The **debug** command shows internal information to help diagnose problems.
If you are reporting a bug about coverage.py, including the output of this
command can often help::

    $ coverage debug sys > please_attach_to_bug_report.txt

A few types of information are available:

* ``config``: show coverage's configuration
* ``sys``: show system configuration
* ``data``: show a summary of the collected coverage data
* ``premain``: show the call stack invoking coverage
* ``pybehave``: show internal flags describing Python behavior
* ``sqlite``: show internal compilation options for SQLite

.. [[[cog show_help("debug") ]]]
.. code::

    $ coverage debug --help
    Usage: coverage debug <topic>

    Display information about the internals of coverage.py, for diagnosing
    problems. Topics are: 'data [filenames]' to summarize data files; 'sys' to
    show installation information; 'config' to show the configuration; 'premain'
    to show what is calling coverage; 'pybehave' to show internal flags describing
    Python behavior; 'sqlite' to show SQLite compilation options.

    Options:
      --debug=OPTS     Debug options, separated by commas. [env: COVERAGE_DEBUG]
      -h, --help       Get help on this command.
      --rcfile=RCFILE  Specify configuration file. By default '.coveragerc',
                       'setup.cfg', 'tox.ini', and 'pyproject.toml' are tried.
                       [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: 8K0+009GCf)


.. _cmd_run_debug:

``--debug`` option
..................

The ``--debug`` option is available on all commands.  It instructs
coverage.py to log internal details of its operation to help with diagnosing
problems.  It takes a comma-separated list of options, each indicating a facet
of activity to log:

* ``callers``: annotate each debug message with a stack trace of the callers
  to that point.

* ``config``: before starting, dump all the :ref:`configuration <config>`
  values.

* ``core``: log decision about choosing the measurement core to use.

* ``dataio``: log when reading or writing any data file.

* ``dataop``: log a summary of data being added to CoverageData objects.

* ``dataop2``: when used with ``debug=dataop``, log the actual data being added
  to CoverageData objects.

* ``lock``: log operations acquiring locks in the data layer.

* ``multiproc``: log the start and stop of multiprocessing processes.

* ``patch``: log when patches are applied and when they are executed. See
  :ref:`config_run_patch`.

* ``pathmap``: log the remapping of paths that happens during ``coverage
  combine``. See :ref:`config_paths`.

* ``pid``: annotate all warnings and debug output with the process and thread
  ids.

* ``plugin``: print information about plugin operations.

* ``process``: show process creation information, and changes in the current
  directory.  This also writes a time stamp and command arguments into the data
  file.

* ``pybehave``: show the values of `internal flags <env.py_>`_ describing the
  behavior of the current version of Python.

* ``pytest``: indicate the name of the current pytest test when it changes.

* ``self``: annotate each debug message with the object printing the message.

* ``sql``: log the SQL statements used for recording data.

* ``sqldata``: when used with ``debug=sql``, also log the full data being used
  in SQL statements.

* ``sys``: before starting, dump all the system and environment information,
  as with :ref:`coverage debug sys <cmd_debug>`.

* ``trace``: print every decision about whether to trace a file or not. For
  files not being traced, the reason is also given.

.. _env.py: https://github.com/coveragepy/coveragepy/blob/main/coverage/env.py

Debug options can also be set with the ``COVERAGE_DEBUG`` environment variable,
a comma-separated list of these options, or in the :ref:`config_run_debug`
section of the .coveragerc file.

The debug output goes to stderr, unless the :ref:`config_run_debug_file`
setting or the ``COVERAGE_DEBUG_FILE`` environment variable names a different
file, which will be appended to.  This can be useful because many test runners
capture output, which could hide important details.  ``COVERAGE_DEBUG_FILE``
accepts the special names ``stdout`` and ``stderr`` to write to those
destinations.
