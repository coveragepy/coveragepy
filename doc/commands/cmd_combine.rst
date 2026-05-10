.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_combine:

Combining data files: ``coverage combine``
------------------------------------------

Often test suites are run under different conditions, for example, with
different versions of Python, or dependencies, or on different operating
systems.  In these cases, you can collect coverage data for each test run, and
then combine all the separate data files into one combined file for reporting.

The **combine** command reads a number of separate data files, matches the data
by source file name, and writes a combined data file with all of the data.

As of version 7.14.0, files are combined by the :ref:`reporting commands
<cmd_reporting>`, so there is less need to use an explicit ``combine`` command.

Coverage normally writes data to a filed named ".coverage".  The ``run
--parallel-mode`` switch (or ``[run] parallel=True`` configuration option)
tells coverage to expand the file name to include distinguising information
so that every data file is distinct::

    .coverage.Neds-MacBook-Pro.pid88335.XSpwmKEx.HFOd8LCkdg8h
    .coverage.Geometer.pid8044.XJeYqEYx.H7cDrkGAlTVh

You can also define a new data file name with the ``[run] data_file`` option.

Once you have created a number of these files, you can copy them all to a
single directory, and use the **combine** command to combine them into one
.coverage data file::

    $ coverage combine

You can also name directories or files to be combined on the command line::

    $ coverage combine data1.dat windows_data_files/

Coverage.py will collect the data from those places and combine them.  The
current directory isn't searched if you use command-line arguments.  If you
also want data from the current directory, name it explicitly on the command
line.

When coverage.py combines data files, it looks for files named the same as the
data file (defaulting to ".coverage"), with a dotted suffix.  Here are some
examples of data files that can be combined::

    .coverage.machine1
    .coverage.20120807T212300
    .coverage.last_good_run.ok

An existing combined data file is ignored and re-written. If you want to use
**combine** to accumulate results into the .coverage data file over a number of
runs, use the ``--append`` switch on the **combine** command.  This behavior
was the default before version 4.2.

If any of the data files can't be read, coverage.py will print a warning
indicating the file and the problem.

The original input data files are deleted once they've been combined. If you
want to keep those files, use the ``--keep`` command-line option.

.. [[[cog show_help("combine") ]]]
.. code::

    $ coverage combine --help
    Usage: coverage combine [options] <path1> <path2> ... <pathN>

    Combine data from multiple coverage files. The combined results are written to
    a single file representing the union of the data. The positional arguments are
    data files or directories containing data files. If no paths are provided,
    data files in the default data file's directory are combined.

    Options:
      -a, --append          Append data to the data file. Otherwise it starts
                            clean each time.
      --data-file=DATAFILE  Base name of the data files to operate on. Defaults to
                            '.coverage'. [env: COVERAGE_FILE]
      --keep                Keep original coverage files, otherwise they are
                            deleted.
      -q, --quiet           Don't print messages about what is happening.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: ARyg8KB1fE)


.. _cmd_combine_remapping:

Re-mapping paths
................

To combine data for a source file, coverage has to find its data in each of the
data files.  Different test runs may run the same source file from different
locations. For example, different operating systems will use different paths
for the same file, or perhaps each Python version is run from a different
subdirectory.  Coverage needs to know that different file paths are actually
the same source file for reporting purposes.

You can tell coverage.py how different source locations relate with a
``[paths]`` section in your configuration file (see :ref:`config_paths`).
It might be more convenient to use the ``[run] relative_files``
setting to store relative file paths (see :ref:`relative_files
<config_run_relative_files>`).

If data isn't combining properly, you can see details about the inner workings
with ``--debug=pathmap``.
