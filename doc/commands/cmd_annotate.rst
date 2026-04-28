.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_annotate:

Text annotation: ``coverage annotate``
--------------------------------------

.. note::

    The **annotate** command has been obsoleted by more modern reporting tools,
    including the **html** command.  The command is still supported, but won't
    be getting new features.

The **annotate** command produces a text annotation of your source code.  With
a ``-d`` argument specifying an output directory, each Python file becomes a
text file in that directory.  Without ``-d``, the files are written into the
same directories as the original Python files.

Coverage status for each line of source is indicated with a character prefix::

    > executed
    ! missing (not executed)
    - excluded

For example::

      # A simple function, never called with x==1

    > def h(x):
          """Silly function."""
    -     if 0:  # pragma: no cover
    -         pass
    >     if x == 1:
    !         a = 1
    >     else:
    >         a = 2

.. [[[cog show_help("annotate") ]]]
.. code::

    $ coverage annotate --help
    Usage: coverage annotate [options] [modules]

    Make annotated copies of the given files, marking statements that are executed
    with > and statements that are missed with !.

    Options:
      -d DIR, --directory=DIR
                            Write the output files to DIR.
      --data-file=INFILE    Read coverage data for report generation from this
                            file. Defaults to '.coverage'. [env: COVERAGE_FILE]
      -i, --ignore-errors   Ignore errors while reading source files.
      --include=PAT1,PAT2,...
                            Include only files whose paths match one of these
                            patterns. Accepts shell-style wildcards, which must be
                            quoted.
      --omit=PAT1,PAT2,...  Omit files whose paths match one of these patterns.
                            Accepts shell-style wildcards, which must be quoted.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: /X2PvS3W4k)

Other common reporting options are described above in :ref:`cmd_reporting`.
