.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_report:

Coverage summary: ``coverage report``
-------------------------------------

The simplest reporting is a textual summary produced with **report**::

    $ coverage report
    Name                      Stmts   Miss  Cover
    ---------------------------------------------
    my_program.py                20      4    80%
    my_module.py                 15      2    86%
    my_other_module.py           56      6    89%
    ---------------------------------------------
    TOTAL                        91     12    87%

For each module executed, the report shows the count of executable statements,
the number of those statements missed, and the resulting coverage, expressed
as a percentage.

.. [[[cog show_help("report") ]]]
.. code::

    $ coverage report --help
    Usage: coverage report [options] [modules]

    Report coverage statistics on modules.

    Options:
      --contexts=REGEX1,REGEX2,...
                            Only display data from lines covered in the given
                            contexts. Accepts Python regexes, which must be
                            quoted.
      --data-file=INFILE    Read coverage data for report generation from this
                            file. Defaults to '.coverage'. [env: COVERAGE_FILE]
      --fail-under=MIN      Exit with a status of 2 if the total coverage is less
                            than MIN.
      --format=FORMAT       Output format, either text (default), markdown, or
                            total.
      -i, --ignore-errors   Ignore errors while reading source files.
      --include=PAT1,PAT2,...
                            Include only files whose paths match one of these
                            patterns. Accepts shell-style wildcards, which must be
                            quoted.
      --omit=PAT1,PAT2,...  Omit files whose paths match one of these patterns.
                            Accepts shell-style wildcards, which must be quoted.
      --precision=N         Number of digits after the decimal point to display
                            for reported coverage percentages.
      --sort=COLUMN         Sort the report by the named column: name, stmts,
                            miss, branch, brpart, or cover. Default is name.
      -m, --show-missing    Show line numbers of statements in each module that
                            weren't executed.
      --skip-covered        Skip files with 100% coverage.
      --no-skip-covered     Disable --skip-covered.
      --skip-empty          Skip files with no code.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: FnJyop2efr)

The ``-m`` flag also shows the line numbers of missing statements::

    $ coverage report -m
    Name                      Stmts   Miss  Cover   Missing
    -------------------------------------------------------
    my_program.py                20      4    80%   33-35, 39
    my_module.py                 15      2    86%   8, 12
    my_other_module.py           56      6    89%   17-23
    -------------------------------------------------------
    TOTAL                        91     12    87%

If you are using branch coverage, then branch statistics will be reported in
the Branch and BrPart (for Partial Branch) columns, the Missing column will
detail the missed branches::

    $ coverage report -m
    Name                      Stmts   Miss Branch BrPart  Cover   Missing
    ---------------------------------------------------------------------
    my_program.py                20      4     10      2    80%   33-35, 36->38, 39
    my_module.py                 15      2      3      0    86%   8, 12
    my_other_module.py           56      6      5      1    89%   17-23, 40->45
    ---------------------------------------------------------------------
    TOTAL                        91     12     18      3    87%

Ranges of lines are shown with a dash: ``17-23`` means all lines from 17 to 23
inclusive are missing coverage.  Missed branches are shown with an arrow:
``40->45`` means the branch from line 40 to line 45 is missing.  A branch can go
backwards in a file, so you might see a branch from a later line to an earlier
line, like ``55->50``. This happens when returning to the top of a loop.  For
detailed examples of how branch coverage works in loops and other control flow
constructs, see :ref:`branch_explain`.

You can restrict the report to only certain files by naming them on the
command line::

    $ coverage report -m my_program.py my_other_module.py
    Name                      Stmts   Miss  Cover   Missing
    -------------------------------------------------------
    my_program.py                20      4    80%   33-35, 39
    my_other_module.py           56      6    89%   17-23
    -------------------------------------------------------
    TOTAL                        76     10    87%

The ``--skip-covered`` switch will skip any file with 100% coverage, letting
you focus on the files that still need attention. The ``--no-skip-covered``
option can be used if needed to see all the files.  The ``--skip-empty`` switch
will skip any file with no executable statements.

If you have :ref:`recorded contexts <contexts>`, the ``--contexts`` option lets
you choose which contexts to report on.  See :ref:`context_reporting` for
details.

The ``--precision`` option controls the number of digits displayed after the
decimal point in coverage percentages, defaulting to none.

The ``--sort`` option is the name of a column to sort the report by.

The ``--format`` option controls the style of the report.  ``--format=text``
creates plain text tables as shown above.  ``--format=markdown`` creates
Markdown tables.  ``--format=total`` writes out a single number, the total
coverage percentage as shown at the end of the tables, but without a percent
sign.

Other common reporting options are described above in :ref:`cmd_reporting`.
These options can also be set in your .coveragerc file. See
:ref:`Configuration: [report] <config_report>`.
