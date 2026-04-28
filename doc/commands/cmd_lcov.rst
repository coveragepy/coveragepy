.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_lcov:

LCOV reporting: ``coverage lcov``
---------------------------------

The **lcov** command writes coverage data to a "coverage.lcov" file.

.. [[[cog show_help("lcov") ]]]
.. code::

    $ coverage lcov --help
    Usage: coverage lcov [options] [modules]

    Generate an LCOV report of coverage results.

    Options:
      --data-file=INFILE    Read coverage data for report generation from this
                            file. Defaults to '.coverage'. [env: COVERAGE_FILE]
      --fail-under=MIN      Exit with a status of 2 if the total coverage is less
                            than MIN.
      -i, --ignore-errors   Ignore errors while reading source files.
      --include=PAT1,PAT2,...
                            Include only files whose paths match one of these
                            patterns. Accepts shell-style wildcards, which must be
                            quoted.
      -o OUTFILE            Write the LCOV report to this file. Defaults to
                            'coverage.lcov'
      --omit=PAT1,PAT2,...  Omit files whose paths match one of these patterns.
                            Accepts shell-style wildcards, which must be quoted.
      -q, --quiet           Don't print messages about what is happening.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: Fqz7roAR0u)

Common reporting options are described above in :ref:`cmd_reporting`.
Also see :ref:`Configuration: [lcov] <config_lcov>`.

.. versionadded:: 6.3
