.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_erase:

Erase data: ``coverage erase``
------------------------------

To erase the collected data, use the **erase** command:

.. [[[cog show_help("erase") ]]]
.. code::

    $ coverage erase --help
    Usage: coverage erase [options]

    Erase previously collected coverage data.

    Options:
      --data-file=DATAFILE  Base name of the data files to operate on. Defaults to
                            '.coverage'. [env: COVERAGE_FILE]
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: z+rvZs6NUV)

If your configuration file indicates parallel data collection, **erase** will
remove all of the data files.
