.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_json:

JSON reporting: ``coverage json``
---------------------------------

The **json** command writes coverage data to a "coverage.json" file.

.. [[[cog show_help("json") ]]]
.. code::

    $ coverage json --help
    Usage: coverage json [options] [modules]

    Generate a JSON report of coverage results.

    Options:
      --contexts=REGEX1,REGEX2,...
                            Only display data from lines covered in the given
                            contexts. Accepts Python regexes, which must be
                            quoted.
      --data-file=INFILE    Read coverage data for report generation from this
                            file. Defaults to '.coverage'. [env: COVERAGE_FILE]
      --fail-under=MIN      Exit with a status of 2 if the total coverage is less
                            than MIN.
      -i, --ignore-errors   Ignore errors while reading source files.
      --include=PAT1,PAT2,...
                            Include only files whose paths match one of these
                            patterns. Accepts shell-style wildcards, which must be
                            quoted.
      --omit=PAT1,PAT2,...  Omit files whose paths match one of these patterns.
                            Accepts shell-style wildcards, which must be quoted.
      -o OUTFILE            Write the JSON report to this file. Defaults to
                            'coverage.json'
      --pretty-print        Format the JSON for human readers.
      -q, --quiet           Don't print messages about what is happening.
      --show-contexts       Show contexts for covered lines.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: 5T5gy2XZcc)

You can specify the name of the output file with the ``-o`` switch.  The JSON
can be nicely formatted by specifying the ``--pretty-print`` switch.

Other common reporting options are described above in :ref:`cmd_reporting`.
These options can also be set in your .coveragerc file. See
:ref:`Configuration: [json] <config_json>`.
