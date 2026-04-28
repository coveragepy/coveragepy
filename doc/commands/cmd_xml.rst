.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_xml:

XML reporting: ``coverage xml``
-------------------------------

The **xml** command writes coverage data to a "coverage.xml" file in a format
compatible with `Cobertura`_.

.. _Cobertura: http://cobertura.github.io/cobertura/

.. [[[cog show_help("xml") ]]]
.. code::

    $ coverage xml --help
    Usage: coverage xml [options] [modules]

    Generate an XML report of coverage results.

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
      --omit=PAT1,PAT2,...  Omit files whose paths match one of these patterns.
                            Accepts shell-style wildcards, which must be quoted.
      -o OUTFILE            Write the XML report to this file. Defaults to
                            'coverage.xml'
      -q, --quiet           Don't print messages about what is happening.
      --skip-empty          Skip files with no code.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: iyOdiVNL4L)

You can specify the name of the output file with the ``-o`` switch.

Other common reporting options are described above in :ref:`cmd_reporting`.

To include complete file paths in the output file, rather than just
the file name, use [include] vs [source] in your ".coveragerc" file.

For example, use this:

.. code:: ini

    [run]
    include =
        foo/*
        bar/*


which will result in

.. code:: xml

    <class filename="bar/hello.py">
    <class filename="bar/baz/hello.py">
    <class filename="foo/hello.py">

in place of this:

.. code:: ini

    [run]
    source =
        foo
        bar

which may result in

.. code:: xml

    <class filename="hello.py">
    <class filename="baz/hello.py">

These options can also be set in your .coveragerc file. See
:ref:`Configuration: [xml] <config_xml>`.
