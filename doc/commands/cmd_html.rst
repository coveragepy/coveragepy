.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_html:

HTML reporting: ``coverage html``
---------------------------------

Coverage.py can annotate your source code to show which lines were executed
and which were not.  The **html** command creates an HTML report similar to the
**report** summary, but as an HTML file.  Each module name links to the source
file decorated to show the status of each line.

Here's a `sample report`__.

__ https://nedbatchelder.com/files/sample_coverage_html/index.html

Lines are highlighted: green for executed, red for missing, and gray for
excluded.  If you've used branch coverage, partial branches are yellow.  The
colored counts at the top of the file are buttons to turn on and off the
highlighting.

A number of keyboard shortcuts are available for navigating the report.
Click the keyboard icon in the upper right to see the complete list.

.. [[[cog show_help("html") ]]]
.. code::

    $ coverage html --help
    Usage: coverage html [options] [modules]

    Create an HTML report of the coverage of the files. Each file gets its own
    page, with the source decorated to show executed, excluded, and missed lines.

    Options:
      --contexts=REGEX1,REGEX2,...
                            Only display data from lines covered in the given
                            contexts. Accepts Python regexes, which must be
                            quoted.
      -d DIR, --directory=DIR
                            Write the output files to DIR.
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
      --precision=N         Number of digits after the decimal point to display
                            for reported coverage percentages.
      -q, --quiet           Don't print messages about what is happening.
      --show-contexts       Show contexts for covered lines.
      --skip-covered        Skip files with 100% coverage.
      --no-skip-covered     Disable --skip-covered.
      --skip-empty          Skip files with no code.
      --title=TITLE         A text string to use as the title on the HTML.
      --debug=OPTS          Debug options, separated by commas. [env:
                            COVERAGE_DEBUG]
      -h, --help            Get help on this command.
      --rcfile=RCFILE       Specify configuration file. By default '.coveragerc',
                            'setup.cfg', 'tox.ini', and 'pyproject.toml' are
                            tried. [env: COVERAGE_RCFILE]
.. [[[end]]] (sum: DwG6DxRZIf)

The title of the report can be set with the ``title`` setting in the
``[html]`` section of the configuration file, or the ``--title`` switch on
the command line.

If you prefer a different style for your HTML report, you can provide your
own CSS file to apply, by specifying a CSS file in the ``[html]`` section of
the configuration file.  See :ref:`config_html_extra_css` for details.

The ``-d`` argument specifies an output directory, defaulting to "htmlcov"::

    $ coverage html -d coverage_html

Other common reporting options are described above in :ref:`cmd_reporting`.

Generating the HTML report can be time-consuming.  Stored with the HTML report
is a data file that is used to speed up reporting the next time.  If you
generate a new report into the same directory, coverage.py will skip
generating unchanged pages, making the process faster.

The ``--skip-covered`` switch will skip any file with 100% coverage, letting
you focus on the files that still need attention.  The ``--skip-empty`` switch
will skip any file with no executable statements.

The ``--precision`` option controls the number of digits displayed after the
decimal point in coverage percentages, defaulting to none.

If you have :ref:`recorded contexts <contexts>`, the ``--contexts`` option lets
you choose which contexts to report on, and the ``--show-contexts`` option will
annotate lines with the contexts that ran them.  See :ref:`context_reporting`
for details.

These options can also be set in your .coveragerc file. See
:ref:`Configuration: [html] <config_html>`.
