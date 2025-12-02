.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to create the tabbed multi-syntax
   configuration examples.  If those are wrong, the quality checks will fail.
   Running "make prebuild" checks them and produces the output.

.. [[[cog
    from cog_helpers import show_configs
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _source:

=======================
Specifying source files
=======================

When coverage.py is running your program and measuring its execution, it needs
to know what code to measure and what code not to.  Measurement imposes a speed
penalty, and the collected data must be stored in memory and then on disk.
More importantly, when reviewing your coverage reports, you don't want to be
distracted with modules that aren't your concern.

Coverage.py has a number of ways you can focus it in on the code you care
about.


.. _source_execution:

Execution
---------

When running your code, the ``coverage run`` command will by default measure
all code, unless it is part of the Python standard library.

You can specify source to measure with the ``--source`` command-line switch, or
the ``[run] source`` configuration value.  The value is a comma- or
newline-separated list of directories or importable names (packages or
modules).

If the source option is specified, only code in those locations will be
measured.  Specifying the source option also enables coverage.py to report on
un-executed files, since it can search the source tree for files that haven't
been measured at all.  Only importable files (ones at the root of the tree, or
in directories with a ``__init__.py`` file) will be considered. Files with
unusual punctuation in their names will be skipped (they are assumed to be
scratch files written by text editors). Files that do not end with ``.py``,
``.pyw``, ``.pyo``, or ``.pyc`` will also be skipped.

.. note::

    Modules named as sources may be imported twice, once by coverage.py to find
    their location, then again by your own code or test suite.  Usually this
    isn't a problem, but could cause trouble if a module has side-effects at
    import time.

    Exceptions during the early import are suppressed and ignored.

You can further fine-tune coverage.py's attention with the ``--include`` and
``--omit`` switches (or ``[run] include`` and ``[run] omit`` configuration
values). ``--include`` is a list of file name patterns. If specified, only
files matching those patterns will be measured. ``--omit`` is also a list of
file name patterns, specifying files not to measure.  If both ``include`` and
``omit`` are specified, first the set of files is reduced to only those that
match the include patterns, then any files that match the omit pattern are
removed from the set.

.. highlight:: ini

The ``include`` and ``omit`` file name patterns follow common shell syntax,
described below in :ref:`source_glob`.  Patterns that start with a wildcard
character are used as-is, other patterns are interpreted relative to the
current directory:

.. [[[cog
    show_configs(
        ini=r"""
            [run]
            omit =
                # omit anything in a .local directory anywhere
                */.local/*
                # omit everything in /usr
                /usr/*
                # omit this single file
                utils/tirefire.py
            """,
        toml=r"""
            [tool.coverage.run]
            omit = [
                # omit anything in a .local directory anywhere
                "*/.local/*",
                # omit everything in /usr
                "/usr/*",
                # omit this single file
                "utils/tirefire.py",
                ]
            """,
        )
.. ]]]

.. tabs::

    .. code-tab:: toml
        :caption: pyproject.toml

        [tool.coverage.run]
        omit = [
            # omit anything in a .local directory anywhere
            "*/.local/*",
            # omit everything in /usr
            "/usr/*",
            # omit this single file
            "utils/tirefire.py",
            ]

    .. code-tab:: ini
        :caption: .coveragerc

        [run]
        omit =
            # omit anything in a .local directory anywhere
            */.local/*
            # omit everything in /usr
            /usr/*
            # omit this single file
            utils/tirefire.py

    .. code-tab:: toml
        :caption: .coveragerc.toml

        # You can also use sections like [tool.coverage.run]
        [run]
        omit = [
            # omit anything in a .local directory anywhere
            "*/.local/*",
            # omit everything in /usr
            "/usr/*",
            # omit this single file
            "utils/tirefire.py",
            ]

    .. code-tab:: ini
        :caption: setup.cfg or tox.ini

        [coverage:run]
        omit =
            # omit anything in a .local directory anywhere
            */.local/*
            # omit everything in /usr
            /usr/*
            # omit this single file
            utils/tirefire.py

.. [[[end]]] (sum: r3vqCJZ28r)

The ``source``, ``include``, and ``omit`` values all work together to determine
the source that will be measured.

If both ``source`` and ``include`` are set, the ``include`` value is ignored
and a warning is issued.


.. _source_reporting:

Reporting
---------

Once your program is measured, you can specify the source files you want
reported.  Usually you want to see all the code that was measured, but if you
are measuring a large project, you may want to get reports for just certain
parts.

The report commands (``report``, ``html``, ``json``, ``lcov``, ``annotate``,
and ``xml``)
all take optional ``modules`` arguments, and ``--include`` and ``--omit``
switches. The ``modules`` arguments specify particular modules to report on.
The ``include`` and ``omit`` values are lists of file name patterns, just as
with the ``run`` command.

Remember that the reporting commands can only report on the data that has been
collected, so the data you're looking for may not be in the data available for
reporting.

Note that these are ways of specifying files to measure.  You can also exclude
individual source lines.  See :ref:`excluding` for details.


.. _source_glob:

File patterns
-------------

File path patterns are used for :ref:`include <config_run_include>` and
:ref:`omit <config_run_omit>`, and for :ref:`combining path remapping
<cmd_combine_remapping>`.  They follow common shell syntax:

- ``?`` matches a single file name character.

- ``*`` matches any number of file name characters, not including the directory
  separator.  As a special case, if a pattern starts with ``*/``, it is treated
  as ``**/``, and if a pattern ends with ``/*``, it is treated as ``/**``.

- ``**`` matches any number of nested directory names, including none. It must
  be used as a full component of the path, not as part of a word: ``/**/`` is
  allowed, but ``/a**/`` is not.

- Both ``/`` and ``\`` will match either a slash or a backslash, to make
  cross-platform matching easier.

- A pattern with no directory separators matches the file name in any
  directory.

Some examples:

.. list-table::
    :widths: 20 20 20
    :header-rows: 1

    * - Pattern
      - Matches
      - Doesn't Match
    * - ``a*.py``
      - | anything.py
        | sub1/sub2/another.py
      - | cat.py
    * - ``sub/*/*.py``
      - | sub/a/main.py
        | sub/b/another.py
      - | sub/foo.py
        | sub/m1/m2/foo.py
    * - ``sub/**/*.py``
      - | sub/something.py
        | sub/a/main.py
        | sub/b/another.py
        | sub/m1/m2/foo.py
      - | sub1/anything.py
        | sub1/more/code/main.py
    * - ``*/sub/*``
      - | some/where/sub/more/something.py
        | sub/hello.py
      - | sub1/anything.py
    * - ``*/sub*/*``
      - | some/where/sub/more/something.py
        | sub/hello.py
        | sub1/anything.py
      - | some/more/something.py
    * - ``*/*sub/test_*.py``
      - | some/where/sub/test_everything.py
        | moresub/test_things.py
      - | some/where/sub/more/test_everything.py
        | more/test_things.py
    * - ``*/*sub/*sub/**``
      - | sub/sub/something.py
        | asub/bsub/more/thing.py
        | code/sub/sub/code.py
      - | sub/something.py
