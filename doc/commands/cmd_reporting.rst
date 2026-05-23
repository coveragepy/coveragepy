.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. This file is processed with cog to insert the latest command help into the
    docs. If it's out of date, the quality checks will fail.  Running "make
    prebuild" will bring it up to date.

.. [[[cog
    from cog_helpers import show_help
.. ]]]
.. [[[end]]] (sum: 1B2M2Y8Asg)


.. _cmd_reporting:

Reporting
---------

Coverage.py provides a few styles of reporting, with the
:ref:`report <cmd_report>`,
:ref:`html <cmd_html>`,
:ref:`json <cmd_json>`,
:ref:`lcov <cmd_lcov>`,
:ref:`xml <cmd_xml>`,
and :ref:`annotate <cmd_annotate>`
commands.  They share a number of common options.

The command-line arguments are module or file names to report on if you'd like
to report on a subset of the data collected.

If parallel data files are present, the are implicitly combined as if you had
used the :ref:`combine <cmd_combine>` command.

The ``--include`` and ``--omit`` flags specify lists of file name patterns.
They control which files to report on, and are described in more detail in
:ref:`source`.

The ``-i`` or ``--ignore-errors`` switch tells coverage.py to ignore problems
encountered trying to find source files to report on.  This can be useful if
some files are missing, or if your Python execution is tricky enough that file
names are synthesized without real source files.

If you provide a ``--fail-under`` value, the total percentage covered will be
compared to that value.  If it is less, the command will exit with a status
code of 2, indicating that the total coverage was less than your target.  This
can be used as part of a pass/fail condition, for example in a continuous
integration server.  This option isn't available for **annotate**.

These options can also be set in your .coveragerc file. See
:ref:`Configuration: [report] <config_report>`.
