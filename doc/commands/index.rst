.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. _cmd:

========
Commands
========

.. highlight:: console

When you install coverage.py, a command called ``coverage`` is installed for
command-line use.  It has a number of commands:

* **run** -- :ref:`Run a Python program and collect execution data <cmd_run>`.

* **combine** -- :ref:`Combine together a number of data files <cmd_combine>`.

* **erase** -- :ref:`Erase previously collected coverage data <cmd_erase>`.

* **report** -- :ref:`Report coverage results <cmd_report>`.

* **html** --
  :ref:`Produce annotated HTML listings with coverage results <cmd_html>`.

* **xml** -- :ref:`Produce an XML report with coverage results <cmd_xml>`.

* **json** -- :ref:`Produce a JSON report with coverage results <cmd_json>`.

* **lcov** -- :ref:`Produce an LCOV report with coverage results <cmd_lcov>`.

* **annotate** --
  :ref:`Annotate source files with coverage results <cmd_annotate>`.

* **debug** -- :ref:`Get diagnostic information <cmd_debug>`.


Global options
--------------

Help is available with the **help** command, or with the ``--help`` switch on
any other command::

    $ coverage help
    $ coverage help run
    $ coverage run --help

Version information for coverage.py can be displayed with
``coverage --version``:

.. parsed-literal::

    $ coverage --version
    Coverage.py, version |release| with C extension
    Documentation at |doc-url|

Any command can use a configuration file by specifying it with the
``--rcfile=FILE`` command-line switch.  Any option you can set on the command
line can also be set in the configuration file.  This can be a better way to
control coverage.py since the configuration file can be checked into source
control, and can provide options that other invocation techniques (like test
runner plugins) may not offer. See :ref:`config` for more details.

For diagnosing problems, commands accept a ``--debug`` option. See
:ref:`cmd_run_debug`.


Commands
--------

The details of each command are on these pages:

.. toctree::
    :maxdepth: 1

    cmd_run
    cmd_combine
    cmd_erase
    cmd_reporting
    cmd_report
    cmd_html
    cmd_xml
    cmd_json
    cmd_lcov
    cmd_annotate
    cmd_debug
