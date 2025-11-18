.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

==============================
Change history for coverage.py
==============================

These changes are listed in decreasing version number order. Note this can be
different from a strict chronological order when there are two branches in
development at the same time, such as 4.5.x and 5.0.

See :ref:`migrating` for significant changes that might be required when
upgrading your version of coverage.py.

    .. When updating the "Unreleased" header to a specific version, use this
    .. format.  Don't forget the jump target:
    ..
    ..  .. _changes_9-8-1:
    ..
    ..  Version 9.8.1 — 2027-07-27
    ..  --------------------------

Unreleased
----------

- The HTML report now shows separate coverage totals for statements and
  branches, as well as the usual combined coverage percentage. Thanks to Ryuta
  Otsuka for the `discussion <issue 2081_>`_ and the `implementation
  <pull 2085_>`_.

- The JSON report now include separate coverage totals for statements and
  branches, thanks to `Ryuta Otsuka <pull 2090_>`_.

- Fix: ``except*`` clauses were not handled properly under the "sysmon"
  measurement core, causing KeyError exceptions as described in `issue 2086`_.
  This is now fixed.

- Fix: we now defend against aggressive mocking of ``open()`` that could cause
  errors inside coverage.py.  An example of a failure is in `issue 2083`_.

- A small tweak to the HTML report: file paths now use thin spaces around
  slashes to make them easier to read.

- Fix: in unusual cases where a test suite intentionally exhausts the system's
  file descriptors to test handling errors in ``open()``, coverage.py would
  fail when trying to open source files, as described in `issue 2091`_.  This
  is now fixed.

.. _issue 2081: https://github.com/coveragepy/coveragepy/issues/2081
.. _issue 2083: https://github.com/coveragepy/coveragepy/issues/2083
.. _pull 2085: https://github.com/coveragepy/coveragepy/pull/2085
.. _issue 2086: https://github.com/coveragepy/coveragepy/issues/2086
.. _pull 2090: https://github.com/coveragepy/coveragepy/pull/2090
.. _issue 2091: https://github.com/coveragepy/coveragepy/issues/2091


.. start-releases

.. _changes_7-11-3:

Version 7.11.3 — 2025-11-09
---------------------------

- Fix: the 7.11.1 changes meant that conflicts between a requested measurement
  core and other settings would raise an error. This was a breaking change from
  previous behavior, as reported in `issue 2076`_ and `issue 2078`_.

  The previous behavior has been restored: when the requested core conflicts
  with other settings, another core is used instead, and a warning is issued.

- For contributors: the repo has moved from Ned's `nedbat GitHub account`_ to
  the `coveragepy GitHub organization`_. The default branch has changed from
  master to main.

.. _issue 2076: https://github.com/coveragepy/coveragepy/issues/2076
.. _issue 2078: https://github.com/coveragepy/coveragepy/issues/2078
.. _nedbat GitHub account: https://github.com/nedbat
.. _coveragepy GitHub organization: https://github.com/coveragepy


.. _changes_7-11-2:

Version 7.11.2 — 2025-11-08
---------------------------

- Fix: using the "sysmon" measurement core in 7.11.1, if Python code was
  claimed to come from a non-Python file, a ``NotPython`` exception could be
  raised. This could happen for example with Jinja templates compiled to
  Python, as reported in `issue 2077`_. This is now fixed.

- Doc: corrected the first entry in the 7.11.1 changelog.

.. _issue 2077: https://github.com/coveragepy/coveragepy/issues/2077


.. _changes_7-11-1:

Version 7.11.1 — 2025-11-07
---------------------------

- Fix: some chanages to details of how the measurement core is chosen, and how
  conflicting settings are handled. The "sysmon" core cannot be used with some
  conurrency settings, with dynamic context, and in Python 3.12/3.13, with
  branch measurement.

  - If the core is not specified and defaults to "sysmon" (Python 3.14+), but
    other settings conflict with sysmon, then the "ctrace" core will be used
    instead with no warning. For concurrency conflicts, this used to produce an
    error, as described in `issue 2064`_.

  - If the "sysmon" core is explicitly requested in your configuration, but
    other settings conflict, an error is now raised. This used to produce a
    warning.

- Fix: some multi-line case clauses or for loops (and probably other
  constructs) could cause incorrect claims of missing branches with the
  sys.monitoring core, as described in `issue 2070`_. This is now fixed.

- Fix: when running in pytest under coverage, a ``breakpoint()`` would stop in
  the wrong frame, one level down from where it should, as described in `issue
  1420`_. This was due to a coverage change in v6.4.1 that seemed to give a
  slight performance improvement, but I couldn't reproduce the performance
  gain, so it's been reverted, fixing the debugger problem.

- A new debug option ``--debug=core`` shows which core is in use and why.

- Split ``sqlite`` debugging information out of the ``sys`` :ref:`coverage
  debug <cmd_debug>` and :ref:`cmd_run_debug` options since it's bulky and not
  very useful.

- Updated the :ref:`howitworks` page to better describe the three different
  measurement cores.

.. _issue 1420: https://github.com/coveragepy/coveragepy/issues/1420
.. _issue 2064: https://github.com/coveragepy/coveragepy/issues/2064
.. _issue 2070: https://github.com/coveragepy/coveragepy/issues/2070


.. _changes_7-11-0:

Version 7.11.0 — 2025-10-15
---------------------------

- Dropped support for Python 3.9, declared support for Python 3.15 alpha.


.. _changes_7-10-7:

Version 7.10.7 — 2025-09-21
---------------------------

- Performance: with branch coverage in large files, generating HTML, JSON, or
  LCOV reports could take far too long due to some quadratic behavior when
  creating the function and class index pages.  This is now fixed, closing
  `issue 2048`_.  Thanks to Daniel Diniz for help diagnosing the problem.

- Most warnings and a few errors now have links to a page in the docs
  explaining the specific message.  Closes `issue 1921`_.

.. _issue 1921: https://github.com/coveragepy/coveragepy/issues/1921
.. _issue 2048: https://github.com/coveragepy/coveragepy/issues/2048


.. _changes_7-10-6:

Version 7.10.6 — 2025-08-29
---------------------------

- Fix: ``source`` directories were not properly communicated to subprocesses
  that ran in different directories, as reported in `issue 1499`_.  This is now
  fixed.

- Performance: `Alex Gaynor continues fine-tuning <pull 2038_>`_ the speed of
  combination, especially with many contexts.

.. _issue 1499: https://github.com/coveragepy/coveragepy/issues/1499
.. _pull 2038: https://github.com/coveragepy/coveragepy/pull/2038


.. _changes_7-10-5:

Version 7.10.5 — 2025-08-23
---------------------------

- Big speed improvements for ``coverage combine``: it's now about twice as
  fast! Huge thanks to Alex Gaynor for pull requests `2032 <pull 2032_>`_,
  `2033 <pull 2033_>`_, and `2034 <pull 2034_>`_.

.. _pull 2032: https://github.com/coveragepy/coveragepy/pull/2032
.. _pull 2033: https://github.com/coveragepy/coveragepy/pull/2033
.. _pull 2034: https://github.com/coveragepy/coveragepy/pull/2034


.. _changes_7-10-4:

Version 7.10.4 — 2025-08-16
---------------------------

- Added ``patch = fork`` for times when the built-in forking support is
  insufficient.

- Fix: ``patch = execv`` also inherits the entire coverage configuration now.


.. _changes_7-10-3:

Version 7.10.3 — 2025-08-10
---------------------------

- Fixes for ``patch = subprocess``:

  - If subprocesses spawned yet more subprocesses simultaneously, some coverage
    could be missed.  This is now fixed, closing `issue 2024`_.

  - If subprocesses were created in other directories, their data files were
    stranded there and not combined into the totals, as described in `issue
    2025`_.  This is now fixed.

  - On Windows (or maybe only some Windows?) the patch would fail with a
    ``ModuleNotFound`` error trying to import coverage.  This is now fixed,
    closing `issue 2022`_.

  - Originally only options set in the coverage configuration file would apply
    to subprocesses.  Options set on the ``coverage run`` command line (such as
    ``--branch``) wouldn't be communicated to the subprocesses.  This could
    lead to combining failures, as described in `issue 2021`_. Now the entire
    configuration is used in subprocesses, regardless of its origin.

  - Added ``debug=patch`` to help diagnose problems.

- Fix: really close all SQLite databases, even in-memory ones. Closes `issue
  2017`_.

.. _issue 2017: https://github.com/coveragepy/coveragepy/issues/2017
.. _issue 2021: https://github.com/coveragepy/coveragepy/issues/2021
.. _issue 2022: https://github.com/coveragepy/coveragepy/issues/2022
.. _issue 2024: https://github.com/coveragepy/coveragepy/issues/2024
.. _issue 2025: https://github.com/coveragepy/coveragepy/issues/2025


.. _changes_7-10-2:

Version 7.10.2 — 2025-08-03
---------------------------

- Fix: some code with NOP bytecodes could report missing branches that are
  actually executed. This is now fixed, closing `issue 1999`_. Python 3.9
  still shows the problem.

.. _issue 1999: https://github.com/coveragepy/coveragepy/issues/1999


.. _changes_7-10-1:

Version 7.10.1 — 2025-07-27
---------------------------

- Fix: the exclusion for ``if TYPE_CHECKING:`` was wrong: it marked the branch
  as partial, but it should have been a line exclusion so the entire clause
  would be excluded. Improves `issue 831`_.

- Fix: changed where .pth files are written for ``patch = subprocess``, closing
  `issue 2006`_.

.. _issue 2006: https://github.com/coveragepy/coveragepy/issues/2006


.. _changes_7-10-0:

Version 7.10.0 — 2025-07-24
---------------------------

- A new configuration option: ":ref:`config_run_patch`" specifies named patches
  to work around some limitations in coverage measurement.  These patches are
  available:

  - ``patch = _exit`` lets coverage save its data even when :func:`os._exit()
    <python:os._exit>` is used to abruptly end the process.  This closes
    long-standing `issue 310`_ as well as its duplicates: `issue 312`_, `issue
    1673`_, `issue 1845`_, and `issue 1941`_.

  - ``patch = subprocess`` measures coverage in Python subprocesses created
    with :mod:`subprocess`, :func:`os.system`, or one of the :func:`execv
    <python:os.execl>` or :func:`spawnv <python:os.spawnl>` family of
    functions. Closes old `issue 367`_, its duplicate `issue 378`_ and old
    `issue 689`_.

  - ``patch = execv`` adjusts the :func:`execv <python:os.execl>` family of
    functions to save coverage data before ending the current program and
    starting the next. Not available on Windows. Closes `issue 43`_ after 15
    years!

- The HTML report now dimly colors subsequent lines in multi-line statements.
  They used to have no color.  This gives a better indication of the amount of
  code missing in the report.  Closes `issue 1308`_.

- Two new exclusion patterns are part of the defaults: ``...`` is automatically
  excluded as a line and ``if TYPE_CHECKING:`` is excluded as a branch.  Closes
  `issue 831`_.

- A new command-line option: ``--save-signal=USR1`` specifies a signal that
  coverage.py will listen for.  When the signal is sent, the coverage data will
  be saved.  This makes it possible to save data from within long-running
  processes.  Thanks, `Arkady Gilinsky <pull 1998_>`_.

- A new configuration option: ":ref:`config_report_partial_also`" is a list of
  regexes to add as pragmas for partial branches.  This parallels the
  ":ref:`config_report_exclude_also`" setting for adding line exclusion
  patterns.

- A few file path configuration settings didn't allow for tilde expansion:
  :ref:`config_json_output`, :ref:`config_lcov_output` and
  :ref:`config_run_debug_file`.  This is now fixed.

- Wheels are included for 3.14 now that 3.14 rc1 is available.

- We no longer ship a PyPy-specific wheel. PyPy will install the pure-Python
  wheel.  Closes `issue 2001`_.

- In the very unusual situation of not having a current frame, coverage no
  longer crashes when using the sysmon core, fixing `issue 2005`_.

.. _issue 43: https://github.com/coveragepy/coveragepy/issues/43
.. _issue 310: https://github.com/coveragepy/coveragepy/issues/310
.. _issue 312: https://github.com/coveragepy/coveragepy/issues/312
.. _issue 367: https://github.com/coveragepy/coveragepy/issues/367
.. _issue 378: https://github.com/coveragepy/coveragepy/issues/378
.. _issue 689: https://github.com/coveragepy/coveragepy/issues/689
.. _issue 831: https://github.com/coveragepy/coveragepy/issues/831
.. _issue 1308: https://github.com/coveragepy/coveragepy/issues/1308
.. _issue 1673: https://github.com/coveragepy/coveragepy/issues/1673
.. _issue 1845: https://github.com/coveragepy/coveragepy/issues/1845
.. _issue 1941: https://github.com/coveragepy/coveragepy/issues/1941
.. _pull 1998: https://github.com/coveragepy/coveragepy/pull/1998
.. _issue 2001: https://github.com/coveragepy/coveragepy/issues/2001
.. _issue 2005: https://github.com/coveragepy/coveragepy/issues/2005

.. _changes_7-9-2:

Version 7.9.2 — 2025-07-03
--------------------------

- Fix: complex conditionals within a line might cause a KeyError when using
  sys.monitoring, as reported in `issue 1991`_.  This is now fixed.

- Fix: we can now measure coverage for code in Python archive (.par) files.
  Thanks, `Itamer Oren <pull 1984_>`_.

.. _pull 1984: https://github.com/coveragepy/coveragepy/pull/1984
.. _issue 1991: https://github.com/coveragepy/coveragepy/issues/1991


.. _changes_7-9-1:

Version 7.9.1 — 2025-06-13
--------------------------

- The "no-ctracer" warning is not issued for Python pre-release versions.
  Coverage doesn't ship compiled wheels for those versions, so this was far too
  noisy.

- On Python 3.14+, the "sysmon" core is now the default if it's supported for
  your configuration.  Plugins and dynamic contexts are still not supported
  with it.


.. _changes_7-9-0:

Version 7.9.0 — 2025-06-11
--------------------------

- Added a ``[run] core`` configuration setting to specify the measurement core,
  which was previously only available through the COVERAGE_CORE environment
  variable. Finishes `issue 1746`_.

- Fixed incorrect rendering of f-strings with doubled braces, closing `issue
  1980`_.

- If the C tracer core can't be imported, a warning ("no-ctracer") is issued
  with the reason.

- The C tracer core extension module now conforms to `PEP 489`_, closing `issue
  1977`_.  Thanks, `Adam Turner <pull 1978_>`_.

- Fixed a "ValueError: min() arg is an empty sequence" error caused by strange
  empty modules, found by `oss-fuzz`_.

.. _issue 1746: https://github.com/coveragepy/coveragepy/issues/1746
.. _issue 1977: https://github.com/coveragepy/coveragepy/issues/1977
.. _pull 1978: https://github.com/coveragepy/coveragepy/pull/1978
.. _issue 1980: https://github.com/coveragepy/coveragepy/issues/1980
.. _PEP 489: https://peps.python.org/pep-0489
.. _oss-fuzz: https://google.github.io/oss-fuzz/


.. _changes_7-8-2:

Version 7.8.2 — 2025-05-23
--------------------------

- Wheels are provided for Windows ARM64 on Python 3.11, 3.12, and 3.13.
  Thanks, `Finn Womack <pull 1972_>`_.

.. _issue 1971: https://github.com/coveragepy/coveragepy/pull/1971
.. _pull 1972: https://github.com/coveragepy/coveragepy/pull/1972

.. _changes_7-8-1:

Version 7.8.1 — 2025-05-21
--------------------------

- A number of EncodingWarnings were fixed that could appear if you've enabled
  PYTHONWARNDEFAULTENCODING, fixing `issue 1966`_.  Thanks, `Henry Schreiner
  <pull 1967_>`_.

- Fixed a race condition when using sys.monitoring with free-threading Python,
  closing `issue 1970`_.

.. _issue 1966: https://github.com/coveragepy/coveragepy/issues/1966
.. _pull 1967: https://github.com/coveragepy/coveragepy/pull/1967
.. _issue 1970: https://github.com/coveragepy/coveragepy/issues/1970

.. _changes_7-8-0:

Version 7.8.0 — 2025-03-30
--------------------------

- Added a new ``source_dirs`` setting for symmetry with the existing
  ``source_pkgs`` setting. It's preferable to the existing ``source`` setting,
  because you'll get a clear error when directories don't exist. Fixes `issue
  1942`_.  Thanks, `Jeremy Fleischman <pull 1943_>`_.

- Fix: the PYTHONSAFEPATH environment variable new in Python 3.11 is properly
  supported, closing `issue 1696`_.  Thanks, `Philipp A. <pull 1700_>`_.  This
  works properly except for a detail when using the ``coverage`` command on
  Windows.  There you can use ``python -m coverage`` instead if you need exact
  emulation.

.. _issue 1696: https://github.com/coveragepy/coveragepy/issues/1696
.. _pull 1700: https://github.com/coveragepy/coveragepy/pull/1700
.. _issue 1942: https://github.com/coveragepy/coveragepy/issues/1942
.. _pull 1943: https://github.com/coveragepy/coveragepy/pull/1943

.. _changes_7-7-1:

Version 7.7.1 — 2025-03-21
--------------------------

- A few small tweaks to the sys.monitoring support for Python 3.14.  Please
  test!


.. _changes_7-7-0:

Version 7.7.0 — 2025-03-16
--------------------------

- The Coverage object has a new method, :meth:`.Coverage.branch_stats` for
  getting simple branch information for a module.  Closes `issue 1888`_.

- The :class:`Coverage constructor<.Coverage>` now has a ``plugins`` parameter
  for passing in plugin objects directly, thanks to `Alex Gaynor <pull
  1919_>`_.

- Many constant tests in if statements are now recognized as being optimized
  away.  For example, previously ``if 13:`` would have been considered a branch
  with one path not taken.  Now it is understood as always true and no coverage
  is missing.

- The experimental sys.monitoring support now works for branch coverage if you
  are using Python 3.14.0 alpha 6 or newer.  This should reduce the overhead
  coverage.py imposes on your test suite. Set the environment variable
  ``COVERAGE_CORE=sysmon`` to try it out.

- Confirmed support for PyPy 3.11. Thanks Michał Górny.

.. _issue 1888: https://github.com/coveragepy/coveragepy/issues/1888
.. _pull 1919: https://github.com/coveragepy/coveragepy/pull/1919


.. _changes_7-6-12:

Version 7.6.12 — 2025-02-11
---------------------------

- Fix: some aarch64 distributions were missing (`issue 1927`_).  These are now
  building reliably.

.. _issue 1927: https://github.com/coveragepy/coveragepy/issues/1927

.. _changes_7-6-11:

Version 7.6.11 — 2025-02-08
---------------------------

- Fix: a memory leak in CTracer has been fixed.  The details are in `issue
  1924`_ and `pytest-dev 676`_.  This should reduce the memory footprint for
  everyone even if it hadn't caused a problem before.

- We now ship a py3-none-any.whl wheel file.  Thanks, `Russell Keith-Magee
  <pull 1914_>`_.

.. _pull 1914: https://github.com/coveragepy/coveragepy/pull/1914
.. _issue 1924: https://github.com/coveragepy/coveragepy/issues/1924
.. _pytest-dev 676: https://github.com/pytest-dev/pytest-cov/issues/676

.. _changes_7-6-10:

Version 7.6.10 — 2024-12-26
---------------------------

- Fix: some descriptions of missing branches in HTML and LCOV reports were
  incorrect when multi-line statements were involved (`issue 1874`_ and `issue
  1875`_).  These are now fixed.

- Fix: Python 3.14 `defers evaluation of annotations <pep649_>`_ by moving them
  into separate code objects.  That code is rarely executed, so coverage.py
  would mark them as missing, as reported in `issue 1908`_.  Now they are
  ignored by coverage automatically.

- Fixed an obscure and mysterious problem on PyPy 3.10 seemingly involving
  mocks, imports, and trace functions: `issue 1902`_.  To be honest, I don't
  understand the problem or the solution, but ``git bisect`` helped find it,
  and now it's fixed.

- Docs: re-wrote the :ref:`subprocess` page to put multiprocessing first and to
  highlight the correct use of :class:`multiprocessing.Pool
  <python:multiprocessing.pool.Pool>`.

.. _issue 1874: https://github.com/coveragepy/coveragepy/issues/1874
.. _issue 1875: https://github.com/coveragepy/coveragepy/issues/1875
.. _issue 1902: https://github.com/coveragepy/coveragepy/issues/1902
.. _issue 1908: https://github.com/coveragepy/coveragepy/issues/1908
.. _pep649: https://docs.python.org/3.14/whatsnew/3.14.html#whatsnew314-deferred-annotations


.. _changes_7-6-9:

Version 7.6.9 — 2024-12-06
--------------------------

- Fix: `Tomas Uribe fixed <pull 1901_>`_ a performance problem in the XML
  report.  Large code bases should produce XML reports much faster now.

.. _pull 1901: https://github.com/coveragepy/coveragepy/pull/1901


.. _changes_7-6-8:

Version 7.6.8 — 2024-11-23
--------------------------

- Fix: the LCOV report code assumed that a branch line that took no branches
  meant that the entire line was unexecuted.  This isn't true in a few cases:
  the line might always raise an exception, or might have been optimized away.
  Fixes `issue 1896`_.

- Fix: similarly, the HTML report will now explain that a line that jumps to
  none of its expected destinations must have always raised an exception.
  Previously, it would say something nonsensical like, "line 4 didn't jump to
  line 5 because line 4 was never true, and it didn't jump to line 7 because
  line 4 was always true."  This was also shown in `issue 1896`_.

.. _issue 1896: https://github.com/coveragepy/coveragepy/issues/1896


.. _changes_7-6-7:

Version 7.6.7 — 2024-11-15
--------------------------

- Fix: ugh, the other assert from 7.6.5 can also be encountered in the wild,
  so it's been restored to a conditional.  Sorry for the churn.


.. _changes_7-6-6:

Version 7.6.6 — 2024-11-15
--------------------------

- One of the new asserts from 7.6.5 caused problems in real projects, as
  reported in `issue 1891`_.  The assert has been removed.

.. _issue 1891: https://github.com/coveragepy/coveragepy/issues/1891


.. _changes_7-6-5:

Version 7.6.5 — 2024-11-14
--------------------------

- Fix: fine-tuned the exact Python version (3.12.6) when exiting from ``with``
  statements changed how they traced.  This affected whether people saw the
  fix for `issue 1880`_.

- Fix: isolate our code more from mocking in the os module that in rare cases
  can cause `bizarre behavior <pytest-cov-666_>`_.

- Refactor: some code unreachable code paths in parser.py were changed to
  asserts.  If you encounter any of these, please let me know!

.. _pytest-cov-666: https://github.com/pytest-dev/pytest-cov/issues/666


.. _changes_7-6-4:

Version 7.6.4 — 2024-10-20
--------------------------

- Fix: multi-line ``with`` statements could cause contained branches to be
  incorrectly marked as missing (`issue 1880`_).  This is now fixed.

.. _issue 1880: https://github.com/coveragepy/coveragepy/issues/1880


.. _changes_7-6-3:

Version 7.6.3 — 2024-10-13
--------------------------

- Fix: nested context managers could incorrectly be analyzed to flag a missing
  branch on the last context manager, as described in `issue 1876`_.  This is
  now fixed.

- Fix: the missing branch message about not exiting a module had an extra
  "didn't," as described in `issue 1873`_.  This is now fixed.

.. _issue 1873: https://github.com/coveragepy/coveragepy/issues/1873
.. _issue 1876: https://github.com/coveragepy/coveragepy/issues/1876


.. _changes_7-6-2:

Version 7.6.2 — 2024-10-09
--------------------------

- Dropped support for Python 3.8 and PyPy 3.8.

- Fix: a final wildcard match/case clause assigning to a name (``case _ as
  value``) was incorrectly marked as a missing branch.  This is now fixed,
  closing `issue 1860`_.

- Fewer things are considered branches now. Lambdas, comprehensions, and
  generator expressions are no longer marked as missing branches if they don't
  complete execution.  Closes `issue 1852`_.

- Fix: the HTML report didn't properly show multi-line f-strings that end with
  a backslash continuation.  This is now fixed, closing `issue 1836`_, thanks
  to `LiuYinCarl and Marco Ricci <pull 1838_>`_.

- Fix: the LCOV report now has correct line numbers (fixing `issue 1846`_) and
  better branch descriptions for BRDA records (fixing `issue 1850`_).  There
  are other changes to lcov also, including a new configuration option
  :ref:`line_checksums <config_lcov_line_checksums>` to control whether line
  checksums are included in the lcov report.  The default is false. To keep
  checksums set it to true.  All this work is thanks to Zack Weinberg
  (`pull 1849`_ and `pull 1851`_).

- Fixed the docs for multi-line regex exclusions, closing `issue 1863`_.

- Fixed a potential crash in the C tracer, closing `issue 1835`_, thanks to
  `Jan Kühle <pull 1843_>`_.

.. _issue 1835: https://github.com/coveragepy/coveragepy/issues/1835
.. _issue 1836: https://github.com/coveragepy/coveragepy/issues/1836
.. _pull 1838: https://github.com/coveragepy/coveragepy/pull/1838
.. _pull 1843: https://github.com/coveragepy/coveragepy/pull/1843
.. _issue 1846: https://github.com/coveragepy/coveragepy/issues/1846
.. _pull 1849: https://github.com/coveragepy/coveragepy/pull/1849
.. _issue 1850: https://github.com/coveragepy/coveragepy/issues/1850
.. _pull 1851: https://github.com/coveragepy/coveragepy/pull/1851
.. _issue 1852: https://github.com/coveragepy/coveragepy/issues/1852
.. _issue 1860: https://github.com/coveragepy/coveragepy/issues/1860
.. _issue 1863: https://github.com/coveragepy/coveragepy/issues/1863


.. _changes_7-6-1:

Version 7.6.1 — 2024-08-04
--------------------------

- Fix: coverage used to fail when measuring code using :func:`runpy.run_path
  <python:runpy.run_path>` with a :class:`Path <python:pathlib.Path>` argument.
  This is now fixed, thanks to `Ask Hjorth Larsen <pull 1819_>`_.

- Fix: backslashes preceding a multi-line backslashed string could confuse the
  HTML report.  This is now fixed, thanks to `LiuYinCarl <pull 1828_>`_.

- Now we publish wheels for Python 3.13, both regular and free-threaded.

.. _pull 1819: https://github.com/coveragepy/coveragepy/pull/1819
.. _pull 1828: https://github.com/coveragepy/coveragepy/pull/1828


.. _changes_7-6-0:

Version 7.6.0 — 2024-07-11
--------------------------

- Exclusion patterns can now be multi-line, thanks to `Daniel Diniz <pull
  1807_>`_.  This enables many interesting exclusion use-cases, including those
  requested in issues `118 <issue 118_>`_ (entire files), `996
  <issue 996_>`_ (multiple lines only when appearing together), `1741
  <issue 1741_>`_ (remainder of a function), and `1803 <issue 1803_>`_
  (arbitrary sequence of marked lines).  See the :ref:`multi_line_exclude`
  section of the docs for more details and examples.

- The JSON report now includes per-function and per-class coverage information.
  Thanks to `Daniel Diniz <pull 1809_>`_ for getting the work started. This
  closes `issue 1793`_ and `issue 1532`_.

- Fixed an incorrect calculation of "(no class)" lines in the HTML classes
  report.

- Python 3.13.0b3 is supported.

.. _issue 118: https://github.com/coveragepy/coveragepy/issues/118
.. _issue 996: https://github.com/coveragepy/coveragepy/issues/996
.. _issue 1532: https://github.com/coveragepy/coveragepy/issues/1532
.. _issue 1741: https://github.com/coveragepy/coveragepy/issues/1741
.. _issue 1793: https://github.com/coveragepy/coveragepy/issues/1793
.. _issue 1803: https://github.com/coveragepy/coveragepy/issues/1803
.. _pull 1807: https://github.com/coveragepy/coveragepy/pull/1807
.. _pull 1809: https://github.com/coveragepy/coveragepy/pull/1809

.. _changes_7-5-4:

Version 7.5.4 — 2024-06-22
--------------------------

- If you attempt to combine statement coverage data with branch coverage data,
  coverage.py used to fail with the message "Can't combine arc data with line
  data" or its reverse, "Can't combine line data with arc data."  These
  messages used internal terminology, making it hard for people to understand
  the problem.  They are now changed to mention "branch coverage data" and
  "statement coverage data."

- Fixed a minor branch coverage problem with wildcard match/case cases using
  names or guard clauses.

- Started testing on 3.13 free-threading (nogil) builds of Python.  I'm not
  claiming full support yet.  Closes `issue 1799`_.

.. _issue 1799: https://github.com/coveragepy/coveragepy/issues/1799


.. _changes_7-5-3:

Version 7.5.3 — 2024-05-28
--------------------------

- Performance improvements for combining data files, especially when measuring
  line coverage. A few different quadratic behaviors were eliminated. In one
  extreme case of combining 700+ data files, the time dropped from more than
  three hours to seven minutes.  Thanks for Kraken Tech for funding the fix.

- Performance improvements for generating HTML reports, with a side benefit of
  reducing memory use, closing `issue 1791`_.  Thanks to Daniel Diniz for
  helping to diagnose the problem.

.. _issue 1791: https://github.com/coveragepy/coveragepy/issues/1791


.. _changes_7-5-2:

Version 7.5.2 — 2024-05-24
--------------------------

- Fix: nested matches of exclude patterns could exclude too much code, as
  reported in `issue 1779`_.  This is now fixed.

- Changed: previously, coverage.py would consider a module docstring to be an
  executable statement if it appeared after line 1 in the file, but not
  executable if it was the first line.  Now module docstrings are never counted
  as executable statements.  This can change coverage.py's count of the number
  of statements in a file, which can slightly change the coverage percentage
  reported.

- In the HTML report, the filter term and "hide covered" checkbox settings are
  remembered between viewings, thanks to `Daniel Diniz <pull 1776_>`_.

- Python 3.13.0b1 is supported.

- Fix: parsing error handling is improved to ensure bizarre source files are
  handled gracefully, and to unblock oss-fuzz fuzzing, thanks to `Liam DeVoe
  <pull 1788_>`_. Closes `issue 1787`_.

.. _pull 1776: https://github.com/coveragepy/coveragepy/pull/1776
.. _issue 1779: https://github.com/coveragepy/coveragepy/issues/1779
.. _issue 1787: https://github.com/coveragepy/coveragepy/issues/1787
.. _pull 1788: https://github.com/coveragepy/coveragepy/pull/1788


.. _changes_7-5-1:

Version 7.5.1 — 2024-05-04
--------------------------

- Fix: a pragma comment on the continuation lines of a multi-line statement
  now excludes the statement and its body, the same as if the pragma is
  on the first line. This closes `issue 754`_. The fix was contributed by
  `Daniel Diniz <pull 1773_>`_.

- Fix: very complex source files like `this one <resolvent_lookup_>`_ could
  cause a maximum recursion error when creating an HTML report.  This is now
  fixed, closing `issue 1774`_.

- HTML report improvements:

  - Support files (JavaScript and CSS) referenced by the HTML report now have
    hashes added to their names to ensure updated files are used instead of
    stale cached copies.

  - Missing branch coverage explanations that said "the condition was never
    false" now read "the condition was always true" because it's easier to
    understand.

  - Column sort order is remembered better as you move between the index pages,
    fixing `issue 1766`_.  Thanks, `Daniel Diniz <pull 1768_>`_.


.. _resolvent_lookup: https://github.com/sympy/sympy/blob/130950f3e6b3f97fcc17f4599ac08f70fdd2e9d4/sympy/polys/numberfields/resolvent_lookup.py
.. _issue 754: https://github.com/coveragepy/coveragepy/issues/754
.. _issue 1766: https://github.com/coveragepy/coveragepy/issues/1766
.. _pull 1768: https://github.com/coveragepy/coveragepy/pull/1768
.. _pull 1773: https://github.com/coveragepy/coveragepy/pull/1773
.. _issue 1774: https://github.com/coveragepy/coveragepy/issues/1774


.. _changes_7-5-0:

Version 7.5.0 — 2024-04-23
--------------------------

- Added initial support for function and class reporting in the HTML report.
  There are now three index pages which link to each other: files, functions,
  and classes.  Other reports don't yet have this information, but it will be
  added in the future where it makes sense.  Feedback gladly accepted!
  Finishes `issue 780`_.

- Other HTML report improvements:

  - There is now a "hide covered" checkbox to filter out 100% files, finishing
    `issue 1384`_.

  - The index page is always sorted by one of its columns, with clearer
    indications of the sorting.

  - The "previous file" shortcut key didn't work on the index page, but now it
    does, fixing `issue 1765`_.

- The debug output showing which configuration files were tried now shows
  absolute paths to help diagnose problems where settings aren't taking effect,
  and is renamed from "attempted_config_files" to the more logical
  "config_files_attempted."

- Python 3.13.0a6 is supported.

.. _issue 780: https://github.com/coveragepy/coveragepy/issues/780
.. _issue 1384: https://github.com/coveragepy/coveragepy/issues/1384
.. _issue 1765: https://github.com/coveragepy/coveragepy/issues/1765


.. _changes_7-4-4:

Version 7.4.4 — 2024-03-14
--------------------------

- Fix: in some cases, even with ``[run] relative_files=True``, a data file
  could be created with absolute path names.  When combined with other relative
  data files, it was random whether the absolute file names would be made
  relative or not. If they weren't, then a file would be listed twice in
  reports, as detailed in `issue 1752`_.  This is now fixed: absolute file
  names are always made relative when combining.  Thanks to Bruno Rodrigues dos
  Santos for support.

- Fix: the last case of a match/case statement had an incorrect message if the
  branch was missed.  It said the pattern never matched, when actually the
  branch is missed if the last case always matched.

- Fix: clicking a line number in the HTML report now positions more accurately.

- Fix: the ``report:format`` setting was defined as a boolean, but should be a
  string.  Thanks, `Tanaydin Sirin <pull 1754_>`_.  It is also now documented
  on the :ref:`configuration page <config_report_format>`.

.. _issue 1752: https://github.com/coveragepy/coveragepy/issues/1752
.. _pull 1754: https://github.com/coveragepy/coveragepy/pull/1754


.. _changes_7-4-3:

Version 7.4.3 — 2024-02-23
--------------------------

- Fix: in some cases, coverage could fail with a RuntimeError: "Set changed
  size during iteration." This is now fixed, closing `issue 1733`_.

.. _issue 1733: https://github.com/coveragepy/coveragepy/issues/1733


.. _changes_7-4-2:

Version 7.4.2 — 2024-02-20
--------------------------

- Fix: setting ``COVERAGE_CORE=sysmon`` no longer errors on 3.11 and lower,
  thanks `Hugo van Kemenade <pull 1747_>`_.  It now issues a warning that
  sys.monitoring is not available and falls back to the default core instead.

.. _pull 1747: https://github.com/coveragepy/coveragepy/pull/1747


.. _changes_7-4-1:

Version 7.4.1 — 2024-01-26
--------------------------

- Python 3.13.0a3 is supported.

- Fix: the JSON report now includes an explicit format version number, closing
  `issue 1732`_.

.. _issue 1732: https://github.com/coveragepy/coveragepy/issues/1732


.. _changes_7-4-0:

Version 7.4.0 — 2023-12-27
--------------------------

- In Python 3.12 and above, you can try an experimental core based on the new
  :mod:`sys.monitoring <python:sys.monitoring>` module by defining a
  ``COVERAGE_CORE=sysmon`` environment variable.  This should be faster for
  line coverage, but not for branch coverage, and plugins and dynamic contexts
  are not yet supported with it.  I am very interested to hear how it works (or
  doesn't!) for you.


.. _changes_7-3-4:

Version 7.3.4 — 2023-12-20
--------------------------

- Fix: the change for multi-line signature exclusions in 7.3.3 broke other
  forms of nested clauses being excluded properly.  This is now fixed, closing
  `issue 1713`_.

- Fix: in the HTML report, selecting code for copying won't select the line
  numbers also. Thanks, `Robert Harris <pull 1717_>`_.

.. _issue 1713: https://github.com/coveragepy/coveragepy/issues/1713
.. _pull 1717: https://github.com/coveragepy/coveragepy/pull/1717


.. _changes_7-3-3:

Version 7.3.3 — 2023-12-14
--------------------------

- Fix: function definitions with multi-line signatures can now be excluded by
  matching any of the lines, closing `issue 684`_.  Thanks, `Jan Rusak,
  Maciej Kowalczyk and Joanna Ejzel <pull 1705_>`_.

- Fix: XML reports could fail with a TypeError if files had numeric components
  that were duplicates except for leading zeroes, like ``file1.py`` and
  ``file001.py``.  Fixes `issue 1709`_.

- The ``coverage annotate`` command used to announce that it would be removed
  in a future version. Enough people got in touch to say that they use it, so
  it will stay.  Don't expect it to keep up with other new features though.

- Added new :ref:`debug options <cmd_run_debug>`:

  - ``pytest`` writes the pytest test name into the debug output.

  - ``dataop2`` writes the full data being added to CoverageData objects.

.. _issue 684: https://github.com/coveragepy/coveragepy/issues/684
.. _pull 1705: https://github.com/coveragepy/coveragepy/pull/1705
.. _issue 1709: https://github.com/coveragepy/coveragepy/issues/1709


.. _changes_7-3-2:

Version 7.3.2 — 2023-10-02
--------------------------

- The ``coverage lcov`` command ignored the ``[report] exclude_lines`` and
  ``[report] exclude_also`` settings (`issue 1684`_).  This is now fixed,
  thanks `Jacqueline Lee <pull 1685_>`_.

- Sometimes SQLite will create journal files alongside the coverage.py database
  files.  These are ephemeral, but could be mistakenly included when combining
  data files.  Now they are always ignored, fixing `issue 1605`_. Thanks to
  Brad Smith for suggesting fixes and providing detailed debugging.

- On Python 3.12+, we now disable SQLite writing journal files, which should be
  a little faster.

- The new 3.12 soft keyword ``type`` is properly bolded in HTML reports.

- Removed the "fullcoverage" feature used by CPython to measure the coverage of
  early-imported standard library modules.  CPython `stopped using it
  <88054_>`_ in 2021, and it stopped working completely in Python 3.13.

.. _issue 1605: https://github.com/coveragepy/coveragepy/issues/1605
.. _issue 1684: https://github.com/coveragepy/coveragepy/issues/1684
.. _pull 1685: https://github.com/coveragepy/coveragepy/pull/1685
.. _88054: https://github.com/python/cpython/issues/88054


.. _changes_7-3-1:

Version 7.3.1 — 2023-09-06
--------------------------

- The semantics of stars in file patterns has been clarified in the docs.  A
  leading or trailing star matches any number of path components, like a double
  star would.  This is different than the behavior of a star in the middle of a
  pattern.  This discrepancy was `identified by Sviatoslav Sydorenko
  <starbad_>`_, who `provided patient detailed diagnosis <pull 1650_>`_ and
  graciously agreed to a pragmatic resolution.

- The API docs were missing from the last version. They are now `restored
  <apidocs_>`_.

.. _apidocs: https://coverage.readthedocs.io/en/latest/api_coverage.html
.. _starbad: https://github.com/coveragepy/coveragepy/issues/1407#issuecomment-1631085209
.. _pull 1650: https://github.com/coveragepy/coveragepy/pull/1650

.. _changes_7-3-0:

Version 7.3.0 — 2023-08-12
--------------------------

- Added a :meth:`.Coverage.collect` context manager to start and stop coverage
  data collection.

- Dropped support for Python 3.7.

- Fix: in unusual circumstances, SQLite cannot be set to asynchronous mode.
  Coverage.py would fail with the error ``Safety level may not be changed
  inside a transaction.`` This is now avoided, closing `issue 1646`_.  Thanks
  to Michael Bell for the detailed bug report.

- Docs: examples of configuration files now include separate examples for the
  different syntaxes: .coveragerc, pyproject.toml, setup.cfg, and tox.ini.

- Fix: added ``nosemgrep`` comments to our JavaScript code so that
  semgrep-based SAST security checks won't raise false alarms about security
  problems that aren't problems.

- Added a CITATION.cff file, thanks to `Ken Schackart <pull 1641_>`_.

.. _pull 1641: https://github.com/coveragepy/coveragepy/pull/1641
.. _issue 1646: https://github.com/coveragepy/coveragepy/issues/1646


.. _changes_7-2-7:

Version 7.2.7 — 2023-05-29
--------------------------

- Fix: reverted a `change from 6.4.3 <pull 1347b_>`_ that helped Cython, but
  also increased the size of data files when using dynamic contexts, as
  described in the now-fixed `issue 1586`_. The problem is now avoided due to a
  recent change (`issue 1538 <issue 1538b_>`_).  Thanks to `Anders Kaseorg
  <pull 1629_>`_ and David Szotten for persisting with problem reports and
  detailed diagnoses.

- Wheels are now provided for CPython 3.12.

.. _pull 1347b: https://github.com/coveragepy/coveragepy/pull/1347
.. _issue 1538b: https://github.com/coveragepy/coveragepy/issues/1538
.. _issue 1586: https://github.com/coveragepy/coveragepy/issues/1586
.. _pull 1629: https://github.com/coveragepy/coveragepy/pull/1629


.. _changes_7-2-6:

Version 7.2.6 — 2023-05-23
--------------------------

- Fix: the ``lcov`` command could raise an IndexError exception if a file is
  translated to Python but then executed under its own name.  Jinja2 does this
  when rendering templates.  Fixes `issue 1553`_.

- Python 3.12 beta 1 now inlines comprehensions.  Previously they were compiled
  as invisible functions and coverage.py would warn you if they weren't
  completely executed.  This no longer happens under Python 3.12.

- Fix: the ``coverage debug sys`` command includes some environment variables
  in its output.  This could have included sensitive data.  Those values are
  now hidden with asterisks, closing `issue 1628`_.

.. _issue 1553: https://github.com/coveragepy/coveragepy/issues/1553
.. _issue 1628: https://github.com/coveragepy/coveragepy/issues/1628


.. _changes_7-2-5:

Version 7.2.5 — 2023-04-30
--------------------------

- Fix: ``html_report()`` could fail with an AttributeError on ``isatty`` if run
  in an unusual environment where sys.stdout had been replaced.  This is now
  fixed.


.. _changes_7-2-4:

Version 7.2.4 — 2023-04-28
--------------------------

PyCon 2023 sprint fixes!

- Fix: with ``relative_files = true``, specifying a specific file to include or
  omit wouldn't work correctly (`issue 1604`_).  This is now fixed, with
  testing help by `Marc Gibbons <pull 1608_>`_.

- Fix: the XML report would have an incorrect ``<source>`` element when using
  relative files and the source option ended with a slash (`issue 1541`_).
  This is now fixed, thanks to `Kevin Brown-Silva <pull 1608_>`_.

- When the HTML report location is printed to the terminal, it's now a
  terminal-compatible URL, so that you can click the location to open the HTML
  file in your browser.  Finishes `issue 1523`_ thanks to `Ricardo Newbery
  <pull 1613_>`_.

- Docs: a new :ref:`Migrating page <migrating>` with details about how to
  migrate between major versions of coverage.py.  It currently covers the
  wildcard changes in 7.x.  Thanks, `Brian Grohe <pull 1610_>`_.

.. _issue 1523: https://github.com/coveragepy/coveragepy/issues/1523
.. _issue 1541: https://github.com/coveragepy/coveragepy/issues/1541
.. _issue 1604: https://github.com/coveragepy/coveragepy/issues/1604
.. _pull 1608: https://github.com/coveragepy/coveragepy/pull/1608
.. _pull 1609: https://github.com/coveragepy/coveragepy/pull/1609
.. _pull 1610: https://github.com/coveragepy/coveragepy/pull/1610
.. _pull 1613: https://github.com/coveragepy/coveragepy/pull/1613


.. _changes_7-2-3:

Version 7.2.3 — 2023-04-06
--------------------------

- Fix: the :ref:`config_run_sigterm` setting was meant to capture data if a
  process was terminated with a SIGTERM signal, but it didn't always.  This was
  fixed thanks to `Lewis Gaul <pull 1600_>`_, closing `issue 1599`_.

- Performance: HTML reports with context information are now much more compact.
  File sizes are typically as small as one-third the previous size, but can be
  dramatically smaller. This closes `issue 1584`_ thanks to `Oleh Krehel
  <pull 1587_>`_.

- Development dependencies no longer use hashed pins, closing `issue 1592`_.

.. _issue 1584: https://github.com/coveragepy/coveragepy/issues/1584
.. _pull 1587: https://github.com/coveragepy/coveragepy/pull/1587
.. _issue 1592: https://github.com/coveragepy/coveragepy/issues/1592
.. _issue 1599: https://github.com/coveragepy/coveragepy/issues/1599
.. _pull 1600: https://github.com/coveragepy/coveragepy/pull/1600


.. _changes_7-2-2:

Version 7.2.2 — 2023-03-16
--------------------------

- Fix: if a virtualenv was created inside a source directory, and a sourced
  package was installed inside the virtualenv, then all of the third-party
  packages inside the virtualenv would be measured.  This was incorrect, but
  has now been fixed: only the specified packages will be measured, thanks to
  `Manuel Jacob <pull 1560_>`_.

- Fix: the ``coverage lcov`` command could create a .lcov file with incorrect
  LF (lines found) and LH (lines hit) totals.  This is now fixed, thanks to
  `Ian Moore <pull 1583_>`_.

- Fix: the ``coverage xml`` command on Windows could create a .xml file with
  duplicate ``<package>`` elements. This is now fixed, thanks to `Benjamin
  Parzella <pull 1574_>`_, closing `issue 1573`_.

.. _pull 1560: https://github.com/coveragepy/coveragepy/pull/1560
.. _issue 1573: https://github.com/coveragepy/coveragepy/issues/1573
.. _pull 1574: https://github.com/coveragepy/coveragepy/pull/1574
.. _pull 1583: https://github.com/coveragepy/coveragepy/pull/1583


.. _changes_7-2-1:

Version 7.2.1 — 2023-02-26
--------------------------

- Fix: the PyPI page had broken links to documentation pages, but no longer
  does, closing `issue 1566`_.

- Fix: public members of the coverage module are now properly indicated so that
  mypy will find them, fixing `issue 1564`_.

.. _issue 1564: https://github.com/coveragepy/coveragepy/issues/1564
.. _issue 1566: https://github.com/coveragepy/coveragepy/issues/1566


.. _changes_7-2-0:

Version 7.2.0 — 2023-02-22
--------------------------

- Added a new setting ``[report] exclude_also`` to let you add more exclusions
  without overwriting the defaults.  Thanks, `Alpha Chen <pull 1557_>`_,
  closing `issue 1391`_.

- Added a :meth:`.CoverageData.purge_files` method to remove recorded data for
  a particular file.  Contributed by `Stephan Deibel <pull 1547_>`_.

- Fix: when reporting commands fail, they will no longer congratulate
  themselves with messages like "Wrote XML report to file.xml" before spewing a
  traceback about their failure.

- Fix: arguments in the public API that name file paths now accept pathlib.Path
  objects.  This includes the ``data_file`` and ``config_file`` arguments to
  the Coverage constructor and the ``basename`` argument to CoverageData.
  Closes `issue 1552`_.

- Fix: In some embedded environments, an IndexError could occur on stop() when
  the originating thread exits before completion.  This is now fixed, thanks to
  `Russell Keith-Magee <pull 1543_>`_, closing `issue 1542`_.

- Added a ``py.typed`` file to announce our type-hintedness.  Thanks,
  `KotlinIsland <pull 1550_>`_.

.. _issue 1391: https://github.com/coveragepy/coveragepy/issues/1391
.. _issue 1542: https://github.com/coveragepy/coveragepy/issues/1542
.. _pull 1543: https://github.com/coveragepy/coveragepy/pull/1543
.. _pull 1547: https://github.com/coveragepy/coveragepy/pull/1547
.. _pull 1550: https://github.com/coveragepy/coveragepy/pull/1550
.. _issue 1552: https://github.com/coveragepy/coveragepy/issues/1552
.. _pull 1557: https://github.com/coveragepy/coveragepy/pull/1557


.. _changes_7-1-0:

Version 7.1.0 — 2023-01-24
--------------------------

- Added: the debug output file can now be specified with ``[run] debug_file``
  in the configuration file.  Closes `issue 1319`_.

- Performance: fixed a slowdown with dynamic contexts that's been around since
  6.4.3.  The fix closes `issue 1538`_.  Thankfully this doesn't break the
  `Cython change`_ that fixed `issue 972`_.  Thanks to Mathieu Kniewallner for
  the deep investigative work and comprehensive issue report.

- Typing: all product and test code has type annotations.

.. _Cython change: https://github.com/coveragepy/coveragepy/pull/1347
.. _issue 972: https://github.com/coveragepy/coveragepy/issues/972
.. _issue 1319: https://github.com/coveragepy/coveragepy/issues/1319
.. _issue 1538: https://github.com/coveragepy/coveragepy/issues/1538


.. _changes_7-0-5:

Version 7.0.5 — 2023-01-10
--------------------------

- Fix: On Python 3.7, a file with type annotations but no ``from __future__
  import annotations`` would be missing statements in the coverage report. This
  is now fixed, closing `issue 1524`_.

.. _issue 1524: https://github.com/coveragepy/coveragepy/issues/1524


.. _changes_7-0-4:

Version 7.0.4 — 2023-01-07
--------------------------

- Performance: an internal cache of file names was accidentally disabled,
  resulting in sometimes drastic reductions in performance.  This is now fixed,
  closing `issue 1527`_.   Thanks to Ivan Ciuvalschii for the reproducible test
  case.

.. _issue 1527: https://github.com/coveragepy/coveragepy/issues/1527


.. _changes_7-0-3:

Version 7.0.3 — 2023-01-03
--------------------------

- Fix: when using pytest-cov or pytest-xdist, or perhaps both, the combining
  step could fail with ``assert row is not None`` using 7.0.2.  This was due to
  a race condition that has always been possible and is still possible. In
  7.0.1 and before, the error was silently swallowed by the combining code.
  Now it will produce a message "Couldn't combine data file" and ignore the
  data file as it used to do before 7.0.2.  Closes `issue 1522`_.

.. _issue 1522: https://github.com/coveragepy/coveragepy/issues/1522


.. _changes_7-0-2:

Version 7.0.2 — 2023-01-02
--------------------------

- Fix: when using the ``[run] relative_files = True`` setting, a relative
  ``[paths]`` pattern was still being made absolute.  This is now fixed,
  closing `issue 1519`_.

- Fix: if Python doesn't provide tomllib, then TOML configuration files can
  only be read if coverage.py is installed with the ``[toml]`` extra.
  Coverage.py will raise an error if TOML support is not installed when it sees
  your settings are in a .toml file. But it didn't understand that
  ``[tools.coverage]`` was a valid section header, so the error wasn't reported
  if you used that header, and settings were silently ignored.  This is now
  fixed, closing `issue 1516`_.

- Fix: adjusted how decorators are traced on PyPy 7.3.10, fixing `issue 1515`_.

- Fix: the ``coverage lcov`` report did not properly implement the
  ``--fail-under=MIN`` option.  This has been fixed.

- Refactor: added many type annotations, including a number of refactorings.
  This should not affect outward behavior, but they were a bit invasive in some
  places, so keep your eyes peeled for oddities.

- Refactor: removed the vestigial and long untested support for Jython and
  IronPython.

.. _issue 1515: https://github.com/coveragepy/coveragepy/issues/1515
.. _issue 1516: https://github.com/coveragepy/coveragepy/issues/1516
.. _issue 1519: https://github.com/coveragepy/coveragepy/issues/1519


.. _changes_7-0-1:

Version 7.0.1 — 2022-12-23
--------------------------

- When checking if a file mapping resolved to a file that exists, we weren't
  considering files in .whl files.  This is now fixed, closing `issue 1511`_.

- File pattern rules were too strict, forbidding plus signs and curly braces in
  directory and file names.  This is now fixed, closing `issue 1513`_.

- Unusual Unicode or control characters in source files could prevent
  reporting.  This is now fixed, closing `issue 1512`_.

- The PyPy wheel now installs on PyPy 3.7, 3.8, and 3.9, closing `issue 1510`_.

.. _issue 1510: https://github.com/coveragepy/coveragepy/issues/1510
.. _issue 1511: https://github.com/coveragepy/coveragepy/issues/1511
.. _issue 1512: https://github.com/coveragepy/coveragepy/issues/1512
.. _issue 1513: https://github.com/coveragepy/coveragepy/issues/1513


.. _changes_7-0-0:

Version 7.0.0 — 2022-12-18
--------------------------

Nothing new beyond 7.0.0b1.


.. _changes_7-0-0b1:

Version 7.0.0b1 — 2022-12-03
----------------------------

A number of changes have been made to file path handling, including pattern
matching and path remapping with the ``[paths]`` setting (see
:ref:`config_paths`).  These changes might affect you, and require you to
update your settings.

(This release includes the changes from `6.6.0b1`__, since 6.6.0 was never
released.)

__ https://coverage.readthedocs.io/en/latest/changes.html#changes-6-6-0b1

- Changes to file pattern matching, which might require updating your
  configuration:

  - Previously, ``*`` would incorrectly match directory separators, making
    precise matching difficult.  This is now fixed, closing `issue 1407`_.

  - Now ``**`` matches any number of nested directories, including none.

- Improvements to combining data files when using the
  :ref:`config_run_relative_files` setting, which might require updating your
  configuration:

  - During ``coverage combine``, relative file paths are implicitly combined
    without needing a ``[paths]`` configuration setting.  This also fixed
    `issue 991`_.

  - A ``[paths]`` setting like ``*/foo`` will now match ``foo/bar.py`` so that
    relative file paths can be combined more easily.

  - The :ref:`config_run_relative_files` setting is properly interpreted in
    more places, fixing `issue 1280`_.

- When remapping file paths with ``[paths]``, a path will be remapped only if
  the resulting path exists.  The documentation has long said the prefix had to
  exist, but it was never enforced.  This fixes `issue 608`_, improves `issue
  649`_, and closes `issue 757`_.

- Reporting operations now implicitly use the ``[paths]`` setting to remap file
  paths within a single data file.  Combining multiple files still requires the
  ``coverage combine`` step, but this simplifies some single-file situations.
  Closes `issue 1212`_ and `issue 713`_.

- The ``coverage report`` command now has a ``--format=`` option.  The original
  style is now ``--format=text``, and is the default.

  - Using ``--format=markdown`` will write the table in Markdown format, thanks
    to `Steve Oswald <pull 1479_>`_, closing `issue 1418`_.

  - Using ``--format=total`` will write a single total number to the
    output.  This can be useful for making badges or writing status updates.

- Combining data files with ``coverage combine`` now hashes the data files to
  skip files that add no new information.  This can reduce the time needed.
  Many details affect the speed-up, but for coverage.py's own test suite,
  combining is about 40% faster. Closes `issue 1483`_.

- When searching for completely un-executed files, coverage.py uses the
  presence of ``__init__.py`` files to determine which directories have source
  that could have been imported.  However, `implicit namespace packages`_ don't
  require ``__init__.py``.  A new setting ``[report]
  include_namespace_packages`` tells coverage.py to consider these directories
  during reporting.  Thanks to `Felix Horvat <pull 1387_>`_ for the
  contribution.  Closes `issue 1383`_ and `issue 1024`_.

- Fixed environment variable expansion in pyproject.toml files.  It was overly
  broad, causing errors outside of coverage.py settings, as described in `issue
  1481`_ and `issue 1345`_.  This is now fixed, but in rare cases will require
  changing your pyproject.toml to quote non-string values that use environment
  substitution.

- An empty file has a coverage total of 100%, but used to fail with
  ``--fail-under``.  This has been fixed, closing `issue 1470`_.

- The text report table no longer writes out two separator lines if there are
  no files listed in the table.  One is plenty.

- Fixed a mis-measurement of a strange use of wildcard alternatives in
  match/case statements, closing `issue 1421`_.

- Fixed internal logic that prevented coverage.py from running on
  implementations other than CPython or PyPy (`issue 1474`_).

- The deprecated ``[run] note`` setting has been completely removed.

.. _implicit namespace packages: https://peps.python.org/pep-0420/
.. _issue 608: https://github.com/coveragepy/coveragepy/issues/608
.. _issue 649: https://github.com/coveragepy/coveragepy/issues/649
.. _issue 713: https://github.com/coveragepy/coveragepy/issues/713
.. _issue 757: https://github.com/coveragepy/coveragepy/issues/757
.. _issue 991: https://github.com/coveragepy/coveragepy/issues/991
.. _issue 1024: https://github.com/coveragepy/coveragepy/issues/1024
.. _issue 1212: https://github.com/coveragepy/coveragepy/issues/1212
.. _issue 1280: https://github.com/coveragepy/coveragepy/issues/1280
.. _issue 1345: https://github.com/coveragepy/coveragepy/issues/1345
.. _issue 1383: https://github.com/coveragepy/coveragepy/issues/1383
.. _issue 1407: https://github.com/coveragepy/coveragepy/issues/1407
.. _issue 1418: https://github.com/coveragepy/coveragepy/issues/1418
.. _issue 1421: https://github.com/coveragepy/coveragepy/issues/1421
.. _issue 1470: https://github.com/coveragepy/coveragepy/issues/1470
.. _issue 1474: https://github.com/coveragepy/coveragepy/issues/1474
.. _issue 1481: https://github.com/coveragepy/coveragepy/issues/1481
.. _issue 1483: https://github.com/coveragepy/coveragepy/issues/1483
.. _pull 1387: https://github.com/coveragepy/coveragepy/pull/1387
.. _pull 1479: https://github.com/coveragepy/coveragepy/pull/1479


.. _changes_6-6-0b1:

Version 6.6.0b1 — 2022-10-31
----------------------------

(Note: 6.6.0 final was never released. These changes are part of `7.0.0b1`__.)

__ https://coverage.readthedocs.io/en/latest/changes.html#changes-7-0-0b1

- Changes to file pattern matching, which might require updating your
  configuration:

  - Previously, ``*`` would incorrectly match directory separators, making
    precise matching difficult.  This is now fixed, closing `issue 1407`_.

  - Now ``**`` matches any number of nested directories, including none.

- Improvements to combining data files when using the
  :ref:`config_run_relative_files` setting:

  - During ``coverage combine``, relative file paths are implicitly combined
    without needing a ``[paths]`` configuration setting.  This also fixed
    `issue 991`_.

  - A ``[paths]`` setting like ``*/foo`` will now match ``foo/bar.py`` so that
    relative file paths can be combined more easily.

  - The setting is properly interpreted in more places, fixing `issue 1280`_.

- Fixed environment variable expansion in pyproject.toml files.  It was overly
  broad, causing errors outside of coverage.py settings, as described in `issue
  1481`_ and `issue 1345`_.  This is now fixed, but in rare cases will require
  changing your pyproject.toml to quote non-string values that use environment
  substitution.

- Fixed internal logic that prevented coverage.py from running on
  implementations other than CPython or PyPy (`issue 1474`_).

.. _issue 991: https://github.com/coveragepy/coveragepy/issues/991
.. _issue 1280: https://github.com/coveragepy/coveragepy/issues/1280
.. _issue 1345: https://github.com/coveragepy/coveragepy/issues/1345
.. _issue 1407: https://github.com/coveragepy/coveragepy/issues/1407
.. _issue 1474: https://github.com/coveragepy/coveragepy/issues/1474
.. _issue 1481: https://github.com/coveragepy/coveragepy/issues/1481


.. _changes_6-5-0:

Version 6.5.0 — 2022-09-29
--------------------------

- The JSON report now includes details of which branches were taken, and which
  are missing for each file. Thanks, `Christoph Blessing <pull 1438_>`_. Closes
  `issue 1425`_.

- Starting with coverage.py 6.2, ``class`` statements were marked as a branch.
  This wasn't right, and has been reverted, fixing `issue 1449`_. Note this
  will very slightly reduce your coverage total if you are measuring branch
  coverage.

- Packaging is now compliant with `PEP 517`_, closing `issue 1395`_.

- A new debug option ``--debug=pathmap`` shows details of the remapping of
  paths that happens during combine due to the ``[paths]`` setting.

- Fix an internal problem with caching of invalid Python parsing. Found by
  OSS-Fuzz, fixing their `bug 50381`_.

.. _bug 50381: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=50381
.. _PEP 517: https://peps.python.org/pep-0517/
.. _issue 1395: https://github.com/coveragepy/coveragepy/issues/1395
.. _issue 1425: https://github.com/coveragepy/coveragepy/issues/1425
.. _issue 1449: https://github.com/coveragepy/coveragepy/issues/1449
.. _pull 1438: https://github.com/coveragepy/coveragepy/pull/1438


.. _changes_6-4-4:

Version 6.4.4 — 2022-08-16
--------------------------

- Wheels are now provided for Python 3.11.


.. _changes_6-4-3:

Version 6.4.3 — 2022-08-06
--------------------------

- Fix a failure when combining data files if the file names contained glob-like
  patterns.  Thanks, `Michael Krebs and Benjamin Schubert <pull 1405_>`_.

- Fix a messaging failure when combining Windows data files on a different
  drive than the current directory, closing `issue 1428`_.  Thanks, `Lorenzo
  Micò <pull 1430_>`_.

- Fix path calculations when running in the root directory, as you might do in
  a Docker container. Thanks `Arthur Rio <pull 1403_>`_.

- Filtering in the HTML report wouldn't work when reloading the index page.
  This is now fixed.  Thanks, `Marc Legendre <pull 1413_>`_.

- Fix a problem with Cython code measurement, closing `issue 972`_.  Thanks,
  `Matus Valo <pull 1347_>`_.

.. _issue 972: https://github.com/coveragepy/coveragepy/issues/972
.. _issue 1428: https://github.com/coveragepy/coveragepy/issues/1428
.. _pull 1347: https://github.com/coveragepy/coveragepy/pull/1347
.. _pull 1403: https://github.com/coveragepy/coveragepy/issues/1403
.. _pull 1405: https://github.com/coveragepy/coveragepy/issues/1405
.. _pull 1413: https://github.com/coveragepy/coveragepy/issues/1413
.. _pull 1430: https://github.com/coveragepy/coveragepy/pull/1430


.. _changes_6-4-2:

Version 6.4.2 — 2022-07-12
--------------------------

- Updated for a small change in Python 3.11.0 beta 4: modules now start with a
  line with line number 0, which is ignored.  This line cannot be executed, so
  coverage totals were thrown off.  This line is now ignored by coverage.py,
  but this also means that truly empty modules (like ``__init__.py``) have no
  lines in them, rather than one phantom line.  Fixes `issue 1419`_.

- Internal debugging data added to sys.modules is now an actual module, to
  avoid confusing code that examines everything in sys.modules.  Thanks,
  `Yilei Yang <pull 1399_>`_.

.. _issue 1419: https://github.com/coveragepy/coveragepy/issues/1419
.. _pull 1399: https://github.com/coveragepy/coveragepy/pull/1399


.. _changes_6-4-1:

Version 6.4.1 — 2022-06-02
--------------------------

- Greatly improved performance on PyPy, and other environments that need the
  pure Python trace function.  Thanks, Carl Friedrich Bolz-Tereick (`pull
  1381`_ and `pull 1388`_).  Slightly improved performance when using the C
  trace function, as most environments do.  Closes `issue 1339`_.

- The conditions for using tomllib from the standard library have been made
  more precise, so that 3.11 alphas will continue to work. Closes `issue
  1390`_.

.. _issue 1339: https://github.com/coveragepy/coveragepy/issues/1339
.. _pull 1381: https://github.com/coveragepy/coveragepy/pull/1381
.. _pull 1388: https://github.com/coveragepy/coveragepy/pull/1388
.. _issue 1390: https://github.com/coveragepy/coveragepy/issues/1390


.. _changes_64:

Version 6.4 — 2022-05-22
------------------------

- A new setting, :ref:`config_run_sigterm`, controls whether a SIGTERM signal
  handler is used.  In 6.3, the signal handler was always installed, to capture
  data at unusual process ends.  Unfortunately, this introduced other problems
  (see `issue 1310`_).  Now the signal handler is only used if you opt-in by
  setting ``[run] sigterm = true``.

- Small changes to the HTML report:

  - Added links to next and previous file, and more keyboard shortcuts: ``[``
    and ``]`` for next file and previous file; ``u`` for up to the index; and
    ``?`` to open/close the help panel.  Thanks, `J. M. F. Tsang
    <pull 1364_>`_.

  - The time stamp and version are displayed at the top of the report.  Thanks,
    `Ammar Askar <pull 1354_>`_. Closes `issue 1351`_.

- A new debug option ``debug=sqldata`` adds more detail to ``debug=sql``,
  logging all the data being written to the database.

- Previously, running ``coverage report`` (or any of the reporting commands) in
  an empty directory would create a .coverage data file.  Now they do not,
  fixing `issue 1328`_.

- On Python 3.11, the ``[toml]`` extra no longer installs tomli, instead using
  tomllib from the standard library.  Thanks `Shantanu <pull 1359_>`_.

- In-memory CoverageData objects now properly update(), closing `issue 1323`_.

.. _issue 1310: https://github.com/coveragepy/coveragepy/issues/1310
.. _issue 1323: https://github.com/coveragepy/coveragepy/issues/1323
.. _issue 1328: https://github.com/coveragepy/coveragepy/issues/1328
.. _issue 1351: https://github.com/coveragepy/coveragepy/issues/1351
.. _pull 1354: https://github.com/coveragepy/coveragepy/pull/1354
.. _pull 1359: https://github.com/coveragepy/coveragepy/pull/1359
.. _pull 1364: https://github.com/coveragepy/coveragepy/pull/1364


.. _changes_633:

Version 6.3.3 — 2022-05-12
--------------------------

- Fix: Coverage.py now builds successfully on CPython 3.11 (3.11.0b1) again.
  Closes `issue 1367`_.  Some results for generators may have changed.

.. _issue 1367: https://github.com/coveragepy/coveragepy/issues/1367


.. _changes_632:

Version 6.3.2 — 2022-02-20
--------------------------

- Fix: adapt to pypy3.9's decorator tracing behavior.  It now traces function
  decorators like CPython 3.8: both the @-line and the def-line are traced.
  Fixes `issue 1326`_.

- Debug: added ``pybehave`` to the list of :ref:`coverage debug <cmd_debug>`
  and :ref:`cmd_run_debug` options.

- Fix: show an intelligible error message if ``--concurrency=multiprocessing``
  is used without a configuration file.  Closes `issue 1320`_.

.. _issue 1320: https://github.com/coveragepy/coveragepy/issues/1320
.. _issue 1326: https://github.com/coveragepy/coveragepy/issues/1326


.. _changes_631:

Version 6.3.1 — 2022-02-01
--------------------------

- Fix: deadlocks could occur when terminating processes.  Some of these
  deadlocks (described in `issue 1310`_) are now fixed.

- Fix: a signal handler was being set from multiple threads, causing an error:
  "ValueError: signal only works in main thread".  This is now fixed, closing
  `issue 1312`_.

- Fix: ``--precision`` on the command-line was being ignored while considering
  ``--fail-under``.  This is now fixed, thanks to
  `Marcelo Trylesinski <pull 1317_>`_.

- Fix: releases no longer provide 3.11.0-alpha wheels. Coverage.py uses CPython
  internal fields which are moving during the alpha phase. Fixes `issue 1316`_.

.. _issue 1310: https://github.com/coveragepy/coveragepy/issues/1310
.. _issue 1312: https://github.com/coveragepy/coveragepy/issues/1312
.. _issue 1316: https://github.com/coveragepy/coveragepy/issues/1316
.. _pull 1317: https://github.com/coveragepy/coveragepy/pull/1317


.. _changes_63:

Version 6.3 — 2022-01-25
------------------------

- Feature: Added the ``lcov`` command to generate reports in LCOV format.
  Thanks, `Bradley Burns <pull 1289_>`_. Closes issues `587 <issue 587_>`_
  and `626 <issue 626_>`_.

- Feature: the coverage data file can now be specified on the command line with
  the ``--data-file`` option in any command that reads or writes data.  This is
  in addition to the existing ``COVERAGE_FILE`` environment variable.  Closes
  `issue 624`_. Thanks, `Nikita Bloshchanevich <pull 1304_>`_.

- Feature: coverage measurement data will now be written when a SIGTERM signal
  is received by the process.  This includes
  :meth:`Process.terminate <python:multiprocessing.Process.terminate>`,
  and other ways to terminate a process.  Currently this is only on Linux and
  Mac; Windows is not supported.  Fixes `issue 1307`_.

- Dropped support for Python 3.6, which reached end-of-life on 2021-12-23.

- Updated Python 3.11 support to 3.11.0a4, fixing `issue 1294`_.

- Fix: the coverage data file is now created in a more robust way, to avoid
  problems when multiple processes are trying to write data at once. Fixes
  issues `1303 <issue 1303_>`_ and `883 <issue 883_>`_.

- Fix: a .gitignore file will only be written into the HTML report output
  directory if the directory is empty.  This should prevent certain unfortunate
  accidents of writing the file where it is not wanted.

- Releases now have MacOS arm64 wheels for Apple Silicon, fixing `issue 1288`_.

.. _issue 587: https://github.com/coveragepy/coveragepy/issues/587
.. _issue 624: https://github.com/coveragepy/coveragepy/issues/624
.. _issue 626: https://github.com/coveragepy/coveragepy/issues/626
.. _issue 883: https://github.com/coveragepy/coveragepy/issues/883
.. _issue 1288: https://github.com/coveragepy/coveragepy/issues/1288
.. _issue 1294: https://github.com/coveragepy/coveragepy/issues/1294
.. _issue 1303: https://github.com/coveragepy/coveragepy/issues/1303
.. _issue 1307: https://github.com/coveragepy/coveragepy/issues/1307
.. _pull 1289: https://github.com/coveragepy/coveragepy/pull/1289
.. _pull 1304: https://github.com/coveragepy/coveragepy/pull/1304


.. _changes_62:

Version 6.2 — 2021-11-26
------------------------

- Feature: Now the ``--concurrency`` setting can have a list of values, so that
  threads and another lightweight threading package can be measured together,
  such as ``--concurrency=gevent,thread``.  Closes `issue 1012`_ and `issue
  1082`_.  This also means that ``thread`` must be explicitly specified in some
  cases that used to be implicit such as ``--concurrency=multiprocessing``,
  which must be changed to ``--concurrency=multiprocessing,thread``.

- Fix: A module specified as the ``source`` setting is imported during startup,
  before the user program imports it.  This could cause problems if the rest of
  the program isn't ready yet.  For example, `issue 1203`_ describes a Django
  setting that is accessed before settings have been configured.  Now the early
  import is wrapped in a try/except so errors then don't stop execution.

- Fix: A colon in a decorator expression would cause an exclusion to end too
  early, preventing the exclusion of the decorated function. This is now fixed.

- Fix: The HTML report now will not overwrite a .gitignore file that already
  exists in the HTML output directory (follow-on for `issue 1244
  <issue 1244b_>`_).

- API: The exceptions raised by Coverage.py have been specialized, to provide
  finer-grained catching of exceptions by third-party code.

- API: Using ``suffix=False`` when constructing a Coverage object with
  multiprocessing wouldn't suppress the data file suffix (`issue 989`_).  This
  is now fixed.

- Debug: The ``coverage debug data`` command will now sniff out combinable data
  files, and report on all of them.

- Debug: The ``coverage debug`` command used to accept a number of topics at a
  time, and show all of them, though this was never documented.  This no longer
  works, to allow for command-line options in the future.

.. _issue 989: https://github.com/coveragepy/coveragepy/issues/989
.. _issue 1012: https://github.com/coveragepy/coveragepy/issues/1012
.. _issue 1082: https://github.com/coveragepy/coveragepy/issues/1082
.. _issue 1203: https://github.com/coveragepy/coveragepy/issues/1203
.. _issue 1244b: https://github.com/coveragepy/coveragepy/issues/1244


.. _changes_612:

Version 6.1.2 — 2021-11-10
--------------------------

- Python 3.11 is supported (tested with 3.11.0a2).  One still-open issue has to
  do with `exits through with-statements <issue 1270_>`_.

- Fix: When remapping file paths through the ``[paths]`` setting while
  combining, the ``[run] relative_files`` setting was ignored, resulting in
  absolute paths for remapped file names (`issue 1147`_).  This is now fixed.

- Fix: Complex conditionals over excluded lines could have incorrectly reported
  a missing branch (`issue 1271`_). This is now fixed.

- Fix: More exceptions are now handled when trying to parse source files for
  reporting.  Problems that used to terminate coverage.py can now be handled
  with ``[report] ignore_errors``.  This helps with plugins failing to read
  files (`django_coverage_plugin issue 78`_).

- Fix: Removed another vestige of jQuery from the source tarball
  (`issue 840 <issue 840b_>`_).

- Fix: Added a default value for a new-to-6.x argument of an internal class.
  This unsupported class is being used by coveralls (`issue 1273`_). Although
  I'd rather not "fix" unsupported interfaces, it's actually nicer with a
  default value.

.. _django_coverage_plugin issue 78: https://github.com/coveragepy/django_coverage_plugin/issues/78
.. _issue 840b: https://github.com/coveragepy/coveragepy/issues/840
.. _issue 1147: https://github.com/coveragepy/coveragepy/issues/1147
.. _issue 1270: https://github.com/coveragepy/coveragepy/issues/1270
.. _issue 1271: https://github.com/coveragepy/coveragepy/issues/1271
.. _issue 1273: https://github.com/coveragepy/coveragepy/issues/1273


.. _changes_611:

Version 6.1.1 — 2021-10-31
--------------------------

- Fix: The sticky header on the HTML report didn't work unless you had branch
  coverage enabled. This is now fixed: the sticky header works for everyone.
  (Do people still use coverage without branch measurement!? j/k)

- Fix: When using explicitly declared namespace packages, the "already imported
  a file that will be measured" warning would be issued (`issue 888`_).  This
  is now fixed.

.. _issue 888: https://github.com/coveragepy/coveragepy/issues/888


.. _changes_61:

Version 6.1 — 2021-10-30
------------------------

- Deprecated: The ``annotate`` command and the ``Coverage.annotate`` function
  will be removed in a future version, unless people let me know that they are
  using it.  Instead, the ``html`` command gives better-looking (and more
  accurate) output, and the ``report -m`` command will tell you line numbers of
  missing lines.  Please get in touch if you have a reason to use ``annotate``
  over those better options: ned@nedbatchelder.com.

- Feature: Coverage now sets an environment variable, ``COVERAGE_RUN`` when
  running your code with the ``coverage run`` command.  The value is not
  important, and may change in the future.  Closes `issue 553`_.

- Feature: The HTML report pages for Python source files now have a sticky
  header so the file name and controls are always visible.

- Feature: The ``xml`` and ``json`` commands now describe what they wrote
  where.

- Feature: The ``html``, ``combine``, ``xml``, and ``json`` commands all accept
  a ``-q/--quiet`` option to suppress the messages they write to stdout about
  what they are doing (`issue 1254`_).

- Feature: The ``html`` command writes a ``.gitignore`` file into the HTML
  output directory, to prevent the report from being committed to git.  If you
  want to commit it, you will need to delete that file.  Closes `issue 1244`_.

- Feature: Added support for PyPy 3.8.

- Fix: More generated code is now excluded from measurement.  Code such as
  `attrs`_ boilerplate, or doctest code, was being measured though the
  synthetic line numbers meant they were never reported.  Once Cython was
  involved though, the generated .so files were parsed as Python, raising
  syntax errors, as reported in `issue 1160`_.  This is now fixed.

- Fix: When sorting human-readable names, numeric components are sorted
  correctly: file10.py will appear after file9.py.  This applies to file names,
  module names, environment variables, and test contexts.

- Performance: Branch coverage measurement is faster, though you might only
  notice on code that is executed many times, such as long-running loops.

- Build: jQuery is no longer used or vendored (`issue 840`_ and `issue 1118`_).
  Huge thanks to Nils Kattenbeck (septatrix) for the conversion to vanilla
  JavaScript in `pull request 1248`_.

.. _issue 553: https://github.com/coveragepy/coveragepy/issues/553
.. _issue 840: https://github.com/coveragepy/coveragepy/issues/840
.. _issue 1118: https://github.com/coveragepy/coveragepy/issues/1118
.. _issue 1160: https://github.com/coveragepy/coveragepy/issues/1160
.. _issue 1244: https://github.com/coveragepy/coveragepy/issues/1244
.. _pull request 1248: https://github.com/coveragepy/coveragepy/pull/1248
.. _issue 1254: https://github.com/coveragepy/coveragepy/issues/1254
.. _attrs: https://www.attrs.org/


.. _changes_602:

Version 6.0.2 — 2021-10-11
--------------------------

- Namespace packages being measured weren't properly handled by the new code
  that ignores third-party packages. If the namespace package was installed, it
  was ignored as a third-party package.  That problem (`issue 1231`_) is now
  fixed.

- Packages named as "source packages" (with ``source``, or ``source_pkgs``, or
  pytest-cov's ``--cov``) might have been only partially measured.  Their
  top-level statements could be marked as un-executed, because they were
  imported by coverage.py before measurement began (`issue 1232`_).  This is
  now fixed, but the package will be imported twice, once by coverage.py, then
  again by your test suite.  This could cause problems if importing the package
  has side effects.

- The :meth:`.CoverageData.contexts_by_lineno` method was documented to return
  a dict, but was returning a defaultdict.  Now it returns a plain dict.  It
  also no longer returns negative numbered keys.

.. _issue 1231: https://github.com/coveragepy/coveragepy/issues/1231
.. _issue 1232: https://github.com/coveragepy/coveragepy/issues/1232


.. _changes_601:

Version 6.0.1 — 2021-10-06
--------------------------

- In 6.0, the coverage.py exceptions moved from coverage.misc to
  coverage.exceptions. These exceptions are not part of the public supported
  API, CoverageException is. But a number of other third-party packages were
  importing the exceptions from coverage.misc, so they are now available from
  there again (`issue 1226`_).

- Changed an internal detail of how tomli is imported, so that tomli can use
  coverage.py for their own test suite (`issue 1228`_).

- Defend against an obscure possibility under code obfuscation, where a
  function can have an argument called "self", but no local named "self"
  (`pull request 1210`_).  Thanks, Ben Carlsson.

.. _pull request 1210: https://github.com/coveragepy/coveragepy/pull/1210
.. _issue 1226: https://github.com/coveragepy/coveragepy/issues/1226
.. _issue 1228: https://github.com/coveragepy/coveragepy/issues/1228


.. _changes_60:

Version 6.0 — 2021-10-03
------------------------

- The ``coverage html`` command now prints a message indicating where the HTML
  report was written.  Fixes `issue 1195`_.

- The ``coverage combine`` command now prints messages indicating each data
  file being combined.  Fixes `issue 1105`_.

- The HTML report now includes a sentence about skipped files due to
  ``skip_covered`` or ``skip_empty`` settings.  Fixes `issue 1163`_.

- Unrecognized options in the configuration file are no longer errors. They are
  now warnings, to ease the use of coverage across versions.  Fixes `issue
  1035`_.

- Fix handling of exceptions through context managers in Python 3.10. A missing
  exception is no longer considered a missing branch from the with statement.
  Fixes `issue 1205`_.

- Fix another rarer instance of "Error binding parameter 0 - probably
  unsupported type." (`issue 1010 <issue 1010b_>`_).

- Creating a directory for the coverage data file now is safer against
  conflicts when two coverage runs happen simultaneously (`pull 1220`_).
  Thanks, Clément Pit-Claudel.

.. _issue 1010b: https://github.com/coveragepy/coveragepy/issues/1010
.. _issue 1035: https://github.com/coveragepy/coveragepy/issues/1035
.. _issue 1105: https://github.com/coveragepy/coveragepy/issues/1105
.. _issue 1163: https://github.com/coveragepy/coveragepy/issues/1163
.. _issue 1195: https://github.com/coveragepy/coveragepy/issues/1195
.. _issue 1205: https://github.com/coveragepy/coveragepy/issues/1205
.. _pull 1220: https://github.com/coveragepy/coveragepy/pull/1220


.. _changes_60b1:

Version 6.0b1 — 2021-07-18
--------------------------

- Dropped support for Python 2.7, PyPy 2, and Python 3.5.

- Added support for the Python 3.10 ``match/case`` syntax.

- Data collection is now thread-safe.  There may have been rare instances of
  exceptions raised in multi-threaded programs.

- Plugins (like the `Django coverage plugin`_) were generating "Already
  imported a file that will be measured" warnings about Django itself.  These
  have been fixed, closing `issue 1150`_.

- Warnings generated by coverage.py are now real Python warnings.

- Using ``--fail-under=100`` with coverage near 100% could result in the
  self-contradictory message :code:`total of 100 is less than fail-under=100`.
  This bug (`issue 1168`_) is now fixed.

- The ``COVERAGE_DEBUG_FILE`` environment variable now accepts ``stdout`` and
  ``stderr`` to write to those destinations.

- TOML parsing now uses the `tomli`_ library.

- Some minor changes to usually invisible details of the HTML report:

  - Use a modern hash algorithm when fingerprinting, for high-security
    environments (`issue 1189`_).  When generating the HTML report, we save the
    hash of the data, to avoid regenerating an unchanged HTML page. We used to
    use MD5 to generate the hash, and now use SHA-3-256.  This was never a
    security concern, but security scanners would notice the MD5 algorithm and
    raise a false alarm.

  - Change how report file names are generated, to avoid leading underscores
    (`issue 1167`_), to avoid rare file name collisions (`issue 584`_), and to
    avoid file names becoming too long (`issue 580`_).

.. _Django coverage plugin: https://pypi.org/project/django-coverage-plugin/
.. _issue 580: https://github.com/coveragepy/coveragepy/issues/580
.. _issue 584: https://github.com/coveragepy/coveragepy/issues/584
.. _issue 1150: https://github.com/coveragepy/coveragepy/issues/1150
.. _issue 1167: https://github.com/coveragepy/coveragepy/issues/1167
.. _issue 1168: https://github.com/coveragepy/coveragepy/issues/1168
.. _issue 1189: https://github.com/coveragepy/coveragepy/issues/1189
.. _tomli: https://pypi.org/project/tomli/


.. _changes_56b1:

Version 5.6b1 — 2021-04-13
--------------------------

Note: 5.6 final was never released. These changes are part of 6.0.

- Third-party packages are now ignored in coverage reporting.  This solves a
  few problems:

  - Coverage will no longer report about other people's code (`issue 876`_).
    This is true even when using ``--source=.`` with a venv in the current
    directory.

  - Coverage will no longer generate "Already imported a file that will be
    measured" warnings about coverage itself (`issue 905`_).

- The HTML report uses j/k to move up and down among the highlighted chunks of
  code.  They used to highlight the current chunk, but 5.0 broke that behavior.
  Now the highlighting is working again.

- The JSON report now includes ``percent_covered_display``, a string with the
  total percentage, rounded to the same number of decimal places as the other
  reports' totals.

.. _issue 876: https://github.com/coveragepy/coveragepy/issues/876
.. _issue 905: https://github.com/coveragepy/coveragepy/issues/905


.. _changes_55:

Version 5.5 — 2021-02-28
------------------------

- ``coverage combine`` has a new option, ``--keep`` to keep the original data
  files after combining them.  The default is still to delete the files after
  they have been combined.  This was requested in `issue 1108`_ and implemented
  in `pull request 1110`_.  Thanks, Éric Larivière.

- When reporting missing branches in ``coverage report``, branches aren't
  reported that jump to missing lines.  This adds to the long-standing behavior
  of not reporting branches from missing lines.  Now branches are only reported
  if both the source and destination lines are executed.  Closes both `issue
  1065`_ and `issue 955`_.

- Minor improvements to the HTML report:

  - The state of the line visibility selector buttons is saved in local storage
    so you don't have to fiddle with them so often, fixing `issue 1123`_.

  - It has a little more room for line numbers so that 4-digit numbers work
    well, fixing `issue 1124`_.

- Improved the error message when combining line and branch data, so that users
  will be more likely to understand what's happening, closing `issue 803`_.

.. _issue 803: https://github.com/coveragepy/coveragepy/issues/803
.. _issue 955: https://github.com/coveragepy/coveragepy/issues/955
.. _issue 1065: https://github.com/coveragepy/coveragepy/issues/1065
.. _issue 1108: https://github.com/coveragepy/coveragepy/issues/1108
.. _pull request 1110: https://github.com/coveragepy/coveragepy/pull/1110
.. _issue 1123: https://github.com/coveragepy/coveragepy/issues/1123
.. _issue 1124: https://github.com/coveragepy/coveragepy/issues/1124


.. _changes_54:

Version 5.4 — 2021-01-24
------------------------

- The text report produced by ``coverage report`` now always outputs a TOTAL
  line, even if only one Python file is reported.  This makes regex parsing
  of the output easier.  Thanks, Judson Neer.  This had been requested a number
  of times (`issue 1086`_, `issue 922`_, `issue 732`_).

- The ``skip_covered`` and ``skip_empty`` settings in the configuration file
  can now be specified in the ``[html]`` section, so that text reports and HTML
  reports can use separate settings.  The HTML report will still use the
  ``[report]`` settings if there isn't a value in the ``[html]`` section.
  Closes `issue 1090`_.

- Combining files on Windows across drives now works properly, fixing `issue
  577`_.  Thanks, `Valentin Lab <pr1080_>`_.

- Fix an obscure warning from deep in the decimal module, as reported in
  `issue 1084`_.

- Update to support Python 3.10 alphas in progress, including `PEP 626: Precise
  line numbers for debugging and other tools <pep626_>`_.

.. _issue 577: https://github.com/coveragepy/coveragepy/issues/577
.. _issue 732: https://github.com/coveragepy/coveragepy/issues/732
.. _issue 922: https://github.com/coveragepy/coveragepy/issues/922
.. _issue 1084: https://github.com/coveragepy/coveragepy/issues/1084
.. _issue 1086: https://github.com/coveragepy/coveragepy/issues/1086
.. _issue 1090: https://github.com/coveragepy/coveragepy/issues/1090
.. _pr1080: https://github.com/coveragepy/coveragepy/pull/1080
.. _pep626: https://www.python.org/dev/peps/pep-0626/


.. _changes_531:

Version 5.3.1 — 2020-12-19
--------------------------

- When using ``--source`` on a large source tree, v5.x was slower than previous
  versions.  This performance regression is now fixed, closing `issue 1037`_.

- Mysterious SQLite errors can happen on PyPy, as reported in `issue 1010`_. An
  immediate retry seems to fix the problem, although it is an unsatisfying
  solution.

- The HTML report now saves the sort order in a more widely supported way,
  fixing `issue 986`_.  Thanks, Sebastián Ramírez (`pull request 1066`_).

- The HTML report pages now have a :ref:`Sleepy Snake <sleepy>` favicon.

- Wheels are now provided for manylinux2010, and for PyPy3 (pp36 and pp37).

- Continuous integration has moved from Travis and AppVeyor to GitHub Actions.

.. _issue 986: https://github.com/coveragepy/coveragepy/issues/986
.. _issue 1037: https://github.com/coveragepy/coveragepy/issues/1037
.. _issue 1010: https://github.com/coveragepy/coveragepy/issues/1010
.. _pull request 1066: https://github.com/coveragepy/coveragepy/pull/1066


.. _changes_53:

Version 5.3 — 2020-09-13
------------------------

- The ``source`` setting has always been interpreted as either a file path or a
  module, depending on which existed.  If both interpretations were valid, it
  was assumed to be a file path.  The new ``source_pkgs`` setting can be used
  to name a package to disambiguate this case.  Thanks, Thomas Grainger. Fixes
  `issue 268`_.

- If a plugin was disabled due to an exception, we used to still try to record
  its information, causing an exception, as reported in `issue 1011`_.  This is
  now fixed.

.. _issue 268: https://github.com/coveragepy/coveragepy/issues/268
.. _issue 1011: https://github.com/coveragepy/coveragepy/issues/1011


.. endchangesinclude

Older changes
-------------

The complete history is available in the `coverage.py docs`__.

__ https://coverage.readthedocs.io/en/latest/changes.html
