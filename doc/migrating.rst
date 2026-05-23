.. Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
.. For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

.. _migrating:

==========================
Migrating between versions
==========================

New versions of coverage.py or Python might require you to adjust your
settings, options, or other aspects of how you use coverage.py.  This page
details those changes.

.. _migrating_cov7x:

Migrating to coverage.py 7.x
----------------------------

Consider these changes when migrating to coverage.py 7.x:

- The way that wildcards when specifying file paths work in certain cases has
  changed in 7.x:

  - Previously, ``*`` would incorrectly match directory separators, making
    precise matching difficult. Patterns such as ``*tests/*``
    will need to be changed to ``*/tests/*``.

  - ``**`` now matches any number of nested directories. If you wish to retain
    the behavior of ``**/tests/*`` in previous versions then  ``*/**/tests/*``
    can be used instead.

- When remapping file paths with ``[paths]``, a path will be remapped only if
  the resulting path exists. Ensure that remapped ``[paths]`` exist when
  upgrading as this is now being enforced.

- The :ref:`config_report_exclude_also` setting is new in 7.2.0.  It adds
  exclusion regexes while keeping the default built-in set. It's better than
  the older :ref:`config_report_exclude_lines` setting, which overwrote the
  entire list.  Newer versions of coverage.py will be adding to the default set
  of exclusions.  Using ``exclude_also`` will let you benefit from those
  updates.


.. _migrating_cov62:

Migrating to coverage.py 6.2
----------------------------

- The ``--concurrency`` settings changed in 6.2 to be a list of values.  You
  might need to explicitly list concurrency options that we previously implied.
  For example, ``--concurrency=multiprocessing`` used to implicitly enable
  thread concurrency.  Now that must be explicitly enabled with
  ``--concurrency=multiprocessing,thread``.


.. _migrating_py312:

Migrating to Python 3.12
------------------------

Keep these things in mind when running under Python 3.12:

- Python 3.12 now inlines list, dict, and set comprehensions.  Previously, they
  were compiled as functions that were called internally.  Coverage.py would
  warn you if comprehensions weren't fully completed, but this no longer
  happens with Python 3.12.
