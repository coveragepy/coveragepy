- Fix: a configuration file (``.coveragerc``, ``setup.cfg``, ``tox.ini`` or
  ``pyproject.toml``) saved with a UTF-8 byte order mark couldn't be read.
  Now a leading BOM is ignored. `pull 2388`_.

.. _pull 2388: https://github.com/coveragepy/coveragepy/pull/2388
