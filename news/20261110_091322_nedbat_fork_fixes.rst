..
..  Write an entry for CHANGES.rst. Include a prefix like "Fix:" or "Perf:".
..  When linking to an issue, use syntax like:
..
..      - Fix: we used to be bad. This is now fixed, closing `issue 1234`_.
..
..      .. _issue 1234: https://github.com/coveragepy/coveragepy/issues/1234
..

- Fix: using ``patch = fork``, a child process wasn't measured unless ``patch =
  subprocess`` was also used.  This is now fixed in `pull 2342`_.

.. _pull 2342: https://github.com/coveragepy/coveragepy/pull/2342
