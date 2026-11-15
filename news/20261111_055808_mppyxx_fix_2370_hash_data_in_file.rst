- Fix: since 7.13.1, a parallel data file could be named with the hash of
  different data than it held, for example when nbval records a notebook's
  coverage into pytest-cov's data file. Combining could then skip it as a
  duplicate and lose its data. Now the hash comes from the data in the file
  when it is saved. Fixes `issue 2370`_ with `pull 2387`_.

.. _issue 2370: https://github.com/coveragepy/coveragepy/issues/2370
.. _pull 2387: https://github.com/coveragepy/coveragepy/pull/2387
