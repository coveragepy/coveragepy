- Fix: ``coverage lcov`` failed with "No data to report." when nothing had been
  measured, for example when no files in ``--source`` ran. Now an empty data
  file produces an empty LCOV file. Closes `issue 2054`_.

.. _issue 2054: https://github.com/coveragepy/coveragepy/issues/2054
