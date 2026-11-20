- Fix: in the "Missing" column of ``coverage report``, a range of missing lines
  could run across excluded lines, so ``2-5`` was shown when lines 3 and 4 were
  excluded, not missing, as described in `issue 1691`_.  Now excluded lines end
  a range, the same as executed lines do.  This is fixed in `pull 2331`_.

.. _issue 1691: https://github.com/coveragepy/coveragepy/issues/1691
.. _pull 2331: https://github.com/coveragepy/coveragepy/pull/2331
