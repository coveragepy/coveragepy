- Fix: combining data files failed with "Conflicting file tracer name" when
  one data file only listed a file without measuring it (as unexecuted source
  files are) and another measured the same file with a plugin. This happened
  in pytest-cov's distributed testing.  Now a file with no measurements doesn't
  conflict with a plugin's measurements.  Fixes `issue 2358`_.

.. _issue 2358: https://github.com/coveragepy/coveragepy/issues/2358
