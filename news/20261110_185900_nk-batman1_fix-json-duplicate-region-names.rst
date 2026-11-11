- Fix: the JSON report keys functions and classes by name, but names can
  repeat, for example a property getter and setter. Only the last one was
  kept, so the others were missing from the report. Now repeated names get a
  ``@<line number>`` suffix, as in the LCOV report. `pull 2353`_.

.. _pull 2353: https://github.com/coveragepy/coveragepy/pull/2353
