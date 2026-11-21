- Fix: the lcov report's function records started at the ``def`` line of
  each function.  That line is executed when the module is imported, even
  if the function is never called, so lcov rejected the report as
  inconsistent: the function was not hit, but its first line was.  Function
  records now start at the first line of the function body, where the line
  data agrees with the function data.  Fixes `issue 2394`_.

.. _issue 2394: https://github.com/coveragepy/coveragepy/issues/2394
