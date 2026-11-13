- Fix: with the C tracer and branch coverage, an error while starting to trace
  a function call (for example, an exception raised while locking the data)
  left the previous call's file in place. If the exception was caught, the
  function's return recorded arcs in that other file, which could report lines
  as executed that never ran. Now a call that fails to start records nothing,
  closing `issue 2385`_.

.. _issue 2385: https://github.com/coveragepy/coveragepy/issues/2385
