- Performance: on Python 3.13 and later, the C tracer no longer creates the
  ``"f_trace"`` attribute name on every function call, which makes measuring
  real-world test suites about 8% to 12% faster (`pull 2371`_).

.. _pull 2371: https://github.com/coveragepy/coveragepy/pull/2371
