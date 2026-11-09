- Performance: the C tracer used to take its data lock on every call into a
  measured file. Now it takes it only the first time it records a file, making
  call-heavy code noticeably faster to measure. Thanks to `Kevin Turcios
  <pull 2378_>`_.

.. _pull 2378: https://github.com/coveragepy/coveragepy/pull/2378
