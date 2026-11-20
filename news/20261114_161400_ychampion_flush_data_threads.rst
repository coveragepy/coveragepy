- Fix: lines or arcs recorded by other threads while data was being flushed
  (for example during ``Coverage.get_data()``, ``Coverage.save()``, or dynamic
  context switches) could be lost. This is now fixed, closing `issue 2384`_.

.. _issue 2384: https://github.com/coveragepy/coveragepy/issues/2384
