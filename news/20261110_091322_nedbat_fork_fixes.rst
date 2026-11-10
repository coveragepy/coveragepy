- Fix: using ``patch = fork``, a child process wasn't measured unless ``patch =
  subprocess`` was also used, as described in `issue 2340`_.  This is now fixed
  in `pull 2342`_.

.. _issue 2340: https://github.com/coveragepy/coveragepy/issues/2340
.. _pull 2342: https://github.com/coveragepy/coveragepy/pull/2342
