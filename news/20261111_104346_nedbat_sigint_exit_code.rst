- Fix: with ``patch = subprocess`` on Python 3.13, a measured subprocess
  stopped with SIGINT exited with status 1 instead of dying from the signal.
  This was a regression in 7.17.1, and is now fixed, closing `issue 2362`_.

.. _issue 2362: https://github.com/coveragepy/coveragepy/issues/2362
