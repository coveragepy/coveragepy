- Fix: with the sysmon core on Python 3.14, starting and stopping a second
  Coverage object stopped the first one from measuring code it had already
  run. Closes `issue 2302`_.

.. _issue 2302: https://github.com/coveragepy/coveragepy/issues/2302
