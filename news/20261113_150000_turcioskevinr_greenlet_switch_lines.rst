- Fix: with ``concurrency = greenlet``, ``gevent``, or ``eventlet``, lines that
  ran right after a switch to another greenlet were recorded in the file of the
  greenlet that switched away, or lost if that greenlet had finished, as in
  lines after ``gevent.joinall()``. Now coverage.py follows greenlet switches,
  closing `issue 841`_.

.. _issue 841: https://github.com/coveragepy/coveragepy/issues/841
