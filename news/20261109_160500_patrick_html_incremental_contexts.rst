- Fix: with ``[html] show_contexts`` enabled, re-running the HTML report kept
  pages whose lines were unchanged, even when the contexts were different, so
  they showed stale contexts. Closes `issue 2372`_.

.. _issue 2372: https://github.com/coveragepy/coveragepy/issues/2372
