- Fix: when ``[html] show_contexts`` was enabled, an HTML page could be reused
  with context names from an earlier run if the source and line/arc data were
  unchanged. Pages are now regenerated when the contexts change. Fixes
  `issue 2372`_.

.. _issue 2372: https://github.com/coveragepy/coveragepy/issues/2372
