- Perf: the HTML report no longer parses each file a second time to find the
  lines with soft keywords like ``match`` and ``case``, if the file has
  already been parsed for analysis. `pull 2406`_.

.. _pull 2406: https://github.com/coveragepy/coveragepy/pull/2406
