- Fix: in the JSON report with ``show_contexts``, each function and class had
  the contexts for every line in the file. Now they only have the contexts for
  their own lines. Closes `issue 2374`_.

.. _issue 2374: https://github.com/coveragepy/coveragepy/issues/2374
