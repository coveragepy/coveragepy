- Perf: the HTML, JSON, and LCOV reports no longer parse each file a second
  time to find its functions and classes, making them about 10% to 35% faster.
  The HTML report without branch coverage also kept every file's parsed code
  until the report finished, so its memory use grew with the size of the
  project. Now it's released as each file is collected, using up to 60% less
  memory on large projects. `pull 2399`_.

.. _pull 2399: https://github.com/coveragepy/coveragepy/pull/2399
