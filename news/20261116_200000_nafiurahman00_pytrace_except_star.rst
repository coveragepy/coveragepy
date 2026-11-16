- Fix: on Python 3.14 with the pure-Python tracer (``COVERAGE_CORE=pytrace``)
  and branch measurement, a function that returned right after an ``except*``
  handler recorded an arc with no line number. Reporting on the data then
  failed with a ``TypeError``. Now that arc is not recorded.
