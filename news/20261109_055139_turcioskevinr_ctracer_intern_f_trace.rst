- Perf: on Python 3.13 and later, the C tracer no longer creates and interns
  the ``"f_trace"`` attribute name on every function call. In real-world test
  suites measured with the ctrace core, this reduces total run time by about
  8% to 12%.
