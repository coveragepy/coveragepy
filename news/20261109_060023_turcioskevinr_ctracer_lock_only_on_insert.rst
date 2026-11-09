- Perf: the C tracer now takes the data lock only when it starts recording a
  new file, instead of on every call into a measured file. Call-heavy code
  measured with the ctrace core runs noticeably faster.
