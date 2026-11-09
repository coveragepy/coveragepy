- Perf: saving branch coverage data spent most of its time computing the data
  file hash one arc at a time. The arcs are now hashed in a single call, which
  makes saving data noticeably faster, especially with dynamic contexts.
