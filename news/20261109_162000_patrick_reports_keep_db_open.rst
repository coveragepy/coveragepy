- Perf: the text, XML, JSON, LCOV and annotate reports now keep the data file
  open while reporting, as the HTML report already did, instead of reconnecting
  to the database several times per file.
