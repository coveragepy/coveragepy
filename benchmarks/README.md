# ASV Benchmarks

This directory contains Airspeed Velocity benchmarks for the highest-leverage
coverage.py performance paths:

- measurement-time tracing overhead
- persistence into `CoverageData`
- source tokenization over representative coverage.py files
- analysis and text reporting
- HTML report generation, with and without contexts

Typical commands:

```bash
python -m pip install asv
asv run
asv run --bench TimeMeasurement
asv run --bench TimePersistence
asv run --bench TimeSourceTokens
asv run --bench TimeReport
```

Most benchmarks use synthetic Python packages generated at runtime so they stay
self-contained and exercise the same code paths on every machine. The source
tokenization benchmark uses representative files from the coverage.py package
itself.
