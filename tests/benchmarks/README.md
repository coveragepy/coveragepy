# Benchmarks

Performance benchmarks for coverage.py's highest-leverage code paths, written
with [pytest-benchmark](https://pytest-benchmark.readthedocs.io/):

- measurement-time tracing overhead, for each core
- persistence into `CoverageData`, and combining many data files
- collection with dynamic contexts, and across multiprocessing workers
- source tokenization over coverage.py's own files
- analysis, and the text, HTML, XML, JSON and LCOV reports

Most benchmarks use synthetic Python packages generated at runtime, so they are
self-contained and exercise the same code paths on every machine.  The
tokenization benchmarks use coverage.py's real source.

## Running them

```bash
make bench
```

or directly:

```bash
python3 -m pytest -n0 --benchmarks -m benchmark tests/benchmarks
python3 -m pytest -n0 --benchmarks -m benchmark tests/benchmarks -k html
python3 -m pytest -n0 --benchmarks -m benchmark tests/benchmarks --benchmark-autosave
python3 -m pytest -n0 --benchmarks -m benchmark tests/benchmarks --benchmark-compare
```

Three things about that command line are not optional:

- **`--benchmarks`** is what makes this directory get collected at all.  Without
  it the benchmarks would run three times per interpreter in the regular test
  suite (once per core), which costs minutes and measures nothing.
- **`-n0`** turns off xdist, which is on by default in `addopts`.  pytest-benchmark
  silently disables itself when xdist is active: the benchmarks still *run*, but
  no timings are collected.
- **`-m benchmark`** overrides the `-m "not benchmark"` in `addopts`.

`make bench` also passes `-m "benchmark and not slow"`, which leaves out the
multiprocessing benchmarks.  They spawn 8 interpreters 32 times and mostly
measure process start-up.  Run them with `-m "benchmark and slow"`.

## Don't run them through igor

Run benchmarks as plain pytest, never via `python3 igor.py test_with_core`.
Igor sets `COVERAGE_TESTING=True`, which turns on a per-AST-node check in the
parser and extra path work in `inorout.py` — real code, but not the code anyone
else is running.  The benchmarks skip themselves if they detect it, or metacov.

## Interpreting the numbers

These are wall-clock measurements, so they only compare against themselves on
the same machine, ideally on an idle one.  The CI job records results as an
artifact for trends; it deliberately does not fail on a regression, because
shared GitHub runners swing far more than most real regressions do.  If we ever
want PR-level regression *gating*, `pytest-codspeed` measures instruction counts
instead and survives noisy runners.
