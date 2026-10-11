# Benchmarks

This suite measures both individual coverage.py operations and a pinned real
project's test-and-report workflow. The ordinary workloads are generated locally
or read from fixed source snapshots. The real-project suite is prepared
explicitly and runs separately.

## Run component benchmarks

```bash
make bench
make bench ARGS='-k html'
make bench ARGS='--benchmark-autosave'
make bench ARGS='--benchmark-compare'
```

The equivalent pytest command is:

```bash
python3 -m pytest -n0 --benchmarks -m 'benchmark and not slow' \
    tests/benchmarks --benchmark-min-rounds=10 --benchmark-max-time=3
```

`--benchmarks` enables collection, `-n0` enables serial timing, and the marker
expression overrides the ordinary test suite's `not benchmark` default.
Benchmarks fail explicitly if xdist is active. They skip under `COVERAGE_TESTING`
or metacov, which change the work being measured. Run them with plain pytest,
without going through igor's test instrumentation.

For a correctness-only smoke run, including slow component workloads:

```bash
python3 -m pytest -n0 --benchmarks --bench-smoke \
    -m 'benchmark and not real_project' tests/benchmarks
```

Smoke mode executes each workload once and runs its validation. It records no
performance samples. `--benchmark-disable` also preserves the validation.

## Workload inventory

| Group | Inputs and timed work |
| --- | --- |
| Tracing | Line/branch coverage with every available core: repeated loops, frequent calls, imports plus first execution, and generators/async execution. Helper code is excluded to exercise filtering. |
| Contexts | 10 or 500 contexts, automatic `test_function` or explicit `switch_context()`, C and Python tracers. Each context visits a small overlapping set of modules. |
| Persistence | Fresh insertion and updates to existing databases; dense and sparse line/arc sets across 80 files. |
| Combination | Context-free dense data, sparse context-rich data, and path remapping from multiple agents. Inputs contain 24 or 48 shards; context-rich inputs contain 200 contexts. |
| Unused source | 800 importable, unexecuted files, including discovery and saving them as uncovered. |
| Reporting | 80 modules with four source shapes and full, partial, unexecuted, and excluded code. Text, HTML, XML, JSON, and LCOV outputs. |
| HTML | Empty output directories, contexts and context selection, a large module, unchanged output, one populated source change, and one data-only change. |
| Tokenization | Verified snapshots of real source and the tokenizer stress fixture. |
| Slow components | Eight multiprocessing workers handling 32 tasks; reports over 400 modules; fresh-process reporting and peak memory. |

The tests verify the intended work outside timing: discovered unused files,
requested cores, context membership and filtering, database unions and canonical
paths, worker coverage, and which HTML pages are regenerated. Multiprocessing
waits for every worker to execute work and shuts the pool down gracefully before
checking or combining data.

Tracing benchmarks generally exclude imports from timing; the explicit import
scenario includes them. Coverage start/stop is timed. Ordinary report benchmarks
use an already loaded database; fresh-process cases also include interpreter
startup, coverage imports, and data loading. Input generation, output cleanup,
and validation are outside the timed region.

## Sampling and comparisons

Setup-dependent benchmarks use ten measured rounds and one warmup. Slow cases
use five measured rounds and one warmup. Override either with `--bench-rounds`:

```bash
make bench ARGS='--bench-rounds=25 --benchmark-max-time=10'
```

`--benchmark-min-rounds` and `--benchmark-max-time` control the plugin's calibrated
benchmarks. They do not override setup-dependent (`pedantic`) sampling. Garbage
collection retains pytest-benchmark's default behavior.

All result names include `[workload-v2]`, and JSON metadata records the workload
version and scenario details. The frozen tokenizer corpus has source revision,
file size, and SHA-256 metadata in `corpus/manifest.json`. Updating it is an
intentional workload change: preserve license notices, update hashes, and bump
the workload version. Do not compare different input versions as a speed change.

Compare results on the same machine and Python build. The CI summary includes
median time, relative standard deviation, and sample count; these do not measure
variation between different CI machines. Investigate noisy cases and repeat
baseline/head measurements before claiming a small improvement. No wall-clock
regression threshold is imposed.

## Prepare and run the real project

Use Python 3.14 for these commands:

```bash
make bench-prepare
make bench-real ARGS='--benchmark-json=.benchmarks/jinja-results.json'
make bench-real ARGS='--bench-smoke'
```

Preparation downloads Jinja2 3.1.6 from the pinned archive URL, verifies its
SHA-256, and creates an isolated environment using `requirements/benchmarks-real.txt`.
It also installs this checkout editably, building its C extension. Repeat
preparation after changing dependencies, Python, or the C implementation.
Preparation is the only step that requires network access; benchmark execution
verifies the cached source and requirements and fails with instructions if they
are missing or stale. Prepared files live under `.benchmarks/real/`.

The workload executes all 909 Jinja2 tests, first uninstrumented and then under
line/branch coverage with each core. Every covered sample must execute the same
test identities as the baseline, without unexpected skips or failures. Separate
text, HTML, and JSON commands use previously collected branch data. Source
selection measures Jinja2 itself, while pytest and its dependencies still run as
excluded code.

Each scenario uses a private source copy. Bytecode is prepared consistently and
a baseline preflight warms pytest's assertion-rewritten bytecode before samples.
The process runner adds the same small harness startup to test measurements,
verifies the coverage checkout/core, and writes validation metadata. Project
revision, archive digest, dependency versions, and test counts accompany results.
This is one representative template-engine suite, not a universal application
performance score.

## Memory measurements

Slow fresh-process HTML/JSON benchmarks over 400 modules and real-project reports
collect three additional memory samples after timing. Each sample starts a new
interpreter and reads that process's peak RSS, avoiding peaks left by earlier
reports in the benchmark runner. Linux KiB and macOS bytes are normalized to
bytes. Other platforms record memory measurements as unavailable.

`extra_info.peak_rss_bytes` contains the individual samples and their median.
Peak RSS includes interpreter startup, imports, data loading, and reporting;
it is not incremental allocation size. Memory collection is omitted in smoke
mode. CI shows the median in MiB and retains the raw samples in JSON.

## CI and maintenance

Relevant pull requests run ordinary component timings and Python 3.10/3.15 Linux
and Python 3.14 macOS smoke checks. A weekly/manual extended job prepares Jinja2
and runs real-project, multiprocessing, large-project, and memory cases. Manual
runs bypass the changed-file gate. Results are informational artifacts with a
step summary; failed workload assertions still fail the job.

Tiny workload regression tests live in `tests/test_benchmarks.py` and run with the
ordinary suite. Benchmark modules remain opt-in, including when an individual
benchmark file is named explicitly without `--benchmarks`.
