# Threat model for coverage.py

## What this project does and where untrusted input enters

coverage.py measures code coverage of Python programs.  It runs (or is started
inside) a Python process, records which lines and branches execute, stores the
results in a SQLite data file (`.coverage`), and produces reports in text,
HTML, XML (Cobertura), JSON, LCOV, and annotated-source formats.

coverage.py runs with the full privileges of the program being measured.  By
design, the following are **trusted** and are not security boundaries:

- The Python code being measured.  coverage.py executes it (`coverage run`) and
  imports it.
- Configuration files (`.coveragerc`, `setup.cfg`, `tox.ini`,
  `pyproject.toml`) and command-line arguments.
- Plugins named in configuration.  They are imported and run as ordinary
  Python code.
- Environment variables (`COVERAGE_*`, etc.).
- The `.pth` file coverage.py may install to measure subprocesses.

Inputs that can reasonably be **less trusted** than the person running
coverage:

- **Source file contents and file names.**  Reports are often generated in CI
  for pull requests from outside contributors and then published (for example
  HTML reports hosted on a web site, or XML/LCOV consumed by other services).
  Source text, file paths, function and class names, and context labels flow
  into report output.  These must not be able to inject markup or script into
  HTML reports, break the structure of XML/JSON/LCOV output, or inject terminal
  control sequences into text output.
- **Data files from other machines.**  `coverage combine` reads `.coverage.*`
  SQLite files that are often collected from many CI jobs or downloaded as
  artifacts.  A malformed or malicious data file should produce an error, not
  memory corruption, code execution, writing outside of the expected
  directories, or unbounded resource use beyond the size of the input.
- **Path remapping during combine and reporting** (`[paths]` settings) applied
  to file names recorded in data files.

## Components that matter most / least

Most important:

- `coverage/ctracer/` — the C extension tracer (`coverage.tracer`).  It is
  called on every line event of the measured program.  Memory-safety bugs here
  (reference-counting errors, use-after-free, buffer overflows) are the highest
  priority.
- `coverage/html.py`, `coverage/templite.py`, and `coverage/htmlfiles/` — HTML
  report generation and escaping.
- `coverage/xmlreport.py`, `coverage/jsonreport.py`, `coverage/lcovreport.py`,
  `coverage/report.py`, `coverage/annotate.py` — other report writers.
- `coverage/sqldata.py`, `coverage/sqlitedb.py`, `coverage/numbits.py`,
  `coverage/data.py` — reading, writing, and combining data files.
- `coverage/files.py` — path handling, globbing, and remapping.
- `coverage/phystokens.py`, `coverage/parser.py` — tokenizing and parsing
  source files for reports.

Less important:

- `coverage/pytracer.py` and `coverage/sysmon.py` — pure-Python tracers; bugs
  here are usually correctness issues, not security issues.
- `coverage/execfile.py`, `coverage/plugin_support.py`, `coverage/config.py`,
  `coverage/tomlconfig.py` — they process trusted input by design.

Out of scope:

- `lab/`, `ci/`, `doc/`, `igor.py`, and `tests/` — developer tooling, not
  shipped in the package.
- The vendored JavaScript and CSS in `coverage/htmlfiles/` beyond how
  coverage.py fills in the data it renders.

## How to exercise it

- The checkout is in `/src`.  The project is installed editable in the tox
  environment `/src/.tox/py313`, which is first on `PATH`, with the C
  extension built in place.  `coverage` is the command-line entry point.
- `tox -e py313` runs the full test suite with each tracer: the C tracer
  (`ctrace`), the Python tracer (`pytrace`), and `sys.monitoring` (`sysmon`).
  It removes the C extension to test the other tracers; rebuild it with
  `python setup.py build_ext --inplace`.
- `python igor.py test_with_core ctrace` runs the tests with just the C
  tracer.  Standard pytest arguments can be added, for example `-k html`.
- Typical flow to produce reports from a program:
  `coverage run --branch prog.py && coverage html && coverage xml && coverage json && coverage lcov`.
- To exercise combining: create several data files with `coverage run -p` and
  run `coverage combine`.
- Tests that need network access or a non-root user are skipped or marked
  xfail.

## How you rate severity

- Memory corruption in the C tracer that a measured program can trigger
  through ordinary Python code: high.  (The measured program is trusted, but
  coverage.py should never crash it.)
- Script or markup injection into HTML reports from source contents, file
  names, or data files: high.
- Code execution, or reading/writing files outside the expected locations,
  triggered by a crafted data file during combine or reporting: high.
- Corrupting the structure of XML, JSON, or LCOV output, or terminal control
  sequence injection in text output: medium.
- Crashes or excessive resource use from malformed data files: low.
- Anything that requires control of configuration, plugins, environment
  variables, or the measured code itself to cause effects that code could
  already cause directly: not a vulnerability.

## Anything to leave alone

- Use of `exec`, `compile`, and imports to run the measured program and
  plugins is intentional.
- Non-cryptographic hashing (for example for file fingerprints) is
  intentional and is marked `usedforsecurity=False`.
- SQL in `sqldata.py` is built from internal constants; table and column names
  are not user-controlled.
