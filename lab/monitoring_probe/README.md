# monitoring-probe

A standalone tool that probes and records CPython's `sys.monitoring` behavior
for use in testing coverage.py's `sysmon.py` tracer.

## Why this exists

coverage.py's `SysMonitor` class (the default tracer on Python 3.14+) translates
`sys.monitoring` events into coverage data. Testing it is hard because:

- **Shallow mocks** test our assumptions about CPython, not reality.
- **Integration tests** (`check_coverage`) can't isolate whether a failure is in
  CPython's event delivery, SysMonitor's processing, or bytecode analysis.
- **CPython changes behavior between versions** — new events appear (BRANCH_RIGHT
  in 3.14), event sequences change, bytecode offsets shift.

This tool solves the problem by **recording what CPython actually does**, then
using those recordings to test SysMonitor in isolation.

## How it works

```
1. Record: Execute a snippet under sys.monitoring, capture every event
2. Save:   Write events + ground truth to versioned JSON files
3. Replay: Feed recorded events into SysMonitor's callbacks
4. Verify: Compare SysMonitor's output against the recording's ground truth
```

The probe uses its own tool_id (2) so it doesn't conflict with coverage.py
(which uses 1 or 3). It records every event without returning DISABLE, so
it sees the full event stream rather than just the first event per line.

## Quick start

All commands run from the `lab/` directory:

```bash
# Record events for all snippets on the current Python
python -m monitoring_probe record monitoring_probe/snippets/ -o recordings/

# Show what happened for a specific recording
python -m monitoring_probe show recordings/3.14.3/if_else.json

# Compare behavior between two Python versions
python -m monitoring_probe diff recordings/3.13.7/ recordings/3.14.3/

# Generate coverage.py test code from recordings
python -m monitoring_probe generate recordings/3.14.3/
```

## Commands

### `record`

Record `sys.monitoring` events for each snippet in a directory.

```
python -m monitoring_probe record <snippets-dir> [-o <output-dir>] [--snippet <name>]
```

- Executes each `.py` file under `sys.monitoring` and captures all events
- Derives ground truth (lines executed, arcs executed) from raw events
- Cross-validates against coverage.py if it's importable (recommended)
- Saves versioned JSON recordings to `<output-dir>/<python-version>/`
- Respects `# requires: 3.X+` comments in snippets

### `show`

Pretty-print a recording with annotated source and event timeline.

```
python -m monitoring_probe show <recording.json>
```

Output shows source lines marked with `*` for executed lines, followed by
the full event sequence and derived ground truth.

### `diff`

Compare recordings between two Python versions.

```
python -m monitoring_probe diff <dir-a> <dir-b>
```

Reports three levels of change:
- **IDENTICAL** — same events, same coverage results
- **Events changed, results same** — bytecode shifted but coverage is correct
- **Results changed** — coverage output differs; tests may need version gates

### `generate`

Generate coverage.py test code from recordings.

```
python -m monitoring_probe generate <recordings-dir> [--format check_coverage|replay_json] [-o <output>]
```

Two output formats:
- `check_coverage` (default) — generates `self.check_coverage()` test methods
  that use coverage.py's existing test infrastructure, no probe dependency at runtime
- `replay_json` — copies recordings for use with the replay harness in
  `tests/sysmon_harness.py`

## Snippets

The `snippets/` directory contains small, self-contained Python files that each
exercise a specific monitoring behavior:

| Snippet | What it exercises |
|---|---|
| `simple_lines.py` | Basic sequential execution |
| `if_else.py` | Simple conditional branching |
| `if_elif_else.py` | Multi-way branching |
| `for_loop.py` | Loop entry, body, exit arcs |
| `for_else.py` | Loop with else clause |
| `while_break_continue.py` | Loop control flow |
| `try_except.py` | Exception handling paths |
| `try_except_else_finally.py` | Full try structure |
| `try_nested.py` | Nested exception handling |
| `with_statement.py` | Context manager entry/exit |
| `with_multiple.py` | Multiple context managers |
| `generator_yield.py` | Yield/resume event sequences |
| `generator_yield_from.py` | Delegated generators |
| `generator_send.py` | Generator.send() behavior |
| `async_await.py` | Async function events |
| `match_case.py` | Structural pattern matching (3.10+) |
| `nested_functions.py` | Multiple code objects, closures |
| `class_definition.py` | Class body execution |
| `comprehensions.py` | Implicit code objects (list/dict/set/gen) |
| `decorators.py` | Decorator application order |
| `multiline_statements.py` | Multi-line if/with/call |
| `lambda_funcs.py` | Lambda code objects |
| `annotation_code.py` | `__annotate__` filtering (PEP 649, 3.14+) |
| `conditional_expr.py` | Ternary operator branching |
| `boolean_short_circuit.py` | `and`/`or` short-circuit evaluation |

To add a new snippet: create a `.py` file in `snippets/`, then re-record.
Use `# requires: 3.X+` on the first line if it needs a minimum Python version.

## Recording format

Each recording is a JSON file containing:

```json
{
    "python_version": [3, 14, 3, "final", 0],
    "source_code": "x = 1\nif x > 0:\n    y = 3\n...",
    "filename": "if_else.py",
    "events": [
        {"type": "PY_START", "code_name": "<module>", "offset": 0, ...},
        {"type": "LINE", "code_name": "<module>", "line": 1, ...},
        {"type": "BRANCH_LEFT", "code_name": "<module>", "offset": 14, "dest": 20, ...},
        ...
    ],
    "expected_lines": [1, 2, 3, 6],
    "expected_arcs": [[1, 1], [2, 2], [2, 3], [3, 3], [6, -1], [6, 6]]
}
```

- `events` — the exact sequence of `sys.monitoring` events CPython fired
- `expected_lines` — which source lines executed (ground truth for line coverage)
- `expected_arcs` — arcs in SysMonitor's format: self-arcs from LINE events,
  branch arcs from BRANCH events, exit arcs from PY_RETURN events

## What lives in coverage.py's test suite

The probe generates two things that go into `tests/`:

- **`tests/sysmon_harness.py`** (~195 lines) — a replay harness that feeds
  recorded events into SysMonitor's callbacks. Compiles the source to get
  real code objects, pre-populates caches to avoid frame access, and patches
  `sys_monitoring` to no-ops during replay.

- **`tests/sysmon_recordings/<version>/`** — versioned JSON recordings.
  The replay tests load the recording matching the current Python version
  and skip with a message if none exists or if bytecode offsets are stale.

- **`tests/test_sysmon.py`** — replay tests (25 snippets x 2 modes = 50 tests)
  plus lifecycle tests for SysMonitor's state management.

None of these import or depend on the probe tool at runtime.

## Workflow: new CPython version

When a new Python version ships (e.g., 3.16):

```bash
# 1. Record with the new Python
python3.16 -m monitoring_probe record monitoring_probe/snippets/ \
    -o /path/to/coveragepy/tests/sysmon_recordings

# 2. Diff against the previous version
python3.16 -m monitoring_probe diff \
    /path/to/coveragepy/tests/sysmon_recordings/3.15.0/ \
    /path/to/coveragepy/tests/sysmon_recordings/3.16.0/

# 3. Triage the diff:
#    - IDENTICAL: nothing to do
#    - Events changed, results same: commit new recordings
#    - Results changed: update tests with version gates
#    - New event types: evaluate if sysmon.py needs changes
```

## Workflow: modifying sysmon.py

After making changes to `coverage/sysmon.py`:

1. Run `python -m pytest tests/test_sysmon.py` — if replay tests fail, the
   change broke SysMonitor's event processing for known-good event sequences
2. Run the full test suite — if `check_coverage` tests fail, the change broke
   end-to-end coverage results
3. If the change was intentional, re-record to update ground truth

## Architecture

```
lab/monitoring_probe/
    __init__.py          # Package marker
    __main__.py          # python -m entry point
    probe.py             # MonitoringProbe class, recording data structures
    cli.py               # CLI: record, show, diff
    generator.py         # Test code generation
    snippets/            # Code patterns to probe (25 files)
```

The probe has **zero dependencies** beyond the Python stdlib. The optional
cross-validation step imports coverage.py if available but works without it.
