# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Collect independent memory samples separately from timing samples."""

from __future__ import annotations

import json
import pathlib
import statistics
import sys
from collections.abc import Callable
from typing import Any

from tests.benchmarks.helpers import run_subprocess


def memory_samples(
    command: list[str],
    workspace: pathlib.Path,
    env: dict[str, str],
    result: pathlib.Path,
    setup: Callable[[], Any],
    validate: Callable[[], Any],
) -> dict[str, Any]:
    """Use one child per sample so previous reports cannot contaminate its peak."""
    if sys.platform not in {"linux", "darwin"}:
        return {"available": False, "reason": "peak RSS normalization supports Linux and macOS"}
    samples = []
    for _ in range(3):
        setup()
        run_subprocess(command, workspace, env)
        validate()
        usage = json.loads(result.read_text(encoding="utf-8"))["peak_rss_bytes"]
        assert isinstance(usage, int) and usage > 0
        samples.append(usage)
    return {"available": True, "samples": samples, "median": statistics.median(samples)}
