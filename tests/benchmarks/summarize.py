# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Render timing dispersion and independent memory measurements from JSON."""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any


def summarize(result: dict[str, Any]) -> str:
    """Keep sample counts and input identities visible, without regression gates."""
    lines = [
        "| Benchmark | Median (ms) | RSD | Rounds | Peak RSS (MiB) |",
        "|---|---:|---:|---:|---:|",
    ]
    for benchmark in result["benchmarks"]:
        stats = benchmark["stats"]
        memory = benchmark.get("extra_info", {}).get("peak_rss_bytes", {})
        rss = f"{memory['median'] / (1024 * 1024):.1f}" if memory.get("available") else "—"
        rsd = 100 * stats["stddev"] / stats["mean"] if stats["mean"] else 0
        name = benchmark["name"].replace("|", "\\|")
        lines.append(
            f"| {name} | {stats['median'] * 1000:.3f} | {rsd:.1f}% | {stats['rounds']} | {rss} |"
        )
    lines += [
        "",
        "RSD is standard deviation / mean within this run, not a confidence interval or a regression threshold.",
        "Workload versions, corpus hashes, environment details, and raw memory samples are included in the JSON artifact.",
    ]
    return "\n".join(lines)


def main() -> None:
    """Print a GitHub step summary for one results artifact."""
    result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(summarize(result))


if __name__ == "__main__":
    main()
