# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""A fresh-process command runner, also used for independent peak-RSS samples."""

from __future__ import annotations

import argparse
import json
import pathlib
import runpy
import sys
from unittest.mock import patch
from typing import Any


def rss_bytes(value: int, platform: str) -> int | None:
    """Linux reports KiB; macOS reports bytes. Other systems are not inferred."""
    if platform == "linux":
        return value * 1024
    if platform == "darwin":
        return value
    return None


def peak_rss() -> int | None:
    """Measure this child, never the parent's accumulated child-process peak."""
    if sys.platform not in {"linux", "darwin"}:
        return None
    import resource  # pylint: disable=import-outside-toplevel

    return rss_bytes(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, sys.platform)


def main() -> None:
    """Run pytest or a coverage command and emit machine-readable validation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["pytest", "run", "report"])
    parser.add_argument("--result", type=pathlib.Path, required=True)
    parser.add_argument("--rcfile", type=pathlib.Path, required=True)
    parser.add_argument("--junit", type=pathlib.Path)
    parser.add_argument("--format", choices=["report", "html", "json"], default="report")
    parser.add_argument("--rss", action="store_true")
    args = parser.parse_args()
    actual_cores: list[str] = []
    metadata: dict[str, Any] = {"python": sys.version, "actual_cores": actual_cores}
    pytest_args = ["-q", "-o", "addopts=", "--junitxml", str(args.junit), "tests"]
    status = 0
    try:
        if args.mode == "pytest":
            sys.argv = ["pytest", *pytest_args]
            try:
                runpy.run_module("pytest", run_name="__main__")
            except SystemExit as exc:
                status = int(exc.code or 0)
        else:
            from coverage import Coverage  # pylint: disable=import-outside-toplevel
            from coverage.cmdline import main as coverage_main  # pylint: disable=import-outside-toplevel
            import coverage  # pylint: disable=import-outside-toplevel

            expected_root = pathlib.Path(__file__).resolve().parents[2]
            assert pathlib.Path(coverage.__file__).resolve().parent == expected_root / "coverage"
            metadata["coverage_file"] = coverage.__file__
            original_start = Coverage.start

            def checked_start(cov: Coverage) -> None:
                original_start(cov)
                assert cov._collector is not None
                actual_cores.append(cov._collector.tracer_name())

            if args.mode == "run":
                with patch.object(Coverage, "start", checked_start):
                    status = (
                        coverage_main(
                            ["run", f"--rcfile={args.rcfile}", "-m", "pytest", *pytest_args]
                        )
                        or 0
                    )
            else:
                status = coverage_main([args.format, f"--rcfile={args.rcfile}"]) or 0
    finally:
        metadata["exit_status"] = status
        if args.rss:
            metadata["peak_rss_bytes"] = peak_rss()
        args.result.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(status)


if __name__ == "__main__":
    main()
