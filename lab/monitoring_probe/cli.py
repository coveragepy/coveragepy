"""CLI interface for the monitoring probe."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .generator import add_generate_parser
from .probe import MonitoringProbe, MonitoringRecording, format_recording


def cmd_record(args: argparse.Namespace) -> None:
    """Record monitoring events for snippets."""
    probe = MonitoringProbe()
    snippets_dir = Path(args.snippets_dir)
    output_dir = Path(args.output_dir) if args.output_dir else None

    vi = sys.version_info
    version_tag = f"{vi.major}.{vi.minor}.{vi.micro}"

    snippet_files = sorted(snippets_dir.glob("*.py"))
    if args.snippet:
        snippet_files = [f for f in snippet_files if f.stem == args.snippet]
        if not snippet_files:
            print(f"Snippet not found: {args.snippet}", file=sys.stderr)
            sys.exit(1)

    for snippet_file in snippet_files:
        source = snippet_file.read_text()

        # Check for version requirements in comments
        min_version = _parse_min_version(source)
        if min_version and sys.version_info[:2] < min_version:
            print(
                f"  SKIP {snippet_file.stem} "
                f"(requires Python {min_version[0]}.{min_version[1]}+)"
            )
            continue

        try:
            recording = probe.record(source, filename=snippet_file.name)
        except Exception as exc:
            print(f"  FAIL {snippet_file.stem}: {exc}", file=sys.stderr)
            continue

        print(
            f"  {snippet_file.stem}: "
            f"{len(recording.events)} events, "
            f"{len(recording.lines_executed)} lines, "
            f"{len(recording.arcs_executed)} arcs"
        )

        if output_dir is not None:
            version_dir = output_dir / version_tag
            version_dir.mkdir(parents=True, exist_ok=True)
            out_path = version_dir / f"{snippet_file.stem}.json"
            out_path.write_text(
                json.dumps(recording.to_dict(), indent=2) + "\n"
            )

    if output_dir:
        print(f"\nRecordings saved to {output_dir / version_tag}/")


def cmd_show(args: argparse.Namespace) -> None:
    """Pretty-print a recording."""
    path = Path(args.recording)
    data = json.loads(path.read_text())
    recording = MonitoringRecording.from_dict(data)
    print(format_recording(recording))


def cmd_diff(args: argparse.Namespace) -> None:
    """Compare recordings between two version directories."""
    dir_a = Path(args.dir_a)
    dir_b = Path(args.dir_b)

    files_a = {f.stem: f for f in dir_a.glob("*.json")}
    files_b = {f.stem: f for f in dir_b.glob("*.json")}

    all_names = sorted(set(files_a) | set(files_b))
    if not all_names:
        print("No recordings found.")
        return

    label_a = dir_a.name
    label_b = dir_b.name
    print(f"Comparing {label_a} vs {label_b}\n")

    changes = 0
    for name in all_names:
        if name not in files_a:
            print(f"  {name}: NEW in {label_b}")
            changes += 1
            continue
        if name not in files_b:
            print(f"  {name}: REMOVED in {label_b}")
            changes += 1
            continue

        rec_a = MonitoringRecording.from_dict(
            json.loads(files_a[name].read_text())
        )
        rec_b = MonitoringRecording.from_dict(
            json.loads(files_b[name].read_text())
        )

        events_same = len(rec_a.events) == len(rec_b.events) and all(
            a.event_type == b.event_type
            for a, b in zip(rec_a.events, rec_b.events)
        )
        lines_same = rec_a.lines_executed == rec_b.lines_executed
        arcs_same = rec_a.arcs_executed == rec_b.arcs_executed

        if events_same and lines_same and arcs_same:
            print(
                f"  {name}: IDENTICAL "
                f"({len(rec_a.events)} events, "
                f"{len(rec_a.lines_executed)} lines, "
                f"{len(rec_a.arcs_executed)} arcs)"
            )
        else:
            changes += 1
            print(f"  {name}: CHANGED")
            if not events_same:
                ev_types_a = [e.event_type for e in rec_a.events]
                ev_types_b = [e.event_type for e in rec_b.events]
                print(
                    f"    Events: {len(rec_a.events)} → {len(rec_b.events)}"
                )
                if ev_types_a != ev_types_b:
                    added = set(ev_types_b) - set(ev_types_a)
                    removed = set(ev_types_a) - set(ev_types_b)
                    if added:
                        print(f"    New event types: {added}")
                    if removed:
                        print(f"    Removed event types: {removed}")
            if not lines_same:
                added = rec_b.lines_executed - rec_a.lines_executed
                removed = rec_a.lines_executed - rec_b.lines_executed
                print(f"    Lines: {sorted(rec_a.lines_executed)} → {sorted(rec_b.lines_executed)}")
                if added:
                    print(f"      +{sorted(added)}")
                if removed:
                    print(f"      -{sorted(removed)}")
            if not arcs_same:
                added = rec_b.arcs_executed - rec_a.arcs_executed
                removed = rec_a.arcs_executed - rec_b.arcs_executed
                print(f"    Arcs changed:")
                if added:
                    print(f"      +{sorted(added)}")
                if removed:
                    print(f"      -{sorted(removed)}")
                if not lines_same or not arcs_same:
                    print(
                        "    ⚠ Coverage results differ — "
                        "tests may need version gates"
                    )

    print(f"\n{changes} difference(s) found." if changes else "\nAll identical.")


def _parse_min_version(source: str) -> tuple[int, int] | None:
    """Parse '# requires: 3.X+' from snippet source."""
    for line in source.splitlines():
        line = line.strip()
        if line.startswith("# requires:"):
            version_str = line.split(":", 1)[1].strip().rstrip("+")
            parts = version_str.split(".")
            if len(parts) >= 2:
                return (int(parts[0]), int(parts[1]))
    return None


def main(argv: list[str] | None = None) -> None:
    """Entry point for the monitoring probe CLI."""
    parser = argparse.ArgumentParser(
        prog="monitoring-probe",
        description="Probe and record CPython sys.monitoring behavior",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # record
    p_record = subparsers.add_parser(
        "record", help="Record monitoring events for snippets"
    )
    p_record.add_argument(
        "snippets_dir", help="Directory containing snippet .py files"
    )
    p_record.add_argument(
        "-o", "--output-dir", help="Directory to write recording JSON files"
    )
    p_record.add_argument(
        "--snippet", help="Record only this specific snippet (by stem name)"
    )
    p_record.set_defaults(func=cmd_record)

    # show
    p_show = subparsers.add_parser(
        "show", help="Pretty-print a recording"
    )
    p_show.add_argument("recording", help="Path to a recording JSON file")
    p_show.set_defaults(func=cmd_show)

    # diff
    p_diff = subparsers.add_parser(
        "diff", help="Compare recordings between two versions"
    )
    p_diff.add_argument("dir_a", help="First version recording directory")
    p_diff.add_argument("dir_b", help="Second version recording directory")
    p_diff.set_defaults(func=cmd_diff)

    # generate
    add_generate_parser(subparsers)

    args = parser.parse_args(argv)
    args.func(args)
