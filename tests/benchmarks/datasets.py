# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Database workloads with known unions, density, and path identities."""

from __future__ import annotations

import pathlib
from dataclasses import dataclass
from typing import Any

from coverage import CoverageData
from coverage.files import PathAliases

DataValues = dict[str, set[Any]]


def add_values(data: CoverageData, values: DataValues, branch: bool) -> None:
    """Write either of CoverageData's two representations."""
    if branch:
        data.add_arcs(values)
    else:
        data.add_lines(values)


def read_values(data: CoverageData, branch: bool) -> DataValues:
    """Read public data for comparison with the intended workload."""
    return {
        filename: set((data.arcs(filename) if branch else data.lines(filename)) or [])
        for filename in data.measured_files()
    }


@dataclass
class CombineDataset:
    """Prepared shards plus an independently accumulated expected union."""

    basename: str
    aliases: PathAliases
    expected: dict[str, DataValues]
    branch: bool
    shard_count: int

    def validate(self, data: CoverageData) -> None:
        """Check context membership, values, and canonical file names."""
        assert data.has_arcs() == self.branch
        assert data.measured_contexts() == set(self.expected)
        for context, values in self.expected.items():
            data.set_query_context(context)
            actual = {f: v for f, v in read_values(data, self.branch).items() if v}
            assert actual == values
        data.set_query_contexts(None)


def make_combine_dataset(
    root: pathlib.Path,
    profile: str,
    branch: bool,
    *,
    file_count: int = 80,
    shards: int | None = None,
) -> CombineDataset:
    """Build dense, sparse-context, or remapped shards without timing setup."""
    root = root.resolve()
    data_dir = root / "parts"
    data_dir.mkdir()
    source = root / "source"
    source.mkdir()
    names = [f"mod_{idx:03d}.py" for idx in range(file_count)]
    for name in names:
        (source / name).write_text("value = 1\n" * 220, encoding="utf-8")
    basename = str(data_dir / ".coverage")
    aliases = PathAliases()
    expected: dict[str, DataValues] = {}
    shard_count = shards or (48 if profile == "contexts_sparse" else 24)
    for shard in range(shard_count):
        path_root = source
        if profile == "remap":
            path_root = root / f"agent_{shard}" / "src"
            aliases.add(str(path_root), str(source))
        data = CoverageData(basename=basename, suffix=f"part{shard:03d}")
        contexts = range(shard % 10, 200, 10) if profile == "contexts_sparse" else [-1]
        for context in contexts:
            label = "" if context == -1 else f"test_{context:04d}"
            data.set_context(label)
            indices = (
                {(context + offset) % file_count for offset in range(4)}
                if context >= 0
                else set(range(file_count))
            )
            values: DataValues = {}
            for idx in sorted(indices):
                start = 1 + (shard % 5) * 2
                lines = set(range(start, start + (4 if context >= 0 else 200)))
                points: set[Any] = {(line, line + 1) for line in lines} if branch else set(lines)
                values[str(path_root / names[idx])] = points
                expected.setdefault(label, {}).setdefault(str(source / names[idx]), set()).update(
                    points
                )
            add_values(data, values, branch)
        data.write()
        data.close()
    return CombineDataset(basename, aliases, expected, branch, shard_count)
