# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Tokenize fixed real source, so implementation changes don't change inputs."""

from __future__ import annotations

import pytest

from coverage.phystokens import source_token_lines
from tests.benchmarks.helpers import Benchmark
from tests.benchmarks.corpora import CORPORA, load_corpus

pytestmark = [pytest.mark.benchmark]


@pytest.mark.benchmark(group="tokenize")
@pytest.mark.parametrize("corpus", list(CORPORA))
def test_source_token_lines(bench: Benchmark, corpus: str) -> None:
    sources, metadata = load_corpus(corpus)
    bench.extra_info.update(metadata)

    def tokenize_all() -> int:
        return sum(1 for source in sources for _ in source_token_lines(source))

    assert bench(tokenize_all) == sum(len(source.splitlines()) for source in sources)
