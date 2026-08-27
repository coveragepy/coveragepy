# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Benchmarks for source tokenization.

Unlike the other benchmarks, these use real source: coverage.py's own files,
which is what the HTML report has to tokenize in practice.

"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING

import pytest

from coverage.phystokens import source_token_lines

from tests.helpers import all_our_source_files

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

pytestmark = [pytest.mark.benchmark]

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

CORPORA = ["phystokens", "parser_reporting", "our_source", "stress"]


@pytest.fixture(scope="session", name="corpus")
def corpus_source(request: pytest.FixtureRequest) -> list[str]:
    """The source text of one named corpus."""
    name: str = request.param
    if name == "our_source":
        return [text for _, text in all_our_source_files()]
    if name == "stress":
        return [(REPO_ROOT / "tests" / "stress_phystoken.tok").read_text(encoding="utf-8")]
    if name == "phystokens":
        paths = [REPO_ROOT / "coverage" / "phystokens.py"]
    else:
        paths = [
            REPO_ROOT / "coverage" / name
            for name in ["parser.py", "html.py", "report_core.py", "xmlreport.py"]
        ]
    return [path.read_text(encoding="utf-8") for path in paths]


@pytest.mark.benchmark(group="tokenize")
@pytest.mark.parametrize("corpus", CORPORA, indirect=True)
def test_source_token_lines(benchmark: BenchmarkFixture, corpus: list[str]) -> None:
    def tokenize_all() -> None:
        for source in corpus:
            for _ in source_token_lines(source):
                pass

    benchmark(tokenize_all)
