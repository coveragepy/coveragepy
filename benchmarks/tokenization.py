"""Benchmarks for source tokenization."""

from pathlib import Path

from coverage.phystokens import source_token_lines


REPO_ROOT = Path(__file__).resolve().parents[1]
CORPORA = {
    "phystokens": [REPO_ROOT / "coverage" / "phystokens.py"],
    "parser_reporting": [
        REPO_ROOT / "coverage" / "parser.py",
        REPO_ROOT / "coverage" / "html.py",
        REPO_ROOT / "coverage" / "report_core.py",
        REPO_ROOT / "coverage" / "xmlreport.py",
    ],
    "coverage_package": sorted((REPO_ROOT / "coverage").rglob("*.py")),
}


class TimeSourceTokens:
    """Measure tokenization over representative coverage.py source."""

    params = (list(CORPORA),)
    param_names = ["corpus"]

    def setup(self, corpus: str) -> None:
        self.sources = [path.read_text(encoding="utf-8") for path in CORPORA[corpus]]

    def time_source_token_lines(self, corpus: str) -> None:
        del corpus
        for source in self.sources:
            list(source_token_lines(source))
