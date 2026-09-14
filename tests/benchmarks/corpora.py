# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Verified, frozen real-source corpora for tokenizer benchmarks."""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

CORPUS_DIR = pathlib.Path(__file__).with_name("corpus")
CORPORA = {
    "phystokens": ["phystokens.tok"],
    "parser_reporting": ["parser.tok", "html.tok", "report_core.tok", "xmlreport.tok"],
    "representative_source": [
        "phystokens.tok",
        "parser.tok",
        "html.tok",
        "report_core.tok",
        "xmlreport.tok",
        "sqldata.tok",
        "sysmon.tok",
    ],
    "stress": ["stress_phystoken.tok"],
}


def load_corpus(name: str) -> tuple[list[str], dict[str, Any]]:
    """Verify provenance before loading a corpus, outside the timed region."""
    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text(encoding="utf-8"))
    sources, hashes = [], {}
    for filename in CORPORA[name]:
        blob = (CORPUS_DIR / filename).read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        assert digest == manifest["files"][filename]["sha256"], filename
        assert len(blob) == manifest["files"][filename]["bytes"]
        sources.append(blob.decode("utf-8"))
        hashes[filename] = digest
    return sources, {
        "corpus_revision": manifest["revision"],
        "corpus_hashes": hashes,
        "source_bytes": sum(len(s.encode("utf-8")) for s in sources),
    }
