# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/coveragepy/coveragepy/blob/main/NOTICE.txt

"""Explicit preparation of an immutable, opt-in Jinja2 test workload."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import venv
from typing import Any

from tests.benchmarks.helpers import REPO_ROOT, run_subprocess, subprocess_env

ARCHIVE_URL = "https://files.pythonhosted.org/packages/df/bf/f7da0350254c0ed7c72f3e33cef02e048281fec7ecec5f032d4aac52226b/jinja2-3.1.6.tar.gz"
ARCHIVE_SHA256 = "0137fb05990d35f1275a587e9aee6d56da821fc83491a0fb838183be43f66d6d"
PROJECT_REVISION = "15206881c006c79667fe5154fe80c01c65410679"
PREPARED_ROOT = REPO_ROOT / ".benchmarks" / "real"
REQUIREMENTS = REPO_ROOT / "requirements" / "benchmarks-real.txt"
EXPECTED_TESTS = 909


def digest_file(path: pathlib.Path) -> str:
    """A digest for fixture and environment identity."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(root: pathlib.Path) -> dict[str, str]:
    """Exclude only Python bytecode artifacts from snapshot identity."""
    return {
        path.relative_to(root).as_posix(): digest_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def prepared_python(root: pathlib.Path = PREPARED_ROOT) -> pathlib.Path:
    """The isolated interpreter created during preparation."""
    return root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def verify_prepared(root: pathlib.Path = PREPARED_ROOT) -> dict[str, Any]:
    """Fail explicitly instead of downloading inside a benchmark fixture."""
    manifest_path = root / "prepared.json"
    if not manifest_path.exists() or not prepared_python(root).exists():
        raise RuntimeError(
            "Jinja2 workload is not prepared. Run make bench-prepare with Python 3.14."
        )
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["archive_sha256"] != ARCHIVE_SHA256 or manifest[
        "requirements_sha256"
    ] != digest_file(REQUIREMENTS):
        raise RuntimeError("Prepared workload is out of date. Run make bench-prepare again.")
    if source_hashes(root / "jinja2-3.1.6") != manifest["source_hashes"]:
        raise RuntimeError(
            "Prepared Jinja2 source has changed. Remove the prepared source and run make bench-prepare again."
        )
    installed = json.loads(
        run_subprocess(
            [str(prepared_python(root)), "-m", "pip", "list", "--format=json"],
            REPO_ROOT,
            subprocess_env(),
        )
    )
    # The editable coverage version can change with the implementation.
    expected = {
        p["name"].lower(): p["version"]
        for p in manifest["packages"]
        if p["name"].lower() != "coverage"
    }
    actual = {p["name"].lower(): p["version"] for p in installed if p["name"].lower() != "coverage"}
    if actual != expected:
        raise RuntimeError(
            "Prepared dependencies have changed. Recreate .benchmarks/real/venv and run make bench-prepare again."
        )
    return manifest


def prepare(root: pathlib.Path = PREPARED_ROOT) -> None:
    """Download, verify, and install dependencies before any measurements."""
    if sys.version_info[:2] != (3, 14):
        raise RuntimeError("Prepare the real-project workload using Python 3.14.")
    root.mkdir(parents=True, exist_ok=True)
    source = root / "jinja2-3.1.6"
    source_manifest = root / "source.json"
    if not source.exists():
        with urllib.request.urlopen(ARCHIVE_URL, timeout=60) as response:
            blob = response.read()
        if hashlib.sha256(blob).hexdigest() != ARCHIVE_SHA256:
            raise RuntimeError("Jinja2 archive checksum mismatch")
        with tempfile.TemporaryDirectory(dir=root) as temp:
            with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
                archive.extractall(temp, filter="data")
            shutil.move(str(pathlib.Path(temp) / source.name), source)
    elif source_manifest.exists() or (root / "prepared.json").exists():
        previous_path = source_manifest if source_manifest.exists() else root / "prepared.json"
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        if source_hashes(source) != previous["source_hashes"]:
            raise RuntimeError(
                "Prepared Jinja2 source has changed; refusing to bless modified inputs."
            )
    else:
        raise RuntimeError(
            "Unverified source directory exists. Remove it and run preparation again."
        )

    # Retain source verification if dependency installation is interrupted.
    source_manifest.write_text(
        json.dumps(
            {"archive_sha256": ARCHIVE_SHA256, "source_hashes": source_hashes(source)}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    python = prepared_python(root)
    if not python.exists():
        venv.EnvBuilder(with_pip=True).create(root / "venv")
    env = subprocess_env()
    # An editable install rebuilds the current checkout's extension, outside timing.
    output = run_subprocess(
        [str(python), "-m", "pip", "install", "--require-hashes", "-r", str(REQUIREMENTS)],
        REPO_ROOT,
        env,
    )
    print(output)
    print(
        run_subprocess([str(python), "-m", "pip", "install", "-e", str(REPO_ROOT)], REPO_ROOT, env)
    )
    packages = json.loads(
        run_subprocess([str(python), "-m", "pip", "list", "--format=json"], REPO_ROOT, env)
    )
    manifest = {
        "project": "Jinja2",
        "version": "3.1.6",
        "project_revision": PROJECT_REVISION,
        "archive_sha256": ARCHIVE_SHA256,
        "requirements_sha256": digest_file(REQUIREMENTS),
        "python": sys.version,
        "packages": packages,
        "source_hashes": source_hashes(source),
    }
    (root / "prepared.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {source}. Run make bench-real to measure it.")


def main() -> None:
    """Command-line preparation entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "verify"])
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    else:
        verify_prepared()
        print("Prepared source and requirements verified.")


if __name__ == "__main__":
    main()
