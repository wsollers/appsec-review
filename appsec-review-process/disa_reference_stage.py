#!/usr/bin/env python3
"""Fetch one hash-pinned official DISA package and materialize its offline snapshot."""
from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import urllib.request
import zipfile

from reference_snapshots import (DEFAULT_LOCK, DEFAULT_OUTPUT, SnapshotError, load_json,
                                 materialize_one, sha256_file, validate_source_lock_semantics)
from schema_validate import validate_document

USAGE = """Official source provenance receipt

The raw XCCDF was extracted without semantic modification from the exact DISA package named in
data/reference/source-lock.json after its SHA-256 was verified. The package was retrieved from the
official dl.dod.cyber.mil host. This receipt does not invent or assert a license grant; downstream
publication must preserve the recorded source and the claim boundary that reference material is
not evidence of target compliance.
"""


def _source(lock_path: Path, family: str) -> dict:
    lock = load_json(lock_path)
    errors = validate_document(lock, "reference-source-lock.schema.json")
    if errors:
        raise SnapshotError("source lock validation failed:\n" + "\n".join(errors))
    validate_source_lock_semantics(lock)
    matches = [item for item in lock["sources"] if item["family"] == family]
    if len(matches) != 1 or matches[0]["source_kind"] != "disa_xccdf":
        raise SnapshotError(f"source lock must contain exactly one {family} XCCDF source")
    source = matches[0]
    if source["resolved_commit"] is not None or not source.get("artifact_sha256"):
        raise SnapshotError("DISA source must use an artifact hash, not a fabricated Git commit")
    return source


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SnapshotError(f"unsafe member in official DISA archive: {name!r}")
    return path


def stage(*, lock_path: Path = DEFAULT_LOCK, output: Path = DEFAULT_OUTPUT,
          retrieved_at: str, family: str, download: Path | None = None) -> Path:
    source = _source(lock_path.resolve(), family)
    with tempfile.TemporaryDirectory(prefix="appsec-disa-") as folder:
        root = Path(folder)
        archive = root / source["immutable_ref"]
        if download is None:
            with urllib.request.urlopen(source["upstream_url"], timeout=60) as response, archive.open("wb") as stream:
                if response.geturl() != source["upstream_url"]:
                    raise SnapshotError("official DISA download redirected away from the locked URL")
                shutil.copyfileobj(response, stream)
        else:
            candidate = download.resolve()
            if not candidate.is_file() or candidate.is_symlink():
                raise SnapshotError("supplied DISA package is absent or linked")
            shutil.copyfile(candidate, archive)
        if sha256_file(archive) != source["artifact_sha256"]:
            raise SnapshotError("official DISA package hash differs from source lock")
        wanted = set(source["raw_includes"])
        with zipfile.ZipFile(archive) as package:
            members = {member.filename: member for member in package.infolist() if not member.is_dir()}
            if not wanted.issubset(members):
                raise SnapshotError("official DISA package lacks the locked XCCDF member")
            for name in sorted(wanted):
                relative = _safe_member(name)
                target = root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.open(members[name]) as incoming, target.open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
        (root / source["license_path"]).write_text(USAGE, encoding="utf-8", newline="\n")
        return materialize_one(source, root, output.resolve(), retrieved_at)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--retrieved-at", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--download", type=Path)
    args = parser.parse_args()
    try:
        print(stage(lock_path=args.source_lock, output=args.output,
                    retrieved_at=args.retrieved_at, family=args.family, download=args.download))
        return 0
    except (OSError, ValueError, KeyError, SnapshotError, zipfile.BadZipFile) as exc:
        print(f"DISA reference stage error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
