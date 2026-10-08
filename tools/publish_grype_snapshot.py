"""Publish an already imported, hash-verified Grype v6 database as an immutable snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot, verify_current


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--destination", type=Path, default=Path("data/feeds/grype"))
    parser.add_argument("--image", default="appsec-review/tool-grype:0.119.0")
    args = parser.parse_args()
    staging = args.staging.resolve(strict=True)
    listing_path = staging / "latest.json"
    archive = staging / "vulnerability-db.tar.zst"
    database = staging / "6" / "vulnerability.db"
    imported = staging / "6" / "import.json"
    listing = json.loads(listing_path.read_text(encoding="utf-8"))
    expected = str(listing["checksum"])
    if expected != "sha256:" + sha256(archive):
        raise ValueError("Grype database archive checksum mismatch")
    if listing.get("status") != "active" or not database.is_file() or not imported.is_file():
        raise ValueError("Grype database import is incomplete")
    inspect = subprocess.run(
        ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    )
    image_id = inspect.stdout.strip()
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ValueError("Grype image identity is not immutable")
    pointer = publish_snapshot(
        args.destination.resolve(), feed_id="grype", schema="appsec-review/grype-snapshot/1",
        files={"6/vulnerability.db": database, "6/import.json": imported, "source/latest.json": listing_path},
        manifest_fields={
            "schema_version": listing["schemaVersion"], "built": listing["built"],
            "source_path": listing["path"], "source_checksum": expected,
            "source_archive_size_bytes": archive.stat().st_size,
            "tool": {"image": args.image, "image_id": image_id},
            "acquisition_gaps": [
                "container updater TLS verification failed; official HTTPS listing and archive were fetched by the host and the published SHA-256 was verified"
            ],
        },
    )
    verified = verify_current(args.destination.resolve(), "grype")
    print(json.dumps({"pointer": pointer, "verified": verified}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
