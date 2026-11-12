"""Small public-feed bytes and a fake Docker boundary; publication and import orchestration are real."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

import zstandard

from appsec_review.container_runtime import ContainerExecutor, load_catalog
from appsec_review.container_runtime.executor import CommandOutcome


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)
BUILT = "2026-10-07T12:00:00Z"
IMAGE_ID = "sha256:" + "a" * 64


def archive_bytes(members: list[tuple[tarfile.TarInfo, bytes]] | None = None) -> bytes:
    if members is None:
        member = tarfile.TarInfo("vulnerability.db")
        members = [(member, b"fixture database")]
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, payload in members:
            if member.isfile():
                member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return zstandard.ZstdCompressor(write_checksum=True).compress(stream.getvalue())


class Downloader:
    def __init__(self, *, archive: bytes | None = None, **listing_overrides):
        self.archive = archive if archive is not None else archive_bytes()
        self.listing = {"status": "active", "schemaVersion": "6.1.3", "built": BUILT,
                        "path": "vulnerability-db_v6.1.3.tar.zst",
                        "checksum": "sha256:" + hashlib.sha256(self.archive).hexdigest(), **listing_overrides}
        self.calls = []

    def download(self, url, destination, *, max_bytes, allowed_hosts):
        self.calls.append((url, max_bytes, allowed_hosts))
        payload = json.dumps(self.listing).encode() if url.endswith("latest.json") else self.archive
        if len(payload) > max_bytes:
            raise ValueError("download exceeds byte bound")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        return {"url": url, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload),
                "retrieved_at": NOW.isoformat(), "etag": None, "last_modified": None}


class Docker:
    def __init__(self, *, version="0.119.0", status=None, fail=None):
        self.version, self.status, self.fail = version, status or {}, fail
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append((tuple(argv), timeout))
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, IMAGE_ID.encode(), b"")
        if tuple(argv[:3]) == ("docker", "rm", "--force"):
            return CommandOutcome(0, b"", b"")
        if tuple(argv[:3]) == ("docker", "container", "inspect"):
            return CommandOutcome(1, b"", f"No such container: {argv[3]}".encode())
        if tuple(argv[:2]) != ("docker", "run"):
            raise AssertionError(argv)
        entry = argv.index("--entrypoint")
        args = tuple(argv[entry + 3:])
        assert argv[entry + 2] == IMAGE_ID
        assert argv[argv.index("--network") + 1] == "none"
        assert "--read-only" in argv and "--ulimit" in argv
        mounts = {}
        for index, arg in enumerate(argv):
            if arg == "--mount":
                spec = dict(item.split("=", 1) for item in argv[index + 1].split(",") if "=" in item)
                mounts[spec["dst"]] = Path(spec["src"])
        if self.fail == args[0] or self.fail == " ".join(args[:2]):
            return CommandOutcome(1, b"", b"fixture tool failure")
        if args == ("version", "-o", "json"):
            return CommandOutcome(0, json.dumps({"application": "grype", "version": self.version}).encode(), b"")
        if args[:2] == ("db", "import"):
            assert args[2] == "/target/vulnerability.db"
            directory = mounts["/scratch"] / "cache/6"
            directory.mkdir(parents=True)
            shutil.copyfile(mounts["/target"] / "vulnerability.db", directory / "vulnerability.db")
            (directory / "import.json").write_text(json.dumps(
                {"digest": "xxh64:" + "b" * 16, "source": "manual import", "client_version": "6.1.3"}))
            return CommandOutcome(0, b"", b"")
        assert args == ("db", "status", "-o", "json")
        assert (mounts["/database"] / "6/vulnerability.db").is_file()
        status = {"schemaVersion": "6.1.3", "built": BUILT, "valid": True,
                  "path": "/database/6/vulnerability.db", "from": "manual import", **self.status}
        return CommandOutcome(0, json.dumps(status).encode(), b"")


def executor(run_root: Path, docker: Docker | None = None) -> ContainerExecutor:
    return ContainerExecutor(load_catalog(ROOT), run_root, runner=docker or Docker())
