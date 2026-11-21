"""Feed publication primitives shared by every sync step: path containment, metadata documents,
atomic hash-pinned snapshots, pointer verification and tamper detection."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_third_party_data_sync import publication
from appsec_review.jobs.job_third_party_data_sync.publication import (
    publish_metadata, publish_snapshot, require_beneath, verify_current, verify_snapshot_directory)
from appsec_review.storage import file_sha256


def _source(tmp_path: Path, name: str, payload: bytes) -> Path:
    path = tmp_path / "sources" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return path


def test_require_beneath_accepts_the_root_and_its_descendants_only(tmp_path: Path) -> None:
    assert require_beneath(tmp_path, tmp_path, "root") == tmp_path.resolve()
    assert require_beneath(tmp_path, tmp_path / "a" / "b", "child") == (tmp_path / "a" / "b").resolve()
    with pytest.raises(ValueError, match="sibling escapes"):
        require_beneath(tmp_path / "root", tmp_path / "root-sibling", "sibling")
    with pytest.raises(ValueError, match="parent escapes"):
        require_beneath(tmp_path / "root", tmp_path / "root" / "..", "parent")


def test_publish_metadata_writes_a_json_document_under_kind_and_refuses_unsafe_identities(tmp_path: Path) -> None:
    path = publish_metadata(tmp_path / "metadata", "feeds", "cve-bin-tool", {"feed_id": "cve-bin-tool", "n": 1})
    assert path == tmp_path / "metadata" / "feeds" / "cve-bin-tool.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {"feed_id": "cve-bin-tool", "n": 1}
    for identity in ("", "../escape", "a/b", "a b", "a.json"):
        with pytest.raises(ValueError, match="metadata identity is invalid"):
            publish_metadata(tmp_path / "metadata", "feeds", identity, {})


def test_stamp_is_a_millisecond_utc_timestamp() -> None:
    value = publication.stamp()
    assert value.endswith("Z") and len(value) == len("2026-11-12T13:00:00.000Z")


def test_snapshot_identity_is_a_hash_of_the_manifest_and_republishing_the_same_content_is_idempotent(
        tmp_path: Path) -> None:
    root = tmp_path / "feed"
    source = _source(tmp_path, "data.bin", b"payload")
    first = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/data.bin": source},
                             manifest_fields={"version": "1"})
    assert first["schema"] == "appsec-review/feed-pointer/1" and first["feed_id"] == "fixture"
    snapshot = root / "snapshots" / first["snapshot_id"]
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["snapshot_id"] == first["snapshot_id"] and manifest["version"] == "1"
    assert manifest["files"] == {"data/data.bin": {"sha256": file_sha256(source), "size_bytes": 7}}
    assert first["manifest_sha256"] == file_sha256(snapshot / "manifest.json")
    assert (snapshot / "data" / "data.bin").read_bytes() == b"payload"

    again = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/data.bin": source},
                             manifest_fields={"version": "1"})
    assert again["snapshot_id"] == first["snapshot_id"]
    assert [path.name for path in (root / "snapshots").iterdir()] == [first["snapshot_id"]]
    assert not list((root / "staging").iterdir())

    changed = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/data.bin": source},
                               manifest_fields={"version": "2"})
    assert changed["snapshot_id"] != first["snapshot_id"]
    assert json.loads((root / "current.json").read_text(encoding="utf-8"))["snapshot_id"] == changed["snapshot_id"]


def test_a_failed_publication_leaves_no_staging_and_keeps_the_previous_pointer(tmp_path: Path) -> None:
    root = tmp_path / "feed"
    source = _source(tmp_path, "data.bin", b"verified")
    first = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/data.bin": source},
                             manifest_fields={})
    for files, message in (({"data/missing.bin": tmp_path / "missing.bin"}, "unsafe publication file"),
                           ({"/abs.bin": source}, "unsafe publication file"),
                           ({"../up.bin": source}, "unsafe publication file")):
        with pytest.raises(ValueError, match=message):
            publish_snapshot(root, feed_id="fixture", schema="fixture/1", files=files, manifest_fields={})
    with pytest.raises(ValueError, match="manifest exceeds its byte bound"):
        publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/data.bin": source},
                         manifest_fields={"padding": "x" * 64}, max_manifest_bytes=64)
    assert json.loads((root / "current.json").read_text(encoding="utf-8"))["snapshot_id"] == first["snapshot_id"]
    assert not list((root / "staging").iterdir())


def test_verify_current_checks_the_pointer_the_manifest_and_every_file(tmp_path: Path) -> None:
    root = tmp_path / "feed"
    source = _source(tmp_path, "data.bin", b"verified")
    pointer = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"data/data.bin": source},
                               manifest_fields={"version": "1"})
    seen: list = []
    verified = verify_current(root, "fixture", manifest_validator=seen.append)
    assert verified["snapshot_id"] == pointer["snapshot_id"] and verified["verified_files"] == 1
    assert verified["manifest_sha256"] == pointer["manifest_sha256"]
    assert verified["directory"] == str(root / "snapshots" / pointer["snapshot_id"])
    assert seen and seen[0]["version"] == "1"

    with pytest.raises(ValueError, match="invalid other current pointer"):
        verify_current(root, "other")
    with pytest.raises(ValueError, match="pointer exceeds its byte bound"):
        verify_current(root, "fixture", max_manifest_bytes=10)

    def reject(manifest):
        raise ValueError("validator refused")
    with pytest.raises(ValueError, match="validator refused"):
        verify_current(root, "fixture", manifest_validator=reject)

    published = root / "snapshots" / pointer["snapshot_id"] / "data" / "data.bin"
    published.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity mismatch: data/data.bin"):
        verify_current(root, "fixture")
    published.unlink()
    with pytest.raises(ValueError, match="published file is missing: data/data.bin"):
        verify_current(root, "fixture")

    manifest_path = root / "snapshots" / pointer["snapshot_id"] / "manifest.json"
    manifest_path.write_text(manifest_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="fixture manifest hash mismatch"):
        verify_current(root, "fixture")


def test_verify_snapshot_directory_needs_an_identity_and_a_file_table(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid snapshot manifest"):
        verify_snapshot_directory(tmp_path, {"files": {}})
    with pytest.raises(ValueError, match="invalid snapshot manifest"):
        verify_snapshot_directory(tmp_path, {"snapshot_id": "s", "files": []})
    assert verify_snapshot_directory(tmp_path, {"snapshot_id": "s", "files": {}}) == {"snapshot_id": "s",
                                                                                      "verified_files": 0}


def test_http_downloader_covers_allowlist_redirects_and_status_errors(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import urllib.request
    from types import SimpleNamespace

    dl = publication.HttpDownloader(timeout_seconds=5, allow_redirects=True)
    for bad_url in (
        "http://allowed.example/x",
        "https://other.example/x",
        "https://user:pass@allowed.example/x",
    ):
        with pytest.raises(ValueError, match="outside the configured HTTPS host allowlist"):
            dl.download(bad_url, tmp_path / "out", max_bytes=16, allowed_hosts=("allowed.example",))

    class Resp(io.BytesIO):
        def __init__(self, body: bytes, status: int = 200, headers: dict[str, str] | None = None):
            super().__init__(body)
            self.status = status
            self.headers = headers or {}

        def geturl(self):
            return "https://allowed.example/ok"

    monkeypatch.setattr(urllib.request, "build_opener",
                        lambda *handlers: SimpleNamespace(open=lambda req, timeout: Resp(b"hello", 200, {"ETag": '"1"'})))
    rec = dl.download("https://allowed.example/ok", tmp_path / "ok.bin", max_bytes=16, allowed_hosts=("allowed.example",))
    assert rec["size_bytes"] == 5 and rec["etag"] == '"1"' and (tmp_path / "ok.bin").read_bytes() == b"hello"

    monkeypatch.setattr(urllib.request, "build_opener",
                        lambda *handlers: SimpleNamespace(open=lambda req, timeout: Resp(b"nope", 503)))
    with pytest.raises(RuntimeError, match="download returned HTTP 503"):
        dl.download("https://allowed.example/err", tmp_path / "err.bin", max_bytes=16, allowed_hosts=("allowed.example",))


def test_publish_snapshot_covers_provenance_collision_stage_cleanup_and_manifest_bounds(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from appsec_review.storage import feed_provenance, shared

    root = tmp_path / "feed"
    source = _source(tmp_path, "item.bin", b"abc")

    monkeypatch.setattr(feed_provenance, "check_root", lambda *a, **k: None)
    monkeypatch.setattr(feed_provenance, "record_snapshot", lambda *a, **k: {"receipt": "r1"})
    monkeypatch.setattr(feed_provenance, "observe_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(shared, "current", lambda: object())
    pointer = publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"a.bin": source}, manifest_fields={})
    snap_dir = root / "snapshots" / pointer["snapshot_id"]
    manifest = json.loads((snap_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["publication_provenance"] == "required-v1"

    verified = verify_current(root, "fixture")
    assert verified["provenance"] == {"receipt": "r1"}

    # Snapshot collision when existing manifest bytes differ despite equal snapshot_id
    existing_manifest = snap_dir / "manifest.json"
    original_bytes = existing_manifest.read_bytes()
    existing_manifest.write_bytes(original_bytes + b" ")
    with pytest.raises(ValueError, match="snapshot identity collision"):
        publish_snapshot(root, feed_id="fixture", schema="fixture/1", files={"a.bin": source}, manifest_fields={})
    assert not list((root / "staging").iterdir())
    existing_manifest.write_bytes(original_bytes)

    # verify_current manifest byte bound & snapshot_id mismatch
    pointer_size = (root / "current.json").stat().st_size
    (snap_dir / "manifest.json").write_text(
        json.dumps({**manifest, "extra": "x" * 512}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="fixture manifest exceeds its byte bound"):
        verify_current(root, "fixture", max_manifest_bytes=pointer_size + 10)

    bad_manifest = json.dumps({**manifest, "feed_id": "wrong"}).encode("utf-8")
    (snap_dir / "manifest.json").write_bytes(bad_manifest)
    pointer_doc = json.loads((root / "current.json").read_text(encoding="utf-8"))
    pointer_doc["manifest_sha256"] = file_sha256(snap_dir / "manifest.json")
    (root / "current.json").write_text(json.dumps(pointer_doc), encoding="utf-8")
    with pytest.raises(ValueError, match="fixture snapshot identity mismatch"):
        verify_current(root, "fixture")
