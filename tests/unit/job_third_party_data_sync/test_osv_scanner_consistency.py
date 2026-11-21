"""Real archive publication and scanner mount selection, without invoking a native scanner."""
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
import tomllib
import zipfile

import pytest
import tomlkit

from appsec_review.jobs.job_third_party_data_sync import publication
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv
from appsec_review.storage import file_sha256
from tests.unit.job_third_party_data_sync.test_osv_feed import _fetched, _record, _settings
from tests.unit.job_third_party_data_sync.test_sync_closure import private_offline_only


def _records():
    old = _record("GHSA-shared", ("PyPI", "fixture"), ("npm", "fixture"),
                  modified="2026-01-01T00:00:00Z", aliases=("CVE-2026-0001",), summary="old")
    new = _record("GHSA-shared", ("PyPI", "fixture"), ("npm", "fixture"),
                  modified="2026-02-01T00:00:00Z", aliases=("CVE-2026-0002",),
                  withdrawn="2026-02-01T00:00:00Z", summary="corrected")
    for record, version in ((old, "1.0.0"), (new, "2.0.0")):
        for affected in record["affected"]:
            affected["versions"] = [version]
    return old, new


def _inputs(tmp_path, order, *, conflict):
    old, new = _records()
    names = ["PyPI", "npm"] if order == "old-first" else ["npm", "PyPI"]
    fetched = _fetched(tmp_path, {name: {"advisory.json": old if conflict and name == "PyPI" else new}
                                 for name in names})
    settings = _settings(tmp_path, feed_root="data/feeds/custom-osv")
    indexed = osv.index(settings, fetched, tmp_path / "index")
    return settings, fetched, indexed, new


def _consumer(tmp_path, settings, consumer, monkeypatch):
    from appsec_review.jobs.job_evidence_collection import job as evidence
    from appsec_review.jobs.job_evidence_collection.adapters import Applicability, adapter_registry
    from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner

    run = tmp_path / "run"
    config = run / "data/configuration/resolved.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"jobs": {"job_third_party_data_sync": {"steps": {"osv_sync": {
        "settings": {"feed_root": str(settings.feed_root), "ecosystems": list(settings.ecosystems)}}}}}}))
    files = ("requirements.txt", "package-lock.json")
    if consumer == "evidence":
        unit = SimpleNamespace(job=SimpleNamespace(repository_root=tmp_path, run_root=run),
                               unit_root=run / "unit")
        selected = Applicability(True, "fixture", files, "dependency_lockfiles")
        _, mounts, _, gap = evidence._prerequisites(unit, adapter_registry()["tool-osv-scanner"], selected)
        return [mount.source for mount in mounts], gap

    root = Path(__file__).resolve().parents[3]
    catalog = tomllib.loads((root / "containers/catalog.toml").read_text())
    catalog["images"] = [item for item in catalog["images"] if item["id"] == "tool-osv-scanner"]
    target = tmp_path / "containers/catalog.toml"
    target.parent.mkdir(exist_ok=True)
    target.write_text(tomlkit.dumps(catalog))
    for name in (catalog["runtime_policy"], catalog["images"][0]["tool_manifest"]):
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, destination)
    runner = ContainerScannerRunner(tmp_path, run, run / "scratch")
    monkeypatch.setattr(runner.executor, "resolve_image", lambda tool: "sha256:" + "a" * 64)
    identity = runner.identity("osv", {})
    if identity.get("unavailable"):
        return [], identity["unavailable"]
    archives = []

    def execute(request):
        archives.extend(mount.source for mount in request.extra_mounts)
        raw = request.scratch_root / "raw"
        raw.mkdir(parents=True)
        (raw / "stdout").write_bytes(b'{"results":[]}')
        (raw / "stderr").write_bytes(b"")
        (raw / "receipt.json").write_text("{}")
        return SimpleNamespace(
            stdout_path=(raw / "stdout").relative_to(run).as_posix(),
            stderr_path=(raw / "stderr").relative_to(run).as_posix(),
            receipt_path=(raw / "receipt.json").relative_to(run).as_posix(),
            exit_code=0, timed_out=False, stdout_truncated=False, stderr_truncated=False)

    monkeypatch.setattr(runner.executor, "execute", execute)
    for filename in files:
        path = tmp_path / filename
        path.write_text("fixture")
        runner("osv", path, {"canonical_identity": filename, "sha256": "a" * 64}, 60, 1024)
    return archives, None


@pytest.mark.parametrize("order", ["old-first", "new-first"], ids=["old-first", "new-first"])
@pytest.mark.parametrize("consumer", ["evidence", "artifact"], ids=["evidence", "artifact"])
def test_published_scanner_archives_agree_with_selected_state(tmp_path, monkeypatch, order, consumer):
    settings, fetched, indexed, newest = _inputs(tmp_path, order, conflict=False)
    raw_hashes = {name: file_sha256(Path(item["path"])) for name, item in fetched["archives"].items()}
    pointer = osv.publish(settings, fetched, indexed)
    archives, gap = _consumer(tmp_path, settings, consumer, monkeypatch)
    assert gap is None and len(archives) == 2
    for path in archives:
        assert path.is_relative_to(settings.feed_root / "snapshots" / pointer["snapshot_id"])
        assert file_sha256(path) == raw_hashes[path.stem]
        with zipfile.ZipFile(path) as archive:
            assert json.loads(archive.read("advisory.json")) == newest


@pytest.mark.parametrize("order", ["old-first", "new-first"], ids=["old-first", "new-first"])
def test_conflicting_raw_archives_fail_publication_without_rewriting_or_advancing(tmp_path, order):
    settings, fetched, indexed, _ = _inputs(tmp_path, order, conflict=False)
    osv.publish(settings, fetched, indexed)
    before = (settings.feed_root / "current.json").read_bytes()
    _, bad, merged, _ = _inputs(tmp_path / "conflict", order, conflict=True)
    original = {name: Path(item["path"]).read_bytes() for name, item in bad["archives"].items()}
    with pytest.raises(ValueError, match="OSV_SCANNER_REVISION_CONFLICT"):
        osv.publish(settings, bad, merged)
    assert (settings.feed_root / "current.json").read_bytes() == before
    assert {name: Path(item["path"]).read_bytes() for name, item in bad["archives"].items()} == original


@pytest.mark.parametrize("order", ["old-first", "new-first"], ids=["old-first", "new-first"])
@pytest.mark.parametrize("consumer", ["evidence", "artifact"], ids=["evidence", "artifact"])
def test_scanners_refuse_preexisting_hash_valid_but_inconsistent_snapshots(tmp_path, monkeypatch, order, consumer):
    settings, fetched, indexed, _ = _inputs(tmp_path, order, conflict=True)
    files = {f"sources/{name}.zip": Path(entry["path"]) for name, entry in fetched["archives"].items()}
    files["index/osv.sqlite"] = Path(indexed["database_path"])
    # The old publisher admitted these exact bytes; model that historical snapshot, not a tamper.
    publication.publish_snapshot(settings.feed_root, feed_id="osv", schema="appsec-review/osv-snapshot/1",
                                 files=files, manifest_fields={"ecosystems": list(settings.ecosystems)})
    before = (settings.feed_root / "current.json").read_bytes()
    archives, gap = _consumer(tmp_path, settings, consumer, monkeypatch)
    assert archives == [] and gap.startswith("OSV_SCANNER_REVISION_CONFLICT")
    assert (settings.feed_root / "current.json").read_bytes() == before


def test_archive_omitting_a_selected_ecosystem_advisory_fails_closed(tmp_path):
    _, new = _records()
    settings = _settings(tmp_path)
    fetched = _fetched(tmp_path, {"PyPI": {}, "npm": {"advisory.json": new}})
    indexed = osv.index(settings, fetched, tmp_path / "index")
    with pytest.raises(ValueError, match="OSV_SCANNER_REVISION_CONFLICT.*omits"):
        osv.publish(settings, fetched, indexed)
    assert not (settings.feed_root / "current.json").exists()
