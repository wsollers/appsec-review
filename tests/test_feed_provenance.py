"""Public-feed provenance with fake publishers and no network, tools or model calls."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot, verify_current
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage import feed_provenance as feeds, shared
from tests.test_shared_layout_provenance import context, receipts


def owner(repository, run, number=1, job="job_third_party_data_sync", configured=None):
    root = repository / "runs" / run
    attempt = root / "data/jobs" / job / "attempts" / f"attempt_{number:04d}"
    resolved = {"jobs": {"job_third_party_data_sync": {"steps": {
        step: {"settings": {"feed_root": (configured or {}).get(feed, f"data/feeds/{feed}")}}
        for feed, step in feeds.STEPS.items()}}}}
    config = root / "data/configuration/resolved.json"
    atomic_json(config, resolved)
    claim = {"run_id": run, "job_id": job, "attempt_id": attempt.name,
             "attempt_path": attempt.relative_to(root).as_posix(),
             "orchestration": {"system": "dagster", "run_id": f"{run}-{number}"},
             "repository_root": str(repository), "resolved_config_sha256": file_sha256(config),
             "dataset_contract": dataset_contract(job, ("work",), ())}
    atomic_json(attempt / "claim.json", claim)
    return shared.SharedArtifacts.for_job(SimpleNamespace(
        run_root=root, attempt_root=attempt, run_id=run, attempt_id=attempt.name,
        orchestration=claim["orchestration"], config=SimpleNamespace(job_id=job)))


def snapshot(repository, feed="mitre", payload=b'{"public":true}\n'):
    source = repository / ("source-" + hashlib.sha256(payload).hexdigest() + ".json")
    if not source.exists():
        source.write_bytes(payload)
    return publish_snapshot(repository / "data/feeds" / feed, feed_id=feed, schema="fixture",
                            files={"reference.json": source}, manifest_fields={"version": "1"})


def proof(actor, ref):
    receipt = shared.verify_receipt(actor.run_root, ref)
    return json.loads(shared.verify_reference(actor.run_root, receipt["object"]).read_bytes())


@pytest.mark.parametrize("feed", list(feeds.STEPS.keys() - {"nvd"}))
def test_independent_publication_survives_entire_producer_run_removal(tmp_path, feed):
    producer = owner(tmp_path, "original")
    with shared.publication_scope(context(producer)):
        pointer = snapshot(tmp_path, feed)
    root = tmp_path / "data/feeds" / feed
    publication = next((root / "provenance" / pointer["snapshot_id"]).iterdir())
    original = publication.read_bytes()
    shutil.rmtree(producer.run_root)
    consumer = owner(tmp_path, "later", job="job_review_data_indexing")
    with shared.publication_scope(context(consumer)):
        verified = verify_current(root, feed)
    selected = proof(consumer, verified["provenance"])
    record = json.loads(shared.verify_reference(root, selected["producer"]).read_bytes())
    assert record["actor"]["orchestration"]["run_id"] == "original-1"
    assert record["computation_fingerprint"] == hashlib.sha256(canonical_json(record["computation"])).hexdigest()
    assert publication.read_bytes() == original
    (root / "current.json").unlink()
    shared.verify_receipt(consumer.run_root, verified["provenance"])
    assert not list(consumer.run_root.rglob("reference.json"))
    assert "repository_root" not in record and "target_root" not in record
    handoff = {"resolving_paths": {"attempt": consumer.attempt_root.relative_to(consumer.run_root).as_posix()},
               "artifacts": shared.attempt_artifacts(consumer.run_root, consumer.attempt_root)}
    shared.verify_handoff(consumer.run_root, handoff)
    for item in handoff["artifacts"]:
        if "/shared/" in item["path"]:
            shared.audit_file(consumer.run_root, item["path"])


def test_same_snapshot_keeps_distinct_productions_and_true_reuse(tmp_path):
    one, two, three = (owner(tmp_path, f"run-{n}") for n in (1, 2, 3))
    with shared.publication_scope(context(one)):
        first = snapshot(tmp_path)
    path = tmp_path / "data/feeds/mitre/snapshots" / first["snapshot_id"] / "reference.json"
    inode = path.stat().st_ino
    with shared.publication_scope(context(two)):
        second = snapshot(tmp_path)
    with shared.publication_scope(context(three)):
        verified = verify_current(tmp_path / "data/feeds/mitre", "mitre")
    assert first["snapshot_id"] == second["snapshot_id"] and path.stat().st_ino == inode
    assert receipts(one, "feed-snapshot")[0]["mode"] == receipts(two, "feed-snapshot")[0]["mode"] == "computed"
    assert receipts(three, "feed-snapshot")[0]["mode"] == "reused"
    candidates = sorted((path.parent.parent.parent / "provenance" / first["snapshot_id"]).iterdir())
    assert len(candidates) == 2
    assert proof(three, verified["provenance"])["producer"]["sha256"] == candidates[0].stem


def test_same_computation_fingerprint_does_not_assert_identical_feed_output(tmp_path):
    actors = [owner(tmp_path, f"producer-{n}") for n in (1, 2)]
    pointers = []
    for actor, payload in zip(actors, (b"result one", b"result two")):
        with shared.publication_scope(context(actor)):
            pointers.append(snapshot(tmp_path, payload=payload))
    root = tmp_path / "data/feeds/mitre"
    records = [json.loads(next((root / "provenance" / p["snapshot_id"]).iterdir()).read_bytes())
               for p in pointers]
    assert records[0]["computation_fingerprint"] == records[1]["computation_fingerprint"]
    assert records[0]["manifest"] != records[1]["manifest"]
    assert len(list((root / "snapshots").iterdir())) == 2


def test_concurrent_producers_and_consumers_pin_without_rebinding(tmp_path):
    actors = [owner(tmp_path, f"producer-{n}") for n in range(4)]
    source = tmp_path / "source.json"
    source.write_bytes(b"one copy")
    root = tmp_path / "data/feeds/mitre"

    def publish(actor):
        with shared.publication_scope(context(actor)):
            return publish_snapshot(root, feed_id="mitre", schema="fixture",
                                    files={"reference.json": source}, manifest_fields={})
    first = publish(actors[0])

    def attest(actor):
        with shared.publication_scope(context(actor)):
            return feeds.record_snapshot(root, "mitre", first["snapshot_id"], computed=True)
    with ThreadPoolExecutor(4) as pool:
        references = list(pool.map(attest, actors))
    assert len({item["sha256"] for item in references}) == 4
    consumer = owner(tmp_path, "consumer", job="job_review_data_indexing")
    with shared.publication_scope(context(consumer)):
        first = verify_current(root, "mitre")
    later = owner(tmp_path, "another-producer")
    publish(later)
    with shared.publication_scope(context(consumer)):
        assert verify_current(root, "mitre")["provenance"] == first["provenance"]
    assert len(list((root / "snapshots").iterdir())) == 1
    assert len(list((root / "provenance" / first["snapshot_id"]).iterdir())) == 5
    assert not list(root.rglob(".publish-*"))


@pytest.mark.parametrize("damage", ["record-bytes", "record-missing", "snapshot", "config", "manifest"])
def test_pinned_tamper_and_missing_records_fail_handoff_validation(tmp_path, damage):
    actor = owner(tmp_path, "one")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(actor)):
        snapshot(tmp_path)
        verified = verify_current(root, "mitre")
    selected = proof(actor, verified["provenance"])
    path = (root / selected["producer"]["path"] if damage.startswith("record") else
            actor.run_root / "data/configuration/resolved.json" if damage == "config" else
            root / selected["manifest"]["path"] if damage == "manifest" else
            Path(verified["directory"]) / "reference.json")
    if damage == "record-missing":
        path.unlink()
    else:
        path.write_bytes(b"tampered")
    with pytest.raises((ValueError, OSError)):
        shared.verify_receipt(actor.run_root, verified["provenance"])


def test_new_snapshot_cannot_downgrade_to_unknown_origin_offline_or_in_job(tmp_path):
    actor = owner(tmp_path, "one")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(actor)):
        pointer = snapshot(tmp_path)
    next((root / "provenance" / pointer["snapshot_id"]).iterdir()).unlink()
    with pytest.raises(ValueError, match="no complete producer"):
        verify_current(root, "mitre")
    consumer = owner(tmp_path, "two")
    with shared.publication_scope(context(consumer)), pytest.raises(ValueError, match="no complete producer"):
        verify_current(root, "mitre")


def test_removing_protocol_marker_cannot_relabel_existing_snapshot_as_legacy(tmp_path):
    actor = owner(tmp_path, "one")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(actor)):
        pointer = snapshot(tmp_path)
    manifest_path = root / "snapshots" / pointer["snapshot_id"] / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    del manifest["publication_provenance"]
    atomic_json(manifest_path, manifest)
    atomic_json(root / "current.json", {**pointer, "manifest_sha256": file_sha256(manifest_path)})
    with pytest.raises(ValueError, match="content identity"):
        verify_current(root, "mitre")


def test_unknown_protocol_is_not_silently_legacy(tmp_path):
    source = tmp_path / "source.json"
    source.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="unsupported.*protocol"):
        publish_snapshot(tmp_path / "data/feeds/mitre", feed_id="mitre", schema="fixture",
                         files={"reference.json": source},
                         manifest_fields={"publication_provenance": "unsupported"})
    assert not (tmp_path / "data/feeds/mitre/current.json").exists()


@pytest.mark.parametrize("mode", ["computed", "reused"])
def test_feed_namespace_cannot_bypass_validation_by_removing_layout(tmp_path, mode):
    actor = owner(tmp_path, "producer")
    with shared.publication_scope(context(actor)):
        snapshot(tmp_path)
        verify_current(tmp_path / "data/feeds/mitre", "mitre")
    path = next(p for p in (actor.attempt_root / "shared/feed-snapshot").iterdir()
                if json.loads(p.read_bytes())["mode"] == mode)
    value = json.loads(path.read_bytes())
    del value["layout"]
    atomic_json(path, value)
    with pytest.raises(ValueError, match="requires public-feed"):
        shared.audit_file(actor.run_root, path.relative_to(actor.run_root).as_posix())


@pytest.mark.parametrize("feed", ["mitre", "grype"])
def test_legacy_and_imported_snapshots_remain_readonly_with_unknown_origin(tmp_path, feed):
    pointer = snapshot(tmp_path, feed)
    root = tmp_path / "data/feeds" / feed
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    actor = owner(tmp_path, "consumer", job="job_evidence_collection")
    with shared.publication_scope(context(actor)):
        verified = verify_current(root, feed)
    value = receipts(actor, "feed-snapshot")[0]
    assert value["legacy"] == "unknown-original-producer" and value["mode"] == "reused"
    assert proof(actor, verified["provenance"])["producer"] is None
    assert all(p.read_bytes() == raw for p, raw in before.items())
    assert not (root / "provenance" / pointer["snapshot_id"]).exists()


@pytest.mark.parametrize("configured", ["../escape", "data/../escape", "/tmp/feed-escape"])
def test_configured_path_escape_fails_before_publication(tmp_path, configured):
    actor = owner(tmp_path, "one", configured={"mitre": configured})
    with shared.publication_scope(context(actor)), pytest.raises(ValueError):
        snapshot(tmp_path)
    assert not (tmp_path / "data/feeds/mitre").exists()


@pytest.mark.parametrize("part", ["root", "manifest", "record", "payload"])
def test_symlink_rejection(tmp_path, part):
    actor = owner(tmp_path, "one")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(actor)):
        pointer = snapshot(tmp_path)
    directory = root / "snapshots" / pointer["snapshot_id"]
    path = (root if part == "root" else directory / "manifest.json" if part == "manifest" else
            next((root / "provenance" / pointer["snapshot_id"]).iterdir()) if part == "record"
            else directory / "reference.json")
    moved = path.with_name(path.name + "-original")
    path.rename(moved)
    path.symlink_to(moved)
    consumer = owner(tmp_path, "consumer")
    with shared.publication_scope(context(consumer)), pytest.raises(ValueError, match="symlink"):
        verify_current(root, "mitre")


def test_interrupted_record_publication_preserves_snapshot_and_allows_retry(tmp_path, monkeypatch):
    actor = owner(tmp_path, "one")
    original = feeds.immutable_bytes

    def interrupted(*args, **kwargs):
        raise OSError("publication interrupted")
    monkeypatch.setattr(feeds, "immutable_bytes", interrupted)
    with shared.publication_scope(context(actor)), pytest.raises(OSError, match="interrupted"):
        snapshot(tmp_path)
    root = tmp_path / "data/feeds/mitre"
    assert not (root / "current.json").exists()
    saved = {p: p.read_bytes() for p in (root / "snapshots").rglob("*") if p.is_file()}
    monkeypatch.setattr(feeds, "immutable_bytes", original)
    with shared.publication_scope(context(actor)):
        snapshot(tmp_path)
        verify_current(root, "mitre")
    assert all(p.read_bytes() == raw for p, raw in saved.items())
    assert not list(root.rglob(".publish-*"))


def test_pinned_consumption_and_handoff_do_not_follow_current_or_producer_run(tmp_path):
    producer = owner(tmp_path, "producer")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(producer)):
        snapshot(tmp_path)
    indexing = owner(tmp_path, "consumer", job="job_review_data_indexing")
    with shared.publication_scope(context(indexing)):
        pin = {"feed_id": "mitre", **verify_current(root, "mitre")}
    shutil.rmtree(producer.run_root)
    (root / "current.json").write_bytes(b"not evidence")
    review = owner(tmp_path, "consumer", job="job_inference_security_review")
    with shared.publication_scope(context(review)):
        ref = feeds.consume_pin(review.run_root, pin)
        assert review.consume_receipt(pin["provenance"]) == ref
    selected = proof(review, ref)
    (indexing.attempt_root / "claim.json").unlink()
    assert proof(review, ref) == selected
    assert selected["producer"] is not None


def test_nvd_separate_publisher_and_actual_database_consumer(tmp_path):
    from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher
    from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
    from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build.database import resolve_nvd_snapshot
    from tests.test_nvd_sync_job import FakeClient, vulnerability
    producer = owner(tmp_path, "nvd-producer")
    raw = json.dumps({"format": "NVD_CVE", "version": "2.0",
                      "vulnerabilities": [vulnerability("CVE-2026-1000")]}).encode()
    settings = NvdSettings.from_mapping(tmp_path, {
        "feed_root": "data/feeds/nvd", "api_key_env": "FIXTURE_ONLY", "first_year": 2026,
        "page_size": 2000, "max_window_days": 119,
        "request_delay_with_key_seconds": 0, "request_delay_without_key_seconds": 0})
    publisher = NvdPublisher(settings, client=FakeClient(raw),
                             clock=lambda: datetime(2026, 10, 8, tzinfo=timezone.utc), pause=lambda _: None)
    with shared.publication_scope(context(producer)):
        pointer = publisher.sync("fixture")
    incremental = owner(tmp_path, "nvd-incremental")
    publisher.clock = lambda: datetime(2026, 10, 8, 2, tzinfo=timezone.utc)
    with shared.publication_scope(context(incremental)):
        second = publisher.sync("fixture incremental")
    values = receipts(incremental, "feed-snapshot")
    assert {value["mode"] for value in values} == {"computed", "reused"}
    assert next(value for value in values if value["mode"] == "reused")["computation"]["snapshot_id"] == pointer["snapshot_id"]
    pointer = second
    shutil.rmtree(producer.run_root)
    shutil.rmtree(incremental.run_root)
    consumer = owner(tmp_path, "nvd-consumer")
    with shared.publication_scope(context(consumer)):
        publisher.verify()
        resolved = resolve_nvd_snapshot(publisher.root, pointer)
    assert resolved["snapshot_id"] == pointer["snapshot_id"]
    values = receipts(consumer, "feed-snapshot")
    assert len(values) == 1 and values[0]["mode"] == "reused"
    selected = json.loads(shared.verify_reference(consumer.run_root, values[0]["object"]).read_bytes())
    assert json.loads((publisher.root / selected["producer"]["path"]).read_bytes())["actor"]["run_id"] == "nvd-incremental"
    blob = Path(resolved["layers"][0]["path"])
    blob.write_bytes(b"damaged")
    with pytest.raises(ValueError):
        shared.attempt_artifacts(consumer.run_root, consumer.attempt_root)


def test_feed_pins_and_product_reader_record_actual_consumption(tmp_path):
    from appsec_review.jobs.job_review_data_indexing.job import feed_pins
    from appsec_review.indexing.products import _feed_database
    from tests.fixtures.reference_feeds import publish_mitre
    producer = owner(tmp_path, "producer")
    with shared.publication_scope(context(producer)):
        publish_mitre(tmp_path / "data/feeds/mitre", {"CWE-120": ("Buffer Copy", "Base")}, tmp_path / "work")
    consumer = owner(tmp_path, "consumer", job="job_review_data_indexing")
    resolved = json.loads((consumer.run_root / "data/configuration/resolved.json").read_bytes())
    with shared.publication_scope(context(consumer)):
        pins = feed_pins(tmp_path, resolved, 30)
    assert pins["mitre"]["status"] == "pinned" and "provenance" in pins["mitre"]
    downstream = owner(tmp_path, "consumer", 2, job="job_review_data_indexing")
    with shared.publication_scope(context(downstream)):
        database, gap = _feed_database(SimpleNamespace(run_root=consumer.run_root, feeds=pins),
                                       "mitre", "index/mitre.sqlite")
    assert database is not None and gap is None
    database.close()
    assert receipts(downstream, "feed-snapshot")[0]["mode"] == "reused"


def test_existing_writer_lock_rejects_competing_snapshot_without_partial_publication(tmp_path):
    from appsec_review.storage import FileLock
    from appsec_review.storage.lock import LockUnavailable
    actor = owner(tmp_path, "producer")
    root = tmp_path / "data/feeds/mitre"
    with FileLock(root / "locks/writer.lock"), shared.publication_scope(context(actor)):
        with pytest.raises(LockUnavailable):
            snapshot(tmp_path)
    assert not (root / "current.json").exists() and not (root / "snapshots").exists()
    with shared.publication_scope(context(actor)):
        snapshot(tmp_path)


def test_wrong_job_cannot_create_global_publication(tmp_path):
    actor = owner(tmp_path, "wrong", job="job_inference_security_review")
    with shared.publication_scope(context(actor)), pytest.raises(ValueError, match="only the feed-sync"):
        snapshot(tmp_path)
    assert not (tmp_path / "data/feeds/mitre").exists()


def test_public_record_exports_only_allowlisted_invocation_identity(tmp_path):
    actor = owner(tmp_path, "producer")
    claim_path = actor.attempt_root / "claim.json"
    claim = json.loads(claim_path.read_bytes())
    claim["orchestration"]["private_correlation"] = "private-fixture-value"
    atomic_json(claim_path, claim)
    actor = shared.SharedArtifacts.for_job(SimpleNamespace(
        run_root=actor.run_root, attempt_root=actor.attempt_root, run_id=actor.run_root.name,
        attempt_id=actor.attempt_root.name, orchestration=claim["orchestration"],
        config=SimpleNamespace(job_id="job_third_party_data_sync")))
    with shared.publication_scope(context(actor)):
        pointer = snapshot(tmp_path)
    path = next((tmp_path / "data/feeds/mitre/provenance" / pointer["snapshot_id"]).iterdir())
    assert b"private-fixture-value" not in path.read_bytes()
    assert json.loads(path.read_bytes())["actor"]["orchestration"] == {
        "system": "dagster", "run_id": "producer-1"}
    assert receipts(actor, "feed-snapshot")[0]["actor"]["orchestration"]["private_correlation"] == "private-fixture-value"


@pytest.mark.parametrize("mode", ["computed", "reused"])
def test_feed_receipt_computation_tampering_is_rejected(tmp_path, mode):
    actor = owner(tmp_path, "producer")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(actor)):
        snapshot(tmp_path)
        verify_current(root, "mitre")
    path = next(path for path in (actor.attempt_root / "shared/feed-snapshot").iterdir()
                if json.loads(path.read_bytes())["mode"] == mode)
    value = json.loads(path.read_bytes())
    value["computation"]["manifest_sha256"] = "0" * 64
    atomic_json(path, value)
    with pytest.raises(ValueError, match="computation differs"):
        shared.verify_receipt(actor.run_root, shared.reference(actor.run_root, path))


def test_offline_pinned_reader_rejects_directory_substitution(tmp_path):
    actor = owner(tmp_path, "producer")
    root = tmp_path / "data/feeds/mitre"
    with shared.publication_scope(context(actor)):
        snapshot(tmp_path)
        pin = {"feed_id": "mitre", **verify_current(root, "mitre")}
    with pytest.raises(ValueError, match="configured provenance root"):
        feeds.consume_pin(actor.run_root, {**pin, "directory": str(tmp_path / "elsewhere")})


def test_nvd_private_directory_interruption_and_retry(tmp_path, monkeypatch):
    from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync import feed
    actor = owner(tmp_path, "producer")
    root = tmp_path / "data/feeds/nvd"
    source = tmp_path / "index.sqlite"
    source.write_bytes(b"fixture index")
    publisher = feed.NvdPublisher(SimpleNamespace(feed_root=root), client=object())
    manifest = {"schema": feed.MANIFEST_SCHEMA, "feed_id": "nvd", "cursor": "2026-10-21T00:00:00Z",
                "files": {"index/nvd.sqlite": {"sha256": file_sha256(source),
                                              "size_bytes": source.stat().st_size}}}
    original = feed.os.rename

    def interrupted(*args):
        raise OSError("snapshot interrupted")
    monkeypatch.setattr(feed.os, "rename", interrupted)
    with shared.publication_scope(context(actor)), pytest.raises(OSError, match="interrupted"):
        publisher._publish(manifest, source)
    assert source.is_file() and not list((root / "snapshots").iterdir())
    assert not list((root / "staging").iterdir()) and not (root / "current.json").exists()
    monkeypatch.setattr(feed.os, "rename", original)
    with shared.publication_scope(context(actor)):
        pointer = publisher._publish(manifest, source)
    assert not source.exists()
    published = root / "snapshots" / pointer["snapshot_id"] / "index/nvd.sqlite"
    inode = published.stat().st_ino
    source.write_bytes(b"fixture index")
    with shared.publication_scope(context(actor)):
        assert publisher._publish(manifest, source)["snapshot_id"] == pointer["snapshot_id"]
    assert published.stat().st_ino == inode and len(receipts(actor, "feed-snapshot")) == 1


def test_reference_reader_records_consumer_and_names_missing_global_record(tmp_path, monkeypatch):
    from appsec_review.review.references import load_cwe_reference
    from appsec_review.retrieval import core
    from appsec_review.jobs.job_review_data_indexing.job import feed_pins
    from tests.fixtures.reference_feeds import publish_mitre
    producer = owner(tmp_path, "producer")
    with shared.publication_scope(context(producer)):
        publish_mitre(tmp_path / "data/feeds/mitre", {"CWE-120": ("Buffer Copy", "Base")}, tmp_path / "work")
    indexing = owner(tmp_path, "consumer", job="job_review_data_indexing")
    resolved = json.loads((indexing.run_root / "data/configuration/resolved.json").read_bytes())
    with shared.publication_scope(context(indexing)):
        pins = feed_pins(tmp_path, resolved, 30)
    artifact = indexing.attempt_root / "inputs.json"
    atomic_json(artifact, {"feeds": pins})
    handoff = indexing.attempt_root / "handoff.json"
    atomic_json(handoff, {"job_id": "job_review_data_indexing", "outputs": {
        "load.accepted_inputs": {"artifact": shared.reference(indexing.run_root, artifact)}}})
    atomic_json(indexing.run_root / "data/indices/accepted.json",
                {"handoff_path": handoff.relative_to(indexing.run_root).as_posix()})
    monkeypatch.setattr(core, "resolve_accepted_manifest", lambda root: None)
    consumer = owner(tmp_path, "consumer", job="job_inference_security_review")
    with shared.publication_scope(context(consumer)):
        reference = load_cwe_reference(consumer.run_root)
    assert reference.source == "mitre_catalog" and "CWE-120" in reference.accepted_ids
    assert receipts(consumer, "feed-snapshot")[0]["mode"] == "reused"
    selected = proof(consumer, pins["mitre"]["provenance"])
    (tmp_path / "data/feeds/mitre" / selected["producer"]["path"]).unlink()
    with shared.publication_scope(context(consumer)):
        reference = load_cwe_reference(consumer.run_root)
    assert reference.source == "fallback" and "provenance" in reference.gap


def test_scanner_identity_records_feed_use_without_running_a_container(tmp_path):
    from appsec_review.jobs.job_artifact_security_analysis.scanners import ContainerScannerRunner
    snapshot(tmp_path, "grype")
    consumer = owner(tmp_path, "consumer", job="job_artifact_security_analysis")
    manifest = tmp_path / "scanner-manifest"
    manifest.write_bytes(b"fixture")
    runner = ContainerScannerRunner.__new__(ContainerScannerRunner)
    runner.repository_root = tmp_path
    runner._identities, runner._feeds = {}, {}
    runner.catalog = SimpleNamespace(tool=lambda tool: SimpleNamespace(version="fixture", manifest_path=manifest))
    runner.executor = SimpleNamespace(resolve_image=lambda tool: "sha256:fixture")
    with shared.publication_scope(context(consumer)):
        identity = runner.identity("grype", {})
    assert "unavailable" not in identity
    assert receipts(consumer, "feed-snapshot")[0]["legacy"] == "unknown-original-producer"
