"""Provenance across retained run-local layouts and parallel producer tasks."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.retrieval.index import IndexBuilder
from appsec_review.review.cells import run_cell, reuse_or_run
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.datasets import artifact_only
from appsec_review.storage import file_sha256
from appsec_review.storage import shared
from tests.test_job_runtime import write_config
from tests.test_shared_artifacts import actor, produce
from tests.review.test_cells import FakeCore, ScriptedInfer, capability, final, spec, validate


LAYOUTS = {
    "index-shard": "data/indices/source/a.sqlite",
    "owasp-shard": "data/indexes/owasp/applicability/a.json",
    "guidance": "data/guidance/a/task.md",
    "review-package": "data/review-packages/a/manifest.json",
    "review-cell": "data/jobs/job_inference_security_review/cells/a/attempt-1.json",
    "cell-check": "data/jobs/job_inference_security_review/cells/a/judge-request-check-1.json",
}


def context(owner):
    return SimpleNamespace(run_root=owner.run_root, attempt_root=owner.attempt_root,
                           run_id=owner.actor["run_id"], attempt_id=owner.actor["attempt_id"],
                           orchestration=owner.actor["orchestration"],
                           config=SimpleNamespace(job_id=owner.actor["job_id"]))


def receipts(owner, namespace):
    return [shared.verify_receipt(owner.run_root, shared.reference(owner.run_root, path))
            for path in sorted((owner.attempt_root / "shared" / namespace).glob("*.json"))]


@pytest.mark.parametrize("namespace", LAYOUTS)
def test_named_layout_preserves_computation_and_original_invocation(tmp_path, namespace):
    path = tmp_path / LAYOUTS[namespace]
    one, two, three = (actor(tmp_path, i) for i in (1, 2, 3))
    with shared.publication_scope(context(one)):
        shared.publish_named(tmp_path, path, b"same bytes", namespace=namespace, computation={"request": "a"})
        other = path.with_name("second" + path.suffix)
        shared.publish_named(tmp_path, other, b"same bytes", namespace=namespace, computation={"request": "b"})
    assert path.stat().st_ino == other.stat().st_ino
    assert len(list((tmp_path / shared.OBJECTS).iterdir())) == 1
    with shared.publication_scope(context(two)):
        shared.consume_named(tmp_path, path, namespace=namespace)
    reused = receipts(two, namespace)[0]
    assert reused["mode"] == "reused"
    origin = shared.verify_receipt(tmp_path, reused["producer_receipt"])
    assert origin["actor"]["orchestration"]["run_id"] == "invocation-1"
    with shared.publication_scope(context(three)):
        shared.publish_named(tmp_path, path, b"same bytes", namespace=namespace, computation={"request": "a"})
    computed = receipts(three, namespace)[0]
    assert computed["mode"] == "computed" and computed["producer_receipt"] is None
    assert path.stat().st_ino == other.stat().st_ino
    for owner in (one, two, three):
        artifacts = shared.attempt_artifacts(tmp_path, owner.attempt_root)
        shared.verify_handoff(tmp_path, {"resolving_paths": {
            "attempt": owner.attempt_root.relative_to(tmp_path).as_posix()}, "artifacts": artifacts})


@pytest.mark.parametrize("damage", ["bytes", "binding", "producer", "symlink"])
def test_named_layout_cannot_downgrade_new_publication_to_legacy(tmp_path, damage):
    one, two = actor(tmp_path, 1), actor(tmp_path, 2)
    path = tmp_path / LAYOUTS["guidance"]
    with shared.publication_scope(context(one)):
        shared.publish_named(tmp_path, path, b"pinned", namespace="guidance")
    if damage == "bytes":
        path.write_bytes(b"changed")
    elif damage == "binding":
        next((tmp_path / shared.NAMED / "guidance").glob("*.json")).write_bytes(b"broken")
    elif damage == "producer":
        next((one.attempt_root / "shared/guidance").glob("*.json")).unlink()
    else:
        other = path.with_name("other")
        path.rename(other)
        path.symlink_to(other)
    with shared.publication_scope(context(two)), pytest.raises((ValueError, OSError)):
        shared.consume_named(tmp_path, path, namespace="guidance")


def test_named_legacy_is_readonly_and_unknown_origin(tmp_path):
    owner = actor(tmp_path, 1)
    path = tmp_path / LAYOUTS["guidance"]
    path.parent.mkdir(parents=True)
    path.write_bytes(b"legacy")
    before = path.stat()
    with shared.publication_scope(context(owner)):
        shared.consume_named(tmp_path, path, namespace="guidance")
    value = receipts(owner, "guidance")[0]
    assert value["legacy"] == "unknown-original-producer"
    assert path.read_bytes() == b"legacy" and path.stat().st_mtime_ns == before.st_mtime_ns
    assert not (tmp_path / shared.OBJECTS).exists()
    assert not (tmp_path / shared.NAMED).exists()


@pytest.mark.parametrize("namespace", ["guidance", "review-package"])
def test_parallel_named_publishers_share_one_payload_without_losing_producers(tmp_path, namespace):
    owners = [actor(tmp_path, i) for i in range(1, 7)]
    path = tmp_path / LAYOUTS[namespace]

    def publish(owner):
        with shared.publication_scope(context(owner)):
            shared.publish_named(tmp_path, path, b"concurrent", namespace=namespace)
    with ThreadPoolExecutor(6) as pool:
        list(pool.map(publish, owners))
    assert len(list((tmp_path / shared.OBJECTS).iterdir())) == 1
    values = [receipts(owner, namespace)[0] for owner in owners]
    assert all(value["mode"] == "computed" for value in values)
    assert len({value["actor"]["attempt_id"] for value in values}) == 6
    assert not list(tmp_path.rglob(".publish-*"))


def test_downstream_receipt_reference_preserves_producer_without_copying_payload(tmp_path):
    producer, consumer, later = (actor(tmp_path, i) for i in (1, 2, 3))
    original = produce(producer, b"derived input")
    reference = consumer.consume_receipt(original)
    selected = shared.verify_receipt(tmp_path, reference)
    assert selected["namespace"] == "shared-input" and selected["mode"] == "reused"
    assert selected["producer_receipt"] == original
    chained = later.consume_receipt(reference)
    assert shared.verify_receipt(tmp_path, chained)["producer_receipt"] == original
    assert len(list((tmp_path / shared.OBJECTS).iterdir())) == 1
    original_file = tmp_path / original["path"]
    original_file.unlink()
    with pytest.raises(ValueError):
        shared.verify_receipt(tmp_path, chained)


def test_cell_reporting_is_readonly_offline_and_records_job_consumption(tmp_path):
    from appsec_review.reporting.sources import RunReader
    one, two = actor(tmp_path, 1), actor(tmp_path, 2)
    path = tmp_path / LAYOUTS["review-cell"]
    with shared.publication_scope(context(one)):
        shared.publish_named(tmp_path, path, b'{"cell_id":"a"}\n', namespace="review-cell")
    reader = RunReader(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert reader.read_cell_receipt(path) == {"cell_id": "a"}
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    with shared.publication_scope(context(two)):
        assert reader.read_cell_receipt(path) == {"cell_id": "a"}
    assert receipts(two, "review-cell")[0]["mode"] == "reused"
    path.write_bytes(b'{"cell_id":"tampered"}\n')
    assert reader.read_cell_receipt(path) is None
    assert any("cell provenance" in gap for gap in reader.gaps)


def test_build_guidance_identity_includes_model_without_overwriting_old_bundle(tmp_path):
    from appsec_review.jobs.job_project_build.job import _repair_guidance
    one, two = actor(tmp_path, 1), actor(tmp_path, 2)
    unit = SimpleNamespace(job=SimpleNamespace(
        repository_root=Path(__file__).parents[1], run_root=tmp_path))
    with shared.publication_scope(context(one)):
        first = _repair_guidance(unit, "native", {"provider": "fixture", "model": "one", "reasoning": "low"})
    original = {p: p.read_bytes() for p in (tmp_path / "data/guidance" / first[-1]).iterdir()}
    with shared.publication_scope(context(two)):
        second = _repair_guidance(unit, "native", {"provider": "fixture", "model": "two", "reasoning": "low"})
    assert first[-1] != second[-1]
    assert all(p.read_bytes() == raw for p, raw in original.items())
    assert all(value["mode"] == "computed" for value in receipts(two, "guidance"))


def test_failed_guidance_publication_is_not_cached_as_ready_for_inference(tmp_path, monkeypatch):
    from appsec_review.jobs.job_inference_security_review import teams
    from appsec_review.review.models import Lane, Role
    ctx = SimpleNamespace(_lock=Lock(), _bundles={}, _pinned=set(), repository_root=tmp_path,
                          run_root=tmp_path, vocabulary=None, crosswalk=None)
    monkeypatch.setattr(teams, "compose_bundle", lambda *args, **kwargs: {"sha256": "a" * 64})
    monkeypatch.setattr(teams, "render_prompt", lambda bundle: "fixture prompt")
    attempts = []

    def pin(*args):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("interrupted guidance publication")
    monkeypatch.setattr(teams, "pin_bundle", pin)
    arguments = dict(role=Role.HYPOTHESIS_HUNTER, persona="fixture", stack="fixture", task="fixture",
                     lane=Lane.HUNT, capability=capability())
    with pytest.raises(OSError, match="interrupted"):
        teams.ReviewContext.bundle(ctx, **arguments)
    assert not ctx._pinned
    assert teams.ReviewContext.bundle(ctx, **arguments)["text"] == "fixture prompt"
    assert len(attempts) == 2 and ctx._pinned == {"a" * 64}


def test_named_interruption_can_retry_without_rebinding_or_deleting_evidence(tmp_path, monkeypatch):
    owner = actor(tmp_path, 1)
    path = tmp_path / LAYOUTS["guidance"]
    original = shared.os.link

    def fail(source, destination):
        if "/requests/" in str(destination):
            raise OSError("interrupted candidate")
        return original(source, destination)

    with shared.publication_scope(context(owner)):
        monkeypatch.setattr(shared.os, "link", fail)
        with pytest.raises(OSError, match="interrupted"):
            shared.publish_named(tmp_path, path, b"pinned", namespace="guidance")
        saved = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        monkeypatch.setattr(shared.os, "link", original)
        shared.publish_named(tmp_path, path, b"pinned", namespace="guidance")
    assert all(p.read_bytes() == raw for p, raw in saved.items())
    assert not list(tmp_path.rglob(".publish-*"))
    assert len(receipts(owner, "guidance")) == 1


def test_runner_threads_index_handoff_and_audit_pin_named_objects(tmp_path):
    declarations = (artifact_only("source", "work", "source", "fixture", "Fixture source shard",
                                  artifacts=("data/indices/source/*.sqlite",), reason="fixture"),)
    runner = JobRunner(load_config(write_config(tmp_path)))

    def handler(unit):
        def build():
            root = unit.job.run_root
            path = root / "data/indices/source/a.sqlite"
            builder = IndexBuilder(path, name="source", fingerprint="a" * 64,
                                   target_snapshot="snapshot")
            builder.build()
            return file_sha256(path)
        with shared.PublicationThreadPoolExecutor(2) as pool:
            assert pool.submit(build).result()
        return {}

    job = Job("job_fixture", "fixture", handler, units=(Unit("work.only", handler),), datasets=declarations)
    outcome = runner.run(job, source_fingerprint="snapshot",
                         orchestration={"system": "dagster", "run_id": "thread-producer"})
    root = Path(outcome["attempt_root"]).parents[4]
    pinned = outcome["handoff"]["artifacts"]
    assert any("/shared/index-shard/" in item["path"] for item in pinned)
    assert any(item["path"].startswith(shared.NAMED + "/") for item in pinned)
    shared.verify_handoff(root, outcome["handoff"])
    report = build_inventory(InventoryInputs(
        root, root.name, "snapshot", {}, {}, {}, {}, {}, [],
        file_job_steps={"job_fixture": ("work",)}, file_declarations={"job_fixture": declarations}))
    assert report["audit"]["status"] == "PASSED"
    (root / "data/indices/source/a.sqlite").write_bytes(b"tampered")
    with pytest.raises(ValueError):
        shared.verify_handoff(root, outcome["handoff"])
    assert shared.current() is None


def test_cell_concurrency_retains_both_results_and_later_reuse(tmp_path):
    owners = [actor(tmp_path, i) for i in (1, 2)]
    root = tmp_path / "data/jobs/job_inference_security_review/cells"
    barrier = Barrier(2)

    def compute(owner):
        infer = ScriptedInfer(final())

        def invoke(request, **kwargs):
            barrier.wait(timeout=10)
            return infer(request, **kwargs)
        with shared.publication_scope(context(owner)):
            return run_cell(spec(), infer=invoke, core=FakeCore(), capability=capability(),
                            receipts_root=root, validate_final=validate)

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(compute, owners))
    assert len({outcome.receipt_paths[0] for outcome in outcomes}) == 2
    assert all(outcome.receipt_paths[0].is_file() for outcome in outcomes)
    consumer = actor(tmp_path, 3)
    infer = ScriptedInfer()
    with shared.publication_scope(context(consumer)):
        reused = reuse_or_run(spec(), infer=infer, core=FakeCore(), capability=capability(),
                              receipts_root=root, validate_final=validate)
    assert reused.reused and not infer.requests
    receipt = receipts(consumer, "review-cell")[0]
    assert receipt["mode"] == "reused" and receipt["producer_receipt"]
    assert shared.verify_receipt(tmp_path, receipt["producer_receipt"])["actor"]["attempt_id"] in {
        owner.actor["attempt_id"] for owner in owners}
