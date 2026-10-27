"""Shared bytes never stand in for computation, invocation, or accepted publication."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.derive import Derived, publish_derived
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import accepted_handoff
from appsec_review.inference import ModelResult
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_triage import CACHE_SCHEMA, cache_read, run_triage
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.datasets import artifact_only, dataset_contract
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage import shared as storage
from tests.review.test_lead_triage import GUIDANCE, PROFILE, RESULT_SCHEMA, SCHEMAS, lead, reader, settings
from tests.test_job_runtime import write_config


FP = "a" * 64
DECLARATION = artifact_only(
    "shared", "work", "inventory", storage.RECEIPT_SCHEMA, "Fixture shared receipts",
    artifacts=("data/jobs/job_fixture/attempts/*/shared/*/*.json",), reason="not accepted evidence")


def actor(root: Path, number: int, *, declarations=(DECLARATION,)) -> storage.SharedArtifacts:
    attempt = root / "data/jobs/job_fixture/attempts" / f"attempt_{number:04d}"
    claim = {"schema": "appsec-review/attempt-claim/1", "run_id": root.name, "job_id": "job_fixture",
             "attempt_id": attempt.name, "attempt_path": attempt.relative_to(root).as_posix(),
             "source_fingerprint": "snapshot",
             "orchestration": {"system": "dagster", "run_id": f"invocation-{number}"},
             "dataset_contract": dataset_contract("job_fixture", ("work",), declarations)}
    atomic_json(attempt / "claim.json", claim)
    return storage.SharedArtifacts.for_job(SimpleNamespace(
        run_root=root, attempt_root=attempt, run_id=root.name, attempt_id=attempt.name,
        orchestration=claim["orchestration"], config=SimpleNamespace(job_id="job_fixture")))


def produce(owner, payload=b"result", fingerprint=FP):
    obj = storage.put_bytes(owner.run_root, payload)
    return owner.computed("fixture", fingerprint, obj, computation={"request": fingerprint})


def invocation_context(root):
    owner = actor(root, 1)
    path = owner.attempt_root / "claim.json"
    claim = json.loads(path.read_bytes())
    claim["orchestration"]["node"] = "fixture__begin"
    atomic_json(path, claim)
    return SimpleNamespace(
        run_root=root, attempt_root=owner.attempt_root, run_id=root.name,
        attempt_id=owner.attempt_root.name, orchestration=dict(claim["orchestration"]),
        config=SimpleNamespace(job_id="job_fixture"))


@pytest.mark.parametrize("node", ["fixture__begin", "fixture__work__execute", "fixture__finalize"])
def test_dagster_nodes_share_attempt_identity_without_rewriting_producer(tmp_path, node):
    context = invocation_context(tmp_path)
    path = context.attempt_root / "claim.json"
    original = path.read_bytes()
    context.orchestration["node"] = node
    owner = storage.SharedArtifacts.for_job(context)
    receipt = storage.verify_receipt(tmp_path, produce(owner))
    assert receipt["actor"]["orchestration"] == {
        "system": "dagster", "run_id": "invocation-1", "node": "fixture__begin"}
    assert context.orchestration["node"] == node
    assert path.read_bytes() == original


@pytest.mark.parametrize("field,value", [
    ("run_id", "another-application-run"),
    ("attempt_id", "attempt_9999"),
    ("job_id", "job_other"),
    ("orchestrator", "other"),
    ("invocation", "another-dagster-run"),
    ("correlation", "changed"),
])
def test_dagster_node_tolerance_does_not_allow_identity_substitution(tmp_path, field, value):
    context = invocation_context(tmp_path)
    context.orchestration["node"] = "fixture__work__execute"
    if field == "job_id":
        context.config.job_id = value
    elif field in {"orchestrator", "invocation", "correlation"}:
        key = {"orchestrator": "system", "invocation": "run_id", "correlation": "extra"}[field]
        context.orchestration[key] = value
    else:
        setattr(context, field, value)
    with pytest.raises(ValueError, match="differs from original invocation"):
        storage.SharedArtifacts.for_job(context)


@pytest.mark.parametrize("orchestration", [
    {"system": "application", "run_id": "invocation-1", "node": "original"},
    {"system": "dagster", "node": "original"},
    {"system": "dagster", "run_id": "", "node": "original"},
])
def test_node_tolerance_requires_identified_dagster_invocation(tmp_path, orchestration):
    context = invocation_context(tmp_path)
    path = context.attempt_root / "claim.json"
    claim = json.loads(path.read_bytes())
    claim["orchestration"] = orchestration
    atomic_json(path, claim)
    context.orchestration = {**orchestration, "node": "changed"}
    with pytest.raises(ValueError, match="differs from original invocation"):
        storage.SharedArtifacts.for_job(context)


def inventory(root):
    return build_inventory(InventoryInputs(
        root, root.name, "snapshot", {}, {}, {}, {}, {}, [],
        file_job_steps={"job_fixture": ("work",)}, file_declarations={"job_fixture": (DECLARATION,)}))


def test_same_bytes_have_one_object_and_distinct_computation_receipts(tmp_path):
    one, two, three = (actor(tmp_path, i) for i in (1, 2, 3))
    first = produce(one)
    second = produce(two)
    third = produce(three, fingerprint="b" * 64)
    assert len(list((tmp_path / storage.OBJECTS).iterdir())) == 1
    receipts = [storage.verify_receipt(tmp_path, ref) for ref in (first, second, third)]
    assert all(value["mode"] == "computed" and value["producer_receipt"] is None for value in receipts)
    assert len({ref["sha256"] for ref in (first, second, third)}) == 3
    assert len({value["object"]["sha256"] for value in receipts}) == 1
    assert inventory(tmp_path)["audit"]["status"] == "PASSED"


def test_same_request_can_preserve_different_results_and_pins_selection(tmp_path):
    one, two, consumer = (actor(tmp_path, i) for i in (1, 2, 3))
    first = produce(one, b"result one")
    second = produce(two, b"result two")
    selected, receipt = consumer.lookup("fixture", FP)
    expected = min((first, second), key=lambda ref: ref["sha256"])
    assert selected["mode"] == "reused" and selected["producer_receipt"] == expected
    produce(actor(tmp_path, 4), b"later result")
    assert consumer.lookup("fixture", FP) == (selected, receipt)
    assert len(list((tmp_path / storage.OBJECTS).iterdir())) == 3
    assert selected["actor"]["orchestration"]["run_id"] == "invocation-3"
    origin = storage.verify_receipt(tmp_path, expected)
    assert origin["actor"]["orchestration"]["run_id"] in {"invocation-1", "invocation-2"}


def test_concurrent_writers_deduplicate_without_rebinding_receipts(tmp_path):
    owners = [actor(tmp_path, i) for i in range(1, 9)]
    with ThreadPoolExecutor(8) as pool:
        refs = list(pool.map(produce, owners))
    assert len(list((tmp_path / storage.OBJECTS).iterdir())) == 1
    assert len(list((tmp_path / storage.REQUESTS / "fixture" / FP).iterdir())) == 8
    assert len({ref["sha256"] for ref in refs}) == 8
    same = owners[0]
    assert produce(same) == refs[0]
    original = (tmp_path / refs[0]["path"]).read_bytes()
    with pytest.raises(ValueError, match="conflicts"):
        produce(same, b"different")
    assert (tmp_path / refs[0]["path"]).read_bytes() == original
    assert not list(tmp_path.rglob(".publish-*"))


@pytest.mark.parametrize("failure_at", [1, 2, 3])
def test_interrupted_publication_retains_complete_bytes_and_retries_idempotently(tmp_path, monkeypatch, failure_at):
    owner = actor(tmp_path, 1)
    original = storage.os.link
    calls = 0

    def fail(source, destination):
        nonlocal calls
        calls += 1
        if calls == failure_at:
            raise OSError("simulated interruption")
        return original(source, destination)

    monkeypatch.setattr(storage.os, "link", fail)
    with pytest.raises(OSError, match="interruption"):
        produce(owner)
    retained = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert not list(tmp_path.rglob(".publish-*"))
    monkeypatch.setattr(storage.os, "link", original)
    receipt = produce(owner)
    assert storage.verify_receipt(tmp_path, receipt)["mode"] == "computed"
    assert all(path.read_bytes() == value for path, value in retained.items())


@pytest.mark.parametrize("part,damage", [
    (part, damage) for part in ("object", "receipt", "claim", "candidate")
    for damage in ("missing", "tamper") if (part, damage) != ("candidate", "missing")
])
def test_missing_or_tampered_shared_state_never_silently_recomputes(tmp_path, part, damage):
    owner, consumer = actor(tmp_path, 1), actor(tmp_path, 2)
    ref = produce(owner)
    value = storage.verify_receipt(tmp_path, ref)
    paths = {"object": tmp_path / value["object"]["path"], "receipt": tmp_path / ref["path"],
             "claim": tmp_path / value["actor"]["claim"]["path"],
             "candidate": tmp_path / storage.REQUESTS / "fixture" / FP / f"{ref['sha256']}.json"}
    if damage == "missing":
        paths[part].unlink()
    else:
        paths[part].write_bytes(b"corrupt")
    with pytest.raises((ValueError, OSError)):
        consumer.lookup("fixture", FP)
    assert inventory(tmp_path)["audit"]["status"] == "FAILED"


@pytest.mark.parametrize("relative", ["../escape", "/absolute", "data/../escape", "data//object",
                                     "data\\object", "data/./object"])
def test_publication_rejects_noncanonical_or_escaping_paths(tmp_path, relative):
    with pytest.raises(ValueError):
        storage.immutable_bytes(tmp_path, relative, b"never written")


@pytest.mark.parametrize("parent", [False, True])
def test_publication_and_consumption_reject_symlinks_even_with_matching_bytes(tmp_path, parent):
    owner = actor(tmp_path, 1)
    ref = produce(owner)
    value = storage.verify_receipt(tmp_path, ref)
    obj = tmp_path / value["object"]["path"]
    if parent:
        directory = obj.parent
        destination = directory.with_name("moved")
        directory.rename(destination)
        directory.symlink_to(destination, target_is_directory=True)
    else:
        destination = obj.with_name("retained")
        obj.rename(destination)
        obj.symlink_to(destination)
    with pytest.raises(ValueError, match="symlink"):
        storage.put_bytes(tmp_path, b"result")
    with pytest.raises(ValueError, match="symlink"):
        actor(tmp_path, 2).lookup("fixture", FP)


def test_wrong_existing_object_bytes_are_never_overwritten(tmp_path):
    root = tmp_path / storage.OBJECTS
    root.mkdir(parents=True)
    path = root / hashlib.sha256(b"expected").hexdigest()
    path.write_bytes(b"wrong")
    with pytest.raises(ValueError, match="conflicts"):
        storage.put_bytes(tmp_path, b"expected")
    assert path.read_bytes() == b"wrong"


def test_partial_write_never_publishes_and_retries_without_deleting_evidence(tmp_path, monkeypatch):
    original = storage.os.fsync

    def fail(_descriptor):
        raise OSError("flush interrupted")

    monkeypatch.setattr(storage.os, "fsync", fail)
    with pytest.raises(OSError, match="flush interrupted"):
        storage.put_bytes(tmp_path, b"complete bytes")
    assert not list((tmp_path / storage.OBJECTS).iterdir())
    monkeypatch.setattr(storage.os, "fsync", original)
    obj = storage.put_bytes(tmp_path, b"complete bytes")
    assert storage.verify_reference(tmp_path, obj).read_bytes() == b"complete bytes"


def test_receipts_must_match_the_pinned_declaration_not_current_registration(tmp_path):
    owner = actor(tmp_path, 1, declarations=())
    with pytest.raises(ValueError, match="not declared"):
        produce(owner)
    assert actor(tmp_path, 2).lookup("fixture", FP) is None
    assert list((tmp_path / storage.OBJECTS).iterdir())
    assert inventory(tmp_path)["audit"]["status"] == "FAILED"


def test_unknown_and_undeclared_shared_files_are_not_accepted(tmp_path):
    actor(tmp_path, 1)
    storage.immutable_bytes(tmp_path, "data/shared/requests/fixture/unknown/stray.json", b"{}\n")
    report = inventory(tmp_path)
    assert report["audit"]["status"] == "FAILED"
    assert report["run_tree"]["scan_errors"]


def test_triage_fake_model_reuses_exact_result_and_records_both_invocations(tmp_path):
    one, two = actor(tmp_path, 1), actor(tmp_path, 2)
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult({"schema": RESULT_SCHEMA, "items": [
            {"lead_id": "lead-1", "severity": "high", "basis": "code_context", "reason": "Bounded test result"}
        ]})

    kwargs = dict(settings=settings(), profile=PROFILE, infer=infer, read_excerpt=reader,
                  reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    first = run_triage([lead("lead-1")], shared=one, **kwargs)
    second = run_triage([lead("lead-1")], shared=two, **kwargs)
    assert len(calls) == 1 and first.model_calls == 1 and second.model_calls == 0
    assert first.document["leads"][0]["origin"] == "model"
    assert second.document["leads"][0]["origin"] == "cache"
    producer = first.document["leads"][0]["shared_receipt"]
    consumer = storage.verify_receipt(tmp_path, second.document["leads"][0]["shared_receipt"])
    assert consumer["producer_receipt"] == producer
    assert storage.verify_receipt(tmp_path, producer)["actor"]["orchestration"]["run_id"] == "invocation-1"


def test_concurrent_nondeterministic_model_results_are_both_retained(tmp_path):
    owners = [actor(tmp_path, i) for i in (1, 2)]
    barrier = Barrier(2)

    def compute(pair):
        owner, severity = pair

        def infer(_request, *, timeout_seconds):
            barrier.wait(timeout=10)
            return ModelResult({"schema": RESULT_SCHEMA, "items": [
                {"lead_id": "lead-1", "severity": severity, "basis": "code_context",
                 "reason": "Nondeterministic fixture result"}]})

        return run_triage([lead("lead-1")], settings=settings(), profile=PROFILE, infer=infer,
                          read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS,
                          shared=owner)

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(compute, zip(owners, ("high", "medium"))))
    rows = [outcome.document["leads"][0] for outcome in outcomes]
    assert len({row["fingerprint"] for row in rows}) == 1
    assert {row["assessed"]["value"] for row in rows} == {"high", "medium"}
    assert all(row["origin"] == "model" for row in rows)
    receipts = [storage.verify_receipt(tmp_path, row["shared_receipt"]) for row in rows]
    assert len({value["object"]["sha256"] for value in receipts}) == 2
    assert all(value["mode"] == "computed" for value in receipts)
    selected, _ = actor(tmp_path, 3).lookup("lead-triage", rows[0]["fingerprint"])
    assert selected["producer_receipt"] in [row["shared_receipt"] for row in rows]


def test_verified_legacy_triage_is_readonly_and_does_not_invent_a_producer(tmp_path):
    owner = actor(tmp_path, 1)
    directory = tmp_path / "data/jobs/job_fixture/triage-cache"
    body = {"schema": CACHE_SCHEMA, "fingerprint": FP, "lead_id": "lead-1",
            "item": {"lead_id": "lead-1", "severity": "high"}, "batch_id": "batch-1",
            "request_sha256": "b" * 64, "model_profile": {}}
    path = directory / f"{FP}.json"
    atomic_json(path, {**body, "entry_sha256": sha256_hex(body)})
    before = path.read_bytes()
    hit = cache_read(directory, FP, "lead-1", shared=owner)
    receipt = storage.verify_receipt(tmp_path, hit["shared_receipt"])
    assert receipt["mode"] == "reused" and receipt["producer_receipt"] is None
    assert receipt["legacy"] == "unknown-original-producer"
    assert path.read_bytes() == before and not (tmp_path / storage.OBJECTS).exists()
    assert cache_read(directory, FP, "lead-1", shared=owner) == hit
    path.write_bytes(b"broken")
    with pytest.raises(ValueError):
        cache_read(directory, FP, "lead-1", shared=owner)


def test_derived_shard_and_checkpoint_are_shared_and_legacy_is_preserved(tmp_path):
    one, two = actor(tmp_path, 1), actor(tmp_path, 2)
    calls = []

    def build():
        calls.append(1)
        return Derived(coverage=[("fixture", "complete", None)])

    kwargs = dict(index="inventory", shard_id="fixture", job_id="job_fixture", unit_id="work.only",
                  rule="fixture", rule_version="1", snapshot="snapshot", inputs={}, build=build)
    first = publish_derived(tmp_path, shared=one, **kwargs)
    second = publish_derived(tmp_path, shared=two, **kwargs)
    assert len(calls) == 1 and not first["reused"] and second["reused"]
    assert canonical_json(first["index_identity"]) == canonical_json(second["index_identity"])
    assert first["index_identity"]["relative_path"].startswith(storage.OBJECTS + "/")
    assert len(list((tmp_path / storage.OBJECTS).iterdir())) == 2
    legacy = publish_derived(tmp_path, **{**kwargs, "rule_version": "legacy"})
    before = {p: p.read_bytes() for p in (tmp_path / "data/indexing").rglob("*.json")}
    reused = publish_derived(tmp_path, shared=two, **{**kwargs, "rule_version": "legacy"})
    receipt = storage.verify_receipt(tmp_path, reused["shared_receipt"])
    assert receipt["legacy"] == "unknown-original-producer"
    assert all(p.read_bytes() == content for p, content in before.items())
    path = tmp_path / legacy["index_identity"]["relative_path"]
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="integrity"):
        publish_derived(tmp_path, **{**kwargs, "rule_version": "legacy"})
    assert path.read_bytes() == b"corrupt"


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_new_runner_restores_claimed_admission_before_unit_input_validation(tmp_path, monkeypatch, mode):
    from appsec_review.storage import validation

    target = tmp_path / "target"
    target.mkdir()
    config_path = write_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write(
            f'\n[review_policy]\nmode = "{mode}"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}\n'
            '\n[jobs.job_consumer]\nname = "consumer"\nworkers = 1\n')
    config = load_config(config_path)

    def compute(unit):
        return {"receipt": produce(storage.SharedArtifacts.for_job(unit.job))}

    producer = Job("job_fixture", "fixture", compute, units=(Unit("work.only", compute),),
                   datasets=(DECLARATION,))
    first = JobRunner(config).run(producer, target_root=target, source_fingerprint="target")
    root = Path(first["attempt_root"]).parents[4]
    ref = next(item for item in first["handoff"]["artifacts"]
               if item["path"].startswith(storage.OBJECTS + "/"))
    payload = root / ref["path"]
    assert validation.current_validation(root) is None
    digest = validation.file_sha256
    hashes, phases = [], []

    def counted(path):
        if path == payload:
            hashes.append(path)
        return digest(path)

    def validate_input(unit, result):
        assert result is None
        context = validation.current_validation(root)
        assert context is not None
        assert ((ref["path"], ref["sha256"]) in context.admitted) == (mode == "first_party_managed")
        assert storage.verify_reference(root, ref).read_bytes() == b"result"
        phases.append("validated")

    def consume(unit):
        assert phases == ["validated"]
        storage.consume_handoff(root, first["handoff"])
        return {"artifact": ref}

    monkeypatch.setattr(validation, "file_sha256", counted)
    consumer = Job("job_consumer", "consumer", consume,
                   units=(Unit("work.only", consume, input_validators=(validate_input,)),),
                   consumes=("job_fixture",))
    outcome = JobRunner(config).run(
        consumer, run_id=root.name, target_root=target, source_fingerprint="target",
        upstream_handoffs={"job_fixture": first["handoff_sha256"]})
    assert outcome["handoff"]["status"] == "ACCEPTED"
    assert outcome["handoff"]["upstream_handoff_sha256"] == {"job_fixture": first["handoff_sha256"]}
    assert (len(hashes) == 0) if mode == "first_party_managed" else bool(hashes)
    assert validation.current_validation(root) is None


@pytest.mark.parametrize("damage", ["object_tamper", "receipt_missing"])
def test_handoff_resume_and_downstream_failure_keep_original_producer(tmp_path, damage):
    config_path = write_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write('\n[review_policy.releases]\nplatform = "fixture-1"\nvalidation = "fixture-1"\n')
    runner = JobRunner(load_config(config_path))

    def compute(unit):
        owner = storage.SharedArtifacts.for_job(unit.job)
        hit = owner.lookup("fixture", FP)
        if hit is None:
            produce(owner)
        return {"reused": hit is not None}

    job = Job("job_fixture", "fixture", compute, units=(Unit("work.only", compute),),
              datasets=(DECLARATION,))
    first = runner.run(job, orchestration={"system": "dagster", "run_id": "original"})
    root = Path(first["attempt_root"]).parents[4]
    receipt = next(item for item in first["handoff"]["artifacts"] if "/shared/fixture/" in item["path"])
    original = storage.verify_receipt(root, receipt)
    assert len(first["handoff"]["artifacts"]) >= 4

    def fail(unit):
        compute(unit)
        raise ValueError("downstream failure")

    with pytest.raises(RuntimeError, match="downstream failure"):
        runner.run(replace(job, units=(Unit("work.only", fail),)), run_id=root.name,
                   orchestration={"system": "dagster", "run_id": "failed"})
    third = runner.run(job, run_id=root.name, orchestration={"system": "dagster", "run_id": "later"})
    assert third["result"]["outputs"]["work.only"]["reused"]
    assert storage.verify_receipt(root, receipt) == original
    reasons, _ = ResumePlanner(runner.config, root, (job,), "none").accepted(job, {})
    assert not reasons
    assert inventory(root)["audit"]["status"] == "PASSED"
    if damage == "object_tamper":
        (root / original["object"]["path"]).write_bytes(b"tampered")
    else:
        (root / receipt["path"]).unlink()
    reasons, _ = ResumePlanner(runner.config, root, (job,), "none").accepted(job, {})
    assert any("shared" in reason or "artifact changed" in reason for reason in reasons)
    with pytest.raises(ValueError, match="integrity"):
        accepted_handoff(root, "job_fixture")
