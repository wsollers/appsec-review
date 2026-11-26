from __future__ import annotations

from pathlib import Path
import pytest

from appsec_review.config import load_config
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime import datasets as datasets_mod
from appsec_review.runtime.datasets import artifact_only
from appsec_review.runtime.repair import ComputationAdmission, IncompatibleComputation
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import shared as storage
from appsec_review.storage import validation as validation_mod
from appsec_review.storage.shared import safe_path, verify_receipt
from appsec_review.storage.validation import ValidationContext, validation_scope
from tests.release_support import write_release
from tests.test_job_runtime import write_config

FP = "a" * 64
DECLARATION = artifact_only(
    "shared",
    "work",
    "inventory",
    storage.RECEIPT_SCHEMA,
    "Fixture shared receipts",
    artifacts=("data/jobs/job_fixture/attempts/*/shared/*/*.json",),
    reason="not accepted evidence",
)


CONSUMER_DECLARATION = artifact_only(
    "shared",
    "work",
    "inventory",
    storage.RECEIPT_SCHEMA,
    "Consumer shared receipts",
    artifacts=("data/jobs/job_consumer/attempts/*/shared/*/*.json",),
    reason="not accepted evidence",
)


def _setup_fixture_run(tmp_path: Path):
    write_release(tmp_path, ("job_fixture", "job_consumer"))
    target = tmp_path / "target"
    target.mkdir()
    config_path = write_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write(
            '\n[review_policy.releases]\nplatform = "fixture-1"\nvalidation = "fixture-1"\n'
            '\n[jobs.job_consumer]\nname = "consumer"\nworkers = 1\n'
        )
    config = load_config(config_path)

    def compute(unit):
        owner = storage.SharedArtifacts.for_job(unit.job)
        obj = storage.put_bytes(owner.run_root, b"shared-artifact-payload")
        return {"receipt": owner.computed("fixture", FP, obj, computation={"request": FP})}

    producer = Job(
        "job_fixture",
        "fixture",
        compute,
        units=(Unit("work.only", compute),),
        datasets=(DECLARATION,),
    )
    runner = JobRunner(config)
    first = runner.run(producer, target_root=target, source_fingerprint="target")
    root = Path(first["attempt_root"]).parents[4]

    def consume(unit):
        storage.consume_handoff(root, first["handoff"])
        return {"ok": True}

    consumer = Job(
        "job_consumer",
        "consumer",
        consume,
        units=(Unit("work.only", consume),),
        datasets=(CONSUMER_DECLARATION,),
        consumes=("job_fixture",),
    )
    second = runner.run(
        consumer,
        run_id=root.name,
        target_root=target,
        source_fingerprint="target",
        upstream_handoffs={"job_fixture": first["handoff_sha256"]},
    )
    assert second["handoff"]["status"] == "ACCEPTED"
    return config, root, target, (producer, consumer), second


def test_resume_planner_incompatible_computation_skips_corrupt_artifact_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, root, target, job, _second = _setup_fixture_run(tmp_path)
    monkeypatch.setattr(
        ComputationAdmission,
        "verify",
        lambda self, run_root, receipt: (_ for _ in ()).throw(
            IncompatibleComputation("producer job release changed")
        ),
    )

    import appsec_review.storage.validation as validation_mod

    observed_calls: list[Path] = []
    real_observed = validation_mod.observed_digest

    def counted_observed(run_root: Path, path: Path) -> str:
        observed_calls.append(path)
        return real_observed(run_root, path)

    monkeypatch.setattr(validation_mod, "observed_digest", counted_observed)
    with validation_scope(root):
        plan = ResumePlanner(config, root, list(job), "target", target_root=target).plan()

    decision = plan[1]
    assert decision.action == "RUN"
    assert any("producer job release changed" in r for r in decision.reasons)
    assert not any(r.startswith("artifact ") for r in decision.reasons)
    assert [p for p in observed_calls if "job_consumer" in p.as_posix()] == []


def test_resume_planner_still_detects_tampered_and_missing_shared_artifacts(
    tmp_path: Path,
) -> None:
    config, root, target, job, second = _setup_fixture_run(tmp_path)
    obj_rel = next(
        item["path"]
        for item in second["handoff"]["artifacts"]
        if item["path"].startswith(storage.OBJECTS + "/")
    )
    obj_path = root / obj_rel
    obj_path.chmod(0o600)
    obj_path.write_bytes(b"tampered-bytes")

    with validation_scope(root):
        tampered = ResumePlanner(config, root, list(job), "target", target_root=target).plan()
    assert any(
        f"artifact changed: {obj_rel}" in reason
        for reason in tampered[1].reasons
    )

    obj_path.unlink()
    with validation_scope(root):
        missing = ResumePlanner(config, root, list(job), "target", target_root=target).plan()
    assert any(
        f"artifact missing: {obj_rel}" in reason
        for reason in missing[1].reasons
    )


def test_safe_path_and_validation_context_reject_sibling_prefix_symlinks_and_root(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run"
    sibling = tmp_path / "run_escape"
    run_root.mkdir()
    sibling.mkdir()
    secret = sibling / "secret.txt"
    secret.write_text("outside", encoding="utf-8")

    ctx = ValidationContext(run_root=run_root.resolve())
    with pytest.raises(ValueError, match="escapes its run"):
        ctx._resolved(run_root)
    with pytest.raises(ValueError, match="escapes its run"):
        ctx._resolved(secret)

    link = run_root / "link.txt"
    link.symlink_to(secret)
    with pytest.raises(ValueError, match="symlink"):
        safe_path(run_root, "link.txt")
    with pytest.raises(ValueError, match="canonical POSIX"):
        safe_path(run_root, "../run_escape/secret.txt")


def test_verify_receipt_caches_actor_claim_contracts_within_validation_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    config = load_config(write_config(tmp_path))

    def compute(unit):
        owner = storage.SharedArtifacts.for_job(unit.job)
        refs = []
        for idx in range(5):
            fp = f"{idx:064x}"
            obj = storage.put_bytes(owner.run_root, f"payload-{idx}".encode("utf-8"))
            refs.append(owner.computed("fixture", fp, obj, computation={"idx": idx}))
        return {"receipts": refs}

    job = Job(
        "job_fixture",
        "fixture",
        compute,
        units=(Unit("work.only", compute),),
        datasets=(DECLARATION,),
    )
    outcome = JobRunner(config).run(job, target_root=target, source_fingerprint="target")
    root = Path(outcome["attempt_root"]).parents[4]
    receipts = [
        ref
        for ref in outcome["handoff"]["artifacts"]
        if "/shared/fixture/" in ref["path"] and ref["path"].endswith(".json")
    ]
    assert len(receipts) == 5

    real_read_ds = datasets_mod.read_dataset_contract
    ds_calls = 0

    def counted_read_ds(*args, **kwargs):
        nonlocal ds_calls
        ds_calls += 1
        return real_read_ds(*args, **kwargs)

    monkeypatch.setattr(datasets_mod, "read_dataset_contract", counted_read_ds)
    with validation_scope(root):
        for ref in receipts:
            verify_receipt(root, ref)
    assert ds_calls == 1
