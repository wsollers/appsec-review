"""Real accepted-review, gate seal and certificate readers on inert producer artifacts."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.accepted_review import REVIEW_JOB, load_accepted_review
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.job_final_publication_gate import job, verify
from appsec_review.jobs.job_inference_security_review.datasets import DATASETS as REVIEW_DATASETS
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.review.packages import PackageSettings, assemble_packages, publish_packages, verify_package_manifest
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_json
from tests.downstream_contract_fixture import LEGACY_REVIEW_OUTPUTS, fixture as review_fixture
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
GATE = "job_final_publication_gate"


def _put(root, path, document):
    atomic_json(path, document)
    return artifact_ref(root, path)


@pytest.fixture
def gate_case(tmp_path):
    case = review_fixture(tmp_path)
    built = job.build_job(repository_root=ROOT)
    attempt = case.root / "data" / "jobs" / GATE / "attempts" / "attempt_0001"
    context = SimpleNamespace(
        run_root=case.root, repository_root=ROOT, config=case.config.job(GATE),
        events=EventLog(attempt / "events.jsonl"), upstream_handoffs={REVIEW_JOB: case.accepted_review.sha256})
    outputs = {}
    certificates = []

    def run(index):
        callback = built.units[index]
        step, task = callback.unit_id.split(".")
        unit = UnitContext(context, callback.unit_id, step, task,
                           attempt / "steps" / step / "tasks" / task, outputs)
        outputs[callback.unit_id] = callback.handler(unit)
        return outputs[callback.unit_id]

    def certify(document=None):
        result = deepcopy(outputs["acceptance.publish_handoff"])
        if document is not None:
            result["artifact"] = _put(case.root, attempt / "certificate.json", document)
            result["item_count"] = document["package_counts"]["total"]
            result["package_counts"] = document["package_counts"]
        # A complete synthetic acceptance envelope; the gate's validator/seal and reader are real.
        envelope = attempt.parent / f"certificate_{len(certificates) + 1}" / "handoff.json"
        write_fixture_handoff(case.root, envelope, {
            "job_id": GATE, "outputs": {"acceptance.publish_handoff": result},
            "target_snapshot": case.snapshot,
            "upstream_handoff_sha256": {REVIEW_JOB: case.accepted_review.sha256}})
        reference = artifact_ref(case.root, envelope)
        atomic_json(attempt.parent.parent / "latest.json",
                    {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
        certificates.append(reference)
        return reference

    return SimpleNamespace(case=case, root=case.root, outputs=outputs, run=run, certify=certify,
                           context=context, schemas=SchemaSet(ROOT / job.SCHEMA_ROOT))


def _context_packages(f):
    case = f.case
    assembly = assemble_packages(accept_manifest(f.root), PackageSettings(hunt_max_units=1))
    assert assembly.unit_contexts and any(package.kind == "hunt" for package in assembly.packages)
    accepted = case.accepted_review
    outputs = deepcopy(accepted.handoff["outputs"])
    manifest_path = publish_packages(assembly, f.root / "data" / "context-packages" / "hunt")
    references = [artifact_ref(f.root, manifest_path.parent / entry["path"])
                  for entry in assembly.manifest["unit_contexts"]]
    outputs["packages.assemble_hunt_packages"] = {"artifact": _put(
        f.root, manifest_path.parent / "lane.json", {
            "package_manifest": artifact_ref(f.root, manifest_path),
            "package_manifest_content_sha256": assembly.manifest["content_sha256"],
            "packages": [{"package_id": package.package_id, **artifact_ref(
                f.root, manifest_path.parent / "packages" / f"{package.package_id}.json")}
                for package in assembly.packages if package.lane == "hunt"]})}
    review_ref = outputs["publication.publish_handoff"]["artifact"]
    review = read_bound_json(f.root, review_ref)
    review.update(package_manifest_sha256=assembly.manifest["content_sha256"])
    outputs["publication.publish_handoff"]["artifact"] = _put(f.root, f.root / review_ref["path"], review)
    (f.root / accepted.handoff["resolving_paths"]["result"]).unlink()
    case.accepted_review = case.publish(
        REVIEW_JOB, outputs,
        datasets=tuple(row for row in REVIEW_DATASETS if row.output_kind in LEGACY_REVIEW_OUTPUTS),
        upstream=accepted.handoff["upstream_handoff_sha256"])
    f.context.upstream_handoffs[REVIEW_JOB] = case.accepted_review.sha256
    return references, manifest_path


def _publish(f):
    for index in range(3):
        f.run(index)
    f.certify()
    accepted, gate = verify.load_accepted_gate(f.root, f.schemas)
    assert accepted == accepted_handoff(f.root, GATE)
    return gate


def _invalidate_live_inputs(f):
    for producer in (REVIEW_JOB, "job_poc_generation", "job_remediation_planning",
                     "job_remediation_validation", "job_dossier_publication"):
        atomic_json(f.root / "data" / "jobs" / producer / "latest.json", {"unusable": True})
    f.case.config.source_path.write_text("invalid live configuration", encoding="utf-8")


def test_gate_certificate_retains_every_verified_unit_context_without_inlining_it(gate_case):
    f = gate_case
    references, _ = _context_packages(f)
    verified = load_accepted_review(f.root, SchemaSet(ROOT / SCHEMA_DIRECTORY), max_packages=10)
    gate = _publish(f)
    for reference in references:
        assert verified.document["bindings"].count(reference) == 1
        assert gate["bindings"].count(reference) == 1
    assert "unit_contexts" not in gate and "_decision_audit" not in gate
    assert gate["package_counts"]["total"] == 1
    assert gate["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert any(row["limitation_id"] == "decision_audit_not_run" for row in gate["limitations"])
    _invalidate_live_inputs(f)
    assert verify.load_accepted_gate(f.root, f.schemas)[1] == gate


@pytest.mark.parametrize("mutation", ["changed", "missing"])
def test_sealed_snapshot_rejects_later_unit_context_damage(gate_case, mutation):
    f = gate_case
    references, manifest = _context_packages(f)
    gate = _publish(f)
    _invalidate_live_inputs(f)
    path = f.root / references[0]["path"]
    if mutation == "changed":
        path.write_bytes(b"changed unit context")
    else:
        path.unlink()
    with pytest.raises(IntegrityError):
        verify_package_manifest(manifest, run_root=f.root)
    with pytest.raises(IntegrityError, match="artifact.*(changed|missing)"):
        verify.verify_gate_snapshot(f.root, gate)
    with pytest.raises(IntegrityError, match="artifact.*(changed|missing)"):
        verify.load_accepted_gate(f.root, f.schemas)


def _contradiction(document, mutation):
    row = document["packages"][0]
    identity = row["finding_package_id"]
    if mutation == "bucket_swap":
        document["buckets"]["publishable"] = []
        document["buckets"]["verification_backlog"] = [identity]
    elif mutation == "bucket_counts":
        document["package_counts"].update(publishable=0, withheld=1)
    elif mutation == "count_sum":
        document["package_counts"]["withheld"] = 1
    elif mutation == "wrong_state_bucket":
        row["bucket"] = "verification_backlog"
        document["buckets"]["publishable"] = []
        document["buckets"]["verification_backlog"] = [identity]
        document["package_counts"].update(publishable=0, verification_backlog=1)
    elif mutation == "invented_withholding":
        row.update(bucket="withheld", withheld_reasons=["poc_outcome_unavailable"])
        document["buckets"]["publishable"] = []
        document["buckets"]["withheld"] = [identity]
        document["package_counts"].update(publishable=0, withheld=1)
    elif mutation == "unreported_withholding":
        row["poc"] = {"status": "compile_verified", "result_id": None}
    elif mutation == "extraneous_reason":
        row["withheld_reasons"] = ["attack_chain_unavailable"]
    elif mutation == "duplicate_identity":
        duplicate = {**deepcopy(row), "bucket": "verification_backlog"}
        document["packages"].append(duplicate)
        document["buckets"]["verification_backlog"] = [identity]
        document["package_counts"].update(total=2, verification_backlog=1)
    elif mutation == "omitted_bucket":
        document["buckets"]["publishable"] = []
    elif mutation == "duplicate_bucket":
        document["buckets"]["verification_backlog"] = [identity]
    elif mutation == "dropped_package":
        document["packages"] = []
        document["buckets"]["publishable"] = []
        document["package_counts"].update(total=0, publishable=0)
    elif mutation == "erased_limitations":
        document["limitations"] = []
        document["status"] = "PUBLISHABLE"
    else:
        raise AssertionError(mutation)


@pytest.mark.parametrize("mutation", [
    "bucket_swap", "bucket_counts", "wrong_state_bucket", "duplicate_identity",
    "dropped_package", "erased_limitations",
])
def test_gate_seal_rejects_rehashed_classification_disagreement(gate_case, mutation):
    f = gate_case
    f.run(0)
    result = f.run(1)
    classified = read_bound_json(f.root, result["artifact"])
    _contradiction(classified, mutation)
    result["artifact"] = _put(f.root, f.root / result["artifact"]["path"], classified)
    with pytest.raises(IntegrityError, match="classification.*verified review"):
        f.run(2)
    assert "acceptance.publish_handoff" not in f.outputs


@pytest.mark.parametrize("mutation", [
    "bucket_swap", "bucket_counts", "count_sum", "wrong_state_bucket", "invented_withholding",
    "unreported_withholding", "extraneous_reason", "duplicate_identity", "omitted_bucket", "duplicate_bucket",
])
def test_certificate_reader_rejects_schema_valid_accounting_contradictions(gate_case, mutation):
    f = gate_case
    gate = _publish(f)
    _contradiction(gate, mutation)
    assert not f.schemas.errors("final-publication-gate", gate)
    f.certify(gate)
    _invalidate_live_inputs(f)
    with pytest.raises(IntegrityError, match="gate package"):
        verify.load_accepted_gate(f.root, f.schemas)
