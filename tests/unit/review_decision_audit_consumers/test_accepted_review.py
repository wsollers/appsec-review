import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.accepted_review import load_accepted_review
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.job_dossier_publication.inputs import load_inputs, verify_snapshot
from appsec_review.jobs.job_dossier_publication.job import build_job
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.metadata import build_publication, policy_document
from appsec_review.review.decision_audit.reader import REVIEW_JOB, expected_origin, load_decision_audit
from appsec_review.storage import atomic_bytes, atomic_json, file_sha256
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import producer_contract
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import UnitContext
from tests.dossier_fixture import settings as dossier_settings
from tests.downstream_contract_fixture import fixture as review_fixture
from tests.handoff_fixture import write_fixture_handoff
from .helpers import audit_declarations

ROOT = Path(__file__).resolve().parents[3]


def accepted_case(tmp_path):
    case = review_fixture(tmp_path)
    historical = accepted_handoff(case.root, REVIEW_JOB)
    historical_declarations = tuple(row for row in producer_contract(case.root, historical.handoff)
                                    if row.output_kind not in {item.output_kind for item in audit_declarations(
                                        historical.handoff["resolving_paths"]["attempt"])})
    case.publish(REVIEW_JOB, historical.handoff["outputs"], datasets=historical_declarations,
                 upstream=historical.handoff["upstream_handoff_sha256"])
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    original = load_accepted_review(case.root, schemas, max_packages=10)
    legacy = load_accepted_review(case.root, schemas, max_packages=10, include_decision_audit=True)
    assert original.decision_audit is None and legacy.decision_audit.unavailable_reason == "legacy_unrecorded"
    assert original.document == legacy.document
    assert load_inputs(case.root, legacy.document, dossier_settings(), decision_audit=legacy.decision_audit) == \
        load_inputs(case.root, original.document, dossier_settings())
    before_bytes = (case.root / legacy.document["inputs"]["review_handoff"]["path"]).read_bytes()

    accepted = accepted_handoff(case.root, REVIEW_JOB)
    outputs = dict(accepted.handoff["outputs"])
    attempt = case.root / accepted.handoff["resolving_paths"]["attempt"]
    directory = attempt / "steps/consumer-fixture"
    copies = []

    def copy(old, relative):
        destination = directory / relative
        atomic_bytes(destination, (case.root / old).read_bytes())
        reference = artifact_ref(case.root, destination)
        copies.append(reference)
        return reference

    review_ref = copy(legacy.document["inputs"]["review_handoff"]["path"], "review.json")
    for row in legacy.document["packages"]:
        copy(row["path"], "findings/" + row["finding_package_id"] + ".json")
    old_ledger = Path(legacy.document["inputs"]["projection"]["path"]).parent
    for name in ("projection.json", "claim-ledger.jsonl", "ledger-head.json"):
        copied = copy((old_ledger / name).as_posix(), "ledger/" + name)
        if name == "ledger-head.json":
            outputs["publication.publish_claim_ledger"] = {"artifact": copied}
    old_scope = read_bound_json(case.root, outputs["scope.accept_manifest"]["artifact"])
    manifest = read_bound_json(case.root, {"path": old_scope["manifest_path"], "sha256": old_scope["manifest_sha256"]})
    scope = {**old_scope, "run_id": case.root.name, "target_snapshot": accepted.handoff["target_snapshot"],
             "shards": [{key: row.get(key, "default") for key in ("name", "shard_id", "sha256")}
                        for row in manifest["indexes"]]}
    atomic_json(directory / "scope.json", scope)
    outputs["scope.accept_manifest"] = {"artifact": artifact_ref(case.root, directory / "scope.json")}
    atomic_json(directory / "adjudications.json", {"adjudications": []})
    outputs["adjudicate.apply_policy"] = {"artifact": artifact_ref(case.root, directory / "adjudications.json")}
    frozen = json.loads((case.root / "data/configuration/resolved.json").read_bytes())
    settings = DecisionAuditSettings.from_mapping(frozen["jobs"][REVIEW_JOB]["settings"]["decision_audit"], "audit")
    publication = {**outputs["publication.publish_handoff"], "artifact": review_ref}
    origin = expected_origin(handoff=accepted.handoff, published=publication,
                             review=json.loads(before_bytes), scope=scope, policy=policy_document(settings))
    audit_manifest = c.AuditManifest(origin, (), tuple(
        c.CoverageCount(pop, None, 0, 0, None, c.CoverageReason.INPUT_UNAVAILABLE) for pop in c.Population))
    audit_dir = attempt / "artifacts/decision-audit"
    atomic_bytes(audit_dir / "manifest.json", c.canonical_bytes(audit_manifest))
    ref = c.ManifestRef.of((audit_dir / "manifest.json").relative_to(case.root).as_posix(), audit_manifest)
    atomic_json(audit_dir / "publication.json", build_publication(origin, settings=settings, manifest=ref))
    publication["metadata_path"] = (audit_dir / "publication.json").relative_to(case.root).as_posix()
    outputs["publication.publish_handoff"] = publication
    declarations = (*producer_contract(case.root, accepted.handoff),
                    *audit_declarations(attempt.relative_to(case.root).as_posix()))
    claim = json.loads((attempt / "claim.json").read_bytes())
    claim["dataset_contract"] = dataset_contract(REVIEW_JOB, tuple(sorted({row.step for row in declarations})),
                                                declarations)
    atomic_json(attempt / "claim.json", claim)
    (attempt / "result.json").unlink()
    path = write_fixture_handoff(case.root, attempt / "handoff.json", {
        "job_id": REVIEW_JOB, "target_snapshot": case.snapshot, "source_fingerprint": case.snapshot,
        "outputs": outputs, "upstream_handoff_sha256": accepted.handoff["upstream_handoff_sha256"],
        "artifacts": [*copies, artifact_ref(case.root, audit_dir / "manifest.json"),
                      artifact_ref(case.root, audit_dir / "publication.json")]})
    atomic_json(attempt.parent.parent / "latest.json",
                {"handoff_path": path.relative_to(case.root).as_posix(), "handoff_sha256": file_sha256(path)})
    return case, schemas, original, ref, before_bytes, review_ref


def test_real_review_loader_default_legacy_and_optin_do_not_rewrite_public_state(tmp_path):
    case, schemas, original, ref, before_bytes, review_ref = accepted_case(tmp_path)
    plain = load_accepted_review(case.root, schemas, max_packages=10)
    enriched = load_accepted_review(case.root, schemas, max_packages=10, include_decision_audit=True)
    assert plain.decision_audit is None and enriched.decision_audit.available
    assert plain.document["packages"] == enriched.document["packages"]
    assert [{key: value for key, value in row.items() if key != "path"} for row in plain.document["packages"]] == [
        {key: value for key, value in row.items() if key != "path"} for row in original.document["packages"]]
    assert set(row["path"] for row in enriched.document["bindings"]) > set(
        row["path"] for row in plain.document["bindings"])
    assert "decision_basis" not in json.dumps(enriched.document)
    assert (case.root / review_ref["path"]).read_bytes() == before_bytes
    assert load_decision_audit(case.root).reference == ref
    inputs = load_inputs(case.root, enriched.document, dossier_settings(), decision_audit=enriched.decision_audit)
    assert inputs["decision_audit"] == ref.to_dict()
    verify_snapshot(case.root, inputs, dossier_settings())


def test_dossier_units_reverify_the_sidecar_and_reject_a_substituted_reference(tmp_path):
    case, _, _, reference, _, _ = accepted_case(tmp_path)
    directory = case.root / "data/jobs/job_dossier_publication/attempts/attempt_0001"
    events = EventLog(directory / "events.jsonl")
    context = SimpleNamespace(run_root=case.root, repository_root=ROOT, events=events,
                              config=SimpleNamespace(settings=dossier_settings(render_pdf=False).identity()))

    class Core:
        def read_excerpt(self, *, identity, context_lines):
            return {"results": [], "truncated": False}

    job = build_job(repository_root=ROOT, core_factory=lambda *_: Core())
    loaded = job.units[0].handler(UnitContext(context, "load.verify_inputs", "load", "verify_inputs",
                                              directory / "load", {}))
    inputs = read_bound_json(case.root, loaded["artifact"])
    assert inputs["decision_audit"] == reference.to_dict()
    created = job.units[1].handler(UnitContext(context, "dossiers.create", "dossiers", "create",
                                               directory / "create", {"load.verify_inputs": loaded}))
    summary = read_bound_json(case.root, created["artifact"])
    assert len(summary["items"]) == 1
    model = read_bound_json(case.root, summary["items"][0]["files"]["json"])
    assert model["decision_basis"]["reason"] == "decision_basis_not_emitted"
    assert model["state"] == "confirmed"
    alternate = directory / "alternate-manifest.json"
    atomic_bytes(alternate, (case.root / reference.path).read_bytes())
    inputs["decision_audit"]["path"] = alternate.relative_to(case.root).as_posix()
    alternate_inputs = directory / "alternate-inputs.json"
    atomic_json(alternate_inputs, inputs)
    with pytest.raises(IntegrityError, match="audit changed"):
        job.units[1].handler(UnitContext(context, "dossiers.create", "dossiers", "create",
            directory / "rejected-create", {"load.verify_inputs": {"artifact": artifact_ref(case.root, alternate_inputs)}}))


def test_fresh_unavailable_audit_retains_its_reason_in_the_protected_dossier(tmp_path):
    case, _, _, reference, _, _ = accepted_case(tmp_path)
    accepted = accepted_handoff(case.root, REVIEW_JOB)
    publication = accepted.handoff["outputs"]["publication.publish_handoff"]
    frozen = json.loads((case.root / "data/configuration/resolved.json").read_bytes())
    settings = DecisionAuditSettings.from_mapping(frozen["jobs"][REVIEW_JOB]["settings"]["decision_audit"], "audit")
    atomic_json(case.root / publication["metadata_path"], build_publication(
        reference.origin, settings=settings, unavailable_reason="input_unavailable"))
    attempt = case.root / accepted.handoff["resolving_paths"]["attempt"]
    artifacts = [artifact_ref(case.root, case.root / row["path"]) for row in accepted.handoff["artifacts"]
                 if row["path"] != (attempt / "result.json").relative_to(case.root).as_posix()]
    (attempt / "result.json").unlink()
    path = write_fixture_handoff(case.root, attempt / "handoff.json", {
        "job_id": REVIEW_JOB, "target_snapshot": case.snapshot, "source_fingerprint": case.snapshot,
        "outputs": accepted.handoff["outputs"], "artifacts": artifacts,
        "upstream_handoff_sha256": accepted.handoff["upstream_handoff_sha256"]})
    atomic_json(attempt.parent.parent / "latest.json",
                {"handoff_path": path.relative_to(case.root).as_posix(), "handoff_sha256": file_sha256(path)})
    directory = case.root / "data/jobs/job_dossier_publication/attempts/attempt_0001"
    context = SimpleNamespace(run_root=case.root, repository_root=ROOT, events=EventLog(directory / "events.jsonl"),
                              config=SimpleNamespace(settings=dossier_settings(render_pdf=False).identity()))
    core = SimpleNamespace(read_excerpt=lambda **_: {"results": [], "truncated": False})
    job = build_job(repository_root=ROOT, core_factory=lambda *_: core)
    loaded = job.units[0].handler(UnitContext(context, "load.verify_inputs", "load", "verify_inputs",
                                              directory / "load", {}))
    snapshot = read_bound_json(case.root, loaded["artifact"])
    assert snapshot["decision_audit_unavailable_reason"] == "input_unavailable"
    assert "decision_audit" not in snapshot
    result = job.units[1].handler(UnitContext(context, "dossiers.create", "dossiers", "create",
                                              directory / "create", {"load.verify_inputs": loaded}))
    summary = read_bound_json(case.root, result["artifact"])
    dossier = read_bound_json(case.root, summary["items"][0]["files"]["json"])
    assert dossier["state"] == "confirmed"
    assert dossier["decision_basis"]["available"] is False
    assert dossier["decision_basis"]["reason"] == "input_unavailable"
