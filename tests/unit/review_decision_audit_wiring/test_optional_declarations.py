"""Direct admission/observation units over small, real hash-bound synthetic handoffs.

No producer job, consumer job, model or graph runner executes. The handoff helper writes
only immutable control fixtures; admission, contract decoding and observed reads are real.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest

from appsec_review.interchange import HANDOFF_SCHEMA
from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, accepted_inputs, read_job_contract,
)
from appsec_review.runtime.datasets import dataset_contract, protected
from appsec_review.runtime.inputs import admit_inputs, input_read_scope, observe_output
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
PRODUCER = "job_fixture"
KIND = "review_audit_metadata"
SCHEMA = "appsec-review/review-audit-publication/1"
SNAPSHOT = "target-sha256:" + "a" * 64
ATTEMPT = f"data/jobs/{PRODUCER}/attempts/attempt_0001"
PAYLOAD = ATTEMPT + "/artifacts/decision-audit/publication.json"
OLD_MODES = (Availability.REQUIRED, Availability.OPTIONAL, Availability.WHEN_ENABLED)
MODES = (*OLD_MODES, Availability.WHEN_DECLARED)


def requirement(mode=Availability.WHEN_DECLARED, *, missing=None, **changes):
    return InputRequirement(
        PRODUCER, KIND, SCHEMA, EvidenceAuthority.OPERATIONAL, mode,
        missing if missing is not None else MissingPolicy.REJECT if mode is Availability.REQUIRED else MissingPolicy.GAP,
        **changes)


def resign(document):
    body = {key: value for key, value in document.items() if key != "sha256"}
    document["sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return document


def fixture(tmp_path, *, declaration="present", emitted=True, terminal="SUCCEEDED", target=SNAPSHOT):
    root = tmp_path / "run-admission"
    attempt = root / ATTEMPT
    settings = tomllib.loads((ROOT / "appsec-review.toml").read_text())["build_capture"]
    config_path = root / "data/configuration/resolved.json"
    atomic_json(config_path, {"build_capture": settings, "jobs": {PRODUCER: {
        "name": "synthetic producer", "settings": {}, "steps": {}}}})
    atomic_json(root / "data/configuration/manifest.json", {"resolved_sha256": file_sha256(config_path)})
    dataset = protected(KIND, "publish", "inference_review", SCHEMA, "Synthetic protected metadata.",
                        artifacts=(PAYLOAD,), reason="unit fixture", authority=EvidenceAuthority.OPERATIONAL)
    if declaration == "unrelated":
        dataset = replace(dataset, output_kind="unrelated")
    elif declaration == "wrong-schema":
        dataset = replace(dataset, schema=SCHEMA + "-other")
    elif declaration == "wrong-authority":
        dataset = replace(dataset, authority=EvidenceAuthority.PRODUCER_EVIDENCE)
    declared = () if declaration == "absent" else (dataset,)
    contract = dataset_contract(PRODUCER, ("publish",), declared)
    if declaration in {"unknown-authority", "invalid-authority"}:
        if declaration == "unknown-authority":
            contract["datasets"][0].pop("authority")
        else:
            contract["datasets"][0]["authority"] = "invented-authority"
        resign(contract)
    atomic_json(attempt / "claim.json", {"dataset_contract": contract})
    atomic_json(root / PAYLOAD, {"synthetic": "not audit evidence"})
    ref = {"path": PAYLOAD, "sha256": file_sha256(root / PAYLOAD)}
    output = {"terminal_status": terminal, "gaps": [] if terminal == "SUCCEEDED" else ["synthetic coverage gap"]}
    if emitted:
        output["artifact"] = ref
    handoff_path = write_fixture_handoff(
        root, attempt / "handoff.json", {"job_id": PRODUCER, "outputs": {"publish.emit": output}},
        target_snapshot=target)
    handoff = json.loads(handoff_path.read_bytes())
    context = SimpleNamespace(
        run_root=root, config=SimpleNamespace(job_id="job_reader"), evidence_target_snapshot=SNAPSHOT,
        upstream_handoffs={PRODUCER: file_sha256(handoff_path)}, external_input_selection=None,
        contract=JobContract(inputs=(requirement(),)))
    return SimpleNamespace(root=root, context=context, ref=ref, handoff=handoff, handoff_path=handoff_path)


@pytest.mark.parametrize("channel,kind", [
    (InputChannel.HANDOFF, "handoff"),
    (InputChannel.EXTERNAL, KIND), (InputChannel.TRANSACTION, KIND),
    (InputChannel.EXTERNAL, "handoff"), (InputChannel.TRANSACTION, "handoff"),
])
def test_when_declared_is_only_for_non_envelope_handoff_datasets(channel, kind):
    with pytest.raises(ValueError, match="non-envelope handoff dataset"):
        replace(requirement(), channel=channel, output_kind=kind)
    document = JobContract(inputs=(requirement(),)).document()
    document["inputs"][0].update(channel=channel.value, output_kind=kind)
    with pytest.raises(ValueError, match="non-envelope handoff dataset"):
        read_job_contract(resign(document))


def test_new_mode_roundtrips_without_new_fields_or_envelope_permission():
    contract = JobContract(inputs=(requirement(),))
    document = contract.document()
    assert Availability.WHEN_DECLARED.value == "when_output_declared"
    assert document["schema"] == "appsec-review/job-contract/1"
    assert read_job_contract(document) == contract
    assert contract.consumes == (PRODUCER,)
    assert set(document["inputs"][0]) == {
        "producer", "output_kind", "schema", "authority", "availability", "missing", "coverage", "channel"}
    assert not requirement().required(set()) and not requirement().required({PRODUCER})
    with pytest.raises(ValueError, match="non-envelope handoff dataset"):
        accepted_inputs(PRODUCER, (), availability=Availability.WHEN_DECLARED)
    ordinary = InputRequirement(PRODUCER, KIND, SCHEMA)
    assert ordinary.availability is Availability.OPTIONAL
    assert ordinary.missing is MissingPolicy.GAP


@pytest.mark.parametrize("availability,missing,digest", [
    ("required", "reject", "2bf0ec6784bcbd3e5f19f3d5258a3bb04d7622fc9042e629ea2c66d718a995b4"),
    ("optional", "gap", "c904ef75779329eaf17dfecfe81755f58179e2bb2e47e38aa80ce6108633b519"),
    ("when_producer_enabled", "reject", "59af9e6ac48bb191a92b9a150de42ae413c6a446f51410305635cbc5837023fc"),
], ids=["required", "optional", "conditional"])
def test_historical_serialized_contracts_keep_prechange_shapes_and_hashes(availability, missing, digest):
    # Hashes were captured from the unchanged parent base, not generated by the new enum.
    document = {
        "schema": "appsec-review/job-contract/1", "always_execute": False, "dispatch": "review_graph",
        "inputs": [{"authority": "operational", "availability": availability, "channel": "handoff",
                    "coverage": "allow_partial", "missing": missing, "output_kind": KIND,
                    "producer": PRODUCER, "schema": SCHEMA}],
        "propagate_handoff": True, "schedule_after": [], "target_access": "checkout", "sha256": digest,
    }
    original = deepcopy(document)
    assert read_job_contract(document).document() == document == original
    changed = deepcopy(document)
    changed["inputs"][0]["availability"] = Availability.WHEN_DECLARED.value
    with pytest.raises(ValueError, match="identity"):
        read_job_contract(changed)
    assert read_job_contract(resign(changed)).document() == changed
    assert changed["sha256"] != digest


@pytest.mark.parametrize("declaration", ["absent", "unrelated"])
@pytest.mark.parametrize("mode", OLD_MODES, ids=lambda item: item.name.lower())
@pytest.mark.parametrize("enabled", [False, True])
def test_ordinary_modes_still_reject_a_missing_output_declaration(tmp_path, declaration, mode, enabled):
    f = fixture(tmp_path, declaration=declaration)
    f.context.contract = JobContract(inputs=(requirement(mode),))
    with pytest.raises(ValueError, match="producer output contract mismatch"):
        admit_inputs(f.context, {PRODUCER} if enabled else set())


@pytest.mark.parametrize("missing", tuple(MissingPolicy), ids=lambda item: item.value)
@pytest.mark.parametrize("declaration", ["absent", "unrelated"])
@pytest.mark.parametrize("emitted", [False, True])
def test_explicit_mode_records_absence_and_retains_accepted_supply_identity(tmp_path, missing, declaration, emitted):
    f = fixture(tmp_path, declaration=declaration, emitted=emitted)
    f.context.contract = JobContract(inputs=(requirement(missing=missing),))
    admission = admit_inputs(f.context, {PRODUCER})
    assert admission["schema"] == "appsec-review/input-admission/1"
    assert admission["contract_sha256"] == f.context.contract.document()["sha256"]
    assert admission["requirements"] == [{
        "channel": "handoff", "producer": PRODUCER, "output_kind": KIND, "schema": SCHEMA,
        "authority": "operational", "available": False, "supplied": False, "read": False, "cited": None,
        "handoff_sha256": f.context.upstream_handoffs[PRODUCER],
        "attempt_id": "attempt_0001", "target_snapshot": SNAPSHOT, "coverage": f.handoff["coverage"],
        "status": "not_applicable" if missing is MissingPolicy.NOT_APPLICABLE else "gap",
    }]
    assert file_sha256(f.handoff_path) == f.context.upstream_handoffs[PRODUCER]


@pytest.mark.parametrize("mode", MODES, ids=lambda item: item.name.lower())
@pytest.mark.parametrize("emitted", [False, True])
def test_present_matching_declaration_preserves_availability_and_required_behavior(tmp_path, mode, emitted):
    f = fixture(tmp_path, emitted=emitted)
    f.context.contract = JobContract(inputs=(requirement(mode, missing=MissingPolicy.REJECT),))
    if not emitted and mode in {Availability.REQUIRED, Availability.WHEN_ENABLED}:
        with pytest.raises(ValueError, match="required input unavailable"):
            admit_inputs(f.context, {PRODUCER})
        return
    row = admit_inputs(f.context, {PRODUCER})["requirements"][0]
    assert row["available"] is emitted and row["supplied"] is emitted
    assert row["status"] == ("supplied" if emitted else "gap")
    assert row["read"] is False and row["cited"] is None


@pytest.mark.parametrize("mode", MODES, ids=lambda item: item.name.lower())
@pytest.mark.parametrize("declaration", ["wrong-schema", "wrong-authority", "unknown-authority", "invalid-authority"])
def test_no_mode_accepts_incompatible_or_unknown_present_declarations(tmp_path, mode, declaration):
    f = fixture(tmp_path, declaration=declaration)
    f.context.contract = JobContract(inputs=(requirement(mode),))
    with pytest.raises(ValueError, match="contract mismatch|authority mismatch|EvidenceAuthority"):
        admit_inputs(f.context, {PRODUCER})


@pytest.mark.parametrize("mode", MODES, ids=lambda item: item.name.lower())
@pytest.mark.parametrize("enabled", [False, True])
def test_missing_producer_keeps_existing_required_and_conditional_policy(tmp_path, mode, enabled):
    context = SimpleNamespace(contract=JobContract(inputs=(requirement(mode, missing=MissingPolicy.REJECT),)),
                              upstream_handoffs={})
    if mode is Availability.REQUIRED or (mode is Availability.WHEN_ENABLED and enabled):
        with pytest.raises(ValueError, match="required input unavailable"):
            admit_inputs(context, {PRODUCER} if enabled else set())
    else:
        row = admit_inputs(context, {PRODUCER} if enabled else set())["requirements"][0]
        assert row["available"] is None and row["supplied"] is False and row["status"] == "gap"


@pytest.mark.parametrize("declaration", ["absent", "present"])
@pytest.mark.parametrize("terminal", ["SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED"])
@pytest.mark.parametrize("policy", tuple(CoveragePolicy), ids=lambda item: item.value)
def test_compatibility_does_not_skip_coverage_policy(tmp_path, declaration, terminal, policy):
    f = fixture(tmp_path, declaration=declaration, terminal=terminal)
    f.context.contract = JobContract(inputs=(requirement(coverage=policy),))
    coverage = f.handoff["coverage"]
    rejected = ((policy is CoveragePolicy.REQUIRE_COMPLETE and coverage["disposition"] != "complete")
                or (policy is CoveragePolicy.REQUIRE_NONRETRIABLE and coverage["retry_required"]))
    if rejected:
        with pytest.raises(ValueError, match="input coverage"):
            admit_inputs(f.context, {PRODUCER})
    else:
        row = admit_inputs(f.context, {PRODUCER})["requirements"][0]
        assert row["coverage"] == coverage
        assert row["supplied"] is (declaration == "present")


@pytest.mark.parametrize("change", ["wrong-pin", "changed-envelope", "changed-payload", "changed-claim",
                                   "foreign-target", "undeclared-producer"])
def test_compatibility_cannot_bypass_handoff_pins_custody_target_or_permissions(tmp_path, change):
    f = fixture(tmp_path, declaration="absent")
    if change == "wrong-pin":
        f.context.upstream_handoffs[PRODUCER] = "0" * 64
    elif change == "changed-envelope":
        f.handoff_path.write_bytes(b"{}")
    elif change == "changed-payload":
        (f.root / PAYLOAD).write_bytes(b"changed")
    elif change == "changed-claim":
        (f.root / ATTEMPT / "claim.json").write_bytes(b"{}")
    elif change == "foreign-target":
        f.context.evidence_target_snapshot = "different-target"
    else:
        f.context.contract = JobContract()
    with pytest.raises(ValueError):
        admit_inputs(f.context, {PRODUCER})


def test_target_independent_supplied_producer_remains_supported(tmp_path):
    f = fixture(tmp_path, declaration="absent", target="none")
    row = admit_inputs(f.context, {PRODUCER})["requirements"][0]
    assert row["status"] == "gap" and row["target_snapshot"] == "none"


@pytest.mark.parametrize("declaration", ["absent", "unrelated"])
def test_admitting_historical_absence_is_not_permission_to_read_undeclared_bytes(tmp_path, declaration):
    f = fixture(tmp_path, declaration=declaration)
    assert admit_inputs(f.context, {PRODUCER})["requirements"][0]["supplied"] is False
    with pytest.raises(ValueError, match="input contract violation"):
        with input_read_scope(f.context) as reads:
            with pytest.raises(ValueError, match="consumed output schema differs"):
                observe_output(f.root, PRODUCER, KIND, f.ref)
            assert reads.document()["reads"] == []
    assert reads.document()["reads"] == []


@pytest.mark.parametrize("change", ["valid", "undeclared-requirement", "unsupplied", "unbound", "tampered",
                                   "foreign-run", "wrong-schema", "wrong-authority", "unknown-authority"])
def test_observed_reads_still_require_exact_contract_pin_and_bytes(tmp_path, change):
    declaration = change if change in {"wrong-schema", "wrong-authority", "unknown-authority"} else "present"
    f = fixture(tmp_path, declaration=declaration)
    reference = dict(f.ref)
    root = f.root
    if change == "undeclared-requirement":
        f.context.contract = JobContract(inputs=(InputRequirement(PRODUCER, "handoff", HANDOFF_SCHEMA),))
    elif change == "unsupplied":
        f.context.upstream_handoffs = {}
    elif change == "unbound":
        reference["sha256"] = "0" * 64
    elif change == "tampered":
        (f.root / PAYLOAD).write_bytes(b"changed")
    elif change == "foreign-run":
        root = tmp_path / "other-run"
    if change != "valid":
        with pytest.raises(ValueError):
            with input_read_scope(f.context) as reads:
                observe_output(root, PRODUCER, KIND, reference)
        assert reads.document()["reads"] == []
        return
    assert admit_inputs(f.context, {PRODUCER})["requirements"][0]["read"] is False
    with input_read_scope(f.context) as reads:
        observe_output(root, PRODUCER, KIND, reference)
        assert reads.document()["reads"] == [{
            "producer": PRODUCER, "output_kind": KIND, "schema": SCHEMA,
            "channel": "handoff", "authority": "operational", "read": True, "cited": None,
            **reference, "handoff_sha256": f.context.upstream_handoffs[PRODUCER],
            "attempt_id": "attempt_0001", "target_snapshot": SNAPSHOT,
        }]
