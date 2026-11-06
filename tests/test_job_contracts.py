from dataclasses import replace
import hashlib
import json

import pytest

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement, JobContract,
    MissingPolicy, TargetAccess, accepted_inputs, read_job_contract,
)
from appsec_review.runtime.datasets import artifact_only, dataset_contract, read_dataset_contract
from appsec_review.runtime.job import Job


def output():
    return artifact_only("facts", "publish", "catalog", "appsec-review/facts/1", "Accepted facts.",
                         artifacts=("data/facts.json",), reason="metadata")


def resign(document):
    body = {key: value for key, value in document.items() if key != "sha256"}
    document["sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return document


def test_contract_roundtrip_and_job_projection():
    contract = JobContract(inputs=accepted_inputs("job_source", (output(),)),
                           schedule_after=("job_gate",), target_access=TargetAccess.ACCEPTED_EVIDENCE)
    assert read_job_contract(contract.document()) == contract
    job = Job("job_consumer", "consumer", lambda _: {}, contract=contract)
    assert job.consumes == ("job_source",)
    assert "job_gate" not in job.consumes
    with pytest.raises(ValueError, match="legacy consumes"):
        replace(job, consumes=("job_gate",))


@pytest.mark.parametrize("field,value", [
    ("producer", "../foreign"), ("output_kind", ""), ("schema", ""),
    ("authority", "conclusion"), ("availability", "sometimes"), ("missing", "ignore"),
    ("coverage", "clean"), ("channel", "filesystem"),
])
def test_closed_input_values(field, value):
    with pytest.raises(ValueError):
        InputRequirement(**{"producer": "job_source", "output_kind": "facts",
                            "schema": "appsec-review/facts/1", field: value})


@pytest.mark.parametrize("change", ("unknown", "version", "digest", "input_unknown", "bool"))
def test_closed_document(change):
    document = JobContract(inputs=accepted_inputs("job_source", (output(),))).document()
    if change == "unknown":
        document["extra"] = True
    elif change == "version":
        document["schema"] = "appsec-review/job-contract/999"
    elif change == "digest":
        document["schedule_after"] = ["job_other"]
    elif change == "input_unknown":
        document["inputs"][0]["extra"] = True
    else:
        document["always_execute"] = "false"
    if change != "digest":
        resign(document)
    with pytest.raises(ValueError):
        read_job_contract(document)


def test_required_optional_conditional():
    optional = InputRequirement("job_source", "facts", "appsec-review/facts/1")
    required = replace(optional, availability=Availability.REQUIRED, missing=MissingPolicy.REJECT)
    conditional = replace(optional, availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT)
    assert not optional.required({"job_source"})
    assert required.required(set())
    assert not conditional.required(set())
    assert conditional.required({"job_source"})
    with pytest.raises(ValueError, match="required inputs"):
        replace(optional, availability=Availability.REQUIRED)


def test_dispatch_classes_and_external_inputs():
    external = InputRequirement("job_feed", "snapshot", "appsec-review/feed/1",
                                EvidenceAuthority.REFERENCE, channel=InputChannel.EXTERNAL)
    contract = JobContract(inputs=(external,), dispatch=DispatchClass.MAINTENANCE,
                           target_access=TargetAccess.NONE)
    assert contract.consumes == ()
    assert read_job_contract(contract.document()) == contract
    with pytest.raises(ValueError, match="non-graph"):
        replace(contract, schedule_after=("job_gate",))
    with pytest.raises(ValueError, match="internal transactions"):
        replace(contract, dispatch=DispatchClass.INTERNAL_TRANSACTION)
    assert replace(contract, dispatch=DispatchClass.INTERNAL_TRANSACTION,
                   propagate_handoff=False).consumes == ()


def test_duplicates_self_and_unknown_outputs():
    requirement = InputRequirement("job_source", "facts", "appsec-review/facts/1")
    with pytest.raises(ValueError, match="duplicate"):
        JobContract(inputs=(requirement, requirement))
    with pytest.raises(ValueError, match="itself"):
        Job("job_source", "source", lambda _: {}, contract=JobContract(inputs=(requirement,)))
    with pytest.raises(ValueError, match="unknown input"):
        accepted_inputs("job_source", (output(),), output_kinds=("missing",))


def test_historical_dataset_contract_readability_without_retrospective_provenance():
    historical = dataset_contract("job_consumer", ("publish",), (output(),))
    historical["datasets"][0].pop("authority")
    resign(historical)
    original = json.dumps(historical, sort_keys=True)
    contract = JobContract(inputs=accepted_inputs("job_source", (output(),)))
    current = dataset_contract("job_consumer", ("publish",), (output(),), job_contract=contract.document())
    assert historical["schema"] == "appsec-review/attempt-datasets/2"
    assert current["schema"] == "appsec-review/attempt-datasets/3"
    assert current["sha256"] != historical["sha256"]
    old_steps, old_outputs = read_dataset_contract(historical, "job_consumer")
    new_steps, new_outputs = read_dataset_contract(current, "job_consumer")
    assert old_steps == new_steps
    assert old_outputs[0].schema == new_outputs[0].schema
    assert old_outputs[0].authority is None
    assert new_outputs[0].authority is EvidenceAuthority.PRODUCER_EVIDENCE
    assert json.dumps(historical, sort_keys=True) == original
    assert "job_contract" not in historical
    changed = replace(contract, target_access=TargetAccess.NONE)
    assert dataset_contract("job_consumer", ("publish",), (output(),),
                            job_contract=changed.document())["sha256"] != current["sha256"]
    legacy = {key: value for key, value in historical.items() if key != "shared_namespaces"}
    legacy["schema"] = "appsec-review/attempt-datasets/1"
    assert read_dataset_contract(resign(legacy), "job_consumer") == (old_steps, old_outputs)
