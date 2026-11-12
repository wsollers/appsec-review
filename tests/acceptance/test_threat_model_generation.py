"""Manual, read-only acceptance of an operator-supplied run that published a generated threat model.

Never part of implicit unit collection, and never run without the user's request. The run is named
by ``APPSEC_THREAT_MODEL_ACCEPTANCE_RUN`` (the run directory); these tests read it and write
nothing. They assert the publication contract (T-107), not whether the generated model is right.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from appsec_review.indexing.store import accepted_handoff, handoff_manifests
from appsec_review.jobs.job_threat_model_generation.job import PUBLISH
from appsec_review.runtime.contracts import read_job_contract
from appsec_review.runtime.inputs import read_input_observations
from appsec_review.storage.shared import verify_reference
from appsec_review.threat_model.contract import AUTHORITY, JOB_ID
from appsec_review.threat_model.validate import validate_documents

RUN_ENVIRONMENT = "APPSEC_THREAT_MODEL_ACCEPTANCE_RUN"
CATALOG = "job_target_catalog"
SUPPLIED_KINDS = ("dfd", "threat_model")


def _run() -> Path:
    selected = os.environ.get(RUN_ENVIRONMENT)
    assert selected, f"manual prerequisite: {RUN_ENVIRONMENT} is not set"
    return Path(selected).resolve(strict=True)


def _accepted(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The accepted handoff, its attempt claim and its published documents, all hash-verified."""
    accepted = accepted_handoff(root, JOB_ID)
    assert accepted is not None, f"manual prerequisite: no accepted {JOB_ID} in the supplied run"
    handoff = accepted.handoff
    claim_path = handoff["resolving_paths"]["attempt"] + "/claim.json"
    reference = next(item for item in handoff["artifacts"] if item["path"] == claim_path)
    claim = json.loads(verify_reference(root, reference).read_bytes())
    result = json.loads(verify_reference(root, handoff["outputs"][PUBLISH]["artifact"]).read_bytes())
    documents = {"result.json": result}
    for name, identity in result["artifacts"].items():
        data = verify_reference(root, identity).read_bytes()
        documents[name] = json.loads(data) if name.endswith(".json") else data.decode("utf-8")
    return handoff, claim, documents


@pytest.mark.time_budget(120, reason="bounded fixture publication")
def test_published_model_preserves_admitted_input_and_read_identities() -> None:
    root = _run()
    handoff, claim, documents = _accepted(root)
    assert claim["dataset_contract"]["schema"] == "appsec-review/attempt-datasets/3"
    contract = read_job_contract(claim["dataset_contract"]["job_contract"])
    declared = {item.key: item for item in contract.inputs}
    assert handoff["upstream_handoff_sha256"] == claim["upstream_handoffs"]
    assert set(claim["upstream_handoffs"]) <= set(contract.consumes)

    # Every observed read is a declared input of the admitted handoff; nothing else was opened.
    observations = read_input_observations(root, handoff)
    assert observations is not None, "the accepted attempt retained no read receipts"
    assert observations["citation_observation"] == "not_observed"
    read_shards: set[tuple[str, str]] = set()
    for observed in observations["reads"]:
        requirement = declared[(observed["channel"], observed["producer"], observed["output_kind"])]
        assert observed["schema"] == requirement.schema and observed["authority"] == requirement.authority
        assert observed["read"] is True and observed["cited"] is None
        assert observed["handoff_sha256"] == claim["upstream_handoffs"][observed["producer"]]
        if observed.get("sha256"):
            read_shards.add((observed["producer"], observed["sha256"]))

    # The ledger states the same admitted identities, and every citation names a shard that was read.
    for row in documents["result.json"]["input_ledger"]:
        if row["handoff_sha256"] is not None:
            assert row["handoff_sha256"] == claim["upstream_handoffs"][row["producer"]], row
        else:
            assert row["producer"] not in claim["upstream_handoffs"] or row["state"] == "not_registered", row
    for reference in documents["evidence.json"]["references"]:
        publication = reference["publication"]
        assert (publication["job"], publication["sha256"]) in read_shards, reference["ref"]
    validate_documents(*(documents[name] for name in ("dfd.json", "threat-model.json", "evidence.json", "result.json")))


@pytest.mark.time_budget(120, reason="bounded fixture publication")
def test_generated_model_never_satisfies_supplied_document_coverage() -> None:
    root = _run()
    handoff, _claim, documents = _accepted(root)
    for name in ("dfd.json", "threat-model.json", "evidence.json", "result.json"):
        origin = documents[name]["origin"]
        assert (origin["kind"], origin["target_supplied"], origin["producer"], origin["authority"]) == (
            "generated", False, JOB_ID, AUTHORITY), name

    # The job published no index shard, so no retrieval surface can return a generated element.
    assert handoff_manifests(root, handoff) == []
    assert not any(item["path"].startswith("data/indices/") for item in handoff["artifacts"])
    assert not any(key in output for output in handoff["outputs"].values()
                   for key in ("index_identity", "index_manifest"))

    # The catalog's own account of supplied documents is the one accepted before this job ran: its
    # handoff is the admitted one, and none of its shards (the documents index included) names this
    # job as a producer.
    catalog = accepted_handoff(root, CATALOG)
    assert catalog is not None, f"manual prerequisite: no accepted {CATALOG} in the supplied run"
    assert catalog.sha256 == handoff["upstream_handoff_sha256"][CATALOG]
    shards = [shard for manifest in handoff_manifests(root, catalog.handoff) for shard in manifest["document"]["indexes"]]
    assert any(shard["name"] == "documents" for shard in shards), "manual prerequisite: the catalog has no documents index"
    assert all(shard.get("producer", {}).get("job") != JOB_ID for shard in shards)
    # A supplied dfd or threat_model, when the target has one, is listed for a reader and never merged.
    supplied = documents["threat-model.json"]["supplied_documents"]
    assert isinstance(supplied, list) and not any(item.startswith(("proc:", "threat:", "flow:")) for item in supplied)
    assert all(kind not in json.dumps(handoff["outputs"]) for kind in (f"target-documents:{k}" for k in SUPPLIED_KINDS))
