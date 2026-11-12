"""Manual integration of job_threat_model_generation behind real producers (T-107).

Never part of implicit unit collection: name this file explicitly, and only at the user's request.
The real ``GraphRunner`` runs intake, the catalog and the threat-model job over the inert C fixture
``tests/fixtures/threat_model/client_server_c``. ``job_tree_sitter_ast`` is left out: it parses in a
tool container, which this tier does not start, so the interaction lane reports its absent inputs
and the model is the structure-only one of design section 7.1. No model, no network.
"""
from __future__ import annotations

from pathlib import Path
import shutil
from typing import Any

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_threat_model_generation import build_job
from appsec_review.jobs.job_threat_model_generation.job import PUBLISH
from appsec_review.runtime import GraphRunner, JobRunner
from appsec_review.runtime.consume import accepted_latest
from appsec_review.storage.shared import verify_reference
from appsec_review.threat_model.codec import evidence_ref_from_plain
from appsec_review.threat_model.contract import AUTHORITY, JOB_ID, Limits
from appsec_review.threat_model.index_view import DECLARED_INPUTS, IndexEvidenceView
from appsec_review.threat_model.render import render_markdown, render_mermaid
from appsec_review.threat_model.validate import validate_documents
from tests.release_support import write_release
from tests.test_threat_model_generation_job import FIXTURE, _config

CATALOG, INTAKE = "job_target_catalog", "job_review_intake"


def _graph(config: Any) -> GraphRunner:
    return GraphRunner(config, [build_intake(), build_catalog(), build_job()])


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    return target


def _published(run_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """The accepted handoff and its documents, each read through the hash that names it."""
    import json
    accepted = accepted_latest(run_root, JOB_ID)
    assert accepted is not None, "the threat-model job published no accepted handoff"
    handoff = accepted.handoff
    result = json.loads(verify_reference(run_root, handoff["outputs"][PUBLISH]["artifact"]).read_bytes())
    documents = {"result.json": result}
    for name, identity in result["artifacts"].items():
        data = verify_reference(run_root, identity).read_bytes()
        documents[name] = json.loads(data) if name.endswith(".json") else data.decode("utf-8")
    return handoff, documents


def test_catalog_through_threat_model_on_the_client_server_fixture(tmp_path: Path) -> None:
    config = _config(tmp_path, profile="dev")
    target = _target(tmp_path)
    outcome = _graph(config).run(target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    run_root = config.runtime.runs_dir / outcome["run_id"]
    handoff, documents = _published(run_root)
    dfd, model, evidence, result = (documents[name] for name in ("dfd.json", "threat-model.json", "evidence.json",
                                                                 "result.json"))
    validate_documents(dfd, model, evidence, result)
    assert (dfd["origin"]["authority"], dfd["origin"]["target_supplied"], dfd["origin"]["model"]) == (
        AUTHORITY, False, None)
    assert dfd["origin"]["target_snapshot"] == handoff["target_snapshot"]

    # The real catalog declares the two executables of the fixture's build file.
    processes = {item["name"] for item in dfd["elements"] if item["kind"] == "process"}
    assert {"echo-client", "echo-server"} <= processes
    assert all(item["basis"] == "declared" for item in dfd["elements"] if item["kind"] == "process")
    ledger = {(row["producer"], row["output_kind"]): row for row in result["input_ledger"]}
    assert set(DECLARED_INPUTS) <= set(ledger)
    assert ledger[(CATALOG, "build_units")]["state"] in {"read", "partial"}
    assert ledger[(CATALOG, "build_units")]["handoff_sha256"] == handoff["upstream_handoff_sha256"][CATALOG]
    assert ledger[("job_tree_sitter_ast", "tree_sitter_ast")]["state"] in {"absent", "disabled"}
    assert ledger[("job_deployment_inventory", "deployment_inventory")]["state"] == "not_registered"

    # Every citation resolves against the shards the real catalog published.
    view = IndexEvidenceView(run_root, handoff["upstream_handoff_sha256"])
    references = [evidence_ref_from_plain(item) for item in evidence["references"]]
    assert references and all(view.resolves(item) for item in references)

    fresh = {f"views/{name}": text for name, text in render_mermaid(dfd, Limits())[0].items()}
    fresh["views/threat-model.md"] = render_markdown(dfd, model, result)
    assert {name: text for name, text in documents.items() if name.startswith("views/")} == fresh
    # Nothing the job published is an index shard.
    assert not any(item["path"].startswith("data/indices/") for item in handoff["artifacts"])


def test_repaired_upstream_reruns_only_the_threat_model_job(tmp_path: Path) -> None:
    config = _config(tmp_path, profile="dev")
    write_release(tmp_path, (INTAKE, CATALOG, JOB_ID))
    target = _target(tmp_path)
    fingerprint = source_fingerprint(target)
    first = _graph(config).run(target_root=target, source_fingerprint=fingerprint)
    assert first["status"] == "COMPLETED_WITH_GAPS", first
    run_root = config.runtime.runs_dir / first["run_id"]
    before, _ = _published(run_root)

    # Unchanged inputs: intake and the catalog are reused. This job is not: the producers this small
    # graph leaves out are retryable gaps, and the runtime re-runs an accepted attempt that has one.
    unchanged = _graph(config).run(target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    decisions = {item["job_id"]: item for item in unchanged["decisions"]}
    assert {job_id: item["action"] for job_id, item in decisions.items()} == {
        INTAKE: "REUSE", CATALOG: "REUSE", JOB_ID: "RUN"}
    assert decisions[JOB_ID]["reasons"] == ["accepted job contains a retriable failed producer"]
    before, _ = _published(run_root)

    # A repaired upstream: the catalog publishes a new accepted attempt of the same target, so its
    # handoff digest changes while its own inputs do not.
    repaired = JobRunner(config).run(build_catalog(), run_id=first["run_id"], target_root=target,
                                     source_fingerprint=fingerprint)
    assert repaired["handoff_sha256"] != before["upstream_handoff_sha256"][CATALOG]

    resumed = _graph(config).run(target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    decisions = {item["job_id"]: item for item in resumed["decisions"]}
    assert {job_id: item["action"] for job_id, item in decisions.items()} == {
        INTAKE: "REUSE", CATALOG: "REUSE", JOB_ID: "RUN"}
    assert "upstream handoffs identity changed" in decisions[JOB_ID]["reasons"]
    after, documents = _published(run_root)
    assert after["attempt_id"] != before["attempt_id"]
    assert after["upstream_handoff_sha256"][CATALOG] == repaired["handoff_sha256"]
    validate_documents(*(documents[name] for name in ("dfd.json", "threat-model.json", "evidence.json", "result.json")))
