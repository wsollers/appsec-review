"""Consumer schema parity, admission, and B2 observe_output enforcement for Wave 2."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.container_runtime import load_catalog
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.job_change_context_analysis.sources import identity_hash
from appsec_review.jobs.job_artifact_security_analysis import load_accepted_artifact_security_analysis
from appsec_review.jobs.job_change_context_analysis import build_job as build_change_context
from appsec_review.jobs.job_review_prioritization import build_job as build_prioritization
from appsec_review.jobs.job_review_prioritization.streaming import ShardRowIndex
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy,
)
from appsec_review.runtime.inputs import input_read_scope, observe_output, read_input_observations
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256
from tests.release_support import write_release
from tests.unit.runtime.test_wave2_contracts import (
    ASA_OBSERVATION_SCHEMA, ASA_SCHEMA, TS_SCHEMA, run_asa_publication, run_tree_sitter_publication,
)


ASA_CONSUMERS = (
    "job_codeql_analysis",
    "job_document_issue_analysis",
    "job_inference_security_review",
    "job_owasp_control_assessment",
    "job_review_data_indexing",
    "job_review_package_assembly",
    "job_security_tagging",
)
TS_CONSUMERS = (
    "job_change_context_analysis",
    "job_code_graph_index",
    "job_codeql_analysis",
    "job_document_issue_analysis",
    "job_inference_security_review",
    "job_owasp_control_assessment",
    "job_review_data_indexing",
    "job_review_package_assembly",
    "job_review_prioritization",
    "job_security_tagging",
)
TS_ACCEPTANCE_READERS = frozenset({"job_change_context_analysis", "job_review_prioritization"})


def _probe_job(inputs: tuple[InputRequirement, ...], handler=None, *,
               job_id: str = "job_wave2_probe", name: str = "wave2_probe") -> Job:
    def default_handler(_unit):
        return {"terminal_status": "SUCCEEDED"}

    units = (Unit("work.read", handler or default_handler),)
    return Job(job_id, name, UnitExecutor(units).execute,
               units=units, contract=JobContract(inputs=inputs), strict_gaps=True)


@pytest.mark.parametrize("consumer_id", ASA_CONSUMERS)
def test_artifact_security_consumers_declare_exact_results_and_no_unused_acceptance(
    consumer_id: str,
) -> None:
    contract = builtin_registry().build(consumer_id).contract
    asa_inputs = {item.output_kind: item for item in contract.inputs
                  if item.producer == "job_artifact_security_analysis"}
    assert "artifact_security_results" in asa_inputs
    assert "artifact_security_acceptance" not in asa_inputs
    req = asa_inputs["artifact_security_results"]
    assert (req.schema, req.authority, req.availability, req.missing, req.coverage, req.channel) == (
        ASA_OBSERVATION_SCHEMA, EvidenceAuthority.PRODUCER_EVIDENCE, Availability.OPTIONAL,
        MissingPolicy.GAP, CoveragePolicy.ALLOW_PARTIAL, InputChannel.HANDOFF,
    )


def test_artifact_security_acceptance_loader_and_admission_enforce_observe_output(tmp_path: Path) -> None:
    index_only_inputs = tuple(
        item for item in builtin_registry().build("job_review_data_indexing").contract.inputs
        if item.producer == "job_artifact_security_analysis"
    )
    index_probe = _probe_job(index_only_inputs, job_id="job_wave2_asa_index", name="wave2_asa_index")
    unauthorized = _probe_job(
        (InputRequirement("job_artifact_security_analysis", "handoff", "appsec-review/job-handoff/2",
                          authority=EvidenceAuthority.PRODUCER_EVIDENCE),
         InputRequirement("job_artifact_security_analysis", "artifact_security_results",
                          ASA_OBSERVATION_SCHEMA, authority=EvidenceAuthority.PRODUCER_EVIDENCE)),
        handler=lambda unit: load_accepted_artifact_security_analysis(unit.job.run_root),
        job_id="job_wave2_asa_unauth", name="wave2_asa_unauth",
    )
    authorized = _probe_job(
        (InputRequirement("job_artifact_security_analysis", "handoff", "appsec-review/job-handoff/2",
                          authority=EvidenceAuthority.PRODUCER_EVIDENCE),
         InputRequirement("job_artifact_security_analysis", "artifact_security_acceptance",
                          ASA_SCHEMA, authority=EvidenceAuthority.PRODUCER_EVIDENCE),
         InputRequirement("job_artifact_security_analysis", "artifact_security_results",
                          ASA_OBSERVATION_SCHEMA, authority=EvidenceAuthority.PRODUCER_EVIDENCE)),
        handler=lambda unit: {"terminal_status": "SUCCEEDED",
                              "loaded_schema": load_accepted_artifact_security_analysis(unit.job.run_root)["schema"]},
        job_id="job_wave2_asa_auth", name="wave2_asa_auth",
    )
    runner, run_root, target, snapshot, _asa_job, asa_out = run_asa_publication(
        tmp_path, extra_jobs=(index_probe, unauthorized, authorized),
    )
    standalone = load_accepted_artifact_security_analysis(run_root)
    assert standalone["schema"] == ASA_SCHEMA

    idx_out = runner.run(index_probe, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
                         upstream_handoffs={"job_artifact_security_analysis": asa_out["handoff_sha256"]})
    claim = json.loads((Path(idx_out["attempt_root"]) / "claim.json").read_text(encoding="utf-8"))
    by_kind = {row["output_kind"]: row for row in claim["input_admission"]["requirements"]}
    assert by_kind["artifact_security_results"]["supplied"] is True
    assert by_kind["artifact_security_results"]["read"] is False
    assert read_input_observations(run_root, idx_out["handoff"])["reads"] == []

    with pytest.raises(RuntimeError, match="undeclared consumption.*artifact_security_acceptance"):
        runner.run(unauthorized, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
                   upstream_handoffs={"job_artifact_security_analysis": asa_out["handoff_sha256"]})

    out = runner.run(authorized, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
                     upstream_handoffs={"job_artifact_security_analysis": asa_out["handoff_sha256"]})
    reads = {row["output_kind"] for row in read_input_observations(run_root, out["handoff"])["reads"]}
    assert reads == {"handoff", "artifact_security_acceptance"}


@pytest.mark.parametrize("consumer_id", TS_CONSUMERS)
def test_tree_sitter_consumers_align_node_shards_and_scope_acceptance_permissions(
    consumer_id: str,
) -> None:
    contract = builtin_registry().build(consumer_id).contract
    ts_inputs = {item.output_kind: item for item in contract.inputs
                 if item.producer == "job_tree_sitter_ast"}
    assert "tree_sitter_node_shards" in ts_inputs
    assert "tree_sitter_scope_results" not in ts_inputs
    assert ("tree_sitter_acceptance" in ts_inputs) is (consumer_id in TS_ACCEPTANCE_READERS)
    shards_req = ts_inputs["tree_sitter_node_shards"]
    assert (shards_req.schema, shards_req.authority, shards_req.availability,
            shards_req.missing, shards_req.coverage, shards_req.channel) == (
        NORMALIZER_SCHEMA, EvidenceAuthority.PRODUCER_EVIDENCE, Availability.OPTIONAL,
        MissingPolicy.GAP, CoveragePolicy.ALLOW_PARTIAL, InputChannel.HANDOFF,
    )
    if consumer_id in TS_ACCEPTANCE_READERS:
        acc_req = ts_inputs["tree_sitter_acceptance"]
        assert (acc_req.schema, acc_req.authority, acc_req.availability,
                acc_req.missing, acc_req.coverage, acc_req.channel) == (
            TS_SCHEMA, EvidenceAuthority.PRODUCER_EVIDENCE, Availability.OPTIONAL,
            MissingPolicy.GAP, CoveragePolicy.ALLOW_PARTIAL, InputChannel.HANDOFF,
        )


def test_tree_sitter_consumer_admission_accepts_split_and_rejects_stale_schema(tmp_path: Path) -> None:
    index_inputs = tuple(
        item for item in builtin_registry().build("job_review_data_indexing").contract.inputs
        if item.producer == "job_tree_sitter_ast"
    )
    reader_inputs = tuple(
        item for item in builtin_registry().build("job_change_context_analysis").contract.inputs
        if item.producer == "job_tree_sitter_ast"
    )
    index_probe = _probe_job(index_inputs, job_id="job_wave2_ts_index", name="wave2_ts_index")
    reader_probe = _probe_job(reader_inputs, job_id="job_wave2_ts_reader", name="wave2_ts_reader")
    stale_probe = _probe_job(tuple(
        replace(item, schema=TS_SCHEMA) if item.output_kind == "tree_sitter_node_shards" else item
        for item in index_inputs
    ), job_id="job_wave2_ts_stale", name="wave2_ts_stale")
    runner, run_root, target, snapshot, _ts_job, _intake, _catalog, ts_out = run_tree_sitter_publication(
        tmp_path, extra_jobs=(index_probe, reader_probe, stale_probe), recorded_upstream=True,
    )
    for probe, expects_acceptance in ((index_probe, False), (reader_probe, True)):
        out = runner.run(probe, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
                         upstream_handoffs={"job_tree_sitter_ast": ts_out["handoff_sha256"]})
        claim = json.loads((Path(out["attempt_root"]) / "claim.json").read_text(encoding="utf-8"))
        by_kind = {row["output_kind"]: row for row in claim["input_admission"]["requirements"]}
        assert by_kind["tree_sitter_node_shards"]["supplied"] is True
        assert ("tree_sitter_acceptance" in by_kind) is expects_acceptance
        if expects_acceptance:
            assert by_kind["tree_sitter_acceptance"]["supplied"] is True

    with pytest.raises(ValueError, match="producer output contract mismatch.*tree_sitter_node_shards"):
        runner.run(stale_probe, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
                   upstream_handoffs={"job_tree_sitter_ast": ts_out["handoff_sha256"]})


class FakeBlameExecutor:
    def __init__(self, target_root: Path, repository_root: Path, run_root: Path) -> None:
        self.target_root = target_root
        self.catalog = load_catalog(repository_root)
        self.run_root = run_root

    def resolve_image(self, _tool) -> str:
        return "sha256:" + "9" * 64

    def execute(self, request) -> ExecutionResult:
        path = request.argv[-1]
        lines = (self.target_root / path).read_text(encoding="utf-8").splitlines()
        commit = "1" * 40
        chunks: list[str] = []
        for idx, text in enumerate(lines, 1):
            chunks.append(
                f"{commit} {idx} {idx} 1\nauthor Dev\nauthor-mail <dev@example.com>\n"
                f"author-time 1700000000\nauthor-tz +0000\ncommitter Dev\n"
                f"committer-mail <dev@example.com>\ncommitter-time 1700000000\n"
                f"committer-tz +0000\nsummary init\nfilename {path}\n\t{text}\n"
            )
        stdout_file = request.scratch_root / "stdout.log"
        stderr_file = request.scratch_root / "stderr.log"
        stdout_file.parent.mkdir(parents=True, exist_ok=True)
        stdout_file.write_text("".join(chunks), encoding="utf-8")
        stderr_file.write_text("", encoding="utf-8")
        stdout_rel = stdout_file.relative_to(self.run_root).as_posix()
        stderr_rel = stderr_file.relative_to(self.run_root).as_posix()
        now = "2026-10-10T00:00:00+00:00"
        return ExecutionResult(
            "appsec-review/container-execution/1", "tool-git", "tool-git:test",
            "sha256:" + "9" * 64, "sha256:" + "9" * 64, "fake-git", (), {}, now, now,
            0, False, False, False, False, stdout_rel, stderr_rel, "",
        )


def test_change_context_line_attribution_records_and_enforces_tree_sitter_reads(tmp_path: Path) -> None:
    runner, run_root, target, snapshot, _ts_job, _intake_out, catalog_out, ts_out = run_tree_sitter_publication(
        tmp_path, extra_job_ids=("job_change_context_analysis",),
        disabled_jobs=("job_source_history_analysis",), recorded_upstream=True,
    )
    app_sha = file_sha256(target / "src" / "app.js")
    app_size = (target / "src" / "app.js").stat().st_size
    signals_path = run_root / "data" / "fixture-history-signals.json"
    lifetime_path = run_root / "data" / "fixture-lifetime.json"
    atomic_json(signals_path, {"files": {"src/app.js": {"churn_lines": 10}}})
    atomic_json(lifetime_path, {"identities": {"author-0001": identity_hash("dev@example.com")}})

    real_cc = build_change_context(
        executor_factory=lambda unit: FakeBlameExecutor(
            unit.job.target_root, unit.job.repository_root, unit.job.run_root,
        ),
    )
    seeded_units = tuple(
        Unit("load.accepted_history", lambda _unit: {
            "available": True,
            "eligible": {"src/app.js": {"exact": True, "sha256": app_sha, "size_bytes": app_size}},
            "history_signals": {"path": signals_path.relative_to(run_root).as_posix(),
                                "sha256": file_sha256(signals_path)},
            "lifetime": {"path": lifetime_path.relative_to(run_root).as_posix(),
                         "sha256": file_sha256(lifetime_path)},
            "git": {"decision": "SUCCEEDED", "reason": "git repository resolved",
                    "git_dir": ".git", "object_format": "sha1", "mainline_ref": "refs/heads/main",
                    "snapshot_commit": "1" * 40, "head_commit": "1" * 40,
                    "shallow": [], "observations": []},
            "source": {"root": "."},
            "terminal_status": "SUCCEEDED",
        }) if unit.unit_id == "load.accepted_history" else unit
        for unit in real_cc.units
    )
    cc_job = replace(real_cc, units=seeded_units, handler=UnitExecutor(seeded_units).execute)
    claim = runner.begin_attempt(
        cc_job, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_target_catalog": catalog_out["handoff_sha256"],
                           "job_tree_sitter_ast": ts_out["handoff_sha256"]},
    )
    runner.execute_or_reuse_unit(cc_job, claim, "load.accepted_history")
    attr_out = runner.execute_or_reuse_unit(cc_job, claim, "attribute.line_attribution")
    assert attr_out["attributed_file_count"] == 1
    assert attr_out["function_count"] == 1

    attempt_root = run_root / claim["attempt_path"]
    status = json.loads((attempt_root / "steps/attribute/tasks/line_attribution/status.json").read_text())
    ts_reads = {row["output_kind"] for row in status["input_consumption"]["reads"]
                if row["producer"] == "job_tree_sitter_ast"}
    assert ts_reads == {"handoff", "tree_sitter_acceptance", "tree_sitter_node_shards"}

    accepted_ref = ts_out["result"]["outputs"]["acceptance.publish_handoff"]["artifact"]
    context = runner._context_from_claim(cc_job, claim)
    wrong_schema_job = replace(cc_job, contract=replace(
        cc_job.contract,
        inputs=tuple(
            replace(item, schema=NORMALIZER_SCHEMA) if item.output_kind == "tree_sitter_acceptance" else item
            for item in cc_job.contract.inputs
        ),
    ))
    wrong_schema_ctx = replace(context, contract=wrong_schema_job.contract)
    with pytest.raises(ValueError, match="consumed output schema differs from input contract"), \
            input_read_scope(wrong_schema_ctx):
        observe_output(run_root, "job_tree_sitter_ast", "tree_sitter_acceptance", accepted_ref)

    unbound = {"path": "data/treesitter/shards/" + "0" * 64 + ".jsonl", "sha256": "1" * 64}
    with pytest.raises(ValueError, match="consumed output is not bound to supplied producer"), input_read_scope(context):
        observe_output(run_root, "job_tree_sitter_ast", "tree_sitter_node_shards", unbound)

    without_acceptance = replace(cc_job, contract=replace(
        cc_job.contract,
        inputs=tuple(item for item in cc_job.contract.inputs if item.output_kind != "tree_sitter_acceptance"),
    ))
    narrow_claim = runner.begin_attempt(
        without_acceptance, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_target_catalog": catalog_out["handoff_sha256"],
                           "job_tree_sitter_ast": ts_out["handoff_sha256"]},
    )
    narrow_context = runner._context_from_claim(without_acceptance, narrow_claim)
    with pytest.raises(ValueError, match="undeclared consumption.*tree_sitter_acceptance"), \
            input_read_scope(narrow_context):
        observe_output(run_root, "job_tree_sitter_ast", "tree_sitter_acceptance", accepted_ref)


def test_review_prioritization_units_record_and_enforce_tree_sitter_reads(tmp_path: Path) -> None:
    runner, run_root, target, snapshot, _ts_job, intake_out, catalog_out, ts_out = run_tree_sitter_publication(
        tmp_path, extra_job_ids=("job_review_prioritization",), recorded_upstream=True,
    )
    priority_job = build_prioritization()
    claim = runner.begin_attempt(
        priority_job, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_review_intake": intake_out["handoff_sha256"],
                           "job_target_catalog": catalog_out["handoff_sha256"],
                           "job_tree_sitter_ast": ts_out["handoff_sha256"]},
    )
    runner.execute_or_reuse_unit(priority_job, claim, "load.accepted_inputs")
    syntax_out = runner.execute_or_reuse_unit(priority_job, claim, "extract.syntax_metrics")
    assert syntax_out["file_count"] == 1

    attempt_root = run_root / claim["attempt_path"]
    load_status = json.loads((attempt_root / "steps/load/tasks/accepted_inputs/status.json").read_text())
    load_ts_reads = {row["output_kind"] for row in load_status["input_consumption"]["reads"]
                     if row["producer"] == "job_tree_sitter_ast"}
    assert load_ts_reads == {"handoff", "tree_sitter_acceptance"}

    syntax_status = json.loads((attempt_root / "steps/extract/tasks/syntax_metrics/status.json").read_text())
    syntax_ts_reads = {row["output_kind"] for row in syntax_status["input_consumption"]["reads"]
                       if row["producer"] == "job_tree_sitter_ast"}
    assert syntax_ts_reads == {"tree_sitter_acceptance", "tree_sitter_node_shards"}

    shard_ref = ts_out["result"]["outputs"]["acceptance.publish_handoff"]["dispositions"][0]["artifact"]
    context = runner._context_from_claim(priority_job, claim)
    unbound_path = run_root / "data" / "treesitter" / "shards" / ("e" * 64 + ".jsonl")
    unbound_path.write_bytes((run_root / shard_ref["path"]).read_bytes())
    unbound_ref = {"path": unbound_path.relative_to(run_root).as_posix(),
                   "sha256": hashlib.sha256(unbound_path.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="consumed output is not bound to supplied producer"), input_read_scope(context):
        ShardRowIndex(run_root, [unbound_ref], {"src/app.js"}, tmp_path / "scratch-unbound")

    without_shards = replace(priority_job, contract=replace(
        priority_job.contract,
        inputs=tuple(item for item in priority_job.contract.inputs if item.output_kind != "tree_sitter_node_shards"),
    ))
    no_shards_claim = runner.begin_attempt(
        without_shards, run_id=run_root.name, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_review_intake": intake_out["handoff_sha256"],
                           "job_target_catalog": catalog_out["handoff_sha256"],
                           "job_tree_sitter_ast": ts_out["handoff_sha256"]},
    )
    no_shards_ctx = runner._context_from_claim(without_shards, no_shards_claim)
    with pytest.raises(ValueError, match="undeclared consumption.*tree_sitter_node_shards"), \
            input_read_scope(no_shards_ctx):
        ShardRowIndex(run_root, [shard_ref], {"src/app.js"}, tmp_path / "scratch-unauth")

    shard_disk = run_root / shard_ref["path"]
    original = shard_disk.read_bytes()
    try:
        shard_disk.chmod(0o644)
        shard_disk.write_bytes(original + b"\n")
        with pytest.raises(ValueError, match="consumed output bytes changed"), input_read_scope(context):
            ShardRowIndex(run_root, [shard_ref], {"src/app.js"}, tmp_path / "scratch-tampered")
    finally:
        shard_disk.write_bytes(original)
