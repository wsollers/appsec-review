"""Runner-mediated regression coverage for originally owned downstream evidence."""
from dataclasses import replace

import pytest

from appsec_review.inference import ModelResult
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_dossier_publication import build_job as dossier_job
from appsec_review.jobs.job_final_publication_gate import build_job as gate_job
from appsec_review.jobs.job_poc_generation import build_job as poc_job
from appsec_review.jobs.job_remediation_planning import build_job as remediation_job
from appsec_review.runtime.inputs import read_input_observations
from tests.downstream_contract_fixture import ROOT, SOURCE, TEXT, REVIEW, LANGUAGE, fixture, publish_build, publish_poc
from tests.remediation_support import answer


def test_fixture_uses_real_accepted_review_and_original_source_owners(tmp_path):
    case = fixture(tmp_path)
    assert case.review["partition"]["confirmed"]
    assert set(case.originals) == {
        "job_target_catalog", "job_evidence_collection", "job_code_graph_index",
        "job_review_data_indexing", "job_source_history_analysis"}


@pytest.mark.parametrize("kind", ("remediation", "poc", "dossier"))
def test_original_shard_reads_execute_under_real_typed_runner(tmp_path, kind):
    job_id = {"remediation": "job_remediation_planning", "poc": "job_poc_generation",
              "dossier": "job_dossier_publication"}[kind]
    case = fixture(tmp_path, engineering=(job_id,))
    build = publish_build(case)
    calls = []

    def model(request, *, timeout_seconds):
        calls.append(request)
        if kind == "poc":
            result = {"decline": {"status": "unsafe_to_attempt", "why": "fixture does not execute target code"}}
        else:
            result = answer([item["relation_id"] for item in request.task_input["task"]["accepted_evidence"]], None)
        return ModelResult(proposal={"action": "final", "result": result})

    factory = {"remediation": remediation_job, "poc": poc_job, "dossier": dossier_job}[kind]
    job = factory(repository_root=ROOT, **({"infer": model} if kind != "dossier" else {}))
    supplied = {REVIEW: case.accepted_review.sha256}
    if kind != "dossier":
        supplied[LANGUAGE] = build.sha256
    result = case.runner.run(job, run_id=case.root.name, upstream_handoffs=supplied)
    observed = read_input_observations(case.root, result["handoff"])["reads"]
    assert any(row["producer"] == "job_target_catalog" and row["output_kind"] == "source_files"
               for row in observed)
    assert all(row["cited"] is None for row in observed)
    shard_owners = {row["producer"] for row in observed if row.get("path", "").endswith(".sqlite")}
    assert {"job_target_catalog", "job_code_graph_index", "job_evidence_collection",
            "job_review_data_indexing"} <= shard_owners
    assert "job_source_history_analysis" not in result["handoff"]["upstream_handoff_sha256"]
    assert "job_source_history_analysis" not in shard_owners
    assert REVIEW not in shard_owners
    if kind == "remediation":
        assert calls and calls[0].task_input["task"]["source_files"][0]["path"] == SOURCE
        assert calls[0].task_input["task"]["source_files"][0]["text"] == TEXT
    elif kind == "poc":
        assert calls, "the real brief reader must reach the scripted model transport"
        plan = read_bound_json(case.root, result["result"]["outputs"]["plan.briefs"]["artifact"])
        assert all(row["brief"] is not None for row in plan["entries"].values())
    else:
        assert not calls
        assert result["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}


@pytest.mark.parametrize("binding,enabled", ((True, True), (False, True), (True, False)),
                         ids=("bound-build", "no-binding", "poc-disabled"))
def test_gate_reads_build_only_when_an_admitted_poc_binds_it(tmp_path, binding, enabled):
    case = fixture(tmp_path, engineering=("job_poc_generation",) if enabled else ())
    build = publish_build(case) if binding else None
    publish_poc(case, build_sha=build.sha256 if build else None)
    result = case.runner.run(gate_job(repository_root=ROOT), run_id=case.root.name)
    observed = read_input_observations(case.root, result["handoff"])["reads"]
    assert any(row["producer"] == "job_language_build" for row in observed) is (binding and enabled)
    gate = read_bound_json(case.root, result["result"]["outputs"]["acceptance.publish_handoff"]["artifact"])
    assert gate["capabilities"]["poc_generation"]["enabled"] is enabled


def test_source_view_does_not_grant_undeclared_original_owners(tmp_path):
    case = fixture(tmp_path, engineering=("job_remediation_planning",))
    build = publish_build(case)
    calls = []

    def forbidden_model(*args, **kwargs):
        calls.append(True)
        raise AssertionError("an undeclared source must not reach model dispatch")

    job = remediation_job(repository_root=ROOT, infer=forbidden_model)
    job = replace(job, consumes=(), contract=replace(job.contract, inputs=tuple(
        item for item in job.contract.inputs if item.producer != "job_target_catalog")))
    with pytest.raises(RuntimeError, match="undeclared or unsupplied shard producer: job_target_catalog"):
        case.runner.run(job, run_id=case.root.name,
                        upstream_handoffs={REVIEW: case.accepted_review.sha256, LANGUAGE: build.sha256})
    assert calls == []


def test_unknown_origin_stays_unknown_and_cannot_enter_typed_consumption(tmp_path):
    from appsec_review.jobs.bound_artifacts import artifact_ref, source_context_core
    from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
    from appsec_review.runtime import Unit
    from appsec_review.runtime.contracts import JobContract
    from tests.test_input_contract_admission import SNAPSHOT, run, setup

    runner, producer, consumer, target = setup(tmp_path, read=False)
    first = run(runner, producer, target)
    root = runner.runs.resolve(first["status"]["run_id"])
    path = root / "data/indices/source/legacy.sqlite"
    identity = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, SNAPSHOT, {"legacy": True})
    builder = IndexBuilder(path, name="source", fingerprint="a" * 64, target_snapshot=SNAPSHOT,
                           shard_id="legacy")
    builder.add_entity(EntityRecord(identity, "legacy", "legacy", "legacy source", {}))
    builder.add_coverage("legacy", "complete")
    shard = IndexIdentity("source", "appsec-review/retrieval-index/2", builder.build(), "a" * 64,
                          path.relative_to(root).as_posix(), {"tool": "legacy"}, (), "legacy")
    manifest = root / "data/inputs/legacy-manifest.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=SNAPSHOT, target_root=target, indexes=(shard,))
    reference = artifact_ref(root, manifest)
    core = source_context_core(root, reference)
    assert core.find(identity=identity.value)["results"]
    assert "job" not in core.manifest["indexes"][0]["producer"]

    def read(unit):
        return source_context_core(root, reference).find(identity=identity.value)

    consumer = replace(consumer, consumes=(), contract=JobContract(), units=(Unit("work.read", read),))
    with pytest.raises(RuntimeError, match="undeclared or unsupplied shard producer: None"):
        run(runner, consumer, target, root.name)


def test_read_path_inventory_and_source_requirements_match_the_factories():
    import re
    from appsec_review.jobs.bound_artifacts import source_context_inputs, source_context_datasets
    from appsec_review.runtime.registry import builtin_registry
    registry = builtin_registry()
    text = (ROOT / "docs/architecture/job-consumer-read-paths.md").read_text()
    assert set(re.findall(r"^\| `(job_[a-z_]+)` \|", text, re.M)) == set(registry.job_ids())
    required = {item.key: item for item in source_context_inputs()}
    for job_id in ("job_remediation_planning", "job_poc_generation", "job_dossier_publication"):
        actual = {item.key: item for item in registry.build(job_id).contract.inputs}
        assert all(actual[key] == value for key, value in required.items())
    assert all(declaration.indexes for declarations in source_context_datasets().values()
               for declaration in declarations)
    assert "job_source_history_analysis" not in source_context_datasets()
    assert "job_model_connectivity" not in source_context_datasets()
    assert "job_target_catalog" not in registry.build("job_remediation_validation").consumes


def test_source_view_preserves_manifest_but_isolates_query_cursors(tmp_path):
    from appsec_review.jobs.bound_artifacts import artifact_ref, source_context_core
    from appsec_review.retrieval import RetrievalCore
    from tests.test_retrieval_core import RUN_ID, _fixture

    runs, ids = _fixture(tmp_path)
    full = RetrievalCore(runs, RUN_ID)
    reference = artifact_ref(full.run_root, full.run_root / "data/indices/manifests/fixture.json")
    scoped = source_context_core(full.run_root, reference)
    assert scoped.manifest == full.manifest
    assert scoped.manifest_sha256 == full.manifest_sha256
    assert scoped.mcp_session_id != full.mcp_session_id
    assert source_context_core(full.run_root, reference).mcp_session_id == scoped.mcp_session_id
    assert "build" in full.indexes and "build" not in scoped.indexes
    assert full.find(identity=ids["compile"])["results"]
    assert scoped.find(identity=ids["compile"])["results"] == []
    assert scoped.find(identity=ids["symbol"])["results"]
    page = full.search(query="token", limit=1)
    assert page["pagination"]["next_cursor"]
    with pytest.raises(ValueError, match="tampered"):
        scoped.search(query="token", limit=1, cursor=page["pagination"]["next_cursor"])
