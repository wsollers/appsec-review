"""Job-local coverage, input admission and publication regressions; no external execution."""
from contextlib import contextmanager
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.codeql.runtime import CodeQLImage
from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import admit_inputs, input_read_scope
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, attempt_artifacts, publication_scope_for_owner, reference
from tests.handoff_fixture import write_fixture_handoff
from tests.test_codeql_seeded_export import SeededExecutor
from tests.unit.job_target_catalog.support import context as catalog_context
from .test_handlers import _make_unit


JOB = "job_codeql_analysis"
REQUIRED = ("job_artifact_indexing", "job_cpp_compiled_analysis", "job_language_build", "job_target_catalog")


def _publish_input(unit, producer, outputs, *, artifacts=(), attempt_id=None):
    root = unit.job.run_root
    job = builtin_registry().build(producer)
    attempts = root / f"data/jobs/{producer}/attempts"
    attempt_id = attempt_id or f"attempt_{len(list(attempts.glob('attempt_*/handoff.json'))) + 1:04d}"
    claim = attempts / attempt_id / "claim.json"
    if not claim.exists():
        atomic_json(claim, {"orchestration": {}, "dataset_contract": dataset_contract(
            producer, sorted({item.step for item in job.datasets}), job.datasets)})
    handoff = write_fixture_handoff(root, claim.with_name("handoff.json"), {
        "job_id": producer, "outputs": outputs, "artifacts": list(artifacts),
    }, target_snapshot=unit.job.source_fingerprint)
    identity = reference(root, handoff)
    atomic_json(attempts.parent / "latest.json", {
        "handoff_path": identity["path"], "handoff_sha256": identity["sha256"]})
    unit.job.upstream_handoffs[producer] = identity["sha256"]
    return identity


def _catalog_input(unit, tmp_path):
    outputs = {}
    context = catalog_context(tmp_path, "repository_discovery.partition_repository", outputs)
    context.job.run_root = unit.job.run_root
    context.job.run_id = unit.job.run_id
    context.job.source_fingerprint = unit.job.source_fingerprint
    context.job.config.job_id = "job_target_catalog"
    context.job.orchestration = {}
    context.job.attempt_root = unit.job.run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    _publish_input(unit, "job_target_catalog", {})
    job = builtin_registry().build("job_target_catalog")
    with publication_scope_for_owner(SharedArtifacts.for_job(context.job)):
        for task in job.units:
            context.unit_id = task.unit_id
            outputs[task.unit_id] = task.handler(context)
    # Replace the synthetic bootstrap result with the actual producer's outputs.
    (context.job.attempt_root / "result.json").unlink()
    _publish_input(unit, "job_target_catalog", outputs, attempt_id="attempt_0001",
                   artifacts=attempt_artifacts(unit.job.run_root, context.job.attempt_root))


def _fixture(tmp_path, *, paths=("a/app.py", "b/app.py")):
    unit = _make_unit(tmp_path)
    root, target = unit.job.run_root, unit.job.target_root
    for path in paths:
        source = target / path
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("value = 1\nvalue = 2\nvalue = 3\n")
    unit.job.source_fingerprint = source_fingerprint(target)
    unit.job.evidence_target_snapshot = unit.job.source_fingerprint
    unit.job.config.job_id = JOB
    unit.job.contract = codeql.CONTRACT
    unit.job.upstream_handoffs = {}
    settings = unit.job.config.typed_settings
    unit.job.config.typed_settings = replace(
        settings, concurrency=1, preinstalled_runtimes=(),
        languages={**settings.languages, "python": replace(
            settings.languages["python"], additional_queries=(), custom_queries=())})
    for producer in REQUIRED:
        outputs, artifacts = {}, []
        directory = root / f"data/jobs/{producer}/attempts/attempt_0001/artifacts"
        if producer == "job_language_build":
            document = directory / "language-build/receipts.json"
            atomic_json(document, {"schema": "appsec-review/language-build-handoff/2",
                                  "source_fingerprint": unit.job.source_fingerprint, "receipts": []})
            outputs = {"acceptance.publish_handoff": {"artifact": reference(root, document)}}
        elif producer == "job_target_catalog":
            _catalog_input(unit, tmp_path)
            continue
        _publish_input(unit, producer, outputs, artifacts=artifacts)
    with input_read_scope(unit.job):
        catalog = codeql.load_target_catalog(root)
        build = codeql.load_accepted_language_build(root)
    plan = build_codeql_plan(
        source_fingerprint=unit.job.source_fingerprint, files=catalog.files, projects=catalog.projects,
        receipts=build["receipts"], supported_extractors=("python",), source_image_id=settings.source_image_id)
    path = unit.job.attempt_root / "artifacts/codeql/plan.json"
    atomic_json(path, plan.as_dict())
    manifest = root / "data/indices/manifests/upstream.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=target, indexes=[])
    unit.job.input_manifest_path, unit.job.input_manifest_sha256 = manifest, file_sha256(manifest)
    unit._stored["plan.inventory"] = {"plan": reference(root, path), "upstream_manifests": [reference(root, manifest)]}
    unit.job.orchestration = {"system": "unit", "run_id": "codeql-closure"}
    atomic_json(unit.job.attempt_root / "claim.json", {
        "run_id": unit.job.run_id, "job_id": JOB, "attempt_id": unit.job.attempt_id,
        "attempt_path": unit.job.attempt_root.relative_to(root).as_posix(),
        "orchestration": unit.job.orchestration,
        "dataset_contract": dataset_contract(JOB, ("plan", "execution", "acceptance"), codeql.DATASETS)})
    return unit, plan


def _engine(unit, monkeypatch):
    settings = unit.job.config.typed_settings
    image = CodeQLImage("appsec-review/codeql-runtime-image/2", "fixture", settings.source_image_id,
                        settings.source_image_id, "fixture:1", settings.source_image_id, "fixture:1",
                        "10001:10001", None, None, False, "manifest.json")
    monkeypatch.setattr(codeql, "_resolve_image", lambda *args, **kwargs: (image, b"", b""))
    monkeypatch.setattr(codeql, "_make_workspace_accessible", lambda *args, **kwargs: None)

    class Engine(SeededExecutor):
        def __init__(self, **kwargs):
            super().__init__({("app.py", 1, 1): ["f"], ("app.py", 3, 3): ["f"]},
                             [["f", "app.py", 1, 1, 0]], language="python")

        def execute(self, action, argv, *, scratch_root):
            if action in {"compile", "export"}:
                return super().execute(action, argv, scratch_root=scratch_root)
            if action == "database":
                database = scratch_root / "database"
                database.mkdir(parents=True)
                (database / "codeql-database.yml").write_text("primaryLanguage: python\n")
            elif action == "query":
                atomic_json(scratch_root / "sarif/results.sarif", {
                    "version": "2.1.0", "runs": [{"results": [{
                        "ruleId": "py/fixture", "message": {"text": "inert fixture observation"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "app.py"}, "region": {"startLine": 3}}}],
                    }]}]})
            else:
                raise AssertionError(f"unexpected engine action: {action}")
            atomic_json(scratch_root / f"executions/{action}/receipt.json", {
                "schema": "appsec-review/codeql-execution/2", "action": action})
            return SimpleNamespace(exit_code=0, timed_out=False, duration_ms=1,
                                   stdout_truncated=False, stderr_truncated=False)

    monkeypatch.setattr(codeql, "CodeQLExecutor", Engine)


def _execute_publish(unit):
    owner = SharedArtifacts.for_job(unit.job)
    with publication_scope_for_owner(owner), input_read_scope(unit.job) as reads:
        execute, publish = codeql.build_job().units[1:]
        unit.unit_id = execute.unit_id
        output = execute.handler(unit)
        unit._stored[execute.unit_id] = output
        unit.unit_id = publish.unit_id
        published = publish.handler(unit)
    assert any(row["producer"] == "job_language_build" for row in reads.document()["reads"])
    return output, published


@pytest.mark.parametrize("filename", ["legacy.vb", "legacy.fs", "app.swift", "main.go"])
def test_plan_only_gaps_survive_acceptance_and_canonical_projection(tmp_path, filename):
    unit, plan = _fixture(tmp_path, paths=(filename,))
    assert plan.scopes == () and plan.gaps
    output, published = _execute_publish(unit)
    assert output["scopes"] == []
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert set(plan.gaps) <= set(published["gaps"])
    path = unit.job.attempt_root / "handoff.json"
    write_fixture_handoff(unit.job.run_root, path, {
        "job_id": JOB, "completion_status": published["terminal_status"], "outputs": unit._stored | {
            "acceptance.publish_handoff": published},
        "artifacts": attempt_artifacts(unit.job.run_root, unit.job.attempt_root),
    }, target_snapshot=unit.job.source_fingerprint)
    prior = json.loads(path.read_bytes())
    claim = json.loads(path.with_name("claim.json").read_bytes())
    claim.update(component_identities={"implementation": "unit/1", "schema": "unit/1", "validation": "unit/1"},
                 started_at=prior["started_at"], job_config_sha256=prior["job_config_sha256"])
    projected = JobRunner(load_config(unit.job.repository_root / "appsec-review.toml"))._handoff_document(
        unit.job, claim, {"status": published["terminal_status"], "outputs": prior["outputs"]},
        json.loads(path.with_name("outcomes.json").read_bytes()), prior["outcomes"],
        accepted=True, completed=prior["completed_at"], artifacts=prior["artifacts"])
    assert "scopes" not in projected["outputs"]["execution.scopes"]
    assert projected["outputs"]["execution.scopes"]["artifact"] == output["artifact"]
    assert projected["completion_status"] == "COMPLETED_WITH_GAPS"
    assert projected["coverage"]["disposition"] != "complete"


@pytest.mark.parametrize("fail_stop", [False, True])
def test_export_admission_failure_keeps_successful_query_publication(tmp_path, monkeypatch, fail_stop):
    unit, plan = _fixture(tmp_path, paths=("a/app.py",))
    _engine(unit, monkeypatch)
    reserve = codeql.ResourceAdmission.reserve

    @contextmanager
    def timeout_export(self, *args, **kwargs):
        if kwargs["action"] == "codeql.export":
            raise TimeoutError("fixture export reservation expired")
        with reserve(self, *args, **kwargs) as lease:
            yield lease

    monkeypatch.setattr(codeql.ResourceAdmission, "reserve", timeout_export)
    if fail_stop:
        from appsec_review.runtime import execution_safety as safety

        calls = []

        def controller_request(self, command, **fields):
            calls.append((command, fields))
            return {"ok": True, **({"permit": f"fixture-{len(calls)}"} if command == "admit" else {})}

        monkeypatch.setattr(safety.SafetyClient, "request", controller_request)
        policy = safety.policy("00000000-0000-0000-0000-000000000001",
                               {"source_commit": "a" * 40, "target_commit": "b" * 40, "configuration": {}})
        with safety.safety_scope(policy), pytest.raises(safety.ReviewStopped, match="CodeQL export failed"):
            _execute_publish(unit)
        assert any(command == "failure" and fields["action"] == "codeql.export" for command, fields in calls)
        assert not (unit.job.attempt_root / "artifacts/codeql/graph-exports.json").exists()
        return
    output, published = _execute_publish(unit)
    exported, = output["exports"]
    assert exported["scope_id"] == plan.scopes[0].scope_id
    assert exported["database_identity"] == output["databases"][0]["database_identity"]
    assert exported["export_status"] == "FAILED"
    assert exported["gaps"] == ["CodeQL export operational failure (TimeoutError)"]
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert published["item_count"] == 1
    assert output["scopes"][0]["terminal_status"] == "SUCCEEDED"
    failures = [payload for event, payload in unit.job.events.items if event == "CODEQL_ACTION_FAILED"]
    assert failures[0]["scope_id"] == plan.scopes[0].scope_id
    assert failures[0]["action"] == "export"


@pytest.mark.parametrize("outside", [False, True])
def test_export_seed_ownership_uses_whole_plan_and_only_own_normalizations(tmp_path, monkeypatch, outside):
    unit, plan = _fixture(tmp_path)
    _engine(unit, monkeypatch)
    root, snapshot = unit.job.run_root, unit.job.source_fingerprint
    path = root / "data/indices/observations/static-fixture.sqlite"
    builder = IndexBuilder(path, name="observations", shard_id="static-fixture",
                           target_snapshot=snapshot, fingerprint="a" * 64)
    for scope in plan.scopes:
        source = scope.files[0]
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"path": source["path"]})
        builder.add_entity(EntityRecord(identity, source["path"], "fixture", "fixture",
            {"tool_id": "tool-semgrep", "category": "source_sast", "native_severity": "HIGH"},
            SourceLocation(snapshot, source["path"], source["sha256"], 0, 9, 1, 1, 1, 10, {}, "exact", 1.0)))
    if outside:
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"outside": True})
        builder.add_entity(EntityRecord(identity, "outside", "outside", "outside",
            {"tool_id": "tool-semgrep", "category": "source_sast"},
            SourceLocation(snapshot, "unplanned.txt", "b" * 64, 0, 1, 1, 1, 1, 2, {}, "exact", 1.0)))
    sha = builder.build()
    shard = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, "a" * 64,
                          path.relative_to(root).as_posix(), {"job": "job_evidence_collection"}, (), "static-fixture")
    manifest = root / "data/indices/manifests/static.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=snapshot,
                   target_root=unit.job.target_root, indexes=[shard])
    ref = reference(root, manifest)
    _publish_input(unit, "job_evidence_collection", {"publish.main": {"index_manifest": ref}},
                   artifacts=[reference(root, path)])
    unit._stored["plan.inventory"]["upstream_manifests"].append(ref)
    captured = []
    seed_plan = codeql._seed_plan

    def capture(*args, **kwargs):
        result = seed_plan(*args, **kwargs)
        captured.append((result, kwargs["extra_observation_shards"]))
        return result

    monkeypatch.setattr(codeql, "_seed_plan", capture)
    output, published = _execute_publish(unit)
    assert len(captured) == 2
    for (seeds, shards), scope, normalized, exported in zip(
        captured, plan.scopes, output["scopes"], output["exports"], strict=True,
    ):
        assert seeds.not_in_database == int(outside)
        assert shards == [normalized["index_identity"]]
        own = seeds.for_scope(scope.scope_id)
        assert own.rows == (("app.py", 1, 1), ("app.py", 3, 3))
        assert {source.scanner for seed in own.seeds for source in seed.sources} == {"tool-semgrep", "codeql"}
        other = next(item for item in plan.scopes if item.scope_id != scope.scope_id)
        assert seeds.for_scope(other.scope_id).rows == (("app.py", 1, 1),)
        assert exported["export_status"] == "SUCCEEDED"
        assert exported["seeded"]["status_counts"].get("file_not_in_database", 0) == int(outside)
    assert published["terminal_status"] == ("COMPLETED_WITH_GAPS" if outside else "SUCCEEDED")


@pytest.mark.parametrize("missing", [*REQUIRED, "catalog_documents", "language_build_receipts"])
def test_mandatory_reads_are_rejected_during_input_admission(tmp_path, missing):
    unit, _ = _fixture(tmp_path, paths=())
    if missing in REQUIRED:
        unit.job.upstream_handoffs.pop(missing)
    else:
        producer = "job_target_catalog" if missing == "catalog_documents" else "job_language_build"
        prior = json.loads((unit.job.run_root / f"data/jobs/{producer}/attempts/attempt_0001/handoff.json").read_bytes())
        manifests = {key: {field: value[field] for field in ("index_identity", "index_manifest") if field in value}
                     for key, value in prior["outputs"].items()
                     if "index_identity" in value or "index_manifest" in value}
        attempt = unit.job.run_root / prior["resolving_paths"]["attempt"]
        (attempt / "result.json").unlink()
        _publish_input(unit, producer, manifests or {"publish.empty": {"terminal_status": "SUCCEEDED"}},
                       attempt_id=prior["attempt_id"],
                       artifacts=[ref for ref in prior["artifacts"] if ref["path"].startswith("data/indices/")
                                  or "/shared/" in ref["path"]])
    with pytest.raises(ValueError, match="required input unavailable"):
        admit_inputs(unit.job, set(REQUIRED))


def test_optional_absence_is_allowed_but_invalid_required_payload_is_not_defaulted(tmp_path):
    unit, _ = _fixture(tmp_path, paths=())
    admitted = admit_inputs(unit.job, set(REQUIRED))
    assert any(row["status"] == "gap" and row["producer"] == "job_evidence_collection"
               for row in admitted["requirements"])
    with input_read_scope(unit.job) as reads:
        assert codeql.load_target_catalog(unit.job.run_root).files == ()
        assert codeql.load_accepted_language_build(unit.job.run_root)["receipts"] == []
    assert {row["producer"] for row in reads.document()["reads"]} >= {"job_target_catalog", "job_language_build"}
    path = unit.job.run_root / "data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/receipts.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="(identity changed|changed)"), input_read_scope(unit.job):
        codeql.load_accepted_language_build(unit.job.run_root)
