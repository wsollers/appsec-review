from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.cbmc import CbmcSettings
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.job_cbmc_analysis.analysis import Analysis, stage_source
from appsec_review.jobs.job_cbmc_analysis.protocol import (
    CompileRejected, OutputRejected, compile_argv, function_entries, goto_functions_output, judgment, native_json,
)
from appsec_review.storage import file_sha256, run_artifact

IMAGE = "sha256:" + "c" * 64


def settings(**overrides):
    return CbmcSettings(image_id=IMAGE, **overrides)


def outcome(status="SUCCESS", *, name="f.pointer_dereference.1", trace=False):
    return [{"result": [{"property": name, "description": "pointer check", "status": status,
                         "sourceLocation": {"file": "/target/source/main.c", "line": "2"},
                         **({"trace": [{"stepType": "failure"}]} if trace else {})}]},
            {"cProverStatus": "success" if status == "SUCCESS" else "failure"}]


def functions(names=("f",)):
    return [{"functions": [
        {"name": name, "isBodyAvailable": True, "isInternal": False,
         "instructions": [{"sourceLocation": {"file": "/target/source/main.c", "line": str(line)}}
                          for line in (1, 3)]} for name in names]}]


def goto_functions_text(names=("f",), *, file="/target/source/main.c", lines=(1, 3)) -> bytes:
    sep = "^" * 44
    chunks = ["Reading GOTO program from '/inputs/unit.goto'"]
    for name in names:
        chunks.extend([sep, "", f"{name} /* {name} */"])
        for idx, line in enumerate(lines):
            chunks.append(f"        // {idx} file {file} line {line} function {name}")
            chunks.append("        SKIP")
        chunks.append(f"        // {len(lines)} file {file} line {lines[-1]} function {name}")
        chunks.append("        END_FUNCTION")
    return ("\n".join(chunks) + "\n").encode("utf-8")


SEED = {"path": "main.c", "start_line": 2, "end_line": 2, "rank": 0,
        "observation_ids": ["asr:tool_observation:" + "a" * 64]}


def fixture(tmp_path):
    run = tmp_path / "run"
    case = run / "data/cpp/projects/case"
    source = case / "source/main.c"
    source.parent.mkdir(parents=True)
    source.write_text("int f(int *p) {\n  return *p;\n}\n")
    accepted = {"target_path": "native/main.c", "scratch_path": "source/main.c",
                "sha256": file_sha256(source)}
    row = {"file": "/target/source/main.c", "arguments": ["clang", "-c", "/target/source/main.c", "-o", "old.o"]}
    database = case / "build/compile_commands.json"
    database.parent.mkdir()
    database.write_text(json.dumps([row]))
    scope = IndexScope("scope", "case", "native", "native", "f" * 64, case, (accepted,),
                       ({"target_path": "native/main.c", "arguments": row["arguments"]},),
                       run_artifact(run, database), {"main.c": accepted})
    job = SimpleNamespace(run_root=run, repository_root=tmp_path, attempt_root=run / "attempt",
                          config=SimpleNamespace(settings={}))
    return scope, row, SimpleNamespace(job=job)


class FakeExecutor:
    def __init__(self, run, responses=None, *, timed_out=False, wrong_image=False, discovery_response=None):
        self.run = run
        self.responses = list(responses or [(0, outcome())])
        self.timed_out = timed_out
        self.wrong_image = wrong_image
        self.discovery_response = discovery_response or (0, goto_functions_text())
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        assert request.argv[:3] == ("/usr/bin/timeout", "--signal=TERM", "--kill-after=2s")
        command = request.argv[4]
        if command == "/usr/bin/goto-cc":
            (request.scratch_root / "unit.goto").write_bytes(b"fixture goto")
            code, data = 0, []
        elif command == "/usr/bin/goto-instrument":
            code, data = self.discovery_response
        else:
            code, data = self.responses.pop(0)
        stdout, stderr, receipt = [request.scratch_root / name for name in ("stdout.bin", "stderr.bin", "execution.json")]
        stdout.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
        stderr.write_text("")
        receipt.write_text(json.dumps({"argv": list(request.argv), "exit_code": code}))
        rel = lambda path: path.relative_to(self.run).as_posix()
        return ExecutionResult("appsec-review/container-execution/1", "tool-cbmc", "fixture", "wrong" if self.wrong_image else IMAGE,
                               IMAGE, "argv", (), {}, "start", "end", code, self.timed_out, False, False, False,
                               rel(stdout), rel(stderr), rel(receipt))


def test_compile_admission_preserves_semantics_and_replaces_output():
    row = {"file": "/target/source/a.c", "arguments": [
        "clang", "-DVALUE=2", "-I", "/target/source/include", "-std=c11",
        "-c", "/target/source/a.c", "-o", "/tmp/native.o", "-MMD", "-MF", "/tmp/deps",
    ]}
    argv, replaced = compile_argv(row)
    assert argv == ("/usr/bin/goto-cc", "-c", "-DVALUE=2", "-I", "/target/source/include",
                    "-std=c11", "/target/source/a.c", "-o", "/scratch/unit.goto")
    assert "/tmp/native.o" in replaced


@pytest.mark.parametrize("flag", ["@response", "-fplugin=evil.so", "--sysroot=/outside", "-I/outside", "-Wp,-include,/outside"])
def test_compile_admission_rejects_unmodeled_flags(flag):
    with pytest.raises(CompileRejected):
        compile_argv({"file": "/target/source/a.c", "arguments": ["cc", flag, "/target/source/a.c"]})


def test_function_selection_requires_unique_source_backed_entry():
    entries, gaps = function_entries(functions(), [SEED], max_instructions=10)
    assert entries[0]["function"] == "f" and entries[0]["seeds"] == [SEED] and not gaps
    entries, gaps = function_entries(functions(("f", "g")), [SEED], max_instructions=10)
    assert entries == [] and gaps[0]["reason"] == "function_ambiguous"
    with pytest.raises(OutputRejected, match="instruction bound"):
        function_entries(functions(), [SEED], max_instructions=1)


def test_bounded_pass_counterexample_and_unwinding_are_distinct():
    assert judgment(outcome(), 0, max_properties=10)["judgment"] == "bounded_pass"
    failure = judgment(outcome("FAILURE", trace=True), 10, max_properties=10)
    assert failure["judgment"] == "counterexample_candidate" and failure["candidate_count"] == 1
    unwind = judgment(outcome("FAILURE", name="f.unwind.0", trace=True), 10, max_properties=10)
    assert unwind["judgment"] == "inconclusive" and unwind["retry_unwind"]
    missing = judgment(outcome("FAILURE", name="f.no-body.1", trace=True), 10, max_properties=10)
    assert missing["judgment"] == "inconclusive" and not missing["retry_unwind"]
    no_trace = judgment(outcome("FAILURE"), 10, max_properties=10)
    assert no_trace["judgment"] == "inconclusive"
    warning = judgment([{"messageType": "WARNING"}, *outcome()], 0, max_properties=10)
    assert warning["judgment"] == "inconclusive"


@pytest.mark.parametrize("data,code", [
    ([], 0), ([{"result": []}, {"cProverStatus": "success"}], 0),
    (outcome("FAILURE", trace=True), 0), (outcome(), 10),
    (outcome(), 6), ([*outcome(), {"cProverStatus": "success"}], 0),
])
def test_incomplete_or_contradictory_native_output_is_rejected(data, code):
    with pytest.raises(OutputRejected):
        judgment(data, code, max_properties=10)


def test_native_json_rejects_duplicate_fields_and_truncation():
    for data in (b'[{"result":[],"result":[]}]', b'[{"result":', b'{}', b'\xff'):
        with pytest.raises(OutputRejected):
            native_json(data, 1024)
    with pytest.raises(OutputRejected, match="bound"):
        native_json(b"[{}]", 2)
    malformed = outcome()
    malformed[0]["result"][0]["status"] = {}
    with pytest.raises(OutputRejected):
        judgment(malformed, 0, max_properties=10)


def test_staging_refuses_changed_source_and_unlisted_files_never_reach_mount(tmp_path):
    scope, _, unit = fixture(tmp_path)
    (scope.case_root / "source/extra.h").write_text("unaccepted")
    stage_source(scope, unit.job.attempt_root / "input", settings())
    assert not (unit.job.attempt_root / "input/source/extra.h").exists()
    (scope.case_root / "source/main.c").write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        stage_source(scope, unit.job.attempt_root / "another", settings())


def test_staging_refuses_symlink_ancestors(tmp_path):
    scope, _, unit = fixture(tmp_path)
    source = scope.case_root / "source"
    relocated = scope.case_root / "original"
    source.rename(relocated)
    source.symlink_to(relocated, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        stage_source(scope, unit.job.attempt_root / "input", settings())


def test_execution_uses_original_source_and_retries_only_unwinding(tmp_path):
    scope, row, unit = fixture(tmp_path)
    executor = FakeExecutor(unit.job.run_root, [
        (10, outcome("FAILURE", name="f.unwind.0", trace=True)),
        (10, outcome("FAILURE", trace=True)),
    ])
    engine = Analysis(unit, settings(), executor_factory=lambda *_: executor)
    results = engine.translation_unit(scope, row, [SEED], scope.case_root)
    assert results[0]["judgment"] == "counterexample_candidate"
    assert results[0]["unwind_limits_attempted"] == [8, 32]
    assert results[0]["seed_locations"][0]["file_sha256"] == scope.files[0]["sha256"]
    assert [r.argv[4] for r in executor.requests] == [
        "/usr/bin/goto-cc", "/usr/bin/goto-instrument", "/usr/bin/cbmc", "/usr/bin/cbmc"]
    assert all(r.target_root == scope.case_root for r in executor.requests)
    assert all("--unwinding-assertions" in r.argv for r in executor.requests[2:])
    assert all(r.accepted_exit_codes == frozenset({0, 10, 124}) for r in executor.requests[2:])
    assert all(int(r.argv[3]) == settings().command_timeout_seconds - 3 for r in executor.requests)
    assert all(r.extra_mounts[0].read_only and r.extra_mounts[0].target == "/inputs/unit.goto"
               for r in executor.requests[1:])


def test_exhausted_budget_launches_nothing_and_timeout_is_not_clean(tmp_path):
    scope, row, unit = fixture(tmp_path)
    executor = FakeExecutor(unit.job.run_root)
    engine = Analysis(unit, settings(), executor_factory=lambda *_: executor, clock=lambda: 0)
    engine.clock = lambda: 301
    results = engine.translation_unit(scope, row, [SEED], scope.case_root)
    assert results[0]["judgment"] == "not_attempted" and not executor.requests
    failed = Analysis(unit, settings(), executor_factory=lambda *_: FakeExecutor(unit.job.run_root, timed_out=True))
    result = failed.translation_unit(scope, row, [SEED], scope.case_root)
    assert result[0]["judgment"] == "inconclusive"


def test_image_identity_mismatch_fails_instead_of_publishing_a_gap(tmp_path):
    scope, row, unit = fixture(tmp_path)
    engine = Analysis(unit, settings(), executor_factory=lambda *_: FakeExecutor(unit.job.run_root, wrong_image=True))
    with pytest.raises(ValueError, match="admitted image"):
        engine.translation_unit(scope, row, [SEED], scope.case_root)


@pytest.mark.parametrize("change", [{"enabled": 1}, {"max_functions": True}, {"unwind_limits": [32, 8]},
                                   {"unknown": 3}, {"image_id": "moving-tag"}])
def test_settings_are_closed_and_typed(change):
    with pytest.raises(ValueError):
        CbmcSettings.from_mapping({"image_id": IMAGE, **change})


def test_function_budget_records_omitted_entry(tmp_path):
    scope, row, unit = fixture(tmp_path)
    executor = FakeExecutor(unit.job.run_root)
    engine = Analysis(unit, settings(max_functions=1), executor_factory=lambda *_: executor)
    engine.function_count = 1
    result = engine.translation_unit(scope, row, [SEED], scope.case_root)[0]
    assert result["judgment"] == "not_attempted" and result["gaps"] == ["function_budget"]
    assert len(executor.requests) == 2


def admitted_fixture(tmp_path, monkeypatch, *, wrong_seed_hash=False):
    from appsec_review.jobs.job_cbmc_analysis import job as module
    from appsec_review.jobs.job_evidence_collection.datasets import DATASETS as SAST_DATASETS
    from appsec_review.indexing import store as store_module
    from appsec_review.runtime.datasets import dataset_contract
    from appsec_review.storage import atomic_json
    from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest
    scope, row, unit = fixture(tmp_path)
    job = unit.job
    job.source_fingerprint = "none"
    job.evidence_target_snapshot = "f" * 64
    job.run_id, job.attempt_id = "run", "attempt_0001"
    job.config.settings = asdict(settings())
    job.events = SimpleNamespace(write=lambda *args, **kwargs: None)
    unit.unit_root = job.attempt_root / "steps/acceptance/tasks/publish_handoff"
    unit.unit_root.mkdir(parents=True)
    unit.unit_id = "acceptance.publish_handoff"
    shard = job.run_root / "data/indices/observations/seeds.sqlite"
    builder = IndexBuilder(shard, name="observations", fingerprint="a" * 64,
                           target_snapshot="f" * 64, shard_id="seeds")
    location = SourceLocation("f" * 64, "native/main.c", "0" * 64 if wrong_seed_hash else scope.files[0]["sha256"],
                              0, 20, 2, 2, 1, 1, producer_location={}, mapping_method="fixture", confidence=1.0)
    builder.add_entity(EntityRecord(
        LogicalIdentity.parse(SEED["observation_ids"][0]), "seed", "pointer", "pointer finding",
        {"tool_id": "tool-cppcheck", "category": "source_sast", "native_rule_id": "nullPointer",
         "native_severity": "high"}, location))
    digest = builder.build()
    identity = IndexIdentity("observations", "appsec-review/retrieval-index/2", digest, "a" * 64,
                             shard.relative_to(job.run_root).as_posix(), {"job": "job_evidence_collection"}, (), "seeds")
    manifest = job.run_root / "data/indices/manifests/input.json"
    write_manifest(manifest, run_id="run", target_snapshot="f" * 64, target_root=scope.case_root,
                   indexes=[identity])
    job.input_manifest_path, job.input_manifest_sha256 = manifest, file_sha256(manifest)
    accepted = {"handoff": {"source_fingerprint": "f" * 64}}
    summary_path = job.run_root / "data/jobs/job_cpp_compiled_analysis/attempts/attempt_0001/steps/acceptance/tasks/publish_handoff/summary.json"
    summary_path.parent.mkdir(parents=True)
    summary_path.write_text(json.dumps({"schema": "appsec-review/cpp-compiled-analysis/2"}))
    summary_ref = run_artifact(job.run_root, summary_path)
    supplied = SimpleNamespace(handoff={
        "outputs": {"acceptance.publish_handoff": {"artifact": summary_ref}}, "artifacts": [summary_ref]})
    contract = dataset_contract("job_evidence_collection", sorted({item.step for item in SAST_DATASETS}),
                                SAST_DATASETS)
    producer_attempt = job.run_root / "data/jobs/job_evidence_collection/attempts/attempt_0001"
    atomic_json(producer_attempt / "claim.json", {"dataset_contract": contract})
    evidence = SimpleNamespace(handoff={
        "job_id": "job_evidence_collection", "dataset_contract_sha256": contract["sha256"],
        "resolving_paths": {"attempt": producer_attempt.relative_to(job.run_root).as_posix()}})
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _: (accepted, [scope], {}))
    monkeypatch.setattr(module, "accepted_upstream", lambda *_args, **_kwargs: supplied)
    monkeypatch.setattr(store_module, "accepted_handoff",
                        lambda _root, producer: evidence if producer == "job_evidence_collection" else None)
    return module, scope, row, unit


def test_real_selection_analysis_and_index_publication_are_consumable(tmp_path):
    from appsec_review.indexing.store import ShardSet
    from appsec_review.retrieval import EntityKind
    from appsec_review.retrieval.index import load_verified_manifest
    from appsec_review.review.bounded_analysis import BoundedAnalysisContext
    from appsec_review.review.evidence import classify
    from appsec_review.review.models import Admissibility, Predicate
    from appsec_review.provenance import verify_native_reference
    harness = runtime_fixture(tmp_path, responses=[(10, outcome("FAILURE", trace=True))])
    run_units(harness)
    accepted = harness.runner.finalize_attempt(harness.job, harness.claim)
    outputs = accepted["result"]["outputs"]
    selected = json.loads((harness.root / outputs["load.accepted_inputs"]["artifact"]["path"]).read_bytes())
    assert len(selected["work"]) == 1
    analyzed = json.loads((harness.root / outputs["analyze.bounded_checks"]["artifact"]["path"]).read_bytes())
    assert analyzed["counts"] == {"counterexample_candidate": 1}
    published = outputs["acceptance.publish_handoff"]
    manifest, _ = load_verified_manifest(harness.root, harness.root / published["index_manifest"]["path"],
                                         published["index_manifest"]["sha256"])
    cbmc = [shard for shard in manifest["indexes"] if shard["producer"].get("job") == "job_cbmc_analysis"]
    store = ShardSet(harness.root, manifest["indexes"])
    records = list(store.entities(cbmc, kinds=("review_signal",)))
    assert len(records) == 1 and records[0]["payload"]["judgment"] == "counterexample_candidate"
    assert records[0]["payload"]["seed_observation_ids"] == SEED["observation_ids"]
    [native] = records[0]["payload"]["common"]["evidence_refs"]
    assert verify_native_reference(harness.root, native, resolve=True) == outcome("FAILURE", trace=True)
    assert all(classify(EntityKind.REVIEW_SIGNAL, p, tuple(Predicate)) is Admissibility.INDIRECT for p in Predicate)
    review_scope = SimpleNamespace(run_root=harness.root, store=store,
                                  select=lambda predicate: tuple(s for s in manifest["indexes"] if predicate(s)),
                                  shard_sha256=lambda shard: shard["sha256"])
    context = BoundedAnalysisContext(review_scope)
    entries, gaps = context.for_leads(
        [SimpleNamespace(path="native/main.c", observation_id=SEED["observation_ids"][0])])
    assert len(entries) == 1 and entries[0].role == "bounded_analysis" and not gaps
    assert entries[0].id == records[0]["identity"]
    unrelated, missing = context.for_leads(
        [SimpleNamespace(path="native/main.c", observation_id="asr:tool_observation:" + "d" * 64)])
    assert unrelated == [] and missing[0].state == "unavailable"
    assert published["terminal_status"] == "SUCCEEDED"
    assert any(row["status"] == "partial" for row in store.coverage(cbmc))


def test_native_result_publication_requires_active_shared_owner(tmp_path, monkeypatch):
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import current

    module, _, _, unit = admitted_fixture(tmp_path, monkeypatch)
    assert current() is None
    selected = module.plan(unit.job, settings())
    analyzed = module.analyze(unit, selected, settings(),
                              lambda *_: FakeExecutor(unit.job.run_root, [(0, outcome())]))
    plan_path = unit.job.attempt_root / "plan.json"
    result_path = unit.job.attempt_root / "artifacts/cbmc/analysis.json"
    atomic_json(plan_path, selected)
    atomic_json(result_path, analyzed)
    with pytest.raises(ValueError, match="native provenance requires a run-owned publication attempt"):
        module.publish(unit, analyzed, run_artifact(unit.job.run_root, plan_path),
                       run_artifact(unit.job.run_root, result_path))
    assert not (unit.unit_root / "summary.json").exists()
    assert not (unit.job.run_root / "data/indices/manifests/cbmc-attempt_0001.json").exists()


def test_foreign_seed_bytes_and_changed_manifest_are_rejected(tmp_path, monkeypatch):
    module, _, _, unit = admitted_fixture(tmp_path, monkeypatch, wrong_seed_hash=True)
    with pytest.raises(ValueError, match="identities differ"):
        module.plan(unit.job, settings())
    unit.job.input_manifest_path.write_text("{}")
    with pytest.raises(ValueError, match="changed"):
        module.plan(unit.job, settings())


def test_foreign_target_snapshot_is_rejected(tmp_path, monkeypatch):
    module, _, _, unit = admitted_fixture(tmp_path, monkeypatch)
    unit.job.evidence_target_snapshot = "d" * 64
    with pytest.raises(ValueError, match="different target"):
        module.plan(unit.job, settings())


def test_missing_cpp_input_reports_gap_instead_of_clean_result(tmp_path, monkeypatch):
    module, scope, _, unit = admitted_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "accepted_cpp_scopes",
                        lambda _: ({"handoff": {"source_fingerprint": "f" * 64}}, [], {"case": "build failed"}))
    selected = module.plan(unit.job, settings())
    assert selected["work"] == [] and selected["gaps"][0]["schema"] == "appsec-review/producer-gap/1"
    monkeypatch.setattr(module, "accepted_cpp_scopes",
                        lambda _: ({"handoff": {"source_fingerprint": "f" * 64}}, [], {}))
    unmapped = module.plan(unit.job, settings())
    assert unmapped["work"] == []
    assert any("no accepted compiled source scope" in gap["reason"] for gap in unmapped["gaps"])


def test_registry_topology_contracts_and_disabled_projection():
    from appsec_review.config import load_config
    from appsec_review.runtime.registry import builtin_registry
    from appsec_review.orchestration.topology import wave1_dependencies, upstream_closure
    from appsec_review.runtime.datasets import shard_owner
    root = Path(__file__).resolve().parents[3]
    registry = builtin_registry()
    registry.require_matches(load_config(root / "appsec-review.toml").jobs, surface="CBMC unit")
    jobs = set(registry.job_ids())
    graph = wave1_dependencies(jobs)
    assert "job_cbmc_analysis" in upstream_closure("job_review_package_assembly", graph, jobs)
    assert "job_cbmc_analysis" in upstream_closure("job_inference_security_review", graph, jobs)
    disabled = wave1_dependencies(jobs - {"job_cbmc_analysis"})
    assert "job_cbmc_analysis" not in disabled
    job = registry.build("job_cbmc_analysis")
    assert job.strict_gaps and job.contract.target_access.value == "accepted_evidence"
    assert shard_owner(job.datasets, "observations", "cbmc-results-attempt_1").output_kind == "cbmc_results"
    assert shard_owner(job.datasets, "observations", "cbmc-coverage-attempt_1").output_kind == "cbmc_coverage"


def test_native_trace_preview_is_bounded_and_preserves_failure():
    data = outcome("FAILURE", trace=True)
    data[0]["result"][0]["trace"] = [
        {"stepType": "assignment", "lhs": f"x{i}", "value": {"data": "1" * 50}} for i in range(8)
    ] + [{"stepType": "failure"}]
    result = judgment(data, 10, max_properties=10, max_trace_steps=3, max_trace_value_chars=8)
    prop = result["properties"][0]
    assert len(prop["trace"]) == 3 and prop["trace_omitted"] == 6
    assert prop["trace"][0]["value"] == "1" * 8 and prop["trace"][-1]["kind"] == "failure"


def test_expected_command_deadline_is_inconclusive(tmp_path):
    scope, row, unit = fixture(tmp_path)
    executor = FakeExecutor(unit.job.run_root, [(124, [])])
    engine = Analysis(unit, settings(), executor_factory=lambda *_: executor)
    result = engine.translation_unit(scope, row, [SEED], scope.case_root)[0]
    assert result["judgment"] == "inconclusive" and "command deadline" in result["reason"]
    assert 124 in executor.requests[-1].accepted_exit_codes


def test_unresolving_native_failure_does_not_become_a_candidate(tmp_path):
    from appsec_review.review.bounded_analysis import summary
    scope, row, unit = fixture(tmp_path)
    data = outcome("FAILURE", trace=True)
    data[0]["result"][0]["sourceLocation"]["line"] = "9000"
    executor = FakeExecutor(unit.job.run_root, [(10, data)])
    result = Analysis(unit, settings(), executor_factory=lambda *_: executor).translation_unit(
        scope, row, [SEED], scope.case_root)[0]
    assert result["judgment"] == "inconclusive" and result["candidate_count"] == 0
    assert "failed_property_source_unresolved" in result["gaps"]
    assert summary({"schema": "appsec-review/cbmc-result/1", **result})["counterexamples"] == []


def test_model_view_exposes_conditional_judgment_and_assumptions(tmp_path):
    from appsec_review.retrieval.core import RetrievalCore
    from appsec_review.review.package_view import ViewLimits, build_view
    from appsec_review.review.packages import PackageSettings, assemble_packages
    from appsec_review.review.scope import accept_manifest
    from tests.fixtures.inference_review.builder import build_accepted_index_set
    fixture_run = build_accepted_index_set(tmp_path, publish_v1_packages=False)
    assembly = assemble_packages(accept_manifest(fixture_run.run_root), PackageSettings(lead_cluster_lines=0))
    package = next(p.document() for p in assembly.packages if fixture_run.ids["sast_critical"] in p.lead_ids)
    identity = "asr:review_signal:" + "b" * 64
    package["context"].append({"id": identity, "kind": "review_signal", "role": "bounded_analysis"})
    package["retrieval"]["entity_ids"].append(identity)
    core = RetrievalCore(fixture_run.runs_dir, fixture_run.run_id)
    payload = {
        "schema": "appsec-review/cbmc-result/1", "judgment": "bounded_pass", "function": "parse",
        "reason": "conditional", "property_count": 1, "candidate_count": 0,
        "unwind_limits_attempted": [8], "assumptions": ["caller preconditions not established"],
        "gaps": [], "properties": [], "omitted_properties": 0,
    }

    class RetrievalBoundary:
        def find(self, **kwargs):
            if kwargs.get("identity") == identity:
                return {"results": [{"identity": identity, "kind": "review_signal", "payload": payload}]}
            return core.find(**kwargs)

        def __getattr__(self, name):
            return getattr(core, name)

    view = build_view(package, RetrievalBoundary(), ViewLimits(48 * 1024, 160, 6))
    row = next(item for item in view.document["other_context"] if item.get("role") == "bounded_analysis")
    assert row["bounded_analysis"]["judgment"] == "bounded_pass"
    assert row["bounded_analysis"]["assumptions"] == ["caller preconditions not established"]
    assert identity in view.labels.values()


def test_real_executor_keeps_isolation_and_reuses_goto_read_only(tmp_path, monkeypatch):
    from appsec_review.container_runtime.executor import ContainerExecutor, CommandOutcome
    from appsec_review.jobs.job_cbmc_analysis import analysis as module
    scope, _, unit = fixture(tmp_path)
    unit.job.repository_root = Path(__file__).resolve().parents[3]
    binary = unit.job.run_root / "compiled.goto"
    binary.write_bytes(b"fixture goto")
    calls = []

    def docker_boundary(argv, timeout):
        if argv[:3] == ("docker", "image", "inspect"):
            return CommandOutcome(0, IMAGE.encode(), b"")
        assert list(argv[:2]) == ["docker", "run"]
        calls.append((list(argv), timeout))
        return CommandOutcome(0, b"[]", b"")

    class SignatureBoundary:
        def verify(self, image_id, *, reference):
            assert image_id == IMAGE

    monkeypatch.setattr(module, "ContainerExecutor", lambda catalog, root: ContainerExecutor(
        catalog, root, runner=docker_boundary, image_verifier=SignatureBoundary()))
    engine = Analysis(unit, settings())
    engine.execute(scope.case_root, ("/usr/bin/goto-instrument", "--show-goto-functions", "--json-ui",
                                    "/inputs/unit.goto"), goto=run_artifact(unit.job.run_root, binary))
    [(argv, timeout)] = calls
    assert argv[argv.index("--network") + 1] == "none" and "--read-only" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--entrypoint") + 1] == "/usr/bin/timeout"
    assert timeout <= settings().command_timeout_seconds
    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]
    assert any("dst=/inputs/unit.goto,readonly" in mount for mount in mounts)
    assert [mount for mount in mounts if not mount.endswith(",readonly")] == [
        mount for mount in mounts if "dst=/scratch" in mount]


def runtime_fixture(tmp_path, *, responses=None, planning_gap=False, no_work=False, discovery_response=None,
                    clang_findings=None):
    """Publish inert upstream evidence through the real runner; fake only the CBMC container."""
    from appsec_review.config import load_config
    from appsec_review.jobs.job_cbmc_analysis.job import build_job
    from appsec_review.jobs.job_cpp_compiled_analysis.datasets import DATASETS as CPP_DATASETS
    from appsec_review.jobs.job_evidence_collection.datasets import DATASETS as SAST_DATASETS
    from appsec_review.jobs.job_clang_static_analysis.datasets import DATASETS as CLANG_DATASETS
    from appsec_review.retrieval import (
        EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
    )
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.storage import atomic_json
    from tests.capture_fakes import build_capture_toml
    from tests.host_pins_support import write_host_pins
    from tests.release_support import write_release

    scope, _, _ = fixture(tmp_path)
    write_release(tmp_path, ("job_cpp_compiled_analysis", "job_evidence_collection", "job_cbmc_analysis",
                            "job_clang_static_analysis"))
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(
        '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n'
        + build_capture_toml()
        + '\n[review_policy.releases]\nplatform = "fixture-1"\nvalidation = "fixture-1"\n'
        '[jobs.job_cpp_compiled_analysis]\nname = "fixture_cpp"\n'
        '[jobs.job_cpp_compiled_analysis.settings]\nlane = "cpp"\n'
        '[jobs.job_cpp_compiled_analysis.steps.prepare]\n'
        '[jobs.job_evidence_collection]\nname = "fixture_sast"\n'
        '[jobs.job_clang_static_analysis]\nname = "fixture_clang"\n'
        '[jobs.job_clang_static_analysis.steps.analyze]\n'
        '[jobs.job_clang_static_analysis.steps.acceptance]\n'
        '[jobs.job_cbmc_analysis]\nname = "cbmc_analysis"\n'
        f'[jobs.job_cbmc_analysis.settings]\nenabled = true\ntag = "{settings().tag}"\n'
        '[jobs.job_cbmc_analysis.steps.load.tasks.accepted_inputs]\n'
        '[jobs.job_cbmc_analysis.steps.analyze.tasks.bounded_checks]\n'
        '[jobs.job_cbmc_analysis.steps.acceptance.tasks.publish_handoff]\n')
    pins = write_host_pins(tmp_path / "host-pins.toml", images={settings().tag: IMAGE})
    config = load_config(config_path, host_pins=pins)
    runner = JobRunner(config)

    def cpp_catalog(unit):
        root = unit.job.run_root
        case = root / "data/cpp/projects/case"
        source = case / "source/main.c"
        source.parent.mkdir(parents=True)
        source.write_bytes((scope.case_root / "source/main.c").read_bytes())
        commands = [{"target_path": "native/main.c", "directory": "/scratch/source",
                     "arguments": ["clang", "-c", "/scratch/source/main.c", "-o", "old.o"]}]
        database = case / "compile_commands.json"
        atomic_json(database, commands)
        catalog = {"terminal_status": "SUCCEEDED", "compile_commands": commands,
                   "compile_database": run_artifact(root, database),
                   "mapping": {"project_id": "native", "root": "native", "case_snapshot": "f" * 64,
                               "files": [dict(scope.files[0])]}}
        projects = {} if no_work else {"case": catalog}
        if planning_gap:
            projects["unavailable"] = {"terminal_status": "FAILED", "gaps": ["fixture build unavailable"]}
        return {"projects": projects, "artifacts": [run_artifact(root, source), run_artifact(root, database)]}

    def cpp_publish(unit):
        root = unit.job.run_root
        summary = unit.unit_root / "summary.json"
        atomic_json(summary, {"schema": "appsec-review/cpp-compiled-analysis/2"})
        manifest = root / "data/indices/manifests/cpp.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot="f" * 64,
                       target_root=scope.case_root, indexes=[])
        return {"artifact": run_artifact(root, summary), "index_manifest": run_artifact(root, manifest)}

    cpp = Job("job_cpp_compiled_analysis", "fixture_cpp", lambda _: {},
              units=(Unit("catalog.projects", cpp_catalog),
                     Unit("acceptance.publish_handoff", cpp_publish, ("catalog.projects",))),
              datasets=tuple(d for d in CPP_DATASETS if d.output_kind in {
                  "cpp_plan_and_summary", "cpp_case_material"}))
    accepted_cpp = runner.run(cpp, target_root=scope.case_root, source_fingerprint="f" * 64)
    run_id = accepted_cpp["status"]["run_id"]

    def sast_publish(unit):
        root = unit.job.run_root
        shard = root / "data/indices/observations/seeds.sqlite"
        builder = IndexBuilder(shard, name="observations", fingerprint="a" * 64,
                               target_snapshot="f" * 64, shard_id="seeds")
        if not no_work and clang_findings is None:
            location = SourceLocation("f" * 64, "native/main.c", scope.files[0]["sha256"],
                                      0, 20, 2, 2, 1, 1, producer_location={},
                                      mapping_method="fixture", confidence=1.0)
            builder.add_entity(EntityRecord(
                LogicalIdentity.parse(SEED["observation_ids"][0]), "seed", "pointer", "pointer finding",
                {"tool_id": "tool-cppcheck", "category": "source_sast", "native_rule_id": "nullPointer",
                 "native_severity": "high"}, location))
        digest = builder.build()
        index = IndexIdentity("observations", "appsec-review/retrieval-index/2", digest, "a" * 64,
                              shard.relative_to(root).as_posix(),
                              {"job": "job_evidence_collection"}, (), "seeds")
        manifest = root / "data/indices/manifests/sast.json"
        write_manifest(manifest, run_id=run_id, target_snapshot="f" * 64,
                       target_root=scope.case_root, indexes=[index])
        return {"index_manifest": run_artifact(root, manifest)}

    sast = Job("job_evidence_collection", "fixture_sast", lambda _: {},
               units=(Unit("evidence_publication.publish", sast_publish),),
               datasets=tuple(d for d in SAST_DATASETS if d.output_kind == "static_tool_observations"))
    accepted_sast = runner.run(sast, run_id=run_id, target_root=scope.case_root, source_fingerprint="f" * 64)
    run_root = config.runtime.runs_dir / run_id
    executor = FakeExecutor(run_root, responses, discovery_response=discovery_response)
    job = build_job(executor_factory=lambda *_: executor)
    upstream = {"job_cpp_compiled_analysis": accepted_cpp["handoff_sha256"],
                "job_evidence_collection": accepted_sast["handoff_sha256"]}
    if clang_findings is not None:
        def clang_publish(unit):
            indexes = []
            for label in ("findings", "coverage"):
                shard_id = "clang-static-" + ("coverage-" if label == "coverage" else "") + "fixture"
                path = unit.job.run_root / "data/indices/observations" / (shard_id + ".sqlite")
                builder = IndexBuilder(path, name="observations", fingerprint="b" * 64,
                                       target_snapshot="f" * 64, shard_id=shard_id)
                if label == "findings" and clang_findings:
                    location = SourceLocation("f" * 64, "native/main.c", scope.files[0]["sha256"],
                                              0, 20, 2, 2, 1, 1, producer_location={},
                                              mapping_method="fixture", confidence=1.0)
                    builder.add_entity(EntityRecord(
                        LogicalIdentity.parse(SEED["observation_ids"][0]), "clang-seed", "pointer",
                        "Clang pointer finding", {"tool_id": "tool-clang-static-analysis",
                        "category": "source_sast", "native_rule_id": "core.NullDereference",
                        "native_severity": "high"}, location))
                if label == "coverage":
                    builder.add_coverage("clang", "complete", "fixture coverage")
                digest = builder.build()
                indexes.append(IndexIdentity("observations", "appsec-review/retrieval-index/2",
                                             digest, "b" * 64, path.relative_to(unit.job.run_root).as_posix(),
                                             {"job": "job_clang_static_analysis"}, (), shard_id))
            manifest = unit.job.run_root / "data/indices/manifests/clang.json"
            write_manifest(manifest, run_id=run_id, target_snapshot="f" * 64,
                           target_root=scope.case_root, indexes=indexes)
            return {"index_manifest": run_artifact(unit.job.run_root, manifest)}

        clang = Job("job_clang_static_analysis", "fixture_clang", lambda _: {},
                    units=(Unit("acceptance.publish_handoff", clang_publish),),
                    datasets=tuple(d for d in CLANG_DATASETS if d.output_kind in {
                        "clang_static_observations", "clang_static_scope_coverage"}))
        published_clang = runner.run(clang, run_id=run_id, target_root=scope.case_root,
                                     source_fingerprint="f" * 64)
        upstream["job_clang_static_analysis"] = published_clang["handoff_sha256"]
    claim = runner.begin_attempt(job, run_id=run_id, upstream_handoffs=upstream)
    return SimpleNamespace(runner=runner, job=job, claim=claim, executor=executor,
                           root=run_root, upstream=upstream, config=config)


def run_units(harness):
    for unit in harness.job.units:
        harness.runner.execute_or_reuse_unit(harness.job, harness.claim, unit.unit_id)


@pytest.mark.parametrize("findings", [True, False], ids=["findings-and-coverage", "empty-findings-and-coverage"])
def test_clang_seed_selection_excludes_coverage_under_real_contract(tmp_path, findings):
    from appsec_review.runtime.inputs import read_input_observations

    harness = runtime_fixture(tmp_path, clang_findings=findings)
    run_units(harness)
    accepted = harness.runner.finalize_attempt(harness.job, harness.claim)
    assert accepted["handoff"]["status"] == "ACCEPTED"
    plan_ref = accepted["result"]["outputs"]["load.accepted_inputs"]["artifact"]
    selected = json.loads((harness.root / plan_ref["path"]).read_bytes())
    assert len(selected["work"]) == int(findings)
    if findings:
        assert selected["work"][0]["seeds"][0]["observation_ids"] == SEED["observation_ids"]
    reads = read_input_observations(harness.root, accepted["handoff"])
    assert reads is not None
    clang_reads = [row for row in reads["reads"] if row["producer"] == "job_clang_static_analysis"]
    assert {row["output_kind"] for row in clang_reads} == {"handoff", "clang_static_observations"}
    assert all(row["cited"] is None for row in clang_reads)


@pytest.mark.parametrize("planning_gap,execution_gap", [(True, False), (False, True), (True, True)],
                         ids=["selection-only", "execution-only", "both"])
def test_runtime_accepts_canonical_planning_and_execution_gaps(tmp_path, planning_gap, execution_gap):
    harness = runtime_fixture(tmp_path, planning_gap=planning_gap, no_work=not execution_gap,
                              responses=[(124, [])])
    run_units(harness)
    accepted = harness.runner.finalize_attempt(harness.job, harness.claim)
    assert accepted["handoff"]["status"] == "ACCEPTED"
    assert accepted["handoff"]["completion_status"] == "COMPLETED_WITH_GAPS"
    outputs = accepted["result"]["outputs"]
    planning = outputs["load.accepted_inputs"]["gaps"]
    executed = outputs["analyze.bounded_checks"]["gaps"]
    published = outputs["acceptance.publish_handoff"]["gaps"]
    assert len(planning) == int(planning_gap)
    assert len(executed) == int(planning_gap) + int(execution_gap)
    assert all(gap in executed for gap in planning) and executed == published
    assert all(gap["unit_id"] is None for gap in published)
    outcomes = json.loads((Path(accepted["attempt_root"]) / "outcomes.json").read_bytes())
    assert {gap["gap_id"] for gap in outcomes["gaps"]} == {gap["gap_id"] for gap in published}


@pytest.mark.parametrize("failure", ["timeout", "malformed"], ids=["timeout", "malformed"])
def test_failed_unwind_retry_preserves_round_provenance(tmp_path, failure):
    from appsec_review.indexing.store import ShardSet
    from appsec_review.provenance import verify_native_reference
    from appsec_review.retrieval.index import load_verified_manifest

    retry = (124, []) if failure == "timeout" else (0, b'[{"result":')
    harness = runtime_fixture(tmp_path, responses=[
        (10, outcome("FAILURE", name="f.unwind.0", trace=True)), retry])
    run_units(harness)
    analysis_path = harness.root / harness.claim["attempt_path"] / "artifacts/cbmc/analysis.json"
    analysis = json.loads(analysis_path.read_bytes())
    result = analysis["results"][0]
    assert result["unwind_limits_attempted"] == [8, 32]
    assert result["judgment"] == "inconclusive" and result["candidate_count"] == 0
    assert result["rounds"][0]["status"] == "validated"
    assert result["rounds"][1]["status"] == "failed"
    assert result["native_execution"] == result["executions"][-2]["receipt"]
    assert result["rounds"][0]["execution"] == result["native_execution"]
    assert result["rounds"][1]["execution"] == result["executions"][-1]["receipt"]
    assert result["rounds"][1]["output"] == result["executions"][-1]["stdout"]
    assert result["rounds"][1]["gaps"]
    assert "unwinding_incomplete" in result["gaps"]
    accepted = harness.runner.finalize_attempt(harness.job, harness.claim)
    output = accepted["result"]["outputs"]["acceptance.publish_handoff"]
    manifest, _ = load_verified_manifest(harness.root, harness.root / output["index_manifest"]["path"],
                                         output["index_manifest"]["sha256"])
    shards = [s for s in manifest["indexes"] if s["shard_id"].startswith("cbmc-results-")]
    store = ShardSet(harness.root, shards)
    [row] = store.entities(shards, kinds=("review_signal",))
    [native] = row["payload"]["common"]["evidence_refs"]
    assert native["execution_reference"] == result["native_execution"]
    assert verify_native_reference(harness.root, native, resolve=True) == outcome(
        "FAILURE", name="f.unwind.0", trace=True)


RAW_PATHS = (
    "00001/unit.goto", "00001/stdout.bin", "00001/stderr.bin", "00001/execution.json",
    "00002/stdout.bin", "00002/stderr.bin", "00002/execution.json",
    "00003/stdout.bin", "00003/stderr.bin", "00003/execution.json", "source",
)


@pytest.mark.parametrize("raw_path", RAW_PATHS, ids=[
    "goto", "compiler-stdout", "compiler-stderr", "compiler-receipt",
    "discovery-json", "discovery-stderr", "discovery-receipt",
    "native-json", "cbmc-stderr", "cbmc-receipt", "source-copy",
])
@pytest.mark.parametrize("damage", ["delete", "change"], ids=["delete", "change"])
@pytest.mark.parametrize("phase", ["acceptance", "reuse"], ids=["acceptance", "reuse"])
def test_runtime_rejects_damaged_raw_closure(tmp_path, raw_path, damage, phase):
    from appsec_review.runtime.resume import ResumePlanner

    harness = runtime_fixture(tmp_path)
    run_units(harness)
    accepted = None
    if phase == "reuse":
        accepted = harness.runner.finalize_attempt(harness.job, harness.claim)
        reasons, _ = ResumePlanner(harness.config, harness.root, [harness.job], "none")._accepted(
            harness.job, harness.upstream)
        assert not reasons
    analysis_path = harness.root / harness.claim["attempt_path"] / "artifacts/cbmc/analysis.json"
    analysis_bytes = analysis_path.read_bytes()
    analysis = json.loads(analysis_bytes)
    raw = (harness.root / analysis["source_artifacts"][0]["path"] if raw_path == "source" else
           analysis_path.parent / "executions" / raw_path)
    original = raw.read_bytes()
    changed = bytes(byte ^ 1 for byte in original) if original else b"changed"
    if damage == "delete":
        raw.unlink()
    else:
        raw.chmod(0o644)
        raw.write_bytes(changed)
    if phase == "acceptance":
        with pytest.raises(ValueError):
            harness.runner.finalize_attempt(harness.job, harness.claim)
        assert not (harness.root / "data/jobs/job_cbmc_analysis/latest.json").exists()
    else:
        before = (harness.root / "data/jobs/job_cbmc_analysis/latest.json").read_bytes()
        reasons, _ = ResumePlanner(harness.config, harness.root, [harness.job], "none")._accepted(
            harness.job, harness.upstream)
        assert reasons and any("artifact" in reason or "integrity" in reason for reason in reasons)
        assert (harness.root / "data/jobs/job_cbmc_analysis/latest.json").read_bytes() == before
        assert (Path(accepted["attempt_root"]) / "handoff.json").is_file()
    assert analysis_path.read_bytes() == analysis_bytes
    assert raw.read_bytes() == changed if damage == "change" else not raw.exists()
    assert len(harness.executor.requests) == 3


@pytest.mark.parametrize("completed_calls", [2, 3], ids=["before-first-bound", "before-retry"])
def test_unlaunched_bound_is_distinct_from_failed_round(tmp_path, completed_calls):
    scope, row, unit = fixture(tmp_path)
    executor = FakeExecutor(unit.job.run_root, [(10, outcome("FAILURE", name="f.unwind.0", trace=True))])
    engine = Analysis(unit, settings(), executor_factory=lambda *_: executor,
                      clock=lambda: 301 if len(executor.requests) >= completed_calls else 0)
    [result] = engine.translation_unit(scope, row, [SEED], scope.case_root)
    assert len(executor.requests) == completed_calls
    assert result["judgment"] == "inconclusive" and result["candidate_count"] == 0
    unlaunched = result["rounds"][-1]
    assert unlaunched["status"] == "not_attempted" and unlaunched["gaps"] == ["BudgetExhausted"]
    assert "execution" not in unlaunched and "output" not in unlaunched
    if completed_calls == 3:
        assert result["unwind_limits_attempted"] == [8] and unlaunched["unwind"] == 32
        assert result["native_execution"] == result["rounds"][0]["execution"]
        assert result["native_output"] == result["rounds"][0]["output"]
        assert result["gaps"] == ["unwinding_incomplete", "BudgetExhausted"]
    else:
        assert result["unwind_limits_attempted"] == [] and unlaunched["unwind"] == 8
        assert result["property_count"] == 0
        assert "native_output" not in result and "native_execution" not in result


def test_discovery_failure_retains_goto_and_execution_artifacts(tmp_path):
    from appsec_review.runtime.resume import ResumePlanner

    harness = runtime_fixture(tmp_path, discovery_response=(124, []))
    run_units(harness)
    accepted = harness.runner.finalize_attempt(harness.job, harness.claim)
    assert accepted["handoff"]["completion_status"] == "COMPLETED_WITH_GAPS"
    analysis_ref = accepted["result"]["outputs"]["analyze.bounded_checks"]["artifact"]
    analysis = json.loads((harness.root / analysis_ref["path"]).read_bytes())
    assert len(analysis["executions"]) == 2 and analysis["results"][0]["property_count"] == 0
    artifacts = {ref["path"]: ref for ref in accepted["handoff"]["artifacts"]}
    goto = analysis["executions"][0]["goto"]
    assert artifacts[goto["path"]] == goto
    for execution in analysis["executions"]:
        for kind in ("stdout", "stderr", "receipt"):
            assert artifacts[execution[kind]["path"]] == execution[kind]
    (harness.root / goto["path"]).unlink()
    reasons, _ = ResumePlanner(harness.config, harness.root, [harness.job], "none")._accepted(
        harness.job, harness.upstream)
    assert reasons and any("artifact" in reason or "integrity" in reason for reason in reasons)
    assert len(harness.executor.requests) == 2


@pytest.mark.parametrize("source,args", [
    ("/target/source/session.cpp", ["clang++", "-std=gnu++17", "-c", "/target/source/session.cpp"]),
    ("/target/source/request.cpp", ["clang++", "-std=c++17", "-c", "/target/source/request.cpp"]),
    ("/target/source/synthetic.cc", ["clang++", "-std=c++11", "-c", "/target/source/synthetic.cc"]),
    ("/target/source/modern.cxx", ["clang++", "-std=c++20", "-c", "/target/source/modern.cxx"]),
    ("/target/source/unflagged.cpp", ["clang++", "-c", "/target/source/unflagged.cpp"]),
    ("/target/source/c_flag.cpp", ["clang++", "-std=c11", "-c", "/target/source/c_flag.cpp"]),
    ("/target/source/cpp_flag.c", ["clang", "-std=c++98", "-c", "/target/source/cpp_flag.c"]),
])
def test_compile_admission_rejects_modern_or_unflagged_cpp_standards(source, args):
    with pytest.raises(CompileRejected):
        compile_argv({"file": source, "arguments": args})


@pytest.mark.parametrize("flag", ["-std=c++98", "-std=c++03", "-std=gnu++98", "-std=gnu++03"])
def test_compile_admission_allows_explicit_legacy_cpp98(flag):
    argv, _ = compile_argv({"file": "/target/source/legacy.cpp",
                            "arguments": ["clang++", flag, "-c", "/target/source/legacy.cpp", "-o", "legacy.o"]})
    assert argv == ("/usr/bin/goto-cc", "-c", flag, "/target/source/legacy.cpp", "-o", "/scratch/unit.goto")


def test_compact_goto_functions_parses_large_multi_function_table_without_json_truncation(tmp_path):
    sep = "^" * 44
    blocks = [
        "Reading GOTO program from '/inputs/unit.goto'",
        sep, "", "__CPROVER__start /* __CPROVER__start */",
        "        // 0 no location",
        "        // Labels: __CPROVER_HIDE",
        "        CALL __CPROVER_initialize()",
        "        END_FUNCTION",
    ]
    for fn_idx in range(120):
        fn_name = f"helper_{fn_idx:03d}"
        start_line = 10 + fn_idx * 10
        blocks.extend([sep, "", f"{fn_name} /* {fn_name} */"])
        blocks.append("        // 0 file /usr/include/stdlib.h line 42")
        blocks.append("        SKIP")
        for step in range(1, 200):
            line_no = start_line + (step % 8)
            blocks.append(f"        // {step} file /target/source/main.c line {line_no} column 5 function {fn_name}")
            blocks.append("        // Labels: L_BODY")
            blocks.append(f"        x = {step};")
        blocks.append(f"        // 200 file /target/source/main.c line {start_line + 8} function {fn_name}")
        blocks.append("        END_FUNCTION")
    compact_bytes = ("\n".join(blocks) + "\n").encode("utf-8")
    assert len(compact_bytes) < settings().max_output_bytes

    scope, row, unit = fixture(tmp_path)
    (scope.case_root / "source/main.c").write_text("\n".join(f"int line_{i};" for i in range(1, 1300)) + "\n")
    accepted = {"target_path": "native/main.c", "scratch_path": "source/main.c",
                "sha256": file_sha256(scope.case_root / "source/main.c")}
    scope = replace(scope, files=(accepted,))
    target = tmp_path / "staged"
    stage_source(scope, target, settings())
    seed = {"path": "main.c", "start_line": 514, "end_line": 514, "rank": 0,
            "observation_ids": SEED["observation_ids"]}
    executor = FakeExecutor(
        unit.job.run_root,
        [(0, [{"result": [{"property": "helper_050.bounds.1", "description": "array bounds",
                           "status": "SUCCESS", "sourceLocation": {"file": "/target/source/main.c", "line": "514"}}]},
              {"cProverStatus": "success"}])],
        discovery_response=(0, compact_bytes),
    )
    engine = Analysis(unit, settings(unwind_limits=(8,)), executor_factory=lambda *_: executor)
    results = engine.translation_unit(scope, row, [seed], target)
    assert len(results) == 1
    assert results[0]["function"] == "helper_050"
    assert results[0]["judgment"] == "bounded_pass"
    assert executor.requests[1].argv[4:] == (
        "/usr/bin/goto-instrument", "--show-goto-functions", "/inputs/unit.goto"
    )
    assert "--json-ui" not in executor.requests[1].argv
    assert "--drop-unused-functions" in executor.requests[2].argv
    assert "--object-bits" in executor.requests[2].argv

    with pytest.raises(OutputRejected, match="missing program header"):
        goto_functions_output(b"not goto-instrument output\n", 4096, max_instructions=100)
    with pytest.raises(OutputRejected, match="incomplete GOTO function body"):
        goto_functions_output(
            f"Reading GOTO program from '/inputs/unit.goto'\n{sep}\n\nf /* f */\n        // 0 no location\n".encode(),
            4096, max_instructions=100,
        )
    with pytest.raises(OutputRejected, match="instruction bound"):
        goto_functions_output(compact_bytes, settings().max_output_bytes, max_instructions=100)


def test_compact_goto_functions_accepts_labeled_end_function_epilogues(tmp_path):
    sep = "^" * 44
    compact = "\n".join([
        "Reading GOTO program from '/inputs/unit.goto'",
        sep, "", "frame_fill /* frame_fill */",
        "        // 0 file /target/source/main.c line 10 function frame_fill",
        "     1: IF !(n == 0) THEN GOTO 2",
        "        // 1 file /target/source/main.c line 11 function frame_fill",
        "        GOTO 2",
        "        // 2 file /target/source/main.c line 14 function frame_fill",
        "     2: END_FUNCTION",
        sep, "", "multi_digit /* multi_digit */",
        "        // 0 file /target/source/main.c line 20 function multi_digit",
        "    89: END_FUNCTION",
        sep, "", "six_digit /* six_digit */",
        "        // 0 file /target/source/main.c line 30 function six_digit",
        "100000: END_FUNCTION",
        sep, "", "multi_label /* multi_label */",
        "        // 0 file /target/source/main.c line 40 function multi_label",
        "     1: 2: END_FUNCTION",
        "",
    ]).encode("utf-8")
    parsed = goto_functions_output(compact, 4096, max_instructions=100)
    by_name = {fn["name"]: fn for fn in parsed[0]["functions"]}
    assert list(by_name) == ["frame_fill", "multi_digit", "six_digit", "multi_label"]
    assert by_name["frame_fill"]["sourceSpans"] == {"main.c": [10, 14]}
    assert by_name["frame_fill"]["instructionCount"] == 3

    with pytest.raises(OutputRejected, match="incomplete GOTO function body"):
        goto_functions_output(
            f"Reading GOTO program from '/inputs/unit.goto'\n{sep}\n\nf /* f */\nEND_FUNCTION\n".encode("utf-8"),
            4096,
            max_instructions=100,
        )
    with pytest.raises(OutputRejected, match="incomplete GOTO function body"):
        goto_functions_output(
            f"Reading GOTO program from '/inputs/unit.goto'\n{sep}\n\nf /* f */\n     label: END_FUNCTION\n".encode("utf-8"),
            4096,
            max_instructions=100,
        )

    scope, row, unit = fixture(tmp_path)
    (scope.case_root / "source/main.c").write_text("\n".join(f"int line_{i};" for i in range(1, 50)) + "\n")
    accepted = {"target_path": "native/main.c", "scratch_path": "source/main.c",
                "sha256": file_sha256(scope.case_root / "source/main.c")}
    scope = replace(scope, files=(accepted,))
    target = tmp_path / "staged"
    stage_source(scope, target, settings())
    seed = {"path": "main.c", "start_line": 11, "end_line": 11, "rank": 0,
            "observation_ids": SEED["observation_ids"]}
    executor = FakeExecutor(
        unit.job.run_root,
        [(0, [{"result": [{"property": "frame_fill.pointer_dereference.1", "description": "dereference failure",
                           "status": "SUCCESS", "sourceLocation": {"file": "/target/source/main.c", "line": "11"}}]},
              {"cProverStatus": "success"}])],
        discovery_response=(0, compact),
    )
    engine = Analysis(unit, settings(unwind_limits=(8,)), executor_factory=lambda *_: executor)
    results = engine.translation_unit(scope, row, [seed], target)
    assert len(results) == 1
    assert results[0]["function"] == "frame_fill"
    assert results[0]["judgment"] == "bounded_pass"


def test_plan_rejects_cpp17_units_without_starving_c_units_or_seeds(tmp_path):
    from appsec_review.config import load_config
    from appsec_review.indexing.store import ShardSet
    from appsec_review.jobs.job_cbmc_analysis.job import build_job
    from appsec_review.jobs.job_cpp_compiled_analysis.datasets import DATASETS as CPP_DATASETS
    from appsec_review.jobs.job_evidence_collection.datasets import DATASETS as SAST_DATASETS
    from appsec_review.retrieval import (
        EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
    )
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.storage import atomic_json
    from tests.capture_fakes import build_capture_toml
    from tests.host_pins_support import write_host_pins
    from tests.release_support import write_release

    write_release(tmp_path, ("job_cpp_compiled_analysis", "job_evidence_collection", "job_cbmc_analysis"))
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(
        '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n'
        + build_capture_toml()
        + '\n[review_policy.releases]\nplatform = "fixture-1"\nvalidation = "fixture-1"\n'
        '[jobs.job_cpp_compiled_analysis]\nname = "fixture_cpp"\n'
        '[jobs.job_cpp_compiled_analysis.settings]\nlane = "cpp"\n'
        '[jobs.job_cpp_compiled_analysis.steps.prepare]\n'
        '[jobs.job_evidence_collection]\nname = "fixture_sast"\n'
        '[jobs.job_cbmc_analysis]\nname = "cbmc_analysis"\n'
        f'[jobs.job_cbmc_analysis.settings]\nenabled = true\ntag = "{settings().tag}"\n'
        'max_translation_units = 5\nmax_seeds_per_scope = 6\nunwind_limits = [4]\n'
        '[jobs.job_cbmc_analysis.steps.load.tasks.accepted_inputs]\n'
        '[jobs.job_cbmc_analysis.steps.analyze.tasks.bounded_checks]\n'
        '[jobs.job_cbmc_analysis.steps.acceptance.tasks.publish_handoff]\n'
    )
    pins = write_host_pins(tmp_path / "host-pins.toml", images={settings().tag: IMAGE})
    config = load_config(config_path, host_pins=pins)
    runner = JobRunner(config)

    cpp_rels = ["src/session.cpp", "src/request.cpp", "src/main.cpp", "src/synthetic.cpp"]
    c_rels = ["src/util.c", "third_party/bzlib.c", "third_party/compress.c",
              "third_party/cJSON.c", "third_party/lz4frame.c"]
    hdr_rel = "src/cpp_only.hpp"
    file_hashes: dict[str, str] = {}
    target_dir = tmp_path / "target"
    target_dir.mkdir()

    def cpp_catalog(unit):
        root = unit.job.run_root
        case = root / "data/cpp/projects/case"
        files = []
        commands = []
        artifacts = []
        hdr = case / "source" / hdr_rel
        hdr.parent.mkdir(parents=True, exist_ok=True)
        hdr.write_text("inline int only_cpp(int x) { return x + 1; }\n")
        file_hashes[hdr_rel] = file_sha256(hdr)
        files.append({"target_path": f"native/{hdr_rel}", "scratch_path": f"source/{hdr_rel}",
                      "sha256": file_hashes[hdr_rel]})
        artifacts.append(run_artifact(root, hdr))

        for rel in cpp_rels:
            src = case / "source" / rel
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text('#include "cpp_only.hpp"\nint bad_cpp(int *p) {\n  return *p;\n}\n')
            file_hashes[rel] = file_sha256(src)
            files.append({"target_path": f"native/{rel}", "scratch_path": f"source/{rel}",
                          "sha256": file_hashes[rel]})
            artifacts.append(run_artifact(root, src))
            commands.append({
                "target_path": f"native/{rel}",
                "directory": "/scratch/source",
                "arguments": ["clang++", "-std=gnu++17", "-I/scratch/source/src", "-c",
                              f"/scratch/source/{rel}", "-o", f"{rel}.o"],
            })
        for rel in c_rels:
            src = case / "source" / rel
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text("int ok_c(int *p) {\n  return *p;\n}\n")
            file_hashes[rel] = file_sha256(src)
            files.append({"target_path": f"native/{rel}", "scratch_path": f"source/{rel}",
                          "sha256": file_hashes[rel]})
            artifacts.append(run_artifact(root, src))
            commands.append({
                "target_path": f"native/{rel}",
                "directory": "/scratch/source",
                "arguments": ["clang", "-std=gnu11", "-c", f"/scratch/source/{rel}", "-o", f"{rel}.o"],
            })
        database = case / "compile_commands.json"
        atomic_json(database, commands)
        artifacts.append(run_artifact(root, database))
        catalog = {"terminal_status": "SUCCEEDED", "compile_commands": commands,
                   "compile_database": run_artifact(root, database),
                   "mapping": {"project_id": "native", "root": "native", "case_snapshot": "f" * 64, "files": files}}
        return {"projects": {"case": catalog}, "artifacts": artifacts}

    def cpp_publish(unit):
        root = unit.job.run_root
        summary = unit.unit_root / "summary.json"
        atomic_json(summary, {"schema": "appsec-review/cpp-compiled-analysis/2"})
        manifest = root / "data/indices/manifests/cpp.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot="f" * 64,
                       target_root=target_dir, indexes=[])
        return {"artifact": run_artifact(root, summary), "index_manifest": run_artifact(root, manifest)}

    cpp = Job("job_cpp_compiled_analysis", "fixture_cpp", lambda _: {},
              units=(Unit("catalog.projects", cpp_catalog),
                     Unit("acceptance.publish_handoff", cpp_publish, ("catalog.projects",))),
              datasets=tuple(d for d in CPP_DATASETS if d.output_kind in {
                  "cpp_plan_and_summary", "cpp_case_material"}))
    accepted_cpp = runner.run(cpp, target_root=target_dir, source_fingerprint="f" * 64)
    run_id = accepted_cpp["status"]["run_id"]

    def sast_publish(unit):
        root = unit.job.run_root
        shard = root / "data/indices/observations/seeds.sqlite"
        builder = IndexBuilder(shard, name="observations", fingerprint="a" * 64,
                               target_snapshot="f" * 64, shard_id="seeds")
        seeded = (
            [(rel, "critical", 2) for rel in cpp_rels]
            + [(hdr_rel, "high", 1)]
            + [(rel, "medium", 2) for rel in c_rels]
        )
        for idx, (rel, sev, line) in enumerate(seeded):
            obs_id = f"asr:tool_observation:{idx:064x}"
            loc = SourceLocation("f" * 64, f"native/{rel}", file_hashes[rel],
                                 0, 10, line, line, 1, 1, producer_location={},
                                 mapping_method="fixture", confidence=1.0)
            builder.add_entity(EntityRecord(
                LogicalIdentity.parse(obs_id), f"seed-{idx}", "ptr", "finding",
                {"tool_id": "tool-cppcheck", "category": "source_sast",
                 "native_rule_id": "nullPointer", "native_severity": sev}, loc))
        digest = builder.build()
        index = IndexIdentity("observations", "appsec-review/retrieval-index/2", digest, "a" * 64,
                              shard.relative_to(root).as_posix(), {"job": "job_evidence_collection"}, (), "seeds")
        manifest = root / "data/indices/manifests/sast.json"
        write_manifest(manifest, run_id=run_id, target_snapshot="f" * 64,
                       target_root=target_dir, indexes=[index])
        return {"index_manifest": run_artifact(root, manifest)}

    sast = Job("job_evidence_collection", "fixture_sast", lambda _: {},
               units=(Unit("evidence_publication.publish", sast_publish),),
               datasets=tuple(d for d in SAST_DATASETS if d.output_kind == "static_tool_observations"))
    accepted_sast = runner.run(sast, run_id=run_id, target_root=target_dir, source_fingerprint="f" * 64)
    run_root = config.runtime.runs_dir / run_id

    class MultiCExecutor(FakeExecutor):
        def execute(self, request):
            self.requests.append(request)
            command = request.argv[4]
            if command == "/usr/bin/goto-cc":
                source_arg = request.argv[-3]
                assert source_arg.endswith(".c"), f"unexpected non-C compile: {source_arg}"
                self._last_source = source_arg
                (request.scratch_root / "unit.goto").write_bytes(b"fixture goto")
                code, data = 0, b""
            elif command == "/usr/bin/goto-instrument":
                code, data = 0, goto_functions_text(("ok_c",), file=self._last_source, lines=(1, 3))
            else:
                code, data = 0, [
                    {"result": [{"property": "ok_c.pointer_dereference.1", "description": "pointer check",
                                 "status": "SUCCESS",
                                 "sourceLocation": {"file": self._last_source, "line": "2"}}]},
                    {"cProverStatus": "success"},
                ]
            stdout, stderr, receipt = [request.scratch_root / n for n in ("stdout.bin", "stderr.bin", "execution.json")]
            stdout.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
            stderr.write_text("")
            receipt.write_text(json.dumps({"argv": list(request.argv), "exit_code": code}))
            rel = lambda p: p.relative_to(self.run).as_posix()
            return ExecutionResult("appsec-review/container-execution/1", "tool-cbmc", "fixture", IMAGE,
                                   IMAGE, "argv", (), {}, "start", "end", code, False, False, False, False,
                                   rel(stdout), rel(stderr), rel(receipt))

    executor = MultiCExecutor(run_root)
    job = build_job(executor_factory=lambda *_: executor)
    upstream = {"job_cpp_compiled_analysis": accepted_cpp["handoff_sha256"],
                "job_evidence_collection": accepted_sast["handoff_sha256"]}
    claim = runner.begin_attempt(job, run_id=run_id, upstream_handoffs=upstream)
    for unit_def in job.units:
        runner.execute_or_reuse_unit(job, claim, unit_def.unit_id)
    accepted = runner.finalize_attempt(job, claim)

    assert accepted["handoff"]["completion_status"] == "COMPLETED_WITH_GAPS"
    summary_ref = accepted["result"]["outputs"]["acceptance.publish_handoff"]["artifact"]
    summary = json.loads((run_root / summary_ref["path"]).read_bytes())
    plan_doc = json.loads((run_root / summary["plan"]["path"]).read_bytes())

    selected_files = [item["row"]["file"] for item in plan_doc["work"]]
    assert sorted(selected_files) == sorted(f"/target/source/{rel}" for rel in c_rels)
    assert plan_doc["omitted"]["translation_units"] == 0
    assert summary["counts"] == {"bounded_pass": 5}

    reasons = [gap["reason"] for gap in summary["gaps"]]
    for rel in cpp_rels:
        assert any(f"CompileRejected ({rel}):" in reason for reason in reasons), reasons
    assert not any("seed_without_translation_unit" in reason for reason in reasons), reasons

    manifest = json.loads((run_root / accepted["result"]["outputs"]["acceptance.publish_handoff"]["index_manifest"]["path"]).read_bytes())
    cov_shards = [s for s in manifest["indexes"] if str(s.get("shard_id", "")).startswith("cbmc-coverage-")]
    cov_rows = list(ShardSet(run_root, cov_shards).coverage(cov_shards))
    assert any("CompileRejected (src/session.cpp)" in (row["gap"] or "") for row in cov_rows)
