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
    CompileRejected, OutputRejected, compile_argv, function_entries, judgment, native_json,
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
    def __init__(self, run, responses=None, *, timed_out=False, wrong_image=False):
        self.run = run
        self.responses = list(responses or [(0, outcome())])
        self.timed_out = timed_out
        self.wrong_image = wrong_image
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        assert request.argv[:3] == ("/usr/bin/timeout", "--signal=TERM", "--kill-after=2s")
        command = request.argv[4]
        if command == "/usr/bin/goto-cc":
            (request.scratch_root / "unit.goto").write_bytes(b"fixture goto")
            code, data = 0, []
        elif command == "/usr/bin/goto-instrument":
            code, data = 0, functions()
        else:
            code, data = self.responses.pop(0)
        stdout, stderr, receipt = [request.scratch_root / name for name in ("stdout.bin", "stderr.bin", "execution.json")]
        stdout.write_text(json.dumps(data))
        stderr.write_text("")
        receipt.write_text("{}")
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
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _: (accepted, [scope], {}))
    monkeypatch.setattr(module, "accepted_upstream", lambda *_args, **_kwargs: supplied)
    return module, scope, row, unit


def test_real_selection_analysis_and_index_publication_are_consumable(tmp_path, monkeypatch):
    from appsec_review.indexing.store import ShardSet
    from appsec_review.retrieval import EntityKind
    from appsec_review.retrieval.index import load_verified_manifest
    from appsec_review.review.bounded_analysis import BoundedAnalysisContext
    from appsec_review.review.evidence import classify
    from appsec_review.review.models import Admissibility, Predicate
    from appsec_review.storage import run_artifact, atomic_json
    module, scope, _, unit = admitted_fixture(tmp_path, monkeypatch)
    selected = module.plan(unit.job, settings())
    assert len(selected["work"]) == 1
    executor = FakeExecutor(unit.job.run_root, [(10, outcome("FAILURE", trace=True))])
    analyzed = module.analyze(unit, selected, settings(), lambda *_: executor)
    assert analyzed["counts"] == {"counterexample_candidate": 1}
    plan_path, result_path = unit.job.attempt_root / "plan.json", unit.job.attempt_root / "artifacts/cbmc/analysis.json"
    atomic_json(plan_path, selected)
    atomic_json(result_path, analyzed)
    published = module.publish(unit, analyzed, run_artifact(unit.job.run_root, plan_path),
                               run_artifact(unit.job.run_root, result_path))
    manifest, _ = load_verified_manifest(unit.job.run_root, unit.job.run_root / published["index_manifest"]["path"],
                                         published["index_manifest"]["sha256"])
    cbmc = [shard for shard in manifest["indexes"] if shard["producer"].get("job") == "job_cbmc_analysis"]
    store = ShardSet(unit.job.run_root, manifest["indexes"])
    records = list(store.entities(cbmc, kinds=("review_signal",)))
    assert len(records) == 1 and records[0]["payload"]["judgment"] == "counterexample_candidate"
    assert records[0]["payload"]["seed_observation_ids"] == SEED["observation_ids"]
    assert all(classify(EntityKind.REVIEW_SIGNAL, p, tuple(Predicate)) is Admissibility.INDIRECT for p in Predicate)
    review_scope = SimpleNamespace(run_root=unit.job.run_root, store=store,
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
