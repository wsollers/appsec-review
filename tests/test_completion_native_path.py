"""Real accepted native evidence through every completion lane, with offline boundary adapters."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import shutil
import tomllib

from appsec_review.inference import ModelResult
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.accepted_review import load_accepted_review
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.job_dossier_publication import build_job as dossier_job
from appsec_review.jobs.job_final_publication_gate import build_job as gate_job
from appsec_review.jobs.job_final_report_publication import build_job as report_job
from appsec_review.jobs.job_inference_security_review import build_job as review_job
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_poc_generation import build_job as poc_job
from appsec_review.jobs.job_poc_generation.buildctx import CompileCommand
from appsec_review.jobs.job_remediation_planning import build_job as planning_job
from appsec_review.jobs.job_remediation_validation import build_job as validation_job
from appsec_review.observability import PipelineLog
from appsec_review.observability.telemetry import aggregate_run_metrics
from appsec_review.reporting.dossier_render import render_dossier
from tests import poc_support, remediation_support as support
from tests.final_report_support import GATE, REPORT, job_tables, run_job
from tests.fixtures.inference_review.acceptance import JOB, write_config, write_overlay
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.test_dossiers import executor_factory

POC, PLAN, VALIDATE, DOSSIERS = (
    "job_poc_generation", "job_remediation_planning", "job_remediation_validation", "job_dossier_publication")
FUNCTIONS = ("poc_native_overlong", "poc_native_control")
SOURCES = tuple(
    f'void {name}() {{\n  char input[{size}] = "{text}";\n  p(input);\n}}'
    for name, size, text in zip(FUNCTIONS, (16, 4), ("A" * 15, "A" * 3), strict=True))


class NativeWriter:
    def __init__(self):
        self.requests = []

    def __call__(self, request, *, timeout_seconds):
        self.requests.append(request)
        return ModelResult({"action": "final", "result": {
            "claim": request.cell_id.removeprefix("poc-writer:"),
            "test_function": {"name": FUNCTIONS[0], "includes": ["parse.h"], "source": SOURCES[0]},
            "negative_control": {"name": FUNCTIONS[1], "source": SOURCES[1]},
            "setup": ["bounded synthetic character arrays; no external input"],
            "expected_observation": "the overlong input exceeds the accepted 8-byte destination",
            "breakpoints": [{"function": "p", "line": 3, "why": "accepted strcpy sink"}],
            "notes": "Developer compile-only functions; never execute in this pipeline."}},
            input_tokens=100, output_tokens=100)


def native_ast(text):
    """A deterministic compiler boundary double for exactly the two native fixture functions."""
    assert all(source in text for source in SOURCES)
    source = f"/workspace/{poc_support.settings().build.scratch_directory}/poc.c"
    declarations = {"p": {"kind": "FunctionDecl", "name": "p", "qualified": "p",
                           "file": "/workspace/native/include/parse.h", "line": 3}}
    nodes = []
    for name, size, literal in zip(FUNCTIONS, (16, 4), ("A" * 15, "A" * 3), strict=True):
        identity = "input-" + name
        declarations[identity] = {"kind": "VarDecl", "name": "input", "qualified": "input", "file": source}
        nodes.append({"kind": "FunctionDecl", "name": name, "type": {"qualType": "void ()"}, "inner": [{
            "kind": "CompoundStmt", "inner": [
                {"kind": "DeclStmt", "inner": [{"kind": "VarDecl", "id": identity, "name": "input",
                    "type": {"qualType": f"char[{size}]"}, "inner": [
                        {"kind": "StringLiteral", "value": f'"{literal}"'}]}]},
                {"kind": "CallExpr", "inner": [
                    {"kind": "DeclRefExpr", "referencedDecl": {"kind": "FunctionDecl", "id": "p", "name": "p"}},
                    {"kind": "DeclRefExpr", "referencedDecl": {
                        "kind": "VarDecl", "id": identity, "name": "input"}}]}]}]})
    return {"schema": "appsec-review/poc-ast/1", "source": source, "project_roots": ["/workspace/"],
            "declarations": declarations, "nodes": nodes, "project_declarations": []}


def test_completion_job_tables_preserve_every_configured_step():
    central = tomllib.loads((support.ROOT / "appsec-review.toml").read_text())["jobs"]
    for job in ("job_third_party_data_sync", POC, PLAN, VALIDATE, DOSSIERS, GATE, REPORT):
        assert tomllib.loads(job_tables(job))["jobs"][job] == central[job]


def test_real_native_review_through_all_completion_lanes(tmp_path_factory):
    base = tmp_path_factory.mktemp("n")
    fixture = build_accepted_index_set(base / "data")
    native_ids = support.add_native_graph_facts(fixture)
    jobs = (POC, PLAN, VALIDATE, DOSSIERS, GATE, REPORT)
    config = write_config(base, fixture.runs_dir, extra="".join(
        job_tables(job) for job in ("job_third_party_data_sync", *jobs)))
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(base, 1))}
    root = fixture.run_root
    accepted = {}
    summaries = {}

    def run(job, unit, upstream):
        run_job(config, job, fixture.run_id, {key: accepted[key].sha256 for key in upstream}, env)
        handoff = accepted_handoff(root, job.job_id)
        assert handoff is not None, job.job_id
        accepted[job.job_id] = handoff
        publication = handoff.handoff["outputs"][unit]
        summaries[job.job_id] = read_bound_json(root, publication["artifact"])
        return publication

    infer = support.native_review_infer({**fixture.ids, **native_ids})
    run(review_job(infer=infer, repository_root=support.ROOT), "publication.publish_handoff", ())
    review = summaries[JOB]
    verified = load_accepted_review(root, SchemaSet(support.ROOT / SCHEMA_DIRECTORY), max_packages=10000).document
    before_packages = deepcopy(verified["packages"])
    before_ship_block = deepcopy(verified["ship_block"])
    candidates = review["poc_candidates"]
    assert len(candidates) == 1, read_bound_json(
        root, accepted[JOB].handoff["outputs"]["scoring.score_claims"]["artifact"])
    candidate = candidates[0]
    assert candidate["poc_basis"]["brief"]["entry"] == [native_ids["fix_entry"]]
    assert candidate["poc_basis"]["brief"]["path"] == [native_ids["fix_call"]]
    native_finding = next(item for item in before_packages if item["claim_id"] == candidate["claim_id"])
    assert native_finding["state"] == candidate["state"] == "confirmed"
    confirmed = set(verified["partition"]["confirmed"])
    assert native_finding["finding_package_id"] in confirmed

    workspace = root / "data" / "build" / "native" / "units" / ("build-unit-" + "1" * 20) / "workspace"
    shutil.copytree(fixture.target, workspace)
    header = workspace / "native" / "include" / "parse.h"
    header.parent.mkdir(parents=True)
    header.write_text("#ifndef PARSE_H\n#define PARSE_H\nvoid p(char *s);\n#endif\n")
    obj = workspace / "build" / "parse.o"
    obj.parent.mkdir()
    obj.write_bytes(b"synthetic object supplied only by the deterministic compiler adapter")
    manifest = poc_support.manifest_of(workspace)
    builds = support.builds_for(root, workspace, manifest)
    located = builds.locate("native/src/parse.c")
    assert located.unit is not None
    unit = replace(located.unit, objects=("build/parse.o",), command=CompileCommand(
        ("/usr/bin/clang", "-I/workspace/native/include", "-O2", "-Wall", "-c", "/workspace/native/src/parse.c"),
        "native/src/parse.c", "c", ".", "exact"))
    poc_builds = poc_support.builds(unit)
    writer = NativeWriter()
    compiler = poc_support.FakeExecutor(native_ast, undefined="p U\n", project="p T 0 10\n")
    run(poc_job(infer=writer, builds_factory=lambda _root: poc_builds,
                executor_factory=lambda _unit, _profile: compiler, repository_root=support.ROOT),
        "publish.publish_handoff", (JOB,))
    poc = summaries[POC]
    assert len(writer.requests) == 1
    assert len(poc["candidates"]) == 1 and poc["omitted_claims"] == []
    outcome = poc["candidates"][0]
    assert outcome["claim_id"] == candidate["claim_id"] and outcome["status"] == "compile_verified"
    compiler.assert_nothing_is_linked_or_run()

    planner, reviewer, syntax = support.Writer(retrieve=True), support.Writer(), support.Executor(codes=(0, 0))
    run(planning_job(infer=planner, builds_factory=lambda _root: builds, repository_root=support.ROOT),
        "acceptance.publish_handoff", (JOB, POC))
    run(validation_job(infer=reviewer, builds_factory=lambda _root: builds,
                       executor_factory=lambda _unit, _profile: syntax, repository_root=support.ROOT),
        "acceptance.publish_handoff", (JOB, POC, PLAN))
    for job in (PLAN, VALIDATE):
        assert {item["finding"]["finding_package_id"] for item in summaries[job]["items"]} == confirmed
    plan = next(item for item in summaries[PLAN]["items"] if item["finding"]["claim_id"] == candidate["claim_id"])
    validation = next(item for item in summaries[VALIDATE]["items"]
                      if item["finding"]["claim_id"] == candidate["claim_id"])
    assert plan["status"] == "proposal_generated"
    assert validation["status"] == "build_checked"
    checked = read_bound_json(root, validation["validation"])
    assert checked["plan"] == plan["plan"] and checked["checks"]["build"]["status"] == "passed"
    assert checked["checks"]["runtime_regression"]["status"] == "not_performed_by_policy"
    assert len(planner.requests) >= 2 and reviewer.requests and len(syntax.calls) == 2
    assert all("-fsyntax-only" in call["argv"] for call in syntax.calls)
    assert poc_support.manifest_of(workspace) == manifest

    renders = []
    fake_pdf = b"%PDF-1.5\n" + b"deterministic renderer boundary double " * 3 + b"\n%%EOF\n"

    def render(*args, **kwargs):
        return render_dossier(*args, **kwargs, executor_factory=executor_factory(renders, render_status=0, pdf=fake_pdf))

    run(dossier_job(renderer=render, repository_root=support.ROOT), "acceptance.publish_handoff",
        (JOB, POC, PLAN, VALIDATE))
    dossiers = summaries[DOSSIERS]
    assert dossiers["counts"]["by_kind"] == {"confirmed_finding": len(confirmed), "poc": 1}
    assert dossiers["counts"]["items"] == dossiers["counts"]["by_status"]["rendered"] == len(confirmed) + 1
    assert dossiers["omitted"] == [] and dossiers["gaps"] == []
    for item in dossiers["items"]:
        assert item["status"] == "rendered" and item["files"]["pdf"] is not None
        assert read_bound_json(root, item["files"]["json"])["finding"]["claim_id"] == item["finding"]["claim_id"]

    run(gate_job(repository_root=support.ROOT), "acceptance.publish_handoff", (JOB, *jobs[:4]))
    gate = summaries[GATE]
    assert gate["ship_block"] == before_ship_block
    assert [{key: value for key, value in item.items() if key not in {"bucket", "withheld_reasons"}}
            for item in gate["packages"]] == before_packages
    assert gate["package_counts"]["withheld"] == 0
    for capability, producer in (("poc_generation", POC), ("remediation_planning", PLAN),
                                 ("remediation_validation", VALIDATE), ("dossiers", DOSSIERS)):
        record = gate["capabilities"][capability]
        assert record["enabled"] and record["handoff"]["sha256"] == accepted[producer].sha256
        assert record["item_count"] == len(gate["attachments"][capability])
    assert gate["capabilities"]["poc_generation"]["disposition"] == "SUCCEEDED"
    assert gate["capabilities"]["dossiers"]["disposition"] == "SUCCEEDED"
    for binding in gate["bindings"]:
        resolve_bound(root, binding)

    pointers = {path: path.read_bytes() for job in jobs[:4]
                for path in (root / "data" / "jobs" / job / "latest.json",)}
    for path in pointers:
        path.write_text("invalid optional pointer must never be discovered after the gate")
    try:
        publication = run(report_job(repository_root=support.ROOT), "acceptance.publish_handoff", (GATE,))
    finally:
        for path, data in pointers.items():
            path.write_bytes(data)
    report = summaries[REPORT]
    assert report["capabilities"] == gate["capabilities"]
    assert report["summary"]["ship_block"] == before_ship_block
    assert report["findings"] == [item for item in gate["packages"] if item["bucket"] == "publishable"]
    assert report["poc_outcomes"]["items"] == gate["attachments"]["poc_generation"]
    assert report["dossiers"]["items"] == gate["attachments"]["dossiers"]
    public = json.dumps(report) + resolve_bound(root, publication["markdown"]).read_text()
    for protected in ("strcpy(b, s);", "if (strlen(s) < sizeof b)", *SOURCES):
        assert protected not in public
    assert outcome["runtime_verified"] is False and outcome["result_id"] is None

    records, torn = PipelineLog(root).read()
    assert not torn
    assert {record["job_id"] for record in records} >= {JOB, *jobs}
    metrics = aggregate_run_metrics(root)["completion"]
    assert metrics["authority"] == "observational_process_metrics_not_security_evidence"
    assert metrics["measurement_gaps"] == [] and metrics["measurement_gap_count"] == 0
    assert set(metrics["lanes"]) == {"attack_chains", "poc_generation", "remediation_planning",
                                    "remediation_validation", "dossiers", "publication_gate", "report_publication"}
    assert all(lane["observed"] for lane in metrics["lanes"].values())

    def event(lane, name):
        measured = metrics["lanes"][lane]["events"][name]
        assert measured["count"] == 1
        assert any(record["event_type"] == name for record in records)
        return measured

    chains = event("attack_chains", "INFERENCE_REVIEW_ATTACK_CHAIN_COMPOSITION_COMPLETED")
    assert chains["counters"]["proposed"] == chains["counters"]["admitted"] == 0
    poc_event = event("poc_generation", "POC_GENERATION_PUBLISHED")
    assert poc_event["counters"]["candidate_count"] == poc_event["counters"]["compile_verified_count"] == 1
    assert poc_event["outcomes"]["by_status.compile_verified"] == 1
    assert event("remediation_planning", "REMEDIATION_PLANNING_PUBLISHED")["outcomes"][
        "outcome_counts.proposal_generated"] >= 1
    assert event("remediation_validation", "REMEDIATION_VALIDATION_PUBLISHED")["outcomes"][
        "outcome_counts.build_checked"] >= 1
    adapter = event("remediation_validation", "REMEDIATION_VALIDATION_ADAPTER_COMPLETED")
    assert adapter["outcomes"]["passed"] == 1
    assert adapter["flags"]["baseline_attempted.true"] == adapter["flags"]["patched_attempted.true"] == 1
    dossier_event = event("dossiers", "DOSSIER_PUBLICATION_PUBLISHED")
    assert dossier_event["counters"]["item_count"] == dossier_event["counters"]["rendered_count"] == len(confirmed) + 1
    gate_event = event("publication_gate", "FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED")
    assert gate_event["counters"]["attachment_count"] == sum(map(len, gate["attachments"].values()))
    assert gate_event["outcomes"]["dispositions.poc_generation.SUCCEEDED"] == 1
    report_event = event("report_publication", "FINAL_REPORT_ASSEMBLED")
    assert report_event["counters"]["publishable_count"] == len(report["findings"])
    assert report_event["counters"]["withheld_count"] == 0
    event("report_publication", "FINAL_REPORT_PUBLISHED")

    again = run(report_job(repository_root=support.ROOT), "acceptance.publish_handoff", (GATE,))
    assert again["artifact"]["sha256"] == publication["artifact"]["sha256"]
    assert again["markdown"]["sha256"] == publication["markdown"]["sha256"]
