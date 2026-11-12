"""job_threat_model_generation through the real runner (T-107, first slice).

Unit tests: the real configuration copied under ``tmp_path`` with the job enabled there, the real
``JobRunner``, and fixture upstream producers that publish real SQLite shards, real manifests, the
producers' real dataset declarations and hash-bound handoffs (``tests.handoff_fixture``). Claim-time
admission, the unit read scope, the index view, the lanes, assembly, validation, rendering and
publication are all the production code. No Docker, no model, no network, no target checkout.

The tests assert the published contract, never whether a generated model is right: there is no
answer key.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any, Mapping, Sequence

import pytest

from appsec_review.cli import main
from appsec_review.config import load_config
from appsec_review.indexing.inventory import Claim, FileClaims, compile_glob, runtime_claims, scan_run_tree
from appsec_review.interchange import GAP_SCHEMA, GapCode
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.job_threat_model_generation import build_job
from appsec_review.jobs.job_threat_model_generation.datasets import ARTIFACT_DIRECTORY, DATASETS, PRODUCER_DATASETS
from appsec_review.jobs.job_threat_model_generation.job import (
    DEPLOYMENT_GAP, INTERACTIONS, LOAD, PUBLISH, RENDER, STRUCTURE, TOPOLOGY, ThreatModelGenerationFailed,
)
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.review import evidence as admissibility
from appsec_review.runtime import JobRunner, Unit, UnitExecutor, job_is_enabled
from appsec_review.runtime.contracts import Availability, MissingPolicy, TargetAccess
from appsec_review.runtime.datasets import RUNTIME_SHARED_NAMESPACES, EvidenceAuthority, dataset_contract, shard_owner
from appsec_review.observability import write_run_metrics
from appsec_review.runtime.launch import complete, launch, launch_inputs
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.repair import WORKER_PROTOCOL
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.threat_model.codec import evidence_ref_from_plain
from appsec_review.threat_model.contract import (
    AUTHORITY, DFD_SCHEMA, EVIDENCE_SCHEMA, JOB_ID, RESULT_SCHEMA, THREAT_MODEL_SCHEMA, InputState, Limits, canonical,
)
from appsec_review.threat_model.index_view import DECLARED_INPUTS, IndexEvidenceView
from appsec_review.threat_model.reference import load_reference
from appsec_review.threat_model.render import render_markdown, render_mermaid
from appsec_review.threat_model.validate import validate_documents
from tests.handoff_fixture import write_fixture_handoff
from tests.release_support import write_release
from tests.telemetry_support import assert_job_lifecycle, job_events

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "threat_model" / "client_server_c"
RUN_ID = "2026-11-12-0001"
SNAPSHOT = "target-sha256:" + "7" * 64
CATALOG, SYNTAX = "job_target_catalog", "job_tree_sitter_ast"
UNIT = "native-cmake-0001"
SETTINGS = "[jobs.job_threat_model_generation.settings]\nenabled = false\n"
CALLEES = ("accept", "connect", "fopen", "listen", "recv")
POINTS = [
    {"name": "echo-server", "kind": "executable", "evidence": "CMakeLists.txt:4", "sources": ["server.c"],
     "include_dirs": []},
    {"name": "echo-client", "kind": "executable", "evidence": "CMakeLists.txt:5", "sources": ["client.c"],
     "include_dirs": []},
]


def _config(tmp_path: Path, *, enabled: bool = True, edit: Any = None, profile: str | None = None):
    """The real configuration under ``tmp_path``; the job is enabled only in this copy."""
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    assert text.count(SETTINGS) == 1, "the committed configuration keeps the job disabled"
    if enabled:
        text = text.replace(SETTINGS, SETTINGS.replace("false", "true"))
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "appsec-review.toml").write_text(edit(text) if edit else text, encoding="utf-8")
    shutil.copytree(ROOT / "data" / "reference" / "threat-model", tmp_path / "data" / "reference" / "threat-model")
    if profile is None:
        return load_config(tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    return load_config(tmp_path / "appsec-review.toml", profile=profile)


def entity(kind: EntityKind, key: str, payload: Mapping[str, Any] | None = None, *, name: str | None = None,
           text: str = "", location: SourceLocation | None = None) -> EntityRecord:
    return EntityRecord(LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": key}), key, name or key, text,
                        payload or {}, location)


def build_unit(points: Sequence[Mapping[str, Any]] = POINTS) -> EntityRecord:
    return entity(EntityKind.BUILD_ACTION, UNIT, {
        "build_unit_id": UNIT, "root": ".", "family": "native", "build_system": "cmake",
        "build_points": list(points)}, name="cmake")


def fixture_calls() -> list[EntityRecord]:
    """Tree-sitter call nodes of the C fixture as ``job_tree_sitter_ast`` publishes them, at their real lines."""
    nodes = []
    for path in sorted(FIXTURE.glob("*.c")):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        for match in re.finditer(rb"\b(" + "|".join(CALLEES).encode() + rb")\(", data):
            written = match[1].decode()
            line = data.count(b"\n", 0, match.start()) + 1
            location = SourceLocation(SNAPSHOT, path.name, digest, match.start(1), match.end(1), line, line, 1, 1, {},
                                      "fixture", 1.0)
            nodes.append(entity(EntityKind.AST_NODE, f"{path.name}:{match.start()}", {
                "schema": "appsec-review/tree-sitter-normalizer/1", "grammar_native_type": "call_expression",
                "language": "c", "syntax_only": True, "build_unit_id": UNIT,
                "syntax": {"category": "call_expression", "written_name": written, "enclosing_definition": None,
                           "syntactic_qualifiers": [], "resolution": "unresolved"}},
                name="call_expression", text=f"call_expression {written}", location=location))
    assert {node.payload["syntax"]["written_name"] for node in nodes} == set(CALLEES)
    return nodes


class Run:
    """One accepted run under the configured runs directory: real shards, one handoff per producer."""

    def __init__(self, config: Any, run_id: str = RUN_ID) -> None:
        self.config = config
        self.root = config.runtime.runs_dir / run_id
        self.root.mkdir(parents=True)
        # The run is bound to this configuration and release before any fixture producer claims in it,
        # exactly as the first real job of a run would bind it.
        JobRunner(config)._bind_configuration(self.root)
        self.units = 0
        self.pins: dict[str, str] = {}

    def shard(self, producer: str, index: str, shard_id: str, entities: Sequence[EntityRecord] = ()) -> IndexIdentity:
        fingerprint = hashlib.sha256(f"{producer}/{index}/{shard_id}/{len(entities)}".encode()).hexdigest()
        path = self.root / "data" / "indices" / index / f"{producer}-{shard_id}-{fingerprint[:8]}.sqlite"
        builder = IndexBuilder(path, name=index, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for item in entities:
            builder.add_entity(item)
        builder.add_coverage("fixture", "complete")
        self.units += 1
        unit = f"{shard_owner(PRODUCER_DATASETS[producer], index, shard_id).step}.shard{self.units}"
        return IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                             path.relative_to(self.root).as_posix(), {"job": producer, "unit": unit}, (), shard_id)

    def accept(self, producer: str, shards: Sequence[IndexIdentity], attempt_id: str = "attempt_0001") -> str:
        datasets = PRODUCER_DATASETS[producer]
        manifest = self.root / "data" / "indices" / "manifests" / f"{producer}-{attempt_id}.json"
        write_manifest(manifest, run_id=self.root.name, target_snapshot=SNAPSHOT,
                       target_root=self.root.parent / "target", indexes=shards)
        attempt = self.root / "data" / "jobs" / producer / "attempts" / attempt_id
        # The fixture producer is not running: its claim carries the current worker protocol, as a
        # finished real attempt's does, so a later attempt in this run is not refused as historical.
        atomic_json(attempt / "claim.json", {"worker_protocol": WORKER_PROTOCOL, "dataset_contract": dataset_contract(
            producer, sorted({item.step for item in datasets}), datasets)})
        outputs = {item.producer["unit"]: {"index_identity": asdict(item),
                                           "index_manifest": artifact_ref(self.root, manifest)} for item in shards}
        handoff = attempt / "handoff.json"
        write_fixture_handoff(self.root, handoff, {
            "job_id": producer, "source_fingerprint": SNAPSHOT, "outputs": outputs,
            "artifacts": [artifact_ref(self.root, self.root / item.relative_path) for item in shards]})
        digest = file_sha256(handoff)
        atomic_json(self.root / "data" / "jobs" / producer / "latest.json", {
            "handoff_path": handoff.relative_to(self.root).as_posix(), "handoff_sha256": digest})
        self.pins[producer] = digest
        return digest

    def accept_catalog(self, **entities: Sequence[EntityRecord]) -> str:
        """The catalog's five required datasets (handoff verification rejects a catalog without them)."""
        return self.accept(CATALOG, [self.shard(CATALOG, index, "default", entities.get(index, ()))
                                     for index in ("analysis", "build", "components", "documents", "source")])

    def accept_syntax(self, nodes: Sequence[EntityRecord], attempt_id: str = "attempt_0001") -> IndexIdentity:
        shard = self.shard(SYNTAX, "analysis", "ts-c", nodes)
        self.accept(SYNTAX, [shard], attempt_id)
        return shard

    def accept_remaining_inputs(self) -> None:
        """A complete accepted handoff of every other declared producer, with a (possibly empty) shard
        of each declared output kind and of each output the producer's contract requires."""
        for producer in sorted({name for name, _ in DECLARED_INPUTS} - set(self.pins)):
            shards = []
            for declaration in PRODUCER_DATASETS[producer]:
                declared = (producer, declaration.output_kind) in DECLARED_INPUTS
                if declaration.disposition != "indexed" or not (declared or declaration.required):
                    continue
                shard_id = "".join((*declaration.shard_prefixes[:1], "fixture", *declaration.shard_suffixes[:1]))
                assert shard_owner(PRODUCER_DATASETS[producer], declaration.indexes[0], shard_id) is declaration
                shards.append(self.shard(producer, declaration.indexes[0], shard_id))
            self.accept(producer, shards)

    def run(self, job: Any = None) -> Mapping[str, Any]:
        """One standalone launch, as the CLI drives it: claim or reuse, every unit, finalize, run metrics."""
        job = job or build_job()
        inputs = launch_inputs(job, target=self.root.parent / "target", upstream_handoffs=None)
        assert inputs.target_root is None and inputs.source_fingerprint == "none", "accepted evidence only"
        return launch(JobRunner(self.config), job, inputs, run_id=self.root.name)

    def handoff(self) -> dict[str, Any]:
        pointer = json.loads((self.root / "data" / "jobs" / JOB_ID / "latest.json").read_bytes())
        return json.loads((self.root / pointer["handoff_path"]).read_bytes())

    def unit_result(self, unit_id: str) -> dict[str, Any]:
        """The full result of one unit of the accepted attempt (the handoff projects only control keys)."""
        step, task = unit_id.split(".")
        attempt = self.root / self.handoff()["resolving_paths"]["attempt"]
        return json.loads((attempt / "steps" / step / "tasks" / task / "result.json").read_bytes())

    def published(self) -> dict[str, Any]:
        """What a consumer reads: the handoff names ``result.json``, which names every other artifact.

        Documents are parsed, views are text; each is checked against the hash that names it.
        """
        def read(identity: Mapping[str, Any]) -> bytes:
            data = (self.root / identity["path"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == identity["sha256"] and len(data) == identity["size_bytes"]
            assert identity["path"] in bound
            return data

        handoff = self.handoff()
        bound = {item["path"] for item in handoff["artifacts"]}
        document = json.loads(read(handoff["outputs"][PUBLISH]["artifact"]))
        result = {"result.json": document}
        for name, identity in document["artifacts"].items():
            data = read(identity)
            result[name] = json.loads(data) if name.endswith(".json") else data.decode("utf-8")
        return result


def _catalog_run(tmp_path: Path, run_id: str = RUN_ID, *, edit: Any = None, release: bool = False) -> Run:
    config = _config(tmp_path, edit=edit)
    if release:  # reuse needs a measured release; the run binds it when it is created
        write_release(tmp_path, (JOB_ID,))
    run = Run(config, run_id)
    run.accept_catalog(build=[build_unit()])
    return run


def _fixture_run(tmp_path: Path, run_id: str = RUN_ID, *, edit: Any = None, release: bool = False) -> Run:
    run = _catalog_run(tmp_path, run_id, edit=edit, release=release)
    run.accept_syntax(fixture_calls())
    return run


def _gap_records(handoff: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(unit_id, gap) for unit_id, output in sorted(handoff["outputs"].items()) for gap in output.get("gaps", ())]


def _index_bytes(run_root: Path) -> dict[str, str]:
    return {path.relative_to(run_root).as_posix(): file_sha256(path)
            for path in sorted((run_root / "data" / "indices").rglob("*")) if path.is_file()}


def test_job_is_registered_configured_and_in_the_graph_after_owasp_and_before_indexing(tmp_path: Path) -> None:
    from appsec_review.orchestration.dagster.adapter import _pool_for
    config = _config(tmp_path)
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="threat-model test")
    jobs = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    order = list(jobs)
    assert order.index("job_owasp_control_assessment") < order.index(JOB_ID) < order.index("job_review_data_indexing")
    assert jobs[JOB_ID]["dependencies"] == ["job_owasp_control_assessment"]
    assert JOB_ID in jobs["job_review_data_indexing"]["dependencies"]
    assert jobs[JOB_ID]["upstream_handoffs"] == sorted({producer for producer, _ in DECLARED_INPUTS})
    assert JOB_ID not in jobs["job_review_data_indexing"]["upstream_handoffs"], "scheduling only: no consumer yet"

    configured = config.jobs[JOB_ID]
    assert configured.name == "threat_model_generation" and configured.workers == 2
    assert {step: tuple(configured.step(step).tasks) for step in configured.steps} == dict(TOPOLOGY)
    job = registry.build(JOB_ID)
    assert [unit.unit_id for unit in job.units] == [f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks]
    assert job.strict_gaps is True and job.name == configured.name
    assert not {"inference", "deterministic", "inspection", "provenance"} & set(TOPOLOGY)
    assert {_pool_for(unit.unit_id, JOB_ID) for unit in job.units} == {"application", "lifecycle"}

    contract = job.contract
    assert contract.target_access is TargetAccess.ACCEPTED_EVIDENCE
    assert contract.schedule_after == ("job_owasp_control_assessment", "job_dependency_intelligence",
                                       "job_security_tagging")
    assert {(item.producer, item.output_kind) for item in contract.inputs if item.output_kind != "handoff"} \
        == set(DECLARED_INPUTS)
    envelopes = {item.producer: item for item in contract.inputs if item.output_kind == "handoff"}
    assert {producer for producer, item in envelopes.items() if item.availability is Availability.REQUIRED} == {CATALOG}
    assert envelopes[CATALOG].missing is MissingPolicy.REJECT
    assert all(item.missing is MissingPolicy.GAP and item.availability is Availability.OPTIONAL
               for item in contract.inputs if item is not envelopes[CATALOG])


def test_default_configuration_has_the_job_disabled_and_a_disabled_job_is_not_dispatched() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    assert config.jobs[JOB_ID].settings["enabled"] is False and not job_is_enabled(config, JOB_ID)
    assert config.jobs[JOB_ID].typed_settings.limits == Limits()
    jobs = {item["job_id"]: item for item in describe_wave1(config, builtin_registry())["jobs"]}
    assert JOB_ID not in jobs
    assert JOB_ID not in jobs["job_review_data_indexing"]["dependencies"]
    with pytest.raises(ValueError, match=f"job is disabled by configuration: {JOB_ID}"):
        main(["--config", str(ROOT / "appsec-review.toml"), "run", JOB_ID])


REFUSED = {
    "bound-bool": lambda text: text.replace("max_threats = 4000\nmax_query_rows", "max_threats = true\nmax_query_rows"),
    "bound-missing": lambda text: text.replace("max_evidence_refs_per_element = 8\n", ""),
    "bound-over": lambda text: text.replace("max_flows = 8000\nmax_threats", "max_flows = 100001\nmax_threats"),
    "bound-zero": lambda text: text.replace("max_processes = 200\n", "max_processes = 0\n"),
    "enabled-text": lambda text: text.replace(SETTINGS.replace("false", "true"),
                                              SETTINGS.replace("false", '"yes"')),
    "model-table": lambda text: text.replace(
        "[jobs.job_threat_model_generation.steps.load]",
        "[jobs.job_threat_model_generation.settings.model]\nenabled = false\n\n"
        "[jobs.job_threat_model_generation.steps.load]"),
    "reservation-range": lambda text: text.replace("io_slots = 1\nadmission_timeout_seconds = 600",
                                                    "io_slots = 1\nadmission_timeout_seconds = 0"),
    "reservation-unknown": lambda text: text.replace("admission_timeout_seconds = 600\n",
                                                      "admission_timeout_seconds = 600\ngpu = 1\n"),
    "unknown-key": lambda text: text.replace("max_render_nodes = 120\n", "max_render_nodes = 120\nmax_assets = 5\n"),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_unknown_setting_or_out_of_range_bound_is_refused(tmp_path: Path, case: str) -> None:
    def edit(text: str) -> str:
        edited = REFUSED[case](text)
        assert edited != text, "the edit must change the configuration it tests"
        return edited

    with pytest.raises(ValueError, match="job_threat_model_generation"):
        _config(tmp_path, edit=edit)


def test_run_with_only_the_catalog_completes_with_gaps_and_publishes_an_honest_model(tmp_path: Path) -> None:
    run = _catalog_run(tmp_path)
    outcome = run.run()
    assert outcome["status"]["status"] == "COMPLETED_WITH_GAPS", outcome["status"]
    documents = run.published()
    dfd, model, evidence, result = (documents[name] for name in ("dfd.json", "threat-model.json", "evidence.json",
                                                                 "result.json"))
    assert [item["schema"] for item in (dfd, model, evidence, result)] == [
        DFD_SCHEMA, THREAT_MODEL_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA]
    validate_documents(dfd, model, evidence, result)
    origin = dfd["origin"]
    assert (origin["kind"], origin["target_supplied"], origin["producer"], origin["authority"], origin["model"]) == (
        "generated", False, JOB_ID, AUTHORITY, None)
    assert (origin["run_id"], origin["attempt_id"], origin["target_snapshot"]) == (RUN_ID, "attempt_0001", SNAPSHOT)
    assert origin["reference_data"] == dict(load_reference(ROOT).sha256s)

    # Design 7.1: declared build points become processes; nothing else is invented.
    processes = {item["name"]: item for item in dfd["elements"]}
    assert sorted(processes) == ["echo-client", "echo-server"]
    assert all(item["kind"] == "process" and item["basis"] == "declared" and item["name_basis"] == "declared_name"
               and item["attributes"]["built"] is False and item["evidence"] for item in processes.values())
    assert dfd["flows"] == dfd["boundaries"] == [] and model["threats"] == model["entry_points"] == []
    assert model["actors"] == model["assets"] == model["supplied_documents"] == []
    for process in processes.values():
        kinds = {item["kind"] for item in dfd["unknowns"] if process["id"] in item["subject_ids"]}
        assert {"runtime_role_unknown", "boundary_not_established", "deployment_not_described"} <= kinds
    assert result["counts"]["processes"] == 2 and result["counts"]["flows"] == result["counts"]["threats"] == 0
    assert result["counts"]["gaps"] == len(result["gaps"]) > 0

    # Every absent producer is a named gap; the catalog itself is not one.
    unavailable = {gap["scope_id"] for gap in result["gaps"] if gap["code"] == GapCode.INPUT_UNAVAILABLE.value}
    assert unavailable == {producer for producer, _ in DECLARED_INPUTS if producer != CATALOG} | {
        "job_deployment_inventory"}
    assert [gap["reason"] for gap in result["gaps"] if gap["scope_id"] == "job_deployment_inventory"] == [DEPLOYMENT_GAP]

    views = {name: text for name, text in documents.items() if not name.endswith(".json")}
    assert sorted(views) == ["views/dfd.mmd", "views/threat-model.md"]
    assert views["views/dfd.mmd"] == render_mermaid(dfd, Limits())[0]["dfd.mmd"]
    assert views["views/threat-model.md"] == render_markdown(dfd, model, result)
    assert "GENERATED by job_threat_model_generation" in views["views/threat-model.md"]

    [published] = job_events(run.root, JOB_ID, "THREAT_MODEL_PUBLISHED")
    assert published["counts"] == result["counts"] and published["gap_count"] == len(result["gaps"])
    assert_job_lifecycle(run.root, JOB_ID, terminal="COMPLETED_WITH_GAPS")


def test_every_gap_is_a_producer_gap_record_and_each_is_counted_once(tmp_path: Path) -> None:
    run = _catalog_run(tmp_path, release=True)
    assert run.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    handoff = run.handoff()
    # Absent optional producers are gaps this job cannot close by running again, so none is
    # retryable and a resume over the same inputs reuses the accepted attempt instead of rerunning.
    assert handoff["coverage"]["gap_count"] > 1 and handoff["coverage"]["retry_required"] is False
    job = build_job()
    planner = ResumePlanner(run.config, run.root, (job,), "none")
    assert planner.accepted(job, handoff["upstream_handoff_sha256"])[0] == ()
    again = JobRunner(run.config).begin_or_reuse_attempt(build_job(), run_id=RUN_ID)
    assert again.get("reused") is True and again["attempt_id"] == "attempt_0001"
    records = _gap_records(handoff)
    assert records and all(gap["schema"] == GAP_SCHEMA and gap["unit_id"] == unit_id for unit_id, gap in records)
    identities = [gap["gap_id"] for _, gap in records]
    assert len(identities) == len(set(identities)), "no gap is reported by two units"
    assert handoff["coverage"]["gap_count"] == len(records)

    outputs = handoff["outputs"]
    assert outputs[PUBLISH]["gaps"] == [] and outputs[PUBLISH]["terminal_status"] == "SUCCEEDED"
    assert run.unit_result(PUBLISH)["joined_gap_count"] == len(records)
    for unit_id, output in outputs.items():
        assert output["terminal_status"] == ("COMPLETED_WITH_GAPS" if output["gaps"] else "SUCCEEDED"), unit_id
    # The deployment producer is not registered in this slice, so the load unit always has one gap.
    assert [gap["reason"] for gap in outputs[LOAD]["gaps"]] == [DEPLOYMENT_GAP]
    assert outputs[LOAD]["gaps"][0]["retryable"] is False
    # The result document carries the join: the same records, once each, nothing more.
    joined = run.published()["result.json"]["gaps"]
    assert sorted(gap["gap_id"] for gap in joined) == sorted(identities)
    assert {json.dumps(gap, sort_keys=True) for gap in joined} == {json.dumps(gap, sort_keys=True) for _, gap in records}

    # The absent producer arriving is what closes its gap: a new pinned digest, so the job reruns.
    run.accept_syntax(fixture_calls())
    assert set(run.pins) > set(handoff["upstream_handoff_sha256"])
    assert planner.accepted(job, run.pins)[0] == ("upstream handoffs identity changed",)


def test_input_ledger_lists_every_declared_input_with_its_state(tmp_path: Path) -> None:
    run = _fixture_run(tmp_path)
    assert run.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    ledger = {(row["producer"], row["output_kind"]): row for row in run.published()["result.json"]["input_ledger"]}
    assert set(ledger) == set(DECLARED_INPUTS) | {("job_deployment_inventory", "deployment_inventory")}
    absent = lambda producer: (InputState.ABSENT if job_is_enabled(run.config, producer)  # noqa: E731
                               else InputState.DISABLED).value
    for key, row in ledger.items():
        if key[0] == CATALOG:
            assert (row["state"], row["handoff_sha256"], row["coverage_disposition"]) == (
                "read", run.pins[CATALOG], "complete"), key
        elif key[0] == SYNTAX:
            assert (row["state"], row["handoff_sha256"]) == ("read", run.pins[SYNTAX])
            assert row["records_read"] == len(fixture_calls())
        elif key[0] == "job_deployment_inventory":
            assert (row["state"], row["handoff_sha256"], row["records_read"]) == ("not_registered", None, 0)
        else:
            assert (row["state"], row["handoff_sha256"], row["records_read"]) == (absent(key[0]), None, 0), key
    assert ledger[(CATALOG, "build_units")]["records_read"] == 1
    # What the runtime observed agrees: the admitted claim lists the same declared inputs.
    claim = json.loads((run.root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001" / "claim.json").read_bytes())
    admitted = {(row["producer"], row["output_kind"]): row for row in claim["input_admission"]["requirements"]}
    assert set(DECLARED_INPUTS) <= set(admitted)
    assert admitted[(CATALOG, "build_units")]["status"] == "supplied"
    assert admitted[("job_code_graph_index", "code_graph_facts")]["status"] == "gap"
    assert claim["upstream_handoffs"] == run.pins and claim["target_root"] is None


def test_undeclared_upstream_read_fails_the_unit(tmp_path: Path) -> None:
    run = _catalog_run(tmp_path)
    # A real accepted shard of an output kind the contract does not declare (tree_sitter_coverage).
    coverage = run.shard(SYNTAX, "analysis", "tree-sitter-coverage-attempt_0001", fixture_calls()[:1])
    run.accept(SYNTAX, [run.shard(SYNTAX, "analysis", "ts-c", fixture_calls()), coverage])
    undeclared = (SYNTAX, "tree_sitter_coverage")
    seen: dict[str, Any] = {}

    def probe(unit):
        declared = IndexEvidenceView(unit.job.run_root, unit.job.upstream_handoffs)
        with pytest.raises(ValueError, match="undeclared threat-model input"):
            declared.entities(*undeclared, "ast_node", limit=5)
        with pytest.raises(ValueError, match="undeclared threat-model input"):
            declared.input_status("job_security_tagging", "tag_assignments")
        seen["declared"] = len(declared.entities(SYNTAX, "tree_sitter_ast", "ast_node", limit=50).records)
        # A view widened past the contract reaches the runtime's own read boundary, which refuses.
        widened = IndexEvidenceView(unit.job.run_root, unit.job.upstream_handoffs, inputs=(*DECLARED_INPUTS, undeclared))
        widened.entities(*undeclared, "ast_node", limit=5)
        raise AssertionError("the undeclared read was admitted")

    real = build_job()
    units = (Unit(LOAD, probe), *real.units[1:])
    with pytest.raises(Exception) as raised:
        run.run(replace(real, units=units, handler=UnitExecutor(units).execute))
    assert "the undeclared read was admitted" not in str(raised.value)
    assert seen == {"declared": len(fixture_calls())}
    attempt = run.root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    receipt = json.loads((attempt / "steps" / "load" / "tasks" / "accepted_inputs" / "status.json").read_bytes())
    assert receipt["status"] == "FAILED" and receipt["error"]["type"] != "AssertionError", receipt["error"]
    assert "tree_sitter_coverage" in receipt["error"]["message"] or "undeclared" in receipt["error"]["message"]
    assert not (run.root / "data" / "jobs" / JOB_ID / "latest.json").exists()
    assert_job_lifecycle(run.root, JOB_ID, terminal="FAILED")


def test_changed_upstream_bytes_are_refused(tmp_path: Path) -> None:
    run = Run(_config(tmp_path))
    run.accept_catalog(build=[build_unit()])
    shard = run.accept_syntax(fixture_calls())
    runner, job = JobRunner(run.config), build_job()
    claim = runner.begin_attempt(job, run_id=RUN_ID)
    # The admitted tree-sitter shard changes after the claim pinned it and before any unit reads it.
    path = run.root / shard.relative_path
    path.write_bytes(path.read_bytes() + b"\0")
    with pytest.raises(RuntimeError, match="integrity"):
        complete(runner, job, claim)
    assert not (run.root / "data" / "jobs" / JOB_ID / "latest.json").exists()
    attempt = run.root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    receipts = [json.loads(path.read_bytes()) for path in sorted(attempt.glob("steps/*/tasks/*/status.json"))]
    failed = [receipt for receipt in receipts if receipt["status"] == "FAILED"]
    # The first unit that opens the changed shard refuses it; it is the runtime's integrity error,
    # not a failure of the job's own.
    assert [receipt["unit_id"] for receipt in failed] == [INTERACTIONS], receipts
    assert "integrity" in failed[0]["error"]["message"]
    assert failed[0]["error"]["type"] != ThreatModelGenerationFailed.__name__
    assert not (attempt / ARTIFACT_DIRECTORY / "result.json").exists()
    write_run_metrics(run.root)  # what the driver writes when the run ends
    assert_job_lifecycle(run.root, JOB_ID, terminal="FAILED")
    # A second claim is refused at admission: the accepted handoff no longer matches its bytes.
    with pytest.raises(ValueError):
        runner.begin_attempt(job, run_id=RUN_ID)


def test_outputs_match_the_dataset_declarations_and_nothing_lands_in_any_index(tmp_path: Path) -> None:
    run = _fixture_run(tmp_path)
    before = _index_bytes(run.root)
    assert any("/documents/" in path for path in before), "the fixture run has a documents index"
    assert run.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    assert _index_bytes(run.root) == before, "no shard or manifest is written or changed, documents included"

    assert {item.output_kind for item in DATASETS} == {
        "generated_dfd", "generated_threat_model", "generated_model_evidence", "generated_model_views",
        "threat_model_documents"}
    assert all(item.disposition == "artifact_only" and item.family == "threat_model" and item.sensitivity == "internal"
               and item.authority is EvidenceAuthority.ROUTING_CONTEXT and not item.indexes and item.reason
               and item.query_route for item in DATASETS)
    schemas = {item.output_kind: item.schema for item in DATASETS}
    assert schemas == {"generated_dfd": DFD_SCHEMA, "generated_threat_model": THREAT_MODEL_SCHEMA,
                       "generated_model_evidence": EVIDENCE_SCHEMA, "generated_model_views": "text/markdown",
                       "threat_model_documents": RESULT_SCHEMA}

    # Every file the job wrote under its artifact directory is claimed by exactly one declaration.
    attempt = run.root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    written = sorted(path.relative_to(run.root).as_posix() for path in (attempt / ARTIFACT_DIRECTORY).rglob("*")
                     if path.is_file())
    owners = {path: [item.output_kind for item in DATASETS
                     if any(compile_glob(pattern).fullmatch(path) for pattern in item.artifacts)] for path in written}
    assert all(len(kinds) == 1 for kinds in owners.values()), owners
    assert {kinds[0] for kinds in owners.values()} == set(schemas), "each declared dataset was produced"
    by_name = {Path(path).name: kinds[0] for path, kinds in owners.items()}
    assert (by_name["dfd.json"], by_name["threat-model.json"], by_name["evidence.json"], by_name["result.json"],
            by_name["dfd.mmd"], by_name["threat-model.md"]) == (
        "generated_dfd", "generated_threat_model", "generated_model_evidence", "threat_model_documents",
        "generated_model_views", "generated_model_views")

    # The real inventory scan, under the contract the attempt pinned, leaves none of the job's files unclaimed.
    job = build_job()
    steps = sorted({unit.unit_id.split(".")[0] for unit in job.units})
    claims = FileClaims([*runtime_claims({JOB_ID: steps}, shared_namespaces=RUNTIME_SHARED_NAMESPACES),
                         *(Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS)])
    tree = scan_run_tree(run.root, claims, max_files=100_000, sample_limit=100_000, run_id=RUN_ID)
    assert not tree.claim_errors and not tree.truncated
    assert [path for path in tree.unaccounted if f"/jobs/{JOB_ID}/" in path] == []
    assert tree.attempts[(JOB_ID, "attempt_0001")]["contract_basis"] == "pinned_attempt_contract"

    handoff = run.handoff()
    assert not any(key in output for output in handoff["outputs"].values() for key in ("index_identity", "index_manifest"))
    bound = {item["path"] for item in handoff["artifacts"]}
    # The only index files the handoff binds are inputs that existed before the job ran.
    assert {path for path in bound if path.startswith("data/indices/")} <= set(before)
    assert set(written) <= bound, "every published and working file is hash-bound by the handoff"


def test_generated_entity_kinds_are_indirect_under_review_admissibility() -> None:
    # R3 (review/evidence.py::classify) admits a citation only by its index entity kind. That
    # vocabulary is closed: a generated-model kind is not a member, so it cannot be classified at
    # all, and every kind outside the direct, mapped and graph tables is indirect for every predicate.
    kinds = {kind.value for kind in EntityKind}
    generated = ("generated_dfd_element", "generated_flow", "generated_threat", "generated_trust_boundary",
                 "generated_entry_point", "threat", "dfd_element", "trust_boundary")
    predicates = sorted(admissibility.Predicate, key=str)
    assert predicates
    for name in generated:
        assert name not in kinds
        for predicate in predicates:
            with pytest.raises(ValueError):
                admissibility.classify(name, predicate)
    assert not any("generated" in kind or "threat" in kind or "dfd" in kind for kind in kinds)
    listed = set(admissibility.DIRECT_KINDS) | set(admissibility.MAPPED_KINDS) | set(admissibility.GRAPH_KINDS)
    unlisted = sorted(set(EntityKind) - listed, key=str)
    assert unlisted, "the default-deny branch is exercised"
    assert all(admissibility.classify(kind, predicate) is admissibility.Admissibility.INDIRECT
               for kind in unlisted for predicate in predicates)
    # And the job publishes no index entity at all: its datasets claim no shard.
    assert all(not item.indexes and item.authority is EvidenceAuthority.ROUTING_CONTEXT for item in DATASETS)


def test_second_run_with_unchanged_inputs_is_reused_and_a_changed_input_reruns(tmp_path: Path) -> None:
    config = _config(tmp_path)
    write_release(tmp_path, (JOB_ID,))  # reuse needs a measured release; the run binds it when it is created
    run = Run(config)
    run.accept_catalog(build=[build_unit()])
    run.accept_syntax(fixture_calls())
    # Every declared producer has a complete accepted handoff (the gap-accounting test shows reuse
    # with producers absent).
    run.accept_remaining_inputs()
    assert set(run.pins) == {producer for producer, _ in DECLARED_INPUTS}
    runner, job = JobRunner(run.config), build_job()
    planner = ResumePlanner(run.config, run.root, (job,), "none")
    first = runner.begin_or_reuse_attempt(job, run_id=RUN_ID)
    assert not first.get("reused")
    assert complete(runner, job, first)["status"]["status"] == "COMPLETED_WITH_GAPS"
    accepted = run.handoff()
    result = run.published()["result.json"]
    states = {(row["producer"], row["output_kind"]): row["state"] for row in result["input_ledger"]}
    assert {states[key] for key in DECLARED_INPUTS} == {"read"}
    # Only the unregistered deployment producer is left, and that gap is not retryable.
    assert [gap["scope_id"] for gap in result["gaps"] if gap["code"] == GapCode.INPUT_UNAVAILABLE.value] == [
        "job_deployment_inventory"]
    assert accepted["coverage"]["retry_required"] is False

    # Unchanged inputs, configuration, contract and release: the accepted attempt is reused.
    assert planner.accepted(job, run.pins) == ((), file_sha256(run.root / accepted["resolving_paths"]["attempt"]
                                                               / "handoff.json"))
    again = runner.begin_or_reuse_attempt(build_job(), run_id=RUN_ID)
    assert again.get("reused") is True and again["attempt_id"] == "attempt_0001"
    assert again["handoff_sha256"] == file_sha256(run.root / again["handoff_path"])
    attempts = run.root / "data" / "jobs" / JOB_ID / "attempts"
    assert sorted(path.name for path in attempts.iterdir()) == ["attempt_0001"]
    write_run_metrics(run.root)  # what the driver writes when the run ends
    assert_job_lifecycle(run.root, JOB_ID, terminal="COMPLETED_WITH_GAPS")

    # A repaired upstream: the tree-sitter producer publishes a new accepted handoff. Its digest
    # changes, the accepted threat model no longer matches its inputs, and the runtime claims a
    # fresh attempt pinned to the new handoff instead of reusing the old one.
    run.accept_syntax(fixture_calls()[:-1], "attempt_0002")
    assert planner.accepted(job, run.pins)[0] == ("upstream handoffs identity changed",)
    changed = runner.begin_or_reuse_attempt(build_job(), run_id=RUN_ID)
    assert not changed.get("reused") and changed["attempt_id"] == "attempt_0002"
    assert changed["upstream_handoffs"] == run.pins != accepted["upstream_handoff_sha256"]
    assert changed["unit_ids"] == [unit.unit_id for unit in job.units]
    assert json.loads((attempts / "attempt_0002" / "status.json").read_bytes())["status"] == "RUNNING"
    assert run.handoff() == accepted, "the accepted pointer moves only when the new attempt publishes"


def _normalized(document: Mapping[str, Any]) -> bytes:
    """A published document with the two origin fields that name the run and attempt blanked."""
    return canonical({**document, "origin": {**document["origin"], "run_id": "-", "attempt_id": "-"}})


def test_fixture_client_server_target_yields_a_resolving_dfd(tmp_path: Path) -> None:
    run = _fixture_run(tmp_path / "first")
    assert run.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    documents = run.published()
    dfd, model, evidence, result = (documents[name] for name in ("dfd.json", "threat-model.json", "evidence.json",
                                                                 "result.json"))
    validate_documents(dfd, model, evidence, result)

    # Every published citation resolves against the admitted shards, and each is cited by a record.
    view = IndexEvidenceView(run.root, run.pins)
    references = [evidence_ref_from_plain(item) for item in evidence["references"]]
    assert references and all(view.resolves(item) for item in references)
    cited = {item["ref"] for records in (dfd["elements"], dfd["flows"], dfd["boundaries"], model["entry_points"],
                                         model["actors"], model["threats"])
             for record in records for item in record["evidence"]}
    assert cited == {item.ref for item in references}
    located = [item.locator for item in references if item.locator]
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in FIXTURE.glob("*.c")}
    assert located and all(locator.split(":", 1)[0] in hashes and locator.endswith("@" + hashes[locator.split(":", 1)[0]])
                           for locator in located), "locators name the fixture's real files and bytes"

    names = {item["id"]: item["name"] for item in dfd["elements"] if item["kind"] == "process"}
    assert sorted(names.values()) == ["echo-client", "echo-server"]
    network = [item for item in dfd["boundaries"] if item["kind"] == "network"]
    assert network and {names[member] for item in network for member in item["inside"]} == {"echo-client", "echo-server"}
    by_process: dict[str, set[str]] = {}
    for flow in dfd["flows"]:
        process = flow["source"] if flow["source"] in names else flow["target"]
        by_process.setdefault(names[process], set()).add(flow["interaction"])
        assert flow["basis"] == "observed_syntax" and flow["attributes"]["ownership"] == "source_path"
    assert by_process == {"echo-server": {"network_listen", "network_receive", "file_read"},
                          "echo-client": {"network_connect", "network_receive"}}
    assert model["threats"] and all(item["state"] == "candidate" and item["mitigation"]["state"] == "not_examined"
                                    for item in model["threats"])
    assert {item["interaction"] for item in model["entry_points"]} == {"network_listen", "network_receive", "file_read"}

    # The views on disk are exactly a fresh render of the published documents.
    fresh = {f"views/{name}": text for name, text in render_mermaid(dfd, Limits())[0].items()}
    fresh["views/threat-model.md"] = render_markdown(dfd, model, result)
    assert {name: text for name, text in documents.items() if name.startswith("views/")} == fresh
    assert all(f"run: {RUN_ID}" in text for text in fresh.values())

    # An independent run of the same fixture elsewhere publishes the same model: only the origin's
    # run and attempt fields (and what is derived from them) differ.
    other = _fixture_run(tmp_path / "second", "2026-11-12-0002")
    assert other.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    again = other.published()
    assert again["dfd.json"]["origin"]["run_id"] == "2026-11-12-0002" != dfd["origin"]["run_id"]
    for name in ("dfd.json", "threat-model.json", "evidence.json"):
        assert _normalized(again[name]) == _normalized(documents[name]), name
    assert again["result.json"]["counts"] == result["counts"]
    assert [gap["gap_id"] for gap in again["result.json"]["gaps"]] == [gap["gap_id"] for gap in result["gaps"]]
    strip = lambda rows: [{**row, "handoff_sha256": None} for row in rows]  # noqa: E731
    assert strip(again["result.json"]["input_ledger"]) == strip(result["input_ledger"])
    body = lambda text: [line for line in text.splitlines() if not line.startswith(("%% run: ", "%% source-sha256: "))]  # noqa: E731
    assert body(again["views/dfd.mmd"]) == body(documents["views/dfd.mmd"]), "the diagram does not depend on the run"


def test_render_bound_reached_is_a_truncated_gap_and_each_process_gets_its_own_diagram(tmp_path: Path) -> None:
    run = _fixture_run(tmp_path, edit=lambda text: text.replace("max_render_nodes = 120\n", "max_render_nodes = 2\n"))
    assert run.config.jobs[JOB_ID].typed_settings.limits.max_render_nodes == 2
    assert run.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    handoff, documents = run.handoff(), run.published()
    [gap] = handoff["outputs"][RENDER]["gaps"]
    assert (gap["code"], gap["scope_id"], gap["unit_id"]) == (GapCode.TRUNCATED.value, "publication.max_render_nodes",
                                                              RENDER)
    assert handoff["outputs"][RENDER]["terminal_status"] == "COMPLETED_WITH_GAPS"
    dfd, model, result = documents["dfd.json"], documents["threat-model.json"], documents["result.json"]
    assert gap["gap_id"] in {item["gap_id"] for item in result["gaps"]}
    # The published views are a fresh render under the configured bound, the gap row included.
    fresh, truncated = render_mermaid(dfd, Limits(max_render_nodes=2))
    views = {name: text for name, text in documents.items() if name.startswith("views/")}
    assert truncated and views == {**{f"views/{name}": text for name, text in fresh.items()},
                                   "views/threat-model.md": render_markdown(dfd, model, result)}
    processes = [item["id"] for item in dfd["elements"] if item["kind"] == "process"]
    assert sorted(views) == sorted(["views/dfd.mmd", "views/threat-model.md",
                                    *(f"views/dfd-{identity.replace(':', '-')}.mmd" for identity in processes)])
    assert "publication.max_render_nodes" in views["views/threat-model.md"]


def test_redacted_names_reach_the_published_model_identified_by_record(tmp_path: Path) -> None:
    run = Run(_config(tmp_path))
    points = [{**POINTS[0], "name": "<redacted>", "sources": ["server.c", "<redacted>"]},
              {**POINTS[1], "name": "<redacted>"}]
    run.accept_catalog(build=[build_unit(points)])
    assert run.run()["status"]["status"] == "COMPLETED_WITH_GAPS"
    handoff, documents = run.handoff(), run.published()
    processes = [item for item in documents["dfd.json"]["elements"] if item["kind"] == "process"]
    assert [item["name"] for item in processes] == ["redacted-name"] * 2 and len({item["id"] for item in processes}) == 2
    [gap] = [gap for gap in handoff["outputs"][STRUCTURE]["gaps"] if gap["scope_id"] == "structure.redacted"]
    assert gap["code"] == GapCode.PROVENANCE_UNAVAILABLE.value and gap["reason"].startswith("3 names or paths ")
    assert gap["gap_id"] in {item["gap_id"] for item in documents["result.json"]["gaps"]}
    assert "<redacted>" not in json.dumps(documents["dfd.json"]) and "redacted-name" in documents["views/dfd.mmd"]
    assert handoff["outputs"][INTERACTIONS]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert handoff["outputs"][RENDER]["gaps"] == []
