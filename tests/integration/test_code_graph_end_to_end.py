"""Offline end-to-end acceptance for code-graph precomputation (code-graph-precomputation.md 10, C9).

One run goes through the real jobs, in graph order, with no container:

``job_codeql_analysis``
    The real job (plan, database, query, export, normalize, publish) with an injected CodeQL
    executor and image resolver. The executor writes a database tree, a SARIF path-problem result
    whose code flow is the synthetic fixture's ``getenv -> memcpy`` flow, and plays back the C1
    recorded native and synthetic graph exports. The accepted target catalog and language-build
    receipts are injected at their loaders; the plan itself is the real ``build_codeql_plan``.
``job_code_graph_index``
    The real job over the real CodeQL handoff. Its clangd input exists only in the accepted
    ``job_cpp_symbol_index`` handoff, because the CodeQL publication rewrote the accepted manifest.
``job_review_data_indexing``
    The real job (links, products, audit, matrices); the FTS image validation is unavailable.
``job_inference_security_review``
    The real job with an injected worker that cites only graph identities it was given or retrieved.

The Joern check uses the real ``job_cpg_analysis`` over the real native C/C++ build fixture.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from appsec_review.codeql import CodeQLImage
from appsec_review.config import load_config
from appsec_review.graph.contract import GRAPH_INDEX, Family
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.indexing.store import ShardSet
from appsec_review.inference import ModelResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_code_graph_index import build_job as build_graph_job
from appsec_review.jobs.job_codeql_analysis import job as codeql_job
from appsec_review.jobs.job_inference_security_review import build_job as build_review_job
from appsec_review.jobs.job_review_data_indexing import build_job as build_indexing_job
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.review.cells import TURN_SCHEMA
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.red import Proposal, red_result

ROOT = Path(__file__).resolve().parents[2]
EXPORTS = ROOT / "tests" / "fixtures" / "graph" / "codeql_export"
NATIVE_SOURCES = ROOT / "tests" / "fixtures" / "build_toolchains" / "native"
IMAGE_ID = "sha256:" + "1" * 64
SYNTHETIC_PATH = "src/synthetic.cpp"
PYTHON_PATH = "svc/app.py"
WORKFLOW_PATH = ".github/workflows/ci.yml"
SRC_UNIT = "build-unit-" + hashlib.sha256(b"src").hexdigest()[:20]
NATIVE_UNIT = "build-unit-" + hashlib.sha256(b"native").hexdigest()[:20]
# SARIF regions (end column exclusive) of CodeQL's getenv -> atoi -> m -> len -> memcpy path-problem flow.
BRIDGED_FLOW = ((55, 16, 55, 35), (55, 11, 55, 36), (58, 32, 58, 33), (41, 49, 41, 56), (45, 3, 45, 24))
CLANGD_SYMBOLS = {"main": (52, 5), "copy_checked": (32, 6), "copy_unchecked": (41, 6), "dispatch": (24, 6),
                  "forward": (48, 6)}
CLANGD_CALLS = {("main", "copy_checked"): (56, 3), ("main", "copy_unchecked"): (57, 3)}
GRAPH_KINDS = {family.value for family in Family}


# ------------------------------------------------------------------------------------------------ staging


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _handoff(run_root: Path, snapshot: str, job_id: str, outputs: Mapping[str, Any],
             artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    path = attempt / "handoff.json"
    atomic_json(path, {"schema": "appsec-review/job-handoff/1", "job_id": job_id, "attempt_id": "attempt_0001",
                       "status": "ACCEPTED", "completion_status": "SUCCEEDED", "outputs": dict(outputs),
                       "artifacts": artifacts, "source_fingerprint": snapshot,
                       "resolving_paths": {"attempt": attempt.relative_to(run_root).as_posix()}})
    identity = _artifact(run_root, path)
    atomic_json(attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001", "handoff_path": identity["path"],
        "handoff_sha256": identity["sha256"]})
    return identity


def _location(target: Path, snapshot: str, path: str, line: int = 1, column: int = 1, end_line: int | None = None,
              end_column: int | None = None, method: str = "fixture-exact") -> SourceLocation:
    data = (target / path).read_bytes()
    if end_line is None:
        return SourceLocation(snapshot, path, file_sha256(target / path), 0, len(data), 1, max(1, data.count(b"\n")),
                              1, 1, {}, method, 1.0)
    source = SourceFile.from_bytes(data)
    start, end = source.offset(line, column), source.offset(end_line, end_column)
    return SourceLocation(snapshot, path, file_sha256(target / path), start, end, line, end_line, column,
                          end_column, {}, method, 1.0)


class Shards:
    """Accepted upstream shards built with the real ``IndexBuilder``, grouped per producing job."""

    def __init__(self, run_root: Path, snapshot: str) -> None:
        self.run_root, self.snapshot = run_root, snapshot
        self.by_job: dict[str, list[IndexIdentity]] = {}

    def add(self, job_id: str, name: str, shard_id: str, producer: Mapping[str, Any],
            entities: list[EntityRecord], relations: list[RelationRecord] = ()) -> None:
        fingerprint = index_fingerprint(name=name, target_snapshot=self.snapshot, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity=dict(producer), parser_identity="e2e/1",
                                        normalizer_identity="e2e/1", mapping_identity="e2e/1")
        path = self.run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=self.snapshot,
                               shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(shard_id, "complete")
        self.by_job.setdefault(job_id, []).append(IndexIdentity(
            name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
            path.relative_to(self.run_root).as_posix(), {"job": job_id, **producer}, (), shard_id))

    def manifest(self, job_id: str, target: Path, run_id: str) -> dict[str, Any]:
        path = self.run_root / "data" / "indices" / "manifests" / f"{job_id}-attempt_0001.json"
        write_manifest(path, run_id=run_id, target_snapshot=self.snapshot, target_root=target,
                       indexes=self.by_job[job_id])
        return _artifact(self.run_root, path)


def _stage_upstream(run_root: Path, run_id: str, target: Path, snapshot: str) -> dict[str, str]:
    """Catalog shards (accepted), clangd shards (only in their handoff) and the CodeQL plan's handoffs."""
    ids: dict[str, str] = {}
    shards = Shards(run_root, snapshot)
    files = {SYNTHETIC_PATH: "C++", "native/main.cpp": "C++", "native/helper.c": "C", PYTHON_PATH: "Python"}
    source_entities = []
    for path, language in files.items():
        identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": path})
        ids[path] = identity.value
        source_entities.append(EntityRecord(identity, path, path, path, {"language": language, "path": path},
                                            _location(target, snapshot, path)))
    shards.add("job_target_catalog", "source", "default", {}, source_entities)
    components = []
    for root in ("src", "native", "svc"):
        identity = LogicalIdentity.derive(EntityKind.COMPONENT, snapshot, {"component_id": f"component:{root}"})
        ids[f"component:{root}"] = identity.value
        components.append(EntityRecord(identity, f"component:{root}", f"component:{root}", root,
                                       {"component_id": f"component:{root}", "root": root}))
    shards.add("job_target_catalog", "components", "default", {}, components)
    units = []
    for unit, root, languages in ((SRC_UNIT, "src", ["C++"]), (NATIVE_UNIT, "native", ["C", "C++"])):
        identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, snapshot, {"id": unit, "root": root})
        ids[f"unit:{root}"] = identity.value
        units.append(EntityRecord(identity, unit, "cmake", unit, {"build_unit_id": unit, "root": root,
                                                                    "build_system": "cmake", "languages": languages}))
    shards.add("job_target_catalog", "build", "default", {}, units)
    # Required catalog datasets this test has no content for: published empty, with complete coverage.
    shards.add("job_target_catalog", "analysis", "declaration-symbols", {}, [])
    shards.add("job_target_catalog", "documents", "default", {}, [])
    catalog =shards.manifest("job_target_catalog", target, run_id)
    catalog_handoff = _handoff(run_root, snapshot, "job_target_catalog",
                               {"retrieval_indexes.publish": {"index_manifest": catalog}}, [catalog])

    # clangd over the synthetic source; published by job_cpp_symbol_index's own manifest only.
    clangd: dict[str, str] = {}
    entities = []
    for name, (line, column) in CLANGD_SYMBOLS.items():
        identity = LogicalIdentity.derive(EntityKind.SYMBOL, snapshot, {"producer": "clangd", "clangd_id": name})
        clangd[name] = identity.value
        entities.append(EntityRecord(identity, name.upper(), name, f"Function {name}", {
            "producer": "clangd", "kind": "Function",
            "definition": {"path": SYNTHETIC_PATH, "line": line, "column": column, "end_line": line,
                           "end_column": column + len(name)}},
            _location(target, snapshot, SYNTHETIC_PATH, line, column, line, column + len(name),
                      "clangd-uri-exact-path")))
    relations = [RelationRecord(RelationKind.CALLS, clangd[caller], clangd[callee], True, 1.0, None, {
        "producer": "clangd", "occurrences": 1,
        "locations": [{"path": SYNTHETIC_PATH, "line": line, "column": column, "ref_kind": 28}]})
        for (caller, callee), (line, column) in CLANGD_CALLS.items()]
    shards.add("job_cpp_symbol_index", "analysis", "clangd-cpp-scope-src", {"unit": "index.scopes"},
               entities, relations)
    ids.update({f"clangd:{name}": value for name, value in clangd.items()})
    symbols = shards.manifest("job_cpp_symbol_index", target, run_id)
    _handoff(run_root, snapshot, "job_cpp_symbol_index", {"acceptance.publish_handoff": {"index_manifest": symbols}},
             [symbols])
    for job_id in ("job_language_build", "job_artifact_indexing", "job_cpp_compiled_analysis"):
        _handoff(run_root, snapshot, job_id, {}, [])
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": catalog_handoff["path"], "handoff_sha256": catalog_handoff["sha256"],
        "manifest_path": catalog["path"], "manifest_sha256": catalog["sha256"]})
    return ids


# ------------------------------------------------------------------------------------------------ CodeQL doubles


def _sarif_region(line: int, column: int, end_line: int, end_column: int) -> dict[str, Any]:
    return {"artifactLocation": {"uri": "synthetic.cpp"},
            "region": {"startLine": line, "startColumn": column, "endLine": end_line, "endColumn": end_column}}


SARIF_RULE = {"id": "cpp/unbounded-write", "name": "UnboundedWrite",
              "properties": {"kind": "path-problem", "security-severity": "9.3", "precision": "high",
                             "tags": ["security", "external/cwe/cwe-120", "external/cwe/cwe-787"]}}


def _sarif(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": [SARIF_RULE]}},
                                          "results": results}]}


BRIDGED_RESULT = {
    "ruleId": "cpp/unbounded-write", "level": "error",
    "message": {"text": "memcpy length depends on an environment variable"},
    "locations": [{"physicalLocation": _sarif_region(*BRIDGED_FLOW[-1])}],
    "partialFingerprints": {"primaryLocationLineHash": "e2e-bridged"},
    "codeFlows": [{"threadFlows": [{"locations": [
        {"location": {"physicalLocation": _sarif_region(*step), "message": {"text": f"step {index}"}}}
        for index, step in enumerate(BRIDGED_FLOW)]}]}],
}


class FakeResolver:
    def __init__(self, **_kwargs: Any) -> None:
        pass

    def resolve(self, *, build_image_tag: str, build_image_id: str, runtime_user: str):
        image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, IMAGE_ID, build_image_id,
                            build_image_tag, IMAGE_ID, "codeql:e2e", runtime_user, "b" * 64, "c" * 64, True,
                            "manifest.json")
        return image, b"", b""


class FakeExecutor:
    """Stands in for the CodeQL runner container; every action writes what the runner would."""

    calls: list[tuple[str, str]] = []

    def __init__(self, *, image: Any, run_root: Path, settings: Any, **_kwargs: Any) -> None:
        self.image, self.run_root, self.settings = image, run_root, settings

    def execute(self, action: str, argv, *, scratch_root: Path):
        values = dict(zip(argv[::2], argv[1::2]))
        FakeExecutor.calls.append((action, scratch_root.name))
        if action == "inventory":
            atomic_json(scratch_root / values["--output"], {
                "schema": "appsec-review/codeql-extractor-inventory/1", "languages": ["actions", "cpp", "python"],
                "roots": {}, "extractors": {}, "query_packs": {}, "prerequisites": {}})
        elif action == "database":
            database = scratch_root / values["--database"]
            (database / "db").mkdir(parents=True)
            (database / "db" / "default.trap").write_text("e2e database", encoding="utf-8")
            (database / "source-subroot.txt").write_text(values["--source-subroot"], encoding="utf-8")
        elif action == "query":
            subroot = (scratch_root / values["--database"] / "source-subroot.txt").read_text(encoding="utf-8")
            default = (values.get("--pack") == "codeql/cpp-queries"
                       and values.get("--suite") == "codeql-suites/cpp-code-scanning.qls")
            results = [BRIDGED_RESULT] if subroot == "src" and default else []
            output = scratch_root / values["--output"]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(_sarif(results)), encoding="utf-8")
        elif action == "compile":
            pass  # the export pack precompile warms a cache; the fake has nothing to compile
        elif action == "export":
            subroot = (scratch_root / values["--database"] / "source-subroot.txt").read_text(encoding="utf-8")
            recording = {"src": "synthetic", "native": "native", "svc": "python-synthetic"}[subroot]
            shutil.copytree(EXPORTS / recording / "exports", scratch_root / values["--output-dir"])
        else:
            raise AssertionError(f"unexpected CodeQL action {action}")
        atomic_json(scratch_root / "executions" / action / "receipt.json",
                    {"schema": "appsec-review/codeql-execution/2", "action": action})
        return SimpleNamespace(exit_code=0, timed_out=False, duration_ms=1, stdout_truncated=False,
                               stderr_truncated=False)


def _receipt(unit: str, root: str) -> dict[str, Any]:
    image = {"image_id": IMAGE_ID, "image_tag": "build:e2e", "user": "10001:10001"}
    return {"build_unit_id": unit, "family": "native", "root": root, "terminal_status": "SUCCEEDED",
            "workspace": f"data/jobs/job_language_build/workspaces/{root}",
            "commands": [{"role": "build", "argv_sha256": "d" * 64}],
            "recipe": {"build_commands": [["cmake", "--build", "."]]}, "image": image,
            "recipe_identity": hashlib.sha256(root.encode()).hexdigest(), "dependency_identity": "e" * 64,
            "workspace_manifest": None, "fingerprint": hashlib.sha256(unit.encode()).hexdigest()}


def _install_codeql_doubles(monkeypatch, target: Path, snapshot: str) -> None:
    files = [{"path": path.relative_to(target).as_posix(), "sha256": file_sha256(path),
              "size_bytes": path.stat().st_size} for path in sorted(target.rglob("*")) if path.is_file()]
    catalog = SimpleNamespace(source_fingerprint=snapshot, files=tuple(files), projects=({"root": "svc"},))
    receipts = [_receipt(SRC_UNIT, "src"), _receipt(NATIVE_UNIT, "native")]
    monkeypatch.setattr(codeql_job, "load_target_catalog", lambda run_root: catalog)
    monkeypatch.setattr(codeql_job, "load_accepted_language_build",
                        lambda run_root: {"source_fingerprint": snapshot, "receipts": receipts})
    monkeypatch.setattr(codeql_job, "_accepted_replay", lambda unit, receipt: {
        "schema": "appsec-review/codeql-build-replay/1", "commands": [], "recipe_identity": receipt["recipe_identity"],
        "build_image_id": IMAGE_ID, "dependency_hashes": {}, "protected_commands": []})
    monkeypatch.setattr(codeql_job, "CodeQLImageResolver", FakeResolver)
    monkeypatch.setattr(codeql_job, "CodeQLExecutor", FakeExecutor)


# ------------------------------------------------------------------------------------------------ worker


class GraphWorker:
    """Deterministic review worker that reasons only from graph identities it was given or retrieved."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    @staticmethod
    def _final(result: Mapping[str, Any]) -> ModelResult:
        return ModelResult({"schema": TURN_SCHEMA, "action": "final", "result": dict(result)}, input_tokens=50,
                           output_tokens=20)

    @staticmethod
    def _retrieve(*requests: Mapping[str, Any]) -> ModelResult:
        return ModelResult({"schema": TURN_SCHEMA, "action": "retrieve", "requests": list(requests)},
                           input_tokens=50, output_tokens=10)

    @staticmethod
    def _rows(request, kind: str) -> list[Mapping[str, Any]]:
        return [row for turn in request.transcript if turn.get("from") == "application"
                for response in turn["responses"] for row in response.get("results", ())
                if row.get("kind") == kind]

    def __call__(self, request, *, timeout_seconds: int) -> ModelResult:
        task = request.task_input
        self.calls.append({"role": request.role, "task": task.get("task"), "turn": len(request.transcript) // 2})
        payload = task["input"]
        if request.role == "red_team_analyst":
            return self._lead_red(task, payload)
        if request.role == "hypothesis_hunter":
            return self._hunter(request, payload)
        if request.role == "blue_team_refuter":
            return self._final({"stance": "unresolved",
                                "why": "no dominating guard and no reachability break was found here"})
        if request.role == "independent_verifier":
            return self._verifier(request, payload)
        raise AssertionError(request.role)

    @staticmethod
    def _view_rows(payload: Mapping[str, Any], section: str) -> list[Mapping[str, Any]]:
        return list(payload["package"]["neighborhood"][section])

    def _lead_red(self, cell_input: Mapping[str, Any], payload: Mapping[str, Any]) -> ModelResult:
        sinks, paths = self._view_rows(payload, "sinks"), self._view_rows(payload, "flows")
        if cell_input["task"] != "lead_red_stack" or not sinks or not paths:
            return self._final(red_result(cell_input))
        lead = payload["package"]["leads"][0]["ref"]
        # The sink and the correlated dataflow path are cited; the lead observation is not, so it never becomes
        # a relation (the compact answer carries no taint hops).
        proposal = Proposal(
            "g1", [sinks[0]["ref"]], None, "memory_corruption", ["attacker_controls_environment_variable"],
            "the INPUT_LEN environment variable bounds a memcpy into a 64 byte stack buffer",
            support=[("affected_construct", sinks[0]["ref"]), ("source_to_sink_reachability", paths[0]["ref"])],
            leads=[lead])
        return self._final(red_result(cell_input, [proposal]))

    def _hunter(self, request, payload: Mapping[str, Any]) -> ModelResult:
        sinks = sorted(row["ref"] for row in self._view_rows(payload, "sinks"))
        empty = red_result(request.task_input)
        if payload.get("strategy") != "sink_up" or not sinks:
            return self._final(empty)
        if not request.transcript:
            # Graph rows of this unit's CodeQL scope are granted; the sink's enclosing symbol is not in the
            # package, so asking for its callers works only through the scope-bound graph grant.
            return self._retrieve({"tool": "query_code_graph", "parameters": {"mode": "guards", "subject": sinks[0]}},
                                  {"tool": "find", "parameters": {"identity": sinks[0]}})
        if len(request.transcript) == 2:
            found = self._rows(request, "sink_site")
            symbol = found[0]["payload"]["result"]["enclosing_function"]["symbol"] if found else None
            if symbol:
                return self._retrieve({"tool": "query_code_graph", "parameters": {"mode": "callers", "subject": symbol}})
        return self._final(empty)

    def _verifier(self, request, payload: Mapping[str, Any]) -> ModelResult:
        claim = payload["claim"]
        by_label = {row["label"]: row["ref"] for row in self._view_rows(payload, "sinks")}
        sink = by_label[claim["affected"][0]["label"]]
        if not request.transcript:
            return self._retrieve({"tool": "query_code_graph", "parameters": {"mode": "paths", "subject": sink}},
                                  {"tool": "query_code_graph", "parameters": {"mode": "guards", "subject": sink}})
        paths = [row for row in self._rows(request, "dataflow_path")
                 if row["payload"]["admissibility"]["direct_eligible"]]
        guards = [row for row in self._rows(request, "guard_fact")
                  if row["payload"]["result"]["guard_state"] in {"none", "non_dominating"}
                  and row["payload"]["admissibility"]["direct_eligible"]]
        cited = {"affected_construct": [sink]}
        for predicate in ("source_to_sink_reachability", "attacker_input_control"):
            if paths:
                cited[predicate] = [paths[0]["identity"]]
        if guards:
            cited["missing_or_ineffective_guard"] = [guards[0]["identity"]]
        return self._final({"disposition": "supported", "why": "re-derived the path and the guard state at the sink",
                            "per_predicate": {predicate: {"stance": "supports", "cites": refs}
                                              for predicate, refs in cited.items()}})


# ------------------------------------------------------------------------------------------------ pipeline


def _outputs(outcome: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads((Path(outcome["attempt_root"]) / "result.json").read_text(encoding="utf-8"))["outputs"]


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _offline_fts(unit):
    raise RuntimeError("the pinned FTS5 image is not available in the offline end-to-end test")


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory) -> SimpleNamespace:
    # The export precompile remembers warm caches per process; this test asserts the cold compile ran.
    codeql_job._PRECOMPILED.clear()
    base = tmp_path_factory.mktemp("e2e")
    target = base / "target"
    (target / "src").mkdir(parents=True)
    shutil.copyfile(EXPORTS / "synthetic" / "source" / "synthetic.cpp", target / SYNTHETIC_PATH)
    (target / "native").mkdir()
    for name in ("main.cpp", "helper.c"):
        shutil.copyfile(NATIVE_SOURCES / name, target / "native" / name)
    (target / "svc").mkdir()
    shutil.copyfile(EXPORTS / "python-synthetic" / "source" / "app.py", target / PYTHON_PATH)
    # A GitHub Actions workflow: a CodeQL language with no graph export pack.
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / WORKFLOW_PATH).write_text("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                        "    steps:\n      - run: echo ok\n", encoding="utf-8")
    snapshot = source_fingerprint(target)
    loaded = load_config(ROOT / "appsec-review.toml")
    # The recordings are whole-program exports; a seeded scope would need seeds from evidence.
    codeql_config = loaded.jobs["job_codeql_analysis"]
    codeql_settings = codeql_config.typed_settings
    loaded = replace(loaded, jobs={**loaded.jobs, "job_codeql_analysis": replace(
        codeql_config, typed_settings=replace(codeql_settings, export_queries=replace(
            codeql_settings.export_queries, mode="whole_program")))})
    config = replace(loaded, runtime=replace(loaded.runtime, runs_dir=base / "runs", data_dir=base / "data",
                                             metadata_dir=base / "runs" / "metadata"))
    runner = JobRunner(config)
    run_id, run_root = runner.runs.create(datetime(2026, 10, 12, tzinfo=timezone.utc))
    runner._bind_configuration(run_root)
    ids = _stage_upstream(run_root, run_id, target, snapshot)
    worker = GraphWorker()
    FakeExecutor.calls = []

    def run(job) -> Mapping[str, Any]:
        return JobRunner(config).run(job, run_id=run_id, target_root=target, source_fingerprint=snapshot)

    with pytest.MonkeyPatch.context() as monkeypatch:
        _install_codeql_doubles(monkeypatch, target, snapshot)
        codeql = run(codeql_job.build_job())
    graph = run(build_graph_job())
    indexing = run(build_indexing_job(executor_factory=_offline_fts))
    review = run(build_review_job(infer=worker, repository_root=ROOT))
    return SimpleNamespace(base=base, target=target, snapshot=snapshot, config=config, run_id=run_id,
                           run_root=run_root, ids=ids, worker=worker, codeql=codeql, graph=graph,
                           indexing=indexing, review=review)


def _review_unit(pipeline, unit_id: str) -> Path:
    step, task = unit_id.split(".")
    return Path(pipeline.review["attempt_root"]) / "steps" / step / "tasks" / task


def _graph_facts(pipeline) -> dict[str, dict[str, Any]]:
    path, sha = resolve_accepted_manifest(pipeline.run_root)
    manifest, _ = load_verified_manifest(pipeline.run_root, path, sha)
    shards = [item for item in manifest["indexes"] if item["name"] == GRAPH_INDEX]
    return {row["identity"]: dict(row) for row in ShardSet(pipeline.run_root, shards).entities(shards)}


# ------------------------------------------------------------------------------------------------ tests


def test_codeql_publishes_what_the_graph_job_reads_and_build_units_match(pipeline) -> None:
    for outcome in (pipeline.codeql, pipeline.graph, pipeline.indexing, pipeline.review):
        assert outcome["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome["status"]
    codeql = _outputs(pipeline.codeql)
    # Full unit outputs live in the hash-bound result, not the handoff's compact output projection.
    handoff = _json(Path(pipeline.codeql["attempt_root"]) / "handoff.json")
    bound = {item["path"] for item in handoff["artifacts"]}
    assert codeql["plan.inventory"]["plan"]["path"] in bound
    assert codeql["execution.scopes"]["graph_export_artifact"]["path"] in bound
    assert "graph_export_artifact" not in handoff["outputs"]["execution.scopes"]
    exports = {item["scope_id"]: item for item in codeql["execution.scopes"]["exports"]}
    by_root = {item["root"]: item for item in exports.values()}
    assert by_root["src"]["export_status"] == by_root["native"]["export_status"] == "SUCCEEDED"
    assert by_root["svc"]["export_status"] == "SUCCEEDED"
    assert {item["language"]: item["export_status"] for item in exports.values()}["actions"] == "NOT_APPLICABLE"
    assert {action for action, _scope in FakeExecutor.calls} == {"inventory", "database", "query", "export", "compile"}
    graph = _outputs(pipeline.graph)
    loaded = graph["load.accepted_inputs"]
    assert {scope["scope_id"] for scope in loaded["scopes"]} == set(exports)
    # The clangd shard was dropped by the CodeQL manifest rewrite and restored from its own handoff.
    assert [item["shard_id"] for item in loaded["restored_secondary"]] == ["clangd-cpp-scope-src"]
    crosscheck = {item["scope_id"]: item for item in graph["crosscheck.scopes"]["scopes"]}
    assert crosscheck[by_root["src"]["scope_id"]]["states"].get("agree", 0) >= 1
    # Package build-unit ids are the CodeQL build_unit_id the graph shards publish.
    path, sha = resolve_accepted_manifest(pipeline.run_root)
    manifest, _ = load_verified_manifest(pipeline.run_root, path, sha)
    graph_units = {item["producer"]["build_unit_id"] for item in manifest["indexes"] if item["name"] == GRAPH_INDEX}
    assert graph_units == {SRC_UNIT, NATIVE_UNIT, None}
    scope = accept_manifest(pipeline.run_root)
    assert {unit.build_unit_id for unit in scope.build_units} == {SRC_UNIT, NATIVE_UNIT}
    lead_packages = _json(_review_unit(pipeline, "packages.assemble_lead_packages") / "lead-packages.json")
    documents = [_json(pipeline.run_root / item["path"]) for item in lead_packages["packages"]]
    (lead,) = [item for item in documents if item["lead_family"] == "codeql"]
    assert lead["scope"]["build_unit_id"] == SRC_UNIT
    assert lead["retrieval"]["graph_scopes"] == [by_root["src"]["scope_id"]]
    assert {entry["role"] for entry in lead["context"]} >= {"path", "sink", "entry_point", "guard", "range"}
    for exported in exports.values():
        assert all(export["export_manifest"]["path"] in bound for export in [exported]
                   if export["export_status"] == "SUCCEEDED")


def test_a_bridged_codeql_lead_is_confirmed_by_direct_graph_relations(pipeline) -> None:
    facts = _graph_facts(pipeline)
    adjudications = _json(_review_unit(pipeline, "adjudicate.apply_policy") / "adjudications.json")["adjudications"]
    (decided,) = [item for item in adjudications if item["state"] in {"supported", "confirmed"}]
    # Blindness and re-derived evidence establish independence; model distinctness gates ship-blocking only.
    assert decided["verifier_independent"] is True
    assert decided["state"] == "confirmed" and decided["deciding_row"] == "r5_confirmed"
    ledger = [json.loads(line) for line in (_review_unit(pipeline, "publication.publish_claim_ledger")
                                            / "claim-ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    relations = {event["body"]["relation"]["relation_id"]: event["body"]["relation"] for event in ledger
                 if event["kind"] == "relation_added"}
    counted = [relations[item] for status in decided["predicates"] for item in status["supporting"]]
    direct = {(item["predicate"], item["entity_kind"]) for item in counted
              if item["admissibility"] == "direct_for_mapped_predicate"}
    assert ("affected_construct", "sink_site") in direct
    assert ("source_to_sink_reachability", "dataflow_path") in direct
    assert ("missing_or_ineffective_guard", "guard_fact") in direct
    assert ("attacker_input_control", "dataflow_path") in direct
    path = next(facts[item["entity_id"]] for item in counted if item["entity_kind"] == "dataflow_path")
    assert path["payload"]["result"]["source"]["source_class"] == "environment"
    # The cited path is the one correlated `bridged` with the CodeQL observation.
    path_manifest = resolve_accepted_manifest(pipeline.run_root)
    manifest, _ = load_verified_manifest(pipeline.run_root, *path_manifest)
    shards = [item for item in manifest["indexes"] if item["name"] == GRAPH_INDEX]
    states = {row["payload"]["state"] for row in ShardSet(pipeline.run_root, shards).relations(
        shards, kinds=("DERIVED_FROM",)) if row["source_id"] == path["identity"] and row["payload"]}
    assert states == {"bridged"}


def test_red_citations_of_graph_facts_become_direct_relations_and_the_lead_is_never_cited(pipeline) -> None:
    lane = _json(_review_unit(pipeline, "lead_review.teams") / "lane.json")
    reds = {row["cell_id"] for row in lane["capabilities"] if row["role"] == "red_team_analyst"}
    ledger = [json.loads(line) for line in (_review_unit(pipeline, "publication.publish_claim_ledger")
                                            / "claim-ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    red = [event["body"]["relation"] for event in ledger
           if event["kind"] == "relation_added" and event["body"]["relation"]["producing_cell_id"] in reds]
    cited = {(item["predicate"], item["entity_kind"], item["admissibility"]) for item in red}
    # The cited graph facts became direct relations through resolve_relation...
    assert ("source_to_sink_reachability", "dataflow_path", "direct_for_mapped_predicate") in cited
    assert ("affected_construct", "sink_site", "direct_for_mapped_predicate") in cited
    # ...while the lead observation, which red did not cite, never became one.
    assert not any(item["entity_kind"] == "tool_observation" for item in red)
    # Every package lead is accounted; a lens that proposed nothing is never clean coverage.
    outcomes = {lead["outcome"] for leads in lane["lead_accounting"].values() for lead in leads.values()}
    assert "proposal" in outcomes and outcomes <= {"proposal", "no_proposal", "blocked", "unaccounted"}
    assert _json(pipeline.run_root / lane["chain_seeds"]["path"])["seeds"] == []


def test_scoring_reads_graph_factors(pipeline) -> None:
    root = _review_unit(pipeline, "scoring.score_claims")
    (score,) = _json(root / "scores.json")["scores"]
    package = _json(root / "scores" / score["file"])
    factors = {factor["factor"]: factor for factor in package["factors"]}
    assert factors["taint_path"]["value"] == "graph_dataflow_path"
    assert factors["taint_path"]["detail"] == {"entity_kind": ["dataflow_path"]}
    # getenv is the catalog's ``environment`` source class: attacker-reachable and local.
    assert factors["attacker_control"]["value"] == "local"
    assert factors["attacker_control"]["detail"] == {"source_class": ["environment"]}
    assert factors["guard_absent"]["value"] == "graph_fact"
    cited = {item["factor"]: item["entities"] for item in package["factor_citations"]}
    assert all(entity.startswith("asr:dataflow_path:") for entity in cited["taint_path"] + cited["attacker_control"])


def test_a_hunt_unit_with_sink_and_entry_facts_launches_sink_up_and_entry_down(pipeline) -> None:
    lane = _json(_review_unit(pipeline, "hunt_review.teams") / "lane.json")
    hunt_packages = _json(_review_unit(pipeline, "packages.assemble_hunt_packages") / "hunt-packages.json")
    synthetic = [item for item in hunt_packages["packages"]
                 if {"sink_site", "entry_point"} <= set(_json(pipeline.run_root / item["path"])["retrieval"]
                                                        ["graph_families"])]
    assert synthetic
    # A unit whose scope has no graph facts falls back to persona sweeps with a named gap.
    assert any(row["status"] == "gap" and row["reason"].startswith("required_source_unavailable")
               for row in lane["coverage"])
    strategies = {row["strategy"] for row in lane["coverage"] if row["package_id"] in {
        item["package_id"] for item in synthetic} and row["status"] != "gap"}
    assert {"sink_up", "entry_down"} <= strategies
    # The sink_up hunter used the scope-bound graph grant: nothing it asked for was withheld or denied.
    receipts = [_json(path) for path in (pipeline.run_root / "data" / "jobs" / "job_inference_security_review"
                                         / "cells").glob("*/attempt-*.json")]
    graph_calls = [call for receipt in receipts for turn in receipt["turns"] for call in turn["retrievals"]
                   if call["tool"] == "query_code_graph"]
    assert graph_calls and all(call["status"] == "executed" and call["withheld_count"] == 0
                               for call in graph_calls)
    # The hunter reached its third turn, so its callers query on the granted symbol was authorized.
    assert any(call["role"] == "hypothesis_hunter" and call["turn"] == 2 for call in pipeline.worker.calls)


def test_the_completeness_ledger_names_the_code_graph_lane_for_an_uncovered_language(pipeline) -> None:
    matrices = _json(Path(pipeline.indexing["attempt_root"]) / "steps" / "matrix" / "tasks" / "coverage"
                     / "coverage-matrices.json")
    lanes = {row["language"]: row for row in matrices["languages"]}
    assert lanes["python"]["lanes"]["code_graph"]["state"] in {"complete", "partial"}
    assert lanes["c/c++"]["lanes"]["code_graph"]["state"] in {"complete", "partial"}
    assert lanes["actions"]["lanes"]["code_graph"]["state"] == "unavailable"
    ledger = (_review_unit(pipeline, "completeness.audit") / "ledger.jsonl").read_text(encoding="utf-8")
    gaps = [json.loads(line)["body"]["gap"] for line in ledger.splitlines()
            if json.loads(line)["kind"] == "gap_recorded"]
    graph = [gap for gap in gaps if gap["subject_id"].startswith("producer:code_graph:")]
    actions_scope = next(item["scope_id"] for item in _outputs(pipeline.codeql)["execution.scopes"]["exports"]
                         if item["language"] == "actions")
    assert any(actions_scope in gap["subject_id"] and "no hash-pinned CodeQL graph export pack for actions"
               in gap["reason"] for gap in graph)


def test_a_byte_flip_in_any_graph_shard_fails_scope_acceptance(pipeline) -> None:
    path, sha = resolve_accepted_manifest(pipeline.run_root)
    manifest, _ = load_verified_manifest(pipeline.run_root, path, sha)
    shards = [item for item in manifest["indexes"] if item["name"] == GRAPH_INDEX]
    # Seven family shards for each of three scopes plus one database card and one producers shard per scope.
    assert len(shards) == 27
    assert sum(item["producer"].get("kind") == "codeql_database" for item in shards) == 3
    accept_manifest(pipeline.run_root)
    for shard in shards:
        target = pipeline.run_root / shard["relative_path"]
        original = target.read_bytes()
        flipped = bytearray(original)
        flipped[len(flipped) // 2] ^= 0x01
        target.write_bytes(bytes(flipped))
        try:
            with pytest.raises(IntegrityError):
                accept_manifest(pipeline.run_root)
        finally:
            target.write_bytes(original)
    accept_manifest(pipeline.run_root)


def test_joern_is_disabled_by_default_publishes_unavailable_rows_and_runs_no_container(tmp_path: Path) -> None:
    from tests.test_cpp_index_jobs import IndexExecutor, _accepted_cpp, _outputs as cpp_outputs, _rows, _run
    from appsec_review.jobs.job_cpg_analysis import JOERN_DISABLED, build_job as build_cpg

    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, joern=False)
    calls: list[str] = []
    outcome = _run(config, target, run_id, fingerprint,
                   build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls)))
    assert calls == []
    published = cpp_outputs(outcome, "job_cpg_analysis")["acceptance.publish_handoff"]
    run_root = config.runtime.runs_dir / run_id
    manifest, _ = load_verified_manifest(run_root, run_root / published["index_manifest"]["path"],
                                         published["index_manifest"]["sha256"])
    joern = [item for item in manifest["indexes"] if item["producer"].get("job") == "job_cpg_analysis"]
    assert joern
    for shard in joern:
        rows = _rows(run_root, shard, "SELECT status, gap FROM coverage")
        assert rows and all(status == "unavailable" and JOERN_DISABLED in (gap or "") for status, gap in rows)
        assert _rows(run_root, shard, "SELECT COUNT(*) FROM entities WHERE kind = 'tool_observation'") == [(0,)]
