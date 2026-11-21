from __future__ import annotations

import copy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import BuildEnvironmentSettings, load_config
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.job_build_environment_analysis.datasets import DATASETS as ENV_DATASETS
from appsec_review.jobs.job_build_environment_analysis.job import (
    RULES,
    SCHEMA as ENV_SCHEMA,
    optional_prior_environment_handoffs,
    planning_environment_inputs,
)
from appsec_review.jobs.job_target_analysis_plan import (
    __all__ as public_exports,
    build_job,
    job as planner,
    load_accepted_plan,
)
from appsec_review.jobs.job_target_analysis_plan.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_target_catalog import reader as catalog_reader
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PLAN_SCHEMA,
    deterministic_plan,
    summarize_catalog,
    validate_plan,
)
from appsec_review.orchestration.topology import wave1_dependencies
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.handoff import verify_handoff_integrity
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[3]
JOB = "job_target_analysis_plan"
ENVIRONMENT = "job_build_environment_analysis"
SOURCE = "synthetic-planner-source"
UNIT = "catalog_summary.load_accepted_catalog"
CATALOG_SHA = "c" * 64


def test_every_input_requirement_field_and_dispatch_policy_is_pinned() -> None:
    assert set(public_exports) == {"build_job", "load_accepted_plan"}
    rows = [
        (ENVIRONMENT, "handoff", "appsec-review/job-handoff/2", "operational"),
        (ENVIRONMENT, "build_environment", ENV_SCHEMA, "operational"),
        ("job_review_intake", "handoff", "appsec-review/job-handoff/2", "producer_evidence"),
        ("job_review_intake", "model_preflight", "appsec-review/model-preflight/1", "producer_evidence"),
        ("job_review_intake", "binary_evidence", "appsec-review/binary-evidence-intake/1", "producer_evidence"),
        ("job_review_intake", "review_intake", "appsec-review/review-intake/1", "producer_evidence"),
        ("job_source_history_analysis", "handoff", "appsec-review/job-handoff/2", "routing_context"),
        ("job_source_history_analysis", "history_signals", "appsec-review/retrieval-index/2", "routing_context"),
        ("job_source_history_analysis", "history_documents", "appsec-review/source-history-analysis/2", "routing_context"),
        ("job_source_history_analysis", "raw_git_history", "application/octet-stream", "routing_context"),
        ("job_source_history_analysis", "history_tool_io", "appsec-review/container-execution/1", "routing_context"),
        ("job_target_catalog", "handoff", "appsec-review/job-handoff/2", "producer_evidence"),
        ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1", "producer_evidence"),
        ("job_target_catalog", "source_files", "appsec-review/retrieval-index/2", "producer_evidence"),
        ("job_target_catalog", "declaration_symbols", "appsec-review/retrieval-index/2", "producer_evidence"),
        ("job_target_catalog", "components", "appsec-review/retrieval-index/2", "producer_evidence"),
        ("job_target_catalog", "target_documents", "appsec-review/retrieval-index/2", "producer_evidence"),
        ("job_target_catalog", "build_units", "appsec-review/retrieval-index/2", "producer_evidence"),
        ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1", "producer_evidence"),
    ]
    expected = []
    for producer, kind, schema, authority in rows:
        hard = (producer, kind) == ("job_target_catalog", "handoff")
        enabled = (producer, kind) == (ENVIRONMENT, "handoff")
        expected.append({
            "producer": producer, "output_kind": kind, "schema": schema, "authority": authority,
            "availability": "required" if hard else "when_producer_enabled" if enabled else "optional",
            "missing": "reject" if hard else "gap", "coverage": "allow_partial", "channel": "handoff",
        })
    assert [asdict(item) for item in CONTRACT.inputs] == expected
    assert {key: value for key, value in asdict(CONTRACT).items() if key != "inputs"} == {
        "schedule_after": ("job_ci_configuration_analysis", "job_source_history_analysis", ENVIRONMENT),
        "dispatch": "review_graph", "target_access": "checkout",
        "always_execute": False, "propagate_handoff": True,
    }
    assert CONTRACT.consumes == CONSUMES == (
        ENVIRONMENT, "job_review_intake", "job_source_history_analysis", "job_target_catalog",
    )


def test_every_dataset_field_and_topology_registration_is_pinned() -> None:
    common = {
        "family": "analysis_plan", "indexes": (), "shard_prefixes": (), "shard_suffixes": (),
        "required": False, "store": "retrieval", "authority": "producer_evidence",
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
    }
    assert [asdict(item) for item in DATASETS] == [
        {
            **common, "output_kind": "planning_feedback_cache", "step": "analysis_decisions",
            "schema": "appsec-review/target-analysis-proposal/3", "sensitivity": "sensitive",
            "disposition": "protected",
            "description": "Validated complete bounded feedback and exact additive evidence.",
            "artifacts": ("data/planning-feedback/*.json",),
            "reason": "immutable source/environment/profile/prompt/model keyed cache; not a retrieval endpoint",
        },
        {
            **common, "output_kind": "analysis_plan", "step": "plan_acceptance",
            "schema": "appsec-review/retrieval-index/2", "sensitivity": "internal",
            "disposition": "indexed",
            "description": "Accepted components, scanner selections and planned build actions.",
            "indexes": ("analysis",), "shard_prefixes": ("target-analysis-plan",), "artifacts": (),
            "query_route": "find/search/trace index=analysis shard=target-analysis-plan",
            "required": True, "reason": None,
        },
        {
            **common, "output_kind": "analysis_plan_documents", "step": "plan_acceptance",
            "schema": "appsec-review/target-analysis-plan/1", "sensitivity": "sensitive",
            "disposition": "artifact_only",
            "description": "Catalog summary and accepted analysis plan documents.",
            "artifacts": ("data/jobs/job_target_analysis_plan/attempts/*/artifacts/analysis-plan/*.json",),
            "reason": "source documents of the analysis-plan shard; accepted recipes carry exact commands",
        },
    ]
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    registry.require_matches(config.jobs.keys(), surface="test")
    deps = wave1_dependencies(set(config.jobs))
    assert deps is not None and deps[JOB] == (
        "job_ci_configuration_analysis", "job_source_history_analysis", ENVIRONMENT,
    )


def test_graph_edges_validators_and_identity_transform_are_explicit() -> None:
    built = build_job()
    assert (built.job_id, built.name, built.schema_identity) == (
        JOB, "target_analysis_plan", "appsec-review/target-analysis-plan/1",
    )
    assert built.contract is CONTRACT and built.datasets is DATASETS
    assert built.consumes == CONTRACT.consumes and built.strict_gaps is False
    assert built.input_validators == (planner._validate_config,)
    assert built.output_validators == () and built.result_transform is None
    assert {unit.unit_id: unit.dependencies for unit in built.units} == {
        UNIT: (),
        "catalog_summary.summarize_components": (UNIT,),
        "analysis_decisions.apply_deterministic_rules": (UNIT, "catalog_summary.summarize_components"),
        "analysis_decisions.resolve_ambiguity": (
            "analysis_decisions.apply_deterministic_rules", UNIT, "catalog_summary.summarize_components"),
        "plan_acceptance.validate_plan": ("analysis_decisions.resolve_ambiguity", UNIT),
        "plan_acceptance.index_plan": ("plan_acceptance.validate_plan",),
        "plan_acceptance.publish_handoff": (
            "plan_acceptance.validate_plan", "plan_acceptance.index_plan", "analysis_decisions.resolve_ambiguity"),
    }
    assert [unit.unit_id for unit in built.units] == [
        f"{step}.{task}" for step, tasks in planner.TOPOLOGY.items() for task in tasks
    ]
    assert all(unit.output_validators == () for unit in built.units)
    result = {"status": "SUCCEEDED", "outputs": {}}
    assert built.finalize_result(SimpleNamespace(), result) is result


def test_guidance_bundles_are_group_scoped_immutable_and_reusable(tmp_path: Path) -> None:
    model = {"provider": "claude-cli", "model": "example", "reasoning": "low"}
    arguments = {
        "persona": "persona",
        "role": "role",
        "guidance": load_runtime_skill(ROOT, "target-analysis-planning", job_id=JOB).text,
        "model": model,
        "family": "native",
        "repository_root": ROOT,
    }
    cmake = planner.publish_guidance_bundle(tmp_path, build_system="cmake", **arguments)
    make = planner.publish_guidance_bundle(tmp_path, build_system="make", **arguments)
    assert cmake != make
    assert planner.publish_guidance_bundle(tmp_path, build_system="cmake", **arguments) == cmake
    root = tmp_path / "data" / "guidance"
    assert json.loads((root / cmake / "bundle.json").read_text(encoding="utf-8"))["identity"]["build_system"] == "cmake"
    assert json.loads((root / make / "bundle.json").read_text(encoding="utf-8"))["identity"]["build_system"] == "make"
    (root / cmake / "prompt.md").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="immutable shared artifact conflicts"):
        planner.publish_guidance_bundle(tmp_path, build_system="cmake", **arguments)


def test_artifact_and_read_artifact_enforce_custody_size_and_json_object_bounds(tmp_path: Path) -> None:
    attempt = tmp_path / "data/jobs" / JOB / "attempts/attempt_0001"
    unit = SimpleNamespace(job=SimpleNamespace(attempt_root=attempt, run_root=tmp_path))
    ref = planner._artifact(unit, "plan.json", {"ok": True})
    assert catalog_reader.read_artifact(tmp_path, ref) == {"ok": True}

    with pytest.raises(ValueError, match="exceeds its 32 MiB reader bound"):
        planner._artifact(unit, "huge.json", {"blob": "x" * (32 * 1024 * 1024 + 1)})

    with pytest.raises(ValueError, match="unsupported accepted-artifact byte limit"):
        catalog_reader.read_artifact(tmp_path, ref, byte_limit=1024)
    with pytest.raises(ValueError, match="not run-relative canonical POSIX"):
        catalog_reader.read_artifact(tmp_path, {"path": "../escape.json", "sha256": "0" * 64, "size_bytes": 2})
    with pytest.raises(ValueError, match="unavailable or outside the run"):
        catalog_reader.read_artifact(tmp_path, {"path": "missing.json", "sha256": "0" * 64, "size_bytes": 2})

    arr_path = tmp_path / "array.json"
    raw_arr = b"[1, 2, 3]"
    arr_path.write_bytes(raw_arr)
    with pytest.raises(ValueError, match="must be a JSON object"):
        catalog_reader.read_artifact(tmp_path, {
            "path": "array.json",
            "sha256": hashlib.sha256(raw_arr).hexdigest(),
            "size_bytes": len(raw_arr),
        })
    oversized = tmp_path / "oversized.json"
    with oversized.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="exceeds its byte bound"):
        catalog_reader.read_artifact(tmp_path, {"path": oversized.name},
            before_read=lambda: pytest.fail("oversized payload must not reach hash observation"))


def _write_ref(root: Path, rel_path: str, payload: dict) -> dict:
    path = root / rel_path
    atomic_json(path, payload)
    return {"path": rel_path, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _publish_catalog(root: Path, *, source: str = SOURCE, partition_source: str | None = None,
                     catalog_source: str | None = None, catalog_schema: str = "appsec-review/target-catalog/1",
                     child_schema_override: tuple[str, str] | None = None) -> str:
    attempt = root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    part = _write_ref(root, "data/jobs/job_target_catalog/partition.json", {
        "schema": child_schema_override[1] if child_schema_override and child_schema_override[0] == "partition" else "appsec-review/repository-partition/1",
        "source_fingerprint": partition_source or source,
        "files": [
            {"path": "CMakeLists.txt", "sha256": "1" * 64, "size_bytes": 34},
            {"path": "app.csproj", "sha256": "2" * 64, "size_bytes": 20},
        ],
        "gaps": ["partition_gap"],
    })
    proj = _write_ref(root, "data/jobs/job_target_catalog/projects.json", {
        "schema": "appsec-review/project-catalog/1",
        "projects": [{"root": ".", "kind": "cmake"}],
        "gaps": [],
    })
    comp = _write_ref(root, "data/jobs/job_target_catalog/components.json", {
        "schema": "appsec-review/component-catalog/1",
        "components": [{"component_id": "component:0001", "root": "."}],
        "gaps": [],
    })
    builds = _write_ref(root, "data/jobs/job_target_catalog/builds.json", {
        "schema": "appsec-review/build-systems/4",
        "systems": [{"path": "CMakeLists.txt", "systems": ["cmake"]}],
        "source_only_scopes": ["docs"],
        "gaps": [],
    })
    comp_db = _write_ref(root, "data/jobs/job_target_catalog/compile-db.json", {
        "schema": "appsec-review/compile-commands/1",
        "files": [{"path": "compile_commands.json", "sha256": "3" * 64, "size_bytes": 2}],
        "gaps": [],
    })
    targets = _write_ref(root, "data/jobs/job_target_catalog/targets.json", {
        "schema": "appsec-review/build-targets/2",
        "targets": discover_build_units([
            {"path": "CMakeLists.txt", "sha256": "1" * 64, "size_bytes": 34},
            {"path": "app.csproj", "sha256": "2" * 64, "size_bytes": 20},
        ]),
        "gaps": [],
    })
    cat_ref = _write_ref(root, "data/jobs/job_target_catalog/catalog.json", {
        "schema": catalog_schema,
        "source_fingerprint": catalog_source or source,
        "artifacts": {
            "repository_discovery.partition_repository": part,
            "repository_discovery.discover_projects": proj,
            "component_discovery.catalog_components": comp,
            "build_discovery.discover_build_systems": builds,
            "build_discovery.discover_compile_commands": comp_db,
            "build_discovery.catalog_build_targets": targets,
        },
    })
    handoff = write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": "job_target_catalog",
        "source_fingerprint": source,
        "artifacts": [part, proj, comp, builds, comp_db, targets, cat_ref],
        "outputs": {
            "publish_catalog.publish_handoff": {"artifact": cat_ref},
        },
    })
    digest = file_sha256(handoff)
    atomic_json(attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": handoff.relative_to(root).as_posix(),
        "handoff_sha256": digest,
    })
    return digest


def test_accepted_catalog_validates_schemas_source_identities_and_recognized_builds(tmp_path: Path) -> None:
    ok_root = tmp_path / "ok"
    _publish_catalog(ok_root)
    accepted = catalog_reader.load_accepted_catalog(ok_root)
    assert {item["path"] for item in accepted["build_files"]} == {"CMakeLists.txt", "app.csproj"}
    assert accepted["accepted_artifacts"] == ()
    assert accepted["source_only_scopes"] == ("docs",)
    assert accepted["gaps"] == ("partition_gap",)

    bad_cat = tmp_path / "bad-cat-schema"
    _publish_catalog(bad_cat, catalog_schema="wrong/1")
    with pytest.raises(ValueError, match="target catalog schema is unsupported"):
        catalog_reader.load_accepted_catalog(bad_cat)

    bad_src = tmp_path / "bad-cat-source"
    _publish_catalog(bad_src, catalog_source="other-source")
    with pytest.raises(ValueError, match="accepted catalog and handoff source identities differ"):
        catalog_reader.load_accepted_catalog(bad_src)

    bad_child = tmp_path / "bad-child-schema"
    _publish_catalog(bad_child, child_schema_override=("partition", "wrong/1"))
    with pytest.raises(ValueError, match="child artifact schema is unsupported"):
        catalog_reader.load_accepted_catalog(bad_child)

    bad_part = tmp_path / "bad-part-source"
    _publish_catalog(bad_part, partition_source="other-part-source")
    with pytest.raises(ValueError, match="partition source identity differs"):
        catalog_reader.load_accepted_catalog(bad_part)


@pytest.fixture
def real_catalog_publication(tmp_path):
    from appsec_review.interchange import validate_unit_output
    from appsec_review.jobs.job_target_catalog import job as catalog_job
    from appsec_review.runtime.runner import JobRunner
    from appsec_review.storage.shared import SharedArtifacts, attempt_artifacts, publication_scope_for_owner
    from tests.unit.job_target_catalog.support import PARTITION, context, source

    unit = context(tmp_path, PARTITION)
    unit.job.config.job_id = "job_target_catalog"
    unit.job.run_id = unit.job.run_root.name
    unit.job.repository_root = ROOT
    unit.job.orchestration = {}
    source(unit, "CMakeLists.txt", b"project(app)\nadd_library(app SHARED main.c)\n", None)
    source(unit, "main.c", b"int main(void) { return 0; }\n", "C")
    source(unit, "prebuilt/app.jar", b"PK\x03\x04\x00inert-archive-fixture", None)
    source(unit, "prebuilt/libapp.so", b"\x7fELF" + b"\x00" * 60, None)
    root, attempt = unit.job.run_root, unit.job.attempt_root
    job = catalog_job.build_job()
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(
            job.job_id, tuple(catalog_job.TOPOLOGY), job.datasets, job_contract=job.contract.document()),
        "orchestration": {},
    })
    identity = {"job_id": job.job_id, "source_fingerprint": unit.job.source_fingerprint,
                "schema_identity": job.schema_identity}
    write_fixture_handoff(root, attempt / "handoff.json", identity)
    with publication_scope_for_owner(SharedArtifacts.for_job(unit.job)):
        for task in job.units:
            unit.unit_id = task.unit_id
            unit.outputs[task.unit_id] = task.handler(unit)
            validate_unit_output(unit.outputs[task.unit_id], unit_id=task.unit_id, strict_gaps=True)
    (attempt / "result.json").unlink()
    path = write_fixture_handoff(root, attempt / "handoff.json", {
        **identity, "completion_status": "COMPLETED_WITH_GAPS",
        "outputs": unit.outputs, "artifacts": attempt_artifacts(root, attempt),
    })
    provisional = json.loads(path.read_bytes())
    claim = json.loads((attempt / "claim.json").read_bytes())
    claim.update(component_identities={"implementation": "unit/1", "schema": job.schema_identity,
                                       "validation": "unit/1"},
                 started_at=provisional["started_at"], job_config_sha256=provisional["job_config_sha256"])
    projected = JobRunner(load_config(ROOT / "appsec-review.toml"))._handoff_document(
        unit.job, claim, {"status": "COMPLETED_WITH_GAPS", "outputs": unit.outputs},
        json.loads((attempt / "outcomes.json").read_bytes()), provisional["outcomes"],
        accepted=True, completed=provisional["completed_at"], artifacts=provisional["artifacts"])
    atomic_json(path, projected)
    digest = file_sha256(path)
    atomic_json(root / "data/jobs/job_target_catalog/latest.json", {
        "handoff_path": path.relative_to(root).as_posix(), "handoff_sha256": digest})
    return unit, projected, digest


@pytest.mark.parametrize("consumer_id", ["job_target_analysis_plan", "job_build_environment_analysis"],
                         ids=["planner", "environment"])
def test_real_catalog_intake_reaches_admitted_plan_and_exact_document_receipts(
        real_catalog_publication, consumer_id):
    from appsec_review.runtime.inputs import admit_inputs
    from tests.unit.job_target_catalog.support import PARTITION

    unit, published, digest = real_catalog_publication
    job = builtin_registry().build(consumer_id)
    consumer = SimpleNamespace(
        run_root=unit.job.run_root, config=SimpleNamespace(job_id=consumer_id),
        source_fingerprint=unit.job.source_fingerprint, evidence_target_snapshot=unit.job.source_fingerprint,
        contract=job.contract, upstream_handoffs={"job_target_catalog": digest},
        optional_prior_handoffs={}, external_input_selection=None)
    admit_inputs(consumer, {"job_target_catalog"})
    (consumer.run_root / "data/jobs/job_target_catalog/latest.json").unlink()
    with input_read_scope(consumer) as reads:
        accepted = catalog_reader.load_accepted_catalog(consumer.run_root)
    raw = unit.outputs[PARTITION]["target_artifacts"]
    assert {item["target_relative_path"] for item in raw} == {"prebuilt/app.jar", "prebuilt/libapp.so"}
    by_path = {item["path"]: item for item in accepted["accepted_artifacts"]}
    assert set(by_path) == {item["target_relative_path"] for item in raw}
    for item in raw:
        projection = by_path[item["target_relative_path"]]
        assert projection["intake"] == item
        assert projection["sha256"] == item["sha256"] and projection["size_bytes"] == item["size_bytes"]
        assert projection["path"] != item["path"]
        assert item["path"].startswith("data/shared/objects/")
    observed = reads.document()["reads"]
    assert len(observed) == 8
    assert {item["output_kind"] for item in observed} == {"handoff", "catalog_documents"}
    main = unit.outputs["publish_catalog.publish_handoff"]["artifact"]
    document = catalog_reader.read_artifact(consumer.run_root, main)
    refs = [main, *(document["artifacts"][name] for name in (
        "repository_discovery.partition_repository", "repository_discovery.discover_projects",
        "component_discovery.catalog_components", "build_discovery.discover_build_systems",
        "build_discovery.discover_compile_commands", "build_discovery.catalog_build_targets"))]
    assert {(r["path"], r["sha256"]) for r in observed if r["output_kind"] == "catalog_documents"} == {
        (r["path"], r["sha256"]) for r in refs}
    assert all(r["handoff_sha256"] == digest and r["read"] is True and r["cited"] is None for r in observed)
    plan = deterministic_plan(accepted, summarize_catalog(
        accepted, max_items=2000, max_bytes=524288, sample_per_prefix=20))
    validate_plan(plan, accepted)
    selections = {item["scanner_id"]: item["scope"] for item in plan["scanner_selections"]}
    for scanner, path in (("tool-spotbugs", "prebuilt/app.jar"), ("tool-blint", "prebuilt/libapp.so")):
        assert selections[scanner] == [{"path": path, "sha256": by_path[path]["sha256"]}]
    assert plan["build_topology"]["targets"] == list(accepted["accepted_artifacts"])
    assert plan["build_topology"]["link_outputs"] == [by_path["prebuilt/libapp.so"]]
    assert all(action["executable"] is False for action in plan["build_topology"]["build_actions"])


@pytest.mark.parametrize("case", ["grant", "pin", "bytes", "schema", "authority"],
                         ids=["missing-grant", "missing-pin", "changed-bytes", "wrong-schema", "wrong-authority"])
def test_catalog_document_reads_fail_closed_under_real_admission(real_catalog_publication, case):
    unit, _published, digest = real_catalog_publication
    consumer = SimpleNamespace(
        run_root=unit.job.run_root, config=SimpleNamespace(job_id=JOB),
        contract=CONTRACT, upstream_handoffs={"job_target_catalog": digest})
    if case == "grant":
        consumer.contract = replace(CONTRACT, inputs=tuple(
            item for item in CONTRACT.inputs if item.output_kind != "catalog_documents"))
        message = "undeclared consumption"
    elif case == "pin":
        consumer.upstream_handoffs = {}
        message = "not supplied by the attempt claim"
    elif case == "bytes":
        ref = unit.outputs["repository_discovery.discover_projects"]["artifact"]
        path = consumer.run_root / ref["path"]
        path.write_bytes(path.read_bytes() + b"\n")
        message = "consumed output bytes changed"
    else:
        from appsec_review.runtime.contracts import EvidenceAuthority
        changes = {"schema": "wrong/1"} if case == "schema" else {"authority": EvidenceAuthority.OPERATIONAL}
        consumer.contract = replace(CONTRACT, inputs=tuple(
            replace(item, **changes) if item.output_kind == "catalog_documents" else item
            for item in CONTRACT.inputs))
        message = "consumed output schema differs from input contract"
    with pytest.raises(ValueError, match=message):
        with input_read_scope(consumer):
            catalog_reader.load_accepted_catalog(consumer.run_root)


def test_verify_source_topology_swift_policy_base_indexes_and_load_accepted_plan(tmp_path: Path) -> None:
    cmake = "project(app)\nadd_executable(app main.c)\n"
    (tmp_path / "CMakeLists.txt").write_text(cmake, encoding="utf-8")
    files = [{"path": "CMakeLists.txt", "sha256": hashlib.sha256(cmake.encode()).hexdigest(), "size_bytes": len(cmake)}]
    units = discover_build_units(files)
    units[0]["descriptor_package"] = descriptor_package(tmp_path, units[0], files)
    catalog = {
        "source_fingerprint": SOURCE,
        "catalog_handoff_sha256": CATALOG_SHA,
        "files": files,
        "components": [],
        "build_files": files,
        "compile_databases": [],
        "build_units": units,
    }
    plan = deterministic_plan(catalog, summarize_catalog(catalog, max_items=50, max_bytes=32768, sample_per_prefix=5))
    planner._verify_source_topology(canonical_json(plan))

    drifted = copy.deepcopy(plan)
    drifted["build_topology"]["planning_refinement"]["units"] = [{"broken": True}]
    with pytest.raises(ValueError, match="does not reproduce"):
        planner._verify_source_topology(canonical_json(drifted))

    # apply_swift_catalog_policy enabled vs disabled
    swift_cat = {
        "files": [{"path": "Sources/App.swift", "language": "Swift"}, {"path": "a.c", "language": "C"}],
        "accepted_artifacts": [{"path": "Sources/App.swift", "language": "Swift"}],
        "build_units": [{"build_unit_id": "u-swift", "language": "Swift", "markers": [{"path": "Sources/App.swift"}]}],
        "gaps": (),
    }
    assert len(planner.apply_swift_catalog_policy(swift_cat, enabled=True)["build_units"]) == 1
    filtered = planner.apply_swift_catalog_policy(swift_cat, enabled=False)
    assert filtered["build_units"] == ()
    assert len(filtered["gaps"]) == 1

    # _base_indexes walks observations manifest chain and filters self shard
    run_root = tmp_path / "idx-run"
    s1_sha = IndexBuilder(run_root / "data/indices/source.sqlite", name="source", fingerprint="a" * 64,
                          target_snapshot=SOURCE, shard_id="source-files").build()
    s2_sha = IndexBuilder(run_root / "data/indices/plan.sqlite", name="analysis", fingerprint="b" * 64,
                          target_snapshot=SOURCE, shard_id="target-analysis-plan").build()
    s3_sha = IndexBuilder(run_root / "data/indices/obs.sqlite", name="observations", fingerprint="c" * 64,
                          target_snapshot=SOURCE, shard_id="observations").build()
    base_shard = IndexIdentity("source", "appsec-review/retrieval-index/2", s1_sha, "a" * 64,
                               "data/indices/source.sqlite", {"job": "job_target_catalog"}, (), "source-files")
    self_shard = IndexIdentity("analysis", "appsec-review/retrieval-index/2", s2_sha, "b" * 64,
                               "data/indices/plan.sqlite", {"job": JOB}, (), "target-analysis-plan")
    base_manifest = run_root / "data/indices/manifests/catalog.json"
    write_manifest(base_manifest, run_id="idx-run", target_snapshot=SOURCE, target_root=tmp_path,
                   indexes=[base_shard, self_shard])
    obs_shard = IndexIdentity("observations", "appsec-review/retrieval-index/2", s3_sha, "c" * 64,
                              "data/indices/obs.sqlite", {"job": "job_evidence_collection"}, (), "observations")
    obs_manifest = run_root / "data/indices/manifests/obs.json"
    write_manifest(
        obs_manifest, run_id="idx-run", target_snapshot=SOURCE, target_root=tmp_path,
        indexes=[obs_shard],
        upstream_manifests=({"path": base_manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(base_manifest)},),
    )
    obs_ref = {"path": obs_manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(obs_manifest), "size_bytes": obs_manifest.stat().st_size}
    cat_attempt = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    cat_handoff = write_fixture_handoff(run_root, cat_attempt / "handoff.json", {
        "job_id": "job_target_catalog",
        "source_fingerprint": SOURCE,
        "outputs": {"publish_catalog.publish_handoff": {"index_manifest": obs_ref}},
    })
    cat_digest = file_sha256(cat_handoff)
    atomic_json(cat_attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": cat_handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": cat_digest,
    })
    indexes, resolved_path, _ = planner._base_indexes(SimpleNamespace(
        run_root=run_root,
        upstream_handoffs={"job_target_catalog": cat_digest},
        input_manifest_path=obs_manifest,
        input_manifest_sha256=obs_ref["sha256"],
    ))
    assert [idx.shard_id for idx in indexes] == ["source-files"]
    assert resolved_path == base_manifest.resolve()

    # Orphan observations manifest with no upstream_manifests raises ValueError
    orphan_manifest = run_root / "data/indices/manifests/orphan.json"
    write_manifest(orphan_manifest, run_id="idx-run", target_snapshot=SOURCE, target_root=tmp_path, indexes=[obs_shard])
    orphan_ref = {"path": orphan_manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(orphan_manifest), "size_bytes": orphan_manifest.stat().st_size}
    orphan_attempt = run_root / "data/jobs/job_target_catalog/attempts/attempt_0002"
    orphan_handoff = write_fixture_handoff(run_root, orphan_attempt / "handoff.json", {
        "job_id": "job_target_catalog",
        "attempt_id": "attempt_0002",
        "source_fingerprint": SOURCE,
        "outputs": {"publish_catalog.publish_handoff": {"index_manifest": orphan_ref}},
    })
    orphan_digest = file_sha256(orphan_handoff)
    atomic_json(orphan_attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0002",
        "handoff_path": orphan_handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": orphan_digest,
    })
    with pytest.raises(ValueError, match="no stable upstream index set"):
        planner._base_indexes(SimpleNamespace(
            run_root=run_root,
            upstream_handoffs={"job_target_catalog": orphan_digest},
            input_manifest_path=orphan_manifest,
            input_manifest_sha256=orphan_ref["sha256"],
        ))


def test_load_accepted_plan_validates_schema_graph_and_environment_drift(
    environment_publication,
) -> None:
    root, config, digest, identity, document = environment_publication
    cmake = "project(app)\nadd_executable(app main.c)\n"
    (root / "CMakeLists.txt").write_text(cmake, encoding="utf-8")
    files = [{"path": "CMakeLists.txt", "sha256": hashlib.sha256(cmake.encode()).hexdigest(), "size_bytes": len(cmake)}]
    units = discover_build_units(files)
    units[0]["descriptor_package"] = descriptor_package(root, units[0], files)
    catalog = {
        "source_fingerprint": SOURCE,
        "catalog_handoff_sha256": CATALOG_SHA,
        "files": files,
        "components": [],
        "build_files": files,
        "compile_databases": [],
        "build_units": units,
    }
    launch, _ = planning_environment_inputs(
        config, root, SOURCE, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": digest}, {},
    )
    env_record = {
        **launch,
        "availability": "AVAILABLE",
        "artifact": identity,
        "reason": "accepted not_applicable static environment",
        "evidence": document,
    }
    plan = deterministic_plan(catalog, summarize_catalog(catalog, max_items=50, max_bytes=32768, sample_per_prefix=5))
    plan["build_environment"] = env_record
    planner._publish_build_graph(plan)
    plan_ref = _write_ref(root, f"data/jobs/{JOB}/plan.json", plan)
    attempt = root / "data/jobs" / JOB / "attempts/attempt_0001"
    handoff = write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": JOB,
        "source_fingerprint": SOURCE,
        "outputs": {"plan_acceptance.publish_handoff": {"artifact": plan_ref}},
    })
    plan_sha = file_sha256(handoff)
    atomic_json(attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": handoff.relative_to(root).as_posix(),
        "handoff_sha256": plan_sha,
    })
    assert load_accepted_plan(root)["schema"] == PLAN_SCHEMA

    # Tamper environment availability by changing plan's recorded availability -> environment drift rejected
    drifted_env = copy.deepcopy(plan)
    drifted_env["build_environment"]["availability"] = "UNAVAILABLE"
    drift_ref = _write_ref(root, f"data/jobs/{JOB}/drift-plan.json", drifted_env)
    attempt2 = root / "data/jobs" / JOB / "attempts/attempt_0002"
    handoff2 = write_fixture_handoff(root, attempt2 / "handoff.json", {
        "job_id": JOB, "attempt_id": "attempt_0002", "source_fingerprint": SOURCE,
        "outputs": {"plan_acceptance.publish_handoff": {"artifact": drift_ref}},
    })
    atomic_json(attempt2.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0002",
        "handoff_path": handoff2.relative_to(root).as_posix(),
        "handoff_sha256": file_sha256(handoff2),
    })
    with pytest.raises(ValueError, match="environment identity changed"):
        load_accepted_plan(root)

    # Unsupported schema & missing executable_graph
    for idx, (bad_plan, match) in enumerate([
        ({"schema": "wrong/1"}, "plan schema is unsupported"),
        ({**plan, "build_topology": {}}, "no source-bound executable build graph"),
    ], start=3):
        bad_ref = _write_ref(root, f"data/jobs/{JOB}/bad-{idx}.json", bad_plan)
        att = root / "data/jobs" / JOB / f"attempts/attempt_000{idx}"
        hf = write_fixture_handoff(root, att / "handoff.json", {
            "job_id": JOB, "attempt_id": f"attempt_000{idx}", "source_fingerprint": SOURCE,
            "outputs": {"plan_acceptance.publish_handoff": {"artifact": bad_ref}},
        })
        atomic_json(att.parent.parent / "latest.json", {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": f"attempt_000{idx}",
            "handoff_path": hf.relative_to(root).as_posix(),
            "handoff_sha256": file_sha256(hf),
        })
        with pytest.raises(ValueError, match=match):
            load_accepted_plan(root)


@pytest.mark.parametrize("mutator,expected", [
    (lambda j: replace(j, steps={}), "topology does not match"),
    (lambda j: replace(j, steps={**j.steps, "catalog_summary": replace(j.steps["catalog_summary"], tasks={})}), "task order mismatch"),
    (lambda j: replace(j, settings={**j.settings, "summary_max_items": 0}), "setting is invalid: summary_max_items"),
    (lambda j: replace(j, settings={**j.settings, "summary_max_bytes": 512}), "summary bounds are inconsistent"),
    (lambda j: replace(j, settings={**j.settings, "model": "bad"}), "model settings are required"),
    (lambda j: replace(j, settings={**j.settings, "model": {"enabled": True}}), "model settings are incomplete"),
    (lambda j: replace(j, settings={**j.settings, "model": {**j.settings["model"], "enabled": 1}}), "enabled setting must be a boolean"),
    (lambda j: replace(j, settings={**j.settings, "model": {**j.settings["model"], "provider": " "}}), "model setting is invalid: provider"),
    (lambda j: replace(j, settings={**j.settings, "model": {**j.settings["model"], "max_input_tokens": 0}}), "model setting is invalid: max_input_tokens"),
    (lambda j: replace(j, settings={**j.settings, "model": {**j.settings["model"], "retries": 6}}), "retries must be between zero and five"),
    (lambda j: replace(j, settings={**j.settings, "model": {**j.settings["model"], "workers": 0}}), "workers must be between one and sixteen"),
])
def test_validate_config_enforces_topology_summary_and_model_bounds(mutator, expected: str) -> None:
    job_cfg = load_config(ROOT / "appsec-review.toml").job(JOB)
    planner._validate_config(SimpleNamespace(config=job_cfg), None)
    with pytest.raises(ValueError, match=expected):
        planner._validate_config(SimpleNamespace(config=mutator(job_cfg)), None)


@pytest.fixture
def environment_publication(tmp_path):
    root = tmp_path / "synthetic-planner-run"
    catalog_sha = _publish_catalog(root)
    attempt = root / "data/jobs" / ENVIRONMENT / "attempts/attempt_0001"
    document = {
        "schema": ENV_SCHEMA, "source_fingerprint": SOURCE, "catalog_handoff_sha256": catalog_sha,
        "rules": RULES, "availability": "AVAILABLE", "coverage": "not_applicable",
        "declarations": [], "gaps": [],
        "bounds": {**asdict(BuildEnvironmentSettings()), "inspected_scripts": 0,
                   "inventory_scope": "accepted inventory only; no whole-target absence claim"},
    }
    path = attempt / "steps/environment_analysis/tasks/publish_handoff/build-environment.json"
    atomic_json(path, document)
    identity = {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
                "size_bytes": path.stat().st_size}
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(ENVIRONMENT, ("environment_analysis",), ENV_DATASETS),
    })
    handoff = write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": ENVIRONMENT, "source_fingerprint": SOURCE,
        "schema_identity": ENV_SCHEMA, "upstream_handoff_sha256": {"job_target_catalog": catalog_sha},
        "outputs": {"environment_analysis.publish_handoff": {
            "schema": ENV_SCHEMA, "artifact": identity, "gaps": [], "terminal_status": "SUCCEEDED",
        }},
    })
    verify_handoff_integrity(root, json.loads(handoff.read_bytes()))
    digest = file_sha256(handoff)
    atomic_json(attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
        "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": digest,
    })
    return root, load_config(ROOT / "appsec-review.toml"), digest, identity, document


def _handler_context(monkeypatch, root, config, source, launch, pins, *,
                     optional_prior=None, history_value=None):
    catalog = {"source_fingerprint": source,
               "catalog_handoff_sha256": pins.get("job_target_catalog", CATALOG_SHA)}
    calls = []

    def catalog_reader(run):
        assert run == root
        calls.append("catalog")
        return catalog

    def history_reader(run):
        assert run == root
        calls.append("history")
        return history_value

    monkeypatch.setattr(planner, "load_accepted_catalog", catalog_reader)
    monkeypatch.setattr(planner, "load_accepted_history", history_reader)
    events = []
    context = SimpleNamespace(
        run_root=root, source_fingerprint=source, contract=CONTRACT, upstream_handoffs=pins,
        optional_prior_handoffs=optional_prior or {},
        config=config.job(JOB), events=SimpleNamespace(write=lambda event, **fields: events.append((event, fields))),
        orchestration={"build_environment_contract": json.dumps(launch)},
    )
    return SimpleNamespace(job=context, unit_id=UNIT), catalog, calls, events


def _load(unit):
    return next(value for value in planner.build_job().units if value.unit_id == UNIT).handler(unit)


@pytest.mark.parametrize("stale", [False, True], ids=["current-source", "stale-source"])
def test_load_catalog_consumes_optional_environment_selected_for_its_claim(
        environment_publication, monkeypatch, stale):
    root, config, digest, identity, document = environment_publication
    source = "later-planner-source" if stale else SOURCE
    launch, selected = planning_environment_inputs(
        config, root, source, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": digest}, {})
    assert launch["mode"] == "OPTIONAL_PRIOR" and launch["reference"] == digest
    optional_prior = optional_prior_environment_handoffs(launch)
    assert optional_prior == {ENVIRONMENT: digest}
    unit, catalog, calls, events = _handler_context(
        monkeypatch, root, config, source, launch, selected, optional_prior=optional_prior,
    )
    planner._validate_config(unit.job, None)
    with input_read_scope(unit.job) as reads:
        loaded = _load(unit)
        assert loaded["catalog"] == catalog and loaded["history"] is None
        assert loaded["environment"]["availability"] == ("UNAVAILABLE" if stale else "AVAILABLE")
        assert loaded["environment"]["artifact"] == (None if stale else identity)
        assert loaded["environment"]["evidence"] == (None if stale else document)
        assert reads.violation is None
        observed = [(r["output_kind"], r["handoff_sha256"]) for r in reads.document()["reads"]]
        assert observed == [("handoff", digest), ("build_environment", digest)]
    assert calls == ["catalog", "history"]
    assert events == [("ANALYSIS_PLAN_STARTED", {"catalog_handoff_sha256": CATALOG_SHA})]


def test_load_catalog_reads_supplied_environment_and_records_producer_scope(
        environment_publication, monkeypatch):
    root, config, digest, identity, document = environment_publication
    catalog_sha = document["catalog_handoff_sha256"]
    pins = {ENVIRONMENT: digest, "job_target_catalog": catalog_sha}
    launch, selected = planning_environment_inputs(
        config, root, SOURCE, {"workflow": "wave1_review"}, pins)
    assert launch["mode"] == "EXPECTED_CURRENT" and selected == pins
    unit, catalog, calls, events = _handler_context(
        monkeypatch, root, config, SOURCE, launch, selected,
        history_value={"target_snapshot": "stale-snap"},
    )
    with input_read_scope(unit.job) as reads:
        loaded = _load(unit)
        observed = reads.document()
    assert loaded == {
        "catalog": catalog, "catalog_handoff_sha256": catalog_sha,
        "history": {"stale_reason": "accepted source history describes a different target snapshot"},
        "environment": {**launch, "availability": "AVAILABLE", "artifact": identity,
                        "reason": "accepted not_applicable static environment", "evidence": document},
    }
    assert observed["schema"] == "appsec-review/input-reads/1"
    assert [(r["producer"], r["output_kind"], r["schema"]) for r in observed["reads"]] == [
        (ENVIRONMENT, "handoff", "appsec-review/job-handoff/2"),
        (ENVIRONMENT, "build_environment", ENV_SCHEMA),
        ("job_target_catalog", "handoff", "appsec-review/job-handoff/2"),
    ]
    assert [r["handoff_sha256"] for r in observed["reads"]] == [digest, digest, catalog_sha]
    assert calls == ["catalog", "history"]
    assert events == [("ANALYSIS_PLAN_STARTED", {"catalog_handoff_sha256": catalog_sha})]


@pytest.mark.parametrize("case", ["unsupplied", "tampered"])
def test_load_catalog_rejects_unadmitted_or_changed_current_catalog(
        environment_publication, monkeypatch, case):
    root, config, digest, _identity, document = environment_publication
    pins = {ENVIRONMENT: digest, "job_target_catalog": document["catalog_handoff_sha256"]}
    launch, selected = planning_environment_inputs(
        config, root, SOURCE, {"workflow": "wave1_review"}, pins)
    if case == "unsupplied":
        selected.pop("job_target_catalog")
        message = "reads job_target_catalog, which is not supplied by the attempt claim"
    else:
        handoff = root / "data/jobs/job_target_catalog/attempts/attempt_0001/handoff.json"
        handoff.write_bytes(handoff.read_bytes() + b"\n")
        message = "accepted job_target_catalog handoff changed after it was recorded"
    unit, _catalog, _calls, _events = _handler_context(
        monkeypatch, root, config, SOURCE, launch, selected)
    with pytest.raises(ValueError, match=message):
        with input_read_scope(unit.job) as reads:
            _load(unit)
    assert reads.violation is not None and message in reads.violation
    assert [(r["producer"], r["output_kind"]) for r in reads.document()["reads"]] == [
        (ENVIRONMENT, "handoff"), (ENVIRONMENT, "build_environment"),
    ]


def test_load_catalog_unsupplied_environment_fails_with_exact_producer_scope(
        environment_publication, monkeypatch):
    root, config, digest, _identity, _document = environment_publication
    launch, selected = planning_environment_inputs(
        config, root, SOURCE, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": digest}, {})
    assert selected == {}
    unit, _catalog, calls, events = _handler_context(monkeypatch, root, config, SOURCE, launch, selected)
    message = "consumed handoff is not the supplied immutable input: " + ENVIRONMENT
    with pytest.raises(ValueError, match="input contract violation: " + message):
        with input_read_scope(unit.job) as reads:
            with pytest.raises(ValueError) as caught:
                _load(unit)
            assert type(caught.value) is ValueError and str(caught.value) == message
            assert reads.violation == message and reads.document()["reads"] == []
    assert calls == ["catalog", "history"]
    assert events == [("ANALYSIS_PLAN_STARTED", {"catalog_handoff_sha256": CATALOG_SHA})]


def test_load_catalog_not_run_and_catalog_fingerprint_mismatch(tmp_path, monkeypatch):
    config = load_config(ROOT / "appsec-review.toml")
    launch, selected = planning_environment_inputs(config, tmp_path, SOURCE, {}, {})
    assert launch["mode"] == "NOT_RUN" and selected == {}
    unit, catalog, calls, events = _handler_context(monkeypatch, tmp_path, config, SOURCE, launch, selected)
    with input_read_scope(unit.job) as reads:
        result = _load(unit)
        assert reads.document()["reads"] == [] and reads.violation is None
    assert result == {
        "catalog": catalog, "catalog_handoff_sha256": CATALOG_SHA, "history": None,
        "environment": {**launch, "availability": "ABSENT", "artifact": None, "evidence": None},
    }
    assert calls == ["catalog", "history"]
    assert events == [("ANALYSIS_PLAN_STARTED", {"catalog_handoff_sha256": CATALOG_SHA})]

    mismatch_unit = SimpleNamespace(
        job=replace_ns(unit.job, source_fingerprint="different-source"),
        unit_id=UNIT,
    )
    with pytest.raises(ValueError, match="graph target fingerprint does not match"):
        _load(mismatch_unit)


def replace_ns(ns: SimpleNamespace, **updates) -> SimpleNamespace:
    data = dict(vars(ns))
    data.update(updates)
    return SimpleNamespace(**data)
