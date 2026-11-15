"""Exact input, dataset, graph, admission, and artifact contracts for job_change_context_analysis."""
from __future__ import annotations

import ast
from dataclasses import asdict, replace
from fnmatch import fnmatch
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_change_context_analysis import build_job, job
from appsec_review.jobs.job_change_context_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.runtime import plan_jobs
from appsec_review.runtime.consume import UpstreamIntegrityError, upstream_scope
from appsec_review.runtime.contracts import Availability, MissingPolicy
from appsec_review.runtime.inputs import admit_inputs
from .support import ROOT, artifact, context, document, raw_settings, write_resolved_config


INPUTS = [
    ("job_target_catalog", "handoff", "appsec-review/job-handoff/2", "required", "reject", "producer_evidence"),
    ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1", "optional", "gap", "producer_evidence"),
    *[
        ("job_target_catalog", name, "appsec-review/retrieval-index/2", "optional", "gap", "producer_evidence")
        for name in ("source_files", "declaration_symbols", "components", "target_documents", "build_units")
    ],
    ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1", "optional", "gap", "producer_evidence"),
    ("job_source_history_analysis", "handoff", "appsec-review/job-handoff/2", "when_producer_enabled", "reject", "routing_context"),
    ("job_source_history_analysis", "history_signals", "appsec-review/retrieval-index/2", "optional", "gap", "routing_context"),
    ("job_source_history_analysis", "history_documents", "appsec-review/source-history-analysis/2", "optional", "gap", "routing_context"),
    ("job_source_history_analysis", "raw_git_history", "application/octet-stream", "optional", "gap", "routing_context"),
    ("job_source_history_analysis", "history_tool_io", "appsec-review/container-execution/1", "optional", "gap", "routing_context"),
    ("job_tree_sitter_ast", "handoff", "appsec-review/job-handoff/2", "optional", "gap", "producer_evidence"),
    ("job_tree_sitter_ast", "tree_sitter_ast", "appsec-review/tree-sitter-normalizer/1", "optional", "gap", "producer_evidence"),
    ("job_tree_sitter_ast", "tree_sitter_coverage", "appsec-review/tree-sitter-ast/1", "optional", "gap", "producer_evidence"),
    ("job_tree_sitter_ast", "tree_sitter_node_shards", "appsec-review/tree-sitter-normalizer/1", "optional", "gap", "producer_evidence"),
    ("job_tree_sitter_ast", "tree_sitter_acceptance", "appsec-review/tree-sitter-ast/1", "optional", "gap", "producer_evidence"),
    ("job_tree_sitter_ast", "generated_source_backing", "appsec-review/generated-source-backing/1", "optional", "gap", "producer_evidence"),
    ("job_tree_sitter_ast", "tree_sitter_tool_io", "appsec-review/container-execution/1", "optional", "gap", "producer_evidence"),
]
A = "data/jobs/job_change_context_analysis/attempts/*"
METADATA = "query_dataset_inventory (sanitized identity, hash, status and coverage only)"
OUTPUTS = [
    (
        "change_context", "publish", "appsec-review/retrieval-index/2", "internal", "indexed",
        "Ranked change-context signals, changes, review units and deployment events.",
        ("history",), ("change-context",),
        (),
        "query_change_context; query_precomputed query_set=history_context",
        None,
    ),
    (
        "change_context_documents", "publish", "appsec-review/change-context-analysis/1", "sensitive", "artifact_only",
        "Attribution, change records, unit signals and ranking documents.",
        (), (),
        (A + "/steps/*/tasks/*/artifacts/*.json", A + "/steps/*/tasks/*/sources/*/artifacts/*.json"),
        METADATA,
        "normalized inputs of the change-context shard; pseudonym maps are never indexed",
    ),
    (
        "operator_exports", "load", "application/json", "sensitive", "protected",
        "Verbatim operator review, deployment and organization exports.",
        (), (),
        (
            A + "/steps/load/tasks/external_sources/artifacts/inputs/*",
            A + "/steps/load/tasks/external_sources/sources/*/artifacts/inputs/*",
        ),
        METADATA,
        "unredacted operator-supplied records; only normalized bounded facts are indexed",
    ),
    (
        "change_context_tool_io", "attribute", "appsec-review/container-execution/1", "sensitive", "protected",
        "Git blame and diff container scratch.",
        (), (),
        (A + "/steps/*/tasks/*/scratch/**", A + "/steps/*/tasks/*/sources/*/scratch/**"),
        METADATA,
        "raw tool streams and receipts may contain unredacted target content and host paths",
    ),
]
GRAPH = {
    "load.accepted_history": (),
    "load.external_sources": ("load.accepted_history",),
    "attribute.line_attribution": ("load.accepted_history",),
    "attribute.fix_on_fix": ("load.accepted_history",),
    "analyze.change_signals": ("load.external_sources",),
    "analyze.unit_signals": ("analyze.change_signals", "attribute.line_attribution", "attribute.fix_on_fix"),
    "analyze.rank": ("analyze.unit_signals",),
    "publish.index_change_context": ("analyze.rank",),
    "publish.publish_handoff": ("publish.index_change_context",),
}
WRITES = {
    "load_history_source": {"lifetime.json"},
    "external": {"external-sources.json"},
    "attribute_lines": {"attribution.json"},
    "fix_on_fix": {"fix-on-fix.json"},
    "change_signals": {"change-records.json"},
    "unit_signals": {"units.json"},
    "rank": {"signals.json"},
    "publish": {"change-context.json"},
    "publish_sources": {"change-context.json"},
}


def test_every_input_requirement_field_and_job_policy() -> None:
    assert [asdict(item) for item in CONTRACT.inputs] == [
        {
            "producer": producer,
            "output_kind": kind,
            "schema": schema,
            "availability": availability,
            "missing": missing,
            "authority": authority,
            "coverage": "allow_partial",
            "channel": "handoff",
        }
        for producer, kind, schema, availability, missing, authority in INPUTS
    ]
    assert CONSUMES == CONTRACT.consumes == (
        "job_source_history_analysis", "job_target_catalog", "job_tree_sitter_ast",
    )
    assert CONTRACT.schedule_after == ("job_tree_sitter_ast",)
    assert (CONTRACT.dispatch, CONTRACT.target_access, CONTRACT.always_execute, CONTRACT.propagate_handoff) == (
        "review_graph", "checkout", False, True,
    )


def test_every_dataset_field() -> None:
    assert [asdict(item) for item in DATASETS] == [
        {
            "output_kind": kind,
            "step": step,
            "family": "change_context",
            "schema": schema,
            "sensitivity": sensitivity,
            "disposition": disposition,
            "description": description,
            "indexes": indexes,
            "shard_prefixes": prefixes,
            "shard_suffixes": (),
            "artifacts": artifacts,
            "query_route": route,
            "reason": reason,
            "required": False,
            "store": "retrieval",
            "authority": "routing_context",
        }
        for kind, step, schema, sensitivity, disposition, description, indexes, prefixes, artifacts, route, reason in OUTPUTS
    ]


def test_dag_shape_and_job_metadata(tmp_path: Path) -> None:
    built = build_job()
    assert {unit.unit_id: unit.dependencies for unit in built.units} == GRAPH
    assert [unit.unit_id for unit in built.units] == list(GRAPH)
    plan = plan_jobs((built,))
    assert plan.node("job_change_context_analysis.analyze.unit_signals").dependencies == (
        "job_change_context_analysis.analyze.change_signals",
        "job_change_context_analysis.attribute.line_attribution",
        "job_change_context_analysis.attribute.fix_on_fix",
    )
    assert built.contract is CONTRACT and built.datasets is DATASETS
    assert built.schema_identity == "appsec-review/change-context-analysis/1"
    assert built.input_validators == (job._validate,)
    assert built.output_validators == () and all(unit.output_validators == () for unit in built.units)
    assert built.result_transform is None and built.strict_gaps is False
    result = {"outputs": {"publish.publish_handoff": {"schema": job.SCHEMA}}, "status": "SUCCEEDED"}
    assert built.finalize_result(context(tmp_path, "publish.publish_handoff").job, result) is result


def test_catalog_handoff_is_required_and_history_is_when_enabled_reject(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml").job(job.PRODUCER)
    ctx = SimpleNamespace(config=config, run_root=tmp_path / "run", source_fingerprint="fixture-snapshot")
    job._validate(ctx, None)

    catalog_req = next(item for item in CONTRACT.inputs if (item.producer, item.output_kind) == ("job_target_catalog", "handoff"))
    history_req = next(item for item in CONTRACT.inputs if (item.producer, item.output_kind) == ("job_source_history_analysis", "handoff"))
    assert (catalog_req.availability, catalog_req.missing) == (Availability.REQUIRED, MissingPolicy.REJECT)
    assert (history_req.availability, history_req.missing) == (Availability.WHEN_ENABLED, MissingPolicy.REJECT)

    load_unit = next(unit.handler for unit in job.build_job().units if unit.unit_id == "load.accepted_history")
    with upstream_scope(ctx.run_root, job.PRODUCER, {}, contract=CONTRACT):
        with pytest.raises(UpstreamIntegrityError, match=r"^accepted job_target_catalog handoff is required$"):
            load_unit(SimpleNamespace(job=ctx))


def test_admission_enforces_required_catalog_and_conditional_history(tmp_path: Path) -> None:
    missing_catalog = SimpleNamespace(
        contract=CONTRACT, upstream_handoffs={}, run_root=tmp_path / "run",
        evidence_target_snapshot="fixture-snapshot", external_input_selection=None,
    )
    with pytest.raises(ValueError, match=r"^required input unavailable: job_target_catalog/handoff$"):
        admit_inputs(missing_catalog, enabled=set(CONTRACT.consumes))

    from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
    from appsec_review.runtime.datasets import dataset_contract
    from tests.handoff_fixture import write_fixture_handoff
    from appsec_review.storage import atomic_json, file_sha256

    run_root = tmp_path / "run_with_catalog"
    attempt_dir = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    nonreq_catalog_datasets = tuple(replace(item, required=False) for item in CATALOG_DATASETS)
    atomic_json(attempt_dir / "claim.json", {
        "dataset_contract": dataset_contract(
            "job_target_catalog", sorted({item.step for item in nonreq_catalog_datasets}), nonreq_catalog_datasets,
        ),
    })
    handoff_path = attempt_dir / "handoff.json"
    write_fixture_handoff(run_root, handoff_path, {
        "application_run_id": run_root.name,
        "job_id": "job_target_catalog", "attempt_id": "attempt_0001", "source_fingerprint": "fixture-snapshot",
        "status": "ACCEPTED", "outputs": {},
    })
    catalog_sha = file_sha256(handoff_path)
    atomic_json(run_root / "data/jobs/job_target_catalog/latest.json", {
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": catalog_sha,
    })

    with upstream_scope(run_root, job.PRODUCER, {"job_target_catalog": catalog_sha}, contract=CONTRACT):
        got_handoff, got_sha = job._accepted_handoff(run_root, "job_target_catalog", required=True)
        assert got_sha == catalog_sha and got_handoff["job_id"] == "job_target_catalog"
        assert job._accepted_handoff(run_root, "job_tree_sitter_ast", required=False) is None

    missing_enabled_history = SimpleNamespace(
        contract=CONTRACT, upstream_handoffs={"job_target_catalog": catalog_sha}, run_root=run_root,
        evidence_target_snapshot="fixture-snapshot", external_input_selection=None,
    )
    with pytest.raises(ValueError, match=r"^required input unavailable: job_source_history_analysis/handoff$"):
        admit_inputs(missing_enabled_history, enabled=set(CONTRACT.consumes))

    admitted = admit_inputs(missing_enabled_history, enabled={"job_target_catalog"})
    by_key = {(row["producer"], row["output_kind"]): row for row in admitted["requirements"]}
    assert by_key[("job_target_catalog", "handoff")]["status"] == "supplied"
    assert by_key[("job_source_history_analysis", "handoff")]["status"] == "gap"


def test_input_validation_checks_topology_task_order_and_glob_braces(tmp_path: Path) -> None:
    ctx = context(tmp_path, "load.accepted_history").job
    job._validate(ctx, None)

    with pytest.raises(ValueError, match="topology does not match"):
        job._validate(replace(ctx, config=SimpleNamespace(steps={})), None)

    fake_steps = SimpleNamespace(steps=job.TOPOLOGY, step=lambda _key: SimpleNamespace(tasks=("wrong",)))
    with pytest.raises(ValueError, match="task order mismatch: load"):
        job._validate(replace(ctx, config=fake_steps), None)

    bad_glob = raw_settings(**{"test_association.test_patterns": ["tests/{unclosed.py"]})
    with pytest.raises(ValueError, match="unbalanced brace in pattern"):
        job._validate(replace(ctx, config=replace(ctx.config, settings=bad_glob)), None)


def test_handlers_write_only_declared_document_names() -> None:
    tree = ast.parse(inspect.getsource(job.build_job))
    actual = {}
    for function in tree.body[0].body:
        if not isinstance(function, ast.FunctionDef):
            continue
        names = {
            node.args[1].value
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_write"
            and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)
        }
        if names:
            actual[function.name] = names
    assert actual == WRITES
    for names in WRITES.values():
        for name in names:
            assert fnmatch(
                f"data/jobs/job_change_context_analysis/attempts/attempt_0001/"
                f"steps/publish/tasks/publish_handoff/artifacts/{name}",
                DATASETS[1].artifacts[0],
            )


def test_artifact_and_upstream_helpers_verify_identities_and_schemas(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = context(tmp_path, "publish.publish_handoff")
    ref = job._write(unit, "change-context.json", {"schema": job.SCHEMA, "ok": True})
    assert document(unit, {"artifact": ref}) == {"schema": job.SCHEMA, "ok": True}
    assert job._read(unit.job.run_root, ref) == {"schema": job.SCHEMA, "ok": True}

    with pytest.raises(ValueError, match="artifact identity mismatch"):
        job._read_bytes(unit.job.run_root, {"path": "../outside.json", "sha256": ref["sha256"]})
    with pytest.raises(ValueError, match="artifact identity mismatch"):
        job._read_bytes(unit.job.run_root, {"path": "missing.json", "sha256": ref["sha256"]})
    with pytest.raises(ValueError, match="artifact identity mismatch"):
        job._read_bytes(unit.job.run_root, {"path": ref["path"], "sha256": "0" * 64})

    result_ref = artifact(unit, "result.json", {"outputs": {"x": 1}})
    assert job._accepted_outputs(unit.job.run_root, {
        "resolving_paths": {"result": result_ref["path"]}, "artifacts": [result_ref],
    }) == {"x": 1}
    with pytest.raises(ValueError, match="accepted handoff does not pin its result"):
        job._accepted_outputs(unit.job.run_root, {"resolving_paths": {"result": "unlisted.json"}, "artifacts": []})

    write_resolved_config(unit.job.run_root, history_overrides={"bulk_change_file_threshold": 123})
    assert job._resolved_job_settings(unit.job.run_root, "job_source_history_analysis")["bulk_change_file_threshold"] == 123

    components_ref = artifact(unit, "components.json", {
        "components": [{"component_id": "root", "root": ""}, {"component_id": "svc", "root": "services/api"}],
    })
    good_catalog = artifact(unit, "catalog.json", {
        "schema": "appsec-review/target-catalog/1",
        "source_fingerprint": "snapshot",
        "artifacts": {"component_discovery.catalog_components": components_ref},
    })
    monkeypatch.setattr(job, "_accepted_handoff", lambda _root, _job_id, *, required: (
        {"outputs": {"publish_catalog.publish_handoff": {"artifact": good_catalog}}}, "cat-sha",
    ))
    loaded = job._load_catalog(unit.job.run_root)
    assert loaded == {
        "source_fingerprint": "snapshot",
        "catalog_handoff_sha256": "cat-sha",
        "components": [{"component_id": "root", "root": "."}, {"component_id": "svc", "root": "services/api"}],
    }

    bad_catalog = artifact(unit, "bad-catalog.json", {"schema": "wrong/1"})
    monkeypatch.setattr(job, "_accepted_handoff", lambda _root, _job_id, *, required: (
        {"outputs": {"publish_catalog.publish_handoff": {"artifact": bad_catalog}}}, "cat-sha",
    ))
    with pytest.raises(ValueError, match="catalog schema is unsupported"):
        job._load_catalog(unit.job.run_root)
