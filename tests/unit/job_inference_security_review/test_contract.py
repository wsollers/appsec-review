"""Contract, input-validator, and helper unit tests for job_inference_security_review."""
from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_inference_security_review.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_inference_security_review.job import (
    JOB_ID,
    LEDGER_UNITS,
    SCHEMA,
    TOPOLOGY,
    _artifact,
    _check_isolation,
    _excluded,
    _read,
    _settings,
    _status,
    available_sources,
    build_job,
    package_works,
    review_index_names,
    run_sources,
)
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[3]


def _job_context(tmp_path: Path, *, config=None, target_root: Path | None = None) -> JobContext:
    loaded = load_config(ROOT / "appsec-review.toml")
    job_cfg = config if config is not None else loaded.job(JOB_ID)
    run_root = tmp_path / "run"
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt-1"
    attempt_root.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id="run-unit-1",
        attempt_id="attempt-1",
        trigger="cli",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=attempt_root / "meta",
        orchestration={},
        config=job_cfg,
        events=EventLog(attempt_root / "events.jsonl"),
        target_root=target_root,
        contract=CONTRACT,
    )


def test_contract_datasets_topology_and_registry_parity(tmp_path: Path) -> None:
    job = build_job(repository_root=ROOT)
    assert job.job_id == JOB_ID
    assert job.schema_identity == SCHEMA
    assert job.contract == CONTRACT
    assert job.datasets == DATASETS
    assert len(DATASETS) == 13
    assert {item.output_kind for item in DATASETS} == {
        "accepted_scope",
        "lead_triage",
        "review_packages",
        "review_cells",
        "claim_ledger",
        "attack_chains",
        "review_audit_metadata",
        "review_decision_audit",
        "review_decisions",
        "review_verification_coverage",
        "review_decision_bases",
        "review_audit_continuations",
        "scores_and_findings",
    }
    expected_units = tuple(
        f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks
    )
    assert tuple(unit.unit_id for unit in job.units) == expected_units
    assert set(LEDGER_UNITS).issubset(expected_units)

    reg_job = builtin_registry().build(JOB_ID)
    assert reg_job.job_id == JOB_ID
    assert reg_job.contract == CONTRACT
    assert reg_job.datasets == DATASETS

    ctx = _job_context(tmp_path)
    for validator in job.input_validators:
        validator(ctx, None)


def test_input_validator_rejects_mismatched_steps_tasks_and_untyped_settings(tmp_path: Path) -> None:
    job = build_job(repository_root=ROOT)
    validator = job.input_validators[0]
    loaded = load_config(ROOT / "appsec-review.toml")
    base_cfg = loaded.job(JOB_ID)

    missing_step_cfg = replace(
        base_cfg,
        steps=MappingProxyType({k: v for k, v in base_cfg.steps.items() if k != "scoring"}),
    )
    with pytest.raises(ValueError, match="topology does not match configuration"):
        validator(_job_context(tmp_path / "s1", config=missing_step_cfg), None)

    bad_task_step = replace(base_cfg.steps["scoring"], tasks=MappingProxyType({}))
    bad_tasks_cfg = replace(
        base_cfg,
        steps=MappingProxyType({**base_cfg.steps, "scoring": bad_task_step}),
    )
    with pytest.raises(ValueError, match="task order mismatch: scoring"):
        validator(_job_context(tmp_path / "s2", config=bad_tasks_cfg), None)

    untyped_cfg = replace(base_cfg, typed_settings=None)
    untyped_ctx = _job_context(tmp_path / "s3", config=untyped_cfg)
    with pytest.raises(ValueError, match="settings are not typed"):
        validator(untyped_ctx, None)

    u_ctx = UnitContext(
        job=untyped_ctx,
        unit_id="scope.accept_manifest",
        step_id="scope",
        task_id="accept_manifest",
        unit_root=untyped_ctx.attempt_root / "u",
        outputs={},
    )
    with pytest.raises(ValueError, match="settings are not typed"):
        _settings(u_ctx)


def test_status_artifact_and_read_integrity_guards(tmp_path: Path) -> None:
    assert _status([]) == "SUCCEEDED"
    assert _status(["gap-1"]) == "COMPLETED_WITH_GAPS"

    run_root = tmp_path / "run"
    payload = run_root / "data" / "doc.json"
    atomic_json(payload, {"hello": "world"})
    ref = _artifact(run_root, payload)
    assert ref["path"] == "data/doc.json"
    assert _read(run_root, ref) == {"hello": "world"}

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        _read(run_root, {"path": "../outside.json", "sha256": ref["sha256"]})

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        _read(run_root, {"path": "data/missing.json", "sha256": ref["sha256"]})

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        _read(run_root, {"path": "data/doc.json", "sha256": "0" * 64})


def test_check_isolation_and_excluded_reject_evaluator_and_target_guidance(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"target_root": "/safe/repo"}), encoding="utf-8")
    clean_scope = SimpleNamespace(
        manifest_path=manifest_path,
        shards=[{"relative_path": "data/indexes/source/index.sqlite"}],
        source_files=[
            SimpleNamespace(identity="f1", path="src/main.py"),
            SimpleNamespace(identity="f2", path="AGENTS.md"),
            SimpleNamespace(identity="f3", path="sub/.github/copilot-instructions.md"),
            SimpleNamespace(identity="f4", path="pkg/.cursor/rules/sec.mdc"),
            SimpleNamespace(identity="f5", path="appsec-multi-vuln-guide/expected.json"),
        ],
    )
    assert _excluded(clean_scope) == {"f2", "f3", "f4", "f5"}

    with pytest.raises(IntegrityError, match="accepted inputs name an evaluator root"):
        _check_isolation(clean_scope)

    safe_scope = SimpleNamespace(
        manifest_path=manifest_path,
        shards=[{"relative_path": "data/indexes/source/index.sqlite"}],
        source_files=[SimpleNamespace(identity="f1", path="src/main.py")],
    )
    _check_isolation(safe_scope)

    bad_shard_scope = SimpleNamespace(
        manifest_path=manifest_path,
        shards=[{"relative_path": "appsec-multi-vuln-guide/index.sqlite"}],
        source_files=[],
    )
    with pytest.raises(IntegrityError, match="accepted inputs name an evaluator root"):
        _check_isolation(bad_shard_scope)

    manifest_path.write_text(
        json.dumps({"target_root": "/tmp/appsec-multi-vuln-guide"}), encoding="utf-8"
    )
    with pytest.raises(IntegrityError, match="accepted inputs name an evaluator root"):
        _check_isolation(safe_scope)


def test_sources_index_names_and_package_works_tamper_guard(tmp_path: Path) -> None:
    assert run_sources(["source"]) == ()
    assert run_sources(["source", "control_evidence"]) == ("owasp_workbench",)
    assert "owasp_workbench" in available_sources(["control_evidence"], ["sink_site", "entry_point"])

    assert review_index_names(
        [
            {"name": "source"},
            {"name": "binary", "producer": {"binary_id": ""}},
        ]
    ) == ("source",)
    assert review_index_names(
        [
            {"name": "source"},
            {"name": "binary", "producer": {"binary_id": "bin-1"}},
        ]
    ) == ("binary", "source")

    run_root = tmp_path / "run"
    pkg_path = run_root / "pkg.json"
    atomic_json(pkg_path, {"schema": "appsec-review/review-package/7", "package_id": "pkg-1", "lead_menu": []})
    good_doc = {
        "packages": [
            {
                "package_id": "pkg-1",
                "lane": "lead",
                "sha256": file_sha256(pkg_path),
                "unit_key": "u1",
                "rank": [1, "pkg-1"],
                "basis": "b1",
                "entities": ["e1"],
                "path": "pkg.json",
            }
        ]
    }
    works = package_works(run_root, good_doc)
    assert len(works) == 1 and works[0].package_id == "pkg-1"

    bad_doc = {
        "packages": [
            {
                "package_id": "pkg-1",
                "lane": "lead",
                "sha256": "f" * 64,
                "unit_key": "u1",
                "rank": [1, "pkg-1"],
                "basis": "b1",
                "entities": ["e1"],
                "path": "pkg.json",
            }
        ]
    }
    with pytest.raises(IntegrityError, match="review package changed after assembly"):
        package_works(run_root, bad_doc)


def _alternate_cpg_inputs(tmp_path: Path, consumer_id: str):
    """Publish a tiny real graph product; stub only unrelated producer execution."""
    from appsec_review.jobs.bound_artifacts import artifact_ref
    from appsec_review.jobs.job_code_graph_index.alternate_cpg import (
        publish_alternate_cpg, synthesize_alternate_cpg,
    )
    from appsec_review.jobs.job_tree_sitter_ast.cfg import synthesize_file_cfg
    from appsec_review.retrieval import (
        EntityKind, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, write_manifest,
    )
    from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
    from appsec_review.runtime.contracts import JobContract
    from tests.downstream_contract_fixture import configuration
    from tests.unit.job_code_graph_index.test_alternate_cpg import _make_two_fn_ast

    config = configuration(tmp_path)
    runner = JobRunner(config)
    registry = builtin_registry()
    consumer = registry.build(consumer_id)
    target = tmp_path / "source"
    target.mkdir()
    source = target / "app.py"
    source.write_text(
        "# inert parser input; never executed\n"
        "def handle(input_val):\n"
        "    if input_val is not None:\n"
        "        return\n\n\n"
        "    return parse(input_val)\n\n\n"
        "def parse(payload):\n\n"
        "    eval(payload)\n" + "\n" * 8,
        encoding="utf-8",
    )
    source_sha = file_sha256(source)
    snapshot = "target-sha256:" + source_sha
    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": "app.py", "sha256": source_sha})
    ast = _make_two_fn_ast(
        fn_type="function_definition", body_type="block", if_type="if_statement",
        ret_type="return_statement", call_type="call", entry_name="handle",
        helper_name="parse", guard_expr="input_val is not None", sink_call="eval",
    )
    cfg = synthesize_file_cfg(ast, source.read_bytes(), language="python", path="app.py",
                              file_sha256=source_sha, source_identity=source_id.value)
    published = {}

    def graph_output(unit):
        root = unit.job.run_root
        cpg = synthesize_alternate_cpg(
            tree_sitter_files=[cfg], run_id=unit.job.run_id, target_snapshot=snapshot,
            route_entrypoints=[{"handler_symbol": "handle", "path": "app.py", "line": 2,
                                "language": "python", "route_pattern": "/", "http_method": "POST",
                                "framework": "fixture"}],
        )
        _, identity = publish_alternate_cpg(
            root, unit.unit_root, cpg, job_id=unit.job.config.job_id, unit_id=unit.unit_id,
            file_shas={"app.py": file_sha256(source)},
        )
        manifest = unit.unit_root / "manifest.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=snapshot,
                       target_root=target, indexes=(identity,))
        published.update(shard=asdict(identity), manifest=manifest)
        return {"index_manifest": artifact_ref(root, manifest),
                "index_identity": asdict(identity),
                "artifacts": [artifact_ref(root, root / identity.relative_path)]}

    def unrelated_output(unit):
        declarations = registry.build(unit.job.config.job_id).datasets
        identities = []
        for declaration in declarations:
            if not declaration.required:
                continue
            [index] = declaration.indexes
            path = unit.unit_root / f"{index}.sqlite"
            builder = IndexBuilder(path, name=index, fingerprint="a" * 64,
                                   target_snapshot=snapshot)
            builder.add_coverage("fixture", "unavailable", "unrelated producer execution is stubbed")
            identities.append(IndexIdentity(
                index, declaration.schema, builder.build(), "a" * 64,
                path.relative_to(unit.job.run_root).as_posix(),
                {"job": unit.job.config.job_id, "unit": unit.unit_id},
            ))
        manifest = unit.unit_root / "manifest.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=snapshot,
                       target_root=target, indexes=identities)
        output = {"index_manifest": artifact_ref(unit.job.run_root, manifest),
                  "artifacts": [artifact_ref(unit.job.run_root, unit.job.run_root / item.relative_path)
                                for item in identities]}
        if identities:
            [identity] = identities
            output["index_identity"] = asdict(identity)
        return output

    pins = {}
    run_id = None
    required = {item.producer for item in consumer.contract.inputs
                if item.output_kind == "handoff" and item.required(set())}
    for producer_id in ["job_code_graph_index", *sorted(required - {"job_code_graph_index"})]:
        registered = registry.build(producer_id)
        required_steps = {item.step for item in registered.datasets if item.required}
        unit_id = ("acceptance.publish_handoff" if producer_id == "job_code_graph_index"
                   else next(unit.unit_id for unit in registered.units
                             if not required_steps or unit.unit_id.split(".")[0] in required_steps))
        units = (Unit(unit_id, graph_output if producer_id == "job_code_graph_index"
                      else unrelated_output),)
        producer = Job(
            producer_id, registered.name, UnitExecutor(units).execute, units=units,
            datasets=registered.datasets, contract=JobContract(),
        )
        outcome = runner.run(producer, run_id=run_id, target_root=target, source_fingerprint=snapshot)
        run_id = outcome["status"]["run_id"]
        pins[producer_id] = outcome["handoff_sha256"]
    root = runner.runs.resolve(run_id)
    context = SimpleNamespace(
        config=config.job(consumer_id), contract=consumer.contract, run_root=root,
        upstream_handoffs=pins, evidence_target_snapshot=snapshot, external_input_selection=None,
    )
    core = RetrievalCore(root.parent, run_id, manifest_path=published["manifest"],
                         manifest_sha256=file_sha256(published["manifest"]))
    return context, core, published["shard"]


@pytest.mark.parametrize("consumer_id", (
    "job_inference_security_review", "job_review_package_assembly", "job_owasp_control_assessment",
))
def test_alternate_cpg_is_admitted_and_read_without_sticky_violation(tmp_path, consumer_id):
    from appsec_review.runtime.consume import accepted_upstream
    from appsec_review.runtime.inputs import admit_inputs, input_read_scope

    context, core, shard = _alternate_cpg_inputs(tmp_path, consumer_id)
    admission = admit_inputs(context, set(context.upstream_handoffs))
    with input_read_scope(context) as reads:
        accepted = accepted_upstream(context.run_root, "job_code_graph_index")
        result = core.query_call_paths()
        assert result["results"], "the admitted graph must be usable, not just declared"
        located = core.find(path="app.py", indexes=(shard["name"],))["results"]
        assert located and all(row["location"]["file_sha256"] == file_sha256(core.target_root / "app.py")
                               for row in located)
        assert reads.violation is None
    [receipt] = [row for row in reads.document()["reads"] if row["output_kind"] == "alternate_cpg_index"]
    assert receipt["sha256"] == shard["sha256"]
    assert receipt["handoff_sha256"] == accepted.sha256
    assert receipt["read"] is True and receipt["cited"] is None
    [supplied] = [row for row in admission["requirements"] if row["output_kind"] == "alternate_cpg_index"]
    assert supplied["available"] and supplied["supplied"] and not supplied["read"]


@pytest.mark.parametrize("consumer_id", (
    "job_inference_security_review", "job_review_package_assembly", "job_owasp_control_assessment",
))
@pytest.mark.parametrize("defect", ("unadmitted", "missing"))
def test_alternate_cpg_refuses_unadmitted_or_missing_bytes(tmp_path, consumer_id, defect):
    from appsec_review.runtime.inputs import input_read_scope

    context, core, shard = _alternate_cpg_inputs(tmp_path, consumer_id)
    if defect == "unadmitted":
        context.upstream_handoffs.pop("job_code_graph_index")
    else:
        (context.run_root / shard["relative_path"]).unlink()
    with pytest.raises(ValueError, match="input contract violation"):
        with input_read_scope(context) as reads:
            with pytest.raises((ValueError, OSError)):
                core.query_call_paths()
            assert reads.violation is not None
    assert not any(row["output_kind"] == "alternate_cpg_index" for row in reads.document()["reads"])
