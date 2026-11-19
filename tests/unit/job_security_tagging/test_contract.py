from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.collation import ModelPassSettings
from appsec_review.jobs.job_security_tagging import build_job
from appsec_review.jobs.job_security_tagging import job as job_module
from appsec_review.jobs.job_security_tagging.cloud import build_cloud
from appsec_review.jobs.job_security_tagging.collation import collect_facets
from appsec_review.jobs.job_security_tagging.crosswalk import parse_crosswalk, scope_key
from appsec_review.jobs.job_security_tagging.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_security_tagging.model_pass import (
    PROPOSAL_SCHEMA,
    ProposalRejected,
    _excerpts,
    _validate,
    run_model_pass,
)
from appsec_review.jobs.job_security_tagging.producers import (
    AcceptedIndexes,
    Row,
    _extract,
    collect_source_facts,
    component_topology_sha256,
    ownership_rules,
    resolve_scope,
)
from appsec_review.jobs.job_security_tagging.taxonomy import TaxonomyError, assignment
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.runtime.contracts import DispatchClass, TargetAccess
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json
from tests.test_security_tagging import RUN_ID, SNAPSHOT, _run_fixture
from tests.unit.job_security_tagging.helpers import (
    CannedIndexes,
    DATA,
    ROOT,
    fact,
    scope,
    settings,
    shard,
    taxonomy,
    unit_context,
)


def _job_context(config, run_root: Path, target: Path, *, attempt_id: str = "attempt_0001",
                 source_fingerprint: str = SNAPSHOT):
    job_cfg = config.job("job_security_tagging")
    attempt_root = run_root / "data" / "jobs" / "job_security_tagging" / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        repository_root=config.runtime.runs_dir.parent,
        run_root=run_root,
        run_id=RUN_ID,
        attempt_id=attempt_id,
        attempt_root=attempt_root,
        config=job_cfg,
        tools=config.tools,
        source_fingerprint=source_fingerprint,
        target_root=target,
        events=SimpleNamespace(write=lambda *args, **kwargs: None),
    )


def test_contract_datasets_and_registry_parity() -> None:
    built = build_job()
    assert built.job_id == "job_security_tagging"
    assert built.schema_identity == job_module.SCHEMA
    assert built.datasets == DATASETS
    assert built.contract == CONTRACT
    assert CONSUMES == CONTRACT.consumes
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.schedule_after == ("job_codeql_analysis", "job_review_prioritization", "job_code_graph_index")
    assert {item.output_kind for item in DATASETS} == {"tag_assignments", "tagging_documents"}
    assert builtin_registry().build("job_security_tagging").job_id == "job_security_tagging"


def test_unit_executor_drives_all_twelve_units_and_reuses_existing_shards(tmp_path: Path) -> None:
    config, run_root, target = _run_fixture(tmp_path)
    built = build_job()
    ctx = _job_context(config, run_root, target, attempt_id="attempt_0001")
    for validator in built.input_validators:
        validator(ctx, None)
    result = built.execute(ctx)
    outputs = result["outputs"]
    assert set(outputs) == {
        f"{step}.{task}"
        for step, tasks in job_module.TOPOLOGY.items()
        for task in tasks
    }
    handoff = outputs["publication.publish_handoff"]
    assert handoff["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert handoff["security_findings"] == []
    assert handoff["assignment_count"] > 0

    validated_path = run_root / outputs["integrity.validate_assignments"]["artifact"]["path"]
    records = json.loads(validated_path.read_text(encoding="utf-8"))["assignments"]
    by_tag: dict[str, list[dict]] = {}
    for record in records:
        by_tag.setdefault(record["tag"], []).append(record)
    assert "cwe:89" in by_tag and "capec:66" in by_tag
    assert "surface:boundary:ci-trust" in by_tag
    assert "role:auth" in by_tag and "target:library" in by_tag
    assert "gap:no-sast:tool-semgrep" in by_tag and "gap:catalog-fixture" in by_tag

    scope_doc = json.loads((run_root / outputs["scope.resolve_inputs"]["artifact"]["path"]).read_text(encoding="utf-8"))
    assert scope_doc["schema"] == job_module.SCOPE_SCHEMA
    assert scope_doc["component_topology_sha256"] == component_topology_sha256(
        scope_doc["components"], ownership_rules()
    )

    manifest_info = outputs["publication.publish_index"]["index_manifest"]
    core = RetrievalCore(
        config.runtime.runs_dir,
        RUN_ID,
        manifest_path=run_root / manifest_info["path"],
        manifest_sha256=manifest_info["sha256"],
    )
    hits = core.search(query="cwe", indexes=("tags",), kinds=("tag_assignment",), limit=100)
    assert any(hit["name"] == "cwe:89" for hit in hits["results"])

    # Second attempt hits attest_existing() for already-materialized identical shards.
    ctx2 = _job_context(config, run_root, target, attempt_id="attempt_0002")
    second = built.execute(ctx2)
    assert (
        second["outputs"]["publication.publish_index"]["shards"]
        == outputs["publication.publish_index"]["shards"]
    )


def test_settings_config_and_custody_validators_fail_closed(tmp_path: Path) -> None:
    base = settings()
    with pytest.raises(ValueError, match="taxonomy settings"):
        job_module._settings({**base, "taxonomy": {"vocabulary_path": "x"}})
    with pytest.raises(ValueError, match="configured bound is invalid: max_entities_per_shard"):
        job_module._settings({**base, "max_entities_per_shard": True})
    with pytest.raises(ValueError, match="configured bound is invalid: max_assignments"):
        job_module._settings({**base, "max_assignments": 0})
    with pytest.raises(ValueError, match="unknown keys"):
        job_module._settings({**base, "unexpected": 1})

    config, run_root, target = _run_fixture(tmp_path)
    ctx = _job_context(config, run_root, target)
    bad_steps = replace(ctx.config, steps={})
    with pytest.raises(ValueError, match="topology does not match"):
        job_module._validate_config(SimpleNamespace(**{**ctx.__dict__, "config": bad_steps}), None)
    bad_task = dict(ctx.config.steps)
    bad_task["taxonomy"] = replace(bad_task["taxonomy"], tasks={})
    with pytest.raises(ValueError, match="task order mismatch: taxonomy"):
        job_module._validate_config(SimpleNamespace(**{**ctx.__dict__, "config": replace(ctx.config, steps=bad_task)}), None)

    unit = unit_context(tmp_path, "scope.resolve_inputs")
    escaped = tmp_path / "outside.json"
    escaped.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="failed integrity verification"):
        job_module._read(unit, {"path": "../../outside.json", "sha256": "0" * 64})
    written = job_module._write(unit, "sample.json", {"schema": job_module.SCOPE_SCHEMA})
    with pytest.raises(ValueError, match="failed integrity verification"):
        job_module._read(unit, {**written, "sha256": "f" * 64})

    # Scope integrity checks: schema, ownership_rules, component_topology_sha256.
    bad_schema = job_module._write(unit, "bad-schema.json", {"schema": "wrong"})
    with pytest.raises(ValueError, match="scope schema is unsupported"):
        job_module._scope(unit_context(tmp_path, "collection.source_facts",
                                       {"scope.resolve_inputs": {"artifact": bad_schema}}))
    bad_rules = job_module._write(unit, "bad-rules.json", {
        "schema": job_module.SCOPE_SCHEMA, "ownership_rules": {"version": "tampered"},
        "components": [], "component_topology_sha256": "0" * 64,
    })
    with pytest.raises(ValueError, match="ownership rules changed"):
        job_module._scope(unit_context(tmp_path, "collection.source_facts",
                                       {"scope.resolve_inputs": {"artifact": bad_rules}}))
    bad_topo = job_module._write(unit, "bad-topo.json", {
        "schema": job_module.SCOPE_SCHEMA, "ownership_rules": ownership_rules(),
        "components": [], "component_topology_sha256": "0" * 64,
    })
    with pytest.raises(ValueError, match="component topology does not match"):
        job_module._scope(unit_context(tmp_path, "collection.source_facts",
                                       {"scope.resolve_inputs": {"artifact": bad_topo}}))


def test_resolve_inputs_manifest_drift_and_integrity_errors(tmp_path: Path) -> None:
    config, run_root, target = _run_fixture(tmp_path)
    built = build_job()
    handlers = {u.unit_id: u.handler for u in built.units}

    # Target fingerprint mismatch in resolve_inputs.
    bad_ctx = _job_context(config, run_root, target, source_fingerprint="target-sha256:" + "9" * 64)
    tax = handlers["taxonomy.load_taxonomy"](
        job_module.UnitContext(bad_ctx, "taxonomy.load_taxonomy", "taxonomy", "load_taxonomy",
                               bad_ctx.attempt_root / "taxonomy", {})
    )
    with pytest.raises(ValueError, match="target fingerprint does not match"):
        handlers["scope.resolve_inputs"](
            job_module.UnitContext(bad_ctx, "scope.resolve_inputs", "scope", "resolve_inputs",
                                   bad_ctx.attempt_root / "scope", {"taxonomy.load_taxonomy": tax})
        )

    # Manifest drift in _indexes.
    ok_ctx = _job_context(config, run_root, target)
    with pytest.raises(ValueError, match="accepted index manifest changed"):
        job_module._indexes(
            job_module.UnitContext(ok_ctx, "collection.source_facts", "collection", "source_facts",
                                   ok_ctx.attempt_root / "collection",
                                   {"scope.resolve_inputs": {"accepted_manifest": {"sha256": "0" * 64}}})
        )

    # validate_assignments rejects derived record citing unknown assignment_id and observed lacking evidence.
    vocabulary, _, crosswalk = taxonomy()
    subj = {"kind": "project", "logical_id": "project:1", "component_id": None, "project_id": "project:1"}
    dangling = assignment(
        vocabulary=vocabulary, tag="capec:66", basis="derived", subject=subj,
        producer={"name": "tag-crosswalk", "rule_id": "r", "version": crosswalk.sha256},
        derived_from=["tag-assignment:missing"], crosswalk_rule="r", crosswalk_sha256=crosswalk.sha256,
    )
    u_base = unit_context(tmp_path / "val", "taxonomy.load_taxonomy")
    tax_out = handlers["taxonomy.load_taxonomy"](u_base)
    empty_art = job_module._write(u_base, "empty.json", {"assignments": []})
    dangling_art = job_module._write(u_base, "dangling.json", {"assignments": [dangling]})
    outputs = {uid: {"artifact": empty_art} for uid in (*job_module.COLLECTORS, *job_module.COLLATION_UNITS)}
    outputs["taxonomy.load_taxonomy"] = tax_out
    outputs["crosswalk.apply_crosswalk"] = {"artifact": dangling_art}
    with pytest.raises(TaxonomyError, match="unknown input"):
        handlers["integrity.validate_assignments"](
            unit_context(tmp_path / "val", "integrity.validate_assignments", outputs)
        )


def test_cloud_crosswalk_and_producer_edge_branches(tmp_path: Path) -> None:
    vocabulary, rules, _ = taxonomy()
    unrecorded_subject = {"kind": "source_file", "logical_id": "sf:1", "component_id": None, "project_id": "p"}
    sink = assignment(
        vocabulary=vocabulary, tag="func:data:sql-query", basis="invoked", subject=unrecorded_subject,
        producer={"name": "g"}, evidence=[{"ref": "sf:1"}], flow_role="sink",
    )
    guard = assignment(
        vocabulary=vocabulary, tag="func:telemetry:audit-log", basis="invoked", subject=unrecorded_subject,
        producer={"name": "g"}, evidence=[{"ref": "sf:1"}], flow_role="guard",
    )
    declared_sql = assignment(
        vocabulary=vocabulary, tag="func:data:orm", basis="declared", subject=unrecorded_subject,
        producer={"name": "manifest"}, evidence=[{"ref": "sf:1"}],
    )
    cwe_rec = assignment(
        vocabulary=vocabulary, tag="cwe:89", basis="reported", subject=unrecorded_subject,
        producer={"name": "semgrep"}, evidence=[{"ref": "sf:1"}],
    )
    cloud = build_cloud(vocabulary, [declared_sql, sink, guard, cwe_rec])
    assert "func:data" in cloud["views"]["red"]
    assert "func:telemetry" in cloud["views"]["blue"]
    assert cloud["rollup_gaps"]

    # Crosswalk parser edge errors + scope_key / namespace matching.
    base_rule = {
        "id": "r1", "scope": "same_subject", "source": "published",
        "when": {"all": [{"namespace": "cwe", "basis_at_least": "reported"}]},
        "emit": ["capec:66"],
    }
    parsed = parse_crosswalk({"schema": "appsec-review/tag-crosswalk/1", "rules": [base_rule]}, "a" * 64, vocabulary)
    assert len(parsed.rules) == 1
    with pytest.raises(TaxonomyError, match="unsupported crosswalk schema"):
        parse_crosswalk({"schema": "bad"}, "a" * 64, vocabulary)
    for bad_rule, match in (
        ({**base_rule, "id": ""}, "missing or duplicated"),
        ({**base_rule, "scope": "bad"}, "scope is unsupported"),
        ({**base_rule, "source": "bad"}, "source is invalid"),
        ({**base_rule, "when": {}}, "non-empty 'all'"),
        ({**base_rule, "emit": ["capec:66", "capec:66"]}, "distinct tags"),
    ):
        with pytest.raises(TaxonomyError, match=match):
            parse_crosswalk({"schema": "appsec-review/tag-crosswalk/1", "rules": [bad_rule]}, "a" * 64, vocabulary)
    for bad_when, match in (
        ({"all": [{"any": []}]}, "non-empty list"),
        ({"all": [{"tag": "cwe:89", "bogus": 1}]}, "unknown keys"),
        ({"all": [{}]}, "exactly one tag or namespace"),
        ({"all": [{"tag": "cwe:89", "flow_role": "bogus"}]}, "flow role is invalid"),
        ({"all": [{"namespace": "nist53r5"}]}, "unregistered or proposed"),
    ):
        with pytest.raises(TaxonomyError, match=match):
            parse_crosswalk({"schema": "appsec-review/tag-crosswalk/1",
                             "rules": [{**base_rule, "when": bad_when}]}, "a" * 64, vocabulary)
    with pytest.raises(TaxonomyError, match="scope is unsupported"):
        scope_key("invalid_scope", sink)

    # Producer extractors and source-fact edge branches.
    cert_row = Row("obs:1", "tool_observation", "MEM30-C", "MEM30-C", {}, None)
    assert _extract("cert-rule-id", cert_row, "MEM30-C", rules) == [("cert-c:mem30-c", "reported", "cert-rule-id")]
    assert _extract("cert-rule-id", cert_row, "not-a-cert-rule", rules) == []
    with pytest.raises(TaxonomyError, match="unknown extractor"):
        _extract("no-such-extractor", cert_row, "MEM30-C", rules)

    no_loc = Row("sf:0", "source_file", "x.py", "x.py", {"language": "Python"}, None)
    swift_row = Row("sf:1", "source_file", "App.swift", "App.swift", {"language": "Swift"},
                    {"path": "App.swift", "file_sha256": "1" * 64, "start_line": 1, "end_line": 1})
    unknown_lang = Row("sf:2", "source_file", "Main.zig", "Main.zig", {"language": "Brainfuck"},
                       {"path": "Main.zig", "file_sha256": "2" * 64, "start_line": 1, "end_line": 1})
    idxs = CannedIndexes(groups=[(shard("source"), [no_loc, swift_row, unknown_lang])])
    _, gaps = collect_source_facts(idxs, scope(), vocabulary, rules, 2, enable_swift=False)
    assert any("source-file bound 2" in g for g in gaps)


def test_collation_and_model_pass_edge_branches(tmp_path: Path) -> None:
    vocabulary, rules, _ = taxonomy()
    cfg = load_config(ROOT / "appsec-review.toml").job("job_security_tagging").settings
    coll_settings = job_module._collation_settings(cfg)

    # Empty component, build-glue component, plain component (no facet), and OpenAPI + test component.
    comp_a = {"component_id": "component:aaa_empty", "logical_id": "comp:empty", "root": "empty",
              "manifest": "empty/package.json", "ecosystem": "node"}
    comp_b = {"component_id": "component:api", "logical_id": "comp:api", "root": "api",
              "manifest": "api/pyproject.toml", "ecosystem": "python"}
    comp_c = {"component_id": "component:glue", "logical_id": "comp:glue", "root": "glue",
              "manifest": "glue/pyproject.toml", "ecosystem": "python"}
    comp_d = {"component_id": "component:plain", "logical_id": "comp:plain", "root": "plain",
              "manifest": "plain/pyproject.toml", "ecosystem": "python"}
    sc = scope((comp_a, comp_b, comp_c, comp_d))
    src_row = Row(
        LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "api/test_app.py"}).value,
        "source_file", "api/test_app.py", "test_app.py", {"language": "Python"},
        {"path": "api/test_app.py", "file_sha256": "1" * 64, "start_line": 1, "end_line": 2,
         "start_byte": 0, "end_byte": 29, "start_column": 1, "end_column": 10,
         "target_snapshot": SNAPSHOT, "mapping_method": "exact", "confidence": 1.0},
    )
    glue_row = Row(
        LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "glue/setup.py"}).value,
        "source_file", "glue/setup.py", "setup.py", {"language": "Python"},
        {"path": "glue/setup.py", "file_sha256": "3" * 64, "start_line": 1, "end_line": 1,
         "start_byte": 0, "end_byte": 10, "start_column": 1, "end_column": 10,
         "target_snapshot": SNAPSHOT, "mapping_method": "exact", "confidence": 1.0},
    )
    plain_row = Row(
        LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "plain/util.py"}).value,
        "source_file", "plain/util.py", "util.py", {"language": "Python"},
        {"path": "plain/util.py", "file_sha256": "4" * 64, "start_line": 1, "end_line": 1,
         "start_byte": 0, "end_byte": 6, "start_column": 1, "end_column": 6,
         "target_snapshot": SNAPSHOT, "mapping_method": "exact", "confidence": 1.0},
    )
    doc_row = Row(
        LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, SNAPSHOT, {"path": "api/openapi.yaml"}).value,
        "document_record", "api/openapi.yaml", "openapi.yaml", {"document_kind": "openapi"},
        {"path": "api/openapi.yaml", "file_sha256": "2" * 64, "start_line": 1, "end_line": 1,
         "target_snapshot": SNAPSHOT},
    )
    unknown_doc = Row(
        LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, SNAPSHOT, {"path": "api/readme.md"}).value,
        "document_record", "api/readme.md", "readme.md", {"kind": "markdown", "path": "api/readme.md"},
        None,
    )
    build_row = Row(
        LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"id": "b1"}).value,
        "build_action", "b1", "build",
        {"build_points": ["not-a-mapping", {"kind": "static_library", "sources": ["api/test_app.py"]}]},
        None,
    )
    build_row_2 = Row(
        LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"id": "b2"}).value,
        "build_action", "b2", "build", {"build_points": []}, None,
    )
    idxs = CannedIndexes(
        groups=[
            (shard("source"), [src_row, glue_row, plain_row]),
            (shard("documents"), [doc_row, unknown_doc]),
            (shard("build"), [build_row, build_row_2]),
        ],
        data={
            "api/test_app.py": b"def test_ok():\n    assert True\n",
            "glue/setup.py": b"x = 1\n",
            "plain/util.py": b"x = 1\n",
        },
    )
    records, gaps, doc = collect_facets(idxs, sc, vocabulary, rules, coll_settings, [], 10)
    assert any("no_first_party_files:component:aaa_empty" in g for g in gaps)
    assert any("target_class_unresolved:component:plain" in g for g in gaps)
    assert doc["sources"]["documents"] == "available"
    assert doc["sources"]["build"] == "unavailable"
    assert any("no_build_facts" in gap for gap in gaps)
    assert not any(record["subject"].get("component_id") == "component:api" for record in records)
    _, trunc_gaps, _ = collect_facets(idxs, sc, vocabulary, rules, coll_settings, [], 1)
    assert any("collation:build_bound" in g for g in trunc_gaps)
    assert any("collation:documents_bound" in g for g in trunc_gaps)

    # Model pass: infer=None records model_pass_unavailable gap; _excerpts handles unreadable/oversized/budget;
    # _validate rejects malformed proposals across each guard.
    model_cfg = {
        "enabled": True, "provider": "offline", "model": "fixture", "reasoning": "high",
        "max_input_tokens": 32768, "max_output_tokens": 4096, "timeout_seconds": 60, "retries": 0,
    }
    enabled_settings = replace(
        coll_settings,
        model_pass=ModelPassSettings(enabled=True, max_components=1, max_excerpt_lines=40, model=model_cfg),
    )
    mp_records, mp_gaps, mp_doc = run_model_pass(
        repository_root=ROOT, run_root=tmp_path / "run", indexes=idxs, scope=sc,
        vocabulary=vocabulary, rules_sha256=rules.sha256, settings=enabled_settings,
        collation=doc, facet_records=records, infer=None, limit=10, unit_id="collation.model_pass",
    )
    assert mp_records == [] and mp_doc["mode"] == "enabled"
    assert any("no inference transport is wired" in g for g in mp_gaps)

    bad_repo = tmp_path / "missing-guidance"
    (bad_repo / "pipeline" / "guidance").mkdir(parents=True)
    (bad_repo / "pipeline" / "guidance" / "registry.json").write_text("{}", encoding="utf-8")
    _, guid_gaps, _ = run_model_pass(
        repository_root=bad_repo, run_root=tmp_path / "run2", indexes=idxs, scope=sc,
        vocabulary=vocabulary, rules_sha256=rules.sha256, settings=enabled_settings,
        collation=doc, facet_records=records, infer=lambda req, timeout_seconds: None, limit=10,
        unit_id="collation.model_pass",
    )
    assert any("guidance assembly failed" in g for g in guid_gaps)

    from appsec_review.inference import ModelResult
    calls = []

    def unknown_purpose(req, timeout_seconds):
        calls.append(req)
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_id": req.allowed_components[0],
                            "role": [], "asset": [], "purpose": "", "claims": [],
                            "unknown": ["role", "asset", "purpose"]})

    _, bound_gaps, bound_doc = run_model_pass(
        repository_root=ROOT, run_root=tmp_path / "run3", indexes=idxs, scope=sc,
        vocabulary=vocabulary, rules_sha256=rules.sha256, settings=enabled_settings,
        collation=doc, facet_records=records, infer=unknown_purpose, limit=10,
        unit_id="collation.model_pass",
    )
    assert any("max_components 1 reached" in g for g in bound_gaps)
    assert bound_doc["components"][0] == {
        "component_id": "component:aaa_empty", "status": "skipped", "reason": "no first-party file"}
    assert bound_doc["components"][1] == {
        "component_id": "component:api", "status": "skipped", "reason": "no first-party file"}
    assert bound_doc["components"][2]["component_id"] == "component:glue"
    assert bound_doc["components"][2]["status"] == "accepted"
    assert len(calls) == 1 and calls[0].allowed_components == ("component:glue",)

    err_idxs = CannedIndexes(data=OSError("disk error"))
    ex_gaps: list[str] = []
    _excerpts(
        indexes=err_idxs, sources={"api/test_app.py": (src_row, shard("source"))},
        paths=["api/test_app.py", "missing.py"], cited={}, settings=enabled_settings,
        gaps=ex_gaps, component_id="component:api",
    )
    assert any("disk error" in g for g in ex_gaps)

    small_settings = replace(enabled_settings, max_source_bytes_per_file=5)
    size_gaps: list[str] = []
    _excerpts(
        indexes=idxs, sources={"api/test_app.py": (src_row, shard("source"))},
        paths=["api/test_app.py"], cited={}, settings=small_settings,
        gaps=size_gaps, component_id="component:api",
    )
    assert any("exceeds max_source_bytes_per_file" in g for g in size_gaps)

    budget_settings = replace(
        enabled_settings,
        model_pass=ModelPassSettings(enabled=True, max_components=1, max_excerpt_lines=1, model=model_cfg),
    )
    budget_gaps: list[str] = []
    _excerpts(
        indexes=idxs, sources={"api/test_app.py": (src_row, shard("source"))},
        paths=["api/test_app.py"], cited={}, settings=budget_settings,
        gaps=budget_gaps, component_id="component:api",
    )
    assert any("max_excerpt_lines 1 reached" in g for g in budget_gaps)

    valid_base = {
        "schema": PROPOSAL_SCHEMA, "component_id": "component:api",
        "role": ["role:auth"], "asset": [], "purpose": "handles auth", "unknown": [],
        "claims": [{"tag": "role:auth", "citations": [{"path": "api/test_app.py", "line": 1}]}],
    }
    checked = _validate(
        valid_base, component_id="component:api", vocabulary=vocabulary,
        excerpt_keys={("api/test_app.py", 1)}, assignment_ids=set(),
    )
    assert checked["role"] == ["role:auth"]
    for bad_prop, msg in (
        ({}, "closed unit-purpose-proposal/1 set"),
        ({**valid_base, "component_id": "other"}, "does not match"),
        ({**valid_base, "role": "not-list"}, "bounded list"),
        ({**valid_base, "role": ["not-a-term"]}, "outside the vocabulary"),
        ({**valid_base, "purpose": " leading space"}, "trimmed string"),
        ({**valid_base, "unknown": ["bogus"]}, "unknown must name"),
        ({**valid_base, "claims": "bad"}, "bounded list"),
        ({**valid_base, "claims": [{"tag": "role:auth"}]}, "claim keys"),
        ({**valid_base, "claims": [{"tag": "role:admin", "citations": []}]}, "does not assert"),
        ({**valid_base, "claims": [{"tag": "role:auth", "citations": []}]}, "no bounded citation"),
        ({**valid_base, "claims": [{"tag": "role:auth", "citations": ["bad"]}]}, "not an object"),
        ({**valid_base, "claims": [{"tag": "role:auth", "citations": [{"path": "x", "line": 99}]}]}, "not supplied"),
        ({**valid_base, "claims": [{"tag": "role:auth", "citations": [{"assignment_id": "missing"}]}]}, "did not carry"),
        ({**valid_base, "claims": [{"tag": "role:auth", "citations": [{"weird": 1}]}]}, "neither a supplied line"),
        ({**valid_base, "claims": []}, "without a claim"),
    ):
        with pytest.raises(ProposalRejected, match=msg):
            _validate(
                bad_prop, component_id="component:api", vocabulary=vocabulary,
                excerpt_keys={("api/test_app.py", 1)}, assignment_ids=set(),
            )
