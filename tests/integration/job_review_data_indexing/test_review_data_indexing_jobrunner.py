"""Whole-job JobRunner integration scenarios for job_review_data_indexing and package consumers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from appsec_review.indexing import input_matrix, matrix, products
from appsec_review.graph.contract import Family
from appsec_review.jobs.job_review_data_indexing.job import DOWNSTREAM_JOBS, registry_providers
from appsec_review.jobs.job_review_package_assembly import build_job as build_package_job
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.observations import SEVERITY_RULE
from appsec_review.retrieval.precomputed import RETIRED_GRAPH_SETS
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.storage import atomic_json, file_sha256
from tests.test_review_data_indexing import (
    FOLLOW_UP_SETS,
    LocalSqliteFts,
    SECRETS,
    SNAPSHOT,
    _accepted_run,
    _configured,
    _facts,
    _run,
    accepted as _accepted_fixture,
)

pytestmark = pytest.mark.integration

accepted = _accepted_fixture


def _write(root: Path, relative: str, content=None) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({} if content is None else content), encoding="utf-8")
    return path


def test_sast_lead_menus_are_complete_and_traceable(accepted) -> None:
    config, run_id, _run_root, _target, ids, outcome, _executor = accepted
    assert outcome["handoff"]["status"] == "ACCEPTED"
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    facts = _facts(core, "scanner_correlation")
    leads = {item["payload"]["result"]["observation_id"]: item["payload"]["result"] for item in facts
             if item["payload"]["fact_type"] == "lead"}
    assert set(leads) == {ids[key] for key in ("o1", "o2", "o3", "o4", "o5", "o6")}
    assert leads[ids["o2"]]["suppressed"] is True and leads[ids["o2"]]["suppression_ids"] == ["sup-1"]
    assert leads[ids["o3"]]["normalized_reported_severity"] == "unknown"
    assert leads[ids["o6"]]["normalized_reported_severity"] == "critical"
    assert leads[ids["o6"]]["severity_basis"] == "security-severity-cvss-band"
    duplicated = [key for key in ("o1", "o5") if leads[ids[key]]["duplicate_of"]]
    assert len(duplicated) == 1
    menus = [item["payload"]["result"] for item in facts if item["payload"]["fact_type"] == "menu"]
    high = {member["observation_id"] for menu in menus if menu["menu"] == "high_critical" for member in menu["members"]}
    assert high == {ids[key] for key in ("o1", "o2", "o5", "o6")}
    assert {member["observation_id"] for item in menus if item["menu"] == "unknown"
            for member in item["members"]} == {ids["o3"]}
    audit = next(item["payload"]["result"] for item in facts if item["payload"]["fact_type"] == "audit")
    assert audit["status"] == "passed" and audit["counts"]["high_critical_suppressed"] == 1
    assert audit["counts"]["high_critical_duplicates"] == 1


def test_review_packages_keep_complete_membership_and_detect_tampering(accepted) -> None:
    from appsec_review.review_packages import (_identity, assemble_review_packages, publish_review_packages,
                                                validate_packages, verify_review_packages)

    config, run_id, _run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    packages, manifest = assemble_review_packages(core, max_page_size=20)
    finding = [item for item in packages if item["kind"] == "finding_lead"]
    hunts = [item for item in packages if item["kind"] == "hunt"]
    assert {item["lead_menu"][0]["observation_id"] for item in finding} == {
        ids[key] for key in ("o1", "o2", "o3", "o4", "o5", "o6")}
    assert {lead["observation_id"] for item in hunts for lead in item["lead_menu"]} == {
        ids[key] for key in ("o1", "o2", "o3", "o5", "o6")}
    assert manifest["counts"] == {"finding_lead": 6, "hunt": len(hunts), "document_hunt": 0,
                                  "high_critical": 4, "unknown": 1}
    assert any(gap["state"] == "partial" for gap in manifest["coverage_gaps"])
    assert any(item["metrics"] for item in packages)
    assert any(item["build_context"]["command_facts"] for item in packages)
    auth = next(item for item in finding if item["lead_menu"][0]["observation_id"] == ids["o1"])
    assert auth["build_context"]["bindings"][0]["function_scope_id"] == ids["auth-function"]
    assert auth["build_context"]["bindings"][0]["action_ids"] == [ids["action"]]
    assert auth["tag_context"]["cloud"] == [{"tag": "surface:memory", "assignment_count": 2}]
    assert auth["compiled_context"][0]["entity_id"] == ids["ast-check"]
    assert all(metric["scope_id"] != ids["other-function"] for metric in auth["metrics"])
    assert not any(secret in json.dumps(auth) for secret in SECRETS)
    assert not any(item["tag"] == "surface:command" for item in auth["tag_context"]["assignments"])
    util = next(item for item in finding if item["lead_menu"][0]["observation_id"] == ids["o2"])
    assert not util["build_context"]["command_facts"]
    assert util["build_context"]["bindings"][0]["function_scope_id"] is None
    assert any(gap["producer"] == "function_scope" for gap in util["coverage_gaps"])
    assert assemble_review_packages(core, max_page_size=20) == (packages, manifest)
    expected = {"all": {item["lead_menu"][0]["observation_id"] for item in finding}, "documents": set(),
                "high_critical": {lead["observation_id"] for item in hunts for lead in item["lead_menu"]
                                  if lead["reported_severity"] in {"high", "critical"}},
                "unknown": {lead["observation_id"] for item in hunts for lead in item["lead_menu"]
                            if lead["reported_severity"] == "unknown"}}
    audit = {"status": "passed", "counts": {"source_sast_observations": 6,
             "high_critical": 4, "unknown_severity": 1}}
    missing = deepcopy(packages)
    changed = next(item for item in missing if item["kind"] == "hunt" and len(item["lead_menu"]) > 1)
    changed["lead_menu"].pop()
    changed["package_id"] = _identity(changed)
    with pytest.raises(ValueError, match="membership"):
        validate_packages(core, missing, expected, audit)
    extra = deepcopy(packages)
    extra[0]["unexpected"] = True
    with pytest.raises(Exception, match="unexpected"):
        validate_packages(core, extra, expected, audit)
    from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
    secret = b"integration-capability-secret-32-bytes"
    selected = finding[0]
    token = issue_capability(selected, role="red", round_id="1", secret=secret,
                             expires_at=int(datetime.now(timezone.utc).timestamp()) + 300)
    scoped = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), selected, capability=token,
                                       secret=secret, role="red", round_id="1")
    subject = selected["lead_menu"][0]["observation_id"]
    assert scoped.call("query_precomputed", {"query_set": "scanner_correlation", "subject": subject,
                                             "limit": 1})["results"]
    auth_token = issue_capability(auth, role="red", round_id="1", secret=secret,
                                  expires_at=int(datetime.now(timezone.utc).timestamp()) + 300)
    auth_scoped = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), auth, capability=auth_token,
                                            secret=secret, role="red", round_id="1")
    assert auth_scoped.call("find", {"identity": ids["auth-tag"]})["results"]
    assert auth_scoped.call("find", {"identity": ids["ast-check"]})["results"]
    assert auth_scoped.call("find", {"identity": ids["auth-function"]})["results"]
    assert auth_scoped.call("find", {"identity": ids["action"]})["results"]
    with pytest.raises(ValueError, match="outside review package"):
        auth_scoped.call("find", {"identity": ids["util-tag"]})
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("find", {"identity": next(item["lead_menu"][0]["observation_id"] for item in finding
                                                if item["package_id"] != selected["package_id"])})
    directory = publish_review_packages(core, max_page_size=20)
    assert verify_review_packages(core, directory) == manifest
    target = directory / f"{finding[0]['package_id']}.json"
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        verify_review_packages(core, directory)


def test_package_projection_rejects_rehashed_grant_evidence_context_and_gap_changes(accepted, monkeypatch):
    from appsec_review.retrieval.model import canonical_json
    from appsec_review import review_packages as packages
    config, run_id, _run_root, *_ = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    original = packages.publish_review_packages(core)
    manifest = json.loads((original / "manifest.json").read_bytes())

    def forbidden(*args, **kwargs):
        raise AssertionError("serialized validation must not reconstruct packages")

    monkeypatch.setattr(packages, "assemble_review_packages", forbidden)
    packages.verify_review_packages(core, original)
    for kind in ("finding_lead", "hunt"):
        entry = next(item for item in manifest["packages"] if item["kind"] == kind)
        baseline = json.loads((original / f"{entry['package_id']}.json").read_bytes())
        for field in ("retrieval", "evidence", "context_ids", "coverage_gaps"):
            changed = deepcopy(baseline)
            if field == "retrieval":
                changed[field]["max_pages"] += 1
            else:
                assert changed[field], field
                changed[field].pop()
            changed["package_id"] = packages._identity(changed)
            altered = deepcopy(manifest)
            replacement = next(item for item in altered["packages"] if item["package_id"] == entry["package_id"])
            replacement.update(package_id=changed["package_id"], sha256=packages._digest(changed))
            altered.pop("content_sha256")
            altered["content_sha256"] = packages._digest(altered)
            destination = original.parent / altered["content_sha256"]
            shutil.copytree(original, destination)
            (destination / f"{entry['package_id']}.json").unlink()
            (destination / f"{changed['package_id']}.json").write_bytes(canonical_json(changed) + b"\n")
            (destination / "manifest.json").write_bytes(canonical_json(altered) + b"\n")
            with pytest.raises(ValueError, match="validated assembly projection"):
                packages.verify_review_packages(core, destination)


def test_query_observations_filters_and_paginates_without_raw_output(accepted) -> None:
    config, run_id, _run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    adapter = RetrievalMcpAdapter(core)
    high = adapter.call("query_observations", {"severity": "high", "observation_class": "source_sast"})
    assert {item["identity"] for item in high["results"]} == {ids["o1"], ids["o5"]}
    assert all(item["reported_severity"]["rule"] == SEVERITY_RULE for item in high["results"])
    assert {item["reported_severity"]["native"] for item in high["results"]} == {"ERROR", "HIGH"}
    assert any("opengrep scan timed out" in gap for gap in high["coverage_gaps"])
    suppressed = core.query_observations(suppressed=True)
    assert [item["identity"] for item in suppressed["results"]] == [ids["o2"]]
    assert core.query_observations(duplicate=True)["results"][0]["lead_state"]["duplicate_of"]
    assert [item["identity"] for item in core.query_observations(severity="unknown")["results"]] == [ids["o3"]]
    located = core.query_observations(path="src/auth.c", start_line=2, end_line=2, scanner="tool-semgrep")
    assert [item["identity"] for item in located["results"]] == [ids["o1"]]
    assert [item["identity"] for item in core.query_observations(source=ids["src/util.c"])["results"]] == [ids["o2"]]
    first = core.query_observations(observation_class="source_sast", limit=2)
    assert first["results"][0]["reported_severity"]["value"] == "critical"
    second = core.query_observations(observation_class="source_sast", limit=2, cursor=first["pagination"]["next_cursor"])
    assert not {item["identity"] for item in first["results"]} & {item["identity"] for item in second["results"]}
    with pytest.raises(ValueError):
        core.query_observations(observation_class="source_sast", limit=3, cursor=first["pagination"]["next_cursor"])
    with pytest.raises(ValueError):
        core.query_observations(severity="severe")
    with pytest.raises(ValueError):
        core.query_observations(start_line=2)


def test_build_facts_keep_order_and_never_expose_exact_argv_or_environment(accepted) -> None:
    config, run_id, run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    facts = _facts(core, "build_provenance")
    action = next(item["payload"]["result"] for item in facts if item["payload"]["fact_type"] == "build_action")
    command = action["command_facts"][0]
    assert set(command) == {"build_action_id", "tool_id", "ordered_tokens", "exact_artifact_sha256",
                            "normalization_rule"}
    assert [token["ordinal"] for token in command["ordered_tokens"]] == list(range(10))
    kinds = [token["kind"] for token in command["ordered_tokens"]]
    assert kinds[:4] == ["tool", "mode", "optimization", "security_flag"]
    assert "-D_FORTIFY_SOURCE=2" in action["security_flags"] and "-fstack-protector-strong" in action["security_flags"]
    assert action["source_inputs"] == ["target:src/auth.c"]
    define = next(token for token in command["ordered_tokens"] if token["kind"] == "define")
    assert define["redacted"] is True and "supersecretvalue" not in json.dumps(define)
    environment = {item["class"]: item for item in action["environment_facts"]}
    assert environment["loader_injection"]["present"] and "safe_value" not in environment["loader_injection"]
    assert environment["toolchain_selection"]["safe_value"] == "gcc"
    assert environment["compiler_flags"]["safe_value"] == "-fstack-protector-strong"
    assert "sensitive_variable" in environment
    chain = next(item["payload"]["result"] for item in facts if item["payload"].get("subject_identity") == ids["exe"])
    assert chain["sources"] == [ids["src/auth.c"]] and chain["observations"] == [ids["sec"]]
    for database in (run_root / "data" / "indices").rglob("*.sqlite"):
        if "precomputed" in database.parts or "inventory" in database.parts or "links" in database.parts:
            raw = database.read_bytes()
            assert not any(secret.encode() in raw for secret in SECRETS), database


def test_metric_vectors_mark_missing_values_unknown_not_zero(accepted) -> None:
    config, run_id, _run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    vector = next(item["payload"]["result"] for item in _facts(core, "history_context")
                  if item["payload"]["fact_type"] == "metric_vector"
                  and item["payload"].get("subject_identity") == ids["priority"])
    metrics = {item["name"]: item for item in vector["metrics"]}
    assert metrics["revision_count"]["value"] == 9 and metrics["revision_count"]["window_days"] == 365
    assert metrics["sii_score"]["producer"] == "job_source_history_analysis"
    assert metrics["cognitive"]["algorithm_version"] == "appsec-review/cognitive-complexity-approx/1"
    assert metrics["cyclomatic_high_risk_share"]["status"] == "unavailable"
    assert metrics["cyclomatic_high_risk_share"]["value"] is None and metrics["cyclomatic_high_risk_share"]["gap_id"]
    assert metrics["cyclomatic_mean"]["gap_id"] == "cyclomatic_mean_not_produced_by_prioritization"


@pytest.mark.time_budget(60, reason="User-approved F02 exception, 2026-11-06 via coordinator "
                        "02825845-7ac6-4a31-b648-999b3823ecf5: real indexing-to-package publication, "
                        "partial-tree recovery and context bindings; includes setup/call/teardown")
def test_package_job_publishes_accepted_manifest_and_receipts(accepted, monkeypatch) -> None:
    config, run_id, run_root, target, ids, indexing, _executor = accepted
    from appsec_review.review_packages import assemble_review_packages
    seed_core = RetrievalCore(config.runtime.runs_dir, run_id)
    seed_packages, seed_manifest = assemble_review_packages(seed_core)
    partial = run_root / "data" / "review-packages" / seed_manifest["content_sha256"]
    partial.mkdir(parents=True)
    atomic_json(partial / f"{seed_packages[0]['package_id']}.json", seed_packages[0])
    import appsec_review.review_packages as package_module
    assembly_calls = []

    def counted_assembly(*args, **kwargs):
        assembly_calls.append(1)
        return assemble_review_packages(*args, **kwargs)

    monkeypatch.setattr(package_module, "assemble_review_packages", counted_assembly)
    outcome = JobRunner(config).run(
        build_package_job(), run_id=run_id, target_root=target, source_fingerprint=SNAPSHOT,
        upstream_handoffs={"job_review_data_indexing": indexing["handoff_sha256"]})
    assert outcome["handoff"]["status"] == "ACCEPTED"
    assert len(assembly_calls) == 1
    result = outcome["result"]["outputs"]["publication.publish_packages"]
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    from appsec_review.review_packages import verify_review_packages
    manifest = verify_review_packages(core, run_root / result["package_directory"])
    assert manifest["accepted_manifest_sha256"] == core.manifest_sha256
    assert manifest["counts"]["finding_lead"] == 6
    assert result["package_count"] == len(manifest["packages"])
    assert result["coverage_gap_count"] == len(manifest["coverage_gaps"])
    assert {item["path"] for item in outcome["handoff"]["artifacts"]} >= {
        item["path"] for item in result["artifacts"]}
    auth = next(json.loads((run_root / result["package_directory"] / f"{item['package_id']}.json").read_text())
                for item in manifest["packages"]
                if json.loads((run_root / result["package_directory"] / f"{item['package_id']}.json").read_text())
                ["lead_menu"][0]["observation_id"] == ids["o1"])
    assert auth["build_context"]["bindings"][0]["function_scope_id"] == ids["auth-function"]
    assert auth["tag_context"]["cloud"]
    assert auth["compiled_context"]


@pytest.mark.time_budget(45, reason="User-approved F02 exception, 2026-11-06 via coordinator "
                        "02825845-7ac6-4a31-b648-999b3823ecf5: real 16-unit indexing publication, "
                        "inventory, matrices, links and FTS transport; includes setup/call/teardown")
def test_inventory_audit_matrices_links_and_fts_validation(accepted) -> None:
    config, run_id, _run_root, _target, ids, outcome, executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    adapter = RetrievalMcpAdapter(core)
    audit = adapter.call("query_dataset_inventory", {"record_type": "audit"})["results"][0]["payload"]
    assert audit["status"] == "PASSED", audit["violations"]
    rows = [item["payload"] for item in core.query_dataset_inventory(record_type="dataset",
                                                                    job="job_review_data_indexing", limit=100)["results"]]
    assert {row["query_set"] for row in rows if row["output_kind"] == "precomputed_products"} >= set(products.FIRST_STAGE_SETS)
    assert {row["output_kind"] for row in rows} >= {
        "accepted_input_summary", "cross_domain_links", "precomputed_products", "derived_checkpoints",
        "fts_image_validation", "dataset_audit_report", "coverage_matrices", "dataset_inventory"}
    self_row = next(row for row in rows if row["output_kind"] == "dataset_inventory")
    assert self_row["index"]["hash_resolution"] == "accepted_manifest"
    unavailable = core.query_dataset_inventory(record_type="dataset", disposition="unavailable", limit=100)
    assert unavailable["results"] and all(item["payload"]["coverage"]["reason"] for item in unavailable["results"])
    assert not any(item["payload"].get("job_id") == "job_review_package_assembly"
                   for item in unavailable["results"])
    sources = []
    cursor = None
    while True:
        page = core.query_dataset_inventory(cell_type="input_source", limit=100, cursor=cursor)
        sources.extend(page["results"])
        cursor = page["pagination"]["next_cursor"]
        if cursor is None:
            break
    disabled = {job_id for job_id, job in config.jobs.items() if job.settings.get("enabled") is False}
    expected_sources = {source if source != "secret_leads" else "<redacted>"
                        for source, producers, *_ in input_matrix.INPUT_SOURCES
                        if any(producer.removeprefix("planned:") not in disabled for producer in producers)}
    assert {item["payload"]["source"] for item in sources} == expected_sources
    assert len(sources) == len(expected_sources)
    assert all(item["payload"]["source"] != "joern_cpg" for item in sources)
    language = core.query_dataset_inventory(cell_type="language", limit=100)["results"]
    native = next(item["payload"] for item in language if item["payload"]["language"] == "c/c++")
    assert native["lanes"]["cpg_graph"]["state"] == "unavailable" and native["lanes"]["codeql"]["state"] == "complete"
    assert all(item["payload"]["lanes"]["code_graph"]["state"] == "unavailable" for item in language)
    assert native["lanes"]["code_graph"]["basis"] == matrix.GRAPH_UNAVAILABLE
    assert set(native["lanes"]["code_graph"]["families"]) == {family.value for family in Family}
    follow_up = core.query_dataset_inventory(cell_type="graph_follow_up", limit=100)["results"]
    names = sorted(item["payload"]["query_set"] for item in follow_up)
    assert names == sorted(name if "secret" not in name else "<redacted>" for name in FOLLOW_UP_SETS)
    assert {item["payload"]["status"] for item in follow_up} == {"pending_follow_up"}
    hotspot = next(item["payload"] for item in follow_up if item["payload"]["query_set"] == "hotspot_context")
    assert "no language has accepted graph coverage" in hotspot["missing_prerequisite"]
    assert "c/c++" in hotspot["graph_coverage"]["unavailable"]
    matrix_sets = {name for item in sources for name in item["payload"]["query_sets"]}
    assert not matrix_sets & set(RETIRED_GRAPH_SETS)
    fts = core.query_dataset_inventory(cell_type="fts_validation")["results"][0]["payload"]
    assert fts["status"] == "verified" and fts["image_id"] == executor.image_id
    assert executor.calls == ["probe", "build", "verify"]
    package = core.find(kind="dependency_package", indexes=("links",))["results"]
    assert package and package[0]["payload"]["identity_basis"] == "name-only"
    traced = core.trace(identity=package[0]["identity"], relations=("AFFECTED_BY",), depth=1)
    assert traced["results"] and not traced["results"][0]["exact"]
    assert outcome["result"]["outputs"]["publish.inventory_index"]["index_manifest"]["path"]


def test_rerun_reuses_unchanged_products_and_rebuilds_only_changed_rule(accepted, monkeypatch) -> None:
    config, run_id, _run_root, target, _ids, _outcome, executor = accepted
    second = _run(config, run_id, target, executor)
    outputs = second["result"]["outputs"]
    assert all(outputs[f"precompute.{name}"]["reused"] for name in products.FIRST_STAGE_SETS)
    assert all(item["reused"] for item in outputs["links.cross_domain"]["links"])
    changed = tuple(replace(rule, version="dependency-advisories/99") if rule.query_set == "dependency_advisories"
                    else rule for rule in products.PRODUCT_RULES)
    monkeypatch.setattr(products, "PRODUCT_RULES", changed)
    third = _run(config, run_id, target, executor)["result"]["outputs"]
    assert not third["precompute.dependency_advisories"]["reused"]
    assert all(third[f"precompute.{name}"]["reused"] for name in products.FIRST_STAGE_SETS
               if name != "dependency_advisories")


def test_audit_violation_blocks_acceptance_but_keeps_report(tmp_path_factory) -> None:
    tmp_path = tmp_path_factory.mktemp("v")
    config = _configured(tmp_path)
    run_id, run_root, target, _ids = _accepted_run(tmp_path, config)
    stray = run_root / "data" / "stray" / "unexpected.bin"
    stray.parent.mkdir(parents=True)
    stray.write_bytes(b"x")
    pointer = (run_root / "data" / "indices" / "accepted.json").read_bytes()
    with pytest.raises(Exception, match="partial failure|audit"):
        _run(config, run_id, target, LocalSqliteFts(run_root, "sha256:" + "0" * 64))
    reports = list(run_root.glob("data/jobs/job_review_data_indexing/attempts/*/steps/audit/tasks/inventory/inventory.json"))
    assert reports
    violations = json.loads(reports[0].read_text(encoding="utf-8"))["audit"]["violations"]
    assert any(item["code"] == "unaccounted_file" and item["subject"] == "data/stray/unexpected.bin"
               for item in violations)
    assert (run_root / "data" / "indices" / "accepted.json").read_bytes() == pointer


@pytest.mark.parametrize("shared_output", [False, True])
def test_indexing_can_resume_after_real_downstream_attempts(accepted, shared_output) -> None:
    config, run_id, root, target, _ids, _outcome, executor = accepted
    job_id = "job_document_issue_analysis"
    declarations = registry_providers()[1][job_id]

    def publish(unit):
        if shared_output:
            from appsec_review.storage.shared import SharedArtifacts, put_bytes
            shared = SharedArtifacts.for_job(unit.job)
            hit = shared.lookup("document-issues", "a" * 64)
            if hit is None:
                artifact = put_bytes(root, b'{"fixture":true}\n')
                receipt = shared.computed("document-issues", "a" * 64, artifact,
                                          computation={"fixture": True})
            else:
                value, receipt = hit
                artifact = value["object"]
            return {"artifact": artifact, "shared_receipt": receipt}
        path = _write(root, "data/document-issues/fixture/ledger.json", {"fixture": True})
        return {"artifact": {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)}}

    job = Job(job_id, "document_issue_analysis", publish, units=(Unit("analysis.map_and_adjudicate", publish),),
              datasets=declarations)
    downstream = JobRunner(config).run(job, run_id=run_id, source_fingerprint=SNAPSHOT,
                                       orchestration={"system": "dagster", "run_id": "downstream-invocation"})

    def fail(unit):
        if shared_output:
            publish(unit)
        raise ValueError("expected retained failure")

    with pytest.raises(RuntimeError, match="expected retained failure"):
        JobRunner(config).run(replace(job, units=(Unit("analysis.map_and_adjudicate", fail),)),
                              run_id=run_id, source_fingerprint=SNAPSHOT,
                              orchestration={"system": "dagster", "run_id": "failed-invocation"})
    retained = {path: path.read_bytes() for path in (root / "data/jobs" / job_id).rglob("*") if path.is_file()}
    outcome = _run(config, run_id, target, executor)
    report = json.loads((Path(outcome["attempt_root"]) / "steps/audit/tasks/inventory/inventory.json").read_text())
    assert report["audit"]["status"] == "PASSED"
    assert not any(row["job_id"] in DOWNSTREAM_JOBS for row in report["rows"])
    provenance = {row["dagster_run_id"] for row in report["file_ownership"] if row["job_id"] == job_id}
    assert {"downstream-invocation", "failed-invocation"} <= provenance
    assert all(path.read_bytes() == content for path, content in retained.items())
    assert file_sha256(Path(downstream["attempt_root"]) / "handoff.json") == downstream["handoff_sha256"]
