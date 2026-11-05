"""I1: catalog -> real planner -> accepted reader/index. AUTHORED - NOT RUN.

R1/R2/R4/R5/R6/R9/R11: source-backed relationships survive publication;
recipe-less discovery is accepted without becoming execution authority.
"""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.build_topology import ready_build_units, topological_order
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis.job import build_job as environment_job
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_analysis_plan import build_job as planner_job, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.retrieval import RunIndexBackend, SearchRequest
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "topology_discovery"
SHARED_SOURCE = {
    "shared/CMakeLists.txt": "project(shared)\nadd_library(core STATIC core.c)\n",
    "shared/core.c": "int core(void) { return 7; }\n",
    "server/CMakeLists.txt": (
        "project(server)\nadd_executable(server main.c)\n"
        "target_link_libraries(server PRIVATE core)\n"
    ),
    "server/main.c": "int core(void); int main(void) { return core(); }\n",
    "client/CMakeLists.txt": (
        "project(client)\nadd_executable(client main.c)\n"
        "target_link_libraries(client PRIVATE core)\n"
    ),
    "client/main.c": "int core(void); int main(void) { return core(); }\n",
}


@pytest.fixture(autouse=True)
def offline_reporting(monkeypatch):
    from appsec_review.reporting import telemetry_finalize

    calls = []
    monkeypatch.setattr(telemetry_finalize, "render_telemetry_report",
                        lambda *args, **kwargs: calls.append((args, kwargs)))
    return calls


def fixture_json(name):
    path = FIXTURES / name
    assert path.stat().st_size <= 33554432
    return json.loads(path.read_bytes())


def frozen_synthetic(path):
    document, = [item for item in fixture_json("synthetic-cases.json")["documents"]
                 if item["path"] == path]
    assert hashlib.sha256(document["content"].encode()).hexdigest() == document["sha256"]
    return document["content"]


def isolated_config(tmp_path, *, model_enabled=False):
    config_path = tmp_path / "appsec-review.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    release_header = "[review_policy.releases]\n"
    model_header = "[jobs.job_target_analysis_plan.settings.model]\nenabled = true"
    assert text.count(release_header) == text.count(model_header) == 1
    text = text.replace(release_header, release_header + (
        'platform = "topology-ia-platform/1"\nvalidation = "topology-ia-validation/1"\n'
        'build_toolchain = "topology-ia-toolchain/1"\n'))
    text = text.replace(model_header, model_header.rsplit("true", 1)[0] + str(model_enabled).lower())
    config_path.write_bytes(text.encode())
    return load_config(config_path)


def run_pipeline(tmp_path, files, *, infer=None, environment=False, planner_transform=None):
    config = isolated_config(tmp_path, model_enabled=infer is not None)
    target = tmp_path / "target"
    target.mkdir()
    for relative, content in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    jobs = [intake_job(), catalog_job()]
    if environment:
        jobs.append(environment_job())
    planner = planner_job(infer=infer)
    jobs.append(planner if planner_transform is None else planner_transform(planner))
    runner = GraphRunner(config, jobs)
    result = runner.run(target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / result["run_id"]
    return config, target, runner, result, run_root, load_accepted_plan(run_root)


def final_proposal(request):
    recipes = []
    for unit in request.summary["build_units"]:
        root = unit["root"]
        build_dir = "build" if root == "." else root + "/build"
        recipes.append({
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": unit["required_image_profile"], "source_dir": root,
            "build_dir": build_dir, "system_packages": [], "environment": {},
            "dependency_files": [marker["path"] for marker in unit["markers"]],
            "configure_commands": [["cmake", "-S", root, "-B", build_dir]],
            "build_commands": [["cmake", "--build", build_dir]],
            "expected_outputs": [build_dir], "network_required": False,
            "reason": "synthetic descriptor-backed I/A recipe; never executed",
        })
    return {"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
            "build_recipes": recipes, "hints": [], "abstentions": []}


def test_shared_producer_relationship_survives_catalog_planning_publication_and_index(tmp_path):
    _config, target, _runner, result, root, plan = run_pipeline(tmp_path, SHARED_SOURCE)
    graph = plan["build_topology"]["executable_graph"]
    by_root = {node["root"]: node["build_unit_id"] for node in graph["nodes"]}
    assert set(by_root) == {"shared", "server", "client"}
    assert {(edge["producer_build_unit_id"], edge["consumer_build_unit_id"])
            for edge in graph["edges"]} == {
                (by_root["shared"], by_root["server"]),
                (by_root["shared"], by_root["client"]),
            }
    assert topological_order(graph)[0] == by_root["shared"]
    assert graph["source_fingerprint"] == source_fingerprint(target) == plan["source_fingerprint"]
    product, = [d for d in graph["declarations"]
                if d["owner_build_unit_id"] == by_root["shared"] and d["role"] == "static_archive"]
    assert product["origin"] == "source_declaration"
    edge = next(e for e in graph["edges"] if e["consumer_build_unit_id"] == by_root["server"])
    declaration, = [e for e in edge["evidence"] if e["relationship"] == "target_link_libraries"]
    assert declaration["path"] == "server/CMakeLists.txt" and declaration["line"] == 3
    assert declaration["sha256"] == hashlib.sha256(SHARED_SOURCE["server/CMakeLists.txt"].encode()).hexdigest()
    publication = result["jobs"]["job_target_analysis_plan"]["result"]["outputs"][
        "plan_acceptance.publish_handoff"]
    assert publication["build_topology_id"] == graph["topology_id"]
    hits = RunIndexBackend(root.parent).search(
        SearchRequest(root.name, "symbol", "tool-semgrep", limit=5)).hits
    assert any(hit.excerpt == "tool-semgrep" for hit in hits)
    assert load_accepted_plan(root) == plan


def test_recipe_less_accepted_plan_retains_unknown_enforcement_and_cannot_schedule(tmp_path):
    _config, _target, _runner, _result, root, plan = run_pipeline(tmp_path, SHARED_SOURCE)
    topology = plan["build_topology"]
    sealed = (root / json.loads((root / "data/jobs/job_target_analysis_plan/latest.json").read_bytes())[
        "handoff_path"]).read_bytes()
    assert all(action["recipe"] is None for action in topology["build_actions"])
    bound = topology["planning_refinement"]["units"]
    assert all(unit["recipe_digest"] is None and "recipe_missing" in unit["blockers"] for unit in bound)
    assert all(proof["status"] == "unknown" and proof["recipe_digest"] is None
               and proof["operation_binding"] is None
               for unit in bound for proof in unit["enforcement"])
    readiness = ready_build_units(topology["executable_graph"], {},
                                  refinement=topology["planning_refinement"])
    assert readiness["ready"] == []
    assert len(readiness["blocked"]) == 3
    assert load_accepted_plan(root)["build_topology"] == topology
    pointer = json.loads((root / "data/jobs/job_target_analysis_plan/latest.json").read_bytes())
    assert (root / pointer["handoff_path"]).read_bytes() == sealed


def test_accepted_reader_rejects_artifact_corruption_without_success_shaped_plan(tmp_path):
    _config, _target, _runner, result, root, _plan = run_pipeline(tmp_path, SHARED_SOURCE)
    publication = result["jobs"]["job_target_analysis_plan"]["result"]["outputs"][
        "plan_acceptance.publish_handoff"]
    artifact = root / publication["artifact"]["path"]
    before = artifact.read_bytes()
    artifact.write_bytes(before + b"\n")
    with pytest.raises(ValueError):
        load_accepted_plan(root)
    artifact.write_bytes(before)
    restored = load_accepted_plan(root)
    assert len(restored["build_topology"]["executable_graph"]["edges"]) == 2


def test_recipe_model_cannot_erase_the_complete_source_relationships(tmp_path):
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(copy.deepcopy(request.summary))
        value = final_proposal(request)
        value["hints"] = []
        return ModelResult(value)

    _config, _target, _runner, _result, root, plan = run_pipeline(
        tmp_path, SHARED_SOURCE, infer=infer)
    assert calls and all(summary["build_units"] for summary in calls)
    graph = load_accepted_plan(root)["build_topology"]["executable_graph"]
    owners = {node["root"]: node["build_unit_id"] for node in graph["nodes"]}
    assert {e["consumer_build_unit_id"] for e in graph["edges"]
            if e["producer_build_unit_id"] == owners["shared"]} == {owners["server"], owners["client"]}
    assert plan["model"]["status"] == "ACCEPTED"


def historical_graph1_producer(planner):
    """Emulate the historical producer, retaining real indexing/publication units."""
    from appsec_review.jobs.build_topology import _compile_graph1, validate_build_topology
    from appsec_review.jobs.job_target_analysis_plan.job import _artifact
    from appsec_review.runtime import UnitExecutor

    def historical_acceptance(unit):
        resolution = unit.output("analysis_decisions.resolve_ambiguity")
        plan = copy.deepcopy(resolution["plan"])
        topology = plan["build_topology"]
        topology["executable_graph"] = _compile_graph1(
            topology["build_actions"], source_fingerprint=plan["source_fingerprint"])
        topology.pop("evidence_bundle")
        topology.pop("planning_refinement")
        validate_build_topology(topology["executable_graph"])
        return {
            "status": "VALID", "plan": plan,
            "artifact": _artifact(unit, "historical-source-plan.json", plan),
            "gaps": plan["coverage_gaps"], "terminal_status": resolution["terminal_status"],
        }

    units = tuple(replace(unit, handler=historical_acceptance)
                  if unit.unit_id == "plan_acceptance.validate_plan" else unit for unit in planner.units)
    assert sum(unit.unit_id == "plan_acceptance.validate_plan" for unit in units) == 1
    return replace(planner, units=units, handler=UnitExecutor(units).execute)


def test_genuine_historical_accepted_plan_is_indexed_and_auditable_but_cannot_authorize_execution(tmp_path):
    from appsec_review.jobs.build_topology_artifacts import (
        guard_action, guard_build_cache, publish_refinement,
    )

    def infer(request, *, timeout_seconds):
        return ModelResult(final_proposal(request))

    _config, _target, _runner, result, root, accepted = run_pipeline(
        tmp_path, SHARED_SOURCE, infer=infer, planner_transform=historical_graph1_producer)
    graph = accepted["build_topology"]["executable_graph"]
    assert graph["schema"] == "appsec-review/build-topology/1"
    publication = result["jobs"]["job_target_analysis_plan"]["result"]["outputs"][
        "plan_acceptance.publish_handoff"]
    assert publication["build_topology_schema"] == graph["schema"]
    assert publication["build_topology_id"] == graph["topology_id"]
    assert publication["index_identity"]["sha256"]
    page = RunIndexBackend(root.parent).search(
        SearchRequest(root.name, "symbol", "planned-build", limit=10))
    assert any("planned-build:" in hit.excerpt for hit in page.hits)
    pointer = root / "data/jobs/job_target_analysis_plan/latest.json"
    sealed = pointer.read_bytes()
    readiness = ready_build_units(graph, {})
    assert readiness["ready"] == [] and len(readiness["blocked"]) == 3
    assert all(item["reasons"] == ["legacy_graph_requires_accepted_replanning"]
               for item in readiness["blocked"])
    action = accepted["build_topology"]["build_actions"][0]
    with pytest.raises(ValueError, match="graph/1"):
        guard_action(root, action, graph=graph)
    with pytest.raises(ValueError, match="graph/1"):
        guard_build_cache(root, "job_project_build", {"dispatches": [action]})
    with pytest.raises(ValueError, match="graph/1"):
        publish_refinement(root, [action])
    assert load_accepted_plan(root) == accepted
    assert pointer.read_bytes() == sealed
    assert not (root / "data/build/topology/accepted-refinements.json").exists()
