"""Composite review-graph topology, independent of the Dagster import.

The Dagster definitions build ``wave1_review`` from :func:`wave1_dependencies`, and the operator's
stepwise acceptance tool reads the same topology from the packaged code location through
``python -m appsec_review.orchestration.topology``. There is one copy of the wave order.

A job launched on its own (its single-job Dagster job) has no in-graph upstream. To execute it
exactly as the composite graph would, the launcher names the accepted upstream handoffs the graph
would have propagated in the :data:`UPSTREAM_HANDOFFS_TAG` run tag; :func:`tagged_upstream_handoffs`
verifies every reference against the application run's accepted pointers before the job binds them.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Set
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

UPSTREAM_HANDOFFS_TAG = "appsec/upstream_handoffs"
WAVE1_GRAPH = "wave1_review"
WAVE1_REQUIRED = frozenset({"job_model_connectivity", "job_review_intake", "job_target_catalog",
                            "job_target_analysis_plan"})
_JOB_ID = re.compile(r"job_[a-z0-9_]+")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def gate_ids(registered: Set[str]) -> tuple[str, ...]:
    """Pre-intake gates in dispatch order: the live model check, then the image-pin verification."""
    return tuple(job_id for job_id in ("job_model_connectivity", "job_image_pin_verification")
                 if job_id in registered)


def gate_dependencies(registered: Set[str]) -> dict[str, tuple[str, ...]]:
    gates = gate_ids(registered)
    return {job_id: ((gates[position - 1],) if position else ()) for position, job_id in enumerate(gates)}


def wave1_dependencies(registered: Set[str]) -> dict[str, tuple[str, ...]] | None:
    """Return ``wave1_review`` job dependencies keyed in dispatch order, or ``None`` when absent.

    ``registered`` holds the enabled registered job ids; a disabled job is transparent to topology.
    Iteration order of the returned mapping is a topological order of the graph.
    """

    if not WAVE1_REQUIRED <= registered:
        return None
    gates = gate_ids(registered)
    wave_dependencies: dict[str, tuple[str, ...]] = {
        **gate_dependencies(registered),
        "job_review_intake": (gates[-1],),
        "job_target_catalog": ("job_review_intake",),
    }
    if "job_ci_configuration_analysis" in registered:
        wave_dependencies["job_ci_configuration_analysis"] = ("job_target_catalog",)
    if "job_source_history_analysis" in registered:
        wave_dependencies["job_source_history_analysis"] = ("job_target_catalog",)
    wave_dependencies["job_target_analysis_plan"] = tuple(job_id for job_id in (
        "job_ci_configuration_analysis", "job_source_history_analysis") if job_id in registered) or (
        "job_target_catalog",)
    if "job_project_build" in registered:
        wave_dependencies["job_project_build"] = ("job_target_analysis_plan",)
    if "job_language_build" in registered:
        wave_dependencies["job_language_build"] = (("job_project_build",)
            if "job_project_build" in registered else ("job_target_analysis_plan",))
    if "job_tree_sitter_ast" in registered:
        wave_dependencies["job_tree_sitter_ast"] = (("job_language_build",)
            if "job_language_build" in registered else ("job_target_analysis_plan",))
    if "job_change_context_analysis" in registered and "job_source_history_analysis" in registered:
        wave_dependencies["job_change_context_analysis"] = (
            ("job_tree_sitter_ast",) if "job_tree_sitter_ast" in registered else ("job_target_analysis_plan",))
    if "job_artifact_indexing" in registered:
        wave_dependencies["job_artifact_indexing"] = (("job_language_build",)
            if "job_language_build" in registered else ("job_project_build",))
    if "job_test_coverage" in registered and "job_artifact_indexing" in registered:
        wave_dependencies["job_test_coverage"] = ("job_artifact_indexing",)
    if "job_profile_data" in registered and "job_artifact_indexing" in registered:
        wave_dependencies["job_profile_data"] = ("job_artifact_indexing",)
    if "job_artifact_security_analysis" in registered:
        wave_dependencies["job_artifact_security_analysis"] = (("job_artifact_indexing",)
            if "job_artifact_indexing" in registered else ("job_language_build",))
    if "job_evidence_collection" in registered:
        # Registered before the seeded Clang producers: their seeds are the finding locations this
        # job's accepted observations carry (docs/architecture/seeded-neighborhoods.md, section 2).
        wave_dependencies["job_evidence_collection"] = ("job_target_analysis_plan",)
    if "job_cpp_compiled_analysis" in registered:
        wave_dependencies["job_cpp_compiled_analysis"] = ((("job_language_build",)
            if "job_language_build" in registered else
            ("job_project_build",) if "job_project_build" in registered else ("job_target_analysis_plan",))
            + (("job_evidence_collection",) if "job_evidence_collection" in registered else ()))
    if "job_clang_static_analysis" in registered and "job_cpp_compiled_analysis" in registered:
        wave_dependencies["job_clang_static_analysis"] = ("job_cpp_compiled_analysis",)
    if "job_sanitizer_build" in registered and "job_language_build" in registered:
        # A sibling of the C/C++ analysis: it rebuilds the accepted native units with sanitizers in
        # its own workspace. No job consumes its output, so it is a leaf that the dataset inventory
        # job (derived from the leaves below) closes, and the graph keeps exactly one terminal job.
        wave_dependencies["job_sanitizer_build"] = ("job_language_build",)
    # The indexers and the SVF points-to producer consume only the accepted C++ handoff and never
    # wait for each other.
    for job_id in ("job_cpp_symbol_index", "job_cpg_analysis", "job_svf_alias_analysis"):
        if job_id in registered and "job_cpp_compiled_analysis" in registered:
            wave_dependencies[job_id] = ("job_cpp_compiled_analysis",)
    if "job_post_build_security_assessment" in registered:
        wave_dependencies["job_post_build_security_assessment"] = (("job_cpp_compiled_analysis",)
            if "job_cpp_compiled_analysis" in registered else
            ("job_project_build",) if "job_project_build" in registered else ("job_target_analysis_plan",))
    if "job_dependency_intelligence" in registered:
        wave_dependencies["job_dependency_intelligence"] = tuple(job_id for job_id in (
            "job_target_catalog", "job_language_build", "job_artifact_indexing",
            "job_evidence_collection", "job_cpp_compiled_analysis") if job_id in wave_dependencies)
    if "job_codeql_analysis" in registered:
        codeql_dependencies = [job_id for job_id in (
            "job_language_build", "job_artifact_indexing", "job_artifact_security_analysis",
            "job_cpp_compiled_analysis", "job_clang_static_analysis", "job_cpp_symbol_index", "job_cpg_analysis",
            "job_svf_alias_analysis",
            "job_post_build_security_assessment", "job_evidence_collection", "job_tree_sitter_ast",
            "job_change_context_analysis")
            if job_id in wave_dependencies]
        wave_dependencies["job_codeql_analysis"] = tuple(codeql_dependencies or ("job_target_analysis_plan",))
    if "job_owasp_control_assessment" in registered:
        build_terminal = ("job_post_build_security_assessment" if "job_post_build_security_assessment" in registered
                          else "job_cpp_compiled_analysis" if "job_cpp_compiled_analysis" in registered
                          else "job_project_build" if "job_project_build" in registered
                          else "job_target_analysis_plan")
        owasp_dependencies = [build_terminal]
        if "job_evidence_collection" in registered:
            owasp_dependencies.append("job_evidence_collection")
        if "job_artifact_security_analysis" in registered:
            owasp_dependencies.append("job_artifact_security_analysis")
        if "job_tree_sitter_ast" in registered:
            owasp_dependencies.append("job_tree_sitter_ast")
        if "job_codeql_analysis" in registered:
            owasp_dependencies.append("job_codeql_analysis")
        wave_dependencies["job_owasp_control_assessment"] = tuple(dict.fromkeys(owasp_dependencies))
    if "job_review_prioritization" in registered and "job_tree_sitter_ast" in registered:
        # Prioritization reads the accepted Tree-sitter, history, Semgrep, and CodeQL handoffs and
        # publishes a retrieval shard, so it follows the last manifest publisher before tagging.
        wave_dependencies["job_review_prioritization"] = tuple(job_id for job_id in (
            "job_codeql_analysis",) if job_id in registered) or tuple(
            job_id for job_id in ("job_evidence_collection", "job_tree_sitter_ast") if job_id in registered)
    if "job_code_graph_index" in registered and "job_codeql_analysis" in registered:
        # The graph index reads the accepted CodeQL exports and observations, the clangd/IR/AST shards
        # and the prioritization flow steps, and composes the accepted manifest, so it follows every
        # one of them and precedes the next manifest publisher (tagging, then data indexing).
        wave_dependencies["job_code_graph_index"] = tuple(job_id for job_id in (
            "job_codeql_analysis", "job_cpp_compiled_analysis", "job_clang_static_analysis",
            "job_cpp_symbol_index", "job_svf_alias_analysis", "job_tree_sitter_ast",
            "job_review_prioritization") if job_id in wave_dependencies)
    if "job_security_tagging" in registered:
        # Tagging reads the accepted retrieval manifest, so it follows its last publisher, and it
        # closes the wave so the graph keeps exactly one terminal job.
        tagging_dependencies = ["job_codeql_analysis"] if "job_codeql_analysis" in registered else [
            job_id for job_id in ("job_language_build", "job_artifact_indexing",
                                  "job_artifact_security_analysis", "job_cpp_compiled_analysis",
                                  "job_clang_static_analysis",
                                  "job_post_build_security_assessment", "job_evidence_collection",
                                  "job_tree_sitter_ast", "job_change_context_analysis") if job_id in registered]
        if "job_review_prioritization" in wave_dependencies:
            tagging_dependencies.append("job_review_prioritization")
        if "job_code_graph_index" in wave_dependencies:
            tagging_dependencies.append("job_code_graph_index")
        wave_dependencies["job_security_tagging"] = tuple(tagging_dependencies or ("job_target_analysis_plan",))
    if "job_owasp_control_assessment" in registered:
        # OWASP consumes classification, the tag cloud's accepted assignments and code-graph
        # context. It precedes data-index projection, hunt assembly and red/blue investigation.
        wave_dependencies["job_owasp_control_assessment"] = tuple(dict.fromkeys((
            *wave_dependencies["job_owasp_control_assessment"],
            *(job_id for job_id in ("job_review_prioritization", "job_code_graph_index",
                                    "job_security_tagging") if job_id in wave_dependencies),
        )))
    if "job_review_data_indexing" in registered:
        # The dataset inventory audits every accepted publisher, so it closes the wave after the last
        # enabled producer on every branch and keeps exactly one terminal job. Derive the leaves
        # instead of naming them: disabling any job must make that job transparent to topology.
        depended_on = {dependency for dependencies in wave_dependencies.values()
                       for dependency in dependencies}
        terminals = tuple(sorted(set(wave_dependencies) - depended_on))
        wave_dependencies["job_review_data_indexing"] = terminals or ("job_target_analysis_plan",)
    if "job_review_package_assembly" in registered:
        wave_dependencies["job_review_package_assembly"] = ("job_review_data_indexing",)
    if "job_document_issue_analysis" in registered:
        wave_dependencies["job_document_issue_analysis"] = ("job_review_package_assembly",)
    if "job_inference_security_review" in registered and "job_document_issue_analysis" in registered:
        # The near-terminal review reads the accepted manifest, which holds every index shard and the
        # assembled review packages, so it runs after both consumers of the index and is the one terminal job.
        wave_dependencies["job_inference_security_review"] = ("job_document_issue_analysis",)
    if "job_final_publication_gate" in registered and "job_inference_security_review" in registered:
        # The gate only projects the accepted review handoff and the artifacts it binds.
        wave_dependencies["job_final_publication_gate"] = ("job_inference_security_review",)
    if "job_poc_generation" in registered and "job_final_publication_gate" in registered:
        # Optional (disabled by default): proof-of-concept functions for the claims the judge agreed with.
        # It reads the accepted gate and review and the accepted native build, and the report shows its outcome.
        wave_dependencies["job_poc_generation"] = ("job_final_publication_gate",)
    if "job_final_report_publication" in registered and "job_final_publication_gate" in registered:
        # The report reads the accepted gate handoff (and the PoC handoff when the PoC job ran) and is the one
        # terminal job of the graph. A disabled PoC job is transparent: the report follows the gate.
        wave_dependencies["job_final_report_publication"] = (
            ("job_poc_generation",) if "job_poc_generation" in wave_dependencies else ("job_final_publication_gate",))
    return wave_dependencies


def upstream_closure(job_id: str, dependencies: Mapping[str, Iterable[str]],
                     propagating: Set[str]) -> tuple[str, ...]:
    """Jobs whose handoffs the composite graph hands to ``job_id``.

    Every finalized job passes on the handoffs it received and adds its own when it propagates, so a
    job receives every transitive ancestor that propagates its handoff.
    """

    seen: set[str] = set()
    pending = list(dependencies.get(job_id, ()))
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(dependencies.get(current, ()))
    return tuple(sorted(seen & set(propagating)))


def tagged_upstream_handoffs(run_root: Path, raw: str) -> dict[str, str]:
    """Verify a launcher-supplied upstream handoff set against the run's accepted pointers."""

    from appsec_review.storage import file_sha256

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} is not JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} must be a JSON object of job id to handoff sha256")
    run_root = Path(run_root).resolve()
    verified: dict[str, str] = {}
    for job_id, digest in sorted(value.items()):
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError(f"invalid upstream job id in {UPSTREAM_HANDOFFS_TAG}: {job_id!r}")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"invalid upstream handoff digest for {job_id}")
        pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
        if not pointer_path.is_file():
            raise ValueError(f"tagged upstream {job_id} has no accepted handoff in this run")
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            handoff_path = (run_root / str(pointer["handoff_path"])).resolve()
        except (KeyError, ValueError) as exc:
            raise ValueError(f"accepted pointer for {job_id} is corrupt") from exc
        if pointer.get("handoff_sha256") != digest:
            raise ValueError(f"tagged upstream {job_id} is not the run's accepted handoff")
        if run_root not in handoff_path.parents or not handoff_path.is_file():
            raise ValueError(f"accepted handoff for {job_id} escapes the run or is missing")
        if file_sha256(handoff_path) != digest:
            raise ValueError(f"accepted handoff for {job_id} does not match its digest")
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        if handoff.get("job_id") != job_id or handoff.get("status") != "ACCEPTED":
            raise ValueError(f"tagged upstream {job_id} is not an accepted handoff of that job")
        verified[job_id] = digest
    return verified


def accepted_upstream_handoffs(run_root: Path, job_ids: Iterable[str]) -> dict[str, str]:
    """The run's accepted handoff of every job in ``job_ids``, verified like a tagged set."""

    digests = {}
    for job_id in job_ids:
        pointer = Path(run_root) / "data" / "jobs" / job_id / "latest.json"
        if not pointer.is_file():
            raise ValueError(f"upstream {job_id} has no accepted handoff in this run")
        try:
            digests[job_id] = json.loads(pointer.read_text(encoding="utf-8"))["handoff_sha256"]
        except (KeyError, ValueError) as exc:
            raise ValueError(f"accepted pointer for {job_id} is corrupt") from exc
    return tagged_upstream_handoffs(run_root, json.dumps(digests))


def launch_upstream_handoffs(runs_dir: Path, tags: Mapping[str, str], *,
                             in_graph: bool) -> dict[str, str] | None:
    """Return the verified tagged upstream handoffs of a standalone launch, or ``None`` untagged.

    Only a job with no in-graph upstream may take tagged handoffs, and only inside an existing
    application run named by ``appsec/application_run_id``.
    """

    raw = tags.get(UPSTREAM_HANDOFFS_TAG)
    if raw is None:
        return None
    if in_graph:
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} is only valid for a job without in-graph upstream")
    run_id = tags.get("appsec/application_run_id")
    if not run_id:
        raise ValueError(f"{UPSTREAM_HANDOFFS_TAG} requires appsec/application_run_id")
    from appsec_review.storage import RunStore

    return tagged_upstream_handoffs(RunStore(Path(runs_dir)).resolve(run_id), raw)


def describe_wave1(config: Any, registry: Any, include: Iterable[str] = ()) -> dict[str, Any]:
    """Describe ``wave1_review`` as the packaged code location builds it.

    ``include`` names registered jobs to treat as enabled, so a manually invoked job that is disabled in the
    graph (``job_poc_generation``) can be given the upstream handoffs it would have in the graph.
    """

    from appsec_review.runtime import job_is_enabled

    registered = {job_id for job_id in registry.job_ids() if job_is_enabled(config, job_id)}
    registered |= {job_id for job_id in include if job_id in set(registry.job_ids())}
    dependencies = wave1_dependencies(registered)
    if dependencies is None:
        raise ValueError("wave1_review is not defined by this configuration")
    propagating = {job_id for job_id in dependencies if registry.build(job_id).propagate_handoff}
    return {
        "schema": "appsec-review/graph-topology/1",
        "graph": WAVE1_GRAPH,
        "upstream_handoffs_tag": UPSTREAM_HANDOFFS_TAG,
        "jobs": [{
            "job_id": job_id,
            "name": config.job(job_id).name,
            "dependencies": list(dependencies[job_id]),
            "propagate_handoff": job_id in propagating,
            "upstream_handoffs": list(upstream_closure(job_id, dependencies, propagating)),
        } for job_id in dependencies],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the wave1_review topology as JSON.")
    parser.add_argument("--config", default=os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml"))
    args = parser.parse_args(argv)
    from appsec_review.config import load_config
    from appsec_review.runtime.registry import builtin_registry

    json.dump(describe_wave1(load_config(args.config), builtin_registry()), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
