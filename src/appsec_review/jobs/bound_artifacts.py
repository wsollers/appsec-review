"""Hash-bound reads of run-owned artifacts for jobs that only project accepted state.

The final publication gate and the final report publication read artifacts that earlier jobs
accepted. Every read goes through :func:`read_bound`, which re-hashes the bytes, so a file changed
after acceptance is an :class:`IntegrityError` and never a quietly different report.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

from appsec_review.review.models import IntegrityError
from appsec_review.storage import file_sha256

if TYPE_CHECKING:
    from appsec_review.retrieval.core import RetrievalCore
    from appsec_review.runtime.contracts import InputRequirement
    from appsec_review.runtime.datasets import DatasetDeclaration


def artifact_ref(run_root: Path, path: Path) -> dict[str, str]:
    """``{path, sha256}`` of a run-owned file, the path relative to the run root."""
    resolved = Path(path).resolve()
    root = Path(run_root).resolve()
    if root not in resolved.parents:
        raise IntegrityError(f"artifact is outside the run: {path}")
    return {"path": resolved.relative_to(root).as_posix(), "sha256": file_sha256(resolved)}


def resolve_bound(run_root: Path, reference: Mapping[str, Any]) -> Path:
    """The file a reference names, after proving it is a regular run-owned file with that hash."""
    root = Path(run_root).resolve()
    name = reference.get("path")
    digest = reference.get("sha256")
    if not isinstance(name, str) or not isinstance(digest, str):
        raise IntegrityError("artifact reference is malformed")
    path = root / name
    if path.is_symlink():
        raise IntegrityError(f"run-owned artifact is a symbolic link: {name}")
    resolved = path.resolve()
    if root not in resolved.parents or not resolved.is_file():
        raise IntegrityError(f"run-owned artifact is missing or outside the run: {name}")
    if file_sha256(resolved) != digest:
        raise IntegrityError(f"run-owned artifact changed after acceptance: {name}")
    return resolved


def read_bound(run_root: Path, reference: Mapping[str, Any]) -> bytes:
    return resolve_bound(run_root, reference).read_bytes()


def read_bound_json(run_root: Path, reference: Mapping[str, Any]) -> Any:
    try:
        return json.loads(read_bound(run_root, reference).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise IntegrityError(f"run-owned artifact is not valid JSON: {reference.get('path')}") from exc


def source_context_datasets() -> dict[str, tuple[DatasetDeclaration, ...]]:
    """Original evidence outputs used by downstream source/context readers, not graph ancestors."""
    from importlib import import_module
    selections = (
        ("job_target_catalog", ("source_files", "declaration_symbols", "target_documents")),
        ("job_tree_sitter_ast", ("tree_sitter_ast", "tree_sitter_coverage")),
        ("job_cpp_compiled_analysis", ("clang_ast", "llvm_ir", "binary_symbols", "infer_observations",
                                       "cpp_blocked_branches")),
        ("job_cpp_symbol_index", ("clangd_symbols", "clangd_coverage")),
        ("job_svf_alias_analysis", ("svf_alias_sets", "svf_alias_scope_coverage")),
        ("job_code_graph_index", ("code_graph_facts",)),
        ("job_codeql_analysis", ("codeql_observations",)),
        ("job_evidence_collection", ("static_tool_observations",)),
        ("job_clang_static_analysis", ("clang_static_observations", "clang_static_scope_coverage")),
        ("job_cpg_analysis", ("cpg_graph_coverage", "cpg_scope_coverage")),
        ("job_ci_configuration_analysis", ("ci_observations", "ci_findings")),
        ("job_artifact_security_analysis", ("artifact_security_observations",)),
        ("job_binary_evidence_indexing", ("binary_functions",)),
        ("job_dependency_intelligence", ("dependency_context",)),
        ("job_review_prioritization", ("priority_items",)),
        ("job_security_tagging", ("tag_assignments",)),
        ("job_review_data_indexing", ("cross_domain_links", "precomputed_products")),
    )
    result: dict[str, tuple[DatasetDeclaration, ...]] = {}
    for producer, kinds in selections:
        declarations = import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS
        selected = tuple(item for item in declarations if item.output_kind in kinds)
        if {item.output_kind for item in selected} != set(kinds):
            raise ValueError(f"source context names an unknown output: {producer}")
        result[producer] = selected
    return result


def source_context_inputs() -> tuple[InputRequirement, ...]:
    from appsec_review.runtime.contracts import accepted_inputs
    return tuple(requirement for producer, declarations in source_context_datasets().items()
                 for requirement in accepted_inputs(producer, declarations))


def source_context_core(run_root: Path, manifest: Mapping[str, Any]) -> RetrievalCore:
    """Keep the accepted manifest identity while querying only the explicitly declared source view."""
    from appsec_review.retrieval.core import RetrievalCore
    from appsec_review.runtime.inputs import input_shard_owner
    datasets = source_context_datasets()
    indexes = {index for declarations in datasets.values() for item in declarations for index in item.indexes}

    def selected(shard: Mapping[str, Any]) -> bool:
        producer = shard.get("producer", {}).get("job")
        if producer is None:
            # Preserve provenance-unknown historical views. The runtime observer still refuses
            # to admit these bytes as an original producer's output inside a typed job.
            return shard["name"] in indexes
        if producer not in datasets:
            return False
        owner = input_shard_owner(run_root, shard)
        return any(item.output_kind == owner.output_kind for item in datasets[producer])

    return RetrievalCore(run_root.parent, run_root.name, manifest_path=run_root / manifest["path"],
                         manifest_sha256=manifest["sha256"], shard_filter=selected)
