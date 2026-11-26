from __future__ import annotations

import ast
from dataclasses import asdict
from fnmatch import fnmatch
import inspect
import json

import pytest

from appsec_review.interchange import validate_unit_output
from appsec_review.jobs.job_target_catalog import job as catalog
from appsec_review.jobs.job_target_catalog.datasets import CONTRACT, CONSUMES, DATASETS
from tests.unit.job_target_catalog.support import COMPILE, PARTITION, context, handler, partition


def test_every_input_requirement_field_and_dispatch_policy_is_pinned():
    assert [asdict(item) for item in CONTRACT.inputs] == [
        {"producer": "job_review_intake", "output_kind": kind, "schema": schema,
         "authority": "producer_evidence", "availability": "required" if kind == "handoff" else "optional",
         "missing": "reject" if kind == "handoff" else "gap",
         "coverage": "allow_partial", "channel": "handoff"}
        for kind, schema in (
            ("handoff", "appsec-review/job-handoff/2"),
            ("model_preflight", "appsec-review/model-preflight/1"),
            ("binary_evidence", "appsec-review/binary-evidence-intake/1"),
            ("review_intake", "appsec-review/review-intake/1"),
        )
    ]
    assert CONTRACT.schedule_after == CONSUMES == ("job_review_intake",)
    assert (CONTRACT.dispatch, CONTRACT.target_access, CONTRACT.always_execute, CONTRACT.propagate_handoff) == (
        "review_graph", "checkout", False, True)
    job = catalog.build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS and job.consumes == CONSUMES
    assert job.strict_gaps is True


def test_every_dataset_field_is_pinned():
    common = {
        "sensitivity": "internal", "shard_prefixes": (), "shard_suffixes": (),
        "store": "retrieval", "authority": "producer_evidence",
    }
    indexed = [
        ("source_files", "retrieval_indexes", "source", "source",
         "Accepted source files with language, size, hash and bounded text.",
         "find/search/read_excerpt index=source"),
        ("declaration_symbols", "retrieval_indexes", "symbols", "analysis",
         "Bounded declaration-pattern symbols with line-exact locations.",
         "find/search/trace index=analysis kind=symbol"),
        ("components", "retrieval_indexes", "catalog", "components",
         "Catalogued components and their manifests.", "find/search index=components"),
        ("target_documents", "retrieval_indexes", "documents", "documents",
         "Declared API operations, tests, design intent and threat boundaries from accepted target files.",
         "find/search/read_excerpt index=documents"),
        ("build_units", "publish_catalog", "build", "build",
         "Discovered build units and compile-database identities.", "find/search index=build kind=build_action"),
    ]
    expected = [{
        **common, "output_kind": "target_artifact_inputs", "step": "repository_discovery",
        "family": "artifacts", "schema": "appsec-review/target-artifact-intake/1",
        "disposition": "artifact_only",
        "description": "Bounded target-owned binary candidates with intake provenance and unknown delivery status.",
        "indexes": (), "artifacts": ("data/shared/objects/*",),
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
        "reason": "target input bytes are bound by the catalog and indexed by job_artifact_indexing",
        "required": False,
    }, *({
        **common, "output_kind": kind, "step": step, "family": family,
        "schema": "appsec-review/retrieval-index/2", "disposition": "indexed",
        "description": description, "indexes": (index,), "artifacts": (),
        "query_route": route, "reason": None, "required": True,
    } for kind, step, family, index, description, route in indexed), {
        **common, "output_kind": "catalog_documents", "step": "publish_catalog", "family": "catalog",
        "schema": "appsec-review/target-catalog/1", "disposition": "artifact_only",
        "description": "Repository partition, language census, projects, build systems, components and dependencies.",
        "indexes": (), "artifacts": ("data/jobs/job_target_catalog/attempts/*/artifacts/catalog/*.json",),
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
        "reason": "normalized inputs of the source, analysis, components and build shards; "
                  "the shards are the queryable representation", "required": False,
    }]
    assert [asdict(item) for item in DATASETS] == expected


def test_each_handler_artifact_name_schema_and_read_write_boundary_is_pinned():
    tree = ast.parse(inspect.getsource(catalog))
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    outputs = {}
    reads = {}
    writers = {}
    schemas = {}
    paths = {}
    index_schemas = {}
    for name, function in functions.items():
        if name == "build_job":
            continue
        for node in ast.walk(function):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "_artifact":
                    outputs[name] = ast.literal_eval(node.args[1])
                if node.func.id in {"IndexBuilder", "put_bytes", "write_manifest", "write_json"}:
                    writers.setdefault(name, []).append(node.func.id)
                if node.func.id == "IndexIdentity" and len(node.args) > 1:
                    index_schemas[name] = ast.literal_eval(node.args[1])
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in {
                        "path", "source", "source_path", "target_root",
                        "index_path", "build_path", "manifest_path"}):
                paths.setdefault(name, []).append(ast.unparse(node))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"open", "read_bytes", "read_text"}:
                    reads.setdefault(name, []).append(ast.unparse(node))
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and key.value == "schema" and isinstance(value, ast.Constant):
                        schemas.setdefault(name, set()).add(value.value)
    assert outputs == {
        "partition": "repository-partition.json", "census": "language-census.json",
        "projects": "projects.json", "build_systems": "build-systems.json",
        "compile_commands": "compile-commands.json", "build_targets": "build-targets.json",
        "components": "components.json", "dependencies": "dependencies.json", "publish": "target-catalog.json",
    }
    assert schemas == {
        "partition": {"appsec-review/target-artifact-intake/1", "appsec-review/repository-partition/1"},
        "census": {"appsec-review/language-census/1"}, "projects": {"appsec-review/project-catalog/1"},
        "build_systems": {"appsec-review/build-systems/4"},
        "compile_commands": {"appsec-review/compile-commands/1"},
        "build_targets": {"appsec-review/build-targets/2"}, "components": {"appsec-review/component-catalog/1"},
        "dependencies": {"appsec-review/dependency-catalog/1"},
        "symbol_index": {"appsec-review/retrieval-index/2"}, "component_index": {"appsec-review/retrieval-index/2"},
        "publish": {"appsec-review/retrieval-index/2", "appsec-review/target-catalog/1"},
    }
    assert writers == {
        "_artifact": ["write_json"], "partition": ["put_bytes"], "path_index": ["IndexBuilder"],
        "symbol_index": ["IndexBuilder"], "component_index": ["IndexBuilder"],
        "document_index": ["IndexBuilder"], "publish": ["IndexBuilder", "write_manifest"],
    }
    assert reads == {
        "descriptor_reader": ["path.read_bytes()"], "read_text": ["path.read_bytes()"],
        "partition": ["path.open('rb')"], "dependencies": ["path.read_text(encoding='utf-8')"],
        "path_index": ["source.read_text(encoding='utf-8')"],
        "document_index": ["source.read_bytes()"],
    }
    assert index_schemas == {
        "path_index": "appsec-review/retrieval-index/2",
        "document_index": "appsec-review/retrieval-index/2",
    }
    assert paths == {
        "_artifact": ["path = unit.job.attempt_root / 'artifacts' / 'catalog' / name"],
        "_gap_text": ["path = value.get('path')"],
        "descriptor_reader": ["path = safe_path(target, relative)"],
        "read_text": ["path = safe_path(target, relative)"],
        "partition": ["path = safe_path(_target(unit), candidate['path'])"],
        "projects": ["path = Path(item['path'])"],
        "dependencies": ["path = _target(unit) / manifest"],
        "path_index": [
            "path = unit.job.run_root / 'data' / 'indices' / 'source' / 'attempts' / unit.job.config.job_id / unit.job.attempt_id / f'{fingerprint}.sqlite'",
            "source = _target(unit) / item['path']"],
        "symbol_index": [
            "path = unit.job.run_root / 'data' / 'indices' / 'analysis' / 'attempts' / unit.job.config.job_id / unit.job.attempt_id / f'{fingerprint}.sqlite'",
            "index_path = builder.path", "source_path = safe_path(_target(unit), item['path'])"],
        "component_index": [
            "path = unit.job.run_root / 'data' / 'indices' / 'components' / 'attempts' / unit.job.config.job_id / unit.job.attempt_id / f'{fingerprint}.sqlite'"],
        "document_index": [
            "path = unit.job.run_root / 'data' / 'indices' / 'documents' / 'attempts' / unit.job.config.job_id / unit.job.attempt_id / f'{fingerprint}.sqlite'",
            "source_path = record['path']",
            "target_root = _target(unit).resolve()", "source = (target_root / source_path).resolve()"],
        "validate_catalog": ["path = unit.job.run_root / artifact['path']"],
        "publish": [
            "build_path = unit.job.run_root / 'data' / 'indices' / 'build' / 'attempts' / unit.job.config.job_id / unit.job.attempt_id / f'{build_fingerprint}.sqlite'",
            "manifest_path = unit.job.run_root / 'data' / 'indices' / 'manifests' / f'catalog-{unit.job.attempt_id}.json'"],
    }


@pytest.mark.parametrize(("filename", "schema"), [
    ("build-systems.json", "appsec-review/build-systems/4"),
    ("build-targets.json", "appsec-review/build-targets/2"),
    ("compile-commands.json", "appsec-review/compile-commands/1"),
    ("components.json", "appsec-review/component-catalog/1"),
    ("dependencies.json", "appsec-review/dependency-catalog/1"),
    ("language-census.json", "appsec-review/language-census/1"),
    ("projects.json", "appsec-review/project-catalog/1"),
    ("repository-partition.json", "appsec-review/repository-partition/1"),
    ("target-catalog.json", "appsec-review/target-catalog/1"),
], ids=["systems", "targets", "compile", "components", "dependencies", "languages", "projects", "partition", "catalog"])
def test_catalog_artifact_writer_stays_inside_declared_glob(tmp_path, filename, schema):
    unit = context(tmp_path, "contract")
    result = catalog._artifact(unit, filename, {"schema": schema, "fixture": 1})
    assert result["path"] == f"data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog/{filename}"
    declaration = next(item for item in DATASETS if item.output_kind == "catalog_documents")
    assert any(fnmatch(result["path"], pattern) for pattern in declaration.artifacts)
    assert json.loads((unit.job.run_root / result["path"]).read_text()) == {"schema": schema, "fixture": 1}
    if filename == "target-catalog.json":
        assert schema == declaration.schema


def test_missing_compile_database_satisfies_required_typed_gap_contract(tmp_path):
    unit = context(tmp_path, COMPILE, {PARTITION: partition()})
    result = handler(COMPILE)(unit)
    validate_unit_output(result, unit_id=COMPILE, strict_gaps=True)
    [gap] = result["gaps"]
    assert gap["code"] == "producer_reported_gap"
    assert gap["unit_id"] == COMPILE and gap["scope_id"] == "compile_commands.json"
