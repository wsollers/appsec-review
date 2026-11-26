from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_review.config import TargetDocumentSettings
from appsec_review.jobs.job_target_catalog import job as catalog

PARTITION = "repository_discovery.partition_repository"
SYSTEMS = "build_discovery.discover_build_systems"
PROJECTS = "repository_discovery.discover_projects"
COMPILE = "build_discovery.discover_compile_commands"
TARGETS = "build_discovery.catalog_build_targets"
COMPONENTS = "component_discovery.catalog_components"
DEPENDENCIES = "component_discovery.catalog_dependencies"
INDEX_UNITS = (
    "retrieval_indexes.build_path_index",
    "retrieval_indexes.build_symbol_index",
    "retrieval_indexes.build_component_index",
    "retrieval_indexes.build_target_documents",
)


def context(tmp_path: Path, unit_id: str, outputs=None):
    root = tmp_path / "run"
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    calls = []
    job = SimpleNamespace(
        run_root=root, target_root=target,
        attempt_root=root / "data/jobs/job_target_catalog/attempts/attempt_0001",
        run_id="fixture-run", attempt_id="attempt_0001", source_fingerprint="fixture-snapshot",
        config=SimpleNamespace(job_id="job_target_catalog", inventory_max_file_bytes=128, exclusions=None,
                               typed_settings=TargetDocumentSettings(
                                   max_files=20, max_file_bytes=4096, max_records=100)),
        review_policy=SimpleNamespace(releases=SimpleNamespace(values={"target_documents": "fixture/1"})),
        events=SimpleNamespace(write=lambda event, **data: calls.append((event, data))),
    )
    outputs = {} if outputs is None else outputs
    reads = []

    def output(key):
        reads.append(key)
        return outputs[key]

    return SimpleNamespace(job=job, unit_id=unit_id, output=output, outputs=outputs,
                           reads=reads, events=calls)


def handler(unit_id, **kwargs):
    return next(unit.handler for unit in catalog.build_job(**kwargs).units if unit.unit_id == unit_id)


def source(unit, path="src/main.py", raw=b"def main():\n    return 1\n", language="Python", **extra):
    file = unit.job.target_root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(raw)
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw), "language": language, **extra}


def partition(files=(), gaps=()):
    return {"artifact": {"path": "partition.json", "sha256": "a" * 64, "size_bytes": 1},
            "files": list(files), "gaps": list(gaps), "artifact_candidates": [],
            "file_discovery": {"file_paths_examined": len(files)}, "configured_exclusions": [],
            "excluded_assets": {"files": 0, "bytes": 0, "classes": {}}}


def document(unit, result):
    artifact = result["artifact"]
    path = unit.job.run_root / artifact["path"]
    raw = path.read_bytes()
    assert artifact["sha256"] == hashlib.sha256(raw).hexdigest()
    assert artifact["size_bytes"] == len(raw)
    return json.loads(raw)


def capture_indexes(monkeypatch):
    """Capture the shared SQLite writer boundary, not the catalog transformations."""
    builders = []

    class Builder:
        def __init__(self, path, **identity):
            self.path = path
            self.identity = identity
            self.entities = []
            self.relations = []
            self.coverage = []
            builders.append(self)

        def add_entity(self, entity):
            self.entities.append(entity)

        def add_relation(self, relation):
            self.relations.append(relation)

        def add_coverage(self, *args):
            self.coverage.append(args)

        def build(self):
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(b"fixture-index")
            return hashlib.sha256(b"fixture-index").hexdigest()

    monkeypatch.setattr(catalog, "IndexBuilder", Builder)
    return builders
