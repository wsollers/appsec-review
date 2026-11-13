"""Canned accepted-index and byte-reader boundaries; the selection/resolver code stays real."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256 as hash_bytes
from types import SimpleNamespace

import pytest

from appsec_review.config.owasp import AssessmentMode, OwaspSettings
from appsec_review.owasp_workbench import evidence
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.scope import Component, SourceFile


@pytest.fixture
def settings():
    return OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 60, 120, 8, 10, 4, 8)


@pytest.fixture
def accepted(monkeypatch, tmp_path):
    def make(sources, *, hints=(), languages=None):
        snapshot, run_id = "target-sha256:" + "1" * 64, "unit-run"
        component = Component("api", ".", "component")
        rows, entities, files, reads = [], {}, [], []
        data = {path: value.encode() if isinstance(value, str) else value for path, value in sources.items()}
        for path, raw in data.items():
            sha = hash_bytes(raw).hexdigest()
            identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": path, "sha": sha}).value
            location = {"path": path, "file_sha256": sha, "start_byte": 0, "end_byte": len(raw),
                        "start_line": 1, "end_line": len(raw.splitlines()), "producer_location": {}}
            row = {"identity": identity, "kind": "source_file", "index": "source", "shard_id": "default",
                   "payload": {"language": "Python"}, "location": location}
            rows.append(row)
            entities[identity] = row
            files.append(SourceFile(path, identity, (languages or {}).get(path, "Python")))
        for number, (path, first, last) in enumerate(hints):
            original = next(row for row in rows if row["location"]["path"] == path)
            rows.append({**deepcopy(original), "identity": f"hint-{number}", "kind": "symbol",
                         "index": "analysis", "location": {
                             **original["location"], "start_line": first, "end_line": last}})
        entities["component"] = {"identity": "component", "kind": "component",
                                 "index": "components", "shard_id": "default",
                                 "payload": {"root": ".", "component_id": "api"}, "location": None}
        rows.append(entities["component"])
        shards = tuple({"name": name, "shard_id": "default", "sha256": "2" * 64,
                        "producer": {"job": "job_target_catalog"}}
                       for name in ("source", "analysis", "components"))

        def indexed(shards, *, limit):
            allowed = {item["name"] for item in shards}
            return iter([row for row in sorted(rows, key=lambda row: row["identity"])
                         if row["index"] in allowed][:limit])

        scope = SimpleNamespace(run_id=run_id, run_root=tmp_path, manifest_sha256="3" * 64,
                                target_snapshot=snapshot, components=(component,), build_units=(),
                                shards=shards, source_files=tuple(files),
                                store=SimpleNamespace(entities=indexed), verify=lambda: None,
                                manifest_path=tmp_path / "manifest.json")
        core = SimpleNamespace(run_id=run_id, run_root=tmp_path, target_root=tmp_path / "target",
                               manifest_sha256=scope.manifest_sha256, manifest={"target_snapshot": snapshot})
        resolver = evidence.EvidenceResolver(core, scope)

        def entity(identity):
            if identity not in entities:
                raise ValueError("outside accepted original records")
            return deepcopy(entities[identity])

        def read(root, target, *, target_snapshot, path, sha256: str, native, limit):
            assert root == core.run_root and target == core.target_root and target_snapshot == snapshot
            raw = data[path]
            reads.append((path, limit))
            if len(raw) > limit:
                raise ValueError("source exceeds excerpt verification bound")
            if hash_bytes(raw).hexdigest() != sha256:
                raise ValueError("target source changed after indexing")
            return raw

        monkeypatch.setattr(resolver, "_entity", entity)
        monkeypatch.setattr(evidence, "read_source_bytes", read)
        return SimpleNamespace(resolver=resolver, files=files, rows=rows, entities=entities,
                               data=data, reads=reads, scope=scope)
    return make
