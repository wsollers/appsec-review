from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
from pathlib import Path
from types import SimpleNamespace

from appsec_review.graph.contract import AUTHORITY, GRAPH_FACT_SCHEMA, admissibility, fact_identity
from appsec_review.jobs.job_security_tagging.job import _taxonomy
from appsec_review.jobs.job_security_tagging.producers import Row, Scope
from appsec_review.retrieval import EntityKind, LogicalIdentity, SourceLocation
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256

ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT = "target-sha256:" + "7" * 64
DATA = b"query(user_input)\n"


def settings():
    taxonomy = {}
    for key, name in (("vocabulary", "vocabulary"), ("capability_rules", "capability-rules"),
                      ("crosswalk", "crosswalk")):
        path = f"data/reference/taxonomy/{name}.json"
        taxonomy[f"{key}_path"] = path
        taxonomy[f"{key}_sha256"] = file_sha256(ROOT / path)
    return {"taxonomy": taxonomy, "max_entities_per_shard": 100, "max_assignments": 200}


def taxonomy():
    return _taxonomy(ROOT, settings())


def scope(components=None):
    project = LogicalIdentity.derive(EntityKind.PROJECT, SNAPSHOT, {"fixture": "project"}).value
    component = LogicalIdentity.derive(EntityKind.COMPONENT, SNAPSHOT, {"fixture": "component"}).value
    if components is None:
        components = ({"component_id": "component:app", "logical_id": component,
                       "root": ".", "manifest": None, "ecosystem": "python"},)
    return Scope(SNAPSHOT, {"kind": "project", "logical_id": project, "project_id": project,
                            "component_id": None}, tuple(components))


def shard(name="graph", shard_id="scope", digest="a"):
    return {"name": name, "shard_id": shard_id, "sha256": digest * 64,
            "producer": {"job": "job_code_graph_index", "scope_id": "scope", "attempt_id": "attempt:1"}}


def fact(klass="sql_query", *, family="sink_site", language="python", path="src/app.py",
         data=DATA, component="component:app", scope_id="scope", start=0, end=None):
    end = len(data.rstrip(b"\n")) if end is None else end
    location = SourceLocation(SNAPSHOT, path, hashlib.sha256(data).hexdigest(),
                              start, end, 1, 1, start + 1, end + 1, {}, "codeql-exact", 1.0)
    field = "source_class" if family == "entry_point" else "sink_class"
    native = {"scope_id": scope_id, "path": path, "start_byte": start, "end_byte": end, field: klass}
    result = {field: klass, "catalog_rule": f"fixture.{klass}", "model": "fixture",
              "enclosing_function": {"symbol": None, "display": "handler"}}
    if family == "sink_site":
        native["argument_index"] = 0
        result["argument_index"] = 0
    payload = {
        "schema": GRAPH_FACT_SCHEMA, "family": family, "authority": AUTHORITY,
        "producer": {"name": "codeql-export", "tool_version": "2.24.0", "export_pack_sha256": "c" * 64,
                     "catalog_version": "fixture/1", "rule_version": "graph-normalize/2"},
        "scope": {"scope_id": scope_id, "language": language, "build_unit_id": "build:1",
                  "component_id": component},
        "exact": True, "coverage_status": "complete", "gaps": [],
        "cross_check": {"rule": "graph-cross-check/1", "state": "not_covered", "producers": []},
        "upstream": [{"index": "source", "shard_id": "source", "sha256": "b" * 64}],
        "result": result,
    }
    payload["admissibility"] = admissibility(payload)
    identity = fact_identity(family, SNAPSHOT, native).value
    return Row(identity, family, identity, klass, payload, asdict(location))


def payload_change(row, **changes):
    payload = {**row.payload, **changes}
    payload["admissibility"] = admissibility(payload)
    return replace(row, payload=payload)


class CannedIndexes:
    """Only accepted-index/source I/O is faked; mapping, validation and identities stay real."""

    def __init__(self, rows=(), *, groups=None, data=DATA, missing=False):
        self.groups = groups if groups is not None else ([] if missing else [(shard(), list(rows))])
        self.data = data
        self.reads = []
        self.source_reads = []
        self.target_snapshot = SNAPSHOT

    def shards(self, name):
        return [identity for identity, _ in self.groups if identity["name"] == name]

    def rows(self, identity, kinds, limit):
        self.reads.append((identity, kinds, limit))
        rows = [row for item, rows in self.groups if item == identity for row in rows if row.kind in kinds]
        rows.sort(key=lambda row: row.identity)
        return rows[:limit], len(rows) > limit

    def source_bytes(self, location):
        self.source_reads.append(dict(location))
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


def unit_context(root, unit_id, outputs=None):
    run_root = root / "runs" / "2026-11-13-0001"
    job = SimpleNamespace(
        repository_root=ROOT, run_root=run_root, run_id=run_root.name, attempt_id="attempt:1",
        attempt_root=run_root / "attempt", config=SimpleNamespace(settings=settings()),
        tools=SimpleNamespace(enable_swift=False), source_fingerprint=SNAPSHOT)
    step, task = unit_id.split(".")
    return UnitContext(job, unit_id, step, task, job.attempt_root / step / task, outputs or {})
