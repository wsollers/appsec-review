"""Canned accepted-scope boundary; production planning and validators remain real."""
from types import SimpleNamespace

from appsec_review.review.lead_families import Lead, LeadCollection
from appsec_review.review.scope import BuildUnit, Component, ProducerCoverage, SourceFile

SNAPSHOT = "target-" + "a" * 64
SHA = "b" * 64
SOURCE = "asr:source_file:" + "1" * 64
COMPONENT = "asr:component:" + "2" * 64
BUILD = "asr:build_action:" + "3" * 64
SINK = "asr:sink_site:" + "4" * 64
ENTRY = "asr:entry_point:" + "5" * 64
PATH = "src/api.py"


def graph_row(identity=SINK, kind="sink_site", classification="sql_query", line=20):
    return {
        "identity": identity, "kind": kind, "native_id": identity, "name": identity,
        "index": "graph", "shard_id": "facts",
        "location": {"path": PATH, "file_sha256": SHA, "start_line": line, "end_line": line,
                     "start_byte": line * 10, "end_byte": line * 10 + 5, "target_snapshot": SNAPSHOT},
        "payload": {"schema": "appsec-review/graph-fact/1", "family": kind, "exact": True,
                    "coverage_status": "complete", "cross_check": {"state": "not_covered"},
                    "scope": {"component_id": "api", "build_unit_id": "app"},
                    "result": {"source_class" if kind == "entry_point" else "sink_class": classification}},
    }


def tag_row(tag="func:data:sql-query", basis="invoked", identity="tag", line=20):
    location = graph_row(line=line)["location"]
    return {"identity": "asr:tag_assignment:" + identity.encode().hex().ljust(64, "0")[:64],
            "kind": "tag_assignment", "native_id": identity, "location": location,
            "payload": {"tag": tag, "basis": basis,
                        "subject": {"logical_id": SINK, "component_ownership": "owned", "path": PATH},
                        "evidence": [{"ref": SINK, "location": location}]}}


class Scope:
    def __init__(self, graph=(), tags=(), extra_sources=()):
        self.target_snapshot = SNAPSHOT
        self.run_id = "fixture"
        self.components = (Component("api", "src", COMPONENT),)
        self.build_units = (BuildUnit("app", "src", BUILD, ("Python",)),)
        self.source_files = (SourceFile(PATH, SOURCE, "Python"), *extra_sources)
        self.rows = {"code_graph": list(graph), "security_tagging": list(tags)}
        self.available = set(self.rows)
        self.states = {}
        self.store = SimpleNamespace(entities=self.entities)
        self.shards = ()
        self.gaps = ()

    def producer(self, name):
        state = self.states.get(name, "available" if name in self.available else "missing")
        shards = ({"name": name, "shard_id": "facts", "sha256": SHA},) if name in self.available else ()
        return ProducerCoverage(name, state, shards, ())

    def entities(self, shards, *, kinds=(), limit=None):
        rows = [row for shard in shards for row in self.rows.get(shard["name"], ())
                if not kinds or row["kind"] in kinds]
        return iter(sorted(rows, key=lambda row: row["identity"])[:limit])

    def source_for(self, path):
        return next((source for source in self.source_files if source.path == path), None)

    def component_for(self, path):
        return self.components[0] if self.source_for(path) else None

    def build_unit_for(self, path):
        return self.build_units[0] if self.source_for(path) else None

    def shard_sha256(self, shard):
        return shard["sha256"]


def collection(*lines):
    leads = tuple(Lead("asr:tool_observation:" + str(number).zfill(64), "source_sast", "scanner", "rule",
                       "high", "high", "scanner", "candidate", (), PATH, line, True,
                       "observations", "scanner", SHA) for number, line in enumerate(lines, 1))
    return LeadCollection(leads, (), {"source_sast": True}, None)
