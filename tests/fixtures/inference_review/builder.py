"""Build a small accepted index set for inference-review tests.

The run holds two languages (Python, C) in two components and two build units; source-SAST
leads that are High, Critical, unknown-severity, suppressed, duplicate, unlocated, medium and low;
one CodeQL lead; two dependency advisories; two CI rule findings; review-prioritization, history,
hotspot and tag signals; an accepted ``scanner_correlation`` shard built by ``indexing/sast.py``;
and a stale ``dependency_advisories`` feed. Artifact-scanner, post-build hardening and OWASP
control producers are absent, so their lead families must surface as coverage gaps.

Usage::

    from tests.fixtures.inference_review.builder import build_accepted_index_set
    fixture = build_accepted_index_set(tmp_path)              # FixtureRun
    scope = accept_manifest(fixture.run_root)
    fixture.ids["sast_critical"]                              # logical identity of a named lead

``omit`` drops named shards (see ``SHARDS``) before the manifest is written; ``seed`` shuffles
entity insertion order, which must not change any shard or package byte.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import random
from pathlib import Path
from typing import Any, Iterable

from appsec_review.indexing.derive import publish_derived
from appsec_review.indexing.products_base import AcceptedShards, to_derived
from appsec_review.indexing.sast import build_scanner_correlation
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.storage import atomic_json, file_sha256


RUN_ID = "2026-10-12-0001"
SNAPSHOT = "target-sha256:" + "7" * 64
SHARDS = ("source", "components", "build", "semgrep", "opengrep", "codeql", "osv", "ci", "priority", "history",
          "tags", "scanner_correlation", "dependency_advisories")
FILES = {
    "svc/api/handler.py": ("Python", "import db\ndef get(q):\n    return db.raw(q)\n    print(q)\n"),
    "svc/api/util.py": ("Python", "assert True\n"),
    "native/src/parse.c": ("C", "#include <string.h>\nvoid p(char *s) {\n  char b[8]; strcpy(b, s);\n}\n"
                                "int q(int n) { return n * 4; }\n"),
    "native/src/io.c": ("C", "int r(void) {\n  return 0;\n  system(\"x\"); // nosemgrep\n}\n"),
    ".github/workflows/ci.yml": ("YAML", "on: pull_request_target\njobs:\n  b:\n    steps: []\n"),
}


@dataclass(frozen=True)
class FixtureRun:
    runs_dir: Path
    run_root: Path
    run_id: str
    target: Path
    snapshot: str
    ids: dict[str, str] = field(default_factory=dict)
    shards: tuple[str, ...] = ()


def _identity(kind: EntityKind, native: Any) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native}).value


def build_accepted_index_set(base: Path, *, run_id: str = RUN_ID, omit: Iterable[str] = (),
                             seed: int | None = None) -> FixtureRun:
    omit = frozenset(omit)
    unknown = omit - set(SHARDS)
    if unknown:
        raise ValueError(f"unknown fixture shards: {sorted(unknown)}")
    runs_dir = Path(base) / "runs"
    run_root = runs_dir / run_id
    target = Path(base) / "target"
    for path, (_language, text) in FILES.items():
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_text(text, encoding="utf-8")
    shuffle = random.Random(seed).shuffle if seed is not None else (lambda values: None)
    ids: dict[str, str] = {path: _identity(EntityKind.SOURCE_FILE, path) for path in FILES}
    identities: list[IndexIdentity] = []
    published: list[str] = []

    def location(path: str, line: int) -> SourceLocation:
        data = (target / path).read_bytes()
        return SourceLocation(SNAPSHOT, path, file_sha256(target / path), 0, len(data), line, line, 1, 1,
                              {"fixture": path}, "fixture-exact", 1.0)

    def shard(key: str, name: str, shard_id: str, producer: dict[str, Any], entities: list[EntityRecord],
              relations: Iterable[RelationRecord] = (), coverage: tuple[str, str, str | None] | None = None) -> None:
        if key in omit:
            return
        fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity=producer, parser_identity="fixture/1",
                                        normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        entities = list(entities)
        relations = list(relations)
        shuffle(entities)
        shuffle(relations)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        coverage = coverage or (shard_id, "complete", None)
        builder.add_coverage(*coverage)
        gaps = (coverage[2],) if coverage[2] else ()
        identities.append(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                        path.relative_to(run_root).as_posix(), producer, gaps, shard_id))
        published.append(key)

    catalog = {"job": "job_target_catalog"}
    shard("source", "source", "default", catalog, [
        EntityRecord(LogicalIdentity.parse(ids[path]), path, path, path, {"language": language, "path": path},
                     location(path, 1)) for path, (language, _text) in FILES.items()])
    ids["component:svc"] = LogicalIdentity.derive(EntityKind.COMPONENT, SNAPSHOT, {"component_id": "component:0001"}).value
    ids["component:native"] = LogicalIdentity.derive(EntityKind.COMPONENT, SNAPSHOT,
                                                     {"component_id": "component:0002"}).value
    shard("components", "components", "default", catalog, [
        EntityRecord(LogicalIdentity.parse(ids["component:svc"]), "component:0001", "component:0001", "svc",
                     {"component_id": "component:0001", "root": "svc", "manifest": "svc/pyproject.toml"}),
        EntityRecord(LogicalIdentity.parse(ids["component:native"]), "component:0002", "component:0002", "native",
                     {"component_id": "component:0002", "root": "native", "manifest": "native/Makefile"})])
    ids["unit:py-svc"] = LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"id": "py-svc"}).value
    ids["unit:native-main"] = LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"id": "native-main"}).value
    shard("build", "build", "default", catalog, [
        EntityRecord(LogicalIdentity.parse(ids["unit:py-svc"]), "py-svc", "pip", "py-svc",
                     {"build_unit_id": "py-svc", "root": "svc", "build_system": "pip", "languages": ["Python"]}),
        EntityRecord(LogicalIdentity.parse(ids["unit:native-main"]), "native-main", "make", "native-main",
                     {"build_unit_id": "native-main", "root": "native", "build_system": "make", "languages": ["C"]})])

    def observation(key: str, tool: str, rule: str, severity: str | None, path: str | None, line: int,
                    **extra: Any) -> EntityRecord:
        ids[key] = _identity(EntityKind.TOOL_OBSERVATION, key)
        payload = {"tool_id": tool, "native_rule_id": rule, "category": "source_sast",
                   "message": f"{rule} lead", **({"native_severity": severity} if severity else {}), **extra}
        return EntityRecord(LogicalIdentity.parse(ids[key]), key, rule, f"{rule} {tool}", payload,
                            location(path, line) if path else None)

    def observed(key: str, path: str) -> RelationRecord:
        return RelationRecord(RelationKind.OBSERVED_AT, ids[key], ids[path], True, 1.0)

    evidence = {"job": "job_evidence_collection"}
    semgrep = [
        observation("sast_high", "tool-semgrep", "py.sqli", "ERROR", "svc/api/handler.py", 3,
                    rule_mapping={"cwe": ["CWE-89"]}, language="Python"),
        observation("sast_critical", "tool-semgrep", "c.strcpy", "CRITICAL", "native/src/parse.c", 3,
                    rule_mapping={"cwe": ["CWE-120"]}, language="C"),
        observation("sast_unknown", "tool-semgrep", "c.weird", "SEVERE-ISH", "native/src/io.c", 1, language="C"),
        observation("sast_suppressed", "tool-semgrep", "c.system", "HIGH", "native/src/io.c", 3,
                    rule_mapping={"cwe": "CWE-78"}, language="C"),
        observation("sast_medium", "tool-semgrep", "py.print", "WARNING", "svc/api/handler.py", 4, language="Python"),
        observation("sast_low", "tool-semgrep", "py.assert", "LOW", "svc/api/util.py", 1, language="Python"),
        observation("sast_unlocated", "tool-semgrep", "py.eval", "HIGH", None, 1, language="Python"),
    ]
    shard("semgrep", "observations", "semgrep", {**evidence, "producer": "tool-semgrep"}, semgrep,
          [observed("sast_high", "svc/api/handler.py"), observed("sast_critical", "native/src/parse.c"),
           observed("sast_suppressed", "native/src/io.c")])
    shard("opengrep", "observations", "opengrep", {**evidence, "producer": "tool-opengrep"},
          [observation("sast_duplicate", "tool-opengrep", "c.strcpy-og", "HIGH", "native/src/parse.c", 3,
                       rule_mapping={"cwe": ["CWE-120"]}, language="C")],
          [observed("sast_duplicate", "native/src/parse.c")])
    shard("codeql", "observations", "codeql-cpp-native", {"job": "job_codeql_analysis", "language": "cpp",
                                                          "build_unit_id": "native-main"},
          [observation("codeql_high", "codeql", "cpp/integer-overflow", None, "native/src/parse.c", 5,
                       producer="codeql", producer_level="warning", security_severity="8.1", language="C")])

    def advisory(key: str, advisory_id: str, **extra: Any) -> EntityRecord:
        ids[key] = _identity(EntityKind.TOOL_OBSERVATION, key)
        return EntityRecord(LogicalIdentity.parse(ids[key]), key, advisory_id, f"requests {advisory_id}",
                            {"tool_id": "tool-osv-scanner", "category": "vulnerability_matching",
                             "package": "requests", "version": "2.0.0", "advisory": advisory_id,
                             "message": f"requests is affected by {advisory_id}", **extra},
                            location("svc/api/handler.py", 1))
    shard("osv", "observations", "osv_scanner", {**evidence, "producer": "tool-osv-scanner"},
          [advisory("dep_high", "GHSA-aaaa-bbbb-cccc", cvss_score=7.5, native_severity="MODERATE",
                    aliases=["CVE-2026-0001"], cwe_ids=["CWE-400"]),
           advisory("dep_low", "GHSA-dddd-eeee-ffff", native_severity="LOW")])

    def ci(key: str, rule: str, severity: str, line: int) -> EntityRecord:
        ids[key] = _identity(EntityKind.TOOL_OBSERVATION, key)
        return EntityRecord(LogicalIdentity.parse(ids[key]), key, rule, f"github {rule}",
                            {"tool_id": "ci-static-rules", "native_rule_id": rule, "provider": "github",
                             "category": "untrusted-trigger-execution", "severity": severity,
                             "message": f"{rule} in workflow"}, location(".github/workflows/ci.yml", line))
    shard("ci", "observations", "ci_github", {"job": "job_ci_configuration_analysis", "provider": "github"},
          [ci("ci_high", "untrusted-checkout", "high", 1), ci("ci_medium", "unpinned-action", "medium", 4)])

    ids["priority:handler"] = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, SNAPSHOT,
                                                     {"item_id": "file:svc/api/handler.py"}).value
    ids["priority:parse"] = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, SNAPSHOT,
                                                   {"item_id": "file:native/src/parse.c"}).value
    shard("priority", "priority", "review-prioritization", {"job": "job_review_prioritization"}, [
        EntityRecord(LogicalIdentity.parse(ids["priority:handler"]), "file:svc/api/handler.py", "handler.py",
                     "priority", {"scope": "file", "path": "svc/api/handler.py", "rank": 1, "score": 77.0},
                     location("svc/api/handler.py", 1)),
        EntityRecord(LogicalIdentity.parse(ids["priority:parse"]), "file:native/src/parse.c", "parse.c",
                     "priority", {"scope": "file", "path": "native/src/parse.c", "rank": 2, "score": 55.0},
                     location("native/src/parse.c", 1))])
    ids["history:parse"] = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, SNAPSHOT,
                                                  {"scope": "file", "path": "native/src/parse.c"}).value
    ids["hotspot:parse"] = _identity(EntityKind.HOTSPOT, "hotspot:file:native/src/parse.c")
    shard("history", "history", "git-history", {"job": "job_source_history_analysis", "vcs": "git"}, [
        EntityRecord(LogicalIdentity.parse(ids["history:parse"]), "file:native/src/parse.c", "parse.c", "history",
                     {"change_count": 9, "sii": {"rank": 1, "tier": 1, "score": 0.9}},
                     location("native/src/parse.c", 1)),
        EntityRecord(LogicalIdentity.parse(ids["hotspot:parse"]), "hotspot:file:native/src/parse.c", "parse.c",
                     "hotspot", {"rank": 1, "tier": 1, "score": 0.8}, location("native/src/parse.c", 1))])
    tags = []
    for number, (path, tag) in enumerate((("svc/api/handler.py", "asvs:v5-input"),
                                          ("svc/api/handler.py", "cwe:89"), ("native/src/parse.c", "cwe:120"))):
        ids[f"tag:{number}"] = LogicalIdentity.derive(EntityKind.TAG_ASSIGNMENT, SNAPSHOT,
                                                      {"assignment_id": f"tag-{number}"}).value
        tags.append(EntityRecord(LogicalIdentity.parse(ids[f"tag:{number}"]), f"tag-{number}", tag, f"{tag} {path}",
                                 {"tag": tag, "subject": {"kind": "file", "path": path, "logical_id": ids[path]}},
                                 location(path, 1)))
    shard("tags", "tags", "security-domain", {"job": "job_security_tagging", "family": "security_domain"}, tags)

    ids["advisory_fact"] = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT,
                                                  {"query_set": "dependency_advisories", "key": "requests"}).value
    shard("dependency_advisories", "precomputed", "dependency-advisories",
          {"job": "job_review_data_indexing", "query_set": "dependency_advisories"},
          [EntityRecord(LogicalIdentity.parse(ids["advisory_fact"]), "requests", "requests advisories",
                        "dependency advisory requests",
                        {"schema": FACT_SCHEMA, "query_set": "dependency_advisories", "fact_type": "fact",
                         "result": {"package": "requests", "advisory": "GHSA-aaaa-bbbb-cccc"}, "basis": "fixture"})],
          coverage=("dependency_advisories", "stale",
                    "stale_feed: the pinned OSV snapshot is older than the configured freshness bound"))

    if "scanner_correlation" not in omit:
        syntax_files = {
            "native/src/io.c": {"component_id": "component:0002", "language": "C", "suppression_count": 1,
                                "suppressions": [{"signal_id": "sup-1", "tool": "semgrep", "scope": "line",
                                                  "start_line": 3, "path": "native/src/io.c"}]},
            "native/src/parse.c": {"component_id": "component:0002", "language": "C", "suppression_count": 0,
                                   "suppressions": []},
            "svc/api/handler.py": {"component_id": "component:0001", "language": "Python",
                                   "suppression_count": 0, "suppressions": []},
            "svc/api/util.py": {"component_id": "component:0001", "language": "Python", "suppression_count": 0,
                                "suppressions": []},
        }
        accepted = AcceptedShards(run_root, [asdict(item) for item in identities], SNAPSHOT)
        product = build_scanner_correlation(accepted, {"files": syntax_files}, [], {"menu_partition_size": 50})
        derived = to_derived(product, SNAPSHOT, 10_000)
        document = publish_derived(
            run_root, index="precomputed", shard_id="scanner-correlation", job_id="job_review_data_indexing",
            unit_id="fixture", rule="scanner_correlation", rule_version=product.rule_version, snapshot=SNAPSHOT,
            inputs={"shards": product.inputs}, build=lambda: derived, producer={"query_set": "scanner_correlation"})
        raw = document["index_identity"]
        identities.append(IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}))
        published.append("scanner_correlation")

    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    handoff_path = run_root / "data" / "jobs" / "job_review_data_indexing" / "attempts" / "attempt_0001" / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "job_id": "job_review_data_indexing",
                               "attempt_id": "attempt_0001", "status": "ACCEPTED", "completion_status": "SUCCEEDED",
                               "artifacts": [manifest], "outputs": {}, "source_fingerprint": SNAPSHOT})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff_path),
        "manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    return FixtureRun(runs_dir, run_root, run_id, target, SNAPSHOT, ids, tuple(published))


def shard_path(fixture: FixtureRun, name: str, shard_id: str) -> Path:
    """Physical path of one accepted shard, for tamper tests."""
    found = sorted((fixture.run_root / "data" / "indices" / name / shard_id).glob("*.sqlite"))
    if len(found) != 1:
        raise LookupError(f"fixture shard not found: {name}/{shard_id}")
    return found[0]
