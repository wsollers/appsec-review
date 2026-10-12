"""Build a small accepted index set for inference-review tests.

The run holds two languages (Python, C) in two components and two build units; source-SAST
leads that are High, Critical, unknown-severity, suppressed, duplicate, unlocated, medium and low;
one CodeQL lead; two dependency advisories; two CI rule findings; review-prioritization, history,
hotspot and tag signals; an accepted ``scanner_correlation`` shard built by ``indexing/sast.py``;
and ``dependency_advisories`` and ``reference_intelligence`` shards built by the real
``indexing/products.py`` rules over pinned fixture reference feeds (OSV, NVD, KEV, EPSS, MITRE)
published offline through the real sync code (``tests/fixtures/reference_feeds.py``). By default
the OSV feed is stale; ``dep_high`` (GHSA-aaaa-bbbb-cccc, alias CVE-2026-0001) is enriched with NVD
CVSS v3.1 and v4.0, a KEV listing and EPSS; ``dep_low`` (GHSA-dddd-eeee-ffff, alias CVE-2026-0002)
resolves to a Rejected NVD record with no CVSS. Artifact-scanner, post-build hardening and OWASP
control producers are absent, so their lead families must surface as coverage gaps.

Usage::

    from tests.fixtures.inference_review.builder import build_accepted_index_set
    fixture = build_accepted_index_set(tmp_path)              # FixtureRun
    scope = accept_manifest(fixture.run_root)
    fixture.ids["sast_critical"]                              # logical identity of a named lead

``omit`` drops named shards (see ``SHARDS``) before the manifest is written; ``seed`` shuffles
entity insertion order, which must not change any shard or package byte. ``omit_feeds`` leaves a
reference feed unpublished (unavailable) and ``stale_feeds`` pins a feed older than its freshness
bound; ``kev_cves``, ``nvd_records`` and ``mitre_weaknesses`` replace the fixture feed contents.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import random
from pathlib import Path
from typing import Any, Iterable

from appsec_review.indexing import products
from appsec_review.indexing.derive import publish_derived
from appsec_review.indexing.store import ShardSet
from appsec_review.indexing.products_base import AcceptedShards, to_derived
from appsec_review.indexing.sast import build_scanner_correlation
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures import reference_feeds as feeds


RUN_ID = "2026-10-12-0001"
SNAPSHOT = "target-sha256:" + "7" * 64
SHARDS = ("source", "components", "build", "semgrep", "opengrep", "codeql", "osv", "ci", "priority", "history",
          "tags", "scanner_correlation", "dependency_advisories", "reference_intelligence")
FEEDS = ("osv", "nvd", "kev", "epss", "mitre")
FEED_OVERRIDES = {"kev": 7, "epss": 3}
V31 = {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "baseScore": 7.5,
       "baseSeverity": "HIGH"}
V40 = {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
       "baseScore": 8.7, "baseSeverity": "HIGH"}
NVD_RECORDS = (
    feeds.nvd_vulnerability("CVE-2026-0001", cwes=["CWE-400"], description="requests unbounded resource consumption",
                            metrics={"cvssMetricV31": [V31], "cvssMetricV40": [V40]}),
    feeds.nvd_vulnerability("CVE-2026-0002", status="Rejected", description="** REJECT ** duplicate"),
)
KEV_CVES = ("CVE-2026-0001",)
EPSS_ROWS = (("CVE-2026-0001", 0.42, 0.97), ("CVE-2026-0002", 0.001, 0.05))
MITRE_WEAKNESSES = {
    "CWE-78": ("Improper Neutralization of Special Elements used in an OS Command", "Base"),
    "CWE-89": ("Improper Neutralization of Special Elements used in an SQL Command", "Base"),
    "CWE-120": ("Buffer Copy without Checking Size of Input", "Base"),
    "CWE-190": ("Integer Overflow or Wraparound", "Base"),
    "CWE-400": ("Uncontrolled Resource Consumption", "Class"),
    "CWE-416": ("Use After Free", "Variant"),
    "CWE-787": ("Out-of-bounds Write", "Base"),
}
OSV_RECORDS = (
    {"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-02-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
     "summary": "requests resource exhaustion", "aliases": ["CVE-2026-0001"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}]},
    {"id": "GHSA-dddd-eeee-ffff", "modified": "2026-02-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
     "summary": "requests header leak", "aliases": ["CVE-2026-0002"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}}]},
)
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
    feed_pins: dict[str, Any] = field(default_factory=dict)


def _identity(kind: EntityKind, native: Any) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native}).value


def publish_feeds(base: Path, *, omit_feeds: Iterable[str] = (), stale_feeds: Iterable[str] = ("osv",),
                  kev_cves: Iterable[str] = KEV_CVES, nvd_records: Iterable[dict] = NVD_RECORDS,
                  mitre_weaknesses: dict[str, tuple[str, str]] | None = None) -> dict[str, dict[str, Any]]:
    """Publish the fixture reference feeds under ``base/feeds`` and pin them as the indexing job does."""
    omit_feeds, stale_feeds = frozenset(omit_feeds), frozenset(stale_feeds)
    unknown = (omit_feeds | stale_feeds) - set(FEEDS)
    if unknown:
        raise ValueError(f"unknown fixture feeds: {sorted(unknown)}")
    root, work = Path(base) / "feeds", Path(base) / "feed-work"
    roots = {feed: root / feed for feed in FEEDS}
    publishers = {
        "osv": lambda: feeds.publish_osv(roots["osv"], list(OSV_RECORDS), work / "osv"),
        "nvd": lambda: feeds.publish_nvd(roots["nvd"], [dict(item) for item in nvd_records]),
        "kev": lambda: feeds.publish_kev(roots["kev"], feeds.kev_document(
            [feeds.kev_entry(cve) for cve in kev_cves]), work / "kev"),
        "epss": lambda: feeds.publish_epss(roots["epss"], feeds.epss_bytes(EPSS_ROWS), work / "epss"),
        "mitre": lambda: feeds.publish_mitre(roots["mitre"], dict(mitre_weaknesses or MITRE_WEAKNESSES), work / "mitre"),
    }
    for feed in FEEDS:
        if feed in omit_feeds:
            continue
        publishers[feed]()
        age = 30 if feed in stale_feeds else 1
        feeds.set_published_at(roots[feed], (feeds.FIXED_NOW.replace(day=12) - _days(age)).isoformat()
                               .replace("+00:00", "Z"))
    return feeds.pin_feeds(Path(base), roots, overrides=FEED_OVERRIDES)


def _days(count: int):
    from datetime import timedelta
    return timedelta(days=count)


def build_accepted_index_set(base: Path, *, run_id: str = RUN_ID, omit: Iterable[str] = (),
                             seed: int | None = None, history_change_count: int = 9,
                             omit_feeds: Iterable[str] = (), stale_feeds: Iterable[str] = ("osv",),
                             kev_cves: Iterable[str] = KEV_CVES, nvd_records: Iterable[dict] = NVD_RECORDS,
                             mitre_weaknesses: dict[str, tuple[str, str]] | None = None,
                             advisory_extra: dict[str, dict[str, Any]] | None = None) -> FixtureRun:
    omit = frozenset(omit)
    unknown = omit - set(SHARDS)
    if unknown:
        raise ValueError(f"unknown fixture shards: {sorted(unknown)}")
    advisory_extra = dict(advisory_extra or {})
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
          [advisory("dep_high", "GHSA-aaaa-bbbb-cccc", **{"cvss_score": 7.5, "native_severity": "MODERATE",
                                                          "aliases": ["CVE-2026-0001"], "cwe_ids": ["CWE-400"],
                                                          **advisory_extra.get("dep_high", {})}),
           advisory("dep_low", "GHSA-dddd-eeee-ffff", **{"native_severity": "LOW",
                                                         **advisory_extra.get("dep_low", {})})])

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
                     {"change_count": history_change_count, "sii": {"rank": 1, "tier": 1, "score": 0.9}},
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

    pins = publish_feeds(base, omit_feeds=omit_feeds, stale_feeds=stale_feeds, kev_cves=kev_cves,
                         nvd_records=nvd_records, mitre_weaknesses=mitre_weaknesses)

    def product(key: str, query_set: str, shard_id: str) -> None:
        if key in omit:
            return
        rule = products.product_rule(query_set)
        store = ShardSet(run_root, [asdict(item) for item in identities])
        context = products.ProductContext(run_root, SNAPSHOT, store, {}, {feed: pins[feed] for feed in rule.feeds},
                                          {}, 10_000, rule.version)
        selected = rule.select(store)
        derived = rule.build(context, selected)
        if query_set == "dependency_advisories":
            ids["advisory_fact"] = next(item.identity.value for item in derived.entities
                                        if item.payload["result"]["advisory"] == "GHSA-aaaa-bbbb-cccc")
        document = publish_derived(
            run_root, index="precomputed", shard_id=shard_id, job_id="job_review_data_indexing", unit_id="fixture",
            rule=query_set, rule_version=rule.version, snapshot=SNAPSHOT,
            inputs={"shards": ShardSet.identities(selected),
                    "feeds": {feed: pins[feed].get("manifest_sha256") for feed in rule.feeds}},
            build=lambda: derived, producer={"query_set": query_set})
        raw = document["index_identity"]
        identities.append(IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}))
        published.append(key)

    product("dependency_advisories", "dependency_advisories", "dependency-advisories")
    product("reference_intelligence", "reference_intelligence", "reference-intelligence")

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
    attempt = run_root / "data" / "jobs" / "job_review_data_indexing" / "attempts" / "attempt_0001"
    inputs_path = attempt / "steps" / "load" / "tasks" / "accepted_inputs" / "accepted-inputs.json"
    atomic_json(inputs_path, {"schema": "appsec-review/review-data-indexing-inputs/1", "target_snapshot": SNAPSHOT,
                              "feeds": pins})
    inputs_artifact = {"path": inputs_path.relative_to(run_root).as_posix(), "sha256": file_sha256(inputs_path),
                       "size_bytes": inputs_path.stat().st_size}
    handoff_path = attempt / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "job_id": "job_review_data_indexing",
                               "attempt_id": "attempt_0001", "status": "ACCEPTED", "completion_status": "SUCCEEDED",
                               "artifacts": [manifest], "outputs": {"load.accepted_inputs": {"artifact": inputs_artifact}},
                               "source_fingerprint": SNAPSHOT})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff_path),
        "manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    return FixtureRun(runs_dir, run_root, run_id, target, SNAPSHOT, ids, tuple(published), pins)


def shard_path(fixture: FixtureRun, name: str, shard_id: str) -> Path:
    """Physical path of one accepted shard, for tamper tests."""
    found = sorted((fixture.run_root / "data" / "indices" / name / shard_id).glob("*.sqlite"))
    if len(found) != 1:
        raise LookupError(f"fixture shard not found: {name}/{shard_id}")
    return found[0]
