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

``third_party`` adds two vendored C files (``third_party/zlib/inflate.c`` at the target root and
``native/third_party/lz4/lz4.c`` inside the native component) with a high-severity Semgrep and a high-severity
cppcheck observation located in them, a cppcheck ``style`` observation in each tree, and a cppcheck ``warning``
in first-party ``native/src/parse.c`` (T-165 dispositions, T-167 stylistic classes).

``config`` binds the run to that configuration file (loaded under the ambient environment, so set any
capacity overlay first) before the synthetic upstream handoff is frozen. A test that later drives the
real runner over the run must pass the configuration it will run with: the runner refuses a run bound
to another resolved configuration, and an accepted handoff must match the run's frozen configuration.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
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
from appsec_review.runtime.datasets import dataset_contract, shard_owner
from appsec_review.runtime.registry import builtin_registry
from tests.fixtures import reference_feeds as feeds


RUN_ID = "2026-10-12-0001"
SNAPSHOT = "target-sha256:" + "7" * 64
SHARDS = ("source", "components", "build", "semgrep", "opengrep", "codeql", "osv", "ci", "priority", "history",
          "tags", "scanner_correlation", "dependency_advisories", "reference_intelligence", "gitleaks", "cppcheck")
# The seeded credential of the opt-in ``secrets`` fixture: no artifact the intake produces may contain it.
FIXTURE_SECRET = "sk_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
SECRET_FILE = "native/src/config.cpp"
SECRET_SOURCE = ("#include <string>\n"
                 f'static const char *kApiKey = "{FIXTURE_SECRET}";\n'
                 "int send_key() { return post(kApiKey); }\n")
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
# Names, abstractions and Common_Consequences (scopes, technical impacts) after the MITRE catalog;
# scoring derives each weakness's impact class from its consequences (cwe-impact-derivation/1).
_CIA = ["Confidentiality", "Integrity", "Availability"]
MITRE_WEAKNESSES = {
    "CWE-78": ("Improper Neutralization of Special Elements used in an OS Command", "Base", [
        (_CIA + ["Non-Repudiation"], ["Execute Unauthorized Code or Commands", "DoS: Crash, Exit, or Restart",
                                      "Read Files or Directories", "Modify Files or Directories",
                                      "Read Application Data", "Modify Application Data", "Hide Activities"])]),
    "CWE-89": ("Improper Neutralization of Special Elements used in an SQL Command", "Base", [
        (_CIA, ["Execute Unauthorized Code or Commands"]), (["Confidentiality"], ["Read Application Data"]),
        (["Authentication"], ["Gain Privileges or Assume Identity", "Bypass Protection Mechanism"]),
        (["Integrity"], ["Modify Application Data"])]),
    "CWE-120": ("Buffer Copy without Checking Size of Input", "Base", [
        (["Integrity", "Confidentiality", "Availability"], ["Modify Memory", "Execute Unauthorized Code or Commands"]),
        (["Availability"], ["DoS: Crash, Exit, or Restart", "DoS: Resource Consumption (CPU)"])]),
    "CWE-190": ("Integer Overflow or Wraparound", "Base", [
        (["Availability"], ["DoS: Crash, Exit, or Restart", "DoS: Resource Consumption (Memory)", "DoS: Instability"]),
        (["Integrity"], ["Modify Memory"]),
        (["Confidentiality", "Availability", "Access Control"], ["Execute Unauthorized Code or Commands",
                                                                 "Bypass Protection Mechanism"])]),
    "CWE-400": ("Uncontrolled Resource Consumption", "Class", [
        (["Availability"], ["DoS: Crash, Exit, or Restart", "DoS: Resource Consumption (CPU)",
                            "DoS: Resource Consumption (Memory)"])]),
    "CWE-416": ("Use After Free", "Variant", [
        (["Integrity"], ["Modify Memory"]), (["Availability"], ["DoS: Crash, Exit, or Restart"]),
        (_CIA, ["Execute Unauthorized Code or Commands"])]),
    "CWE-829": ("Inclusion of Functionality from Untrusted Control Sphere", "Base", [
        (_CIA, ["Execute Unauthorized Code or Commands"])]),
    "CWE-787": ("Out-of-bounds Write", "Base", [
        (["Integrity"], ["Modify Memory", "DoS: Crash, Exit, or Restart", "Execute Unauthorized Code or Commands"])]),
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
# Opt-in ``third_party`` fixture: vendored trees at the target root and inside the native component.
THIRD_PARTY_FILES = {
    "third_party/zlib/inflate.c": ("C", "#include <string.h>\nint inflate(char *w) {\n  char b[4]; strcpy(b, w);\n"
                                        "  return 0;\n}\n"),
    "native/third_party/lz4/lz4.c": ("C", "int lz4(char *d, int n) {\n  return d[n];\n}\n"),
}

INDEXING_JOB = "job_review_data_indexing"


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

    @property
    def upstream_handoffs(self) -> dict[str, str]:
        """Exact accepted prerequisites; absent optional publications remain absent."""
        pointer = json.loads((self.run_root / "data" / "jobs" / INDEXING_JOB / "latest.json").read_text(
            encoding="utf-8"))
        result = {INDEXING_JOB: pointer["handoff_sha256"]}
        packages = self.run_root / "data/jobs/job_review_package_assembly/latest.json"
        if packages.is_file():
            result["job_review_package_assembly"] = json.loads(packages.read_bytes())["handoff_sha256"]
        return result


def _identity(kind: EntityKind, native: Any) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native}).value


def publish_feeds(base: Path, *, omit_feeds: Iterable[str] = (), stale_feeds: Iterable[str] = ("osv",),
                  kev_cves: Iterable[str] = KEV_CVES, nvd_records: Iterable[dict] = NVD_RECORDS,
                  mitre_weaknesses: dict[str, tuple] | None = None) -> dict[str, dict[str, Any]]:
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
                             runs_dir: Path | None = None,
                             seed: int | None = None, history_change_count: int = 9,
                             omit_feeds: Iterable[str] = (), stale_feeds: Iterable[str] = ("osv",),
                             kev_cves: Iterable[str] = KEV_CVES, nvd_records: Iterable[dict] = NVD_RECORDS,
                             mitre_weaknesses: dict[str, tuple] | None = None,
                             advisory_extra: dict[str, dict[str, Any]] | None = None,
                             secrets: bool = False, secret_extra: dict[str, Any] | None = None,
                             third_party: bool = False, config: Path | None = None) -> FixtureRun:
    omit = frozenset(omit)
    unknown = omit - set(SHARDS)
    if unknown:
        raise ValueError(f"unknown fixture shards: {sorted(unknown)}")
    advisory_extra = dict(advisory_extra or {})
    runs_dir = Path(runs_dir) if runs_dir is not None else Path(base) / "runs"
    run_root = runs_dir / run_id
    from appsec_review.config import load_config
    from appsec_review.runtime.runner import JobRunner
    config_path = config or Path(__file__).resolve().parents[3] / "appsec-review.toml"
    JobRunner(load_config(config_path))._bind_configuration(run_root)
    target = Path(base) / "target"
    files = dict(FILES)
    if secrets:
        files[SECRET_FILE] = ("C++", SECRET_SOURCE)
    if third_party:
        files.update(THIRD_PARTY_FILES)
    for path, (_language, text) in files.items():
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_text(text, encoding="utf-8")
    shuffle = random.Random(seed).shuffle if seed is not None else (lambda values: None)
    ids: dict[str, str] = {path: _identity(EntityKind.SOURCE_FILE, path) for path in files}
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
                     location(path, 1)) for path, (language, _text) in files.items()])
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
    semgrep_relations = [observed("sast_high", "svc/api/handler.py"), observed("sast_critical", "native/src/parse.c"),
                         observed("sast_suppressed", "native/src/io.c")]
    if third_party:
        semgrep.append(observation("sast_vendored_high", "tool-semgrep", "c.strcpy", "ERROR",
                                   "third_party/zlib/inflate.c", 3, rule_mapping={"cwe": ["CWE-120"]}, language="C"))
        semgrep_relations.append(observed("sast_vendored_high", "third_party/zlib/inflate.c"))
    shard("semgrep", "observations", "semgrep", {**evidence, "producer": "tool-semgrep"}, semgrep,
          semgrep_relations)
    if third_party:
        # cppcheck rows as the adapter indexes them: native severity error/warning/style, category source_sast.
        shard("cppcheck", "observations", "cppcheck", {**evidence, "producer": "tool-cppcheck"}, [
            observation("cppcheck_vendored_high", "tool-cppcheck", "arrayIndexOutOfBounds", "error",
                        "native/third_party/lz4/lz4.c", 2, language="C"),
            observation("cppcheck_vendored_style", "tool-cppcheck", "variableScope", "style",
                        "third_party/zlib/inflate.c", 3, language="C"),
            observation("cppcheck_style", "tool-cppcheck", "unusedStructMember", "style", "native/src/parse.c", 5,
                        language="C"),
            observation("cppcheck_medium", "tool-cppcheck", "nullPointerRedundantCheck", "warning",
                        "native/src/parse.c", 2, language="C"),
        ], [observed("cppcheck_vendored_high", "native/third_party/lz4/lz4.c"),
            observed("cppcheck_style", "native/src/parse.c"), observed("cppcheck_medium", "native/src/parse.c")])
    if secrets:
        # The row shape of a real gitleaks observation (--redact; the sanitizing index blanks the rule id).
        ids["secret_key"] = _identity(EntityKind.TOOL_OBSERVATION, "secret_key")
        leaked = {"match": f'kApiKey = "{FIXTURE_SECRET}"', "secret": FIXTURE_SECRET, **(secret_extra or {})}
        shard("gitleaks", "observations", "gitleaks", {**evidence, "producer": "tool-gitleaks"}, [
            EntityRecord(LogicalIdentity.parse(ids["secret_key"]), "evidence-32aeaf3169218fa428defc78",
                         "generic-api-key", "generic-api-key Detected a Generic API Key secret_detection",
                         {"advisory": None, "category": "secret_detection", "component": None,
                          "evidence_id": "evidence-32aeaf3169218fa428defc78", "language": None,
                          "message": "Detected a Generic API Key, potentially exposing access to various services "
                                     "and sensitive operations.",
                          "native_rule_id": "<redacted>", "native_severity": "UNKNOWN", "package": None,
                          "severity": "UNKNOWN", "tool_id": "tool-gitleaks", **leaked},
                         location(SECRET_FILE, 2))], [observed("secret_key", SECRET_FILE)])
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
                             "rule_mapping": {"cwe": ["CWE-829"]},
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
            run_root, index="precomputed", shard_id="qs-" + shard_id, job_id="job_review_data_indexing",
            unit_id="precompute." + query_set,
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
        if third_party:
            syntax_files["third_party/zlib/inflate.c"] = {"component_id": None, "language": "C",
                                                         "suppression_count": 0, "suppressions": []}
            syntax_files["native/third_party/lz4/lz4.c"] = {"component_id": "component:0002", "language": "C",
                                                           "suppression_count": 0, "suppressions": []}
        accepted = AcceptedShards(run_root, [asdict(item) for item in identities], SNAPSHOT)
        product = build_scanner_correlation(accepted, {"files": syntax_files}, [], {"menu_partition_size": 50})
        derived = to_derived(product, SNAPSHOT, 10_000)
        document = publish_derived(
            run_root, index="precomputed", shard_id="qs-scanner-correlation", job_id="job_review_data_indexing",
            unit_id="precompute.scanner_correlation", rule="scanner_correlation", rule_version=product.rule_version, snapshot=SNAPSHOT,
            inputs={"shards": product.inputs}, build=lambda: derived, producer={"query_set": "scanner_correlation"})
        raw = document["index_identity"]
        identities.append(IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}))
        published.append("scanner_correlation")

    registry = builtin_registry()
    owners = {str(item.producer["job"]) for item in identities} | {INDEXING_JOB}
    for owner in sorted(owners):
        declarations = registry.build(owner).datasets
        owned = [item for item in identities if item.producer["job"] == owner]
        for declaration in declarations:
            if not declaration.required or any(
                    shard_owner(declarations, item.name, item.shard_id) == declaration for item in owned):
                continue
            # Missing fixture evidence stays unavailable, not a fabricated complete dataset.
            index, = declaration.indexes
            shard_id = "fixture-unavailable-" + declaration.output_kind
            path = run_root / "data/indices" / index / (shard_id + ".sqlite")
            empty = IndexBuilder(path, name=index, fingerprint="f" * 64, target_snapshot=SNAPSHOT,
                                 shard_id=shard_id)
            gap = "fixture does not supply " + declaration.output_kind
            empty.add_coverage(declaration.output_kind, "unavailable", gap)
            identities.append(IndexIdentity(index, "appsec-review/retrieval-index/2", empty.build(), "f" * 64,
                path.relative_to(run_root).as_posix(), {"job": owner, "unit": declaration.step + ".fixture"},
                (gap,), shard_id))
    identities = [IndexIdentity(**{**asdict(item), "producer": {
        **item.producer, "unit": shard_owner(registry.build(str(item.producer["job"])).datasets,
                                            item.name, item.shard_id).step + ".fixture"}}) for item in identities]
    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    attempt = run_root / "data" / "jobs" / "job_review_data_indexing" / "attempts" / "attempt_0001"
    inputs_path = attempt / "steps" / "load" / "tasks" / "accepted_inputs" / "accepted-inputs.json"
    from tests.handoff_fixture import write_fixture_handoff
    handoffs = {}
    for owner in sorted(owners - {INDEXING_JOB}):
        owned = [item for item in identities if item.producer["job"] == owner]
        producer_attempt = run_root / "data/jobs" / owner / "attempts/attempt_0001"
        declarations = registry.build(owner).datasets
        atomic_json(producer_attempt / "claim.json", {"dataset_contract": dataset_contract(
            owner, sorted({item.step for item in declarations}), declarations)})
        path = producer_attempt / "handoff.json"
        write_fixture_handoff(run_root, path, {
            "job_id": owner, "source_fingerprint": SNAPSHOT,
            "completion_status": "COMPLETED_WITH_GAPS" if any(item.gaps for item in owned) else "SUCCEEDED",
            "outputs": {item.producer["unit"] + "_" + str(number): {
                "index_manifest": manifest, "index_identity": asdict(item), "gaps": list(item.gaps),
                "terminal_status": "COMPLETED_WITH_GAPS" if item.gaps else "SUCCEEDED"}
                for number, item in enumerate(owned)},
            "artifacts": [{"path": item.relative_path, "sha256": item.sha256} for item in owned],
        })
        handoffs[owner] = {"sha256": file_sha256(path), "path": path.relative_to(run_root).as_posix(),
                           "attempt_id": "attempt_0001",
                           "completion_status": json.loads(path.read_bytes())["completion_status"]}
        atomic_json(producer_attempt.parent.parent / "latest.json", {
            "handoff_path": handoffs[owner]["path"], "handoff_sha256": handoffs[owner]["sha256"]})
    resolved = json.loads((run_root / "data/configuration/resolved.json").read_bytes())
    job_steps = {name: sorted(value["steps"]) for name, value in resolved["jobs"].items()}
    from appsec_review.jobs.job_review_data_indexing.job import downstream_jobs, _unit_statuses, owasp_status
    from appsec_review.runtime.contracts import DispatchClass
    from appsec_review.runtime.selection import resolved_job_is_enabled
    from appsec_review.indexing.store import accepted_handoff
    disabled = {key for key, value in resolved["jobs"].items() if not resolved_job_is_enabled(key, value)}
    active = {key for key in job_steps if key not in disabled
              and registry.build(key).contract.dispatch is DispatchClass.REVIEW_GRAPH} - downstream_jobs()
    stage_handoffs = {key: handoffs.get(key) for key in sorted(active - {INDEXING_JOB})}
    atomic_json(inputs_path, {
        "schema": "appsec-review/review-data-indexing-inputs/2", "target_snapshot": SNAPSHOT,
        "accepted_manifest": manifest, "shards": [asdict(item) for item in identities
                                                  if item.producer["job"] != INDEXING_JOB],
        "restored_shards": [], "shard_conflicts": [], "registry_jobs": sorted(active),
        "registry_configuration_mismatch": [], "job_steps": {key: job_steps[key] for key in sorted(active)},
        "registered_jobs": list(registry.job_ids()),
        "dispatch_classes": {key: registry.build(key).contract.dispatch.value for key in registry.job_ids()},
        "file_job_steps": job_steps, "disabled_jobs": sorted(disabled),
        "declarations": {key: [item.output_kind for item in registry.build(key).datasets] for key in sorted(active)},
        "consumes": {key: [name for name in registry.build(key).consumes if name in active] for key in sorted(active)},
        "handoffs": stage_handoffs, "feeds": pins, "owasp": owasp_status(run_root),
        "unit_statuses": {key: _unit_statuses(run_root, accepted_handoff(run_root, key))
                          for key, value in stage_handoffs.items() if value is not None},
    })
    inputs_artifact = {"path": inputs_path.relative_to(run_root).as_posix(), "sha256": file_sha256(inputs_path),
                       "size_bytes": inputs_path.stat().st_size}
    handoff_path = attempt / "handoff.json"
    declarations = registry.build(INDEXING_JOB).datasets
    atomic_json(attempt / "claim.json", {"dataset_contract": dataset_contract(
        INDEXING_JOB, sorted({item.step for item in declarations}), declarations)})
    write_fixture_handoff(run_root, handoff_path, {"job_id": INDEXING_JOB,
                               "attempt_id": "attempt_0001", "status": "ACCEPTED",
                               "completion_status": "COMPLETED_WITH_GAPS" if any(
                                   item.gaps for item in identities if item.producer["job"] == INDEXING_JOB) else "SUCCEEDED",
                               "artifacts": [manifest, *(
                                   {"path": item.relative_path, "sha256": item.sha256}
                                   for item in identities if item.producer["job"] == INDEXING_JOB)], "outputs": {
                                   "load.accepted_inputs": {"artifact": inputs_artifact},
                                   "publish.inventory_index": {"index_manifest": manifest},
                                   **{item.producer["unit"] + "_" + str(number): {
                                       "index_manifest": manifest, "index_identity": asdict(item),
                                       "gaps": list(item.gaps),
                                       "terminal_status": "COMPLETED_WITH_GAPS" if item.gaps else "SUCCEEDED"}
                                      for number, item in enumerate(identities) if item.producer["job"] == INDEXING_JOB}},
                               "upstream_handoff_sha256": {key: value["sha256"] for key, value in handoffs.items()},
                               "source_fingerprint": SNAPSHOT})
    point_latest_handoff(run_root, handoff_path)
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff_path),
        "manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    if "scanner_correlation" in published:
        _publish_packages(run_root, registry)
    return FixtureRun(runs_dir, run_root, run_id, target, SNAPSHOT, ids, tuple(published), pins)


def _publish_packages(run_root, registry):
    from appsec_review.retrieval import RetrievalCore
    from appsec_review.review_packages import publish_review_packages, verify_review_packages
    from tests.handoff_fixture import write_fixture_handoff
    core = RetrievalCore(run_root.parent, run_root.name)
    directory = publish_review_packages(core, max_page_size=100)
    document = verify_review_packages(core, directory)
    job = registry.build("job_review_package_assembly")
    attempt = run_root / "data/jobs" / job.job_id / "attempts/attempt_0001"
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(job.job_id, ("publication",), job.datasets)})
    indexing = json.loads((run_root / "data/jobs/job_review_data_indexing/latest.json").read_bytes())
    write_fixture_handoff(run_root, attempt / "handoff.json", {
        "job_id": job.job_id, "source_fingerprint": core.manifest["target_snapshot"],
        "upstream_handoff_sha256": {INDEXING_JOB: indexing["handoff_sha256"]},
        "completion_status": "COMPLETED_WITH_GAPS" if document["coverage_gaps"] else "SUCCEEDED",
        "outputs": {"publication.publish_packages": {
            "schema": "appsec-review/review-package-assembly/1",
            "accepted_manifest_sha256": core.manifest_sha256,
            "package_directory": directory.relative_to(run_root).as_posix(),
            "content_sha256": document["content_sha256"], "manifest_sha256": file_sha256(directory / "manifest.json"),
            "counts": document["counts"], "package_count": len(document["packages"]),
            "coverage_gap_count": len(document["coverage_gaps"]),
            "gaps": [item["gap_id"] for item in document["coverage_gaps"]],
        }},
        "artifacts": [{"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}
                      for path in sorted(directory.glob("*.json"))],
    })
    atomic_json(attempt.parent.parent / "latest.json", {
        "handoff_path": (attempt / "handoff.json").relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(attempt / "handoff.json")})


def point_latest_handoff(run_root: Path, handoff_path: Path) -> None:
    """Publish the accepted-handoff pointer a real indexing attempt leaves; call again after a rewrite."""
    atomic_json(run_root / "data" / "jobs" / INDEXING_JOB / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": handoff_path.parent.name,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff_path)})


def shard_path(fixture: FixtureRun, name: str, shard_id: str) -> Path:
    """Physical path of one accepted shard, for tamper tests."""
    found = sorted((fixture.run_root / "data" / "indices" / name / shard_id).glob("*.sqlite"))
    if len(found) != 1:
        raise LookupError(f"fixture shard not found: {name}/{shard_id}")
    return found[0]
