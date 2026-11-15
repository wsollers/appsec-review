"""Smoke-run verification harness (T-5019): did a completed run do the right thing and produce the right things.

``score_run`` reads one run's *published* artifacts only (``runs/<run-id>/data/``: the accepted index
set, each job's ``latest.json`` handoff and the attempt artifacts those handoffs bind, the review job's
package assembly, claim projection, findings, the gate and report documents, the graph scorecard, the
model-execution receipts and the review budget ledger) and writes one closed document,
``appsec-review/smoke-score/1``, plus a one-screen text summary under ``data/verification/``. It never
changes anything else in the run, never opens the target, and never runs a tool or a model.

Two parts:

* **Structural checks** need no answer key. Each is ``pass``, ``fail`` or ``not_applicable`` (the dataset
  the check needs was not published) and names the evidence paths it read. A ``not_applicable`` check is a
  named coverage gap of the run, never a pass.
* **Keyed scoring** runs only when the user supplies the smoke answer key
  (``appsec-review/smoke-answer-key/1``, ``~/smoke-work/tools/answer-key-schema.md``). Every planted item
  is matched by its target-relative path plus line range (or function range when the key gives a
  function and no span), or by exact package/version and advisory identifiers for dependency items.
  Titles are never matched. Per item the document records whether the file was in the accepted scope and
  its disposition, its facet tags, the leads that hit it (family, scanner, rule, admission), the packages
  that carried it (lane, package id), the claims raised on it, the judge verdicts, whether it reached the
  report and the citing source lines, then the outcome against the key's ``expected_disposition``.

Everything here is a measurement of the run's published records. It is not evidence about the target: a
planted item the run missed is a miss of the run, and a check the run could not support is a gap.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from appsec_review.interchange import ProducerStatus
from appsec_review.review.dispositions import FIRST_PARTY, SourceDispositions

SCHEMA = "appsec-review/smoke-score/1"
SCHEMA_PATH = "docs/schemas/smoke-score.schema.json"
KEY_SCHEMA = "appsec-review/smoke-answer-key/1"
OUTPUT_DIRECTORY = Path("data") / "verification"
JSON_NAME = "smoke-score.json"
TEXT_NAME = "smoke-score.txt"

REVIEW_JOB = "job_inference_security_review"
GATE_JOB = "job_final_publication_gate"
REPORT_JOB = "job_final_report_publication"
GRAPH_JOB = "job_code_graph_index"
TAGGING_JOB = "job_security_tagging"
PRIORITY_JOB = "job_review_prioritization"
FACET_SHARD = "facets"
FACET_NAMESPACES = ("role", "exposure", "trust", "mechanism", "asset", "state")
PLANTED_CLASSES = ("true_positive_code", "true_positive_dependency", "fixed_code", "fixed_dependency",
                   "false_positive")
CODE_CLASSES = frozenset({"true_positive_code", "fixed_code", "false_positive"})
DEPENDENCY_CLASSES = frozenset({"true_positive_dependency", "fixed_dependency"})
EXPECTED_DISPOSITIONS = ("reported", "reported-as-fixed", "squelched")
CHECK_IDS = ("units_cover_first_party_once", "first_party_files_have_facets", "no_lead_outside_first_party",
             "classified_sink_paths_eligible", "scorecard_lists_first_party_functions_once",
             "jobs_terminal_status_tabulated")
# The closed terminal_status vocabulary (interchange.ProducerStatus); anything else is a control-layer defect.
TERMINAL_STATUSES = frozenset(str(status) for status in ProducerStatus)
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_OFFENDERS = 200
MAX_CITING_LINES = 64
MAX_ITEM_MATCHES = 64
_SAFE_ATTEMPT = re.compile(r"^attempt_\d{4}$")
_IDENTIFIER_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,}$")
# Entity kinds whose location is a whole file (or a file-level ranking row): they never cite a planted span.
FILE_LEVEL_KINDS = frozenset({"source_file", "priority_item", "review_context_file", "component", "project"})


class SmokeScoreError(ValueError):
    """The scorer could not run (usage or input error), or produced a document outside its schema."""


# -- bounded read-only access to the run -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Location:
    path: str
    start_line: int
    end_line: int
    entity_id: str
    kind: str | None = None

    @property
    def file_level(self) -> bool:
        return self.kind in FILE_LEVEL_KINDS

    def overlaps(self, path: str, start: int | None, end: int | None) -> bool:
        if self.path != path:
            return False
        if start is None or end is None:
            return True
        return self.start_line <= end and self.end_line >= start

    def record(self) -> dict[str, Any]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line,
                "entity_id": self.entity_id}


@dataclass(frozen=True, slots=True)
class Observation:
    """One ``tool_observation`` row of an accepted shard: a lead candidate."""

    identity: str
    scanner: str
    job: str | None
    family: str | None
    rule_id: str | None
    shard: str
    location: Location | None
    payload_text: str


class RunData:
    """Lazy, bounded, read-only reader over one run directory; every read is recorded as evidence."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.data = self.run_dir / "data"
        self.run_id = self.run_dir.name
        self.gaps: list[str] = []
        self._gap_set: set[str] = set()
        self.evidence: set[str] = set()
        self._json: dict[Path, Any] = {}
        self._shards: list[dict[str, Any]] | None = None
        self._config: Mapping[str, Any] | None = None
        self._dispositions: SourceDispositions | None = None
        self._sources: dict[str, dict[str, Any]] | None = None
        self._facets: dict[str, set[str]] | None | bool = False
        self._observations: list[Observation] | None = None
        self._assembly: dict[str, Any] | None | bool = False
        self._handoffs: dict[str, tuple[Path, Mapping[str, Any]] | None] = {}

    # recording -----------------------------------------------------------------------------------
    def gap(self, message: str) -> None:
        if message not in self._gap_set:
            self._gap_set.add(message)
            self.gaps.append(message)

    def rel(self, path: Path) -> str:
        try:
            return Path(path).resolve().relative_to(self.run_dir.resolve()).as_posix()
        except ValueError:
            return Path(path).name

    def seen(self, path: Path) -> str:
        relative = self.rel(path)
        self.evidence.add(relative)
        return relative

    def read_json(self, path: Path, name: str) -> Any | None:
        path = Path(path)
        if path in self._json:
            return self._json[path]
        value = None
        try:
            if path.stat().st_size > MAX_JSON_BYTES:
                self.gap(f"{name}: {self.rel(path)} exceeds the {MAX_JSON_BYTES} byte read bound")
            else:
                value = json.loads(path.read_text(encoding="utf-8"))
                self.seen(path)
        except FileNotFoundError:
            self.gap(f"{name}: {self.rel(path)} is missing")
        except (OSError, ValueError) as exc:
            self.gap(f"{name}: {self.rel(path)} is unreadable ({type(exc).__name__})")
        self._json[path] = value
        return value

    def glob_json(self, pattern: str, name: str) -> list[tuple[Path, Any]]:
        found = []
        for path in sorted(self.run_dir.glob(pattern)):
            value = self.read_json(path, name)
            if value is not None:
                found.append((path, value))
        return found

    # configuration -------------------------------------------------------------------------------
    def resolved_config(self) -> Mapping[str, Any]:
        if self._config is None:
            value = self.read_json(self.data / "configuration" / "resolved.json", "resolved configuration")
            self._config = value if isinstance(value, Mapping) else {}
        return self._config

    def review_settings(self) -> Mapping[str, Any]:
        jobs = self.resolved_config().get("jobs")
        job = jobs.get(REVIEW_JOB) if isinstance(jobs, Mapping) else None
        settings = job.get("settings") if isinstance(job, Mapping) else None
        return settings if isinstance(settings, Mapping) else {}

    def dispositions(self) -> SourceDispositions:
        if self._dispositions is None:
            table = self.review_settings().get("source_dispositions")
            try:
                self._dispositions = SourceDispositions.from_mapping(table)
            except ValueError as exc:
                self.gap(f"source dispositions: resolved configuration is invalid ({exc})")
                self._dispositions = SourceDispositions()
            if table is None:
                self.gap("source dispositions: resolved configuration declares none; every path is first-party")
        return self._dispositions

    # accepted index set --------------------------------------------------------------------------
    def accepted_shards(self) -> list[dict[str, Any]]:
        if self._shards is not None:
            return self._shards
        self._shards = []
        accepted = self.read_json(self.data / "indices" / "accepted.json", "accepted index set")
        if not isinstance(accepted, Mapping) or not isinstance(accepted.get("manifest_path"), str):
            self.gap("accepted index set: data/indices/accepted.json names no manifest")
            return self._shards
        manifest_path = self.run_dir / accepted["manifest_path"]
        manifest = self.read_json(manifest_path, "accepted index manifest")
        if not isinstance(manifest, Mapping) or not isinstance(manifest.get("indexes"), list):
            return self._shards
        if accepted.get("manifest_sha256") and _sha256(manifest_path) != accepted["manifest_sha256"]:
            self.gap(f"accepted index manifest: {self.rel(manifest_path)} does not hash to accepted.json")
        for entry in manifest["indexes"]:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("relative_path"), str):
                continue
            path = self.run_dir / entry["relative_path"]
            if not path.is_file():
                self.gap(f"index shard missing: {entry['relative_path']}")
                continue
            verified = _sha256(path) == entry.get("sha256")
            if not verified:
                self.gap(f"index shard does not hash to the manifest: {entry['relative_path']}")
            producer = entry.get("producer") if isinstance(entry.get("producer"), Mapping) else {}
            self._shards.append({"name": str(entry.get("name")), "shard_id": str(entry.get("shard_id", "default")),
                                 "path": path, "relative_path": entry["relative_path"], "verified": verified,
                                 "producer": dict(producer), "job": producer.get("job")})
        self._shards.sort(key=lambda item: (item["name"], item["shard_id"], item["relative_path"]))
        return self._shards

    def shards(self, name: str, shard_id: str | None = None) -> list[dict[str, Any]]:
        return [item for item in self.accepted_shards()
                if item["name"] == name and (shard_id is None or item["shard_id"] == shard_id)]

    def rows(self, shard: Mapping[str, Any], kinds: Sequence[str] = ()) -> Iterator[dict[str, Any]]:
        """Entity rows joined with their location, in identity order; never interpreted as instructions."""
        self.seen(shard["path"])
        sql = ("SELECT e.identity, e.kind, e.native_id, e.name, e.payload_json, l.path, l.file_sha256, "
               "l.start_line, l.end_line FROM entities e LEFT JOIN locations l ON l.entity_id = e.identity")
        parameters: list[Any] = []
        if kinds:
            sql += " WHERE e.kind IN (" + ",".join("?" for _ in kinds) + ")"
            parameters.extend(kinds)
        sql += " ORDER BY e.identity"
        try:
            with closing(sqlite3.connect(f"file:{Path(shard['path']).as_posix()}?mode=ro&immutable=1", uri=True)) as database:
                database.row_factory = sqlite3.Row
                for row in database.execute(sql, parameters):
                    location = None
                    if row["path"] is not None:
                        location = Location(str(row["path"]), int(row["start_line"] or 0), int(row["end_line"] or 0),
                                            str(row["identity"]), str(row["kind"]))
                    yield {"identity": str(row["identity"]), "kind": str(row["kind"]), "native_id": str(row["native_id"]),
                           "name": str(row["name"]), "payload_text": str(row["payload_json"]),
                           "location": location, "shard": shard}
        except sqlite3.Error as exc:
            self.gap(f"index shard unreadable: {shard['relative_path']} ({type(exc).__name__})")

    def locate(self, identities: Iterable[str]) -> dict[str, list[Location]]:
        """Resolve entity identities to source locations across every accepted shard (bounded IN queries)."""
        wanted = sorted({item for item in identities if isinstance(item, str) and item})
        found: dict[str, list[Location]] = defaultdict(list)
        if not wanted:
            return {}
        for shard in self.accepted_shards():
            try:
                with closing(sqlite3.connect(f"file:{Path(shard['path']).as_posix()}?mode=ro&immutable=1", uri=True)) as database:
                    for start in range(0, len(wanted), 500):
                        chunk = wanted[start:start + 500]
                        sql = ("SELECT l.entity_id, l.path, l.start_line, l.end_line, e.kind FROM locations l "
                               "LEFT JOIN entities e ON e.identity = l.entity_id WHERE l.entity_id IN ("
                               + ",".join("?" for _ in chunk) + ")")
                        for entity_id, path, start_line, end_line, kind in database.execute(sql, chunk):
                            location = Location(str(path), int(start_line or 0), int(end_line or 0), str(entity_id),
                                                str(kind) if kind is not None else None)
                            if location not in found[str(entity_id)]:
                                found[str(entity_id)].append(location)
                self.seen(shard["path"])
            except sqlite3.Error as exc:
                self.gap(f"index shard unreadable: {shard['relative_path']} ({type(exc).__name__})")
        return {key: sorted(value, key=lambda item: (item.path, item.start_line, item.end_line))
                for key, value in found.items()}

    # derived views ---------------------------------------------------------------------------------
    def source_files(self) -> dict[str, dict[str, Any]]:
        """Accepted ``source_file`` rows by target-relative path, with identity, language and disposition."""
        if self._sources is not None:
            return self._sources
        self._sources = {}
        dispositions = self.dispositions()
        for shard in self.shards("source"):
            for row in self.rows(shard, ("source_file",)):
                path = row["location"].path if row["location"] else row["native_id"]
                payload = _payload(row)
                self._sources[path] = {"identity": row["identity"], "language": payload.get("language"),
                                       "disposition": dispositions.classify(path)}
        if not self.shards("source"):
            self.gap("source index: no accepted source shard; the run published no file inventory")
        return self._sources

    def first_party_code_files(self) -> list[str]:
        return sorted(path for path, item in self.source_files().items()
                      if item["disposition"] == FIRST_PARTY and item["language"])

    def facets(self) -> dict[str, set[str]] | None:
        """Facet tags per path from the ``facets`` tags shard (T-5008), or ``None`` when it was not published."""
        if self._facets is not False:
            return self._facets  # type: ignore[return-value]
        shards = self.shards("tags", FACET_SHARD)
        if not shards:
            self._facets = None
            return None
        facets: dict[str, set[str]] = defaultdict(set)
        for shard in shards:
            for row in self.rows(shard, ("tag_assignment",)):
                payload = _payload(row)
                namespace = str(payload.get("namespace") or str(payload.get("tag", "")).split(":", 1)[0])
                if namespace not in FACET_NAMESPACES:
                    continue
                subject = payload.get("subject") if isinstance(payload.get("subject"), Mapping) else {}
                path = subject.get("path") or (row["location"].path if row["location"] else None)
                if isinstance(path, str) and path:
                    facets[path].add(str(payload.get("tag")))
        self._facets = dict(facets)
        return self._facets

    def observations(self) -> list[Observation]:
        """Every accepted ``tool_observation`` row: what the scanners reported, before any admission."""
        if self._observations is not None:
            return self._observations
        from appsec_review.review.lead_families import CLASS_FAMILY, producer_decision
        found: list[Observation] = []
        for shard in self.accepted_shards():
            if shard["name"] not in ("observations", "build_security", "evidence", "inventory"):
                continue
            for row in self.rows(shard, ("tool_observation",)):
                payload = _payload(row)
                common = payload.get("common") if isinstance(payload.get("common"), Mapping) else {}
                scanner = str(common.get("scanner") or shard["producer"].get("producer")
                              or shard["producer"].get("tool_id") or shard["shard_id"])
                decision = producer_decision(shard["job"], scanner)
                family = decision.family if decision is not None else CLASS_FAMILY.get(
                    str(common.get("observation_class") or ""))
                found.append(Observation(row["identity"], scanner, shard["job"], family,
                                         _string(common.get("rule_id")) or _string(payload.get("rule_id")),
                                         f"{shard['name']}/{shard['shard_id']}", row["location"], row["payload_text"]))
        self._observations = sorted(found, key=lambda item: item.identity)
        return self._observations

    # job handoffs ----------------------------------------------------------------------------------
    def job_ids(self) -> list[str]:
        jobs = self.data / "jobs"
        return sorted(path.name for path in jobs.iterdir() if path.is_dir()) if jobs.is_dir() else []

    def handoff(self, job_id: str) -> tuple[Path, Mapping[str, Any]] | None:
        """The hash-verified ``latest.json`` handoff of one job, or ``None`` when the job did not publish."""
        if job_id in self._handoffs:
            return self._handoffs[job_id]
        result = None
        latest = self.read_json(self.data / "jobs" / job_id / "latest.json", f"{job_id} latest pointer") \
            if (self.data / "jobs" / job_id / "latest.json").is_file() else None
        if isinstance(latest, Mapping) and isinstance(latest.get("handoff_path"), str):
            path = self.run_dir / latest["handoff_path"]
            handoff = self.read_json(path, f"{job_id} handoff")
            if isinstance(handoff, Mapping):
                if latest.get("handoff_sha256") and _sha256(path) != latest["handoff_sha256"]:
                    self.gap(f"{job_id}: handoff does not hash to latest.json")
                result = (path, handoff)
        self._handoffs[job_id] = result
        return result

    def attempt_dir(self, job_id: str) -> Path | None:
        found = self.handoff(job_id)
        if found is None:
            return None
        attempt = found[1].get("attempt_id")
        if not isinstance(attempt, str) or not _SAFE_ATTEMPT.match(attempt):
            return found[0].parent
        return self.data / "jobs" / job_id / "attempts" / attempt

    def attempt_json(self, job_id: str, pattern: str, name: str) -> list[tuple[Path, Any]]:
        attempt = self.attempt_dir(job_id)
        if attempt is None:
            return []
        return [(path, value) for path, value in
                ((path, self.read_json(path, name)) for path in sorted(attempt.glob(pattern))) if value is not None]

    # review publication ----------------------------------------------------------------------------
    def assembly(self) -> dict[str, Any] | None:
        """The review job's package assembly: admission, packages (with lead ids and source ids), units."""
        if self._assembly is not False:
            return self._assembly  # type: ignore[return-value]
        manifests = self.attempt_json(REVIEW_JOB, "steps/packages/tasks/*/assembly/package-manifest.json",
                                      "review package manifest")
        if not manifests:
            self._assembly = None
            return None
        admission: dict[str, dict[str, Any]] = {}
        packages: list[dict[str, Any]] = []
        units: list[dict[str, Any]] = []
        counts: list[Mapping[str, Any]] = []
        for manifest_path, manifest in manifests:
            if not isinstance(manifest, Mapping):
                continue
            for entry in manifest.get("admission", ()):
                if isinstance(entry, Mapping) and isinstance(entry.get("lead_id"), str):
                    admission.setdefault(entry["lead_id"], dict(entry))
            for unit in manifest.get("units", ()):
                if isinstance(unit, Mapping):
                    units.append({"unit_key": str(unit.get("unit_key")), "source_ids": [str(x) for x in unit.get("source_ids", ())],
                                  "hunted": bool(unit.get("hunted")), "package_ids": [str(x) for x in unit.get("package_ids", ())],
                                  "manifest": self.rel(manifest_path)})
            if isinstance(manifest.get("counts"), Mapping):
                counts.append(manifest["counts"])
            for entry in manifest.get("packages", ()):
                if not isinstance(entry, Mapping) or not isinstance(entry.get("package_id"), str):
                    continue
                package_id = entry["package_id"]
                if not _IDENTIFIER_SAFE.match(package_id):
                    continue
                body_path = manifest_path.parent / "packages" / f"{package_id}.json"
                body = self.read_json(body_path, f"review package {package_id[:24]}")
                lead_ids: list[str] = []
                source_ids: list[str] = []
                if isinstance(body, Mapping):
                    lead_ids = sorted({str(lead.get("observation_id")) for lead in body.get("lead_menu", ())
                                       if isinstance(lead, Mapping) and lead.get("observation_id")})
                    scope = body.get("scope") if isinstance(body.get("scope"), Mapping) else {}
                    source_ids = [str(x) for x in scope.get("source_ids", ())]
                    reference = body.get("unit_context")
                    if isinstance(reference, Mapping) and isinstance(reference.get("path"), str):
                        unit_doc = self.read_json(manifest_path.parent / reference["path"], "package unit context")
                        if isinstance(unit_doc, Mapping) and isinstance(unit_doc.get("scope"), Mapping):
                            source_ids = [str(x) for x in unit_doc["scope"].get("source_ids", ())]
                packages.append({"package_id": package_id, "kind": str(entry.get("kind")), "lane": str(entry.get("lane")),
                                 "unit_key": entry.get("unit_key"), "lead_ids": lead_ids,
                                 "source_ids": sorted(set(source_ids)), "path": self.rel(body_path)})
        packages.sort(key=lambda item: item["package_id"])
        units.sort(key=lambda item: item["unit_key"])
        self._assembly = {"admission": admission, "packages": packages, "units": units, "counts": counts,
                          "manifests": [self.rel(path) for path, _ in manifests]}
        return self._assembly

    def projection(self) -> Mapping[str, Any] | None:
        found = self.attempt_json(REVIEW_JOB, "steps/publication/tasks/*/projection.json", "claim projection")
        return found[-1][1] if found and isinstance(found[-1][1], Mapping) else None

    def merge_document(self) -> Mapping[str, Any] | None:
        found = self.attempt_json(REVIEW_JOB, "steps/merge/tasks/*/merge.json", "merged claims")
        return found[-1][1] if found and isinstance(found[-1][1], Mapping) else None

    def finding_packages(self) -> list[Mapping[str, Any]]:
        found = self.attempt_json(REVIEW_JOB, "steps/publication/tasks/*/findings/*.json", "finding package")
        return [value for _, value in found if isinstance(value, Mapping) and value.get("claim_id")]

    def gate_document(self) -> Mapping[str, Any] | None:
        found = self.attempt_json(GATE_JOB, "steps/*/tasks/*/final-publication-gate.json", "final publication gate")
        return found[-1][1] if found and isinstance(found[-1][1], Mapping) else None

    def final_report(self) -> Mapping[str, Any] | None:
        found = self.attempt_json(REPORT_JOB, "steps/*/tasks/*/final-report.json", "final report")
        return found[-1][1] if found and isinstance(found[-1][1], Mapping) else None

    def scorecard(self) -> tuple[Path, Mapping[str, Any]] | None:
        found = self.attempt_json(GRAPH_JOB, "steps/acceptance/tasks/*/graph-quality-scorecard.json",
                                  "graph quality scorecard")
        return (found[-1][0], found[-1][1]) if found and isinstance(found[-1][1], Mapping) else None

    def priority_document(self) -> Mapping[str, Any] | None:
        found = self.attempt_json(PRIORITY_JOB, "steps/prioritize/tasks/*/artifacts/priority.json", "priority ranking")
        return found[-1][1] if found and isinstance(found[-1][1], Mapping) else None

    def syntax_facts(self) -> Mapping[str, Any] | None:
        found = self.attempt_json(PRIORITY_JOB, "steps/extract/tasks/*/artifacts/syntax-facts.json", "syntax facts")
        return found[-1][1] if found and isinstance(found[-1][1], Mapping) else None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload(row: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        value = json.loads(row["payload_text"])
    except ValueError:
        return {}
    return value if isinstance(value, Mapping) else {}


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _bounded(values: Iterable[str], limit: int = MAX_OFFENDERS) -> list[str]:
    ordered = sorted(set(values))
    return ordered[:limit]


def _check(check_id: str, status: str, summary: str, *, counts: Mapping[str, int] | None = None,
           offenders: Iterable[str] = (), evidence: Iterable[str] = ()) -> dict[str, Any]:
    return {"check_id": check_id, "status": status, "summary": summary,
            "counts": {key: int(value) for key, value in sorted((counts or {}).items())},
            "offenders": _bounded(offenders), "evidence": _bounded(evidence, 500)}


# -- structural checks ---------------------------------------------------------------------------------


def check_units(run: RunData) -> dict[str, Any]:
    check_id = "units_cover_first_party_once"
    assembly = run.assembly()
    if assembly is None:
        return _check(check_id, "not_applicable", "the review job published no package assembly (no review units)")
    files = run.first_party_code_files()
    by_identity = {item["identity"]: path for path, item in run.source_files().items()}
    membership: Counter[str] = Counter()
    for unit in assembly["units"]:
        for identity in set(unit["source_ids"]):
            path = by_identity.get(identity)
            if path is not None:
                membership[path] += 1
    missing = [path for path in files if membership[path] == 0]
    repeated = [f"{path} x{membership[path]}" for path in files if membership[path] > 1]
    counts = {"first_party_code_files": len(files), "in_one_unit": sum(1 for p in files if membership[p] == 1),
              "in_no_unit": len(missing), "in_several_units": len(repeated), "units": len(assembly["units"])}
    status = "pass" if not missing and not repeated and files else "fail"
    summary = (f"{counts['in_one_unit']}/{len(files)} first-party code files are in exactly one review unit"
               if files else "the accepted source index lists no first-party code file")
    return _check(check_id, status, summary, counts=counts, offenders=[*missing, *repeated], evidence=assembly["manifests"])


def check_facets(run: RunData) -> dict[str, Any]:
    check_id = "first_party_files_have_facets"
    facets = run.facets()
    if facets is None:
        return _check(check_id, "not_applicable", f"no accepted tags shard '{FACET_SHARD}' (collation pass, T-5008) was published")
    files = run.first_party_code_files()
    missing = [path for path in files if not facets.get(path)]
    counts = {"first_party_code_files": len(files), "with_facets": len(files) - len(missing), "without_facets": len(missing),
              "facet_tags": sum(len(tags) for tags in facets.values())}
    evidence = [shard["relative_path"] for shard in run.shards("tags", FACET_SHARD)]
    status = "pass" if files and not missing else "fail"
    return _check(check_id, status, f"{counts['with_facets']}/{len(files)} first-party code files carry facet tags",
                  counts=counts, offenders=missing, evidence=evidence)


def check_scope(run: RunData) -> dict[str, Any]:
    check_id = "no_lead_outside_first_party"
    assembly = run.assembly()
    if assembly is None:
        return _check(check_id, "not_applicable", "the review job published no package assembly (no admitted leads, packages or claims)")
    dispositions = run.dispositions()
    by_id = {item.identity: item for item in run.observations()}
    by_identity = {item["identity"]: path for path, item in run.source_files().items()}
    offenders: list[str] = []
    admitted = 0
    for lead_id, entry in sorted(assembly["admission"].items()):
        if entry.get("status") != "admitted":
            continue
        admitted += 1
        observation = by_id.get(lead_id)
        path = observation.location.path if observation and observation.location else None
        if path is not None and dispositions.classify(path) != FIRST_PARTY:
            offenders.append(f"admitted lead {lead_id[:40]} at {path} ({dispositions.classify(path)})")
    for package in assembly["packages"]:
        for identity in package["source_ids"]:
            path = by_identity.get(identity)
            if path is not None and dispositions.classify(path) != FIRST_PARTY:
                offenders.append(f"package {package['package_id'][:40]} scope {path} ({dispositions.classify(path)})")
        for lead_id in package["lead_ids"]:
            observation = by_id.get(lead_id)
            path = observation.location.path if observation and observation.location else None
            if path is not None and dispositions.classify(path) != FIRST_PARTY:
                offenders.append(f"package {package['package_id'][:40]} lead at {path} ({dispositions.classify(path)})")
    claims = 0
    projection = run.projection()
    if projection is not None:
        claim_rows = [claim for claim in projection.get("claims", ()) if isinstance(claim, Mapping)]
        claims = len(claim_rows)
        located = run.locate(entity for claim in claim_rows for entity in claim.get("affected_entities", ()))
        for claim in claim_rows:
            for entity in claim.get("affected_entities", ()):
                for location in located.get(str(entity), ()):
                    if dispositions.classify(location.path) != FIRST_PARTY:
                        offenders.append(f"claim {str(claim.get('claim_id'))[:40]} at {location.path} "
                                         f"({dispositions.classify(location.path)})")
    counts = {"admitted_leads": admitted, "packages": len(assembly["packages"]), "claims": claims,
              "outside_first_party": len(set(offenders)), "dispositions_configured": int(dispositions.configured)}
    status = "pass" if not offenders else "fail"
    summary = f"{counts['outside_first_party']} lead, package or claim locations outside first-party code"
    return _check(check_id, status, summary, counts=counts, offenders=offenders, evidence=assembly["manifests"])


def check_dataflow_eligibility(run: RunData) -> dict[str, Any]:
    check_id = "classified_sink_paths_eligible"
    shards = [shard for shard in run.shards("graph") if shard["producer"].get("family") == "dataflow_path"
              or shard["shard_id"].endswith("-dataflow_path")]
    if not shards:
        return _check(check_id, "not_applicable", "no accepted dataflow_path graph shard was published")
    counts: Counter[str] = Counter()
    offenders: list[str] = []
    for shard in shards:
        for row in run.rows(shard, ("dataflow_path",)):
            payload = _payload(row)
            result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
            sink = result.get("sink") if isinstance(result.get("sink"), Mapping) else {}
            sink_class = _string(sink.get("sink_class")) or "unclassified"
            admissibility = payload.get("admissibility") if isinstance(payload.get("admissibility"), Mapping) else {}
            eligible = bool(admissibility.get("direct_eligible"))
            counts["paths"] += 1
            if sink_class == "unclassified":
                counts["unclassified_sink"] += 1
                continue
            counts["classified_sink"] += 1
            if eligible:
                counts["classified_eligible"] += 1
            else:
                reasons = ",".join(str(x) for x in admissibility.get("ineligibility_reasons", ())) or "no reason"
                where = f"{row['location'].path}:{row['location'].start_line}" if row["location"] else "unlocated"
                offenders.append(f"{row['identity'][:48]} {sink_class} at {where}: {reasons}")
    status = "pass" if not offenders else "fail"
    summary = (f"{counts['classified_eligible']}/{counts['classified_sink']} paths with a classified sink are eligible; "
               f"{counts['unclassified_sink']} paths have an unclassified sink")
    return _check(check_id, status, summary, counts=counts, offenders=offenders,
                  evidence=[shard["relative_path"] for shard in shards])


def check_scorecard(run: RunData) -> dict[str, Any]:
    check_id = "scorecard_lists_first_party_functions_once"
    if run.handoff(GRAPH_JOB) is None:
        return _check(check_id, "not_applicable", f"{GRAPH_JOB} published no handoff")
    found = run.scorecard()
    if found is None:
        return _check(check_id, "fail", f"{GRAPH_JOB} ran but published no graph-quality-scorecard.json (T-5016)",
                      evidence=[run.rel(run.attempt_dir(GRAPH_JOB) or run.data)])
    path, document = found
    dispositions = run.dispositions()
    seen: Counter[tuple[str, str, int]] = Counter()
    offenders: list[str] = []
    functions = 0
    for scope in document.get("scopes", ()):
        if not isinstance(scope, Mapping):
            continue
        for function in scope.get("functions", ()):
            if not isinstance(function, Mapping):
                continue
            functions += 1
            key = (str(function.get("path")), str(function.get("name")), int(function.get("line") or 0))
            seen[key] += 1
            if function.get("path") and dispositions.classify(str(function["path"])) != FIRST_PARTY:
                offenders.append(f"{key[0]}:{key[2]} {key[1]} is {dispositions.classify(key[0])}")
    offenders.extend(f"{path_}:{line} {name} listed {count} times" for (path_, name, line), count in seen.items() if count > 1)
    totals = document.get("totals") if isinstance(document.get("totals"), Mapping) else {}
    declared = totals.get("first_party_functions")
    if declared is not None and int(declared) != functions:
        offenders.append(f"totals.first_party_functions={declared} but {functions} functions are listed")
    counts = {"functions": functions, "distinct_functions": len(seen), "scopes": len(document.get("scopes", ())),
              "paths": int(totals.get("paths") or 0), "paths_eligible": int(totals.get("paths_eligible") or 0)}
    status = "pass" if not offenders else "fail"
    return _check(check_id, status, f"scorecard lists {functions} first-party functions, {len(seen)} distinct",
                  counts=counts, offenders=offenders, evidence=[run.rel(path)])


def _duration_seconds(record: Mapping[str, Any]) -> float | None:
    started, completed = record.get("started_at"), record.get("completed_at")
    try:
        if isinstance(started, str) and isinstance(completed, str):
            return round((datetime.fromisoformat(completed) - datetime.fromisoformat(started)).total_seconds(), 3)
    except ValueError:
        return None
    return None


def job_table(run: RunData) -> list[dict[str, Any]]:
    """One row per job directory: terminal statuses, declared gaps by code, step and task durations."""
    rows = []
    for job_id in run.job_ids():
        found = run.handoff(job_id)
        if found is None:
            rows.append({"job_id": job_id, "attempt_id": None, "status": None, "completion_status": None,
                         "execution_status": None, "duration_seconds": None, "gap_count": 0, "gaps_by_code": {},
                         "units": [], "steps": [], "task_seconds": None, "published": False})
            continue
        path, handoff = found
        outcomes = run.read_json(run.run_dir / handoff["outcomes"]["path"], f"{job_id} outcomes") \
            if isinstance(handoff.get("outcomes"), Mapping) and isinstance(handoff["outcomes"].get("path"), str) else None
        gaps_by_code: Counter[str] = Counter()
        if isinstance(outcomes, Mapping):
            for gap in outcomes.get("gaps", ()):
                if isinstance(gap, Mapping):
                    gaps_by_code[str(gap.get("code") or "unknown")] += 1
        coverage = handoff.get("coverage") if isinstance(handoff.get("coverage"), Mapping) else {}
        units = []
        outputs = handoff.get("outputs") if isinstance(handoff.get("outputs"), Mapping) else {}
        for unit_id, output in sorted(outputs.items()):
            terminal = output.get("terminal_status") if isinstance(output, Mapping) else None
            # A unit output without a terminal_status is counted as undeclared, not as an unknown word.
            units.append({"unit_id": str(unit_id), "terminal_status": _string(terminal),
                          "known": terminal is None or terminal in TERMINAL_STATUSES})
        attempt = run.attempt_dir(job_id)
        steps = []
        task_seconds = 0.0
        if attempt is not None:
            for lifecycle_path in sorted(attempt.glob("steps/*/lifecycle.json")):
                lifecycle = run.read_json(lifecycle_path, f"{job_id} step lifecycle")
                if isinstance(lifecycle, Mapping):
                    steps.append({"step_id": str(lifecycle.get("step_id") or lifecycle_path.parent.name),
                                  "status": _string(lifecycle.get("status")),
                                  "duration_ms": int(lifecycle.get("duration_ms") or 0)})
            for status_path in sorted(attempt.glob("steps/*/tasks/*/status.json")):
                status = run.read_json(status_path, f"{job_id} task status")
                if isinstance(status, Mapping):
                    seconds = _duration_seconds(status)
                    task_seconds += seconds or 0.0
        rows.append({"job_id": job_id, "attempt_id": _string(handoff.get("attempt_id")), "status": _string(handoff.get("status")),
                     "completion_status": _string(handoff.get("completion_status")),
                     "execution_status": _string(handoff.get("execution_status")),
                     "duration_seconds": _duration_seconds(handoff),
                     "gap_count": int(coverage.get("gap_count") or sum(gaps_by_code.values())),
                     "gaps_by_code": dict(sorted(gaps_by_code.items())), "units": units, "steps": steps,
                     "task_seconds": round(task_seconds, 3), "published": True})
    return rows


def check_jobs(run: RunData, jobs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    check_id = "jobs_terminal_status_tabulated"
    if not jobs:
        return _check(check_id, "not_applicable", "the run has no data/jobs directory")
    offenders = []
    for job in jobs:
        if not job["published"]:
            offenders.append(f"{job['job_id']}: no readable latest.json handoff")
        for unit in job["units"]:
            if not unit["known"]:
                offenders.append(f"{job['job_id']} {unit['unit_id']}: terminal_status {unit['terminal_status']!r} is not in the vocabulary")
    by_completion = Counter(str(job["completion_status"]) for job in jobs if job["published"])
    counts = {"jobs": len(jobs), "published": sum(1 for job in jobs if job["published"]),
              "declared_gaps": sum(job["gap_count"] for job in jobs),
              "units": sum(len(job["units"]) for job in jobs),
              "units_without_terminal_status": sum(1 for job in jobs for unit in job["units"]
                                                   if unit["terminal_status"] is None),
              **{f"completion_{key}": value for key, value in by_completion.items()}}
    status = "pass" if not offenders else "fail"
    summary = f"{counts['published']}/{len(jobs)} jobs published a handoff; {counts['declared_gaps']} declared gaps"
    return _check(check_id, status, summary, counts=counts, offenders=offenders,
                  evidence=[f"data/jobs/{job['job_id']}/latest.json" for job in jobs if job["published"]])


def model_calls(run: RunData) -> dict[str, Any]:
    """Model calls per job from the model-execution receipts, and the review job's budget ledger."""
    by_job: dict[str, dict[str, Any]] = {}
    receipts = 0
    root = run.data / "inference-executions"
    for path in sorted(root.glob("*/*/*.json")) if root.is_dir() else ():
        receipt = run.read_json(path, "model execution receipt")
        if not isinstance(receipt, Mapping) or receipt.get("schema") != "appsec-review/model-execution-receipt/1":
            continue
        receipts += 1
        job = str(receipt.get("job_id") or "unknown")
        row = by_job.setdefault(job, {"calls": 0, "succeeded": 0, "failed": 0, "elapsed_ms": 0, "input_tokens": 0,
                                      "output_tokens": 0, "usage_unavailable": 0})
        row["calls"] += 1
        row["succeeded" if receipt.get("status") == "SUCCEEDED" else "failed"] += 1
        row["elapsed_ms"] += int(receipt.get("elapsed_ms") or 0)
        usage = receipt.get("usage") if isinstance(receipt.get("usage"), Mapping) else {}
        if usage.get("input_tokens") is None and usage.get("output_tokens") is None:
            row["usage_unavailable"] += 1
        row["input_tokens"] += int(usage.get("input_tokens") or 0)
        row["output_tokens"] += int(usage.get("output_tokens") or 0)
    budget_path = run.data / "jobs" / REVIEW_JOB / "budget" / "budget.json"
    budget = None
    if budget_path.is_file():
        state = run.read_json(budget_path, "review budget ledger")
        if isinstance(state, Mapping):
            limits = state.get("limits") if isinstance(state.get("limits"), Mapping) else {}
            budget = {"path": run.rel(budget_path), "exhausted": _string(state.get("exhausted")),
                      "usage": {name: int(state.get(name) or 0) for name in
                                ("model_turns", "input_tokens", "output_tokens", "retrieval_queries")},
                      "limits": {name: int(limits[name]) for name in
                                 ("max_model_turns", "max_input_tokens", "max_output_tokens", "max_retrieval_queries")
                                 if isinstance(limits.get(name), int)},
                      "team_packages": {str(k): int(v) for k, v in sorted((state.get("team_packages") or {}).items())}}
    return {"receipts": receipts, "by_job": dict(sorted(by_job.items())), "review_budget": budget}


# -- keyed scoring -----------------------------------------------------------------------------------


@dataclass
class _Planted:
    record: Mapping[str, Any]
    item_id: str
    klass: str
    expected: str
    path: str | None = None
    function: str | None = None
    start: int | None = None
    end: int | None = None
    match_basis: str = "path"
    package: str | None = None
    version: str | None = None
    identifiers: tuple[str, ...] = ()
    location: str | None = None


def _planted_items(key: Mapping[str, Any], run: RunData) -> list[_Planted]:
    items = []
    for record in key.get("planted", ()):
        if not isinstance(record, Mapping):
            continue
        klass = str(record.get("class"))
        item = _Planted(record, str(record.get("id")), klass, str(record.get("expected_disposition")))
        if klass in CODE_CLASSES:
            item.path = _string(record.get("file"))
            item.function = _string(record.get("function"))
            span = record.get("span") if isinstance(record.get("span"), Mapping) else record.get("introduced_span")
            start = int(span.get("start_line") or 0) if isinstance(span, Mapping) else 0
            end = int(span.get("end_line") or 0) if isinstance(span, Mapping) else 0
            if start > 0 and end >= start:
                item.start, item.end, item.match_basis = start, end, "span"
            elif item.path and item.function:
                found = _function_range(run, item.path, item.function)
                if found is not None:
                    item.start, item.end, item.match_basis = found[0], found[1], "function"
        elif klass in DEPENDENCY_CLASSES:
            item.package = _string(record.get("package"))
            item.version = _string(record.get("version")) or _string(record.get("vulnerable_version"))
            item.identifiers = tuple(sorted({value for value in (record.get("osv"), record.get("cve"))
                                             if isinstance(value, str) and _IDENTIFIER_SAFE.match(value)}))
            item.location = _string(record.get("location"))
            item.match_basis = "identifier"
        items.append(item)
    return sorted(items, key=lambda item: item.item_id)


def _function_range(run: RunData, path: str, function: str) -> tuple[int, int] | None:
    facts = run.syntax_facts()
    if not isinstance(facts, Mapping):
        return None
    files = facts.get("files") if isinstance(facts.get("files"), Mapping) else {}
    record = files.get(path) if isinstance(files, Mapping) else None
    if not isinstance(record, Mapping):
        return None
    for unit in record.get("units", ()):
        if isinstance(unit, Mapping) and unit.get("name") == function:
            try:
                return int(unit["start_line"]), int(unit["end_line"])
            except (KeyError, TypeError, ValueError):
                return None
    return None


def _observation_matches(item: _Planted, observation: Observation) -> bool:
    if item.klass in CODE_CLASSES:
        return item.path is not None and observation.location is not None \
            and observation.location.overlaps(item.path, item.start, item.end)
    for identifier in item.identifiers:
        if re.search(r'(?<![A-Za-z0-9._-])' + re.escape(identifier) + r'(?![A-Za-z0-9._-])', observation.payload_text):
            return True
    return False


def _dependency_rows(run: RunData, item: _Planted) -> list[str]:
    """Inventory ``dependency_package`` rows whose name and version equal the planted package exactly."""
    found = []
    if not item.package:
        return found
    for shard in run.shards("inventory"):
        for row in run.rows(shard, ("dependency_package",)):
            payload = _payload(row)
            if row["name"] == item.package and (item.version is None or payload.get("version") == item.version):
                found.append(row["identity"])
    return sorted(set(found))


def _claim_entities(claim: Mapping[str, Any], relations: Mapping[str, Any]) -> list[str]:
    entities = [str(x) for x in claim.get("affected_entities", ())]
    for relation in relations.get(str(claim.get("claim_id")), ()) or ():
        if isinstance(relation, Mapping) and isinstance(relation.get("entity_id"), str):
            entities.append(relation["entity_id"])
    return sorted(set(entities))


def keyed_scoring(run: RunData, key: Mapping[str, Any]) -> dict[str, Any]:
    items = _planted_items(key, run)
    sources = run.source_files()
    facets = run.facets()
    observations = run.observations()
    assembly = run.assembly()
    projection = run.projection()
    merge = run.merge_document()
    claims = [claim for claim in (projection or {}).get("claims", ()) if isinstance(claim, Mapping)]
    relations = (projection or {}).get("relations") if isinstance((projection or {}).get("relations"), Mapping) else {}
    judge_verdicts = (projection or {}).get("judge_verdicts") if isinstance((projection or {}).get("judge_verdicts"), Mapping) else {}
    proposal_packages = (merge or {}).get("proposal_packages") if isinstance((merge or {}).get("proposal_packages"), Mapping) else {}
    findings = run.finding_packages()
    gate = run.gate_document()
    report = run.final_report()
    buckets: dict[str, str] = {}
    if gate is not None:
        for package in gate.get("packages", ()):
            if isinstance(package, Mapping) and isinstance(package.get("finding_package_id"), str):
                buckets[package["finding_package_id"]] = str(package.get("bucket"))
    reported_claims: set[str] = set()
    if report is not None:
        for finding in report.get("findings", ()):
            if isinstance(finding, Mapping) and isinstance(finding.get("claim_id"), str):
                reported_claims.add(finding["claim_id"])
    located = run.locate(entity for claim in claims for entity in _claim_entities(claim, relations))
    packages_by_lead: dict[str, list[dict[str, Any]]] = defaultdict(list)
    packages_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for package in (assembly or {}).get("packages", ()):
        for lead_id in package["lead_ids"]:
            packages_by_lead[lead_id].append(package)
        for identity in package["source_ids"]:
            packages_by_source[identity].append(package)
    findings_by_claim: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for finding in findings:
        findings_by_claim[str(finding["claim_id"])].append(finding)
    matched_claims_by_item: dict[str, set[str]] = {}
    rows = []
    for item in items:
        source = sources.get(item.path) if item.path else None
        hits = [obs for obs in observations if _observation_matches(item, obs)]
        hit_ids = {obs.identity for obs in hits}
        dependency_rows = _dependency_rows(run, item) if item.klass in DEPENDENCY_CLASSES else []
        leads = []
        for obs in hits[:MAX_ITEM_MATCHES]:
            admission = (assembly or {}).get("admission", {}).get(obs.identity, {})
            leads.append({"lead_id": obs.identity, "family": obs.family, "scanner": obs.scanner, "rule_id": obs.rule_id,
                          "start_line": obs.location.start_line if obs.location else None,
                          "admission": _string(admission.get("status")) or ("unknown" if assembly else "no_review"),
                          "exclusion": _string(admission.get("exclusion"))})
        packages: dict[str, dict[str, Any]] = {}
        for lead_id in hit_ids:
            for package in packages_by_lead.get(lead_id, ()):
                packages.setdefault(package["package_id"], {"package_id": package["package_id"], "lane": package["lane"],
                                                            "kind": package["kind"], "via": "lead"})
        if source is not None:
            for package in packages_by_source.get(source["identity"], ()):
                packages.setdefault(package["package_id"], {"package_id": package["package_id"], "lane": package["lane"],
                                                            "kind": package["kind"], "via": "unit"})
        matched_claims = []
        citing: list[Location] = []
        for claim in claims:
            claim_id = str(claim.get("claim_id"))
            entities = _claim_entities(claim, relations)
            matched = False
            for entity in entities:
                if entity in hit_ids or entity in dependency_rows:
                    matched = True
                for location in located.get(entity, ()):
                    # A whole-file citation (the source_file entity itself) names no planted span.
                    if item.path and not location.file_level and location.overlaps(item.path, item.start, item.end):
                        matched = True
                        citing.append(location)
            proposing = {str(x) for x in proposal_packages.get(claim_id, ())} | {str(claim.get("package_id"))}
            # Only a finding-lead package names the one lead a claim was raised from; a hunt menu lists many.
            if any(package_id in packages and packages[package_id]["via"] == "lead"
                   and packages[package_id]["kind"] == "finding_lead" for package_id in proposing):
                matched = True
            if matched:
                matched_claims.append({"claim_id": claim_id, "state": _string(claim.get("state")),
                                       "lane": _string(claim.get("lane")), "package_id": _string(claim.get("package_id"))})
        matched_claim_ids = {claim["claim_id"] for claim in matched_claims}
        matched_claims_by_item[item.item_id] = matched_claim_ids
        verdicts = [{"claim_id": claim_id, "verdict": _string(verdict.get("verdict")), "cell_id": _string(verdict.get("cell_id"))}
                    for claim_id in sorted(matched_claim_ids)
                    for verdict in judge_verdicts.get(claim_id, ()) if isinstance(verdict, Mapping)]
        finding_rows = [{"finding_package_id": str(finding.get("finding_package_id")), "claim_id": claim_id,
                         "state": _string(finding.get("state")), "bucket": buckets.get(str(finding.get("finding_package_id")))}
                        for claim_id in sorted(matched_claim_ids) for finding in findings_by_claim.get(claim_id, ())]
        reported = any(claim_id in reported_claims for claim_id in matched_claim_ids)
        citing_lines = sorted({loc.record()["entity_id"]: loc for loc in citing}.values(),
                              key=lambda loc: (loc.path, loc.start_line, loc.entity_id))[:MAX_CITING_LINES]
        observed = _observed_disposition(leads, packages, matched_claims, finding_rows, reported)
        outcome, reason = _outcome(item, observed, reported, report is not None, matched_claims)
        rows.append({
            "id": item.item_id, "class": item.klass, "expected_disposition": item.expected,
            "file": item.path, "function": item.function,
            "span": {"start_line": item.start, "end_line": item.end} if item.start is not None else None,
            "match_basis": item.match_basis, "package": item.package, "version": item.version,
            "identifiers": list(item.identifiers), "location": item.location,
            "in_accepted_scope": None if item.klass in DEPENDENCY_CLASSES else source is not None,
            "disposition": (source or {}).get("disposition") if source else (
                run.dispositions().classify(item.path) if item.path else None),
            "facets": sorted(facets.get(item.path, ())) if facets is not None and item.path else [],
            "facets_available": facets is not None,
            "dependency_rows": dependency_rows[:MAX_ITEM_MATCHES],
            "leads": sorted(leads, key=lambda row: row["lead_id"]),
            "packages": sorted(packages.values(), key=lambda row: row["package_id"]),
            "claims": sorted(matched_claims, key=lambda row: row["claim_id"]),
            "judge_verdicts": verdicts,
            "finding_packages": sorted(finding_rows, key=lambda row: row["finding_package_id"]),
            "reported": reported, "citing_lines": [loc.record() for loc in citing_lines],
            "observed_disposition": observed, "outcome": outcome, "outcome_reason": reason,
        })
    return {"items": rows, "metrics": _metrics(rows, reported_claims, report is not None),
            "complexity": _complexity(run, key.get("complexity")),
            "publication_available": {"review_assembly": assembly is not None, "claim_projection": projection is not None,
                                      "finding_packages": bool(findings), "gate": gate is not None, "report": report is not None,
                                      "facets": facets is not None}}


def _observed_disposition(leads: Sequence[Mapping[str, Any]], packages: Mapping[str, Any],
                          claims: Sequence[Mapping[str, Any]], findings: Sequence[Mapping[str, Any]], reported: bool) -> str:
    if reported:
        return "reported"
    if any(row.get("bucket") == "verification_backlog" for row in findings):
        return "verification_backlog"
    if any(row.get("bucket") == "withheld" for row in findings):
        return "withheld"
    if findings:
        return "finding_not_reported"
    if claims:
        return "claimed_not_published"
    if any(row["via"] == "lead" for row in packages.values()):
        return "packaged"
    if any(row["admission"] == "admitted" for row in leads):
        return "admitted_not_packaged"
    if leads:
        return "lead_not_admitted"
    if any(row["via"] == "unit" for row in packages.values()):
        return "in_hunt_unit_only"
    return "not_observed"


def _outcome(item: _Planted, observed: str, reported: bool, report_available: bool,
             claims: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    if not report_available:
        return "not_evaluable", "the run published no final report"
    if item.expected == "reported":
        return ("hit", "a matching finding reached the report") if reported else ("miss", f"observed {observed}")
    if item.expected == "reported-as-fixed":
        return ("miss", "a fixed item was reported as a finding") if reported else ("hit", f"not reported ({observed})")
    if item.expected == "squelched":
        if reported:
            return "miss", "a planted false positive reached the report"
        refuted = [row for row in claims if row.get("state") in ("contradicted", "not_reachable",
                                                                  "not_exploitable_in_observed_configuration")]
        return "hit", (f"refuted by {len(refuted)} claim(s)" if refuted else f"not reported ({observed})")
    return "not_evaluable", f"unknown expected_disposition {item.expected!r}"


def _metrics(rows: Sequence[Mapping[str, Any]], reported_claims: set[str], report_available: bool) -> dict[str, Any]:
    by_class: dict[str, dict[str, Any]] = {}
    for klass in PLANTED_CLASSES:
        members = [row for row in rows if row["class"] == klass]
        hits = sum(1 for row in members if row["outcome"] == "hit")
        misses = sum(1 for row in members if row["outcome"] == "miss")
        total = len(members)
        evaluable = report_available and total > 0
        by_class[klass] = {"planted": total, "hit": hits, "miss": misses,
                           "not_evaluable": total - hits - misses,
                           "recall": round(hits / total, 4) if evaluable and klass.startswith("true_positive") else None,
                           "squelch_rate": round(hits / total, 4) if evaluable and klass == "false_positive" else None,
                           "fixed_rate": round(hits / total, 4) if evaluable and klass.startswith("fixed") else None}
    true_claims: set[str] = set()
    planted_claims: set[str] = set()
    for row in rows:
        ids = {claim["claim_id"] for claim in row["claims"]}
        planted_claims |= ids
        if row["class"].startswith("true_positive"):
            true_claims |= ids
    reported_total = len(reported_claims)
    matched_true = len(reported_claims & true_claims)
    matched_other = len(reported_claims & (planted_claims - true_claims))
    return {"by_class": by_class, "report_available": report_available,
            "reported_findings": reported_total,
            "reported_findings_matching_planted_true_positives": matched_true,
            "reported_findings_matching_planted_fixed_or_false_positive": matched_other,
            "reported_findings_unmatched": reported_total - matched_true - matched_other,
            "precision": round(matched_true / reported_total, 4) if report_available and reported_total else None,
            "recall": (round(sum(c["hit"] for k, c in by_class.items() if k.startswith("true_positive"))
                             / sum(c["planted"] for k, c in by_class.items() if k.startswith("true_positive")), 4)
                       if report_available and sum(c["planted"] for k, c in by_class.items() if k.startswith("true_positive"))
                       else None)}


def _complexity(run: RunData, expected: Any) -> dict[str, Any] | None:
    if not isinstance(expected, Mapping):
        return None
    path, function = _string(expected.get("file")), _string(expected.get("function"))
    document = run.priority_document()
    result: dict[str, Any] = {"file": path, "function": function, "expected_cyclomatic": expected.get("cyclomatic"),
                              "expected_top_rank": expected.get("expected_top_rank"),
                              "observed_cyclomatic": None, "function_rank": None, "file_rank": None,
                              "ranked_functions": 0, "ranked_files": 0, "share_above_threshold_positive": None,
                              "available": document is not None, "top_rank": None}
    if document is None:
        return result
    functions = [row for row in document.get("functions", ()) if isinstance(row, Mapping)]
    files = [row for row in document.get("files", ()) if isinstance(row, Mapping)]
    result["ranked_functions"], result["ranked_files"] = len(functions), len(files)
    for position, row in enumerate(sorted(functions, key=lambda r: (int(r.get("rank") or 10 ** 9), str(r.get("name")))), 1):
        name = row.get("name") or str(row.get("function_id") or "").split("#", 1)[-1].split("@", 1)[0]
        if row.get("path") == path and name == function:
            features = row.get("features") if isinstance(row.get("features"), Mapping) else {}
            result["observed_cyclomatic"] = features.get("cyclomatic", row.get("cyclomatic"))
            result["function_rank"] = int(row.get("rank") or position)
            break
    for position, row in enumerate(sorted(files, key=lambda r: (int(r.get("rank") or 10 ** 9), str(r.get("path")))), 1):
        if row.get("path") == path:
            result["file_rank"] = int(row.get("rank") or position)
            share = row.get("share_above_threshold")
            if isinstance(share, Mapping):
                result["share_above_threshold_positive"] = any((value or 0) > 0 for value in share.values())
            elif isinstance(share, (int, float)):
                result["share_above_threshold_positive"] = share > 0
            break
    if result["function_rank"] is not None:
        result["top_rank"] = result["function_rank"] == 1
    elif result["file_rank"] is not None:
        result["top_rank"] = result["file_rank"] == 1
    if result["observed_cyclomatic"] is None and path and function:
        facts = run.syntax_facts()
        files_facts = (facts or {}).get("files") if isinstance((facts or {}).get("files"), Mapping) else {}
        record = files_facts.get(path) if isinstance(files_facts, Mapping) else None
        for unit in (record or {}).get("units", ()) if isinstance(record, Mapping) else ():
            if isinstance(unit, Mapping) and unit.get("name") == function:
                result["observed_cyclomatic"] = unit.get("cyclomatic")
    return result


# -- document ------------------------------------------------------------------------------------------


def load_answer_key(path: Path) -> dict[str, Any]:
    """The user-supplied answer key; only its schema id and the planted list are required."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SmokeScoreError(f"answer key {path} is unreadable: {exc}") from exc
    if not isinstance(document, Mapping) or document.get("schema") != KEY_SCHEMA:
        raise SmokeScoreError(f"answer key {path} is not {KEY_SCHEMA}")
    if not isinstance(document.get("planted"), list):
        raise SmokeScoreError(f"answer key {path} has no planted list")
    return dict(document)


def score_run(run_dir: Path, answer_key: Mapping[str, Any] | None = None, *, key_path: Path | None = None) -> dict[str, Any]:
    run_dir = Path(run_dir)
    if not (run_dir / "data").is_dir():
        raise SmokeScoreError(f"{run_dir} has no data/ directory; it is not a run")
    run = RunData(run_dir)
    jobs = job_table(run)
    checks = [check_units(run), check_facets(run), check_scope(run), check_dataflow_eligibility(run),
              check_scorecard(run), check_jobs(run, jobs)]
    keyed = keyed_scoring(run, answer_key) if answer_key is not None else None
    key_record = None
    if answer_key is not None:
        key_record = {"schema": KEY_SCHEMA, "sha256": hashlib.sha256(_canonical(answer_key)).hexdigest(),
                      "language": _string(answer_key.get("language")), "tag": _string(answer_key.get("tag")),
                      "commit": _string(answer_key.get("commit")), "planted": len(answer_key.get("planted", ())),
                      "path": str(key_path) if key_path is not None else None}
    document = {
        "schema": SCHEMA, "run_id": run.run_id,
        "authority": "a measurement of the run's published records; never evidence about the target",
        "answer_key": key_record,
        "structural_checks": checks,
        "check_counts": dict(Counter(check["status"] for check in checks)),
        "jobs": jobs, "model_calls": model_calls(run), "keyed": keyed,
        "evidence_paths": sorted(run.evidence), "gaps": sorted(run.gaps),
    }
    validate_document(document)
    return document


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_document(document: Mapping[str, Any]) -> None:
    """Check the document against ``docs/schemas/smoke-score.schema.json`` (closed)."""
    from jsonschema import Draft202012Validator
    from appsec_review.application_paths import application_asset
    schema = json.loads(application_asset(SCHEMA_PATH).read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        where = "/".join(str(part) for part in first.path) or "<root>"
        raise SmokeScoreError(f"smoke score violates its schema at {where}: {first.message}")


def render_summary(document: Mapping[str, Any]) -> str:
    """One screen of text: checks, jobs, model calls and, with a key, the per-item table and metrics."""
    lines = [f"Smoke score ({document['schema']}) run {document['run_id']}",
             f"checks: " + ", ".join(f"{key}={value}" for key, value in sorted(document["check_counts"].items()))]
    for check in document["structural_checks"]:
        lines.append(f"  [{check['status']:>14}] {check['check_id']}: {check['summary']}")
        for offender in check["offenders"][:3]:
            lines.append(f"                   - {offender}")
    jobs = document["jobs"]
    published = [job for job in jobs if job["published"]]
    lines.append(f"jobs: {len(published)}/{len(jobs)} published; "
                 + ", ".join(f"{k}={v}" for k, v in sorted(Counter(str(j['completion_status']) for j in published).items())))
    slowest = sorted((job for job in published if job["duration_seconds"] is not None),
                     key=lambda job: -job["duration_seconds"])[:5]
    for job in slowest:
        lines.append(f"  {job['job_id']:<40} {job['completion_status']:<20} {job['duration_seconds']:>9.1f}s gaps={job['gap_count']}")
    calls = document["model_calls"]
    lines.append(f"model calls: {calls['receipts']} receipts in {len(calls['by_job'])} jobs")
    for job, row in sorted(calls["by_job"].items(), key=lambda item: -item[1]["calls"])[:4]:
        lines.append(f"  {job:<40} calls={row['calls']} ok={row['succeeded']} failed={row['failed']} "
                     f"in={row['input_tokens']} out={row['output_tokens']}")
    budget = calls["review_budget"]
    if budget is not None:
        usage, limits = budget["usage"], budget["limits"]
        lines.append("review budget: " + ", ".join(f"{name}={usage[name]}/{limits.get('max_' + name, '?')}" for name in usage)
                     + (f" exhausted={budget['exhausted']}" if budget["exhausted"] else ""))
    keyed = document["keyed"]
    if keyed is None:
        lines.append("keyed scoring: no answer key supplied (structural checks only)")
    else:
        for item in keyed["items"]:
            where = f"{item['file']}:{item['span']['start_line']}" if item["span"] else (item["file"] or item["package"] or "")
            lines.append(f"  {item['id']:<8} {item['class']:<26} {item['outcome']:<14} {item['observed_disposition']:<22} "
                         f"leads={len(item['leads'])} pkgs={len(item['packages'])} claims={len(item['claims'])} "
                         f"judge={','.join(str(v['verdict']) for v in item['judge_verdicts']) or '-'} {where}")
        metrics = keyed["metrics"]
        lines.append(f"metrics: precision={metrics['precision']} recall={metrics['recall']} "
                     f"reported={metrics['reported_findings']} matched_tp={metrics['reported_findings_matching_planted_true_positives']} "
                     f"matched_fp_or_fixed={metrics['reported_findings_matching_planted_fixed_or_false_positive']} "
                     f"unmatched={metrics['reported_findings_unmatched']}")
        for klass, row in metrics["by_class"].items():
            if row["planted"]:
                lines.append(f"  {klass:<26} planted={row['planted']} hit={row['hit']} miss={row['miss']} "
                             f"not_evaluable={row['not_evaluable']}")
        complexity = keyed["complexity"]
        if complexity is not None:
            lines.append(f"complexity: {complexity['file']}:{complexity['function']} cyclomatic expected={complexity['expected_cyclomatic']} "
                         f"observed={complexity['observed_cyclomatic']} function_rank={complexity['function_rank']} "
                         f"file_rank={complexity['file_rank']} top_rank={complexity['top_rank']}")
    lines.append(f"reader gaps: {len(document['gaps'])}; evidence paths read: {len(document['evidence_paths'])}")
    for gap in document["gaps"][:3]:
        lines.append(f"  - {gap}")
    return "\n".join(lines) + "\n"


def write_outputs(run_dir: Path, document: Mapping[str, Any], summary: str) -> tuple[Path, Path]:
    """Write the document and the summary under ``data/verification/``; nothing else in the run is touched."""
    out = Path(run_dir) / OUTPUT_DIRECTORY
    out.mkdir(parents=True, exist_ok=True)
    json_path, text_path = out / JSON_NAME, out / TEXT_NAME
    json_path.write_bytes(json.dumps(document, sort_keys=True, indent=1, ensure_ascii=False).encode("utf-8") + b"\n")
    text_path.write_text(summary, encoding="utf-8", newline="\n")
    return json_path, text_path


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="smoke-score", description=__doc__.splitlines()[0])
    parser.add_argument("--run", required=True, help="run directory, e.g. runs/2026-11-14-0005")
    parser.add_argument("--answer-key", default=None, help="the smoke answer key (appsec-review/smoke-answer-key/1); "
                                                           "without it only the structural checks run")
    parser.add_argument("--quiet", action="store_true", help="do not print the summary")
    arguments = parser.parse_args(argv)
    try:
        key = load_answer_key(Path(arguments.answer_key)) if arguments.answer_key else None
        document = score_run(Path(arguments.run), key, key_path=Path(arguments.answer_key) if arguments.answer_key else None)
    except SmokeScoreError as exc:
        print(f"smoke-score: {exc}", file=__import__("sys").stderr)
        return 2
    summary = render_summary(document)
    json_path, text_path = write_outputs(Path(arguments.run), document, summary)
    if not arguments.quiet:
        print(summary, end="")
        print(f"written: {json_path.as_posix()} and {text_path.as_posix()}")
    return 0


__all__ = ["SCHEMA", "RunData", "SmokeScoreError", "keyed_scoring", "load_answer_key", "main", "render_summary",
           "score_run", "validate_document", "write_outputs"]
