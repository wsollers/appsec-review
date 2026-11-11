"""Build a ``finding-snapshot/1`` from one accepted run (finding-metrics.md sections 3 and 5.1).

Two layers:

* :func:`findings_from_documents` is pure. It turns the current accepted final report, the claim
  projection and resolved evidence locations into normalized finding records.
* :func:`load_run` is the only code in this domain that reads a run. It goes through the same
  verified readers the report itself uses (``acceptance.system.accepted_final_report`` and the
  retrieval core), never a directory scan and never the target.

What a run records and what it does not:

* ``severity`` is the ship-block policy's technical severity; ``None`` when unrated.
* Lane A findings are scanner-backed by construction. A lane B finding is scanner-backed when a
  scanner observation overlaps one of its locations, and unknown (``None``) when the run has no
  observation index: unknown is never counted as scanner-independent.
* A run does not record which source files a review covered, so ``reviewed_units`` is supplied by
  the caller or stays ``None`` with the named gap ``reviewed_units_not_supplied``.
* Enclosing functions, owners, attacker position and remediation are not recorded by the review
  today; they stay ``None`` (not established) unless the caller's slice rules establish them.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .contracts import BUCKETS, MAX_CODE_CHARS, MAX_LOCATIONS, build_snapshot, digest
from .identity import fingerprint

OVERLAP_TOLERANCE = 2          # lines either side when matching a scanner observation to a finding
GAP_NO_LOCATION = "finding_without_resolved_location"
GAP_UNRESOLVED_CITATION = "citation_unresolved"
GAP_NO_OBSERVATIONS = "scanner_observations_unavailable"
GAP_NO_UNITS = "reviewed_units_not_supplied"
GAP_NO_CLAIM = "finding_claim_missing_from_projection"
GAP_LOCATIONS_TRUNCATED = "finding_locations_truncated"
_REACHABILITY = "source_to_sink_reachability"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RunDocuments:
    """Everything :func:`findings_from_documents` needs, already verified by its loader."""

    report: Mapping[str, Any]                      # the current accepted final report
    projection: Mapping[str, Any]                  # the claim projection it binds
    located: Mapping[str, Mapping[str, Any]]       # finding_package_id -> {"locations", "citations"}
    observations: Sequence[tuple[str, int, int]] | None   # scanner (path, start, end); None when unavailable
    identities: Mapping[str, str | None] = field(default_factory=dict)
    gaps: tuple[str, ...] = ()


def _canonical(claim_id: str, claims: Mapping[str, Mapping[str, Any]]) -> str | None:
    seen: set[str] = set()
    while claim_id in claims and claims[claim_id].get("state") == "duplicate":
        if claim_id in seen:
            return None
        seen.add(claim_id)
        target = claims[claim_id].get("duplicate_of")
        if not isinstance(target, str):
            return None
        claim_id = target
    return claim_id if claim_id in claims else None


def _overlaps(location: Mapping[str, Any], observations: Iterable[tuple[str, int, int]]) -> bool:
    low, high = location["start_line"] - OVERLAP_TOLERANCE, location["end_line"] + OVERLAP_TOLERANCE
    return any(path == location["path"] and start <= high and end >= low for path, start, end in observations)


def findings_from_documents(documents: RunDocuments) -> tuple[list[dict[str, Any]], list[str]]:
    """Finding records of every package in the report's three buckets, and the named gaps.

    A package whose evidence resolved to no source location cannot be given an identity; it is
    counted in the gap ``finding_without_resolved_location:<n>`` and left out, never guessed.
    """
    claims = {claim["claim_id"]: claim for claim in documents.projection.get("claims", ())
              if isinstance(claim, Mapping) and isinstance(claim.get("claim_id"), str)}
    duplicates: dict[str, int] = {}
    for claim_id, claim in claims.items():
        if claim.get("state") == "duplicate":
            canonical = _canonical(claim_id, claims)
            if canonical is not None:
                duplicates[canonical] = duplicates.get(canonical, 0) + 1
    gaps = set(documents.gaps)
    if documents.observations is None:
        gaps.add(GAP_NO_OBSERVATIONS)
    records: list[dict[str, Any]] = []
    unlocated = unresolved = missing_claims = truncated = 0
    for bucket in BUCKETS:
        for row in documents.report.get(bucket, ()):
            finding_id = row["finding_package_id"]
            located = documents.located.get(finding_id, {})
            locations = list(located.get("locations", ()))
            citations = dict(located.get("citations") or {"total": None, "unresolved": None})
            unresolved += citations.get("unresolved") or 0
            if not locations:
                unlocated += 1
                continue
            if len(locations) > MAX_LOCATIONS:
                truncated += 1
                locations = sorted(locations, key=lambda item: (item["path"], item["start_line"]))[:MAX_LOCATIONS]
            claim = claims.get(row["claim_id"])
            if claim is None:
                missing_claims += 1
            block = row["ship_block"]
            judged = row.get("judge_verdict")
            lane = row.get("lane")
            if lane == "lead":
                scanner_backed: bool | None = True
            elif documents.observations is None:
                scanner_backed = None
            else:
                scanner_backed = any(_overlaps(location, documents.observations) for location in locations)
            preconditions = claim.get("preconditions") if claim else None
            records.append({
                "finding_id": finding_id, "claim_id": row["claim_id"], "lane": lane, "state": row["state"],
                "bucket": bucket, "weakness_cwe": claim.get("weakness_cwe") if claim else None,
                "security_predicate": claim.get("security_predicate") if claim else None,
                "severity": block.get("technical_severity"), "ship_block_status": block.get("status"),
                "locations": [{**location, "code": (location.get("code") or None)
                               and location["code"][:MAX_CODE_CHARS]} for location in locations],
                "scanner_backed": scanner_backed,
                "duplicates_collapsed": duplicates.get(row["claim_id"], 0),
                "actionability": {
                    "entry_to_sink_path": _REACHABILITY not in row.get("missing_predicates", ()),
                    "preconditions": True if preconditions else None,
                    "remediation": None, "remediation_validated": None},
                "citations": {"total": citations.get("total"), "unresolved": citations.get("unresolved")},
                "verification": {
                    "verifier_overturned": None if judged is None else bool(judged.get("disagrees_with_state")),
                    "distinct_model": (bool(block.get("verifier_model_distinct"))
                                       if row.get("verification_review_id") is not None else None)},
            })
    for name, count in ((GAP_NO_LOCATION, unlocated), (GAP_UNRESOLVED_CITATION, unresolved),
                        (GAP_NO_CLAIM, missing_claims), (GAP_LOCATIONS_TRUNCATED, truncated)):
        if count:
            gaps.add(f"{name}:{count}")
    return sorted(records, key=lambda item: item["finding_id"]), sorted(gaps)


# ----------------------------------------------------------------------------------- loading

def run_identities(run_root: Path) -> dict[str, str | None]:
    """The frozen configuration, guidance and model identities a run recorded about itself.

    ``configuration_sha256`` is the manifest's ``resolved_sha256`` re-checked against the file;
    ``guidance_sha256`` hashes the sorted pinned bundle identities; ``model_sha256`` hashes the
    sorted enabled ``(job, provider, model)`` triples of the resolved configuration. Anything that
    cannot be read or does not agree is ``None``.
    """
    run_root = Path(run_root)
    identities: dict[str, str | None] = {"configuration_sha256": None, "guidance_sha256": None,
                                         "model_sha256": None}
    configuration = run_root / "data" / "configuration"
    resolved: Any = None
    try:
        payload = (configuration / "resolved.json").read_bytes()
        recorded = json.loads((configuration / "manifest.json").read_text(encoding="utf-8")).get("resolved_sha256")
        if isinstance(recorded, str) and recorded == hashlib.sha256(payload).hexdigest():
            identities["configuration_sha256"] = recorded
            resolved = json.loads(payload)
    except (OSError, ValueError, AttributeError):
        resolved = None
    guidance = run_root / "data" / "guidance"
    if guidance.is_dir():
        bundles = sorted(item.name for item in guidance.iterdir() if item.is_dir() and _SHA256.match(item.name))
        if bundles:
            identities["guidance_sha256"] = digest(bundles)
    if isinstance(resolved, Mapping):
        try:
            from appsec_review.jobs.job_review_intake.job import required_models
            required, _unused = required_models(resolved)
            triples = sorted({(str(item["job_id"]), str(item["provider"]), str(item["model"])) for item in required})
            if triples:
                identities["model_sha256"] = digest([list(item) for item in triples])
        except (ImportError, KeyError, TypeError, ValueError, AttributeError):
            identities["model_sha256"] = None
    return identities


def load_run(run_root: Path, *, schema_root: Path | None = None) -> RunDocuments:
    """Read one run through its verified readers. Raises what those readers raise: an unverifiable
    current report is an integrity error for the caller to name, not an empty finding set."""
    from appsec_review.acceptance.producer_reports import GAP_NO_OBSERVATION_INDEX, reports_from_run
    from appsec_review.acceptance.system import accepted_final_report
    from appsec_review.storage.validation import validation_scope

    run_root = Path(run_root).resolve()
    with validation_scope(run_root):
        report, core, projection = accepted_final_report(run_root, schema_root)
        relations_by_claim = projection.get("relations", {})
        located: dict[str, dict[str, Any]] = {}
        for bucket in BUCKETS:
            for row in report[bucket]:
                relations = {item["relation_id"]: item for item in relations_by_claim.get(row["claim_id"], ())}
                locations, unresolved = [], 0
                for identity in row["direct_evidence"]:
                    relation = relations.get(identity)
                    if relation is None or relation.get("kind") != "supports" or not relation.get("complete"):
                        unresolved += 1
                        continue
                    rows = [item for item in core.find(identity=relation["entity_id"], limit=20)["results"]
                            if f"{item['index']}/{item['shard_id']}" == relation["shard_id"]]
                    if len(rows) != 1:
                        unresolved += 1
                        continue
                    location = rows[0].get("location")
                    if location is None:
                        continue                       # resolved, but not source-located evidence
                    excerpts = core.read_excerpt(identity=relation["entity_id"], context_lines=0)["results"]
                    if not excerpts:
                        unresolved += 1
                        continue
                    locations.append({"path": location["path"], "start_line": location["start_line"],
                                      "end_line": location["end_line"], "function": None,
                                      "code": str(excerpts[0]["excerpt"])})
                located[row["finding_package_id"]] = {
                    "locations": locations,
                    "citations": {"total": len(row["direct_evidence"]), "unresolved": unresolved}}
    reports, report_gaps = reports_from_run(run_root)
    observations = None if GAP_NO_OBSERVATION_INDEX in report_gaps else [
        (item.path, item.start_line, item.end_line) for item in reports]
    return RunDocuments(report=report, projection=projection, located=located, observations=observations,
                        identities=run_identities(run_root))


def snapshot_from_run(run_root: Path, *, target_id: str, source_revision: str,
                      reviewed_units: Mapping[str, str | None] | None = None,
                      unreviewed_units: Mapping[str, str] | None = None, stage: str = "published",
                      annotate: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
                      loader: Callable[[Path], RunDocuments] = load_run) -> dict[str, Any]:
    """The ``finding-snapshot/1`` of ``run_root``.

    ``target_id`` and ``source_revision`` are the caller's: a run names its target by path and
    fingerprint, neither of which is stable across revisions. ``annotate`` (for example
    ``slices.annotate`` bound to the operator's rules) runs on each record before fingerprinting;
    the dimensions it sets are not part of a finding's identity. ``loader`` is the read boundary.
    """
    documents = loader(Path(run_root))
    records, gaps = findings_from_documents(documents)
    if annotate is not None:
        records = [annotate(record) for record in records]
    if reviewed_units is None:
        gaps = sorted({*gaps, GAP_NO_UNITS})
    identities = documents.identities
    return build_snapshot(
        run_id=Path(run_root).name, target_id=target_id, source_revision=source_revision, findings=records,
        fingerprint=fingerprint, stage=stage, reviewed_units=reviewed_units, unreviewed_units=unreviewed_units,
        gaps=gaps, configuration_sha256=identities.get("configuration_sha256"),
        guidance_sha256=identities.get("guidance_sha256"), model_sha256=identities.get("model_sha256"))


__all__ = ["GAP_LOCATIONS_TRUNCATED", "GAP_NO_CLAIM", "GAP_NO_LOCATION", "GAP_NO_OBSERVATIONS", "GAP_NO_UNITS",
           "GAP_UNRESOLVED_CITATION", "OVERLAP_TOLERANCE", "RunDocuments", "findings_from_documents", "load_run",
           "run_identities", "snapshot_from_run"]
