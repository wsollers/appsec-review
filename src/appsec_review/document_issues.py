"""Bounded document-to-source candidates and evidence-qualified adjudication.

Declarations are navigation evidence. This module never infers a missing guard from a
missing search result, nor treats a scanner report as an independently verified issue.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.model import canonical_json
from appsec_review.review_packages import verify_review_packages
from appsec_review.storage import file_sha256


SCHEMA = "appsec-review/document-issue-ledger/1"
RULE = "appsec-review/document-source-mapping/1"
_ROUTE = re.compile(r"\b(?:app|router|server)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.I)
_NON_IMPLEMENTATION = re.compile(r"(^|/)(?:test|tests|spec|specs|docs|fixtures|__tests__)(/|$)|(?:\.test|\.spec)\.[^/]+$", re.I)
_PARAMETER = re.compile(r"(?<=/)(?::([A-Za-z_][\w]*)|\{([A-Za-z_][\w]*)\})")


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _route_key(value: str) -> str:
    return _PARAMETER.sub(lambda match: "{" + (match.group(1) or match.group(2)) + "}", value.rstrip("/") or "/")


def _source_lines(core: RetrievalCore, max_files: int, max_file_bytes: int) -> tuple[list[dict[str, Any]], list[str]]:
    view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
    source = view.select("source", job="job_target_catalog")
    if not source:
        return [], ["accepted source index is unavailable"]
    rows = sorted(view.entities(source, ("source_file",)), key=lambda row: row.identity)
    gaps = []
    if len(rows) > max_files:
        gaps.append(f"source mapping truncated: {len(rows) - max_files} accepted file(s) exceeded bound")
        rows = rows[:max_files]
    result = []
    for row in rows:
        location = row.location
        if (not location or row.payload.get("language") is None or
                _NON_IMPLEMENTATION.search(location["path"])):
            continue
        path = (core.target_root / location["path"]).resolve()
        if core.target_root not in path.parents or path.is_symlink() or not path.is_file():
            raise ValueError("accepted source path is missing or escaped")
        if file_sha256(path) != location["file_sha256"]:
            raise ValueError("accepted source bytes changed after catalog publication")
        if path.stat().st_size > max_file_bytes:
            gaps.append(f"source mapping skipped oversized file: {location['path']}")
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            gaps.append(f"source mapping skipped undecodable file: {location['path']}")
            continue
        for number, line in enumerate(lines, 1):
            match = _ROUTE.search(line)
            if match:
                result.append({"entity_id": row.identity, "shard_id": row.shard_id,
                               "shard_sha256": row.shard_sha256, "path": location["path"],
                               "file_sha256": location["file_sha256"], "line": number,
                               "method": match.group(1).upper(), "route": match.group(2)})
    return sorted(result, key=lambda item: (item["method"], item["route"], item["path"], item["line"])), gaps


def adjudicate(candidate: Mapping[str, Any], *, core: RetrievalCore | None = None,
               red: Mapping[str, Any] | None = None,
               blue: Mapping[str, Any] | None = None,
               verifier: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """A narrow deterministic gate for independently reviewed source/tool evidence.

    A caller may propose a supported security claim, but all three reviews must cite
    the same resolving accepted evidence and blue must have no unresolved refutation.
    This gate intentionally does not manufacture reviews from document text.
    """
    evidence = candidate.get("proof_evidence", [])
    ids = {f"{item['entity_id']}:{item['line']}" for item in evidence
           if item.get("resolution") == "source_line"
           and item.get("file_sha256") and item.get("line", 0) > 0}
    reviews = (red, blue, verifier)
    supported = core is not None and bool(ids) and all(isinstance(item, Mapping) for item in reviews)
    if supported:
        view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
        accepted = {row.identity: row for row in view.entities(
            view.select("source", job="job_target_catalog"), ("source_file",))}
        for item in evidence:
            row = accepted.get(item["entity_id"])
            if row is None or row.location is None or row.shard_sha256 != item["shard_sha256"] or (
                row.location["path"], row.location["file_sha256"]
            ) != (item["path"], item["file_sha256"]):
                raise ValueError("candidate source evidence does not resolve to accepted source")
            path = (core.target_root / item["path"]).resolve()
            if (core.target_root not in path.parents or path.is_symlink() or
                    file_sha256(path) != item["file_sha256"]):
                raise ValueError("candidate source evidence bytes changed")
            lines = path.read_text(encoding="utf-8").splitlines()
            if not 1 <= item["line"] <= len(lines):
                raise ValueError("candidate source line is outside accepted bytes")
            if not lines[item["line"] - 1].strip():
                raise ValueError("candidate proof cites an empty source line")
        supported = (red.get("decision") == "supported" and blue.get("decision") == "not_refuted"
                     and verifier.get("decision") == "independently_supported"
                     and all(set(item.get("evidence_refs", ())) & ids for item in reviews)
                     and not blue.get("unresolved_refutations")
                     and candidate.get("mapping_status") == "unique"
                     and all(any(item["entity_id"] == route_item["entity_id"] and
                                      route_item["line"] < item["line"] <= route_item["line"] + 100
                                      for route_item in candidate.get("implementation_evidence", ()))
                             for item in evidence)
                     and bool(red.get("security_claim")) and bool(verifier.get("security_claim"))
                     and red["security_claim"] == verifier["security_claim"])
    return {"state": "supported" if supported else "insufficient_evidence",
            "finding": ({"candidate_id": candidate["candidate_id"],
                         "claim": red["security_claim"], "route_or_boundary": candidate["subject"],
                         "evidence": [*candidate["implementation_evidence"], *evidence],
                         "coverage_gaps": candidate["coverage_gaps"],
                         "score_input": {"state": "supported", "claim": red["security_claim"],
                                         "evidence_refs": sorted(ids)}} if supported else None)}


def analyze_document_hunts(core: RetrievalCore, package_directory: Path, *, max_files: int = 20000,
                           max_file_bytes: int = 1048576) -> dict[str, Any]:
    manifest = verify_review_packages(core, package_directory)
    source_routes, source_gaps = _source_lines(core, max_files, max_file_bytes)
    candidates = []
    for entry in manifest["packages"]:
        if entry["kind"] != "document_hunt":
            continue
        path = package_directory / f"{entry['package_id']}.json"
        package = json.loads(path.read_text(encoding="utf-8"))
        subject = package["scope"]["partition_key"]
        matches = []
        if subject.startswith("route:"):
            method, _, route = subject.removeprefix("route:").partition(" ")
            matches = [item for item in source_routes if item["method"] == method and
                       _route_key(item["route"]) == _route_key(route)]
        status = "unique" if len(matches) == 1 else "ambiguous" if matches else "unmapped"
        gaps = list(package["coverage_gaps"])
        gaps.extend({"gap_id": _hash([RULE, reason]), "producer": RULE,
                     "scope": "source-inventory", "state": "partial", "reason": reason}
                    for reason in source_gaps)
        # The package's pre-mapping gap is superseded only by a unique, verified link.
        if status == "unique":
            gaps = [gap for gap in gaps if not (gap["producer"] == "document_context" and
                     "has not been mapped" in gap["reason"])]
        else:
            gaps.append({"gap_id": _hash([subject, status]), "producer": RULE,
                         "scope": subject, "state": "partial",
                         "reason": f"implementation mapping {status}; no behavior conclusion"})
        evidence = [{"entity_id": item["entity_id"], "shard_id": item["shard_id"],
                     "shard_sha256": item["shard_sha256"], "path": item["path"],
                     "file_sha256": item["file_sha256"], "line": item["line"],
                     "resolution": "source_line"} for item in matches]
        candidate = {"candidate_id": _hash([package["package_id"], matches, RULE]),
                     "package_id": package["package_id"], "subject": subject,
                     "mapping_status": status, "implementation_evidence": evidence,
                     "proof_evidence": [],
                     "document_evidence": package["evidence"],
                     "proof_obligations": package["proof_obligations"],
                     "coverage_gaps": sorted(gaps, key=lambda item: item["gap_id"]),
                     "hypothesis": "verify declared route or boundary behavior in implementation"}
        decision = adjudicate(candidate, core=core)
        candidate["state"] = decision["state"]
        candidates.append(candidate)
    ledger = {"schema": SCHEMA, "rule": RULE, "run_id": core.run_id,
              "accepted_manifest_sha256": core.manifest_sha256,
              "review_package_manifest_sha256": file_sha256(package_directory / "manifest.json"),
              "target_snapshot": core.manifest["target_snapshot"], "candidates": candidates,
              "findings": [], "scoring_inputs": [],
              "counts": {"candidates": len(candidates), "supported": 0,
                         "unmapped": sum(item["mapping_status"] == "unmapped" for item in candidates),
                         "ambiguous": sum(item["mapping_status"] == "ambiguous" for item in candidates)}}
    ledger["content_sha256"] = _hash(ledger)
    return ledger


def verify_document_issue_ledger(core: RetrievalCore, path: Path) -> dict[str, Any]:
    path = Path(path).resolve()
    if path.parent.parent != (core.run_root / "data" / "document-issues").resolve():
        raise ValueError("document issue ledger escapes its run")
    ledger = json.loads(path.read_text(encoding="utf-8"))
    if path.read_bytes() != canonical_json(ledger) + b"\n":
        raise ValueError("document issue ledger byte integrity mismatch")
    digest = ledger.pop("content_sha256", None)
    if (digest != _hash(ledger) or path.parent.name != digest or
            ledger.get("run_id") != core.run_id or
            ledger.get("accepted_manifest_sha256") != core.manifest_sha256 or
            ledger.get("target_snapshot") != core.manifest["target_snapshot"]):
        raise ValueError("document issue ledger identity mismatch")
    ledger["content_sha256"] = digest
    if ledger["counts"]["candidates"] != len(ledger["candidates"]):
        raise ValueError("document issue ledger count mismatch")
    if ledger["findings"] or ledger["scoring_inputs"] or ledger["counts"]["supported"]:
        raise ValueError("unreviewed document issues cannot be published as findings")
    return ledger
