#!/usr/bin/env python3
"""04-owasp-universe: the deterministic OWASP validation universe and its validator budget (ADR-0034).

Python, not a model, decides what the OWASP validators look at. This job merges the accepted
``04-owasp-candidate-search`` (per-chapter function/symbol candidates) with the accepted
``04-owasp-participation`` (validated classification records) into one target ``asvs-V<n>`` per ASVS
5.0.0 chapter with a decision and its reason:

* ``participating``: at least one validated implements/enforces/consumes record. Participants are
  merged per symbol and rolled up to files; a symbol or file may take part in several chapters. The
  chapter's ``asvs-participants-V<n>`` bundle holds hash-bound source excerpts of its participants.
* ``not_applicable``: zero candidates under complete coverage, or every candidate classified
  ``not_participating`` with resolved citations. Nothing else is N/A.
* ``gap``: incomplete coverage, unclassified candidates or participation unavailable (AGENTS.md rule 2).

Budget: planned validator calls = sum over participating chapters of ceil(L1+L2 control rows /
``max_control_target_rows`` of the named batch config), checked against ``max_validator_calls`` before
any call. Over budget the universe is written ``BLOCKED`` for diagnosis, never accepted, and the
validator dispatch refuses to start. MASVS for a target without a mobile platform is a
``not_applicable`` family with its reason.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import sys
import uuid
from typing import Any

from execution_state import (
    ROOT, Blocked, Lock, atomic_bytes, atomic_json, beneath, data_path, digest, emergency, event,
    file_hash, identifier, now, read_json, run_path,
)
from publish_job_output import common_pointer, validate_published
import reference_snapshots
from schema_validate import validate_document

JOB = "04-owasp-universe"
CANDIDATE_JOB = "04-owasp-candidate-search"
PARTICIPATION_JOB = "04-owasp-participation"
CANDIDATE_ARTIFACT = "owasp-candidate-search.json"
PARTICIPATION_ARTIFACT = "owasp-participation.json"
UNIVERSE = "outputs/owasp-universe.json"
UNIVERSE_INPUT = "asvs-universe"
UNIVERSE_KIND = "asvs_universe"
BUNDLE_KIND = "source_excerpt_bundle"
REPO_ROOT = ROOT.parent
DEFAULT_REFERENCE_ROOT = REPO_ROOT / "data" / "reference"
RULES = REPO_ROOT / "data" / "owasp-asvs" / "category-rules-v1.json"
CONFIG = "appsec-review-process/config/owasp-universe/default-v1.json"
CHAPTERS = tuple(f"V{n}" for n in range(1, 18))
POSITIVE = ("implements", "enforces", "consumes")
FORMULA = "sum(ceil(l1_l2_control_rows / max_control_target_rows)) over participating chapters"
SUCCESS = {"OK", "OK_WITH_GAPS"}
# Deterministic mobile-platform markers (ADR-0034 follow-up 2 replaces this with a full detector).
MOBILE_FILES = frozenset({"AndroidManifest.xml", "Info.plist", "Podfile", "Package.swift"})
MOBILE_SUFFIXES = (".xcodeproj", ".xcworkspace", ".apk", ".ipa", ".aab")
MOBILE_WALK_LIMIT = 200000


def bundle_id(chapter: str) -> str:
    return f"asvs-participants-{chapter}"


def bundle_path(chapter: str) -> str:
    return f"outputs/{bundle_id(chapter)}.json"


def _hex(value: str) -> str:
    return value.removeprefix("sha256:")


def asvs_snapshot_root(reference_root: Path | None = None) -> Path:
    edition = Path(reference_root or DEFAULT_REFERENCE_ROOT) / "owasp" / "owasp_asvs" / "5.0.0"
    snapshots = sorted(path for path in edition.iterdir() if path.is_dir()) if edition.is_dir() else []
    if len(snapshots) != 1:
        raise Blocked("04-owasp-universe: exactly one pinned ASVS 5.0.0 reference snapshot is required")
    return snapshots[0]


def asvs_reference(reference_root: Path | None = None) -> dict[str, str]:
    root = asvs_snapshot_root(reference_root)
    return {"family": "owasp_asvs", "edition": "5.0.0", "snapshot_id": root.name,
            "manifest_sha256": file_hash(root / "manifest.json")}


def chapter_control_rows(reference_root: Path | None = None) -> dict[str, int]:
    """L1+L2 control rows per ASVS 5.0.0 chapter of the verified pinned snapshot."""
    root = asvs_snapshot_root(reference_root)
    reference_snapshots.verify_snapshot(root)
    counts = {chapter: 0 for chapter in CHAPTERS}
    for record in read_json(root / "normalized" / "catalog.json")["records"]:
        if record.get("record_type") == "control" and {"L1", "L2"} & set(record.get("profiles", [])):
            chapter = record["group"]["chapter_id"]
            if chapter not in counts:
                raise Blocked(f"04-owasp-universe: ASVS control {record['control_id']} names unknown chapter {chapter}")
            counts[chapter] += 1
    if not all(counts.values()):
        raise Blocked("04-owasp-universe: an ASVS chapter has no L1/L2 control in the pinned snapshot")
    return counts


def _chapter_names() -> dict[str, str]:
    return {row["chapter_id"]: row["chapter_name"] for row in read_json(RULES)["chapters"]}


def _gap(kind: str, chapters: list[str], statement: str) -> dict[str, Any]:
    return {"gap_id": "gap-" + digest({"kind": kind, "chapters": chapters})[:20], "kind": kind,
            "chapter_ids": chapters, "statement": statement[:1000]}


def _citations(values) -> list[dict[str, Any]]:
    unique = {(row["file"], row["line"]): row for row in values}
    return [{"file": row["file"], "line": row["line"], "file_sha256": row["file_sha256"]}
            for _key, row in sorted(unique.items())]


def _source_file(source_root: Path, relative: str, expected_sha256: str) -> list[str]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise Blocked(f"04-owasp-universe: participant path is not a snapshot-relative path: {relative!r}")
    path = Path(source_root).joinpath(*pure.parts)
    cursor = Path(source_root)
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise Blocked(f"04-owasp-universe: participant path crosses a symlink: {relative}")
    if not path.is_file():
        raise Blocked(f"04-owasp-universe: participant file is missing from the snapshot: {relative}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != _hex(expected_sha256):
        raise Blocked(f"04-owasp-universe: participant file changed since candidate search: {relative}")
    return data.decode("utf-8", errors="replace").splitlines()


def excerpt_text(lines: list[str], start: int, end: int) -> str:
    return "\n".join(lines[start - 1:end])


def verify_bundle(bundle: dict[str, Any], source_root: Path) -> None:
    """Re-read the snapshot: every excerpt is the exact text of its file lines and hash-bound."""
    cache: dict[tuple[str, str], list[str]] = {}
    for row in bundle["excerpts"]:
        key = (row["file"], row["file_sha256"])
        if key not in cache:
            cache[key] = _source_file(source_root, row["file"], row["file_sha256"])
        text = excerpt_text(cache[key], row["start_line"], row["end_line"])
        if text != row["text"] or hashlib.sha256(text.encode("utf-8")).hexdigest() != row["text_sha256"]:
            raise Blocked(f"{bundle_id(bundle.get('chapter_id', 'V?'))}: excerpt {row['file']}:{row['start_line']} "
                          "does not match the source snapshot")


def _bundle(participants: list[dict[str, Any]], source_root: Path, limits: dict[str, int]) -> dict[str, Any]:
    excerpts, truncated, size, cache = [], [], 0, {}
    for row in participants:
        key = (row["file"], row["file_sha256"])
        if key not in cache:
            cache[key] = _source_file(source_root, row["file"], row["file_sha256"])
        end = row["end_line"]
        if end - row["start_line"] + 1 > limits["max_excerpt_lines"]:
            end = row["start_line"] + limits["max_excerpt_lines"] - 1
            truncated.append({"symbol": row["symbol"], "file": row["file"], "reason": "max_excerpt_lines"})
        text = excerpt_text(cache[key], row["start_line"], end)
        encoded = text.encode("utf-8")
        if excerpts and size + len(encoded) > limits["max_bundle_bytes"]:
            truncated.append({"symbol": row["symbol"], "file": row["file"], "reason": "max_bundle_bytes"})
            continue
        size += len(encoded)
        excerpts.append({"symbol": row["symbol"], "file": row["file"], "file_sha256": row["file_sha256"],
                         "start_line": row["start_line"], "end_line": end, "roles": row["roles"],
                         "text": text, "text_sha256": hashlib.sha256(encoded).hexdigest()})
    return {"excerpts": excerpts, "truncated": truncated}


def _participants(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple, dict[str, Any]] = {}
    for record in records:
        key = (record["file"], record["start_line"], record["end_line"], record["symbol"])
        row = merged.setdefault(key, {"symbol": record["symbol"], "file": record["file"],
                                      "file_sha256": record["file_sha256"], "start_line": record["start_line"],
                                      "end_line": record["end_line"], "roles": set(), "candidate_ids": set(),
                                      "citations": []})
        if _hex(row["file_sha256"]) != _hex(record["file_sha256"]):
            raise ValueError(f"04-owasp-universe: {record['file']} is cited at two different file hashes")
        row["roles"].add(record["role"])
        if record["candidate_id"]:
            row["candidate_ids"].add(record["candidate_id"])
        row["citations"].extend(record["citations"])
    return [{**row, "roles": [role for role in POSITIVE if role in row["roles"]],
             "candidate_ids": sorted(row["candidate_ids"]), "citations": _citations(row["citations"])}
            for _key, row in sorted(merged.items())]


def _files(participants: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rolled: dict[str, dict[str, Any]] = {}
    for row in participants:
        entry = rolled.setdefault(row["file"], {"path": row["file"], "sha256": row["file_sha256"], "participant_count": 0})
        entry["participant_count"] += 1
    return [rolled[path] for path in sorted(rolled)]


def _decide(chapter: str, chapter_row: dict[str, Any], candidates: list[dict[str, Any]],
            records: list[dict[str, Any]], unclassified: list[dict[str, Any]],
            participation_available: bool) -> tuple[str, str, str]:
    positive = [row for row in records if row["role"] in POSITIVE]
    if positive:
        return ("participating", "participating_code_cited",
                f"{len(positive)} validated record(s) cite code that implements, enforces or consumes {chapter} controls.")
    if candidates and not participation_available:
        return ("gap", "participation_unavailable",
                f"{len(candidates)} candidate(s) were found but no accepted participation classification exists.")
    if unclassified:
        return ("gap", "unclassified_candidates",
                f"{len(unclassified)} candidate(s) have no single validated classification record.")
    if not chapter_row["coverage_complete"]:
        return ("gap", "coverage_incomplete",
                "Candidate search coverage is incomplete for this chapter (unsearched language or unindexed source); "
                "absence of candidates is not evidence of absence.")
    if not candidates:
        return ("not_applicable", "no_candidates_complete_coverage",
                "No rule of the chapter matched any non-excluded code under complete search coverage.")
    by_candidate: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["candidate_id"]:
            by_candidate[record["candidate_id"]].append(record)
    complete = all(len(by_candidate.get(row["candidate_id"], [])) == 1 and
                   by_candidate[row["candidate_id"]][0]["role"] == "not_participating" and
                   by_candidate[row["candidate_id"]][0]["citations"] for row in candidates)
    if complete:
        return ("not_applicable", "all_candidates_not_participating",
                f"Every one of {len(candidates)} candidate(s) is classified not_participating with resolved citations.")
    return ("gap", "unclassified_candidates", "Some candidates have no single validated classification record.")


def build(candidate_search: dict[str, Any], participation: dict[str, Any] | None, *,
          control_rows: dict[str, int], config: dict[str, Any], batch_config: dict[str, Any],
          batch_config_path: str, source_root: Path, mobile_platform: bool = False
          ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Merge candidates and validated participation into the per-chapter universe.

    Returns ``(universe, bundles)``: the universe members ``status, families, targets, excluded,
    budget, gaps`` and ``{chapter_id: {"excerpts", "truncated"}}`` for participating chapters only.
    Each participating target's ``evidence_bundle.sha256`` is the content digest of its bundle; the
    publishing job replaces it with the hash of the written ``outputs/asvs-participants-V<n>.json``.
    """
    if [row["chapter_id"] for row in candidate_search["chapters"]] != list(CHAPTERS):
        raise ValueError("04-owasp-universe: candidate search must list exactly the chapters V1..V17 in order")
    if set(control_rows) != set(CHAPTERS) or any(int(value) < 1 for value in control_rows.values()):
        raise ValueError("04-owasp-universe: control rows must give every chapter at least one L1/L2 control")
    max_rows = batch_config["limits"]["max_control_target_rows"]
    max_calls = config["validation"]["max_validator_calls"]
    names = _chapter_names()
    candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    candidate_ids = {}
    for row in candidate_search["candidates"]:
        candidates[row["chapter_id"]].append(row)
        candidate_ids[row["candidate_id"]] = row["chapter_id"]
    records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unclassified: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if participation is not None:
        for record in participation["records"]:
            if record["candidate_id"] is not None and candidate_ids.get(record["candidate_id"]) != record["chapter_id"]:
                raise ValueError(f"04-owasp-universe: participation record names unknown candidate {record['candidate_id']}")
            records[record["chapter_id"]].append(record)
        for row in participation["unclassified"]:
            unclassified[row["chapter_id"]].append(row)

    targets, excluded, bundles, per_chapter, gaps = [], [], {}, [], []
    gap_chapters: dict[str, list[str]] = defaultdict(list)
    truncated_chapters = []
    for chapter_row in candidate_search["chapters"]:
        chapter = chapter_row["chapter_id"]
        decision, reason_code, reason = _decide(chapter, chapter_row, candidates[chapter], records[chapter],
                                                unclassified[chapter], participation is not None)
        participants, files, bundle_ref, planned = [], [], None, 0
        for record in records[chapter]:
            if record["role"] == "not_participating" and record["candidate_id"]:
                excluded.append({"chapter_id": chapter, "candidate_id": record["candidate_id"],
                                 "symbol": record["symbol"], "file": record["file"], "reason": "not_participating",
                                 "citations": _citations(record["citations"])})
        if decision == "participating":
            participants = _participants([row for row in records[chapter] if row["role"] in POSITIVE])
            files = _files(participants)
            bundle = _bundle(participants, source_root, config["evidence_bundle"])
            bundles[chapter] = bundle
            if bundle["truncated"]:
                truncated_chapters.append(chapter)
            bundle_ref = {"input_id": bundle_id(chapter), "path": bundle_path(chapter), "sha256": digest(bundle),
                          "excerpt_count": len(bundle["excerpts"])}
            planned = math.ceil(control_rows[chapter] / max_rows)
            per_chapter.append({"chapter_id": chapter, "control_rows": control_rows[chapter], "planned_calls": planned})
            if not chapter_row["coverage_complete"]:
                gap_chapters["coverage_incomplete"].append(chapter)
            if unclassified[chapter]:
                gap_chapters["unclassified_candidates"].append(chapter)
        elif decision == "gap":
            gap_chapters[reason_code].append(chapter)
        targets.append({"target_id": f"asvs-{chapter}", "chapter_id": chapter, "chapter_name": names[chapter],
                        "decision": decision, "reason_code": reason_code, "reason": reason,
                        "control_rows": control_rows[chapter], "candidate_count": len(candidates[chapter]),
                        "participants": participants, "files": files, "evidence_bundle": bundle_ref,
                        "planned_validator_calls": planned})

    statements = {
        "coverage_incomplete": "Candidate search coverage is incomplete (an unsearched language, an unparsed file or a "
                               "truncated index); these chapters are gaps, never not_applicable.",
        "unclassified_candidates": "Candidates without exactly one validated participation record remain unclassified.",
        "participation_unavailable": "No accepted participation classification exists for chapters with candidates.",
    }
    for kind in ("coverage_incomplete", "unclassified_candidates", "participation_unavailable"):
        if gap_chapters[kind]:
            gaps.append(_gap(kind, gap_chapters[kind], statements[kind]))
    if truncated_chapters:
        gaps.append(_gap("bundle_truncated", truncated_chapters,
                         "Participant excerpts were cut at max_excerpt_lines or dropped at max_bundle_bytes."))
    planned_total = sum(row["planned_calls"] for row in per_chapter)
    within = planned_total <= max_calls
    if not within:
        gaps.append(_gap("budget_exceeded", [row["chapter_id"] for row in per_chapter],
                         f"Planned validator calls {planned_total} exceed max_validator_calls {max_calls}; "
                         "no validator call may start (raise the limit only through a reviewed config version)."))
    if mobile_platform:
        masvs = {"family": "owasp_masvs", "decision": "gap", "reason_code": "mobile_platform_present",
                 "reason": "A mobile platform marker is present but no MASVS category rules exist yet "
                           "(ADR-0034 follow-up 2); MASVS coverage is a gap."}
    else:
        masvs = {"family": "owasp_masvs", "decision": "not_applicable", "reason_code": "no_mobile_platform",
                 "reason": "The source snapshot has no Android or iOS platform marker; MASVS applies only to mobile targets."}
    universe = {
        "status": "BLOCKED" if not within else ("OK_WITH_GAPS" if gaps else "OK"),
        "families": [{"family": "owasp_asvs", "decision": "in_scope", "reason_code": "chapter_universe",
                      "reason": "One target per ASVS 5.0.0 chapter, decided from deterministic candidates and "
                                "validated participation."}, masvs],
        "targets": targets,
        "excluded": sorted(excluded, key=lambda row: (row["chapter_id"], row["file"], row["candidate_id"])),
        "budget": {"formula": FORMULA, "max_validator_calls": max_calls, "max_control_target_rows": max_rows,
                   "batch_config": {"path": batch_config_path, "config_id": batch_config["config_id"],
                                    "version": batch_config["version"], "config_digest": digest(batch_config)},
                   "per_chapter": per_chapter, "planned_validator_calls": planned_total, "within_budget": within},
        "gaps": gaps,
    }
    return universe, bundles


# ---- the publishing job ---------------------------------------------------------------------------

def _base(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB, "whole")


def source_root(run_id: str) -> Path:
    """The run's target checkout (``inputs/artifact-manifest.json`` ``target.repo_path``)."""
    manifest_path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required to read the source snapshot")
    value = (read_json(manifest_path).get("target") or {}).get("repo_path")
    path = Path(value) if isinstance(value, str) and value else None
    if path is None or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    return path.resolve()


def mobile_platform(root: Path) -> bool:
    """A deterministic Android/iOS marker scan of the checkout (bounded; an unbounded tree is a Blocked)."""
    seen = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        seen += len(dirs) + len(names)
        if seen > MOBILE_WALK_LIMIT:
            raise Blocked(f"{JOB}: mobile-platform scan exceeded {MOBILE_WALK_LIMIT} entries")
        if MOBILE_FILES & set(names) or any(name.endswith(MOBILE_SUFFIXES) for name in (*dirs, *names)):
            return True
    return False


def _accepted_input(run_id: str, job: str, artifact: str, schema: str, *, required: bool):
    """The newest accepted publication of ``job`` and its one ``artifact`` (common or whole-scope pointer)."""
    for base in (data_path(run_id, "jobs", job), data_path(run_id, "jobs", job, "whole")):
        pointer_path = base / "accepted.json"
        if pointer_path.is_file() and not pointer_path.is_symlink():
            break
    else:
        if required:
            raise Blocked(f"{JOB}: accepted {job} is required")
        return None, None
    pointer = read_json(pointer_path)
    if common_pointer(pointer):
        attempt, envelope = validate_published(base, pointer, pointer.get("fingerprint"), expected_run_id=run_id,
                                               expected_job_id=job)
        status = envelope.get("execution_status")
        published = {row.get("path"): row.get("sha256") for row in envelope.get("artifacts", [])}
    else:
        attempt_id = identifier(pointer.get("attempt_id"))
        if pointer.get("run_id") != run_id or pointer.get("job_id") != job:
            raise Blocked(f"{JOB}: {job} accepted pointer identity mismatch")
        if read_json(base / "latest.json").get("attempt_id") != attempt_id:
            raise Blocked(f"{JOB}: {job} accepted pointer is not the newest attempt")
        attempt, status, published = base / "attempts" / attempt_id, pointer.get("status"), pointer.get("artifacts", {})
    if status == "SKIPPED" and not required:
        return None, None
    if status not in SUCCESS:
        raise Blocked(f"{JOB}: {job} is not an accepted successful publication")
    matches = [path for path in published if PurePosixPath(path).name == artifact]
    if len(matches) != 1:
        raise Blocked(f"{JOB}: {job} does not publish exactly one {artifact}")
    path = beneath(attempt, attempt.joinpath(*PurePosixPath(matches[0]).parts))
    if not path.is_file() or path.is_symlink() or file_hash(path) != _hex(published[matches[0]]):
        raise Blocked(f"{JOB}: {job} {artifact} is missing or no longer hash-bound")
    value = read_json(path)
    errors = validate_document(value, schema)
    if errors or value.get("run_id") != run_id:
        raise Blocked(f"{JOB}: {job} {artifact} no longer validates: " + (errors[0] if errors else "run mismatch"))
    data_root = data_path(run_id)
    return value, {"job_id": job, "attempt_id": attempt.name, "accepted_pointer_sha256": file_hash(pointer_path),
                   "artifact_path": path.relative_to(data_root).as_posix(), "artifact_sha256": file_hash(path)}


def _config() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    import owasp_batching
    config = read_json(owasp_batching.tracked_file(PurePosixPath(CONFIG)))
    errors = validate_document(config, "owasp-universe-config.schema.json")
    if errors:
        raise Blocked(f"{JOB}: universe config no longer validates: " + errors[0])
    batch_path = owasp_batching.tracked_file(PurePosixPath(config["batch_config_path"]))
    batch, batch_digest = owasp_batching._load_batch_config(
        {"path": config["batch_config_path"], "config_digest": digest(read_json(batch_path))})
    reference = {"path": CONFIG, "config_id": config["config_id"], "version": config["version"],
                 "config_digest": digest(config)}
    return config, batch, reference


def derive(run_id: str, *, reference_root: Path | None = None) -> dict[str, Any]:
    """Every input of the universe, bound by hash; no model and no write."""
    search, search_binding = _accepted_input(run_id, CANDIDATE_JOB, CANDIDATE_ARTIFACT,
                                             "owasp-candidate-search.schema.json", required=True)
    participation, participation_binding = _accepted_input(
        run_id, PARTICIPATION_JOB, PARTICIPATION_ARTIFACT, "owasp-participation.schema.json", required=False)
    if participation is not None:
        bound = participation["candidate_search"]
        if (bound["attempt_id"] != search_binding["attempt_id"] or
                bound["artifact_sha256"] != search_binding["artifact_sha256"]):
            raise Blocked(f"{JOB}: participation classifies a different candidate-search publication")
        if participation["source_snapshot_sha256"] != search["source_snapshot_sha256"]:
            raise Blocked(f"{JOB}: candidate search and participation have mixed source snapshots")
    config, batch, config_ref = _config()
    root = source_root(run_id)
    return {"candidate_search": search, "candidate_search_binding": search_binding,
            "participation": participation, "participation_binding": participation_binding,
            "config": config, "config_ref": config_ref, "batch_config": batch,
            "control_rows": chapter_control_rows(reference_root), "asvs_reference": asvs_reference(reference_root),
            "source_root": str(root), "mobile_platform": mobile_platform(root)}


def _document(run_id: str, inputs: dict[str, Any], universe: dict[str, Any]) -> dict[str, Any]:
    return {"schema": "appsec-review/owasp-universe/1.0", "run_id": run_id, "job_id": JOB,
            "source_snapshot_sha256": inputs["candidate_search"]["source_snapshot_sha256"],
            "inputs": {"candidate_search": inputs["candidate_search_binding"],
                       "participation": inputs["participation_binding"],
                       "asvs_reference": inputs["asvs_reference"]},
            "config": inputs["config_ref"], **universe}


def _fingerprint(inputs: dict[str, Any]) -> str:
    return digest({key: inputs[key] for key in ("candidate_search_binding", "participation_binding", "config_ref",
                                                "asvs_reference", "mobile_platform", "control_rows")}
                  | {"batch_config": digest(inputs["batch_config"])})


def _members(path: Path) -> dict[str, Any]:
    document = read_json(path)
    return {key: document[key] for key in ("status", "families", "targets", "excluded", "budget", "gaps")}


def accepted(run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """The accepted, within-budget universe and its binding; anything else is ``Blocked``."""
    run_id = identifier(run_id)
    base = _base(run_id)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked("OWASP validation requires an accepted 04-owasp-universe")
    pointer = read_json(pointer_path)
    if pointer.get("status") not in SUCCESS or pointer.get("run_id") != run_id or pointer.get("job_id") != JOB:
        raise Blocked(f"04-owasp-universe is not accepted (status {pointer.get('status')!r}); no validator call may start")
    attempt_id = identifier(pointer["attempt_id"])
    if read_json(base / "latest.json").get("attempt_id") != attempt_id:
        raise Blocked("04-owasp-universe accepted pointer is not the newest attempt")
    attempt = base / "attempts" / attempt_id
    artifacts = pointer.get("artifacts") or {}
    for relative, expected in artifacts.items():
        path = beneath(attempt, attempt.joinpath(*PurePosixPath(relative).parts))
        if not path.is_file() or path.is_symlink() or file_hash(path) != expected:
            raise Blocked(f"04-owasp-universe accepted artifact is missing or corrupt: {relative}")
    if UNIVERSE not in artifacts:
        raise Blocked("04-owasp-universe accepted pointer does not publish the universe")
    universe = read_json(attempt / UNIVERSE)
    errors = validate_document(universe, "owasp-universe.schema.json")
    if errors or universe["run_id"] != run_id:
        raise Blocked("04-owasp-universe accepted universe no longer validates")
    budget = universe["budget"]
    planned = sum(row["planned_validator_calls"] for row in universe["targets"])
    if (universe["status"] not in SUCCESS or not budget["within_budget"] or planned != budget["planned_validator_calls"]
            or planned > budget["max_validator_calls"]):
        raise Blocked("04-owasp-universe is not within its validator budget; no validator call may start")
    for target in universe["targets"]:
        bundle = target["evidence_bundle"]
        if bundle is not None and artifacts.get(bundle["path"]) != bundle["sha256"]:
            raise Blocked(f"04-owasp-universe evidence bundle of {target['chapter_id']} is not hash-bound")
    data_root = data_path(run_id)
    return universe, {"job_id": JOB, "attempt_id": attempt_id,
                      "accepted_pointer_path": pointer_path.relative_to(data_root).as_posix(),
                      "accepted_pointer_sha256": file_hash(pointer_path),
                      "artifact_path": (attempt / UNIVERSE).relative_to(data_root).as_posix(),
                      "artifact_sha256": artifacts[UNIVERSE],
                      "source_snapshot_sha256": universe["source_snapshot_sha256"],
                      "planned_validator_calls": budget["planned_validator_calls"]}


def _reusable(base: Path, fingerprint: str) -> dict[str, Any] | None:
    if not (base / "accepted.json").is_file() or not (base / "latest.json").is_file():
        return None
    pointer = read_json(base / "accepted.json")
    if pointer.get("status") not in SUCCESS or pointer.get("input_fingerprint") != fingerprint:
        return None
    attempt_id = identifier(pointer["attempt_id"])
    if read_json(base / "latest.json").get("attempt_id") != attempt_id:
        raise Blocked("04-owasp-universe accepted/latest attempt mismatch")
    attempt = beneath(base, base / "attempts" / attempt_id)
    for relative, expected in pointer.get("artifacts", {}).items():
        path = beneath(attempt, attempt.joinpath(*PurePosixPath(relative).parts))
        if not path.is_file() or file_hash(path) != expected:
            raise Blocked("04-owasp-universe accepted artifact is missing or corrupt")
    return pointer


def run(run_id: str, dagster_run_id: str = "standalone-owasp-universe", *, reference_root: Path | None = None,
        force: bool = False) -> dict[str, Any]:
    """Derive, build and publish the universe. Over budget it is written BLOCKED and ``Blocked`` is raised."""
    run_id = identifier(run_id)
    if not (run_path(run_id) / "run-status.json").is_file():
        raise Blocked("create the run through run_process.py --start first")
    inputs = derive(run_id, reference_root=reference_root)
    fingerprint = _fingerprint(inputs)
    base = _base(run_id)
    with Lock(base / "job.lock"):
        if not force and (reused := _reusable(base, fingerprint)):
            return {**reused, "reused": True}
        universe, bundles = build(
            inputs["candidate_search"], inputs["participation"], control_rows=inputs["control_rows"],
            config=inputs["config"], batch_config=inputs["batch_config"],
            batch_config_path=inputs["config"]["batch_config_path"], source_root=Path(inputs["source_root"]),
            mobile_platform=inputs["mobile_platform"])
        attempt_id = uuid.uuid4().hex
        attempt = beneath(base, base / "attempts" / attempt_id)
        attempt.mkdir(parents=True, exist_ok=False)
        started = {"status": "RUNNING", "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
                   "dagster_run_id": dagster_run_id, "input_fingerprint": fingerprint, "started_at": now()}
        atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})
        atomic_json(base / "accepted.json", {"status": "PENDING", "attempt_id": attempt_id, "input_fingerprint": fingerprint})
        try:
            atomic_json(attempt / "status.json", started)
            atomic_bytes(attempt / "logs" / "stdout.log", b"")
            atomic_bytes(attempt / "logs" / "stderr.log", b"")
            event(attempt / "logs" / "events.jsonl", "START", run_id=run_id, job_id=JOB, attempt_id=attempt_id,
                  input_fingerprint=fingerprint)
            snapshot = inputs["candidate_search"]["source_snapshot_sha256"]
            artifacts = {}
            for chapter, bundle in bundles.items():
                document = {"schema": "appsec-review/owasp-participants-bundle/1.0", "run_id": run_id,
                            "input_id": bundle_id(chapter), "chapter_id": chapter,
                            "source_snapshot_sha256": snapshot, **bundle}
                errors = validate_document(document, "owasp-participants-bundle.schema.json")
                if errors:
                    raise ValueError(f"generated {bundle_id(chapter)} is invalid: " + errors[0])
                path = attempt / bundle_path(chapter)
                atomic_json(path, document)
                artifacts[bundle_path(chapter)] = file_hash(path)
                target = next(row for row in universe["targets"] if row["chapter_id"] == chapter)
                target["evidence_bundle"]["sha256"] = artifacts[bundle_path(chapter)]
            document = _document(run_id, inputs, universe)
            errors = validate_document(document, "owasp-universe.schema.json")
            if errors:
                raise ValueError("generated owasp-universe is invalid: " + errors[0])
            atomic_json(attempt / UNIVERSE, document)
            artifacts[UNIVERSE] = file_hash(attempt / UNIVERSE)
            if _fingerprint(derive(run_id, reference_root=reference_root)) != fingerprint:
                raise Blocked("04-owasp-universe inputs changed during construction")
            status = universe["status"]
            atomic_json(attempt / "status.json", {**started, "status": status, "ended_at": now(), "artifacts": artifacts})
            event(attempt / "logs" / "events.jsonl", "END", status=status, run_id=run_id, job_id=JOB, attempt_id=attempt_id)
            pointer = {"status": status, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
                       "input_fingerprint": fingerprint, "artifacts": artifacts, "accepted_at": now(),
                       "planned_validator_calls": universe["budget"]["planned_validator_calls"],
                       "max_validator_calls": universe["budget"]["max_validator_calls"]}
            atomic_json(base / "accepted.json", pointer)
        except BaseException as exc:
            atomic_json(attempt / "status.json", {**started, "status": "FAILED", "ended_at": now(),
                                                   "error_type": type(exc).__name__, "error": str(exc)})
            try:
                event(attempt / "logs" / "events.jsonl", "FAILURE", status="FAILED", error_type=type(exc).__name__,
                      run_id=run_id, job_id=JOB, attempt_id=attempt_id)
            except BaseException as diagnostic_error:
                emergency(diagnostic_error)
            atomic_json(base / "accepted.json", {"status": "FAILED", "attempt_id": attempt_id,
                                                   "input_fingerprint": fingerprint})
            raise
    if status == "BLOCKED":
        budget = universe["budget"]
        raise Blocked(f"04-owasp-universe: planned validator calls {budget['planned_validator_calls']} exceed "
                      f"max_validator_calls {budget['max_validator_calls']}; the universe is BLOCKED and no "
                      f"validator call may start (attempt {attempt_id})")
    return {**pointer, "reused": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-owasp-universe")
    parser.add_argument("--reference-root", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(args.run_id, args.dagster_run_id, reference_root=args.reference_root, force=args.force)
    except (Blocked, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"OWASP_UNIVERSE_BLOCKED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
