#!/usr/bin/env python3
"""Which MITRE tables the run's model jobs answered their lookups from, for ``10-synthesis-report``.

ADR-0034 addendum item 3: the MITRE snapshot is not a job input (jobs use the current snapshot), but
every job granted MITRE lookup tools records a structured ``mitre_reference`` entry
(``mitre_query_mcp.record``, schema ``mitre-reference-record.schema.json``) in the
``invoker-output.json`` of each model invocation. This module reads those entries from the accepted
attempt trees only (each manifest hash-checked against its job's accepted pointer), and projects the
distinct entries, a gap line for every entry with a gap, or "not used" when no job had the tools.
Every name and version comes from the recorded entries (ADR-0013), never from model text.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from execution_state import Blocked, file_hash
from schema_validate import validate_document

SCHEMA = "appsec-review/mitre-reference-report/1.0"
RESULT = "mitre-reference-section.json"
MANIFEST = "invoker-output.json"
MANIFEST_SCHEMA = "persona-invoker-output.schema.json"
OK_STATUSES = ("OK", "OK_WITH_GAPS")
REPORT_JOB = "10-synthesis-report"
NOTE = ("MITRE ids are labels, never evidence. The MITRE snapshot is not a job input: each job granted "
        "MITRE lookup tools used the snapshot current when it ran, and recorded which.")
NOT_USED = "not used: no job in this run was granted MITRE lookup tools"


def _pointers(jobs: Path) -> list[Path]:
    """Accepted pointers of whole jobs and of one level of partitions (``<job>/<part>/accepted.json``)."""
    if not jobs.is_dir() or jobs.is_symlink():
        return []
    found = list(jobs.glob("*/accepted.json")) + list(jobs.glob("*/*/accepted.json"))
    return sorted(path for path in found if "attempts" not in path.relative_to(jobs).parts
                  and path.relative_to(jobs).parts[0] != REPORT_JOB and path.is_file() and not path.is_symlink())


def input_binding(run_root: Path) -> list[dict[str, Any]]:
    """Every accepted attempt holding invoker outputs, with each manifest's accepted hash: what the
    section reads, for the synthesis input fingerprint."""
    jobs = Path(run_root) / "data" / "jobs"
    rows = []
    for pointer_path in _pointers(jobs):
        try:
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(pointer, dict) or pointer.get("status") not in OK_STATUSES:
            continue
        hashes = pointer.get("hashes")
        if not isinstance(hashes, dict) or not isinstance(pointer.get("attempt_id"), str):
            continue
        manifests = [{"path": key, "sha256": value} for key, value in sorted(hashes.items())
                     if isinstance(key, str) and PurePosixPath(key).name == MANIFEST]
        if manifests:
            rows.append({"job": pointer_path.parent.relative_to(jobs).as_posix(),
                         "attempt_id": pointer["attempt_id"],
                         "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
                         "manifests": manifests})
    return rows


def _read(run_root: Path, row: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any] | None:
    """The manifest, hash-checked against the accepted pointer; None when it fails its schema."""
    attempt = Path(run_root) / "data" / "jobs" / row["job"] / "attempts" / row["attempt_id"]
    relative = PurePosixPath(manifest["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise Blocked(f"{REPORT_JOB}: invoker output path in {row['job']} escapes its attempt")
    path = attempt.joinpath(*relative.parts)
    if path.is_symlink() or not path.is_file() or file_hash(path) != manifest["sha256"]:
        raise Blocked(f"{REPORT_JOB}: invoker output {row['job']}/{manifest['path']} changed after acceptance")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return value if not validate_document(value, MANIFEST_SCHEMA) else None


def _key(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


def build(report: dict[str, Any], run_root: Path) -> dict[str, Any]:
    """The report's MITRE reference section (pure function of the report and the accepted attempts)."""
    binding = input_binding(run_root)
    distinct: dict[str, dict[str, Any]] = {}
    unreadable: list[str] = []
    for row in binding:
        for manifest in row["manifests"]:
            value = _read(run_root, row, manifest)
            if value is None:
                unreadable.append(f"{row['job']}/{manifest['path']}")
                continue
            entry = value.get("mitre_reference")
            if entry is None:
                continue
            slot = distinct.setdefault(_key(entry), {"entry": entry, "jobs": set(), "invocations": 0})
            slot["jobs"].add(row["job"].split("/")[0]); slot["invocations"] += 1
    entries = [{**slot["entry"], "jobs": sorted(slot["jobs"]), "invocations": slot["invocations"]}
               for _key_, slot in sorted(distinct.items())]
    gaps = []
    for item in entries:
        codes = [code for code in (item["gap"], item["cwe_gap"]) if code]
        if codes:
            gaps.append(f"mitre-reference: {item['invocations']} invocation(s) in {', '.join(item['jobs'])} "
                        f"answered MITRE lookups with {' and '.join(codes)}; names from the missing table were "
                        f"unknown to the model (recorded gap, not a failure)")
    if unreadable:
        gaps.append(f"mitre-reference: {len(unreadable)} accepted invoker output(s) failed their schema and were "
                    f"not read: {', '.join(sorted(unreadable)[:10])}")
    return {"schema": SCHEMA, "run_id": report["run_id"], "status": "USED" if entries else "NOT_USED",
            "binding": binding, "entries": entries, "gaps": gaps, "note": NOTE}


def _describe(item: dict[str, Any]) -> str:
    versions = item["versions"]
    if item["gap"]:
        attack = f"ATT&CK/CAPEC gap {item['gap']}"
    else:
        domains = ", ".join(f"{domain} {version}" for domain, version in versions["attack"].items()) or "none"
        attack = f"ATT&CK {domains}; CAPEC {versions['capec'] or 'none'}"
    cwe_detail = ", ".join(part for part in (item["cwe_source"], item["cwe_gap"] and f"gap {item['cwe_gap']}") if part)
    cwe = f"CWE {versions['cwe'] or 'none'}" + (f" ({cwe_detail})" if cwe_detail else "")
    identity = "; ".join(part for part in (
        item["snapshot_id"] and f"snapshot {item['snapshot_id']}",
        item["reference_sha256"] and f"table {item['reference_sha256'][:16]}") if part)
    return (f"{attack}; {cwe}" + (f"; {identity}" if identity else "")
            + f"; {item['invocations']} invocation(s) in {len(item['jobs'])} job(s): {', '.join(item['jobs'])}")


def provenance_rows(section: dict[str, Any] | None) -> list[list[str]]:
    """``[label, text]`` rows for the rendered report's Provenance table."""
    if section is None:
        return []
    if not section["entries"]:
        return [["MITRE reference", NOT_USED]]
    rows = [["MITRE reference", _describe(item)] for item in section["entries"]]
    rows += [["MITRE reference gap", gap.removeprefix("mitre-reference: ")] for gap in section["gaps"]]
    return rows
