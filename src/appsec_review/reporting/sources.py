"""Read-only access to the run artifacts the report is built from.

Nothing here writes. A missing, unreadable or malformed artifact becomes a *named gap* on the reader
(``reader.gaps``); the report then says so instead of failing or implying that the artifact was clean.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterator, Mapping

MAX_JSON_BYTES = 64 * 1024 * 1024
JOB = "job_inference_security_review"
_CELL_ID = re.compile(rb'"cell_id"\s*:\s*"(cell-[0-9a-f]{16,128})"')
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(slots=True)
class Ledger:
    """Everything the review ledger shards say, indexed for the report."""

    events: list[dict[str, Any]] = field(default_factory=list)
    claims: dict[str, dict[str, Any]] = field(default_factory=dict)
    claim_order: list[str] = field(default_factory=list)
    relations: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    transitions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    duplicates: dict[str, dict[str, Any]] = field(default_factory=dict)
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    cells: dict[str, dict[str, Any]] = field(default_factory=dict)
    shards: int = 0

    def claim_state(self, claim_id: str) -> str:
        if claim_id in self.duplicates:
            return "duplicate"
        steps = self.transitions.get(claim_id)
        if steps:
            return str(steps[-1].get("to_state", "unknown"))
        return str(self.claims.get(claim_id, {}).get("state", "proposed"))


class RunReader:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.data = self.run_dir / "data"
        self.gaps: list[str] = []
        self._named: set[str] = set()

    def gap(self, message: str) -> None:
        if message not in self._named:
            self._named.add(message)
            self.gaps.append(message)

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.run_dir).as_posix()
        except ValueError:
            return path.name

    def read_json(self, path: Path, name: str) -> Any | None:
        try:
            if path.stat().st_size > MAX_JSON_BYTES:
                self.gap(f"{name}: {self.rel(path)} exceeds the {MAX_JSON_BYTES} byte read bound")
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.gap(f"{name}: {self.rel(path)} is missing")
        except (OSError, ValueError) as exc:
            self.gap(f"{name}: {self.rel(path)} is unreadable ({type(exc).__name__})")
        return None

    def first_json(self, patterns: tuple[str, ...], name: str) -> tuple[Path, Any] | None:
        for pattern in patterns:
            found = sorted(self.run_dir.glob(pattern))
            if found:
                path = found[-1]
                value = self.read_json(path, name)
                return (path, value) if value is not None else None
        self.gap(f"{name}: no artifact matches {patterns[0]}")
        return None

    # -- final report and publication handoffs -------------------------------------------------

    def final_report(self) -> tuple[Path, dict[str, Any]] | None:
        found = self.first_json(("data/jobs/job_final_report_publication/attempts/*/steps/report/tasks/assemble/final-report.json",
                                 "data/jobs/job_final_report_publication/**/final-report.json"), "final report")
        if found is None or not isinstance(found[1], dict):
            return None
        return found[0], found[1]

    def handoff(self, job_id: str) -> dict[str, Any] | None:
        found = sorted(self.run_dir.glob(f"data/jobs/{job_id}/attempts/*/handoff.json"))
        if not found:
            self.gap(f"{job_id} handoff: not found")
            return None
        value = self.read_json(found[-1], f"{job_id} handoff")
        return value if isinstance(value, dict) else None

    # -- ledger ---------------------------------------------------------------------------------

    def ledger(self) -> Ledger:
        ledger = Ledger()
        shards = sorted(self.run_dir.glob(f"data/jobs/{JOB}/attempts/*/steps/*/tasks/*/ledger.jsonl"))
        if not shards:
            self.gap("review ledger: no ledger shard found")
            return ledger
        for shard in shards:
            ledger.shards += 1
            try:
                lines = shard.read_text(encoding="utf-8").splitlines()
            except (OSError, ValueError) as exc:
                self.gap(f"review ledger: {self.rel(shard)} is unreadable ({type(exc).__name__})")
                continue
            for number, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    kind, body = event["kind"], event["body"]
                    subject = event["subject_id"]
                except (ValueError, KeyError, TypeError):
                    self.gap(f"review ledger: {self.rel(shard)} line {number} is not a ledger event")
                    continue
                if not isinstance(body, dict):
                    self.gap(f"review ledger: {self.rel(shard)} line {number} has no body")
                    continue
                ledger.events.append(event)
                _index_event(ledger, str(kind), str(subject), body)
        return ledger

    # -- cell receipts -------------------------------------------------------------------------

    def cell_receipts(self, cell_id: str) -> list[tuple[Path, dict[str, Any]]]:
        if not _SAFE_SEGMENT.match(cell_id):
            return []
        directory = self.data / "jobs" / JOB / "cells" / cell_id
        receipts: list[tuple[Path, dict[str, Any]]] = []
        for path in sorted(directory.glob("attempt-*.json")):
            value = self.read_json(path, f"cell receipt {cell_id[:17]}")
            if isinstance(value, dict):
                receipts.append((path, value))
        return receipts

    # -- model recordings ----------------------------------------------------------------------

    def recording_index(self) -> dict[str, list[Path]]:
        """cell id -> recording files, found by a bounded prefix scan instead of a full parse."""
        directory = self.data / "inference-recordings" / JOB
        index: dict[str, list[Path]] = {}
        if not directory.is_dir():
            self.gap(f"model recordings: {self.rel(directory)} is missing")
            return index
        for path in sorted(directory.glob("*.json")):
            try:
                with path.open("rb") as stream:
                    head = stream.read(16384)
                match = _CELL_ID.search(head)
                cell_id = match.group(1).decode("ascii") if match else None
                if cell_id is None:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    cell_id = str(value["request"]["cell_id"])
            except (OSError, ValueError, KeyError, TypeError):
                self.gap(f"model recordings: {self.rel(path)} is unreadable or has no cell id")
                continue
            index.setdefault(cell_id, []).append(path)
        return index

    def recordings(self, paths: list[Path]) -> Iterator[tuple[Path, dict[str, Any]]]:
        for path in paths:
            value = self.read_json(path, "model recording")
            if isinstance(value, dict) and isinstance(value.get("request"), dict):
                yield path, value

    # -- review packages -----------------------------------------------------------------------

    def assembled_package(self, package_id: str) -> tuple[Path, dict[str, Any]] | None:
        if not _SAFE_SEGMENT.match(package_id):
            return None
        for path in sorted(self.data.glob(f"jobs/{JOB}/attempts/*/steps/packages/tasks/*/assembly/packages/{package_id}.json")):
            value = self.read_json(path, f"assembled package {package_id[:24]}")
            if isinstance(value, dict):
                return path, value
        return None

    def review_package(self, package_id: str) -> tuple[Path, dict[str, Any]] | None:
        if not _SAFE_SEGMENT.match(package_id):
            return None
        for path in sorted(self.data.glob(f"review-packages/*/{package_id}.json")):
            value = self.read_json(path, f"review package {package_id[:24]}")
            if isinstance(value, dict):
                return path, value
        return None


def _index_event(ledger: Ledger, kind: str, subject: str, body: Mapping[str, Any]) -> None:
    if kind == "claim_proposed" and isinstance(body.get("claim"), dict):
        claim = dict(body["claim"])
        claim_id = str(claim.get("claim_id", subject))
        if claim_id not in ledger.claims:
            ledger.claim_order.append(claim_id)
        ledger.claims[claim_id] = claim
    elif kind == "relation_added" and isinstance(body.get("relation"), dict):
        relation = dict(body["relation"])
        ledger.relations.setdefault(str(relation.get("claim_id", "")), []).append(relation)
    elif kind == "state_transition":
        ledger.transitions.setdefault(subject, []).append(dict(body))
    elif kind == "duplicate_marked":
        ledger.duplicates[subject] = dict(body)
    elif kind in ("evidence_request_opened", "evidence_request_closed"):
        entry = ledger.requests.setdefault(subject, {"request_id": subject})
        entry.update({key: value for key, value in body.items()})
        entry["closed" if kind.endswith("closed") else "opened"] = True
    elif kind == "gap_recorded" and isinstance(body.get("gap"), dict):
        ledger.gaps.append(dict(body["gap"]))
    elif kind == "cell_terminal" and isinstance(body.get("cell"), dict):
        cell = dict(body["cell"])
        ledger.cells[str(cell.get("cell_id", subject))] = cell
