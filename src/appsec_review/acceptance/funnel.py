"""Per-defect funnel of one finished run: the last stage each seeded defect reached, and why it stopped.

The answer key (``answer_key``) says whether the deterministic producers *observed* a seeded defect.
This module follows the same defect through the model-backed review and reports, from run artifacts only,
the furthest stage it reached and the specific reason the next stage was not reached. It is read-only on
the run directory and deterministic: the same run and key give byte-identical output.

Stages, in order (``STAGES``):

``available``    the defect is in the answer key and its file is in the run's accepted source catalog;
``observed``     some tool observation lies on the defect's lines (producers listed);
``selected``     a review package or hunt unit covering the location was assembled and admitted to a lane queue;
``reviewed``     a red cell of that package reached a terminal state other than ``not_launched``;
``retrieved``    those cells received retrieval rows (denied lookups are not rows);
``proposed``     a claim whose affected entity lies on the defect was proposed;
``challenged``   a blue cell recorded a disposition on the claim;
``judged``       a judge verdict was recorded on the claim;
``verified``     the independent verifier recorded a disposition;
``adjudicated``  the claim left the ``proposed`` state;
``published``    the claim is in the final report (finding, verification backlog or withheld).

A stage that the run has no mechanism for at all (for example blue cells in a run of the older protocol)
is ``not_applicable_in_this_run`` and does not stop the chain. Missing artifacts are named in
``stopped_because``; nothing is invented.

Model-dependent stages are **reported, never asserted** (docs/processes/acceptance-and-regression-testing.md,
Decision 2): nothing here changes a verdict. Run files, ledger text and model output are data.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
import glob
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any

from .answer_key import Defect, _relative, load_answer_key

STAGES = ("available", "observed", "selected", "reviewed", "retrieved", "proposed", "challenged", "judged",
          "verified", "adjudicated", "published")
REACHED = "reached"
NOT_REACHED = "not_reached"
NOT_APPLICABLE = "not_applicable_in_this_run"

INFERENCE_JOB = "job_inference_security_review"
REPORT_JOB = "job_final_report_publication"
RED_ROLES = ("red_team_analyst", "hypothesis_hunter")
BLUE_ROLE = "blue_team_refuter"
VERIFIER_ROLE = "independent_verifier"
BLUE_SEVERITY = ("contradicts", "qualifies", "unresolved", "supports")
DEFAULT_EXPECTATIONS = Path("test") / "acceptance" / "cpp-multivuln-v1" / "expectations.toml"

# Every ``stopped_because`` code the evaluator can emit. A code may carry a ``:detail`` suffix.
STOPPED_CODES = {
    "file_not_in_catalog": "the defect's file is not in the run's accepted source catalog",
    "no_tool_observation_at_location": "no tool observation lies on the defect's lines",
    "inference_review_absent": "the run has no inference security review to follow",
    "no_lead_at_location": "no review package or hunt unit carries a lead at the location",
    "package_not_selected_cap": "a review package covers the location but the inference job assembled none for it",
    "package_not_selected_lead_cap": "an inference package covers the location but never entered the lead queue",
    "package_not_selected_hunt_cap": "a hunt unit covers the location but never entered the hunt queue",
    "red_not_launched": "the admitted package's red cells were never launched",
    "red_cells_invalid": "no red cell succeeded; the dominant terminal status is invalid (suffix: dominant gap class)",
    "red_cells_timed_out": "no red cell succeeded; the dominant terminal status is timed_out (suffix: gap class)",
    "red_cells_failed": "no red cell succeeded; the dominant terminal status is failed (suffix: gap class)",
    "red_cells_blocked": "no red cell succeeded; the dominant terminal status is blocked (suffix: gap class)",
    "red_cells_canceled": "no red cell succeeded; the dominant terminal status is canceled (suffix: gap class)",
    "retrieval_all_denied": "every lookup the red cells made was denied (suffix: dominant denial code)",
    "retrieval_empty": "lookups executed but returned no rows",
    "retrieval_not_attempted": "red cells succeeded without making any lookup",
    "red_no_claim": "red cells succeeded but proposed no claim on the location",
    "blue_not_run": "blue cells exist in the run but none ran for this claim",
    "blue_cells_not_succeeded": "blue cells ran for this claim but none recorded a disposition",
    "judge_not_run": "a judge exists in the run but none ran for this claim",
    "judge_cells_not_succeeded": "a judge ran for this claim but recorded no verdict",
    "verifier_not_run": "verifier cells exist in the run but none ran for this claim",
    "verifier_cells_not_succeeded": "verifier cells ran for this claim but none recorded a disposition",
    "claim_not_adjudicated": "the claim is still in the proposed state",
    "claim_contradicted_by_blue": "the claim ended contradicted and blue contradicted it",
    "claim_contradicted_by_verifier": "the claim ended contradicted and the verifier contradicted it",
    "claim_contradicted": "the claim ended contradicted",
    "judge_sided_with_blue": "the claim did not survive and the judge sided with blue",
    "verifier_insufficient_evidence": "the verifier found insufficient evidence",
    "claim_insufficient_evidence": "the claim ended insufficient_evidence",
    "claim_not_reachable": "the claim ended not_reachable",
    "claim_not_exploitable": "the claim ended not_exploitable_in_observed_configuration",
    "claim_duplicate": "the claim is a duplicate of another claim",
    "claim_out_of_scope": "the claim ended out_of_scope",
    "claim_coverage_gap": "the claim ended coverage_gap",
    "final_report_absent": "the claim survived adjudication but the run has no final report",
    "not_in_final_report": "the claim survived adjudication but is in no final-report bucket",
    "claim_supported_not_confirmed": "published in the verification backlog: supported, not independently confirmed",
    "published_confirmed": "published as a confirmed finding",
    "published_withheld": "present in the final report but withheld",
}


# --------------------------------------------------------------------------------------- results

@dataclass(frozen=True)
class StageResult:
    stage: str
    status: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, "status": self.status, "detail": self.detail}


@dataclass
class DefectFunnel:
    defect_id: str
    cwe: str
    path: str
    line: int
    end_line: int | None
    stage: str                                   # furthest stage reached
    stages: list[StageResult]
    stopped_because: str
    sentence: str
    producers_seen: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    reviewed: dict[str, Any] = field(default_factory=dict)
    retrieval: dict[str, Any] = field(default_factory=dict)
    claims: list[dict[str, Any]] = field(default_factory=list)
    verdicts: dict[str, Any] = field(default_factory=dict)
    ship_decision: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.defect_id, "cwe": self.cwe, "path": self.path, "line": self.line, "end_line": self.end_line,
            "stage": self.stage, "stopped_because": self.stopped_because, "sentence": self.sentence,
            "stages": [item.as_dict() for item in self.stages], "producers_seen": self.producers_seen,
            "packages": self.packages, "reviewed": self.reviewed, "retrieval": self.retrieval,
            "claims": self.claims, "verdicts": self.verdicts, "ship_decision": self.ship_decision,
            "notes": self.notes}


@dataclass
class FunnelReport:
    run_id: str
    defects: list[DefectFunnel]
    aggregate: dict[str, Any]
    run: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"run": self.run, "defects": [item.as_dict() for item in self.defects], "aggregate": self.aggregate}


# --------------------------------------------------------------------------------------- reading

def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _jsonl(path: Path) -> Iterator[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            yield item


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> Sequence[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _overlaps(path: str | None, start: int | None, end: int | None, defect: Defect) -> bool:
    if not isinstance(path, str) or start is None or _relative(path) != defect.path:
        return False
    last = end if end is not None else start
    return start <= (defect.end_line or defect.line) and defect.line <= last


@dataclass(frozen=True)
class _Location:
    entity_id: str
    kind: str
    path: str
    start: int
    end: int
    producer: str


def _load_locations(run_root: Path) -> dict[str, list[_Location]]:
    """Every located entity of every published index shard, by entity id (read-only, immutable open)."""

    located: dict[str, list[_Location]] = {}
    for name in sorted(glob.glob(str(run_root / "data" / "indices" / "**" / "*.sqlite"), recursive=True)):
        database = None
        try:
            database = sqlite3.connect(f"file:{name}?mode=ro&immutable=1", uri=True)
            rows = database.execute(
                "SELECT e.identity, e.kind, e.name, e.payload_json, l.path, l.start_line, l.end_line "
                "FROM entities e JOIN locations l ON l.entity_id = e.identity").fetchall()
        except sqlite3.Error:
            continue
        finally:
            if database is not None:
                database.close()
        for identity, kind, rule, payload_json, path, start, end in rows:
            producer = ""
            if kind == "tool_observation":
                try:
                    payload = json.loads(payload_json or "{}")
                except ValueError:
                    payload = {}
                scanner = str(_mapping(payload).get("scanner") or _mapping(payload).get("tool") or "")
                producer = scanner or str(rule)
            located.setdefault(str(identity), []).append(
                _Location(str(identity), str(kind), str(path), int(start), int(end), producer))
    return located


def _catalog_paths(run_root: Path) -> set[str]:
    paths: set[str] = set()
    for name in sorted(glob.glob(str(run_root / "data" / "indices" / "source" / "**" / "*.sqlite"), recursive=True)):
        database = None
        try:
            database = sqlite3.connect(f"file:{name}?mode=ro&immutable=1", uri=True)
            paths.update(_relative(str(row[0])) for row in database.execute("SELECT path FROM locations"))
        except sqlite3.Error:
            continue
        finally:
            if database is not None:
                database.close()
    return paths


def _latest_attempt(job_root: Path) -> Path | None:
    pointer = _mapping(_json(job_root / "latest.json"))
    handoff = pointer.get("handoff_path")
    if isinstance(handoff, str):
        # handoff_path is run-root relative: data/jobs/<job>/attempts/<attempt>/handoff.json
        candidate = job_root / "attempts" / Path(handoff).parent.name
        if candidate.is_dir():
            return candidate
    attempts = sorted(path for path in (job_root / "attempts").glob("attempt_*") if path.is_dir())
    return attempts[-1] if attempts else None


@dataclass(frozen=True)
class _Package:
    package_id: str
    lane: str
    locations: tuple[tuple[str, int, int], ...]
    source: str                                   # "inference" or "review"


def _lead_locations(menu: Iterable[Any], located: Mapping[str, list[_Location]]) -> tuple[tuple[str, int, int], ...]:
    found: list[tuple[str, int, int]] = []
    for item in menu:
        entry = _mapping(item)
        location = _mapping(entry.get("location"))
        path, start, end = location.get("source_path"), _int(location.get("start_line")), _int(location.get("end_line"))
        if isinstance(path, str) and start is not None:
            found.append((_relative(path), start, end if end is not None else start))
            continue
        for place in located.get(str(entry.get("observation_id")), ()):
            found.append((_relative(place.path), place.start, place.end))
    return tuple(sorted(set(found)))


def _read_packages(directory: Iterable[Path], located: Mapping[str, list[_Location]], source: str) -> list[_Package]:
    packages: dict[str, _Package] = {}                 # the lane tasks each publish the full set; keep one copy
    for path in sorted(directory):
        document = _mapping(_json(path))
        if "lead_menu" not in document or not isinstance(document.get("package_id"), str):
            continue
        lane = document.get("lane") if isinstance(document.get("lane"), str) else (
            "hunt" if document.get("kind") == "hunt" else "lead")
        packages.setdefault(document["package_id"], _Package(
            document["package_id"], lane, _lead_locations(_sequence(document["lead_menu"]), located), source))
    return [packages[key] for key in sorted(packages)]


# --------------------------------------------------------------------------------------- run view

@dataclass
class _Cell:
    cell_id: str
    lane: str
    package_id: str
    role: str
    task: str
    claim_id: str | None
    status: str
    gap_ids: tuple[str, ...]


class _Run:
    """Everything the evaluator reads from one run directory, loaded once."""

    def __init__(self, run_root: Path) -> None:
        self.root = Path(run_root)
        self.job_root = self.root / "data" / "jobs" / INFERENCE_JOB
        self.attempt = _latest_attempt(self.job_root)
        self.present = self.attempt is not None
        self.located = _load_locations(self.root)
        self.catalog = _catalog_paths(self.root)
        self.events = self._events()
        self.gaps = {str(_mapping(_mapping(e.get("body")).get("gap")).get("gap_id")): _mapping(_mapping(e["body"]).get("gap"))
                     for e in self.events if e.get("kind") == "gap_recorded"}
        self.cells = self._cells()
        self._receipts: dict[str, list[dict[str, Any]]] = {}
        self.lead_packages: list[_Package] = []
        self.review_packages: list[_Package] = []
        self.queues: dict[str, set[str]] | None = None
        self._packages()
        self.claims = self._claims()
        self.judge = self._judge()
        self.report = self._report()
        self.recordings = self._recordings()

    # -- ledger
    def _events(self) -> list[dict[str, Any]]:
        if self.attempt is None:
            return []
        paths = sorted(glob.glob(str(self.attempt / "steps" / "*" / "tasks" / "*" / "ledger.jsonl")))
        paths += sorted(glob.glob(str(self.attempt / "steps" / "*" / "tasks" / "*" / "claim-ledger.jsonl")))
        seen: set[str] = set()
        events = []
        for name in paths:
            for event in _jsonl(Path(name)):
                identity = str(event.get("event_id") or "")
                if identity and identity in seen:
                    continue
                seen.add(identity)
                events.append(event)
        return events

    def _cells(self) -> dict[str, _Cell]:
        cells: dict[str, _Cell] = {}
        for event in self.events:
            if event.get("kind") != "cell_terminal":
                continue
            body = _mapping(_mapping(event.get("body")).get("cell"))
            cell_id = body.get("cell_id")
            if not isinstance(cell_id, str):
                continue
            cells[cell_id] = _Cell(cell_id, str(body.get("lane")), str(body.get("package_id")), str(body.get("role")),
                                   str(body.get("task")), body.get("claim_id") if isinstance(body.get("claim_id"), str) else None,
                                   str(body.get("status")), tuple(str(g) for g in _sequence(body.get("gap_ids"))))
        return cells

    def receipts(self, cell_id: str) -> list[dict[str, Any]]:
        if cell_id not in self._receipts:
            found = []
            for path in (self.job_root / "cells" / cell_id).glob("attempt-*.json"):
                document = _json(path)
                if isinstance(document, dict):
                    found.append(document)
            self._receipts[cell_id] = sorted(found, key=lambda item: _int(item.get("attempt")) or 0)
        return self._receipts[cell_id]

    def gap_class(self, cell: _Cell) -> str:
        """The cause class of a cell that did not succeed: its last receipt's, else its dominant ledger gap."""

        receipts = self.receipts(cell.cell_id)
        if receipts and isinstance(receipts[-1].get("gap_class"), str):
            return str(receipts[-1]["gap_class"])
        classes = Counter(str(self.gaps[g].get("gap_class")) for g in cell.gap_ids if g in self.gaps)
        return _dominant(classes) or "unknown"

    # -- packages
    def _packages(self) -> None:
        if self.attempt is not None:
            files = glob.glob(str(self.attempt / "steps" / "packages" / "tasks" / "assemble_*_packages" / "assembly"
                                  / "packages" / "*.json"))
            self.lead_packages = _read_packages((Path(name) for name in files), self.located, "inference")
            queues: dict[str, set[str]] = {}
            for name in sorted(glob.glob(str(self.attempt / "lanes" / "*.json"))):
                document = _mapping(_json(Path(name)))
                if isinstance(document.get("lane"), str):
                    queues[document["lane"]] = {str(item) for item in _sequence(document.get("package_ids"))}
            self.queues = queues or None
        review = glob.glob(str(self.root / "data" / "review-packages" / "*" / "*.json"))
        self.review_packages = _read_packages((Path(name) for name in review), self.located, "review")

    def admitted(self, package: _Package) -> bool:
        return self.queues is None or package.package_id in self.queues.get(package.lane, set())

    # -- claims
    def _claims(self) -> dict[str, dict[str, Any]]:
        claims: dict[str, dict[str, Any]] = {}
        transitions: dict[str, str] = {}
        for event in self.events:
            body = _mapping(event.get("body"))
            if event.get("kind") == "claim_proposed" and isinstance(body.get("claim"), Mapping):
                claim = dict(body["claim"])
                if isinstance(claim.get("claim_id"), str):
                    claims.setdefault(claim["claim_id"], claim)
            elif event.get("kind") == "state_transition" and isinstance(body.get("to_state"), str):
                transitions[str(event.get("subject_id"))] = body["to_state"]
        for claim_id, state in transitions.items():
            if claim_id in claims:
                claims[claim_id]["state"] = state
        projection = _mapping(_json(self._publication_file("projection.json"))) if self.attempt else {}
        for item in _sequence(projection.get("claims")):
            entry = _mapping(item)
            if isinstance(entry.get("claim_id"), str):
                claims[entry["claim_id"]] = {**claims.get(entry["claim_id"], {}), **entry}
        return claims

    def _publication_file(self, name: str) -> Path:
        assert self.attempt is not None
        return self.attempt / "steps" / "publication" / "tasks" / "publish_claim_ledger" / name

    def claim_locations(self, claim: Mapping[str, Any]) -> list[_Location]:
        return [place for entity in _sequence(claim.get("affected_entities")) for place in self.located.get(str(entity), ())]

    # -- verdicts
    def _judge(self) -> dict[str, list[str]]:
        verdicts: dict[str, list[str]] = {}
        for event in self.events:
            if event.get("kind") != "judge_verdict":
                continue
            body = _mapping(event.get("body"))
            claim_id = body.get("claim_id") or event.get("subject_id")
            verdict = body.get("verdict")
            if isinstance(claim_id, str) and isinstance(verdict, str):
                verdicts.setdefault(claim_id, []).append(verdict)
        return verdicts

    def role_cells(self, role_match: str) -> list[_Cell]:
        return sorted((cell for cell in self.cells.values() if role_match in cell.role), key=lambda c: c.cell_id)

    def cell_result(self, cell: _Cell) -> Mapping[str, Any] | None:
        """The recorded result of the cell's last attempt that has one."""

        for receipt in reversed(self.receipts(cell.cell_id)):
            if receipt.get("status") == "succeeded" and isinstance(receipt.get("result"), Mapping):
                return receipt["result"]
        return None

    # -- report
    def _report(self) -> dict[str, tuple[str, str | None]] | None:
        """claim id -> (bucket, ship status) from the final report; None when the run has no report."""

        names = sorted(glob.glob(str(self.root / "data" / "jobs" / REPORT_JOB / "attempts" / "*" / "steps" / "report"
                                     / "tasks" / "assemble" / "final-report.json")))
        document = _mapping(_json(Path(names[-1]))) if names else {}
        if not document:
            return None
        placed: dict[str, tuple[str, str | None]] = {}
        for key, bucket in (("findings", "finding"), ("verification_backlog", "verification_backlog"),
                            ("withheld", "withheld")):
            for item in _sequence(document.get(key)):
                entry = _mapping(item)
                if isinstance(entry.get("claim_id"), str):
                    ship = _mapping(entry.get("ship_block")).get("status")
                    placed[entry["claim_id"]] = (bucket, ship if isinstance(ship, str) else None)
        return placed

    # -- recordings
    def _recordings(self) -> list[Mapping[str, Any]]:
        found = []
        for name in sorted(glob.glob(str(self.root / "data" / "inference-recordings" / INFERENCE_JOB / "*.json"))):
            document = _json(Path(name))
            if isinstance(document, dict):
                found.append(document)
        return found


def _dominant(counter: Counter[str]) -> str | None:
    if not counter:
        return None
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[0][0]


def _breakdown(counter: Counter[str]) -> str:
    return ",".join(f"{key}={counter[key]}" for key in sorted(counter)) or "none"


# --------------------------------------------------------------------------------------- evaluation

_CLAIM_STAGES = STAGES[STAGES.index("challenged"):]


def _cell_failure(run: _Run, cells: Sequence[_Cell], prefix: str) -> tuple[str, str]:
    statuses = Counter(cell.status for cell in cells)
    status = _dominant(statuses) or "unknown"
    classes = Counter(run.gap_class(cell) for cell in cells if cell.status == status)
    return f"{prefix}_{status}:{_dominant(classes) or 'unknown'}", f"{_breakdown(statuses)}; gap classes {_breakdown(classes)}"


def _claim_chain(run: _Run, claim: Mapping[str, Any]) -> tuple[list[StageResult], str, str, dict[str, Any]]:
    """Stages ``challenged`` to ``published`` for one claim, the stop code, its sentence and the verdicts."""

    claim_id = str(claim.get("claim_id"))
    state = str(claim.get("state"))
    results: list[StageResult] = []
    verdicts: dict[str, Any] = {"blue": None, "judge": None, "verifier": None, "state": state}
    stop: tuple[str, str] | None = None

    def not_reached(stage: str, code: str, sentence: str) -> None:
        nonlocal stop
        results.append(StageResult(stage, NOT_REACHED, code))
        stop = stop or (code, sentence)

    def role_stage(stage: str, role: str, key: str, fields: tuple[str, ...], missing: str, failed: str) -> None:
        cells = [cell for cell in run.role_cells(role) if cell.claim_id == claim_id]
        recorded = [str(value) for cell in cells
                    for value in [next((result.get(name) for name in fields if isinstance(result.get(name), str)), None)
                                  for result in [run.cell_result(cell) or {}]] if value]
        if key == "judge":
            recorded += run.judge.get(claim_id, [])
        if recorded:
            verdicts[key] = sorted(set(recorded))
            results.append(StageResult(stage, REACHED, ",".join(sorted(set(recorded)))))
            return
        applicable = bool(run.role_cells(role)) or (key == "judge" and bool(run.judge))
        if not applicable:
            results.append(StageResult(stage, NOT_APPLICABLE, "the run has no such cells"))
        elif key == "judge":
            # The judge is advisory (it never sets a state) and may be configured for some claims only:
            # its absence for this claim is reported but does not stop the chain.
            results.append(StageResult(stage, NOT_REACHED, failed if cells else missing))
        elif cells:
            _code, detail = _cell_failure(run, cells, key + "_cells")
            not_reached(stage, failed, f"{key} cells ran for the claim but recorded nothing ({detail})")
        else:
            not_reached(stage, missing, f"no {key} cell ran for claim {claim_id}")

    if stop is None:
        role_stage("challenged", BLUE_ROLE, "blue", ("disposition", "stance"), "blue_not_run", "blue_cells_not_succeeded")
    if stop is None:
        role_stage("judged", "judge", "judge", ("verdict",), "judge_not_run", "judge_cells_not_succeeded")
    else:
        results.append(StageResult("judged", NOT_REACHED, ""))
    if stop is None:
        role_stage("verified", VERIFIER_ROLE, "verifier", ("proposed_disposition", "disposition"), "verifier_not_run",
                   "verifier_cells_not_succeeded")
    else:
        results.append(StageResult("verified", NOT_REACHED, ""))
    if stop is None:
        if state == "proposed":
            not_reached("adjudicated", "claim_not_adjudicated", f"claim {claim_id} is still proposed")
        else:
            results.append(StageResult("adjudicated", REACHED, state))
    else:
        results.append(StageResult("adjudicated", NOT_REACHED, ""))
    if verdicts["blue"]:
        verdicts["blue"] = sorted(verdicts["blue"], key=lambda item: (BLUE_SEVERITY.index(item) if item in BLUE_SEVERITY
                                                                       else len(BLUE_SEVERITY), item))
    if stop is None:
        placed = (run.report or {}).get(claim_id)
        if placed is not None:
            bucket, ship = placed
            verdicts["ship_decision"] = ship
            results.append(StageResult("published", REACHED, f"{bucket}; ship_block={ship}"))
            code = {"finding": "published_confirmed", "verification_backlog": "claim_supported_not_confirmed",
                    "withheld": "published_withheld"}[bucket]
            stop = (code, STOPPED_CODES[code])
        elif run.report is None and state in ("supported", "confirmed"):
            not_reached("published", "final_report_absent", STOPPED_CODES["final_report_absent"])
        elif state in ("supported", "confirmed"):
            not_reached("published", "not_in_final_report", f"claim {claim_id} is {state} but in no final-report bucket")
        else:
            code, sentence = _terminal_explanation(claim_id, state, verdicts)
            not_reached("published", code, sentence)
    else:
        results.append(StageResult("published", NOT_REACHED, ""))
    assert stop is not None
    return results, stop[0], stop[1], verdicts


def _terminal_explanation(claim_id: str, state: str, verdicts: Mapping[str, Any]) -> tuple[str, str]:
    blue = verdicts.get("blue") or []
    judge = verdicts.get("judge") or []
    verifier = verdicts.get("verifier") or []
    if state == "contradicted":
        if "blue_correct" in judge:
            code = "judge_sided_with_blue"
        elif "contradicts" in blue:
            code = "claim_contradicted_by_blue"
        elif "contradicted" in verifier:
            code = "claim_contradicted_by_verifier"
        else:
            code = "claim_contradicted"
    elif state == "insufficient_evidence":
        code = "verifier_insufficient_evidence" if "insufficient_evidence" in verifier else "claim_insufficient_evidence"
        if "blue_correct" in judge:
            code = "judge_sided_with_blue"
    elif state == "not_reachable":
        code = "claim_not_reachable"
    elif state == "not_exploitable_in_observed_configuration":
        code = "claim_not_exploitable"
    elif state in ("duplicate", "out_of_scope", "coverage_gap"):
        code = "claim_" + state
    else:
        code = "claim_contradicted"
    return code, f"claim {claim_id} ended {state}: {STOPPED_CODES[code]}"


def _claim_rank(claim: Mapping[str, Any], furthest: int) -> tuple[int, int, str]:
    states = ("confirmed", "supported", "proposed")
    state = str(claim.get("state"))
    return (-furthest, states.index(state) if state in states else len(states), str(claim.get("claim_id")))


def _evaluate_defect(run: _Run, defect: Defect) -> DefectFunnel:
    stages: list[StageResult] = []
    funnel = DefectFunnel(defect.id, defect.cwe, defect.path, defect.line, defect.end_line, "", stages, "", "")

    def stop(stage: str, code: str, sentence: str) -> DefectFunnel:
        stages.append(StageResult(stage, NOT_REACHED, code))
        for later in STAGES[len(stages):]:
            stages.append(StageResult(later, NOT_REACHED, ""))
        reached = [item.stage for item in stages if item.status == REACHED]
        funnel.stage = reached[-1] if reached else "none"
        funnel.stopped_because, funnel.sentence = code, sentence
        return funnel

    # available
    if defect.path not in run.catalog and run.catalog:
        return stop("available", "file_not_in_catalog", f"{defect.path} is not in the accepted source catalog")
    if not run.catalog:
        funnel.notes.append("source catalog index absent; availability could not be confirmed")
    stages.append(StageResult("available", REACHED, defect.path))
    # observed
    seen = sorted({place.producer for places in run.located.values() for place in places
                   if place.kind == "tool_observation" and _overlaps(place.path, place.start, place.end, defect)})
    funnel.producers_seen = seen
    if not seen:
        return stop("observed", "no_tool_observation_at_location", f"no tool observation lies on {defect.path}:{defect.line}")
    stages.append(StageResult("observed", REACHED, ",".join(seen)))
    # selected
    if not run.present:
        return stop("selected", "inference_review_absent", STOPPED_CODES["inference_review_absent"])

    def covers(package: _Package) -> bool:
        return any(_overlaps(path, start, end, defect) for path, start, end in package.locations)

    covering = [package for package in run.lead_packages if covers(package)]
    admitted = [package for package in covering if run.admitted(package)]
    funnel.packages = sorted(package.package_id for package in admitted)
    if not admitted:
        if covering:
            lane = sorted({package.lane for package in covering})[0]
            code = f"package_not_selected_{'hunt' if lane == 'hunt' else 'lead'}_cap"
            return stop("selected", code, f"{len(covering)} covering package(s) never entered the {lane} queue")
        if any(covers(package) for package in run.review_packages):
            return stop("selected", "package_not_selected_cap", STOPPED_CODES["package_not_selected_cap"])
        return stop("selected", "no_lead_at_location", f"no package lead lies on {defect.path}:{defect.line}")
    stages.append(StageResult("selected", REACHED, ",".join(sorted({p.lane for p in admitted}))))
    # reviewed
    red = sorted((cell for cell in run.cells.values() if cell.role in RED_ROLES and cell.package_id in set(funnel.packages)),
                 key=lambda cell: cell.cell_id)
    launched = [cell for cell in red if cell.status != "not_launched"]
    statuses = Counter(cell.status for cell in red) if red else Counter({"not_launched": len(admitted)})
    failing = [cell for cell in red if cell.status != "succeeded"]
    funnel.reviewed = {"cells": len(red), "by_status": dict(sorted(statuses.items())),
                       "dominant_gap_class": _dominant(Counter(run.gap_class(cell) for cell in failing))}
    if not launched:
        return stop("reviewed", "red_not_launched", f"no red cell of {len(admitted)} admitted package(s) was launched")
    stages.append(StageResult("reviewed", REACHED, _breakdown(statuses)))
    # retrieved
    executed, denied, rows, tools, codes = 0, 0, 0, Counter(), Counter()
    for cell in red:
        for receipt in run.receipts(cell.cell_id):
            for turn in _sequence(receipt.get("turns")):
                for retrieval in _sequence(_mapping(turn).get("retrievals")):
                    entry = _mapping(retrieval)
                    if entry.get("status") == "denied":
                        denied += 1
                        codes[str(entry.get("denial_code"))] += 1
                    elif entry.get("status") == "executed":
                        executed += 1
                        rows += _int(entry.get("result_count")) or 0
                        tools[str(entry.get("tool"))] += 1
    funnel.retrieval = {"executed": executed, "denied": denied, "rows": rows, "tools": dict(sorted(tools.items())),
                        "denials_by_code": dict(sorted(codes.items()))}
    succeeded = [cell for cell in red if cell.status == "succeeded"]
    unsuccessful = _cell_failure(run, failing, "red_cells") if failing else None
    if rows == 0:
        if denied and not executed:
            return stop("retrieved", f"retrieval_all_denied:{_dominant(codes)}",
                        f"all {denied} lookup(s) were denied ({_breakdown(codes)})")
        if executed:
            return stop("retrieved", "retrieval_empty", f"{executed} lookup(s) executed and returned no rows")
        if not succeeded and unsuccessful:
            return stop("retrieved", unsuccessful[0], f"no red cell succeeded and none retrieved ({unsuccessful[1]})")
        return stop("retrieved", "retrieval_not_attempted", STOPPED_CODES["retrieval_not_attempted"])
    stages.append(StageResult("retrieved", REACHED, f"{rows} row(s) by {','.join(sorted(tools))}"))
    # proposed
    linked = sorted((claim for claim in run.claims.values()
                     if any(_overlaps(place.path, place.start, place.end, defect) for place in run.claim_locations(claim))),
                    key=lambda claim: str(claim.get("claim_id")))
    if not linked:
        if not succeeded and unsuccessful:
            return stop("proposed", unsuccessful[0], f"no red cell succeeded and no claim lies on the defect ({unsuccessful[1]})")
        return stop("proposed", "red_no_claim", f"{len(succeeded)} red cell(s) succeeded but no claim lies on the defect")
    stages.append(StageResult("proposed", REACHED, ",".join(str(c.get("claim_id")) for c in linked)))
    # per-claim chain; the claim that got furthest represents the defect
    chains = []
    for claim in linked:
        chain, code, sentence, verdicts = _claim_chain(run, claim)
        furthest = sum(1 for item in chain if item.status != NOT_REACHED)
        chains.append((_claim_rank(claim, furthest), claim, chain, code, sentence, verdicts))
    chains.sort(key=lambda item: item[0])
    _rank, best, chain, code, sentence, verdicts = chains[0]
    stages.extend(chain)
    funnel.claims = [{"claim_id": str(claim.get("claim_id")), "state": str(claim.get("state")),
                      "package_id": str(claim.get("package_id")), "lane": str(claim.get("lane"))}
                     for _rank, claim, *_rest in chains]
    funnel.verdicts = {key: verdicts[key] for key in ("blue", "judge", "verifier")}
    funnel.ship_decision = verdicts.get("ship_decision")
    if "blue_correct" in (verdicts.get("judge") or []) and code in ("published_confirmed", "claim_supported_not_confirmed"):
        funnel.notes.append("the judge sided with blue on a published claim")
    reached = [item.stage for item in stages if item.status == REACHED]
    funnel.stage = reached[-1]
    funnel.stopped_because, funnel.sentence = code, sentence
    return funnel


# --------------------------------------------------------------------------------------- aggregate

def _model_quality(run: _Run) -> dict[str, Any]:
    first = parsed = repairs = failed = 0
    calls_by_cell: Counter[str] = Counter()
    by_role: dict[str, Counter[str]] = {}
    for recording in run.recordings:
        request = _mapping(recording.get("request"))
        calls_by_cell[str(request.get("cell_id"))] += 1
        ok = isinstance(_mapping(recording.get("result")).get("proposal"), Mapping)
        failed += 0 if recording.get("result") is not None else 1
        role = by_role.setdefault(str(request.get("role")), Counter())
        if _sequence(request.get("repair_errors")):
            repairs += 1
        else:
            first += 1
            parsed += 1 if ok else 0
            role["first_attempt_calls"] += 1
            role["first_attempt_parsed"] += 1 if ok else 0
    executed = denied = rows = 0
    denials: Counter[str] = Counter()
    tools: Counter[str] = Counter()
    for cell in sorted(run.cells.values(), key=lambda item: item.cell_id):
        for receipt in run.receipts(cell.cell_id):
            for turn in _sequence(receipt.get("turns")):
                for retrieval in _sequence(_mapping(turn).get("retrievals")):
                    entry = _mapping(retrieval)
                    if entry.get("status") == "denied":
                        denied += 1
                        denials[str(entry.get("denial_code"))] += 1
                    elif entry.get("status") == "executed":
                        executed += 1
                        rows += _int(entry.get("result_count")) or 0
                        tools[str(entry.get("tool"))] += 1
    statuses = Counter(cell.status for cell in run.cells.values())
    by_role_status: dict[str, Counter[str]] = {}
    for cell in run.cells.values():
        by_role_status.setdefault(cell.role, Counter())[cell.status] += 1
    calls = sorted(calls_by_cell.values())
    claim_states = Counter(str(claim.get("state")) for claim in run.claims.values())
    gap_classes = Counter(str(gap.get("gap_class")) for gap in run.gaps.values())
    return {
        "recordings": {"calls": len(run.recordings), "first_attempt_calls": first, "first_attempt_parsed": parsed,
                       "first_attempt_parse_rate": round(parsed / first, 4) if first else None,
                       "repair_calls": repairs, "failed_calls": failed,
                       "by_role": {role: dict(sorted(counter.items())) for role, counter in sorted(by_role.items())}},
        "cells": {"total": len(run.cells), "by_status": dict(sorted(statuses.items())),
                  "by_role": {role: dict(sorted(counter.items())) for role, counter in sorted(by_role_status.items())},
                  "calls_per_cell": {"cells_with_calls": len(calls), "min": calls[0] if calls else None,
                                     "max": calls[-1] if calls else None,
                                     "mean": round(sum(calls) / len(calls), 2) if calls else None}},
        "retrieval": {"executed": executed, "denied": denied, "rows": rows, "denials_by_code": dict(sorted(denials.items())),
                      "executed_by_tool": dict(sorted(tools.items()))},
        "claims": {"total": len(run.claims), "by_state": dict(sorted(claim_states.items()))},
        "gaps_by_class": dict(sorted(gap_classes.items()))}


def _aggregate(run: _Run, defects: Sequence[DefectFunnel]) -> dict[str, Any]:
    furthest = Counter(item.stage for item in defects)
    stopped = Counter(item.stopped_because for item in defects)
    conversion = {}
    for stage in STAGES:
        statuses = [next((r.status for r in item.stages if r.stage == stage), NOT_REACHED) for item in defects]
        conversion[stage] = {"reached": statuses.count(REACHED), "not_applicable": statuses.count(NOT_APPLICABLE)}
    return {"defects": len(defects),
            "by_furthest_stage": {stage: furthest[stage] for stage in ("none", *STAGES) if furthest[stage]},
            "by_stopped_because": dict(sorted(stopped.items())),
            "conversion": conversion, "model_quality": _model_quality(run)}


def evaluate_funnel(run_root: Path, defects: Iterable[Defect]) -> FunnelReport:
    """Follow every defect through the run at ``run_root``. Read-only; never raises on missing artifacts."""

    run = _Run(Path(run_root))
    results = [_evaluate_defect(run, defect) for defect in defects]
    info = {"inference_review_present": run.present, "red_cells": sum(1 for c in run.cells.values() if c.role in RED_ROLES),
            "blue_cells": len(run.role_cells(BLUE_ROLE)), "judge_verdicts": sum(len(v) for v in run.judge.values()),
            "verifier_cells": len(run.role_cells(VERIFIER_ROLE)), "claims": len(run.claims),
            "final_report_present": run.report is not None,
            "admitted_packages": sum(1 for package in run.lead_packages if run.admitted(package))}
    return FunnelReport(Path(run_root).name, results, _aggregate(run, results), info)


# --------------------------------------------------------------------------------------- output

def render_lines(report: FunnelReport) -> list[str]:
    """The compact console table: one line per defect, then the aggregate."""

    lines = [f"funnel run={report.run_id} defects={len(report.defects)} claims={report.run['claims']} "
             f"blue_cells={report.run['blue_cells']} verifier_cells={report.run['verifier_cells']} "
             f"judge_verdicts={report.run['judge_verdicts']} (reported, never asserted)"]
    width = max((len(item.defect_id) for item in report.defects), default=0)
    for item in report.defects:
        place = f"{item.path}:{item.line}"
        claims = ",".join(f"{c['claim_id'][:14]}={c['state']}" for c in item.claims) or "-"
        lines.append(f"   funnel {item.defect_id:<{width}} {place:<22} {item.stage:<11} stopped={item.stopped_because} "
                     f"claims={claims} ship={item.ship_decision or '-'}")
    aggregate = report.aggregate
    lines.append("funnel stages " + " ".join(f"{stage}={aggregate['conversion'][stage]['reached']}"
                                             + (f"(+{aggregate['conversion'][stage]['not_applicable']}na)"
                                                if aggregate['conversion'][stage]['not_applicable'] else "")
                                             for stage in STAGES))
    lines.append("funnel stopped_because " + " ".join(f"{key}={value}"
                                                      for key, value in aggregate["by_stopped_because"].items()))
    quality = aggregate["model_quality"]
    recordings, retrieval = quality["recordings"], quality["retrieval"]
    rate = recordings["first_attempt_parse_rate"]
    lines.append(f"funnel model first_attempt_parse={recordings['first_attempt_parsed']}/{recordings['first_attempt_calls']}"
                 f"{'' if rate is None else f' ({rate:.1%})'} calls={recordings['calls']} failed_calls={recordings['failed_calls']} "
                 f"cells={_flat(quality['cells']['by_status'])} claims={_flat(quality['claims']['by_state'])}")
    lines.append(f"funnel retrieval executed={retrieval['executed']} rows={retrieval['rows']} denied={retrieval['denied']} "
                 f"denials={_flat(retrieval['denials_by_code'])} calls_per_cell_mean="
                 f"{quality['cells']['calls_per_cell']['mean']}")
    return lines


def _flat(values: Mapping[str, int]) -> str:
    return ",".join(f"{key}={values[key]}" for key in sorted(values)) or "-"


def resolve_run(value: str, repo_root: Path) -> Path:
    candidate = Path(value)
    if candidate.is_dir():
        return candidate
    return repo_root / "runs" / value


def main(argv: Sequence[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="Per-defect funnel of a finished run (read-only, reported not asserted)")
    parser.add_argument("--run", required=True, help="a run directory, or a run id under <repo>/runs")
    parser.add_argument("--expectations", type=Path, default=repo_root / DEFAULT_EXPECTATIONS,
                        help="the answer key (default: the cpp-multivuln-v1 key)")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args(argv)
    run_root = resolve_run(args.run, repo_root)
    if not (run_root / "data").is_dir():
        print(f"funnel: no run tree at {run_root}", file=sys.stderr)
        return 2
    _corpus, defects = load_answer_key(args.expectations)
    report = evaluate_funnel(run_root, defects)
    if args.json:
        print(json.dumps(report.as_dict(), indent=1, sort_keys=True))
    else:
        print("\n".join(render_lines(report)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
