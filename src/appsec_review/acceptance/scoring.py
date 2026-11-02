"""Score detectors against an answer key, CASTLE style (docs/reviews/castle-style-detector-scoring.md).

The key (``expectations.toml``) lists defect cases (``[[defect]]``) and negative controls
(``[[control]]``). Each report of a producer in a scored path is attributed to at most one case
(decision 2) and classified (decision 3); per producer this gives the CASTLE score (paper eq. 1-2,
decision 6) and the plain TP/FP/FN/TN metrics (decision 7), and over producer sets the CASTLE
combination score and each producer's marginal contribution (decision 8).

Everything here is **reported, never asserted**: no score changes a verdict, and a low score is a
statement about detectors, never evidence that a target is clean. Reports in a scored path that no
case covers are *unattributed*: listed, never scored, because unlabelled code is not known to be clean.
Reference tables are read from the pinned files under ``data/reference/scoring``; nothing is fetched.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

from .funnel import DEFAULT_EXPECTATIONS, resolve_run
from .scoring_model import (CWE_MATCH_REFERENCE, DEFAULT_MAX_COMBINATION, DEFAULT_TOLERANCE, DEFAULT_TOP_LIST,
                            FILE_SCOPE, SCORING_SCHEMA, TOP25_REFERENCE, EntryKind, KeyEntry, Report,
                            ReportOutcome, ScoringKey, normalize_cwe)

TOP25_SCHEMA = "appsec-review/cwe-top25/1"
CWE_MATCH_SCHEMA = "appsec-review/cwe-match/1"
NO_NEGATIVE_CONTROLS = "no_negative_controls"
DETECTION_POINTS = 5  # paper eq. 2: a detected defect
CONTROL_POINTS = 2  # paper eq. 2: a silent negative control
BONUS_MAX = 5  # paper eq. 1: b_max
_LOCATION_HITS = frozenset({ReportOutcome.HIT, ReportOutcome.LOCATION_HIT_CWE_MISS,
                            ReportOutcome.LOCATION_HIT_CWE_UNKNOWN})


# ------------------------------------------------------------------------------------------ key

def _integer(item: Mapping[str, Any], name: str, entry_id: str) -> int:
    value = item[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{entry_id}: {name} must be an integer")
    return value


def _optional_text(item: Mapping[str, Any], name: str, entry_id: str) -> str | None:
    value = item.get(name)
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{entry_id}: {name} must be a non-empty string")
    return value


def _entry(item: Any, kind: EntryKind, source: Path) -> KeyEntry:
    if not isinstance(item, Mapping):
        raise ValueError(f"{source}: every [[{kind.value}]] must be a table")
    entry_id = item.get("id")
    if not isinstance(entry_id, str) or not entry_id:
        raise ValueError(f"{source}: a [[{kind.value}]] needs an id")
    path = item.get("path")
    if not isinstance(path, str) or not path:
        raise ValueError(f"{entry_id}: needs a path")
    lines: tuple[int, ...] | None = None
    if "line" in item:
        line = _integer(item, "line", entry_id)
        end_line = _integer(item, "end_line", entry_id) if "end_line" in item else line
        if line < 1:
            raise ValueError(f"{entry_id}: line must be positive")
        if end_line < line:
            raise ValueError(f"{entry_id}: end_line precedes line")
        lines = tuple(range(line, end_line + 1))
    elif "end_line" in item:
        raise ValueError(f"{entry_id}: end_line needs line")
    if "lines" in item:
        explicit = item["lines"]
        if (not isinstance(explicit, list) or not explicit
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in explicit)):
            raise ValueError(f"{entry_id}: lines must be a non-empty list of positive integers")
        lines = tuple(sorted(set(explicit)))
    if lines is None:
        raise ValueError(f"{entry_id}: needs line (or lines)")
    raw_cwe = item.get("cwe")
    cwe = None if raw_cwe is None else normalize_cwe(raw_cwe)
    if raw_cwe is not None and cwe is None:
        raise ValueError(f"{entry_id}: unrecognised cwe {raw_cwe!r}")
    if kind is EntryKind.DEFECT and cwe is None:
        raise ValueError(f"{entry_id}: a defect needs a cwe")
    has_start, has_end = "scope_start" in item, "scope_end" in item
    if has_start != has_end:
        raise ValueError(f"{entry_id}: scope_start and scope_end go together")
    scope: tuple[int, int] | None
    if "scope" in item:
        if item["scope"] != FILE_SCOPE:
            raise ValueError(f"{entry_id}: scope must be {FILE_SCOPE!r}")
        if has_start:
            raise ValueError(f"{entry_id}: scope = {FILE_SCOPE!r} excludes scope_start/scope_end")
        scope = None
    elif has_start:
        scope = (_integer(item, "scope_start", entry_id), _integer(item, "scope_end", entry_id))
        if not 1 <= scope[0] <= lines[0] or lines[-1] > scope[1]:
            raise ValueError(f"{entry_id}: scope {scope[0]}..{scope[1]} does not contain its lines")
    else:
        scope = (lines[0], lines[-1])
    producers = item.get("producers", [])
    if not isinstance(producers, list) or not all(isinstance(name, str) and name for name in producers):
        raise ValueError(f"{entry_id}: producers must be a list of names")
    if producers and kind is EntryKind.CONTROL:
        raise ValueError(f"{entry_id}: producers are given only on defects")
    summary = item.get("summary", "")
    if not isinstance(summary, str):
        raise ValueError(f"{entry_id}: summary must be a string")
    return KeyEntry(id=entry_id, kind=kind, path=path, cwe=cwe, lines=lines, scope=scope, summary=summary,
                    pair=_optional_text(item, "pair", entry_id), upstream=_optional_text(item, "upstream", entry_id),
                    producers=tuple(producers))


def _check_scopes(entries: Sequence[KeyEntry]) -> None:
    by_path: dict[str, list[KeyEntry]] = {}
    for entry in entries:
        by_path.setdefault(entry.path, []).append(entry)
    for path, group in sorted(by_path.items()):
        if len(group) > 1 and any(entry.scope is None for entry in group):
            raise ValueError(f"{path}: a file-scope case shares its file with "
                             + ", ".join(sorted(entry.id for entry in group)))
        ordered = sorted(group, key=lambda entry: (entry.scope, entry.id))
        for first, second in zip(ordered, ordered[1:]):
            if second.scope[0] <= first.scope[1]:  # type: ignore[index]
                raise ValueError(f"{path}: scopes of {first.id} and {second.id} overlap")


def load_scoring_key(path: Path) -> ScoringKey:
    """Read ``[corpus]``, ``[[defect]]`` and ``[[control]]`` of a key (decision 1); reject inconsistent keys."""

    path = Path(path)
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    corpus = document.get("corpus", {})
    if not isinstance(corpus, dict):
        raise ValueError(f"{path}: [corpus] must be a table")
    scored_paths = corpus.get("scored_paths", [])
    if not isinstance(scored_paths, list) or not all(isinstance(item, str) and item for item in scored_paths):
        raise ValueError(f"{path}: scored_paths must be a list of path prefixes")
    entries: list[KeyEntry] = []
    for table, kind in (("defect", EntryKind.DEFECT), ("control", EntryKind.CONTROL)):
        items = document.get(table, [])
        if not isinstance(items, list):
            raise ValueError(f"{path}: {table} must be an array of tables")
        entries.extend(_entry(item, kind, path) for item in items)
    if not entries:
        raise ValueError(f"{path} lists no defects or controls")
    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            raise ValueError(f"{path} repeats the id {entry.id}")
        seen.add(entry.id)
    key = ScoringKey(corpus=dict(corpus), entries=tuple(entries), scored_paths=tuple(scored_paths))
    for entry in entries:
        if entry.pair is not None and (entry.pair not in seen or entry.pair == entry.id):
            raise ValueError(f"{entry.id}: pair names no other entry: {entry.pair}")
        if not key.is_scored(entry.path):
            raise ValueError(f"{entry.id}: {entry.path} is outside scored_paths")
    _check_scopes(entries)
    return key


# ------------------------------------------------------------------------------------ reference

def _read_json(path: Path, schema: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != schema:
        raise ValueError(f"{path}: expected schema {schema}")
    return document


def load_top_list(name: str = DEFAULT_TOP_LIST, path: Path = TOP25_REFERENCE) -> dict[str, int]:
    """The pinned Top-25 standings ``{"CWE-<n>": rank}`` of list ``name``; an unknown name is a ValueError."""

    lists = _read_json(path, TOP25_SCHEMA).get("lists", {})
    if not isinstance(lists, dict) or name not in lists:
        raise ValueError(f"unknown top list {name!r}; pinned: {', '.join(sorted(lists)) if isinstance(lists, dict) else '-'}")
    ranks = {}
    for cwe, rank in lists[name]["ranks"].items():
        normalized = normalize_cwe(cwe)
        if normalized is None or isinstance(rank, bool) or not isinstance(rank, int) or not 1 <= rank <= 25:
            raise ValueError(f"{path}: invalid rank {cwe}={rank!r} in {name}")
        ranks[normalized] = rank
    return ranks


def load_cwe_match(path: Path = CWE_MATCH_REFERENCE) -> dict[str, frozenset[str]]:
    """Key CWE -> the report CWEs accepted for it (always including itself). One-way, never symmetric."""

    table = {}
    for cwe, row in _read_json(path, CWE_MATCH_SCHEMA).get("accepts", {}).items():
        key = normalize_cwe(cwe)
        accepted = {normalize_cwe(value) for value in row.get("accepts", ())}
        if key is None or None in accepted:
            raise ValueError(f"{path}: invalid entry {cwe}")
        table[key] = frozenset(accepted | {key})
    return table


def bonus(cwe: str | None, ranks: Mapping[str, int]) -> int:
    """Paper eq. 1: ``5 - floor((S - 1) / 5)`` for a Top-25 rank ``S``, else 0."""

    rank = ranks.get(cwe) if cwe else None
    return BONUS_MAX - (rank - 1) // BONUS_MAX if rank is not None and rank <= 25 else 0


# -------------------------------------------------------------------------------------- scoring

def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else round(numerator / denominator, 4)


def _collapse(reports: Iterable[Report]) -> list[Report]:
    """One report per identity (decision 4): the first after a total sort, with the union of the CWEs."""

    merged: dict[tuple[str, str, int, str], Report] = {}
    for report in sorted(reports, key=lambda item: (item.identity, item.end_line, item.evidence, sorted(item.cwes))):
        first = merged.get(report.identity)
        merged[report.identity] = report if first is None else Report(
            first.producer, first.path, first.start_line, first.end_line, first.rule,
            first.cwes | report.cwes, first.evidence)
    return list(merged.values())


def _attribute(report: Report, cases: Sequence[KeyEntry], tolerance: int) -> KeyEntry | None:
    """Decision 2. ``cases`` are one file's cases in line order; their scopes do not overlap.

    A scope that contains the start line wins; else the first widened scope containing it; else the
    first widened scope overlapping the report's lines.
    """

    def span(entry: KeyEntry, widen: int) -> tuple[float, float]:
        if entry.scope is None:
            return (float("-inf"), float("inf"))
        return (entry.scope[0] - widen, entry.scope[1] + widen)

    for widen in (0, tolerance):
        for entry in cases:
            low, high = span(entry, widen)
            if low <= report.start_line <= high:
                return entry
    for entry in cases:
        low, high = span(entry, tolerance)
        if low <= report.end_line and report.start_line <= high:
            return entry
    return None


def _classify(report: Report, entry: KeyEntry, tolerance: int, accepts: Mapping[str, frozenset[str]]) -> ReportOutcome:
    """Decision 3: how an attributed report relates to its case."""

    if entry.kind is EntryKind.CONTROL:
        return ReportOutcome.CONTROL
    if not any(report.start_line - tolerance <= line <= report.end_line + tolerance for line in entry.lines):
        return ReportOutcome.OFF_LOCATION
    if not report.cwes:
        return ReportOutcome.LOCATION_HIT_CWE_UNKNOWN
    accepted = accepts.get(entry.cwe, frozenset({entry.cwe}))  # type: ignore[arg-type]
    return ReportOutcome.HIT if report.cwes & accepted else ReportOutcome.LOCATION_HIT_CWE_MISS


def _case_score(entry: KeyEntry, cells: Iterable[tuple[int, bool]], case_bonus: int) -> int:
    """Decision 8 over ``(|t_k|, hit_k)`` of each member; with one member it is decision 6 (paper eq. 2)."""

    cells = list(cells)
    total = sum(count for count, _hit in cells)
    if entry.kind is EntryKind.DEFECT:
        hitters = sum(1 for _count, hit in cells if hit)
        # extra_k = |t_k| - 1 for a member that hit and |t_k| otherwise: sum(extra_k) = total - hitters.
        return DETECTION_POINTS + case_bonus - (total - hitters) if hitters else -total
    return CONTROL_POINTS if total == 0 else -total


def _report_dict(report: Report) -> dict[str, Any]:
    return {"path": report.path, "start_line": report.start_line, "end_line": report.end_line,
            "rule": report.rule, "cwes": sorted(report.cwes, key=lambda cwe: int(cwe[4:])), "evidence": report.evidence}


@dataclass(frozen=True)
class ProducerScore:
    producer: str
    reports: int  # collapsed reports in scored paths, attributed or not
    castle_score: int
    tp: int
    fp: int  # attributed non-hit reports, counted per report
    fn: int
    tn: int | None  # None when the key has no negative controls
    fp_cases: int  # cases with any attributed non-hit report
    lenient_tp: int  # defect cases with a hit or a location_hit_* report; never scored
    precision: float | None
    recall: float | None
    accuracy: float | None
    outcomes: dict[str, int]
    unattributed: tuple[Report, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"producer": self.producer, "reports": self.reports, "castle_score": self.castle_score,
                "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn, "tn_measurable": self.tn is not None,
                "fp_cases": self.fp_cases, "lenient_tp": self.lenient_tp, "precision": self.precision,
                "recall": self.recall, "accuracy": self.accuracy, "outcomes": dict(self.outcomes),
                "unattributed": len(self.unattributed),
                "unattributed_reports": [_report_dict(report) for report in self.unattributed]}


@dataclass(frozen=True)
class ScoringReport:
    corpus: dict[str, str | None]
    tolerance: int
    top_list: str
    max_score: int
    floor_score: int
    defects: int
    controls: int
    producers: tuple[ProducerScore, ...]
    cases: tuple[dict[str, Any], ...]
    full_set: dict[str, Any]
    best_combinations: tuple[dict[str, Any], ...]
    marginal: dict[str, int]
    reference_comparison: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    ignored_reports: int  # reports outside [corpus] scored_paths, never scored

    def as_dict(self) -> dict[str, Any]:
        return {"schema": SCORING_SCHEMA, "corpus": dict(self.corpus), "tolerance": self.tolerance,
                "top_list": self.top_list, "max_score": self.max_score, "floor_score": self.floor_score,
                "defects": self.defects, "controls": self.controls,
                "producers": [producer.as_dict() for producer in self.producers],
                "cases": [dict(case) for case in self.cases], "full_set": dict(self.full_set),
                "best_combinations": [dict(item) for item in self.best_combinations],
                "marginal": dict(self.marginal), "reference_comparison": [dict(row) for row in self.reference_comparison],
                "gaps": list(self.gaps), "ignored_reports": self.ignored_reports}


def _reference_rows(reference: Mapping[str, Any] | None, scores: Mapping[str, ProducerScore]) -> list[dict[str, Any]]:
    rows = reference.get("paper_reference") if isinstance(reference, Mapping) else None
    comparison = []
    for row in rows if isinstance(rows, list) else ():
        producer = row.get("producer") if isinstance(row, Mapping) else None
        if not isinstance(producer, str) or producer.lower() not in scores:
            continue
        ours = scores[producer.lower()]
        comparison.append({
            "producer": producer.lower(),
            "paper": {name: row.get(name) for name in ("tool", "version", "tp", "tn", "fp", "fn", "castle_score")},
            "ours": {"tp": ours.tp, "tn": ours.tn, "fp": ours.fp, "fn": ours.fn, "castle_score": ours.castle_score}})
    return sorted(comparison, key=lambda item: (item["producer"], str(item["paper"]["tool"]), str(item["paper"]["version"])))


def score(key: ScoringKey, reports: Iterable[Report], *, tolerance: int = DEFAULT_TOLERANCE,
          top_list: str = DEFAULT_TOP_LIST, max_combination: int = DEFAULT_MAX_COMBINATION,
          producers: Iterable[str] | None = None, gaps: Iterable[str] = (),
          reference: Mapping[str, Any] | None = None) -> ScoringReport:
    """Score every producer's reports against ``key``. Deterministic; never raises on a bad report set."""

    if isinstance(tolerance, bool) or not isinstance(tolerance, int) or tolerance < 0:
        raise ValueError("tolerance must be a non-negative integer")
    if isinstance(max_combination, bool) or not isinstance(max_combination, int) or max_combination < 0:
        raise ValueError("max_combination must be a non-negative integer")
    ranks = load_top_list(top_list)
    accepts = load_cwe_match()
    reports = list(reports)
    wanted = None if producers is None else {name.strip().lower() for name in producers if name.strip()}
    names = sorted(wanted if wanted is not None else {report.producer for report in reports})
    selected = [report for report in reports if wanted is None or report.producer in wanted]
    in_scope = [report for report in selected if key.is_scored(report.path)]
    ignored = len(selected) - len(in_scope)

    by_path: dict[str, list[KeyEntry]] = {}
    for entry in key.entries:
        by_path.setdefault(entry.path, []).append(entry)
    for group in by_path.values():
        group.sort(key=lambda entry: (entry.scope or (0, 0), entry.id))
    case_bonus = {entry.id: bonus(entry.cwe, ranks) if entry.kind is EntryKind.DEFECT else 0 for entry in key.entries}

    attributed: dict[str, dict[str, list[ReportOutcome]]] = {name: {} for name in names}
    unattributed: dict[str, list[Report]] = {name: [] for name in names}
    outcomes: dict[str, dict[str, int]] = {name: {item.value: 0 for item in ReportOutcome} for name in names}
    collapsed = _collapse(in_scope)
    for report in collapsed:
        entry = _attribute(report, by_path.get(report.path, ()), tolerance)
        outcome = ReportOutcome.UNATTRIBUTED if entry is None else _classify(report, entry, tolerance, accepts)
        outcomes[report.producer][outcome.value] += 1
        if entry is None:
            unattributed[report.producer].append(report)
        else:
            attributed[report.producer].setdefault(entry.id, []).append(outcome)

    def cell(name: str, entry: KeyEntry) -> tuple[int, bool]:
        found = attributed[name].get(entry.id, ())
        return len(found), ReportOutcome.HIT in found

    def set_score(members: Sequence[str]) -> int:
        return sum(_case_score(entry, (cell(name, entry) for name in members), case_bonus[entry.id])
                   for entry in key.entries)

    measurable = bool(key.controls)
    producer_scores = []
    for name in names:
        tp = sum(1 for entry in key.defects if cell(name, entry)[1])
        fn = len(key.defects) - tp
        tn = sum(1 for entry in key.controls if cell(name, entry)[0] == 0) if measurable else None
        found = attributed[name]
        fp = sum(1 for items in found.values() for outcome in items if outcome is not ReportOutcome.HIT)
        fp_cases = sum(1 for items in found.values() if any(outcome is not ReportOutcome.HIT for outcome in items))
        lenient = sum(1 for entry in key.defects if _LOCATION_HITS.intersection(found.get(entry.id, ())))
        producer_scores.append(ProducerScore(
            producer=name, reports=sum(1 for report in collapsed if report.producer == name),
            castle_score=set_score((name,)), tp=tp, fp=fp, fn=fn, tn=tn, fp_cases=fp_cases, lenient_tp=lenient,
            precision=_ratio(tp, tp + fp), recall=_ratio(tp, tp + fn),
            accuracy=_ratio(tp + tn, tp + tn + fp + fn) if tn is not None else None,
            outcomes=outcomes[name], unattributed=tuple(unattributed[name])))

    cases = []
    for entry in key.entries:
        present = [name for name in names if entry.id in attributed[name]]
        case_outcomes = {}
        for name in present:
            counts: dict[str, int] = {}
            for outcome in attributed[name][entry.id]:
                counts[outcome.value] = counts.get(outcome.value, 0) + 1
            case_outcomes[name] = dict(sorted(counts.items()))
        cases.append({"id": entry.id, "kind": entry.kind.value, "path": entry.path, "cwe": entry.cwe,
                      "bonus": case_bonus[entry.id] if entry.kind is EntryKind.DEFECT else None,
                      "hit_by": [name for name in present if cell(name, entry)[1]], "outcomes": case_outcomes,
                      "scores": {name: _case_score(entry, (cell(name, entry),), case_bonus[entry.id]) for name in names}})

    full_score = set_score(names)
    active = [name for name in names if attributed[name]]
    best = []
    for size in range(1, min(max_combination, len(active)) + 1):
        ranked = sorted(((set_score(members), members) for members in combinations(active, size)),
                        key=lambda item: (-item[0], item[1]))
        best.append({"size": size, "producers": list(ranked[0][1]), "castle_score": ranked[0][0]})
    marginal = {name: full_score - set_score([other for other in names if other != name]) for name in names}

    all_gaps = list(gaps)
    if not measurable:
        all_gaps.append(NO_NEGATIVE_CONTROLS)
    by_name = {item.producer: item for item in producer_scores}
    return ScoringReport(
        corpus={name: (None if key.corpus.get(name) is None else str(key.corpus[name])) for name in ("name", "tag", "commit")},
        tolerance=tolerance, top_list=top_list,
        max_score=sum(DETECTION_POINTS + case_bonus[entry.id] for entry in key.defects) + CONTROL_POINTS * len(key.controls),
        floor_score=CONTROL_POINTS * len(key.controls), defects=len(key.defects), controls=len(key.controls),
        producers=tuple(producer_scores), cases=tuple(cases),
        full_set={"producers": list(names), "castle_score": full_score}, best_combinations=tuple(best),
        marginal=marginal, reference_comparison=tuple(_reference_rows(reference, by_name)),
        gaps=tuple(dict.fromkeys(all_gaps)), ignored_reports=ignored)


# --------------------------------------------------------------------------------------- output

def _number(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def render_lines(report: ScoringReport) -> list[str]:
    """The compact console summary: one line per producer, then sets, marginal contributions and gaps."""

    corpus = report.corpus
    lines = [f"   scoring corpus={corpus.get('name') or '-'} tag={corpus.get('tag') or '-'} defects={report.defects} "
             f"controls={report.controls} tolerance={report.tolerance} top_list={report.top_list} "
             f"max={report.max_score} floor={report.floor_score} (reported, never asserted)"]
    for item in report.producers:
        lines.append(f"   scoring {item.producer} castle={item.castle_score} tp={item.tp} fp={item.fp} fn={item.fn} "
                     f"tn={'n/a' if item.tn is None else item.tn} precision={_number(item.precision)} "
                     f"recall={_number(item.recall)} accuracy={_number(item.accuracy)} lenient_tp={item.lenient_tp} "
                     f"fp_cases={item.fp_cases} unattributed={len(item.unattributed)}")
    lines.append(f"   scoring full_set castle={report.full_set['castle_score']} "
                 f"producers={','.join(report.full_set['producers']) or '-'}")
    for item in report.best_combinations:
        lines.append(f"   scoring best size={item['size']} castle={item['castle_score']} producers={','.join(item['producers'])}")
    for name, value in report.marginal.items():
        lines.append(f"   scoring marginal {name}={value:+d}" + (" net-negative" if value < 0 else ""))
    for row in report.reference_comparison:
        paper, ours = row["paper"], row["ours"]
        lines.append(f"   scoring reference {row['producer']} paper={paper['tool']} {paper['version']} "
                     f"castle={paper['castle_score']} tp={paper['tp']} fp={paper['fp']} | ours castle={ours['castle_score']} "
                     f"tp={ours['tp']} fp={ours['fp']}")
    if report.gaps:
        lines.append("   scoring gaps " + "; ".join(report.gaps))
    return lines


def score_run(run_root: Path, expectations: Path, *, include_review: bool = False,
              tolerance: int = DEFAULT_TOLERANCE, top_list: str = DEFAULT_TOP_LIST,
              max_combination: int = DEFAULT_MAX_COMBINATION, producers: Iterable[str] | None = None,
              repo_root: Path | None = None) -> ScoringReport:
    """Score a finished run's producer reports against a scoring key; the shared path of the CLI and stepwise."""

    from .producer_reports import reports_from_run

    repo_root = repo_root or Path(__file__).resolve().parents[3]
    key = load_scoring_key(expectations)
    reports, gaps = reports_from_run(run_root, include_review=include_review)
    gaps = list(gaps)
    reference = None
    lock = key.corpus.get("reference_lock")
    if isinstance(lock, str) and lock:
        lock_path = repo_root / lock
        if lock_path.is_file():
            reference = json.loads(lock_path.read_text(encoding="utf-8"))
        else:
            gaps.append(f"reference_lock_missing: {lock}")
    return score(key, reports, tolerance=tolerance, top_list=top_list, max_combination=max_combination,
                 producers=producers, gaps=gaps, reference=reference)


def main(argv: Sequence[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description="CASTLE-style detector scoring of a finished run (reported, never asserted)")
    parser.add_argument("--run", required=True, help="a run directory, or a run id under <repo>/runs")
    parser.add_argument("--expectations", type=Path, default=repo_root / DEFAULT_EXPECTATIONS,
                        help="the scoring key (default: the cpp-multivuln-v1 key)")
    parser.add_argument("--tolerance", type=int, default=DEFAULT_TOLERANCE)
    parser.add_argument("--include-review", action="store_true", help="score accepted final findings as producer 'review'")
    parser.add_argument("--producers", default=None, help="comma-separated producers to score (default: every producer)")
    parser.add_argument("--max-combination", type=int, default=DEFAULT_MAX_COMBINATION)
    parser.add_argument("--top-list", default=DEFAULT_TOP_LIST)
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args(argv)
    run_root = resolve_run(args.run, repo_root)
    if not (run_root / "data").is_dir():
        print(f"scoring: no run tree at {run_root}", file=sys.stderr)
        return 2
    try:
        producers = None if args.producers is None else [name for name in args.producers.split(",") if name.strip()]
        report = score_run(run_root, args.expectations, include_review=args.include_review,
                           tolerance=args.tolerance, top_list=args.top_list, max_combination=args.max_combination,
                           producers=producers, repo_root=repo_root)
    except (OSError, ValueError) as error:
        print(f"scoring: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.as_dict(), indent=1, sort_keys=True))
    else:
        print("\n".join(render_lines(report)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
