"""Deterministic history normalization, change classification, signals, and attention ranking.

Nothing here reads wall-clock time: every window is anchored to the snapshot commit's committer
time.  Commit messages, timestamps, and identities are claimed, target-controlled data; they feed
versioned rules only and every classification records its basis.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
import re
import statistics
from typing import Any


RULES_IDENTITY = "appsec-review/history-change-rules/1"
RANKING_IDENTITY = "appsec-review/history-attention/1"
NORMALIZER_IDENTITY = "appsec-review/history-normalizer/1"
DAY = 86_400
MAX_MESSAGE_BYTES = 65_536
FILE_SIGNALS = (
    "change_count", "churn_lines", "relative_churn", "recency_weighted_churn", "author_count",
    "minor_author_count", "top_author_share", "fix_change_count", "security_fix_change_count",
    "revert_count", "retouch_interval_median_days", "young_line_share", "review_bypass_count",
)
COMPONENT_SIGNALS = (
    "change_count", "churn_lines", "recency_weighted_churn", "author_count", "fix_change_count",
    "security_fix_change_count", "revert_count", "review_bypass_count",
)
# Lower values of these signals indicate more instability, so their percentile is inverted.
INVERTED_SIGNALS = frozenset({"retouch_interval_median_days"})

_REVERT_TRAILER = re.compile(r"This reverts commit ([0-9a-f]{40}|[0-9a-f]{64})")
_SECURITY_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|CWE-\d{1,5})\b", re.I)
_SECURITY_WORDS = re.compile(
    r"\b(security|vulnerab\w*|exploit\w*|xss|csrf|ssrf|xxe|sql injection|command injection|"
    r"path traversal|buffer overflow|use[- ]after[- ]free|rce|privilege escalation|auth(?:entication|orization) bypass)\b",
    re.I)
_FIX_PREFIX = re.compile(r"^(fix|bugfix|hotfix)(\([^)]{0,64}\))?!?:", re.I)
_FIX_WORDS = re.compile(r"\b(fix(?:es|ed)?|bug(?:fix)?|hotfix|regression|crash(?:es|ed)?|"
                        r"(?:closes|resolves) #\d+)\b", re.I)


def _round(value: float) -> float:
    return round(float(value), 6)


def normalize(commits: list[Mapping[str, Any]], *, current_paths: Iterable[str], shallow: Iterable[str],
              window_days: int, max_changes: int, bulk_threshold: int) -> dict[str, Any]:
    """Map walked first-parent commits to current paths and window membership."""
    if not commits:
        return {"changes": [], "anchor_time": None, "gaps": [], "observations": [], "author_count": 0,
                "walked_change_count": 0}
    anchor = int(commits[0]["commit_time"])
    window_start = anchor - window_days * DAY
    alias = {path: path for path in current_paths}
    shallow_set = set(shallow)
    authors: dict[str, int] = {}
    changes: list[dict[str, Any]] = []
    anomalies = 0
    previous_time = anchor
    gaps: list[str] = []
    in_window_count = 0
    reached_window_start = False
    for position, commit in enumerate(commits[:max_changes]):
        claimed = int(commit["commit_time"])
        effective = min(claimed, previous_time)
        if claimed > previous_time:
            anomalies += 1
        previous_time = effective
        author = str(commit["author_key"])
        ordinal = authors.setdefault(author, len(authors) + 1)
        files = []
        for entry in commit["files"]:
            current = alias.get(entry["path"])
            if entry.get("renamed_from"):
                if current is not None:
                    alias[entry["renamed_from"]] = current
            files.append({**entry, "current_path": current})
        in_window = effective >= window_start
        if not in_window:
            reached_window_start = True
            continue
        in_window_count += 1
        if commit["commit"] in shallow_set and window_start > 0:
            gaps.append("shallow_history")
        changes.append({
            "change_id": commit["commit"], "position": position, "parents": list(commit["parents"]),
            "commit_time": claimed, "effective_time": effective, "author_time": int(commit["author_time"]),
            "author": f"author-{ordinal:04d}", "file_count": len(files),
            "bulk": len(files) > bulk_threshold, "files": files,
        })
    if len(commits) > max_changes and not reached_window_start:
        gaps.append("history_window_truncated")
    observations = [f"timestamp_anomaly:{anomalies}"] if anomalies else []
    return {"changes": changes, "anchor_time": anchor, "window_start": window_start,
            "gaps": sorted(set(gaps)), "observations": observations, "author_count": len(authors),
            "walked_change_count": min(len(commits), max_changes), "in_window_change_count": in_window_count}


def classify(changes: list[Mapping[str, Any]], messages: Mapping[str, bytes], github: Mapping[str, Mapping[str, Any]],
             *, known_commits: Iterable[str], fix_labels: Iterable[str], security_labels: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Return classification records keyed by change id; each label records ``exact`` or ``heuristic``."""
    known = set(known_commits)
    fix_set = {label.lower() for label in fix_labels}
    security_set = {label.lower() for label in security_labels}
    result: dict[str, dict[str, Any]] = {}
    reverted_by: dict[str, str] = {}
    for change in changes:
        change_id = str(change["change_id"])
        text = messages.get(change_id, b"")[:MAX_MESSAGE_BYTES].decode("utf-8", "replace")
        subject = text.split("\n", 1)[0].strip()
        labels = set(github.get(change_id, {}).get("labels", ()))
        record: dict[str, Any] = {"fix": None, "security_fix": None, "revert": None, "reverts": None,
                                  "security_references": sorted({item.upper() for item in _SECURITY_ID.findall(text)})[:20]}
        trailer = _REVERT_TRAILER.search(text)
        if trailer and trailer.group(1) in known:
            record["revert"], record["reverts"] = "exact", trailer.group(1)
            reverted_by.setdefault(trailer.group(1), change_id)
        elif subject.startswith('Revert "'):
            record["revert"] = "heuristic"
        if labels & security_set:
            record["security_fix"] = "github_label"
        elif record["security_references"] or _SECURITY_WORDS.search(text):
            record["security_fix"] = "heuristic"
        if labels & fix_set:
            record["fix"] = "github_label"
        elif _FIX_PREFIX.search(subject) or _FIX_WORDS.search(text):
            record["fix"] = "heuristic"
        if record["security_fix"] and not record["fix"]:
            record["fix"] = record["security_fix"]
        result[change_id] = record
    for target, source in reverted_by.items():
        if target in result:
            result[target]["reverted_by"] = source
    return result


def _component_of(path: str, roots: list[tuple[str, str]]) -> str | None:
    for root, component_id in roots:
        if root in {"", "."} or path == root or path.startswith(root.rstrip("/") + "/"):
            return component_id
    return None


def component_roots(components: Iterable[Mapping[str, Any]]) -> list[tuple[str, str]]:
    roots = [(str(item.get("root") or "."), str(item["component_id"])) for item in components]
    return sorted(roots, key=lambda item: (-len(item[0]) if item[0] not in {"", "."} else 1, item[1]))


def compute_signals(changes: list[Mapping[str, Any]], classes: Mapping[str, Mapping[str, Any]],
                    github: Mapping[str, Mapping[str, Any]], *, eligible: Mapping[str, Mapping[str, Any]],
                    roots: list[tuple[str, str]], anchor_time: int | None, half_life_days: int,
                    minor_author_share: float, recent_change_limit: int = 20) -> dict[str, Any]:
    per_file: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "changes": [], "churn": 0, "weighted": 0.0, "authors": defaultdict(int), "fix": 0, "security": 0,
        "revert": 0, "bypass": 0, "times": []})
    per_component: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "changes": set(), "churn": 0, "weighted": 0.0, "authors": set(), "fix": set(), "security": set(),
        "revert": set(), "bypass": set(), "files": set()})
    for change in changes:
        change_id = str(change["change_id"])
        age_days = max(0.0, ((anchor_time or 0) - int(change["effective_time"])) / DAY)
        decay = 0.5 ** (age_days / half_life_days)
        label = classes.get(change_id, {})
        bypass = bool(github.get(change_id, {}).get("review_bypass"))
        touched: dict[str, int] = defaultdict(int)
        for entry in change["files"]:
            current = entry.get("current_path")
            if current in eligible:
                touched[current] += int(entry["added"]) + int(entry["deleted"])
        for path, churn in touched.items():
            item = per_file[path]
            item["changes"].append(change_id)
            item["churn"] += churn
            item["weighted"] += churn * decay
            item["times"].append(int(change["effective_time"]))
            if not change["bulk"]:
                item["authors"][change["author"]] += 1
            item["fix"] += bool(label.get("fix"))
            item["security"] += bool(label.get("security_fix"))
            item["revert"] += bool(label.get("revert") or label.get("reverted_by"))
            item["bypass"] += bypass
            component_id = _component_of(path, roots)
            if component_id is None:
                continue
            component = per_component[component_id]
            component["changes"].add(change_id)
            component["churn"] += churn
            component["weighted"] += churn * decay
            component["files"].add(path)
            if not change["bulk"]:
                component["authors"].add(change["author"])
            for key, flag in (("fix", label.get("fix")), ("security", label.get("security_fix")),
                              ("revert", label.get("revert") or label.get("reverted_by")), ("bypass", bypass)):
                if flag:
                    component[key].add(change_id)
    files: dict[str, dict[str, Any]] = {}
    for path in sorted(per_file):
        item = per_file[path]
        author_total = sum(item["authors"].values())
        times = sorted(item["times"])
        gaps = [(later - earlier) / DAY for earlier, later in zip(times, times[1:])]
        lines = int(eligible[path].get("line_count") or 0)
        files[path] = {
            "path": path, "component_id": _component_of(path, roots),
            "change_count": len(item["changes"]), "churn_lines": item["churn"],
            "relative_churn": _round(item["churn"] / lines) if lines else None,
            "recency_weighted_churn": _round(item["weighted"]),
            "author_count": len(item["authors"]),
            "minor_author_count": sum(1 for count in item["authors"].values()
                                      if author_total and count / author_total < minor_author_share),
            "top_author_share": _round(max(item["authors"].values()) / author_total) if author_total else None,
            "fix_change_count": item["fix"], "security_fix_change_count": item["security"],
            "revert_count": item["revert"], "review_bypass_count": item["bypass"],
            "retouch_interval_median_days": _round(statistics.median(gaps)) if gaps else None,
            "young_line_share": None, "last_change_time": times[-1] if times else None,
            "recent_changes": item["changes"][:recent_change_limit],
        }
    components = {
        component_id: {
            "component_id": component_id, "change_count": len(item["changes"]), "churn_lines": item["churn"],
            "recency_weighted_churn": _round(item["weighted"]), "author_count": len(item["authors"]),
            "fix_change_count": len(item["fix"]), "security_fix_change_count": len(item["security"]),
            "revert_count": len(item["revert"]), "review_bypass_count": len(item["bypass"]),
            "file_count": len(item["files"]),
        }
        for component_id, item in sorted(per_component.items())
    }
    return {"files": files, "components": components}


def co_change(changes: list[Mapping[str, Any]], *, eligible: Iterable[str], roots: list[tuple[str, str]],
              top_k: int, min_support: int) -> dict[str, list[dict[str, Any]]]:
    allowed = set(eligible)
    pairs: dict[tuple[str, str], int] = defaultdict(int)
    totals: dict[str, int] = defaultdict(int)
    for change in changes:
        if change["bulk"]:
            continue
        touched = sorted({entry["current_path"] for entry in change["files"] if entry.get("current_path") in allowed})
        for path in touched:
            totals[path] += 1
        for index, left in enumerate(touched):
            for right in touched[index + 1:]:
                pairs[(left, right)] += 1
    partners: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for (left, right), support in pairs.items():
        if support < min_support:
            continue
        cross = _component_of(left, roots) != _component_of(right, roots)
        partners[left].append({"path": right, "support": support,
                               "confidence": _round(support / totals[left]), "cross_component": cross})
        partners[right].append({"path": left, "support": support,
                                "confidence": _round(support / totals[right]), "cross_component": cross})
    return {path: sorted(values, key=lambda item: (-item["support"], item["path"]))[:top_k]
            for path, values in sorted(partners.items())}


def _percentiles(values: Mapping[str, float]) -> dict[str, float]:
    ordered = sorted(values.values())
    count = len(ordered)
    result = {}
    for key, value in values.items():
        below = sum(1 for item in ordered if item < value)
        equal = sum(1 for item in ordered if item == value)
        result[key] = _round((below + 0.5 * equal) / count)
    return result


def rank(records: Mapping[str, Mapping[str, Any]], weights: Mapping[str, float], *, signals: tuple[str, ...]) -> list[dict[str, Any]]:
    """Weighted mid-rank percentiles over records with history; ties break on the stable key."""
    population = {key: value for key, value in records.items() if int(value.get("change_count") or 0) > 0}
    if not population:
        return []
    percentiles: dict[str, dict[str, float]] = {}
    for signal in signals:
        if float(weights.get(signal, 0)) <= 0:
            continue
        present = {key: float(value[signal]) for key, value in population.items() if value.get(signal) is not None}
        if not present:
            continue
        computed = _percentiles(present)
        if signal in INVERTED_SIGNALS:
            computed = {key: _round(1 - value) for key, value in computed.items()}
        percentiles[signal] = computed
    ranked = []
    for key in population:
        used = {signal: values[key] for signal, values in percentiles.items() if key in values}
        total_weight = sum(float(weights[signal]) for signal in used)
        score = sum(float(weights[signal]) * value for signal, value in used.items()) / total_weight if total_weight else 0.0
        ranked.append({"key": key, "score": _round(score), "percentiles": dict(sorted(used.items()))})
    ranked.sort(key=lambda item: (-item["score"], item["key"]))
    for position, item in enumerate(ranked, 1):
        item["rank"] = position
    return ranked
