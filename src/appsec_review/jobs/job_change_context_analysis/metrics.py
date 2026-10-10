"""Deterministic change-context signals, unit aggregation, and review-priority ranking.

Nothing here reads wall-clock time or the local time zone.  Every timestamp is either an observed
review-host or deployment fact, or a claimed Git time, and each derived value records which basis it
used.  Missing sources produce ``None`` values with an ``unavailable`` or ``partial`` availability,
never zero.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone, tzinfo
import math
import re
import statistics
from typing import Any

from .settings import ChangeContextSettings, PRIORITY_SIGNALS


RULES_IDENTITY = "appsec-review/change-context-rules/1"
TEST_ASSOCIATION_IDENTITY = "appsec-review/test-association/1"
PRIORITY_IDENTITY = "appsec-review/change-context-priority/1"
DAY = 86_400
REVIEW_SIGNALS = ("fast_review_change_count", "stale_approval_change_count", "unapproved_mainline_change_count")
_TEST_AFFIXES = (re.compile(r"^(test_|tests_|spec_)", re.I),
                 re.compile(r"(_test|_tests|_spec|\.test|\.spec|test|tests|spec)$", re.I))


def _round(value: float) -> float:
    return round(float(value), 6)


def glob_regex(pattern: str) -> re.Pattern[str]:
    """Translate a ``**``-aware POSIX glob; ``**/`` matches zero or more directories."""
    out, index = [], 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        elif pattern[index] == "{":
            close = pattern.find("}", index)
            if close < 0:
                raise ValueError(f"unbalanced brace in pattern: {pattern}")
            out.append("(?:" + "|".join(re.escape(item) for item in pattern[index + 1:close].split(",")) + ")")
            index = close + 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out))


class PathRoles:
    """Explicit path-role rules: test, contract, production, or other."""

    def __init__(self, settings: ChangeContextSettings):
        tests = settings.test_association
        self.tests = [glob_regex(item) for item in tests.test_patterns]
        self.contracts = [glob_regex(item) for item in tests.contract_patterns]
        self.extensions = set(tests.production_extensions)

    def role(self, path: str) -> str:
        if any(item.fullmatch(path) for item in self.tests):
            return "test"
        if any(item.fullmatch(path) for item in self.contracts):
            return "contract"
        name = path.rsplit("/", 1)[-1]
        suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return "production" if suffix in self.extensions else "other"


def _stem(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.split(".", 1)[0].lower() if not name.startswith(".") else name.lower()


def test_subject(path: str) -> str:
    """Strip one leading and one trailing test affix from a test file stem."""
    name = path.rsplit("/", 1)[-1]
    base = name.rsplit(".", 1)[0] if "." in name else name
    base = _TEST_AFFIXES[0].sub("", base, count=1)
    base = _TEST_AFFIXES[1].sub("", base, count=1)
    return base.lower()


def component_of(path: str, roots: list[tuple[str, str]]) -> str | None:
    for root, component_id in roots:
        if root in {"", "."} or path == root or path.startswith(root.rstrip("/") + "/"):
            return component_id
    return None


def _zone_local(epoch: int, zone: tzinfo) -> datetime:
    return datetime.fromtimestamp(epoch, timezone.utc).astimezone(zone)


# ----------------------------------------------------------------------------------------------
# Per-change facts and classifications


def review_facts(record: Mapping[str, Any] | None, fast_seconds: int) -> dict[str, Any]:
    """Derive review-speed facts for one change's review record (or its absence)."""
    if record is None:
        return {"status": "missing"}
    if record["direct_push"]:
        return {"status": "known", "pull_request": None, "direct_push": True, "unapproved_mainline": True,
                "merged_head_approved": None, "stale_approval": None, "fast_approval": None, "fast_merge": None,
                "creation_to_first_approval_seconds": None, "final_head_to_approval_seconds": None,
                "creation_to_merge_seconds": None}
    approvals = record.get("approvals")
    approved = record.get("approved_by_other")
    head = record.get("head_sha")
    created, merged = record.get("created_at"), record.get("merged_at")
    timed = [item for item in approvals or () if item["submitted_at"] is not None]
    first = timed[0]["submitted_at"] if timed else None
    head_approvals = [item for item in timed if head is not None and item["commit_id"] == head]
    on_head = (any(item["commit_id"] == head for item in approvals) if approvals is not None and head is not None
               else None)
    creation_to_first = first - created if first is not None and created is not None else None
    head_time = record.get("head_committed_at")
    final_to_approval = (head_approvals[0]["submitted_at"] - head_time
                         if head_approvals and head_time is not None else None)
    creation_to_merge = merged - created if merged is not None and created is not None else None
    fast_approval = None
    if creation_to_first is not None or final_to_approval is not None:
        fast_approval = any(value is not None and 0 <= value < fast_seconds
                            for value in (creation_to_first, final_to_approval))
    return {
        "status": "known" if record.get("complete") else "incomplete",
        "pull_request": record.get("pull_request"), "direct_push": False,
        "unapproved_mainline": (approved is False) if approved is not None else None,
        "merged_head_approved": on_head,
        "stale_approval": (bool(approved) and on_head is False) if approved is not None and on_head is not None else None,
        "fast_approval": fast_approval,
        "fast_merge": (0 <= creation_to_merge < fast_seconds) if creation_to_merge is not None else None,
        "creation_to_first_approval_seconds": creation_to_first,
        "final_head_to_approval_seconds": final_to_approval,
        "creation_to_merge_seconds": creation_to_merge,
        "final_head_time_basis": "git_committer_time_claimed" if final_to_approval is not None else None,
    }


def landed_time(change: Mapping[str, Any], record: Mapping[str, Any] | None) -> tuple[int, str]:
    if record is not None and record.get("merged_at") is not None:
        return int(record["merged_at"]), "review_host_merged_at"
    return int(change["commit_time"]), "git_committer_time_claimed"


def schedule_facts(epoch: int, zone: tzinfo | None, settings: ChangeContextSettings) -> dict[str, Any]:
    if zone is None:
        return {"status": "unavailable", "off_hours": None, "local_time": None}
    local = _zone_local(epoch, zone)
    minute = local.hour * 60 + local.minute
    schedule = settings.schedule
    off = local.weekday() in schedule.weekend_days or not schedule.business_start_minute <= minute < schedule.business_end_minute
    return {"status": "available", "off_hours": off, "local_time": local.isoformat(),
            "time_zone": schedule.time_zone, "weekday": local.strftime("%A").lower()}


def deployment_facts(changes: list[Mapping[str, Any]], landed: Mapping[str, int], walked: list[str],
                     deployments: Mapping[str, Any] | None, window_seconds: int) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Match each change to the first configured-environment deployment that shipped it.

    A deployment ships a change when its deployed commit is the change or a first-parent descendant
    of it in the walked mainline.  Deployment proximity is never derived from commit time alone.
    """
    if deployments is None:
        return {str(change["change_id"]): {"status": "unavailable"} for change in changes}, []
    position = {commit: index for index, commit in enumerate(walked)}
    events = [event for event in deployments["events"] if event["commit"] in position]
    unmatched = len(deployments["events"]) - len(events)
    gaps = ["deployment_commit_not_in_history"] if unmatched else []
    start, end = deployments["coverage"]["start"], deployments["coverage"]["end"]
    result: dict[str, dict[str, Any]] = {}
    for change in changes:
        change_id = str(change["change_id"])
        when = landed[change_id]
        if when < start:
            result[change_id] = {"status": "outside_coverage"}
            continue
        shipping = next((event for event in events if position[event["commit"]] <= int(change["position"])), None)
        if shipping is None:
            result[change_id] = {"status": "not_deployed_in_coverage" if when <= end else "outside_coverage"}
            continue
        lead = shipping["deployed_at"] - when
        if lead < 0:
            result[change_id] = {"status": "timestamp_inconsistent", "deployment_id": shipping["deployment_id"],
                                 "deployed_at": shipping["deployed_at"], "lead_seconds": lead, "pre_deployment": None}
            continue
        result[change_id] = {"status": "shipped", "deployment_id": shipping["deployment_id"],
                             "environment": shipping["environment"], "deployed_at": shipping["deployed_at"],
                             "deployed_commit": shipping["commit"], "lead_seconds": lead,
                             "pre_deployment": lead <= window_seconds}
    return result, gaps


def component_relatedness(changes: Iterable[Mapping[str, Any]], roots: list[tuple[str, str]]) -> dict[tuple[str, str], int]:
    """Count non-bulk in-window changes that touched each pair of components."""
    support: dict[tuple[str, str], int] = defaultdict(int)
    for change in changes:
        if change["bulk"]:
            continue
        touched = sorted({component_of(entry.get("current_path") or entry["path"], roots) or "(unassigned)"
                          for entry in change["files"]})
        for index, left in enumerate(touched):
            for right in touched[index + 1:]:
                support[(left, right)] += 1
    return dict(support)


def sprawl_facts(change: Mapping[str, Any], roots: list[tuple[str, str]], support: Mapping[tuple[str, str], int],
                 settings: ChangeContextSettings) -> dict[str, Any]:
    """Group touched components into related groups; unrelated groups indicate scope sprawl.

    Components are related when one's root nests the other (ignoring the repository-root component,
    which would relate everything) or when at least ``related_component_min_support`` *other*
    non-bulk changes touched both.
    """
    root_of = {component_id: root for root, component_id in roots}
    churn: dict[str, int] = defaultdict(int)
    for entry in change["files"]:
        component = component_of(entry.get("current_path") or entry["path"], roots) or "(unassigned)"
        churn[component] += int(entry["added"]) + int(entry["deleted"])
    components = sorted(churn)
    parent = {item: item for item in components}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def nested(left: str, right: str) -> bool:
        a, b = root_of.get(left), root_of.get(right)
        if a is None or b is None or a in {"", "."} or b in {"", "."}:
            return False
        return b.startswith(a.rstrip("/") + "/") or a.startswith(b.rstrip("/") + "/")

    minimum = settings.scope_sprawl.related_component_min_support
    for index, left in enumerate(components):
        for right in components[index + 1:]:
            others = support.get((left, right), 0) - (0 if change["bulk"] else 1)
            if nested(left, right) or others >= minimum:
                parent[find(left)] = find(right)
    groups: dict[str, list[str]] = defaultdict(list)
    for item in components:
        groups[find(item)].append(item)
    group_churn = sorted((sum(churn[item] for item in members), sorted(members)) for members in groups.values())
    total = sum(churn.values())
    shares = [value / total for value, _ in group_churn] if total else []
    entropy = (-sum(p * math.log(p) for p in shares if p > 0) / math.log(len(shares))) if len(shares) > 1 else 0.0
    sprawl = settings.scope_sprawl
    unrelated = len(groups)
    return {
        "file_count": int(change["file_count"]), "component_count": len(components), "components": components,
        "unrelated_group_count": unrelated,
        "groups": [{"components": members, "churn_lines": value} for value, members in
                   sorted(group_churn, key=lambda item: (-item[0], item[1]))][:20],
        "churn_lines": total, "group_churn_entropy": _round(entropy),
        "largest_group_churn_share": _round(max(shares)) if shares else None, "bulk": bool(change["bulk"]),
        "sprawling": unrelated >= sprawl.min_unrelated_groups and total >= sprawl.min_churn_lines and
                     entropy >= sprawl.min_group_entropy,
    }


def test_churn_facts(changes: list[Mapping[str, Any]], roles: PathRoles, roots: list[tuple[str, str]],
                     settings: ChangeContextSettings) -> dict[str, Any]:
    """Compare production and contract churn with associated test churn across one review unit.

    Association rules, in order: ``subject`` (test stem minus test affixes equals a production stem
    in the unit), then ``component`` (test file in the same component as a production file).  A test
    whose subject matches several production files is associated with all of them and reported as
    ambiguous.  Test churn with no association is reported separately and never offsets production.
    """
    totals = defaultdict(int)
    production: dict[str, list[int]] = {}
    tests: dict[str, list[int]] = {}
    for change in changes:
        for entry in change["files"]:
            path = entry.get("current_path") or entry["path"]
            role = roles.role(path)
            if role in {"production", "contract"}:
                bucket = production.setdefault(path, [0, 0])
            elif role == "test":
                bucket = tests.setdefault(path, [0, 0])
            else:
                continue
            bucket[0] += int(entry["added"])
            bucket[1] += int(entry["deleted"])
            totals[f"{role}_added"] += int(entry["added"])
            totals[f"{role}_deleted"] += int(entry["deleted"])
    stems: dict[str, list[str]] = defaultdict(list)
    for path in production:
        stems[_stem(path)].append(path)
    associated: dict[str, set[str]] = defaultdict(set)
    rule_counts = defaultdict(int)
    ambiguous: list[str] = []
    unassociated = [0, 0]
    production_components = {component_of(path, roots) for path in production}
    for path, (added, deleted) in sorted(tests.items()):
        matches = stems.get(test_subject(path), [])
        if matches:
            rule_counts["subject"] += 1
            if len(matches) > 1:
                ambiguous.append(path)
            for match in matches:
                associated[match].add(path)
            continue
        component = component_of(path, roots)
        if component is not None and component in production_components:
            rule_counts["component"] += 1
            for match in production:
                if component_of(match, roots) == component:
                    associated[match].add(path)
            continue
        unassociated[0] += added
        unassociated[1] += deleted
    associated_tests = {item for values in associated.values() for item in values}
    associated_churn = sum(sum(tests[item]) for item in associated_tests)
    production_churn = totals["production_added"] + totals["production_deleted"]
    contract_churn = totals["contract_added"] + totals["contract_deleted"]
    untested_files = sorted(path for path in production if not associated.get(path))
    minimum = settings.test_association.min_production_churn_lines
    return {
        "status": "partial" if ambiguous else "available", "rules": TEST_ASSOCIATION_IDENTITY,
        "production_added": totals["production_added"], "production_deleted": totals["production_deleted"],
        "contract_added": totals["contract_added"], "contract_deleted": totals["contract_deleted"],
        "test_added": totals["test_added"], "test_deleted": totals["test_deleted"],
        "associated_test_churn": associated_churn, "unassociated_test_added": unassociated[0],
        "unassociated_test_deleted": unassociated[1], "association_rule_counts": dict(sorted(rule_counts.items())),
        "ambiguous_test_files": ambiguous[:20], "ambiguous_association_count": len(ambiguous),
        "untested_production_files": untested_files[:20],
        "untested_production": production_churn >= minimum and associated_churn == 0,
        "untested_contract": contract_churn > 0 and totals["test_added"] + totals["test_deleted"] == 0,
    }


def change_records(changes: list[Mapping[str, Any]], classes: Mapping[str, Mapping[str, Any]], *,
                   reviews: Mapping[str, Mapping[str, Any]] | None, deployments: Mapping[str, Any] | None,
                   walked: list[str], zone: tzinfo | None, roots: list[tuple[str, str]],
                   settings: ChangeContextSettings) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build one provenance-carrying record per in-window change."""
    landed: dict[str, int] = {}
    landed_basis: dict[str, str] = {}
    for change in changes:
        record = reviews.get(str(change["change_id"])) if reviews is not None else None
        landed[str(change["change_id"])], landed_basis[str(change["change_id"])] = landed_time(change, record)
    deployment, gaps = deployment_facts(changes, landed, walked, deployments,
                                        settings.deployments.pre_deployment_window_seconds)
    support = component_relatedness(changes, roots)
    roles = PathRoles(settings)
    units: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    unit_of: dict[str, str] = {}
    for change in changes:
        change_id = str(change["change_id"])
        record = reviews.get(change_id) if reviews is not None else None
        unit = f"pr:{record['pull_request']}" if record and record.get("pull_request") else f"change:{change_id}"
        unit_of[change_id] = unit
        units[unit].append(change)
    tests = ({unit: test_churn_facts(members, roles, roots, settings) for unit, members in units.items()}
             if settings.test_association.enabled else {})
    records: dict[str, dict[str, Any]] = {}
    for change in changes:
        change_id = str(change["change_id"])
        record = reviews.get(change_id) if reviews is not None else None
        review = review_facts(record, settings.review.fast_review_seconds) if reviews is not None else {"status": "unavailable"}
        label = classes.get(change_id, {})
        records[change_id] = {
            "change_id": change_id, "position": int(change["position"]), "review_unit": unit_of[change_id],
            "review_unit_size": len(units[unit_of[change_id]]),
            "facts": {
                "commit_time": int(change["commit_time"]), "author_time": int(change["author_time"]),
                "effective_time": int(change["effective_time"]), "commit_time_basis": "git_claimed",
                "landed_at": landed[change_id], "landed_at_basis": landed_basis[change_id],
                "author": change["author"], "bulk": bool(change["bulk"]), "file_count": int(change["file_count"]),
                "review_record": {key: record.get(key) for key in ("pull_request", "direct_push", "created_at", "merged_at",
                                                                   "head_sha", "head_committed_at", "approvals")}
                if record else None,
            },
            "classifications": {"fix": label.get("fix"), "security_fix": label.get("security_fix"),
                                "basis": "history-change-rules"},
            "review": review,
            "schedule": schedule_facts(landed[change_id], zone, settings),
            "deployment": deployment[change_id],
            "sprawl": sprawl_facts(change, roots, support, settings),
            "tests": tests.get(unit_of[change_id], {"status": "unavailable"}),
        }
    return records, gaps


# ----------------------------------------------------------------------------------------------
# Unit aggregation


def peak_window(events: list[tuple[int, str]], window_seconds: int) -> dict[str, Any]:
    """Largest number of events inside any half-open ``[t, t + window)``; earliest peak wins ties."""
    ordered = sorted(events)
    best = (0, 0, 0)
    right = 0
    for left in range(len(ordered)):
        right = max(right, left)
        while right < len(ordered) and ordered[right][0] - ordered[left][0] < window_seconds:
            right += 1
        if right - left > best[0]:
            best = (right - left, left, right)
    count, left, right = best
    members = ordered[left:right]
    return {"peak": count, "window_start": members[0][0] if members else None,
            "window_end": members[-1][0] if members else None, "changes": [item[1] for item in members]}


def ownership(counts: Mapping[str, int], bus_share: float) -> dict[str, Any]:
    total = sum(counts.values())
    if not total:
        return {"author_count": 0, "principal_author": None, "principal_author_share": None, "bus_factor": None}
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    running, factor = 0, 0
    for _, value in ordered:
        running += value
        factor += 1
        if running / total >= bus_share:
            break
    return {"author_count": len(counts), "principal_author": ordered[0][0],
            "principal_author_share": _round(ordered[0][1] / total), "bus_factor": factor, "weight_total": total}


def _availability(values: Iterable[str]) -> str:
    states = list(values)
    if not states or all(item == "unavailable" for item in states):
        return "unavailable"
    return "partial" if any(item != "available" for item in states) else "available"


def aggregate(change_ids: list[str], records: Mapping[str, Mapping[str, Any]], *, fix_events: int | None,
              fix_on_fix_status: str, owner: Mapping[str, Any], owner_status: str,
              organization: Mapping[str, Any] | None, identity_of: Mapping[str, str],
              classification_status: str, settings: ChangeContextSettings) -> dict[str, Any]:
    """Aggregate per-change records into one unit metric vector with explicit availability."""
    members = [records[item] for item in sorted(set(change_ids), key=lambda value: records[value]["position"])]
    metrics: dict[str, Any] = {}
    availability: dict[str, str] = {}
    details: dict[str, Any] = {}
    review_states = [item["review"]["status"] for item in members]
    review_known = [item["review"] for item in members if item["review"]["status"] in {"known", "incomplete"}]
    review_source = "unavailable" if all(state == "unavailable" for state in review_states) else (
        "available" if all(state == "known" for state in review_states) else "partial")
    flags = {"fast_review_change_count": lambda item: item.get("fast_approval") or item.get("fast_merge"),
             "stale_approval_change_count": lambda item: item.get("stale_approval"),
             "unapproved_mainline_change_count": lambda item: item.get("unapproved_mainline")}
    for signal, flagged in flags.items():
        metrics[signal] = None if review_source == "unavailable" else sum(1 for item in review_known if flagged(item))
        availability[signal] = review_source
    speeds = [item["creation_to_first_approval_seconds"] for item in review_known
              if item.get("creation_to_first_approval_seconds") is not None]
    head_speeds = [item["final_head_to_approval_seconds"] for item in review_known
                   if item.get("final_head_to_approval_seconds") is not None]
    details["review"] = {
        "source_status": review_source, "known_change_count": len(review_known), "change_count": len(members),
        "median_creation_to_first_approval_seconds": statistics.median(speeds) if speeds else None,
        "median_final_head_to_approval_seconds": statistics.median(head_speeds) if head_speeds else None,
        "direct_push_change_count": sum(1 for item in review_known if item.get("direct_push")),
        "merged_head_approved_change_count": sum(1 for item in review_known if item.get("merged_head_approved")),
    }
    schedule_states = [item["schedule"]["status"] for item in members]
    if all(state == "unavailable" for state in schedule_states):
        metrics["off_hours_change_count"], availability["off_hours_change_count"] = None, "unavailable"
    else:
        metrics["off_hours_change_count"] = sum(1 for item in members if item["schedule"].get("off_hours"))
        availability["off_hours_change_count"] = "available"
    deployment_states = [item["deployment"]["status"] for item in members]
    if all(state == "unavailable" for state in deployment_states):
        metrics["pre_deployment_change_count"], availability["pre_deployment_change_count"] = None, "unavailable"
    else:
        metrics["pre_deployment_change_count"] = sum(1 for item in members if item["deployment"].get("pre_deployment"))
        availability["pre_deployment_change_count"] = ("available" if all(
            state in {"shipped", "not_deployed_in_coverage"} for state in deployment_states) else "partial")
    details["deployment"] = {"status_counts": dict(sorted(_count(deployment_states).items())),
                             "pre_deployment_changes": [item["change_id"] for item in members
                                                        if item["deployment"].get("pre_deployment")][:20]}
    sprawling = [item["change_id"] for item in members if item["sprawl"]["sprawling"]]
    metrics["sprawling_change_count"], availability["sprawling_change_count"] = len(sprawling), "available"
    details["sprawl"] = {"sprawling_changes": sprawling[:20],
                         "max_unrelated_group_count": max((item["sprawl"]["unrelated_group_count"] for item in members), default=0),
                         "max_change_churn_lines": max((item["sprawl"]["churn_lines"] for item in members), default=0)}
    fixes = [(item["facts"]["effective_time"], item["change_id"]) for item in members if item["classifications"]["fix"]]
    window = peak_window(fixes, settings.repeated_repairs.window_days * DAY)
    metrics["repeated_repair_peak"] = window["peak"]
    availability["repeated_repair_peak"] = classification_status
    details["repeated_repairs"] = {
        **window, "window_days": settings.repeated_repairs.window_days, "fix_change_count": len(fixes),
        "flagged": window["peak"] >= settings.repeated_repairs.min_fix_changes,
        "classification_basis": dict(sorted(_count(str(records[change]["classifications"]["fix"])
                                                   for _, change in fixes).items())),
        "time_basis": "history_effective_commit_time",
    }
    metrics["fix_on_fix_event_count"] = fix_events if fix_on_fix_status != "unavailable" else None
    availability["fix_on_fix_event_count"] = fix_on_fix_status
    test_states = [item["tests"]["status"] for item in members]
    if all(state == "unavailable" for state in test_states):
        metrics["untested_production_change_count"] = None
        availability["untested_production_change_count"] = "unavailable"
    else:
        metrics["untested_production_change_count"] = sum(
            1 for item in members if item["tests"].get("untested_production") or item["tests"].get("untested_contract"))
        availability["untested_production_change_count"] = _availability(test_states)
    details["tests"] = {
        "untested_changes": [item["change_id"] for item in members
                             if item["tests"].get("untested_production") or item["tests"].get("untested_contract")][:20],
        "ambiguous_association_count": sum(int(item["tests"].get("ambiguous_association_count", 0)) for item in members),
        "production_churn": sum(int(item["tests"].get("production_added", 0)) + int(item["tests"].get("production_deleted", 0))
                                for item in members),
        "associated_test_churn": sum(int(item["tests"].get("associated_test_churn", 0)) for item in members),
    }
    metrics["lifetime_principal_author_share"] = owner.get("principal_author_share")
    availability["lifetime_principal_author_share"] = owner_status if owner.get("principal_author_share") is not None else "unavailable"
    departed: bool | None = None
    principal = owner.get("principal_author")
    if organization is None or principal is None:
        departed_status = "unavailable"
    else:
        member = organization["members"].get(identity_of.get(principal, ""))
        if member is None:
            departed_status = "unavailable"
        else:
            departed = member["status"] == "departed" and float(owner["principal_author_share"]) >= \
                settings.ownership.dominant_owner_share
            departed_status = "available"
    metrics["departed_dominant_owner"] = departed
    availability["departed_dominant_owner"] = departed_status
    details["ownership"] = {**owner, "principal_in_organization_data": departed_status == "available",
                            "dominant_owner_share": settings.ownership.dominant_owner_share}
    return {"change_count": len(members), "metrics": metrics, "availability": availability, "details": details,
            "supporting_changes": [item["change_id"] for item in members][:settings.supporting_change_limit]}


def _count(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    return counts


def rank(records: Mapping[str, Mapping[str, Any]], weights: Mapping[str, float]) -> list[dict[str, Any]]:
    """Weighted mean of max-normalized signals; unavailable signals are excluded, not zeroed.

    Each signal is divided by its population maximum (booleans count 1), so a unit with no observed
    anomaly scores 0 on that signal.  ``coverage`` is the share of total weight that was available.
    Ties break on the stable key.
    """
    maxima: dict[str, float] = {}
    for signal in PRIORITY_SIGNALS:
        present = [float(value["metrics"][signal]) for value in records.values()
                   if value["metrics"].get(signal) is not None]
        maxima[signal] = max(present, default=0.0)
    total_weight = sum(float(weights.get(signal, 0)) for signal in PRIORITY_SIGNALS)
    ranked = []
    for key, value in records.items():
        normalized, missing = {}, []
        for signal in PRIORITY_SIGNALS:
            weight = float(weights.get(signal, 0))
            if weight <= 0:
                continue
            raw = value["metrics"].get(signal)
            if raw is None:
                missing.append(signal)
                continue
            normalized[signal] = _round(float(raw) / maxima[signal]) if maxima[signal] > 0 else 0.0
        used = sum(float(weights[signal]) for signal in normalized)
        score = sum(float(weights[signal]) * item for signal, item in normalized.items()) / used if used else 0.0
        ranked.append({"key": key, "score": _round(score), "coverage": _round(used / total_weight) if total_weight else 0.0,
                       "normalized": dict(sorted(normalized.items())), "missing_signals": missing})
    ranked.sort(key=lambda item: (-item["score"], -item["coverage"], item["key"]))
    for position, item in enumerate(ranked, 1):
        item["rank"] = position
    return ranked
