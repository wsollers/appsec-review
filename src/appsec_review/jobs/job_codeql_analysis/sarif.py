from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from appsec_review.retrieval.model import sanitize_producer_data


NORMALIZER_IDENTITY = "appsec-review/codeql-sarif-normalizer/2"


@dataclass(frozen=True, slots=True)
class MappedLocation:
    path: str | None
    file_sha256: str | None
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    confidence: float
    ambiguous: bool
    candidates: tuple[str, ...]
    producer_location: Mapping[str, Any]


def _region(physical: Mapping[str, Any]) -> tuple[int, int, int, int]:
    value = physical.get("region") if isinstance(physical.get("region"), Mapping) else {}
    try:
        start_line = max(1, int(value.get("startLine", 1)))
        end_line = max(start_line, int(value.get("endLine", start_line)))
        start_column = max(1, int(value.get("startColumn", 1)))
        end_column = max(start_column, int(value.get("endColumn", start_column)))
    except (TypeError, ValueError):
        return 1, 1, 1, 1
    return start_line, end_line, start_column, end_column


def map_location(physical: Mapping[str, Any], *, files: Sequence[Mapping[str, Any]],
                 root: str) -> MappedLocation:
    artifact = physical.get("artifactLocation")
    region = _region(physical)
    producer = sanitize_producer_data({"artifactLocation": artifact, "region": physical.get("region", {})})
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("uri"), str):
        return MappedLocation(None, None, *region, 0.0, False, (), producer)
    uri = str(artifact["uri"])
    raw = unquote(urlparse(uri).path if uri.startswith("file:") else uri).replace("\\", "/")
    for prefix in ("/scratch/workspace/", "scratch/workspace/", "/workspace/", "workspace/"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    raw = raw.lstrip("./")
    accepted = {str(item["path"]): str(item["sha256"]) for item in files}
    candidates: list[str] = []
    confidence = 0.0
    if raw in accepted:
        candidates, confidence = [raw], 1.0
    else:
        rooted = f"{root.rstrip('/')}/{raw}" if root != "." and not raw.startswith(root.rstrip("/") + "/") else raw
        if rooted in accepted:
            candidates, confidence = [rooted], 1.0
        elif raw:
            candidates = sorted(path for path in accepted if path == raw or path.endswith("/" + raw))
            confidence = 0.8 if len(candidates) == 1 else 0.5 if candidates else 0.0
    exact = candidates[0] if len(candidates) == 1 else None
    return MappedLocation(exact, accepted.get(exact) if exact else None, *region, confidence,
                          len(candidates) > 1, tuple(candidates), producer)


def _rules(run: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    tool = run.get("tool") if isinstance(run.get("tool"), Mapping) else {}
    drivers = [tool["driver"]] if isinstance(tool.get("driver"), Mapping) else []
    drivers.extend(item for item in tool.get("extensions", ()) if isinstance(item, Mapping))
    values: dict[str, Mapping[str, Any]] = {}
    for driver in drivers:
        for rule in driver.get("rules", ()):
            if isinstance(rule, Mapping) and isinstance(rule.get("id"), str):
                values[str(rule["id"])] = rule
    return values


def _message(value: object, fallback: str) -> str:
    if isinstance(value, Mapping):
        return str(value.get("text") or value.get("markdown") or fallback)[:8192]
    return fallback[:8192]


def normalize_sarif(document: Mapping[str, Any], *, files: Sequence[Mapping[str, Any]],
                    root: str, query_identity: str,
                    result_limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    """Normalize bounded SARIF while retaining partial, ambiguous, and unmapped evidence."""
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("CodeQL SARIF contract is unsupported")
    observations: list[dict[str, Any]] = []
    gaps: list[str] = []
    for run_index, run in enumerate(document["runs"]):
        if not isinstance(run, Mapping):
            gaps.append(f"SARIF run {run_index} was not an object")
            continue
        rules = _rules(run)
        results = run.get("results", ())
        if not isinstance(results, list):
            gaps.append(f"SARIF run {run_index} results were not a list")
            continue
        for result_index, result in enumerate(results):
            if len(observations) >= result_limit:
                gaps.append("CodeQL normalized result count reached its configured bound")
                return observations, list(dict.fromkeys(gaps))
            if not isinstance(result, Mapping):
                gaps.append(f"SARIF result {run_index}:{result_index} was not an object")
                continue
            rule_id = str(result.get("ruleId") or "codeql/unknown")[:1024]
            rule = rules.get(rule_id, {})
            locations: list[MappedLocation] = []
            for location in result.get("locations", ()) if isinstance(result.get("locations", ()), list) else ():
                physical = location.get("physicalLocation") if isinstance(location, Mapping) else None
                if isinstance(physical, Mapping):
                    locations.append(map_location(physical, files=files, root=root))
            primary = next((item for item in locations if item.path is not None), locations[0] if locations else None)
            flows: list[dict[str, Any]] = []
            flow_ordinal = 0
            code_flows = result.get("codeFlows", ()) if isinstance(result.get("codeFlows", ()), list) else ()
            for code_flow_index, code_flow in enumerate(code_flows):
                if not isinstance(code_flow, Mapping):
                    continue
                for thread_index, thread_flow in enumerate(code_flow.get("threadFlows", ())):
                    if not isinstance(thread_flow, Mapping):
                        continue
                    for step in thread_flow.get("locations", ()):
                        location = step.get("location") if isinstance(step, Mapping) else None
                        physical = location.get("physicalLocation") if isinstance(location, Mapping) else None
                        if not isinstance(physical, Mapping):
                            gaps.append(f"CodeQL flow step for {run_index}:{result_index} had no physical location")
                            continue
                        flow_ordinal += 1
                        mapped = map_location(physical, files=files, root=root)
                        flows.append({
                            # code_flow separates alternative SARIF paths for the same result.
                            "ordinal": flow_ordinal, "code_flow": code_flow_index, "thread_flow": thread_index,
                            "message": _message(location.get("message") if isinstance(location, Mapping) else None,
                                                "flow step"),
                            "location": mapped.__dict__ if hasattr(mapped, "__dict__") else {
                                name: getattr(mapped, name) for name in mapped.__slots__
                            },
                            "supporting": True,
                        })
                        if mapped.path is None:
                            gaps.append(f"CodeQL flow step for {run_index}:{result_index} was unmapped or ambiguous")
            mapped_locations = [
                item.__dict__ if hasattr(item, "__dict__") else {name: getattr(item, name) for name in item.__slots__}
                for item in locations
            ]
            payload = sanitize_producer_data({
                "producer": "codeql", "query_identity": query_identity, "rule_id": rule_id,
                "rule": rule, "help_uri": rule.get("helpUri"), "producer_level": result.get("level"),
                "kind": result.get("kind"), "message": _message(result.get("message"), rule_id),
                "partial_fingerprints": result.get("partialFingerprints", {}),
                "properties": result.get("properties", {}), "baseline_state": result.get("baselineState"),
                "suppressions": result.get("suppressions", []), "locations": mapped_locations,
                "flows": flows, "supporting_relations": [item["ordinal"] for item in flows],
                "contradicting_relations": result.get("properties", {}).get("contradictingRelations", [])
                    if isinstance(result.get("properties"), Mapping) else [],
            })
            observations.append({
                "native_id": f"{run_index}:{result_index}", "rule_id": rule_id,
                "message": _message(result.get("message"), rule_id), "payload": payload,
                "location": (mapped_locations[locations.index(primary)] if primary is not None else None),
                "flows": flows,
            })
            if primary is None or primary.path is None:
                gaps.append(f"CodeQL result {run_index}:{result_index} had no uniquely mapped source location")
    if not observations:
        gaps.append("CodeQL query suite completed with zero observations; this is not a clean classification")
    return observations, list(dict.fromkeys(gaps))
