"""Semgrep pattern evidence and CodeQL source-to-sink paths from accepted upstream jobs.

Semgrep contributes ``observed_syntax`` matches from the hash-pinned ``review-signals.yml`` pack.
CodeQL contributes ``verified_semantic_path`` records: the shortest SARIF code flow per
(rule, source, sink) of a path-problem result.  A CodeQL path is evidence that CodeQL's dataflow
model connects the two locations; it is not a confirmed vulnerability, and paths are never inferred
from co-location or import reachability.  An unavailable or failed producer is a named gap.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from .inputs import accepted_handoff, has_handoff, producer_entities, read_json
from .rules import OBSERVED, SEMANTIC


SEMGREP_MARKER = "appsec-review.review-signal."
SEMGREP_CATEGORIES = frozenset({"ingress", "sink", "privilege_shift", "sensitive_wrapper", "state_mutation",
                                "custom_parsing", "public_api", "validator", "parser", "middleware"})
# Catalog language -> CodeQL extractor language covering it.
CODEQL_LANGUAGES = {"C": "cpp", "C++": "cpp", "C/C++": "cpp", "Java": "java", "C#": "csharp", "Go": "go",
                    "JavaScript": "javascript", "TypeScript": "javascript", "TSX": "javascript", "Rust": "rust"}


def _semgrep_pack(repository_root: Path) -> Mapping[str, Any]:
    try:
        lock = json.loads((repository_root / "rules" / "semgrep" / "rules.lock.json").read_text(encoding="utf-8"))
        return {"bundle": lock.get("bundle"), "sha256": lock["files"]["review-signals.yml"]["sha256"]}
    except (OSError, KeyError, ValueError):
        return {"verified": False}


def semgrep_signals(run_root: Path, repository_root: Path) -> dict[str, Any]:
    pack = _semgrep_pack(repository_root)
    if not has_handoff(run_root, "job_evidence_collection"):
        return {"status": "UNAVAILABLE", "signals": [], "pack": pack,
                "gaps": ["semgrep_review_signals_unavailable: evidence collection has no accepted handoff"]}
    handoff, handoff_sha = accepted_handoff(run_root, "job_evidence_collection")
    output = handoff.get("outputs", {}).get("evidence_publication.publish_handoff", {})
    document = read_json(run_root, output["artifact"])
    disposition = next((item for item in document.get("dispositions", ()) if item.get("tool_id") == "tool-semgrep"),
                       None)
    if disposition is None:
        return {"status": "UNAVAILABLE", "signals": [], "pack": pack, "handoff_sha256": handoff_sha,
                "gaps": ["semgrep_review_signals_unavailable: Semgrep was not planned for this target"]}
    gaps = [f"semgrep: {gap}" for gap in disposition.get("gaps", ())][:20]
    if disposition.get("terminal_status") not in {"SUCCEEDED", "PARTIAL"}:
        return {"status": "UNAVAILABLE", "signals": [], "pack": pack, "handoff_sha256": handoff_sha,
                "gaps": [f"semgrep_review_signals_unavailable: Semgrep disposition "
                         f"{disposition.get('terminal_status')}", *gaps]}
    signals = []
    for _shard, entity in producer_entities(run_root, output["index_manifest"], job="job_evidence_collection",
                                            kind="tool_observation", producer="tool-semgrep"):
        payload = entity["payload"]
        rule = str(payload.get("native_rule_id", ""))
        if SEMGREP_MARKER not in rule:
            continue
        rule = rule[rule.index(SEMGREP_MARKER):]
        parts = rule[len(SEMGREP_MARKER):].split(".")
        location = payload.get("location") or {}
        if not parts or parts[0] not in SEMGREP_CATEGORIES or not location.get("path"):
            gaps.append(f"semgrep review signal without category or location: {rule[:128]}")
            continue
        signals.append({
            "rule_id": rule, "rules": f"semgrep-review-signals@{pack.get('sha256', 'unverified')}",
            "producer": "semgrep", "basis": OBSERVED, "category": parts[0],
            "surface": parts[1] if len(parts) > 2 else parts[0], "path": location["path"],
            "file_sha256": location.get("source_sha256"), "start_line": int(location.get("start_line") or 1),
            "end_line": int(location.get("end_line") or location.get("start_line") or 1),
            "function_id": None, "detail": {"message": str(payload.get("message") or "")[:512],
                                            "evidence_id": payload.get("evidence_id")},
        })
    return {"status": "PARTIAL" if gaps else "SUCCEEDED", "signals": signals, "pack": pack,
            "handoff_sha256": handoff_sha, "gaps": gaps}


def codeql_paths(run_root: Path, *, limit: int) -> dict[str, Any]:
    if not has_handoff(run_root, "job_codeql_analysis"):
        return {"status": "UNAVAILABLE", "paths": [], "languages": {},
                "gaps": ["semantic_paths_unavailable: CodeQL analysis has no accepted handoff"]}
    handoff, handoff_sha = accepted_handoff(run_root, "job_codeql_analysis")
    output = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    summary = read_json(run_root, output["artifact"])
    languages: dict[str, str] = {}
    for scope in summary.get("scopes", ()):
        language = str(scope.get("language"))
        status = str(scope.get("terminal_status"))
        if languages.get(language) != "SUCCEEDED":
            languages[language] = status
    gaps = [f"semantic_paths_partial: CodeQL {language} scope {status}"
            for language, status in sorted(languages.items()) if status != "SUCCEEDED"]
    if not output.get("index_manifest"):
        return {"status": "UNAVAILABLE", "paths": [], "languages": languages, "handoff_sha256": handoff_sha,
                "gaps": ["semantic_paths_unavailable: CodeQL published no index manifest", *gaps]}
    best: dict[tuple[str, str, str], dict[str, Any]] = {}
    merged_flows = 0
    for _shard, entity in producer_entities(run_root, output["index_manifest"], job="job_codeql_analysis",
                                            kind="tool_observation"):
        payload = entity["payload"]
        flows = [item for item in payload.get("flows", ()) if isinstance(item, Mapping)]
        groups: dict[Any, list[Mapping[str, Any]]] = {}
        for flow in flows:
            groups.setdefault(flow.get("code_flow", "merged"), []).append(flow)
        if "merged" in groups and len(flows) > 1:
            merged_flows += 1
        for steps in groups.values():
            mapped = [step for step in sorted(steps, key=lambda item: int(item.get("ordinal", 0)))
                      if isinstance(step.get("location"), Mapping) and step["location"].get("path")]
            if len(mapped) < 2 or len(mapped) != len(steps):
                continue
            source, sink = mapped[0]["location"], mapped[-1]["location"]
            key = (str(payload.get("rule_id")), f"{source['path']}:{source['start_line']}:{source['start_column']}",
                   f"{sink['path']}:{sink['start_line']}:{sink['start_column']}")
            candidate = {
                "rule_id": str(payload.get("rule_id")), "rules": str(payload.get("query_identity")),
                "producer": "codeql", "basis": SEMANTIC, "category": "semantic_path", "surface": "dataflow",
                "language": payload.get("language"), "observation": entity["identity"], "steps": len(mapped),
                "source": {key_: source.get(key_) for key_ in ("path", "file_sha256", "start_line", "end_line",
                                                               "start_column", "end_column")},
                "sink": {key_: sink.get(key_) for key_ in ("path", "file_sha256", "start_line", "end_line",
                                                           "start_column", "end_column")},
                "message": str(payload.get("message") or "")[:512],
            }
            current = best.get(key)
            if current is None or (candidate["steps"], candidate["observation"]) < (current["steps"],
                                                                                   current["observation"]):
                best[key] = candidate
    paths = sorted(best.values(), key=lambda item: (item["steps"], item["rule_id"], item["sink"]["path"],
                                                    item["sink"]["start_line"]))
    if merged_flows:
        gaps.append(f"semantic_path_flow_boundaries_unavailable: {merged_flows} results lack code_flow indices")
    if len(paths) > limit:
        gaps.append(f"semantic_paths_truncated: kept {limit} of {len(paths)} shortest paths")
        paths = paths[:limit]
    for item in paths:
        item["path_id"] = "path-" + hashlib.sha256(json.dumps(
            [item["rule_id"], item["source"], item["sink"]], sort_keys=True).encode()).hexdigest()[:24]
    return {"status": "PARTIAL" if gaps else "SUCCEEDED", "paths": paths, "languages": languages,
            "handoff_sha256": handoff_sha, "gaps": gaps}
