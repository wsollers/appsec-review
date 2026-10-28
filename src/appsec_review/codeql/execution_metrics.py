"""Bounded per-query metrics of one CodeQL execution, written beside its execution receipt.

Each document names its source and every missing measurement as a gap; an absent source is never
reported as zero queries, zero runtime or zero results.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.storage import atomic_json


QUERY_METRICS_SCHEMA = "appsec-review/codeql-query-metrics/1"
QUERY_METRICS_NAME = "query-metrics.json"
# Written by `codeql_runner.py query` at the scratch root from `database analyze` progress lines.
QUERY_TIMINGS_SCHEMA = "appsec-review/codeql-query-timings/1"
QUERY_TIMINGS_NAME = "query-timings.json"
COMPILE_SCHEMA = "appsec-review/codeql-compile/1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_QUERY_ROWS = 10000


def _document(action: str, source: str, queries: list[dict[str, Any]], *, gaps: list[str],
              expected: int | None, rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"schema": QUERY_METRICS_SCHEMA, "action": action, "source": source,
                             "expected_query_count": expected, "observed_query_count": len(queries),
                             "queries": queries[:MAX_QUERY_ROWS], "gaps": list(dict.fromkeys(gaps))}
    if len(queries) > MAX_QUERY_ROWS:
        value["gaps"].append(f"per-query rows truncated at {MAX_QUERY_ROWS}")
    if rules is not None:
        value["rules"] = rules[:MAX_QUERY_ROWS]
        if len(rules) > MAX_QUERY_ROWS:
            value["gaps"].append(f"per-rule rows truncated at {MAX_QUERY_ROWS}")
    return value


def _bounded_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(path.name)
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{path.name} exceeds {MAX_INPUT_BYTES} bytes")
    return json.loads(path.read_text(encoding="utf-8"))


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def sarif_rule_counts(sarif: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Result count per SARIF rule id, including declared rules that produced no result."""
    counts: dict[str, int] = {}
    for run in sarif.get("runs", ()):
        if not isinstance(run, Mapping):
            continue
        tool = run.get("tool") if isinstance(run.get("tool"), Mapping) else {}
        components = [tool.get("driver") or {}, *(tool.get("extensions") or ())]
        indexed: list[str] = []
        for component in components:
            for rule in (component.get("rules") or ()) if isinstance(component, Mapping) else ():
                if isinstance(rule, Mapping) and isinstance(rule.get("id"), str):
                    counts.setdefault(rule["id"], 0)
                    if component is components[0]:
                        indexed.append(rule["id"])
        for result in run.get("results", ()) or ():
            if not isinstance(result, Mapping):
                continue
            rule = result.get("rule") if isinstance(result.get("rule"), Mapping) else {}
            rule_id = result.get("ruleId") or rule.get("id")
            index = result.get("ruleIndex", rule.get("index"))
            if not isinstance(rule_id, str) and isinstance(index, int) and 0 <= index < len(indexed):
                rule_id = indexed[index]
            key = rule_id if isinstance(rule_id, str) else "(unidentified rule)"
            counts[key] = counts.get(key, 0) + 1
    return [{"rule_id": key, "result_count": counts[key]} for key in sorted(counts)]


def analyze_query_metrics(timings_path: Path, sarif: Mapping[str, Any] | None) -> dict[str, Any]:
    """Per-query evaluation time from the runner's progress record, per-rule results from SARIF.

    `database analyze` SARIF carries rule ids, not query paths, so runtimes are keyed by query path
    and result counts by rule id; the two are reported side by side and never joined by guesswork.
    """
    gaps: list[str] = []
    queries: list[dict[str, Any]] = []
    expected = None
    try:
        document = _bounded_json(timings_path)
        if not isinstance(document, Mapping) or document.get("schema") != QUERY_TIMINGS_SCHEMA:
            raise ValueError("unsupported schema")
        expected = _count(document.get("expected_query_count"))
        for item in document.get("queries", ()):
            duration = _count(item.get("eval_ms")) if isinstance(item, Mapping) else None
            if not isinstance(item, Mapping) or not isinstance(item.get("query"), str) or duration is None:
                gaps.append("per-query timing record contains an invalid row")
                continue
            queries.append({"query": item["query"], "key_kind": "query_path",
                            "status": "REUSED" if item.get("cached") is True else "SUCCEEDED",
                            "duration_ms": duration, "result_count": None})
        if document.get("truncated") is True:
            gaps.append("runner per-query timing record was truncated")
        if expected is None:
            gaps.append("CodeQL analyze progress reported no per-query evaluation lines")
        elif len(queries) < expected:
            gaps.append(f"{expected - len(queries)} of {expected} queries reported no evaluation time")
    except FileNotFoundError:
        gaps.append("per-query evaluation timing unavailable: runner wrote no query-timings.json")
    except (OSError, ValueError, UnicodeError) as exc:
        gaps.append(f"per-query evaluation timing unreadable ({type(exc).__name__})")
    rules = None
    if sarif is None:
        gaps.append("per-rule result counts unavailable: no accepted SARIF")
    else:
        rules = sarif_rule_counts(sarif)
    return _document("analyze", "codeql-analyze-progress+sarif", queries, gaps=gaps,
                     expected=expected, rules=rules)


def export_query_metrics(manifest: Mapping[str, Any] | None) -> dict[str, Any]:
    """Per-query evaluate/decode time and row counts from an accepted export manifest."""
    if not manifest:
        return _document("export", "export-manifest", [], expected=None,
                         gaps=["per-query export metrics unavailable: no accepted export manifest"])
    gaps: list[str] = []
    queries = []
    for item in manifest.get("exports", ()):
        if not isinstance(item, Mapping) or not isinstance(item.get("query_id"), str):
            gaps.append("export manifest contains an invalid query row")
            continue
        evaluate, decode = _count(item.get("evaluate_ms")), _count(item.get("decode_ms"))
        if evaluate is None:
            gaps.append(f"export query {item['query_id']} has no evaluate_ms")
        compile_s = item.get("compile_s")
        queries.append({
            "query": item["query_id"], "key_kind": "query_id", "status": "SUCCEEDED",
            "duration_ms": None if evaluate is None else evaluate + (decode or 0),
            "evaluate_ms": evaluate, "decode_ms": decode,
            "compile_ms": (int(round(compile_s * 1000)) if isinstance(compile_s, (int, float))
                           and not isinstance(compile_s, bool) and compile_s >= 0 else None),
            "result_count": _count(item.get("row_count")),
            "exported_rows": _count(item.get("exported_rows")),
            "truncated": item.get("truncated") is True})
    return _document("export", "export-manifest", queries, gaps=gaps, expected=len(queries))


def compile_query_metrics(stdout_path: Path | None) -> dict[str, Any]:
    """Per-query compile time from the runner's `compile` summary line on captured stdout."""
    summary = None
    try:
        if stdout_path is None or not stdout_path.is_file() or stdout_path.is_symlink():
            raise FileNotFoundError("stdout")
        if stdout_path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("compile stdout exceeds its bound")
        for line in reversed(stdout_path.read_bytes().decode("utf-8", "replace").splitlines()):
            if line.startswith("{"):
                candidate = json.loads(line)
                if isinstance(candidate, Mapping) and candidate.get("schema") == COMPILE_SCHEMA:
                    summary = candidate
                    break
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError):
        summary = None
    if summary is None:
        return _document("compile", "codeql-compile-progress", [], expected=None,
                         gaps=["per-query compile timing unavailable: no runner compile summary"])
    expected = _count(summary.get("query_count"))
    seconds = summary.get("compile_s") if isinstance(summary.get("compile_s"), Mapping) else {}
    queries = [{"query": str(name), "key_kind": "query_file", "status": "SUCCEEDED",
                "duration_ms": int(round(value * 1000)), "result_count": None}
               for name, value in sorted(seconds.items())
               if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0]
    gaps = []
    if expected is not None and len(queries) < expected:
        gaps.append(f"{expected - len(queries)} of {expected} export queries reported no compile time "
                    "(compile-cache hit or unreported)")
    return _document("compile", "codeql-compile-progress", queries, gaps=gaps, expected=expected)


def write_query_metrics(directory: Path, document: Mapping[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / QUERY_METRICS_NAME
    atomic_json(path, dict(document))
    return path
