"""Schema-conformant history and complexity metric vectors for ranked review units.

Each accepted priority item receives one vector joining the accepted history signal for the same
file (exact path) or function (exact byte span) with the item's complexity features. Every metric
names its scope, producer, algorithm version, language, window and source hash; a missing metric is
``unavailable`` with a gap id, never zero. Vectors order review attention; they are never a finding
severity. Definitions: ``docs/architecture/source-history-analysis.md`` and ``review-prioritization.md``.
"""

from __future__ import annotations

from typing import Any

from appsec_review.indexing.products_base import AcceptedShards, Fact, Product


RULE_VERSION = "appsec-review/history-metric-vectors/1"
HISTORY_PRODUCER = "job_source_history_analysis"
PRIORITY_PRODUCER = "job_review_prioritization"
_HISTORY_METRICS = (
    ("lines_added", "lines_added"), ("lines_deleted", "lines_deleted"), ("churn_lines", "churn_lines"),
    ("relative_churn", "relative_churn"), ("revision_count", "change_count"),
    ("revision_frequency", "revision_frequency"), ("author_count", "author_count"),
    ("author_entropy", "author_entropy"), ("fix_on_fix_count", "fix_on_fix_count"),
)
_HISTORY_ALGORITHMS = {
    "fix_on_fix_count": "appsec-review/fix-on-fix/1", "sii_score": "appsec-review/security-instability-index/1",
    "sii_tier": "appsec-review/security-instability-index/1", "sii_rank": "appsec-review/security-instability-index/1",
}
_COMPLEXITY = (
    ("cyclomatic", "cyclomatic", "appsec-review/cyclomatic-complexity/1"),
    ("cognitive", "cognitive", "appsec-review/cognitive-complexity-approx/1"),
    ("complexity_density", "complexity_density", "appsec-review/cyclomatic-complexity/1"),
    ("cyclomatic_high_risk_share", "share_above_threshold", "appsec-review/cyclomatic-complexity/1"),
)


def metric(name: str, scope_id: str, value: Any, producer: str, algorithm: str, *, gap: str | None = None,
           window_days: int | None = None, language: str | None = None,
           source_sha256: str | None = None) -> dict[str, Any]:
    """One ``review-input-package`` metric object; a missing value is ``unavailable`` with a gap id."""
    item: dict[str, Any] = {"name": name, "scope_id": scope_id, "value": value,
                            "status": "available" if value is not None else "unavailable",
                            "producer": producer, "algorithm_version": algorithm}
    if window_days is not None:
        item["window_days"] = window_days
    if language:
        item["language"] = language
    if source_sha256:
        item["source_sha256"] = source_sha256
    if value is None:
        item["gap_id"] = gap or f"{name}_unavailable"
    return item


def build_metric_vectors(shards: AcceptedShards) -> Product:
    product = Product("history_context", RULE_VERSION)
    history = shards.select("history", shard_prefix="git-history")
    priority = shards.select("priority")
    product.use(history)
    product.use(priority)
    if not priority:
        return product.unavailable("metric vectors unavailable: no accepted priority index")
    if not history:
        product.partial("history index unavailable: churn, entropy, fix-on-fix and SII are unknown, not zero")
    files: dict[str, dict[str, Any]] = {}
    symbols: dict[tuple[str, int, int], dict[str, Any]] = {}
    window_months: int | None = None
    for row in shards.entities(history, ("history_signal", "hotspot")):
        if row.kind == "hotspot":
            months = (row.payload.get("window") or {}).get("months")
            window_months = int(months) if isinstance(months, int) else window_months
            continue
        if row.location is None:
            continue
        if row.native_id.startswith("file:"):
            files[row.location["path"]] = dict(row.payload)
        elif row.native_id.startswith("symbol:"):
            symbols[(row.location["path"], int(row.location["start_byte"]), int(row.location["end_byte"]))] = \
                dict(row.payload)
    window_days = round(window_months * 30.4375) if window_months else None
    if history and window_days is None:
        product.partial("history window unavailable: no accepted hotspot entry published its window")
    history_gap = None if history else "history_index_unavailable"
    unmatched = 0
    for row in shards.entities(priority, ("priority_item",)):
        payload = row.payload
        if row.location is None:
            product.partial(f"priority item {row.native_id} has no resolving location")
            continue
        path, sha, language = row.location["path"], row.location["file_sha256"], payload.get("language")
        source = (symbols.get((path, int(row.location["start_byte"]), int(row.location["end_byte"])))
                  if payload.get("scope") == "function" else files.get(path))
        unmatched += source is None and bool(history)
        metrics = [metric(name, row.identity, (source or {}).get(key), HISTORY_PRODUCER,
                          _HISTORY_ALGORITHMS.get(name, "appsec-review/history-change-rules/2"),
                          gap=history_gap or ("history_scope_unmatched" if source is None else None),
                          window_days=window_days, language=language, source_sha256=sha)
                   for name, key in _HISTORY_METRICS]
        sii = (source or {}).get("sii") or {}
        metrics.extend(metric(name, row.identity, sii.get(key), HISTORY_PRODUCER, _HISTORY_ALGORITHMS[name],
                              gap=history_gap or ("sii_not_ranked" if source else "history_scope_unmatched"),
                              window_days=window_days, language=language, source_sha256=sha)
                       for name, key in (("sii_score", "score"), ("sii_tier", "tier"), ("sii_rank", "rank")))
        features = payload.get("features") or {}
        metrics.extend(metric(name, row.identity, features.get(key), PRIORITY_PRODUCER, algorithm,
                              language=language, source_sha256=sha) for name, key, algorithm in _COMPLEXITY)
        metrics.append(metric("cyclomatic_mean", row.identity, None, PRIORITY_PRODUCER,
                              "appsec-review/cyclomatic-complexity/1",
                              gap="cyclomatic_mean_not_produced_by_prioritization", language=language,
                              source_sha256=sha))
        metrics.append(metric("parser_coverage", row.identity, "partial" if payload.get("gaps") else "complete",
                              PRIORITY_PRODUCER, "tree-sitter-accepted-shards", language=language, source_sha256=sha))
        unavailable = sorted({item["gap_id"] for item in metrics if item["status"] == "unavailable"})
        product.facts.append(Fact(
            "metric_vector", row.identity,
            {"scope": payload.get("scope"), "rank": payload.get("rank"), "score": payload.get("score"),
             "score_identity": payload.get("score_identity"), "window_months": window_months, "metrics": metrics,
             "unavailable_metrics": unavailable,
             "authority": "review-priority features; never technical finding severity"},
            "accepted priority item joined to accepted history signal by exact path or byte span",
            row.identity, path, (row.identity,), "partial" if unavailable else "complete",
            row.source_location(shards.snapshot), f"metric vector {path} {payload.get('scope')} rank {payload.get('rank')}"))
    if unmatched:
        product.partial(f"{unmatched} priority item(s) have no history signal with the same path or byte span")
    product.counts = {"metric_vectors": len(product.facts), "history_files": len(files),
                      "history_symbols": len(symbols)}
    return product
