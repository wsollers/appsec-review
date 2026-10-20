"""Normalize one job's accepted output so two runs of the same corpus can be compared.

A job's output is what its attempt publishes: ``status.json``, ``result.json`` and, when accepted,
``handoff.json`` with the artifacts it names. Gaps and findings are kept in full. Every other
output is kept with volatile values masked and long lists reduced to a count and a digest; large
artifacts are reduced to a normalized content digest, counts, and (for retrieval shards) their
coverage rows and observation entities. Raw digests and sizes are kept apart under ``volatile``.

Masked (docs/processes/acceptance-and-regression-testing.md, Phase 4): run and attempt ids,
timestamps and durations, absolute run/repository/target paths, image ids and digests, randomized
scratch names, container names and pids, Dagster run ids and node names, and the 64-hex digests
computed over any of these.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable, Mapping

SCHEMA = "appsec-review/acceptance-job-output/1"
LIST_SUMMARY_THRESHOLD = 50
JSON_ARTIFACT_LIMIT = 32 * 1024 * 1024

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<timestamp>"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}-\d{4}\b"), "<run-id>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "<uuid>"),
    (re.compile(r"sha256:[0-9a-f]{64}"), "<image-digest>"),
    (re.compile(r"\b[0-9a-f]{64}\b"), "<sha256>"),
    (re.compile(r"\battempt_\d{4}\b"), "<attempt>"),
    (re.compile(r"(?<=execution-capture:command-\d{3}:event-)\d+"), "<n>"),
    (re.compile(r"\btrace\.\d+\b"), "trace.<n>"),
    (re.compile(r"\b0x[0-9a-f]{8,16}\b"), "0x<addr>"),
    (re.compile(r"\(\d+(?:\.\d+)?s\)"), "(<duration>)"),
    (re.compile(r"\.appsec-review-build-scratch\.[A-Za-z0-9]+"), ".appsec-review-build-scratch.<random>"),
    (re.compile(r"\.tmp-[A-Za-z0-9_]{6,}"), ".tmp-<random>"),
    (re.compile(r"(?<=build-scratch\.<random>/)cc[A-Za-z0-9]{6}(?=\.)"), "cc<random>"),
    (re.compile(r"\bTryCompile-[A-Za-z0-9]{6}\b"), "TryCompile-<random>"),
    (re.compile(r"\bcmTC_[0-9a-f]{5,}\b"), "cmTC_<random>"),
    (re.compile(r"\btarget(?=[A-Za-z0-9]*[A-Z0-9])[A-Za-z0-9]{6}\b"), "target<random>"),
    (re.compile(r"\btmp[a-z0-9_]{8}\b"), "tmp<random>"),
    (re.compile(r"(?<![\w.])/tmp/[^\s\"'/]+"), "/tmp/<random>"),
)
_TIME_KEYS = {"timestamp", "started", "completed", "created", "modified", "mtime", "ctime"}
_VOLATILE_KEYS = {"pid", "pids", "container", "container_id", "container_name", "hostname",
                  "image_id", "image_digest", "repo_digest", "repo_digests", "digest",
                  "dagster_run_id", "dagster_node", "size_bytes",
                  # Syscall-trace bookkeeping: how many events a traced build produced, how they were
                  # numbered and how large the raw traces were vary from run to run.
                  "event_ordinals", "event_records_observed", "event_records_retained", "capture_events",
                  "observed_bytes", "retained_bytes", "retained_lines"}
# Inside these mappings every number measures the syscall trace (event counts, byte and line sizes).
_TRACE_PARENTS = {"raw_traces", "execution_capture"}
_TRACE_KEEP = ("exit", "status", "code", "signal")
# Lists whose order is the order concurrent build processes happened to start in.
_UNORDERED_KEYS = {"rows", "tool_invocations"}
_FTS = re.compile(r"^(search_fts|sqlite_)")


@dataclass(frozen=True)
class Masks:
    """Literal path prefixes and the run id one run's output is masked with."""

    run_id: str
    literals: tuple[tuple[str, str], ...] = ()

    @classmethod
    def for_run(cls, run_id: str, *, runs_roots: Iterable[str] = (), repository_roots: Iterable[str] = (),
                target_roots: Iterable[str] = ()) -> "Masks":
        literals = [(f"{str(root).rstrip('/')}/{run_id}", "<run>") for root in runs_roots]
        literals += [(str(root).rstrip("/"), "<target>") for root in target_roots]
        literals += [(str(root).rstrip("/"), "<repo>") for root in repository_roots]
        literals = [(source, target) for source, target in literals if source]
        return cls(run_id, tuple(sorted(set(literals), key=lambda item: -len(item[0]))))

    def text(self, value: str) -> str:
        for source, replacement in self.literals:
            value = value.replace(source, replacement)
        if self.run_id:
            value = value.replace(self.run_id, "<run-id>")
        for pattern, replacement in _PATTERNS:
            value = pattern.sub(replacement, value)
        return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _key_mask(key: str) -> str | None:
    lowered = key.lower()
    if lowered in _VOLATILE_KEYS:
        return f"<{lowered}>"
    if lowered.endswith("_at") or lowered in _TIME_KEYS:
        return "<timestamp>"
    if (lowered.endswith(("_ms", "_ns", "_seconds", "_secs")) or "duration" in lowered
            or "elapsed" in lowered):
        return "<duration>"
    return None


def _enters_trace(key: str, child: Any, trace: bool) -> bool:
    return trace or key in _TRACE_PARENTS or (key == "events" and isinstance(child, Mapping) and "observed" in child)


def _is_trace_number(key: str, child: Any, trace: bool) -> bool:
    return (trace and isinstance(child, (int, float)) and not isinstance(child, bool)
            and not any(word in key.lower() for word in _TRACE_KEEP))


def normalize_value(value: Any, masks: Masks, *, summarize: bool = False, trace: bool = False) -> Any:
    """Mask volatile values; with ``summarize``, reduce long lists to a count and a digest.

    ``trace`` is set inside a build's execution-capture measurements, where every number counts or
    sizes syscall events and so varies from run to run, while the commands that ran do not.
    """

    if isinstance(value, Mapping):
        result = {}
        for key, child in value.items():
            name = masks.text(str(key))
            replacement = _key_mask(str(key))
            inside = _enters_trace(str(key), child, trace)
            if replacement is not None and child is not None:
                result[name] = replacement
            elif _is_trace_number(str(key), child, inside):
                result[name] = "<count>"
            else:
                normalized = normalize_value(child, masks, summarize=summarize, trace=inside)
                if str(key) in _UNORDERED_KEYS and isinstance(normalized, list):
                    normalized = sorted(normalized, key=canonical)
                result[name] = normalized
        return result
    if isinstance(value, (list, tuple)):
        items = [normalize_value(child, masks, summarize=summarize, trace=trace) for child in value]
        if summarize and len(items) > LIST_SUMMARY_THRESHOLD:
            return {"<summary>": {"count": len(items), "sha256": digest(sorted(canonical(item) for item in items))}}
        return items
    if isinstance(value, str):
        return masks.text(value)
    if isinstance(value, float) and value != value:  # NaN never compares equal
        return "<nan>"
    return value


def _is_finding_key(key: str) -> bool:
    return key == "findings" or key.endswith("_findings")


def _extract(value: Any, masks: Masks, gaps: Counter, findings: Counter, unit: str,
             trace: bool = False) -> Any:
    """Pull gaps and findings out of one unit output and return the remainder normalized."""

    if isinstance(value, Mapping):
        remainder = {}
        for key, child in value.items():
            if key == "gaps" and isinstance(child, (list, tuple)):
                for gap in child:
                    gaps[(unit, canonical(normalize_value(gap, masks)))] += 1
                continue
            if _is_finding_key(str(key)) and isinstance(child, (list, tuple)):
                for finding in child:
                    findings[(unit, str(key), canonical(normalize_value(finding, masks)))] += 1
                remainder[f"{key}#count"] = len(child)
                continue
            inside = _enters_trace(str(key), child, trace)
            replacement = _key_mask(str(key))
            if replacement is not None and child is not None:
                remainder[masks.text(str(key))] = replacement
            elif _is_trace_number(str(key), child, inside):
                remainder[masks.text(str(key))] = "<count>"
            else:
                extracted = _extract(child, masks, gaps, findings, unit, inside)
                if str(key) in _UNORDERED_KEYS and isinstance(extracted, list):
                    extracted = sorted(extracted, key=canonical)
                remainder[masks.text(str(key))] = extracted
        return remainder
    if isinstance(value, (list, tuple)):
        items = [_extract(child, masks, gaps, findings, unit, trace) for child in value]
        if len(items) > LIST_SUMMARY_THRESHOLD:
            return {"<summary>": {"count": len(items), "sha256": digest(sorted(canonical(item) for item in items))}}
        return items
    return normalize_value(value, masks)


def _sqlite_signature(path: Path, masked_path: str, masks: Masks, gaps: Counter,
                      findings: Counter) -> dict[str, Any]:
    signature: dict[str, Any] = {"kind": "sqlite"}
    try:
        database = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        return {"kind": "sqlite", "error": type(exc).__name__}
    try:
        tables = [row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        counts = {}
        for table in tables:
            if _FTS.match(table):
                continue
            counts[table] = database.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
        signature["rows"] = counts
        if "entities" in tables:
            signature["entity_kinds"] = dict(sorted(Counter(
                row[0] for row in database.execute("SELECT kind FROM entities")).items()))
        unit = f"artifact:{masked_path}"
        if "coverage" in tables:
            statuses: Counter = Counter()
            for area, status, gap in database.execute("SELECT area, status, gap FROM coverage"):
                statuses[str(status)] += 1
                if gap is not None:
                    gaps[(unit, canonical(normalize_value(
                        {"area": area, "status": status, "gap": gap}, masks)))] += 1
            signature["coverage_statuses"] = dict(sorted(statuses.items()))
        if "/indices/observations/" in f"/{masked_path}" and "entities" in tables:
            has_locations = "locations" in tables
            query = ("SELECT e.kind, e.name, e.text, l.path, l.start_line, l.end_line FROM entities e "
                     "LEFT JOIN locations l ON l.entity_id = e.identity" if has_locations else
                     "SELECT kind, name, text, NULL, NULL, NULL FROM entities")
            for kind, name, text, location, start, end in database.execute(query):
                record = {"kind": kind, "name": name, "text": text, "path": location,
                          "start_line": start, "end_line": end}
                findings[(unit, "observations", canonical(normalize_value(record, masks)))] += 1
    except sqlite3.Error as exc:
        signature["error"] = type(exc).__name__
    finally:
        database.close()
    return signature


def _artifact_signature(path: Path, masked_path: str, masks: Masks, gaps: Counter,
                        findings: Counter) -> dict[str, Any]:
    if not path.is_file():
        return {"kind": "missing"}
    if path.suffix == ".sqlite":
        return _sqlite_signature(path, masked_path, masks, gaps, findings)
    if path.suffix == ".json" and path.stat().st_size <= JSON_ARTIFACT_LIMIT:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"kind": "file"}
        normalized = normalize_value(document, masks)
        signature: dict[str, Any] = {"kind": "json", "sha256": digest(normalized)}
        if isinstance(document, (list, dict)):
            signature["count"] = len(document)
        return signature
    return {"kind": "file"}


def locate_attempt(run_root: Path, job_id: str, dagster_run_id: str | None = None) -> Path | None:
    """The attempt a Dagster run produced, else the accepted attempt, else the newest attempt."""

    job_root = Path(run_root) / "data" / "jobs" / job_id
    attempts = sorted((job_root / "attempts").glob("attempt_*")) if (job_root / "attempts").is_dir() else []
    if dagster_run_id:
        for attempt in reversed(attempts):
            try:
                claim = json.loads((attempt / "claim.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if dict(claim.get("orchestration") or {}).get("run_id") == dagster_run_id:
                return attempt
    pointer = job_root / "latest.json"
    if pointer.is_file():
        try:
            handoff = Path(run_root) / json.loads(pointer.read_text(encoding="utf-8"))["handoff_path"]
            return handoff.parent
        except (OSError, KeyError, ValueError):
            pass
    return attempts[-1] if attempts else None


def _read(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def normalize_job_output(run_root: Path, job_id: str, masks: Masks, *,
                         attempt_root: Path | None = None) -> dict[str, Any]:
    """Return the normalized output of ``job_id`` in one application run."""

    run_root = Path(run_root)
    attempt_root = attempt_root or locate_attempt(run_root, job_id)
    document: dict[str, Any] = {"schema": SCHEMA, "job_id": job_id}
    if attempt_root is None:
        return {**document, "status": "MISSING", "steps": {}, "units": {}, "failed_units": [],
                "skipped_units": [], "gaps": [], "findings": [], "outputs": {}, "artifacts": [],
                "handoff": None, "volatile": {"artifacts": []}}
    status = _read(attempt_root / "status.json") or {}
    result = _read(attempt_root / "result.json") or {}
    handoff = _read(attempt_root / "handoff.json")
    gaps: Counter = Counter()
    findings: Counter = Counter()
    outputs = {}
    for unit_id, output in sorted(dict(result.get("outputs", {})).items()):
        outputs[unit_id] = _extract(output, masks, gaps, findings, unit_id)
    units = {
        unit_id: {key: normalize_value(receipt.get(key), masks)
                  for key in ("status", "disposition", "producer", "terminal_status") if key in receipt}
        for unit_id, receipt in sorted(dict(result.get("units", {})).items()) if isinstance(receipt, Mapping)
    }
    artifacts = []
    volatile = []
    for artifact in (handoff or {}).get("artifacts", ()):
        relative = str(artifact.get("path", ""))
        if relative == (handoff or {}).get("resolving_paths", {}).get("result"):
            continue
        masked = masks.text(relative)
        signature = _artifact_signature(run_root / relative, masked, masks, gaps, findings)
        artifacts.append({"path": masked, **signature})
        volatile.append({"path": masked, "sha256": artifact.get("sha256"), "size_bytes": artifact.get("size_bytes")})
    document.update({
        "status": status.get("status", "UNKNOWN"),
        "handoff": None if handoff is None else {
            "status": handoff.get("status"),
            "completion_status": handoff.get("completion_status"),
            "schema_identity": handoff.get("schema_identity"),
            "upstream_jobs": sorted(dict(handoff.get("upstream_handoff_sha256", {}))),
        },
        "steps": dict(sorted(dict(result.get("steps", {})).items())),
        "units": units,
        "failed_units": sorted(result.get("failed_units", [])),
        "skipped_units": sorted(result.get("skipped_units", [])),
        "gaps": [{"unit": unit, "gap": json.loads(gap), "count": count}
                 for (unit, gap), count in sorted(gaps.items())],
        "findings": [{"unit": unit, "source": source, "record": json.loads(record), "count": count}
                     for (unit, source, record), count in sorted(findings.items())],
        "outputs": outputs,
        "artifacts": sorted(artifacts, key=canonical),
        "volatile": {"artifacts": sorted(volatile, key=canonical)},
    })
    return document


def gap_summary(document: Mapping[str, Any]) -> list[tuple[str, int]]:
    """Unique gaps across a job (unit-independent) with their total occurrence counts."""

    totals: Counter = Counter()
    for item in document.get("gaps", ()):
        gap = item["gap"]
        totals[gap if isinstance(gap, str) else canonical(gap)] += int(item["count"])
    return sorted(totals.items(), key=lambda pair: (-pair[1], pair[0]))
