"""Composite engineering-signal modifiers, lead promotion, and SAST-silence hunt queue.

Wires accepted upstream handoffs from:
- ``job_change_context_analysis`` (``change_context_boost``)
- ``job_test_coverage`` (``uncovered_risk_boost``)
- ``job_profile_data`` (``profile_hotpath_boost``)
- ``job_ci_configuration_analysis`` (``promoted_leads`` with ``lead_source="ci_configuration"``)
- ``job_artifact_security_analysis`` (``promoted_leads`` with ``lead_source="artifact_security"``)
- ``job_dependency_intelligence`` (``sca_reachability_boost`` + ``promoted_leads`` with ``lead_source="sca_reachable"``)
- ``job_evidence_collection`` + ``job_codeql_analysis`` (SAST coverage -> ``sast_silence_hunt_boost``
  and ``hunt_priority_reason="high_surface_zero_sast_coverage"``)

All upstream reads go strictly through ``.inputs`` (``accepted_upstream``) so provenance receipts are recorded.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
from typing import Any

from appsec_review.retrieval import EntityKind
from appsec_review.storage import canonical_json

from .inputs import accepted_handoff, has_handoff, producer_entities, read_json


PRIORITIZATION_SIGNALS_SCHEMA = "appsec-review/review-prioritization-signals/1"
COMPOSITE_SCORE_IDENTITY = "appsec-review/composite-prioritization-score/1"
HUNT_PRIORITY_REASON_ZERO_SAST = "high_surface_zero_sast_coverage"
_SEVERITIES = ("critical", "high", "medium", "low")
_SURFACE_FEATURES = (
    "ingress",
    "public_api",
    "sink",
    "privilege_shift",
    "sensitive_wrapper",
    "custom_parsing",
    "parser",
    "state_mutation",
)


@dataclass(frozen=True)
class CompositePrioritizationSettings:
    """Typed defaults for composite engineering modifiers and SAST-silence hunt promotion."""

    change_context_boost: float = 0.15
    uncovered_risk_boost: float = 0.18
    profile_hotpath_boost: float = 0.12
    sca_reachability_boost: float = 0.22
    sast_silence_hunt_boost: float = 0.20
    sast_silence_min_complexity: int = 5
    enable_change_context: bool = True
    enable_test_coverage: bool = True
    enable_profile_data: bool = True
    enable_ci_configuration: bool = True
    enable_artifact_security: bool = True
    enable_dependency_intelligence: bool = True
    enable_sast_silence_hunt: bool = True

    def __post_init__(self) -> None:
        if type(self.sast_silence_min_complexity) is not int or self.sast_silence_min_complexity < 0:
            raise ValueError("review prioritization sast_silence_min_complexity must be a non-negative integer")
        if any(not math.isfinite(getattr(self, name)) or getattr(self, name) < 0
               for name in self.weights_dict()):
            raise ValueError("review prioritization composite weights must be finite and non-negative")
        self.score_maximum()

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> CompositePrioritizationSettings:
        weights = settings.get("composite_weights")
        w_map = weights if isinstance(weights, Mapping) else {}
        sources = settings.get("sources")
        s_map = sources if isinstance(sources, Mapping) else {}
        sast_enabled = bool(s_map.get("semgrep", True)) or bool(s_map.get("codeql", True))
        enable_hunt = bool(s_map["sast_silence_hunt"]) if "sast_silence_hunt" in s_map else sast_enabled
        min_comp = settings.get("sast_silence_min_complexity", 5)
        return cls(
            change_context_boost=float(w_map.get("change_context_boost", 0.15)),
            uncovered_risk_boost=float(w_map.get("uncovered_risk_boost", 0.18)),
            profile_hotpath_boost=float(w_map.get("profile_hotpath_boost", 0.12)),
            sca_reachability_boost=float(w_map.get("sca_reachability_boost", 0.22)),
            sast_silence_hunt_boost=float(w_map.get("sast_silence_hunt_boost", 0.20)),
            sast_silence_min_complexity=min_comp,
            enable_change_context=bool(s_map.get("change_context", True)),
            enable_test_coverage=bool(s_map.get("test_coverage", True)),
            enable_profile_data=bool(s_map.get("profile_data", True)),
            enable_ci_configuration=bool(s_map.get("ci_configuration", True)),
            enable_artifact_security=bool(s_map.get("artifact_security", True)),
            enable_dependency_intelligence=bool(s_map.get("dependency_intelligence", True)),
            enable_sast_silence_hunt=enable_hunt,
        )

    def weights_dict(self) -> dict[str, float]:
        return {
            "change_context_boost": round(self.change_context_boost, 6),
            "uncovered_risk_boost": round(self.uncovered_risk_boost, 6),
            "profile_hotpath_boost": round(self.profile_hotpath_boost, 6),
            "sca_reachability_boost": round(self.sca_reachability_boost, 6),
            "sast_silence_hunt_boost": round(self.sast_silence_hunt_boost, 6),
        }

    def boost_maxima(self) -> dict[str, float]:
        # Every contributing factor is in [0, 1], including all three silence-hunt multipliers.
        # Use the same six-decimal precision as the emitted modifiers, not observed availability.
        enabled = {"change_context_boost": self.enable_change_context,
                   "uncovered_risk_boost": self.enable_test_coverage,
                   "profile_hotpath_boost": self.enable_profile_data,
                   "sca_reachability_boost": self.enable_dependency_intelligence,
                   "sast_silence_hunt_boost": self.enable_sast_silence_hunt}
        return {key: value if enabled[key] else 0.0 for key, value in self.weights_dict().items()}

    def score_maximum(self) -> float:
        try:
            maximum = round(math.fsum((1.0, *self.boost_maxima().values())), 6)
        except OverflowError as exc:
            raise ValueError("review prioritization composite maximum must be finite") from exc
        if not math.isfinite(maximum):
            raise ValueError("review prioritization composite maximum must be finite")
        return maximum


def score_normalization(settings: Mapping[str, Any]) -> dict[str, Any]:
    cfg = CompositePrioritizationSettings.from_settings(settings)
    return {"rule": COMPOSITE_SCORE_IDENTITY, "maximum": cfg.score_maximum(),
            "boost_maxima": cfg.boost_maxima(),
            "configuration_sha256": hashlib.sha256(canonical_json(dict(settings))).hexdigest()}


def _norm_path(raw: Any) -> str:
    text = str(raw or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _norm_severity(raw: Any, default: str = "medium") -> str:
    val = str(raw or "").strip().lower()
    if val in _SEVERITIES:
        return val
    if val in {"error", "severe"}:
        return "high"
    if val in {"warning", "warn"}:
        return "medium"
    if val in {"note", "info", "informational"}:
        return "low"
    return default


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _lead_id(source: str, *parts: Any) -> str:
    digest = hashlib.sha256(canonical_json([source, *parts])).hexdigest()[:20]
    return f"lead-{source}-{digest}"


def _norm_unit_score(raw: Any, *, bonus: float = 0.0) -> float:
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        return _clamp01(bonus)
    val = float(raw)
    if val <= 0.0:
        return _clamp01(bonus)
    scaled = val / 100.0 if val > 1.0 else val
    return _clamp01(scaled + bonus)


def _completion_status(handoff: Mapping[str, Any], publication: Mapping[str, Any]) -> str:
    # Whole-job completion takes precedence over a final unit that merely published successfully.
    status = str(handoff.get("completion_status") or handoff.get("terminal_status")
                 or publication.get("terminal_status") or "UNAVAILABLE")
    if handoff.get("execution_status") == "FAILED":
        return "FAILED"
    if status in {"SUCCEEDED", "COMPLETE", "COMPLETED"}:
        coverage = handoff.get("coverage")
        if isinstance(coverage, Mapping):
            return {"partial": "COMPLETED_WITH_GAPS", "unavailable": "UNAVAILABLE",
                    "not_applicable": "NOT_APPLICABLE", "skipped_policy": "SKIPPED_POLICY"}.get(
                        coverage.get("disposition"), status)
    return status


def _load_change_context(run_root: Path, enabled: bool) -> tuple[
    str, dict[str, float], dict[tuple[str, str], float],
    list[tuple[str, int, int, int | None, int | None, float]],
]:
    if not enabled:
        return "DISABLED", {}, {}, []
    if not has_handoff(run_root, "job_change_context_analysis"):
        return "UNAVAILABLE", {}, {}, []
    handoff, _ = accepted_handoff(run_root, "job_change_context_analysis")
    out = handoff.get("outputs", {}).get("publish.publish_handoff") or {}
    status = _completion_status(handoff, out)
    art = out.get("artifact")
    if not isinstance(art, Mapping):
        return status, {}, {}, []
    doc = read_json(run_root, art)
    if doc.get("schema") != "appsec-review/change-context-analysis/1":
        return "UNAVAILABLE", {}, {}, []

    file_scores: dict[str, float] = {}
    func_by_name: dict[tuple[str, str], float] = {}
    func_spans: list[tuple[str, int, int, int | None, int | None, float]] = []

    def ingest_entry(item: Mapping[str, Any], scope: str) -> None:
        path = _norm_path(item.get("path") or item.get("file"))
        if not path:
            return
        sec_bonus = 0.2 if (item.get("security_relevant") or item.get("fix_on_fix") or item.get("security_touch")) else 0.0
        raw_score = item.get("score")
        if raw_score is None and isinstance(item.get("priority_score"), (int, float)):
            raw_score = item["priority_score"]
        if raw_score is None:
            raw_score = 0.65
        val = _norm_unit_score(raw_score, bonus=sec_bonus)
        if val <= 0.0:
            return
        if scope == "file":
            file_scores[path] = max(file_scores.get(path, 0.0), val)
        else:
            name = str(item.get("name") or item.get("symbol") or item.get("function") or "").strip()
            start = item.get("start_line") or item.get("line")
            end = item.get("end_line") or start
            if type(start) is int and type(end) is int and 1 <= start <= end:
                location = item.get("location") or {}
                start_byte, end_byte = location.get("start_byte"), location.get("end_byte")
                if start_byte is not None or end_byte is not None:
                    if type(start_byte) is not int or type(end_byte) is not int or not 0 <= start_byte < end_byte:
                        return
                func_spans.append((path, start, end, start_byte, end_byte, val))
            elif name and start is None and end is None:
                func_by_name[(path, name)] = max(func_by_name.get((path, name), 0.0), val)

    top = ((doc.get("priority") or {}).get("top") or {}) if isinstance(doc.get("priority"), Mapping) else {}
    for entry in top.get("files", ()) if isinstance(top, Mapping) else ():
        if isinstance(entry, Mapping):
            ingest_entry(entry, "file")
    for entry in top.get("functions", ()) if isinstance(top, Mapping) else ():
        if isinstance(entry, Mapping):
            ingest_entry(entry, "function")
    if isinstance(doc.get("files"), Mapping):
        for raw_path, meta in doc["files"].items():
            if isinstance(meta, Mapping):
                ingest_entry({"path": raw_path, **meta}, "file")
    elif isinstance(doc.get("files"), list):
        for entry in doc["files"]:
            if isinstance(entry, Mapping):
                ingest_entry(entry, "file")
    if isinstance(doc.get("functions"), list):
        for entry in doc["functions"]:
            if isinstance(entry, Mapping):
                ingest_entry(entry, "function")
    return status, file_scores, func_by_name, func_spans


def _load_test_coverage(run_root: Path, enabled: bool) -> tuple[str, dict[str, dict[str, Any]]]:
    if not enabled:
        return "DISABLED", {}
    if not has_handoff(run_root, "job_test_coverage"):
        return "UNAVAILABLE", {}
    handoff, _ = accepted_handoff(run_root, "job_test_coverage")
    out = handoff.get("outputs", {}).get("acceptance.publish_handoff") or {}
    status = _completion_status(handoff, out)
    art = out.get("artifact")
    if not isinstance(art, Mapping):
        return status, {}
    doc = read_json(run_root, art)
    if doc.get("schema") != "appsec-review/test-coverage-handoff/1":
        return "UNAVAILABLE", {}

    per_file: dict[str, dict[str, Any]] = {}
    units = list(doc.get("build_units", ())) if isinstance(doc.get("build_units"), list) else []
    if isinstance(doc.get("files"), list):
        units.append({"files": doc["files"]})
    for bu in units:
        if not isinstance(bu, Mapping):
            continue
        for fentry in bu.get("files", ()) or ():
            if not isinstance(fentry, Mapping):
                continue
            path = _norm_path(fentry.get("path"))
            if not path:
                continue
            slot = per_file.setdefault(path, {
                "lines_total": 0, "lines_covered": 0,
                "covered_lines": set(), "uncovered_lines": set(),
                "uncovered_functions": set(), "covered_functions": set(),
            })
            totals = fentry.get("totals") if isinstance(fentry.get("totals"), Mapping) else fentry
            lt, lc = totals.get("lines_total", 0), totals.get("lines_covered", 0)
            if isinstance(lt, int) and lt > 0:
                slot["lines_total"] += lt
                slot["lines_covered"] += max(0, min(lt, int(lc) if isinstance(lc, int) else 0))
            for ln in fentry.get("uncovered_lines", ()) or ():
                if isinstance(ln, int) and ln >= 1:
                    slot["uncovered_lines"].add(ln)
            for ln in fentry.get("covered_lines", ()) or ():
                if isinstance(ln, int) and ln >= 1:
                    slot["covered_lines"].add(ln)
            lines_map = fentry.get("lines")
            if isinstance(lines_map, Mapping):
                for raw_ln, hits in lines_map.items():
                    try:
                        ln_i = int(raw_ln)
                    except (TypeError, ValueError):
                        continue
                    if isinstance(hits, (int, float)) and hits > 0:
                        slot["covered_lines"].add(ln_i)
                    else:
                        slot["uncovered_lines"].add(ln_i)
            funcs = fentry.get("functions")
            if isinstance(funcs, list):
                for fn in funcs:
                    if isinstance(fn, Mapping) and fn.get("name"):
                        fname = str(fn["name"])
                        hits = fn.get("count", fn.get("hits", fn.get("covered")))
                        if isinstance(hits, (int, float)) and hits > 0:
                            slot["covered_functions"].add(fname)
                        elif hits == 0 or hits is False:
                            slot["uncovered_functions"].add(fname)
    return status, per_file


def _load_profile_data(run_root: Path, enabled: bool) -> tuple[str, dict[str, float], dict[tuple[str, str], float], list[tuple[str, int, float]]]:
    if not enabled:
        return "DISABLED", {}, {}, []
    if not has_handoff(run_root, "job_profile_data"):
        return "UNAVAILABLE", {}, {}, []
    handoff, _ = accepted_handoff(run_root, "job_profile_data")
    out = handoff.get("outputs", {}).get("acceptance.publish_handoff") or {}
    status = _completion_status(handoff, out)
    art = out.get("artifact")
    if not isinstance(art, Mapping):
        return status, {}, {}, []
    doc = read_json(run_root, art)
    if doc.get("schema") != "appsec-review/profile-data-handoff/1":
        return "UNAVAILABLE", {}, {}, []

    raw_rows: list[Mapping[str, Any]] = []
    for bu in doc.get("build_units", ()) or ():
        if isinstance(bu, Mapping):
            for r in bu.get("rows", ()) or ():
                if isinstance(r, Mapping):
                    raw_rows.append(r)
    for r in doc.get("rows", ()) or ():
        if isinstance(r, Mapping):
            raw_rows.append(r)
    max_count = max(
        (float(r["count"]) for r in raw_rows if isinstance(r.get("count"), (int, float)) and not isinstance(r.get("count"), bool)),
        default=0.0,
    )
    file_hot: dict[str, float] = {}
    sym_hot: dict[tuple[str, str], float] = {}
    line_hot: list[tuple[str, int, float]] = []
    for r in raw_rows:
        path = _norm_path(r.get("source") or r.get("path"))
        if not path:
            continue
        rank = r.get("hotness_rank")
        pop = r.get("hotness_population")
        count = r.get("count")
        if isinstance(rank, int) and isinstance(pop, int) and pop > 0 and 1 <= rank <= pop:
            weight = _clamp01((pop - rank + 1) / pop)
        elif isinstance(count, (int, float)) and max_count > 0:
            weight = _clamp01(float(count) / max_count)
        else:
            weight = 0.5
        file_hot[path] = max(file_hot.get(path, 0.0), weight)
        sym = str(r.get("symbol") or r.get("function") or "").strip()
        if sym:
            sym_hot[(path, sym)] = max(sym_hot.get((path, sym), 0.0), weight)
        line = r.get("line")
        if isinstance(line, int) and line >= 1:
            line_hot.append((path, line, weight))
    return status, file_hot, sym_hot, line_hot


def _load_ci_leads(run_root: Path, enabled: bool) -> tuple[str, list[dict[str, Any]]]:
    if not enabled:
        return "DISABLED", []
    if not has_handoff(run_root, "job_ci_configuration_analysis"):
        return "UNAVAILABLE", []
    handoff, _ = accepted_handoff(run_root, "job_ci_configuration_analysis")
    out = handoff.get("outputs", {}).get("ci_coverage.publish_handoff") or {}
    status = _completion_status(handoff, out)
    candidates: list[Mapping[str, Any]] = []
    art = out.get("artifact")
    if isinstance(art, Mapping):
        doc = read_json(run_root, art)
        for item in doc.get("security_findings", ()) or ():
            if isinstance(item, Mapping):
                candidates.append(item)
        if not candidates:
            for item in doc.get("findings", ()) or ():
                if isinstance(item, Mapping):
                    candidates.append(item)
    if not candidates and isinstance(out.get("index_manifest"), Mapping):
        for _shard, entity in producer_entities(
            run_root, out["index_manifest"],
            job="job_ci_configuration_analysis",
            kind=EntityKind.TOOL_OBSERVATION.value,
        ):
            payload = dict(entity["payload"])
            loc = entity.get("location")
            if isinstance(loc, Mapping):
                payload.setdefault("path", loc.get("path"))
                payload.setdefault("line", loc.get("start_line"))
            candidates.append(payload)

    leads: dict[str, dict[str, Any]] = {}
    for item in candidates:
        if not bool(item.get("lead_candidate")):
            continue
        path = _norm_path(item.get("path") or item.get("workflow_path")) or None
        raw_line = item.get("line", item.get("start_line"))
        line = int(raw_line) if isinstance(raw_line, int) and raw_line >= 1 else None
        rule_id = str(item.get("rule_id") or item.get("id") or "ci-security-risk")
        attack_class = str(item.get("attack_class") or "ci_workflow_compromise")
        severity_hint = _norm_severity(item.get("severity_hint") or item.get("severity"), default="high")
        summary = str(item.get("message") or item.get("summary") or item.get("title") or rule_id)
        lid = _lead_id("ci_configuration", path, line, rule_id, attack_class)
        leads[lid] = {
            "lead_id": lid,
            "lead_source": "ci_configuration",
            "producer": "job_ci_configuration_analysis",
            "attack_class": attack_class,
            "severity_hint": severity_hint,
            "path": path,
            "line": line,
            "start_line": line,
            "end_line": line,
            "rule_id": rule_id,
            "summary": summary,
        }
    ordered = sorted(leads.values(), key=lambda x: (_SEVERITIES.index(x["severity_hint"]), x["path"] or "", x["line"] or 0, x["lead_id"]))
    return status, ordered


def _load_artifact_leads(run_root: Path, enabled: bool) -> tuple[str, list[dict[str, Any]]]:
    if not enabled:
        return "DISABLED", []
    if not has_handoff(run_root, "job_artifact_security_analysis"):
        return "UNAVAILABLE", []
    handoff, _ = accepted_handoff(run_root, "job_artifact_security_analysis")
    out = handoff.get("outputs", {}).get("acceptance.publish_handoff") or {}
    status = _completion_status(handoff, out)
    candidates: list[tuple[str, str | None, str | None, int | None, Mapping[str, Any]]] = []
    art = out.get("artifact")
    if isinstance(art, Mapping):
        doc = read_json(run_root, art)
        for key in ("promoted_findings", "security_findings", "findings"):
            for ordinal, item in enumerate(doc.get(key, ()) or ()):
                if isinstance(item, Mapping):
                    p = _norm_path(item.get("path")) or None
                    ln = item.get("line", item.get("start_line"))
                    identity = _lead_id("artifact_document", art["sha256"], key, ordinal)
                    candidates.append((identity, None, p, int(ln) if type(ln) is int and ln >= 1 else None, item))
    if isinstance(out.get("index_manifest"), Mapping):
        for _shard, entity in producer_entities(
            run_root, out["index_manifest"],
            job="job_artifact_security_analysis",
            kind=EntityKind.TOOL_OBSERVATION.value,
        ):
            loc = entity.get("location")
            loc_path = _norm_path(loc.get("path")) if isinstance(loc, Mapping) else None
            raw_ll = loc.get("start_line") if isinstance(loc, Mapping) else None
            loc_line = int(raw_ll) if isinstance(raw_ll, int) and raw_ll >= 1 else None
            payload = entity["payload"]
            nested = payload.get("findings")
            if isinstance(nested, list):
                for ordinal, nf in enumerate(nested):
                    if isinstance(nf, Mapping):
                        p = _norm_path(nf.get("path")) or loc_path or None
                        ln = nf.get("line", loc_line)
                        identity = _lead_id("artifact_nested", entity["identity"], ordinal)
                        candidates.append((identity, str(entity["identity"]), p,
                                           int(ln) if type(ln) is int and ln >= 1 else None, nf))
            if bool(payload.get("lead_candidate")):
                candidates.append((str(entity["identity"]), str(entity["identity"]), loc_path or None, loc_line, payload))

    leads: dict[str, dict[str, Any]] = {}
    seen_observations: dict[str, bytes] = {}
    for candidate_identity, observation_identity, path, line, item in candidates:
        if not bool(item.get("lead_candidate")):
            continue
        content = canonical_json([path, line, item])
        if candidate_identity in seen_observations and seen_observations[candidate_identity] != content:
            raise ValueError("conflicting artifact finding identity in accepted priority inputs")
        seen_observations[candidate_identity] = content
        common = item.get("common") if isinstance(item.get("common"), Mapping) else {}
        rule_id = str(common.get("rule_id") or item.get("rule_id") or item.get("code")
                      or item.get("id") or "artifact-security-risk")
        attack_class = str(item.get("attack_class") or "packaged_artifact_risk")
        severity_hint = _norm_severity(item.get("severity_hint") or item.get("severity"), default="unknown")
        summary = str(item.get("summary") or item.get("message") or item.get("detail") or rule_id)
        artifact = item.get("artifact") if isinstance(item.get("artifact"), Mapping) else {}
        subject_artifact = item.get("subject_artifact") or artifact.get("canonical_identity")
        lid = _lead_id("artifact_security", candidate_identity, subject_artifact,
                       item.get("subject"), item.get("occurrence"), rule_id, attack_class)
        lead = {
            "lead_id": lid,
            "lead_source": "artifact_security",
            "producer": "job_artifact_security_analysis",
            "attack_class": attack_class,
            "severity_hint": severity_hint,
            "path": path,
            "line": line,
            "start_line": line,
            "end_line": line,
            "rule_id": rule_id,
            "summary": summary,
            **({"observation_identity": observation_identity} if observation_identity is not None else {}),
            "subject_artifact": subject_artifact,
            "subject": item.get("subject"),
            "evidence_refs": list(common.get("evidence_refs") or ()),
        }
        if lid in leads and leads[lid] != lead:
            raise ValueError("conflicting artifact finding identity in accepted priority inputs")
        leads[lid] = lead
    ordered = sorted(leads.values(), key=lambda x: (
        (*_SEVERITIES, "unknown").index(x["severity_hint"]), x["path"] or "", x["line"] or 0, x["lead_id"]))
    return status, ordered


def _load_sca_reachability(
    run_root: Path, enabled: bool,
) -> tuple[str, list[dict[str, Any]], dict[str, float], list[tuple[str, int, float]]]:
    if not enabled:
        return "DISABLED", [], {}, []
    if not has_handoff(run_root, "job_dependency_intelligence"):
        return "UNAVAILABLE", [], {}, []
    from appsec_review.runtime.inputs import observe_output

    handoff, _ = accepted_handoff(run_root, "job_dependency_intelligence")
    out = handoff.get("outputs", {}).get("acceptance.publish_handoff") or {}
    status = _completion_status(handoff, out)
    art = out.get("sca_reachability") or out.get("sca_reachability_artifact")
    if not isinstance(art, Mapping) and isinstance(out.get("artifact"), Mapping):
        observe_output(run_root, "job_dependency_intelligence",
                       "dependency_intelligence_handoff", out["artifact"])
        hdoc = read_json(run_root, out["artifact"])
        art = hdoc.get("sca_reachability")
    if not isinstance(art, Mapping):
        return status, [], {}, []
    observe_output(run_root, "job_dependency_intelligence", "sca_reachability", art)
    doc = read_json(run_root, art)
    if doc.get("schema") != "appsec-review/sca-reachability/1":
        return "UNAVAILABLE", [], {}, []

    leads: dict[str, dict[str, Any]] = {}
    file_reach: dict[str, float] = {}
    site_reach: list[tuple[str, int, float]] = []
    for adv in doc.get("advisories", ()) or ():
        if not isinstance(adv, Mapping):
            continue
        state = str(adv.get("reachability") or "")
        if state not in {"symbol_reachable", "package_imported"}:
            continue
        base_factor = 1.0 if state == "symbol_reachable" else 0.55
        call_sites = [cs for cs in (adv.get("call_sites") or ()) if isinstance(cs, Mapping)]
        ffi_mechanisms = set(adv.get("ffi_mechanisms") or ())
        ffi_paths = {
            _norm_path(cs.get("path")) for cs in call_sites
            if cs.get("kind") == "ffi_boundary" and cs.get("ffi_mechanism") in ffi_mechanisms
        }
        first_path: str | None = None
        first_line: int | None = None
        for cs in call_sites:
            cpath = _norm_path(cs.get("path"))
            cline = cs.get("line")
            if not cpath:
                continue
            factor = _clamp01(base_factor + (0.15 if cpath in ffi_paths else 0.0))
            file_reach[cpath] = max(file_reach.get(cpath, 0.0), factor)
            if isinstance(cline, int) and cline >= 1:
                site_reach.append((cpath, cline, factor))
                if first_path is None:
                    first_path, first_line = cpath, cline
            elif first_path is None:
                first_path = cpath
        adv_id = str(adv.get("advisory_id") or "OSV-UNKNOWN")
        pkg = str(adv.get("package_name") or "unknown-package")
        sev_default = "high" if state == "symbol_reachable" else "medium"
        sev = _norm_severity(adv.get("severity"), default=sev_default)
        attack_class = "native_ffi_vulnerable_dependency" if ffi_paths else "vulnerable_dependency_reachability"
        dependency_ids = sorted(adv.get("dependency_ids") or ())
        lid = _lead_id("sca_reachable", adv_id, pkg, adv.get("ecosystem"), adv.get("package_version"),
                       adv.get("purl"), dependency_ids, state, first_path, first_line)
        subject = adv.get("purl") or f"{adv.get('ecosystem') or 'unknown'}:{pkg}@{adv.get('package_version') or 'unknown'}"
        leads[lid] = {
            "lead_id": lid,
            "lead_source": "sca_reachable",
            "producer": "job_dependency_intelligence",
            "attack_class": attack_class,
            "severity_hint": sev,
            "path": first_path,
            "line": first_line,
            "start_line": first_line,
            "end_line": first_line,
            "rule_id": adv_id,
            "summary": f"{adv_id} in {subject} ({state}; static evidence only)",
            "subject": subject,
            "package_name": pkg,
            "ecosystem": str(adv["ecosystem"]) if adv.get("ecosystem") else None,
            "reachability": state,
        }
    ordered = sorted(leads.values(), key=lambda x: (_SEVERITIES.index(x["severity_hint"]), x["path"] or "", x["line"] or 0, x["lead_id"]))
    return status, ordered, file_reach, site_reach


def _collect_sast_spans(
    run_root: Path, semantic_doc: Mapping[str, Any], sources: Mapping[str, Any],
) -> dict[str, list[tuple[int, int]]]:
    spans: dict[str, set[tuple[int, int]]] = defaultdict(set)
    semgrep_list = [
        *(semantic_doc.get("semgrep_signals") or ()),
        *(((semantic_doc.get("semgrep") or {}).get("signals")) or ()),
    ]
    for sig in semgrep_list:
        if isinstance(sig, Mapping):
            p = _norm_path(sig.get("path"))
            s = sig.get("start_line")
            e = sig.get("end_line") or s
            if p and isinstance(s, int) and s >= 1:
                spans[p].add((s, max(s, int(e) if isinstance(e, int) else s)))
    codeql_list = [
        *(semantic_doc.get("semantic_paths") or ()),
        *(((semantic_doc.get("codeql") or {}).get("paths")) or ()),
    ]
    for cpath in codeql_list:
        if isinstance(cpath, Mapping):
            for endpoint in ("sink", "source"):
                node = cpath.get(endpoint)
                if isinstance(node, Mapping):
                    p = _norm_path(node.get("path"))
                    s = node.get("start_line")
                    e = node.get("end_line") or s
                    if p and isinstance(s, int) and s >= 1:
                        spans[p].add((s, max(s, int(e) if isinstance(e, int) else s)))
            for step in cpath.get("flow_steps") or ():
                loc = step.get("location") if isinstance(step, Mapping) else None
                if isinstance(loc, Mapping):
                    p = _norm_path(loc.get("path"))
                    s = loc.get("start_line")
                    e = loc.get("end_line") or s
                    if p and isinstance(s, int) and s >= 1:
                        spans[p].add((s, max(s, int(e) if isinstance(e, int) else s)))
    if bool(sources.get("semgrep", True)) and has_handoff(run_root, "job_evidence_collection"):
        handoff, _ = accepted_handoff(run_root, "job_evidence_collection")
        outputs = handoff.get("outputs") or {}
        mf_key_name = (
            "evidence_publication.publish_handoff"
            if "evidence_publication.publish_handoff" in outputs
            else "publish_evidence.publish_handoff"
        )
        out = outputs.get(mf_key_name) or {}
        from appsec_review.indexing.sast import read_scanner_output, scanner_handoff_payload
        document = scanner_handoff_payload(run_root, handoff)
        corr = (document or {}).get("corroborated_sast_evidence")
        if isinstance(corr, Mapping):
            cdoc = read_scanner_output(run_root, handoff, "corroborated_sast_evidence", corr)
            if cdoc.get("schema") != "appsec-review/corroborated-sast-evidence/1":
                raise ValueError("scanner corroboration schema mismatch")
            for cl in cdoc.get("clusters", ()) or ():
                loc = cl.get("location") if isinstance(cl, Mapping) else None
                if isinstance(loc, Mapping):
                    p = _norm_path(loc.get("path"))
                    s = loc.get("start_line")
                    e = loc.get("end_line") or s
                    if p and isinstance(s, int) and s >= 1:
                        spans[p].add((s, max(s, int(e) if isinstance(e, int) else s)))
        if isinstance(out.get("index_manifest"), Mapping):
            from appsec_review.indexing.store import ShardSet
            from appsec_review.retrieval.index import load_verified_manifest
            manifest = out["index_manifest"]
            document, _ = load_verified_manifest(run_root, run_root / manifest["path"], manifest["sha256"])
            store = ShardSet(run_root, document["indexes"])
            for entity in store.entities(store.select(index="observations", job="job_evidence_collection"),
                                         kinds=(EntityKind.TOOL_OBSERVATION.value,)):
                loc = entity.get("location")
                if isinstance(loc, Mapping):
                    p = _norm_path(loc.get("path"))
                    raw_s = loc.get("start_line")
                    raw_e = loc.get("end_line") or raw_s
                    if p and isinstance(raw_s, int) and raw_s >= 1:
                        s = int(raw_s)
                        e = max(s, int(raw_e) if isinstance(raw_e, int) else s)
                        spans[p].add((s, e))
    return {p: sorted(vals) for p, vals in spans.items()}


def _has_sast_overlap(
    spans: Mapping[str, list[tuple[int, int]]], path: str, start_line: int | None = None, end_line: int | None = None,
) -> bool:
    file_spans = spans.get(_norm_path(path))
    if not file_spans:
        return False
    if start_line is None:
        return True
    hi = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
    return any(s <= hi and e >= start_line for s, e in file_spans)


def _surface_count(features: Mapping[str, Any]) -> int:
    return sum(int(features.get(k) or 0) for k in _SURFACE_FEATURES)


def _complexity_factor(features: Mapping[str, Any]) -> float:
    cyc = float(features.get("cyclomatic") or 0.0)
    cog = float(features.get("cognitive") or 0.0)
    peak = max(cyc, cog)
    if peak <= 0.0:
        return 0.0
    return _clamp01(0.35 + 0.65 * min(1.0, peak / 12.0))


def _uncovered_factor(
    cov_map: Mapping[str, Mapping[str, Any]],
    path: str,
    *,
    name: str | None = None,
    start_line: int | None = None,
    end_line: int | None = None,
) -> float:
    entry = cov_map.get(_norm_path(path))
    if not entry:
        return 0.0
    if name:
        if name in entry["uncovered_functions"]:
            return 1.0
        if name in entry["covered_functions"] and not entry["uncovered_lines"]:
            return 0.0
    if start_line is not None:
        hi = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
        uncov_in_span = sum(1 for ln in entry["uncovered_lines"] if start_line <= ln <= hi)
        cov_in_span = sum(1 for ln in entry["covered_lines"] if start_line <= ln <= hi)
        if uncov_in_span + cov_in_span > 0:
            return _clamp01(uncov_in_span / (uncov_in_span + cov_in_span))
    lt = int(entry.get("lines_total") or 0)
    lc = int(entry.get("lines_covered") or 0)
    if lt > 0:
        return _clamp01(1.0 - (lc / lt))
    if entry["uncovered_lines"]:
        total_known = len(entry["uncovered_lines"]) + len(entry["covered_lines"])
        return _clamp01(len(entry["uncovered_lines"]) / max(1, total_known))
    return 0.0


def _rerank(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        items,
        key=lambda item: (
            -item["raw_score"],
            -item["boundary_total"],
            -item["feature_coverage"],
            item["path"],
            item.get("start_line") or 0,
            item.get("name") or "",
        ),
    )
    for position, item in enumerate(ordered, 1):
        item["rank"] = position
    return ordered


def apply_composite_prioritization(
    run_root: Path,
    *,
    target_snapshot: str,
    settings: Mapping[str, Any],
    semantic_doc: Mapping[str, Any],
    ranked_files: list[dict[str, Any]],
    ranked_functions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Apply engineering-signal modifiers, promote CI/artifact/SCA leads, and build the SAST-silence hunt queue."""
    cfg = CompositePrioritizationSettings.from_settings(settings)
    normalization = score_normalization(settings)
    sources = settings.get("sources") if isinstance(settings.get("sources"), Mapping) else {}

    cc_status, cc_files, cc_func_names, cc_func_spans = _load_change_context(run_root, cfg.enable_change_context)
    tc_status, tc_files = _load_test_coverage(run_root, cfg.enable_test_coverage)
    pd_status, pd_files, pd_syms, pd_lines = _load_profile_data(run_root, cfg.enable_profile_data)
    ci_status, ci_leads = _load_ci_leads(run_root, cfg.enable_ci_configuration)
    art_status, art_leads = _load_artifact_leads(run_root, cfg.enable_artifact_security)
    sca_status, sca_leads, sca_files, sca_sites = _load_sca_reachability(run_root, cfg.enable_dependency_intelligence)
    sast_spans = _collect_sast_spans(run_root, semantic_doc, sources) if cfg.enable_sast_silence_hunt else {}

    boosted_units = 0
    hunt_candidates: list[dict[str, Any]] = []

    def score_item(item: dict[str, Any], scope: str) -> None:
        nonlocal boosted_units
        path = _norm_path(item["path"])
        features = item.get("features") or {}
        start_line = item.get("start_line") if scope == "function" else None
        end_line = item.get("end_line") if scope == "function" else None
        name = str(item.get("name") or "") if scope == "function" else None

        cc_factor = cc_files.get(path, 0.0)
        if scope == "function":
            if name and (path, name) in cc_func_names:
                cc_factor = max(cc_factor, cc_func_names[(path, name)])
            if isinstance(start_line, int):
                hi = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
                for sp_path, sp_s, sp_e, sp_byte_s, sp_byte_e, sp_val in cc_func_spans:
                    if (sp_path == path and (sp_s, sp_e) == (start_line, hi)
                            and (sp_byte_s is None or (sp_byte_s, sp_byte_e) ==
                                 (item.get("start_byte"), item.get("end_byte")))):
                        cc_factor = max(cc_factor, sp_val)
        cc_boost = round(cfg.change_context_boost * cc_factor, 6)

        uncov_ratio = _uncovered_factor(tc_files, path, name=name, start_line=start_line, end_line=end_line)
        comp_factor = _complexity_factor(features)
        surf_bonus = 0.25 if _surface_count(features) > 0 else 0.0
        uncov_boost = round(
            cfg.uncovered_risk_boost * uncov_ratio * _clamp01(comp_factor + surf_bonus),
            6,
        ) if uncov_ratio > 0.0 and (comp_factor > 0.0 or surf_bonus > 0.0) else 0.0

        prof_factor = pd_files.get(path, 0.0) if scope == "file" else 0.0
        if scope == "function":
            if name and (path, name) in pd_syms:
                prof_factor = max(prof_factor, pd_syms[(path, name)])
            if isinstance(start_line, int):
                hi = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
                for lp, lno, lw in pd_lines:
                    if lp == path and start_line <= lno <= hi:
                        prof_factor = max(prof_factor, lw)
            if prof_factor == 0.0 and path in pd_files:
                prof_factor = pd_files[path] * 0.5
        prof_boost = round(cfg.profile_hotpath_boost * prof_factor, 6)

        sca_factor = sca_files.get(path, 0.0) if scope == "file" else 0.0
        if scope == "function" and isinstance(start_line, int):
            hi = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
            for sp, sln, sfac in sca_sites:
                if sp == path and start_line <= sln <= hi:
                    sca_factor = max(sca_factor, sfac)
            if sca_factor == 0.0 and path in sca_files:
                sca_factor = sca_files[path] * 0.35
        sca_boost = round(cfg.sca_reachability_boost * sca_factor, 6)

        hunt_boost = 0.0
        if cfg.enable_sast_silence_hunt:
            cyc = int(features.get("cyclomatic") or 0)
            cog = int(features.get("cognitive") or 0)
            surf = _surface_count(features)
            sem_paths = int(features.get("semantic_path") or 0)
            is_complex = max(cyc, cog) >= cfg.sast_silence_min_complexity
            sast_covered = sem_paths > 0 or _has_sast_overlap(sast_spans, path, start_line, end_line)
            if is_complex and surf > 0 and not sast_covered:
                ext_reach = (int(features.get("ingress") or 0) + int(features.get("public_api") or 0)) > 0
                reach_mul = 1.0 if ext_reach else 0.75
                surf_mul = min(1.0, 0.55 + 0.15 * min(3, surf))
                comp_mul = min(1.0, max(cyc, cog) / 10.0)
                hunt_boost = round(cfg.sast_silence_hunt_boost * reach_mul * surf_mul * max(0.5, comp_mul), 6)

        base_score = float(item["score"])
        if not math.isfinite(base_score) or not 0.0 <= base_score <= 1.0:
            raise ValueError("review prioritization base score must be finite and in [0, 1]")
        item["base_score"] = base_score
        item["composite_modifiers"] = {
            "change_context_boost": cc_boost,
            "uncovered_risk_boost": uncov_boost,
            "profile_hotpath_boost": prof_boost,
            "sca_reachability_boost": sca_boost,
            "sast_silence_hunt_boost": hunt_boost,
        }
        total_boost = round(math.fsum(item["composite_modifiers"].values()), 6)
        item["raw_score"] = round(math.fsum((base_score, *item["composite_modifiers"].values())), 6)
        # Do not round the quotient again: distinct raw priorities must not acquire artificial ties.
        item["score"] = item["raw_score"] / normalization["maximum"]
        if total_boost > 0.0:
            boosted_units += 1
        if hunt_boost > 0.0:
            item["hunt_priority_reason"] = HUNT_PRIORITY_REASON_ZERO_SAST
            hunt_candidates.append({
                "item_id": item["item_id"],
                "scope": scope,
                "path": item["path"],
                "function_id": item.get("function_id"),
                "name": item["name"],
                "language": item.get("language"),
                "start_line": item.get("start_line"),
                "end_line": item.get("end_line"),
                "score": item["score"],
                "raw_score": item["raw_score"],
                "base_score": base_score,
                "composite_modifiers": dict(item["composite_modifiers"]),
                "sast_silence_hunt_boost": hunt_boost,
                "hunt_priority_reason": HUNT_PRIORITY_REASON_ZERO_SAST,
            })

    for fitem in ranked_files:
        score_item(fitem, "file")
    for fnitem in ranked_functions:
        score_item(fnitem, "function")

    reranked_files = _rerank(ranked_files)
    reranked_functions = _rerank(ranked_functions)
    rank_by_id = {it["item_id"]: it["rank"] for it in (*reranked_files, *reranked_functions)}
    for hc in hunt_candidates:
        if hc["item_id"] in rank_by_id:
            hc["rank"] = rank_by_id[hc["item_id"]]
    hunt_queue = sorted(
        hunt_candidates,
        key=lambda x: (-x["raw_score"], 0 if x["scope"] == "function" else 1, x["path"], x.get("start_line") or 0, x["item_id"]),
    )
    promoted_leads = [*ci_leads, *art_leads, *sca_leads]
    telemetry = {
        "leads_promoted_ci": len(ci_leads),
        "leads_promoted_artifact": len(art_leads),
        "leads_promoted_sca_reachable": len(sca_leads),
        "sast_silence_hunt_units": len(hunt_queue),
        "composite_boosted_units": boosted_units,
    }
    signals_doc = {
        "schema": PRIORITIZATION_SIGNALS_SCHEMA,
        "target_snapshot": target_snapshot,
        "score_normalization": normalization,
        "composite_weights": cfg.weights_dict(),
        "engineering_sources": {
            "change_context": cc_status,
            "test_coverage": tc_status,
            "profile_data": pd_status,
            "ci_configuration": ci_status,
            "artifact_security": art_status,
            "dependency_intelligence": sca_status,
        },
        "promoted_leads": promoted_leads,
        "hunt_queue": hunt_queue,
        "telemetry": telemetry,
    }
    return reranked_files, reranked_functions, signals_doc
