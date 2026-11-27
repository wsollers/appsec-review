"""Verified inputs of ``job_poc_generation``: the accepted review and its packages.

Nothing is read from the target tree. The review handoff is re-verified from
bytes with the shared ``load_accepted_review`` and ``bound_artifacts`` helpers, the
candidates are read from the verified review handoff, and a candidate's review package is loaded by
its recorded hash. The retrieval core that builds the model-facing package view is pinned to the
manifest the review accepted.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import inspect
import json
from pathlib import Path
from typing import Any

from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.accepted_review import REVIEW_JOB, VerifiedReview, load_accepted_review
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError

from .candidates import PocCandidate, check_against_review, read_candidates

LANES = ("lead", "hunt")
_GRAPH_FIRST_KINDS = frozenset({
    "sink_site", "entry_point", "dataflow_path", "call_site", "guard_fact", "symbol",
})
_NON_FUNCTION_SYMBOL_KINDS = frozenset({
    "variable", "field", "member_variable", "parameter", "param", "global",
    "macro", "namespace", "struct", "class", "union", "enum", "typedef", "type_alias",
})


@dataclass(frozen=True, slots=True)
class VerifiedInputs:
    run_id: str
    review_job_handoff: dict[str, str]
    review_handoff: dict[str, str]
    review_status: str
    manifest_sha256: str
    manifest_path: str
    candidates: tuple[PocCandidate, ...]
    findings: Mapping[str, Mapping[str, Any]]            # finding_package_id -> projected finding package
    package_records: Mapping[str, Mapping[str, Any]]     # package_id -> {path, sha256, lane}
    language_build_handoff_sha256: str | None = None
    bindings: tuple[dict[str, str], ...] = ()

    def identity(self) -> dict[str, Any]:
        return {"run_id": self.run_id,
                "review_job_handoff": self.review_job_handoff, "review_handoff": self.review_handoff,
                "manifest_sha256": self.manifest_sha256}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityError(message)


def verify_inputs(run_root: Path, *, review_schemas: SchemaSet,
                  max_packages: int = 10_000) -> VerifiedInputs:
    """Re-verify the accepted review directly, without depending on publication."""
    run_root = Path(run_root).resolve()
    verified: VerifiedReview = load_accepted_review(run_root, review_schemas,
                                                    max_packages=max_packages)
    document = verified.document
    inputs = document["inputs"]
    review = read_bound_json(run_root, inputs["review_handoff"])
    job_handoff = read_bound_json(run_root, inputs["job_handoff"])
    outputs = job_handoff["outputs"]
    # The accepted handoff keeps only each unit's artifact reference; the accepted scope is that artifact.
    scope = read_bound_json(run_root, outputs["scope.accept_manifest"]["artifact"])
    _require(scope["manifest_sha256"] == document["review"]["accepted_manifest_sha256"],
             "the accepted scope does not name the review's manifest")
    findings = {item["finding_package_id"]: item for item in document["packages"]}
    candidates = read_candidates(review)
    problems = check_against_review(candidates, findings)
    _require(not problems, "poc_candidates disagree with the verified review: " + "; ".join(problems[:3]))
    records: dict[str, Mapping[str, Any]] = {}
    for lane in LANES:
        lane_document = read_bound_json(run_root, outputs[f"packages.assemble_{lane}_packages"]["artifact"])
        for record in lane_document["packages"]:
            records[record["package_id"]] = {"path": record["path"], "sha256": record["sha256"], "lane": lane}
    return VerifiedInputs(
        str(document["run_id"]), dict(inputs["job_handoff"]),
        dict(inputs["review_handoff"]), str(document["review"]["status"]), str(scope["manifest_sha256"]),
        str(scope["manifest_path"]), candidates, findings, records, bindings=tuple(document["bindings"]))


def load_package(run_root: Path, inputs: VerifiedInputs, package_id: str) -> Mapping[str, Any] | None:
    """The stored review package of ``package_id`` (hash-checked), or ``None`` when the run has no such package."""
    record = inputs.package_records.get(package_id)
    if record is None:
        return None
    return read_bound_json(Path(run_root), {"path": record["path"], "sha256": record["sha256"]})


def retrieval_core(run_root: Path, inputs: VerifiedInputs) -> Any:
    """The retrieval core pinned to the manifest the review accepted (it reads the target through the index)."""
    from appsec_review.jobs.bound_artifacts import source_context_core
    return source_context_core(Path(run_root), {"path": inputs.manifest_path, "sha256": inputs.manifest_sha256})


def _supports_indexes(core: Any) -> bool:
    find_fn = getattr(core, "find", None)
    if find_fn is None:
        return False
    try:
        params = inspect.signature(find_fn).parameters
    except (TypeError, ValueError):
        return True
    return "indexes" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())


def core_find(core: Any, *, indexes: Sequence[str] | None = None, limit: int = 1, **kwargs: Any) -> Mapping[str, Any]:
    """Bounded ``core.find`` call with index scoping and ``max_results`` clamping."""
    max_results = getattr(getattr(core, "limits", None), "max_results", None)
    effective_limit = min(limit, max_results) if isinstance(max_results, int) and max_results > 0 else limit
    call_kwargs = dict(kwargs)
    if indexes is not None and _supports_indexes(core):
        call_kwargs["indexes"] = tuple(indexes)
    found = core.find(limit=effective_limit, **call_kwargs)
    return found if isinstance(found, Mapping) else {}


def indexes_for_identity(identity: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Primary and bounded fallback index families for an ``asr:<kind>:<digest>`` identity."""
    parts = identity.split(":", 2)
    kind = parts[1] if len(parts) == 3 and parts[0] == "asr" else ""
    if kind in _GRAPH_FIRST_KINDS:
        return (("graph",), ("analysis", "source"))
    if kind == "source_file":
        return (("source",), ("analysis", "inventory"))
    if kind == "precomputed_fact":
        return (("precomputed",), ("graph", "analysis"))
    return (("graph", "analysis", "source"), ())


def find_identity(core: Any, identity: str) -> tuple[Mapping[str, Any] | None, bool]:
    """Resolve one identity via scoped indexes first; returns ``(row_or_none, timed_out)``."""
    if core is None or not hasattr(core, "find") or not isinstance(identity, str) or not identity:
        return None, False
    primary, fallback = indexes_for_identity(identity)
    supports_idx = _supports_indexes(core)
    first = core_find(core, identity=identity, indexes=primary if supports_idx else None, limit=1)
    rows = first.get("results") or ()
    if rows and isinstance(rows[0], Mapping):
        return rows[0], False
    timed_out = first.get("status") == "timeout"
    if supports_idx and fallback:
        second = core_find(core, identity=identity, indexes=fallback, limit=1)
        rows2 = second.get("results") or ()
        if rows2 and isinstance(rows2[0], Mapping):
            return rows2[0], False
        timed_out = timed_out or (second.get("status") == "timeout")
    return None, timed_out


def sink_of(package: Mapping[str, Any], *, core: Any = None,
            diagnostics: list[str] | None = None) -> Mapping[str, Any] | None:
    """The function that holds the sink, from the package neighborhood or Hunt enclosing symbol via core."""
    neighborhood = package.get("neighborhood") or {}
    function = neighborhood.get("function") if isinstance(neighborhood, Mapping) else None
    if isinstance(function, Mapping) and function.get("name") and function.get("path"):
        return {"name": str(function["name"]), "path": str(function["path"]),
                "line": int(function.get("start_line") or function.get("line") or 0),
                "symbol": function.get("symbol")}
    if core is None or not hasattr(core, "find"):
        return None
    scope = package.get("scope") if isinstance(package.get("scope"), Mapping) else {}
    operation = scope.get("operation") if isinstance(scope.get("operation"), Mapping) else {}
    sinks = [row for row in (neighborhood.get("sinks") or ()) if isinstance(row, Mapping)]
    anchor_ids: list[str] = []
    for row in sinks:
        ref = row.get("ref")
        if isinstance(ref, str) and ref and ref not in anchor_ids:
            anchor_ids.append(ref)
    for ref in (operation.get("anchor_ids") or ()):
        if isinstance(ref, str) and ref and ref not in anchor_ids:
            anchor_ids.append(ref)
    op_path = str(operation.get("path") or (sinks[0].get("path") if sinks else "") or "")
    op_line = int(
        operation.get("line")
        or operation.get("start_line")
        or ((sinks[0].get("line") or sinks[0].get("start_line")) if sinks else 0)
        or 0
    )

    def _resolve_symbol_meta(sym_id: str) -> tuple[str | None, str | None, int]:
        sym_item, sym_timed_out = find_identity(core, sym_id)
        if sym_timed_out and diagnostics is not None:
            diagnostics.append(f"retrieval_timeout: core.find timed out resolving enclosing symbol {sym_id}")
        if sym_item is None:
            return None, None, 0
        sym_loc = sym_item.get("location") if isinstance(sym_item.get("location"), Mapping) else {}
        sym_payload = sym_item.get("payload") if isinstance(sym_item.get("payload"), Mapping) else {}
        sym_inner = sym_payload.get("result") if isinstance(sym_payload.get("result"), Mapping) else sym_payload
        sym_name = (
            sym_item.get("name")
            or (sym_inner.get("qualified_name") if isinstance(sym_inner, Mapping) else None)
            or (sym_inner.get("name") if isinstance(sym_inner, Mapping) else None)
            or (sym_inner.get("display") if isinstance(sym_inner, Mapping) else None)
        )
        sym_path = str(sym_loc.get("path") or sym_item.get("path") or "") or None
        sym_line = int(sym_loc.get("start_line") or sym_loc.get("line") or sym_item.get("start_line") or sym_item.get("line") or 0)
        return (str(sym_name) if isinstance(sym_name, str) and sym_name else None), sym_path, sym_line

    for anchor_id in anchor_ids:
        item, timed_out = find_identity(core, anchor_id)
        if timed_out and diagnostics is not None:
            diagnostics.append(f"retrieval_timeout: core.find timed out resolving sink anchor {anchor_id}")
        if item is None:
            continue
        loc = item.get("location") if isinstance(item.get("location"), Mapping) else {}
        item_path = str(loc.get("path") or item.get("path") or op_path)
        item_line = int(loc.get("start_line") or loc.get("line") or item.get("start_line") or item.get("line") or op_line or 0)
        if item.get("kind") == "symbol" and item.get("name") and item_path:
            return {"name": str(item["name"]), "path": item_path, "line": item_line,
                    "symbol": item.get("identity")}
        payload = item.get("payload") if isinstance(item.get("payload"), Mapping) else {}
        inner = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
        enclosing = (
            inner.get("enclosing_function")
            or inner.get("function")
            or payload.get("enclosing_function")
            or payload.get("function")
            or item.get("enclosing_function")
        )
        if isinstance(enclosing, str) and enclosing:
            if enclosing.startswith("asr:"):
                sym_name, sym_path, sym_line = _resolve_symbol_meta(enclosing)
                final_path = sym_path or item_path
                if sym_name and final_path:
                    return {"name": sym_name, "path": final_path, "line": sym_line or item_line, "symbol": enclosing}
            elif item_path:
                return {"name": enclosing, "path": item_path, "line": item_line, "symbol": None}
        if isinstance(enclosing, Mapping):
            enc_name = enclosing.get("name") or enclosing.get("display")
            enc_sym = enclosing.get("identity") or enclosing.get("symbol")
            enc_path = str(enclosing.get("path") or "") or None
            enc_line = int(enclosing.get("start_line") or enclosing.get("line") or 0)
            if isinstance(enc_sym, str) and enc_sym:
                sym_name, sym_path, sym_line = _resolve_symbol_meta(enc_sym)
                if not enc_name and sym_name:
                    enc_name = sym_name
                if not enc_path and sym_path:
                    enc_path = sym_path
                if not enc_line and sym_line > 0:
                    enc_line = sym_line
            final_path = enc_path or item_path
            final_line = enc_line or item_line
            if isinstance(enc_name, str) and enc_name and final_path:
                return {"name": str(enc_name), "path": final_path, "line": final_line,
                        "symbol": enc_sym if isinstance(enc_sym, str) and enc_sym else None}
        if item_path and not op_path:
            op_path = item_path
        if item_line and not op_line:
            op_line = item_line

    if op_path and op_line > 0:
        sym_resp = core_find(core, path=op_path, kind="symbol", indexes=("graph", "analysis"), limit=200)
        if sym_resp.get("status") == "timeout" and diagnostics is not None:
            diagnostics.append(f"retrieval_timeout: core.find timed out scanning symbols in {op_path}")
        best_enclosing: tuple[int, int, int, Mapping[str, Any]] | None = None
        best_preceding: tuple[int, int, Mapping[str, Any]] | None = None
        for sym in sym_resp.get("results") or ():
            if not isinstance(sym, Mapping):
                continue
            sym_payload = sym.get("payload") if isinstance(sym.get("payload"), Mapping) else {}
            cpg_obj: Mapping[str, Any] | None = None
            cpg_raw = sym_payload.get("cpg_node_json")
            if isinstance(cpg_raw, str) and cpg_raw:
                try:
                    parsed_cpg = json.loads(cpg_raw)
                    if isinstance(parsed_cpg, Mapping):
                        cpg_obj = parsed_cpg
                except ValueError:
                    cpg_obj = None
            raw_kind = str(
                sym_payload.get("node_kind")
                or sym_payload.get("symbol_kind")
                or sym_payload.get("kind")
                or (cpg_obj.get("node_kind") if cpg_obj else "")
                or ""
            ).strip().lower()
            if raw_kind in _NON_FUNCTION_SYMBOL_KINDS:
                continue
            name = sym.get("name") or sym_payload.get("name") or (cpg_obj.get("name") if cpg_obj else None)
            loc = sym.get("location") if isinstance(sym.get("location"), Mapping) else {}
            start = int(loc.get("start_line") or loc.get("line") or sym_payload.get("start_line") or 0)
            end = int(loc.get("end_line") or sym_payload.get("end_line") or start)
            if start > 0 and end <= start and cpg_obj is not None:
                cpg_loc = cpg_obj.get("location") if isinstance(cpg_obj.get("location"), Mapping) else {}
                cpg_end = int(cpg_obj.get("end_line") or cpg_loc.get("end_line") or 0)
                if cpg_end > end:
                    end = cpg_end
            if not isinstance(name, str) or not name or start <= 0 or end < start:
                continue
            index_pref = 0 if sym.get("index") == "graph" else 1
            if (end > start and start <= op_line <= end) or (start == op_line == end):
                span = end - start
                rank = (span, -start, index_pref)
                if best_enclosing is None or rank < best_enclosing[:3]:
                    best_enclosing = (span, -start, index_pref, sym)
            elif start <= op_line:
                prec_rank = (op_line - start, index_pref)
                if best_preceding is None or prec_rank < best_preceding[:2]:
                    best_preceding = (op_line - start, index_pref, sym)
        chosen = (best_enclosing[3] if best_enclosing is not None
                  else (best_preceding[2] if best_preceding is not None else None))
        if chosen is not None:
            loc = chosen.get("location") if isinstance(chosen.get("location"), Mapping) else {}
            chosen_payload = chosen.get("payload") if isinstance(chosen.get("payload"), Mapping) else {}
            chosen_name = chosen.get("name") or chosen_payload.get("name")
            return {"name": str(chosen_name), "path": str(loc.get("path") or op_path),
                    "line": int(loc.get("start_line") or loc.get("line") or op_line),
                    "symbol": chosen.get("identity")}
    return None


def evidence_summary(candidate: PocCandidate, limit: int = 32) -> Sequence[str]:
    return candidate.evidence_refs[:limit]


__all__ = ["REVIEW_JOB", "VerifiedInputs", "core_find", "evidence_summary", "find_identity",
           "indexes_for_identity", "load_package", "retrieval_core", "sink_of", "verify_inputs"]
