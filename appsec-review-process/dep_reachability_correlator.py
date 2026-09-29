"""The ``06-cve-reachability`` correlator (ADR-0023 decision 8): engine tables -> one verdict per SCA match.

Inputs are the accepted ``engine-reachability`` tables of ``06-reachability-codeql`` and
``06-reachability-ir`` (hash-bound by the caller) plus the run-supplied language-server and
tree-sitter documents, which are HINTS only. Per match:

* ``reachable``   at least one proof-capable engine (``codeql``, ``ir``) has a hash-bound witness
                  (the engines bind every hop to the source projection before they publish);
* ``unreachable`` only the ``ir`` engine (complete call graph, the vulnerable function's source in
                  the graph, a hash-bound target), no other engine reachable, no hint of a
                  name-matched call site or call-hierarchy path;
* ``conflict``    engines disagree (one ``reachable``, another ``unreachable``): both are listed,
                  nothing is resolved silently;
* ``unknown``     everything else, with every engine's reason and gaps.

Language-server call hierarchy and tree-sitter results never make a verdict ``reachable``, and no
model output is read. Outputs: the ``06`` evidence rows (``assessments`` that
``dependency_workers.build_reachability`` validates; ``conflict`` and ``unknown`` have none, so
``cve-reachability.json`` says ``unknown`` and Critical stays capped), the per-match document
``appsec-review/dependency-reachability/1.0`` and the summary
``appsec-review/dependency-reachability-summary/1`` read by the report and lanes 07 to 12.
"""
from __future__ import annotations

from typing import Any

import dep_reachability
import dep_reachability_engines as engines

REACHABLE, UNREACHABLE, CONFLICT, UNKNOWN = "reachable", "unreachable", "conflict", "unknown"
VERDICTS = (REACHABLE, UNREACHABLE, CONFLICT, UNKNOWN)
PROOF_ENGINES = ("codeql", "ir")
ENGINE_JOBS = {"codeql": "06-reachability-codeql", "ir": "06-reachability-ir"}
HINT_ENGINES = ("lsp", "treesitter")
# Strongest first when several proofs exist: the complete CPG for native code, CodeQL elsewhere.
ORDER = {"cpp": ("ir", "codeql")}
NOT_APPLICABLE = "engine-not-applicable:"


def _gap(match_id: str, reason: str) -> str:
    return f"REACHABILITY_UNKNOWN:{match_id}:{reason}"[:512]


def _applicable(row: dict[str, Any] | None) -> bool:
    return row is not None and not any(gap.startswith(NOT_APPLICABLE) for gap in row["gaps"])


def hints(engine_set: engines.EngineSet, record: dict[str, Any], entry_points: list[str]
          ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """(engine summaries, witness hints, gaps) from the hint engines; never a proof."""
    symbols = [{"package": item.get("package"), "symbol": item["symbol"]}
               for item in [*record["symbols"], *record.get("resolved", [])]]
    if record["language"] is None or not symbols:
        return [], [], []
    query = engines.Query(match_id=record["match_id"], language=record["language"], package=record["package"] or "",
                          symbols=symbols, entry_points=entry_points)
    summaries, found_hints, gaps = [], [], []
    for name in HINT_ENGINES:
        # A hint engine listed for the language reports its absence as a gap; an unlisted one (for
        # example tree-sitter on C/C++) is consulted only when its input exists.
        listed = name in dep_reachability.ENGINES_BY_LANGUAGE.get(record["language"], ())
        result = engine_set.assess(name, query)
        if not result["ran"] and not listed:
            continue
        reason = result["reason"]
        if result["state"] == REACHABLE and result["witness"]:
            last = result["witness"][-1]
            found_hints.append({"file": str(last.get("file") or ""), "line": int(last.get("line") or 0),
                                "callee": dep_reachability.clean_text(last.get("function")),
                                "symbol": dep_reachability.clean_text(last.get("function")),
                                "function": dep_reachability.clean_text(result["witness"][-2]["function"])
                                if len(result["witness"]) > 1 else None})
            reason = "hint only (never proof): " + reason
        found_hints.extend(result.get("witness_hint", []))
        summaries.append({"engine": name, "ran": result["ran"], "state": UNKNOWN if result["state"] == REACHABLE else result["state"],
                          "reason": dep_reachability.clean_text(reason, 512), "witness_length": 0})
        gaps.extend(result["gaps"])
    return summaries, found_hints, gaps


def decide(language: str | None, rows: dict[str, dict[str, Any]], hinted: bool) -> tuple[str, list[str], str]:
    """(verdict, deciding engines, reason) from the proof-capable engines' rows for one match."""
    live = {name: row for name, row in rows.items() if _applicable(row)}
    proofs = [name for name, row in live.items() if row["verdict"] == REACHABLE and row["witness"]]
    absences = [name for name, row in live.items() if row["verdict"] == UNREACHABLE and name == "ir" and row["target"]]
    if proofs and absences:
        reasons = "; ".join(f"{name} says {live[name]['verdict']} ({live[name]['reason']})" for name in sorted(live))
        return CONFLICT, sorted(proofs + absences), "engines disagree: " + reasons
    order = ORDER.get(language or "", ("codeql", "ir"))
    if proofs:
        best = min(proofs, key=lambda name: (order.index(name) if name in order else len(order), len(live[name]["witness"])))
        return REACHABLE, [best], live[best]["reason"]
    if absences:
        if hinted:
            return UNKNOWN, [], "ir found no path but a hint engine found a name-matched call site or call path"
        return UNREACHABLE, ["ir"], live["ir"]["reason"]
    reasons = "; ".join(f"{name}: {row['reason']}" for name, row in sorted(rows.items()) if row) or \
        "no reachability engine table for this match"
    return UNKNOWN, [], reasons


def correlate(*, sca: dict[str, Any], sbom: dict[str, Any], tables: dict[str, dict[str, Any] | None],
              engine_set: engines.EngineSet, entry_points: list[str], osv: dict[str, Any] | None,
              identity: dict[str, Any], input_gaps: list[str]) -> dict[str, Any]:
    components = {row["component_id"]: row for row in sbom.get("components", [])}
    by_engine = {name: {row["match_id"]: row for row in (table or {}).get("rows", [])} for name, table in tables.items()}
    records, assessments, gaps = [], [], []
    for match in sorted(sca.get("matches", []), key=lambda row: row["match_id"]):
        match_id = match["match_id"]
        component = components.get(match["component_ref"]) or {}
        rows = {name: by_engine.get(name, {}).get(match_id) for name in PROOF_ENGINES}
        first = next((row for row in (rows["codeql"], rows["ir"]) if row), None)
        language, _ = dep_reachability.ECOSYSTEMS.get(component.get("ecosystem", ""), (None, None))
        record: dict[str, Any] = {
            "match_id": match_id, "component_ref": match["component_ref"], "advisory_id": match["advisory_id"],
            "ecosystem": component.get("ecosystem"), "language": language,
            "symbols": first["symbols"] if first else [], "resolved": first["resolved"] if first else [],
            "resolution": first["resolution"] if first else [], "engines": [], "verdict": UNKNOWN, "tier": None,
            "deciding_engines": [], "reason": "", "witness": [], "witness_hints": [], "gaps": []}
        hint_input = {**record, "package": component.get("name")}
        summaries, found_hints, hint_gaps = hints(engine_set, hint_input, entry_points)
        verdict, deciding, reason = decide(language, rows, bool(found_hints))
        for name in PROOF_ENGINES:
            row = rows[name]
            if row is None:
                record["engines"].append({"engine": name, "ran": False, "state": UNKNOWN,
                                          "reason": f"no accepted {ENGINE_JOBS[name]} row", "witness_length": 0})
                record["gaps"].append(_gap(match_id, f"engine-input-absent:{ENGINE_JOBS[name]}"))
                continue
            record["engines"].append({"engine": name, "ran": _applicable(row), "state": row["verdict"],
                                      "reason": dep_reachability.clean_text(row["reason"], 512),
                                      "witness_length": len(row["witness"])})
            record["gaps"] += [_gap(match_id, gap) for gap in row["gaps"] if not gap.startswith(NOT_APPLICABLE)]
        record["engines"] += summaries
        record["gaps"] += [_gap(match_id, gap) for gap in hint_gaps]
        record["witness_hints"] = [{**hint, "callee": dep_reachability.clean_text(hint["callee"]),
                                    "function": dep_reachability.clean_text(hint["function"])
                                    if hint.get("function") is not None else None}
                                   for hint in found_hints[:dep_reachability.MAX_WITNESS]]
        if verdict == REACHABLE:
            best = rows[deciding[0]]
            record.update(witness=best["witness"], tier=best["tier"])
            assessments.append({"match_ref": match_id, "classification": REACHABLE,
                                "evidence": [{"kind": "call", "path": hop["file"], "sha256": hop["sha256"],
                                              "locator": f"{hop['function']}@{hop['line']}"[:256]}
                                             for hop in best["witness"]]})
        elif verdict == UNREACHABLE:
            target = rows["ir"]["target"]
            assessments.append({"match_ref": match_id, "classification": UNREACHABLE,
                                "evidence": [{"kind": "call", "path": target["file"], "sha256": target["sha256"],
                                              "locator": f"no-path-to:{target['function']}@{target['line']}"[:256]}]})
        elif verdict == CONFLICT:
            record["gaps"].append(f"REACHABILITY_CONFLICT:{match_id}")
        if verdict in (UNKNOWN, CONFLICT):
            record["gaps"].append(_gap(match_id, "undecided"))
        record.update(verdict=verdict, deciding_engines=deciding, reason=dep_reachability.clean_text(reason, 1024))
        record["gaps"] = sorted(set(record["gaps"]))
        records.append(record)
        gaps += record["gaps"]
    counts = {verdict: sum(1 for row in records if row["verdict"] == verdict) for verdict in VERDICTS}
    document = {"schema": dep_reachability.SCHEMA, "engines": identity, "osv": osv, "entry_points": entry_points,
                "counts": counts, "matches": records,
                "coverage_gaps": sorted(set(gaps) | {"ENGINE_INPUT:" + gap for gap in input_gaps}),
                "claim_ceiling": "EVIDENCE_LEADS_ONLY"}
    return {"assessments": assessments, "document": document}


def summary(document: dict[str, Any], sbom: dict[str, Any], engine_bindings: dict[str, dict[str, Any] | None]
            ) -> dict[str, Any]:
    """The report / lane view of the correlated document (no run fields)."""
    components = {row["component_id"]: row for row in sbom.get("components", [])}
    matches = []
    for record in document["matches"]:
        component = components.get(record["component_ref"]) or {}
        name = " ".join(str(part) for part in (component.get("name"), component.get("version")) if part)
        witness = record["witness"]
        matches.append({
            "match_id": record["match_id"], "component_ref": record["component_ref"],
            "advisory_id": record["advisory_id"], "component": dep_reachability.clean_text(name, 300) or None,
            "ecosystem": record["ecosystem"], "language": record["language"], "verdict": record["verdict"],
            "tier": record.get("tier"), "deciding_engines": record.get("deciding_engines", []),
            "engines": [{"engine": row["engine"],
                         "verdict": ("absent" if not row["ran"] and row["engine"] in PROOF_ENGINES else
                                     "hint" if row["engine"] in HINT_ENGINES else row["state"])}
                        for row in record["engines"]],
            "witness_length": len(witness),
            "entry": {"function": witness[0]["function"], "file": witness[0]["file"], "line": witness[0]["line"]}
            if witness else None,
            "call_site": {"file": witness[-1]["file"], "line": witness[-1]["line"]} if witness else None,
            "reason": record["reason"], "gaps": len(record["gaps"])})
    counts = {verdict: sum(1 for row in matches if row["verdict"] == verdict) for verdict in VERDICTS}
    engines_rows = []
    for name in PROOF_ENGINES:
        binding = engine_bindings.get(name)
        engines_rows.append({"job_id": ENGINE_JOBS[name], "engine": name,
                             "attempt_id": binding["attempt_id"] if binding else None,
                             "result_sha256": binding["result_sha256"] if binding else None,
                             "status": binding.get("status", "OK") if binding else "ABSENT"})
    return {"schema": "appsec-review/dependency-reachability-summary/1", "counts": counts, "engines": engines_rows,
            "matches": matches,
            "review": {"p1_match_ids": [row["match_id"] for row in matches if row["verdict"] == REACHABLE],
                       "conflict_match_ids": [row["match_id"] for row in matches if row["verdict"] == CONFLICT]},
            "coverage_gaps": document["coverage_gaps"], "claim_ceiling": "EVIDENCE_LEADS_ONLY"}


def render_markdown(summary_document: dict[str, Any]) -> str:
    """Plain summary for the attempt (the report renders its own section from the JSON)."""
    counts = summary_document["counts"]
    lines = ["# Dependency reachability (06-cve-reachability)", "",
             f"- reachable {counts['reachable']}, unreachable {counts['unreachable']}, "
             f"conflict {counts['conflict']}, unknown {counts['unknown']}", ""]
    for row in summary_document["matches"]:
        where = f" at {row['call_site']['file']}:{row['call_site']['line']}" if row["call_site"] else ""
        lines.append(f"- {row['match_id']} {row['advisory_id']} ({row['component'] or row['component_ref']}): "
                     f"**{row['verdict']}**{' (' + row['tier'] + ')' if row['tier'] else ''}{where}")
    return "\n".join(lines) + "\n"
