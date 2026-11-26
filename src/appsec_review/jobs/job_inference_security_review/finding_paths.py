"""Check an adjudicated finding's existing path citation. No neighborhood or candidate search."""
from __future__ import annotations

import json
import re
from typing import Mapping

from appsec_review.graph.contract import GRAPH_FACT_SCHEMA
from appsec_review.retrieval.core import retrieval_caller
from appsec_review.retrieval.graph import ALT_PATH_SHARD, ALT_SCHEMA, alternate_path_shard, cited_cpg_nodes, cited_path
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.retrieval.model import normalize_relative_path
from appsec_review.review.evidence import _content_record, satisfies
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import CellStatus, IntegrityError

SCHEMA = "appsec-review/finding-path/1"
REACH = "source_to_sink_reachability"
GAP = "[unverified link]"
MAX_PATH_QUERIES = 12


def cited_alternate(relation, cells=None):
    # Alternate CPG is indirect under predicate admission. Its existing claim-ledger citation
    # is context, not one of the finding package's counted/analyst-assessed supporting IDs.
    if cells is not None and not any(
        record.status is CellStatus.SUCCEEDED
        for record in cells.get(relation.producing_cell_id, ())
    ):
        return False
    return (relation.shard_id == ALT_PATH_SHARD and relation.kind.value in {"supports", "qualifies"}
            and relation.complete and relation.retrieval_receipt_sha256 is not None)


def citation(relation):
    return {"relation_id": relation.relation_id, "entity_id": relation.entity_id,
            "content_sha256": relation.content_sha256, "shard_id": relation.shard_id,
            "retrieval_receipt_sha256": relation.retrieval_receipt_sha256}


def _span(location, snapshot):
    if not isinstance(location, Mapping):
        return None
    path, start, end = (location.get(k) for k in ("path", "start_line", "end_line"))
    if (not isinstance(path, str) or location.get("target_snapshot") != snapshot
            or location.get("ambiguous") is not False or location.get("confidence") != 1
            or not re.fullmatch(r"[a-f0-9]{64}", str(location.get("file_sha256")))
            or type(start) is not int or type(end) is not int or not 0 < start <= end):
        return None
    try:
        if normalize_relative_path(path) != path:
            return None
    except ValueError:
        return None
    return {"path": path, "start_line": start, "end_line": end, "file_sha256": location["file_sha256"]}


@retrieval_caller(job_id="job_inference_security_review", caller_kind="finding_path_verification", if_unset=True)
def assess(ctx, record, claim, relation, *, counted, counter_ids, cache=None):
    """Return only selected, static fields of one re-resolved graph record, with its original pins."""
    core = ctx.core
    entity_cache = cache if isinstance(cache, dict) else {}
    row = {"schema": SCHEMA, "claim_id": claim.claim_id, "adjudication_id": record["adjudication_id"],
           "manifest_sha256": core.manifest_sha256, "target_snapshot": core.manifest["target_snapshot"],
           "citation": citation(relation), "shard_sha256": None, "status": "unverified",
           "steps": [], "controls": [], "limitations": [], "counter_relations": sorted(counter_ids)}
    gaps = row["limitations"]
    remaining = MAX_PATH_QUERIES

    def cached_find(identity: str, indexes: tuple[str, ...] | None = None):
        key = ("find", indexes, identity)
        if key in entity_cache:
            return entity_cache[key]
        if not charge():
            return None
        found = core.find(identity=identity, limit=1) if indexes is None else core.find(
            identity=identity, indexes=indexes, limit=1
        )
        if not found.get("truncated"):
            entity_cache[key] = found
        return found

    def charge():
        nonlocal remaining
        if remaining <= 0 or not ctx.budget.cell_launch_allowed():
            return False
        remaining -= 1
        ctx.budget.charge(retrieval_queries=1)
        return True

    def unavailable(reason):
        gaps.append(reason)
        return row

    index = "analysis" if relation.shard_id == ALT_PATH_SHARD else "graph"
    shards = [s for s in core.indexes.get(index, ()) if f"{index}/{s['shard_id']}" == relation.shard_id
              and (alternate_path_shard(s) or (index == "graph" and s.get("producer", {}).get("job") == "job_code_graph_index"
                                               and s["producer"].get("family") == "dataflow_path"))]
    if len(shards) != 1 or not relation.retrieval_receipt_sha256:
        return unavailable("No unique commissioned graph shard and original retrieval receipt.")
    shard = shards[0]
    row["shard_sha256"] = shard["sha256"]
    found = cached_find(relation.entity_id, (index,))
    if found is None:
        return unavailable("Path verification query budget exhausted.")
    if found["truncated"] or len(found["results"]) != 1:
        return unavailable("Cited path missing or ambiguous in the pinned graph.")
    entity = found["results"][0]
    if (entity["identity"], entity["kind"], entity["shard_id"]) != (relation.entity_id, "dataflow_path", shard["shard_id"]):
        raise IntegrityError("path citation resolved to a different graph record")
    excerpt = None
    if entity.get("location") is not None:
        if not charge():
            return unavailable("Path excerpt verification query budget exhausted.")
        read = core.read_excerpt(identity=relation.entity_id, context_lines=0)
        if (read["truncated"] or len(read["results"]) != 1 or read["results"][0].get("excerpt_truncated")
                or read["results"][0].get("identity") != relation.entity_id):
            return unavailable("Cited path excerpt did not resolve completely.")
        excerpt = read["results"][0]["excerpt"]
    if sha256_hex(_content_record(entity, excerpt)) != relation.content_sha256:
        raise IntegrityError("finding path content differs from the adjudicated citation")
    if not charge():
        return unavailable("Path detail verification query budget exhausted.")
    payload = cited_path(core, identity=relation.entity_id, shard=shard)
    if not payload:
        return unavailable("Cited ordered path payload unavailable.")
    if core._safe_payload(payload) != entity["payload"]:
        raise IntegrityError("finding path details differ from the cited graph payload")
    if alternate_path_shard(shard):
        return _alternate(core, shard, entity, payload, claim, row, charge)
    if (payload.get("schema") != GRAPH_FACT_SCHEMA or payload.get("family") != "dataflow_path"
            or payload.get("producer", {}).get("name") != "codeql-export"):
        return unavailable("Cited ordered graph payload unavailable.")
    result = payload["result"]
    steps = result.get("steps") or []
    if (not isinstance(steps, list) or len(steps) < 2 or not all(isinstance(s, Mapping) for s in steps)
            or [s.get("n") for s in steps] != list(range(len(steps)))
            or steps[0].get("role") != "source" or steps[-1].get("role") != "sink"):
        return unavailable("Graph did not retain one ordered source-to-sink sequence.")
    sink = (result.get("sink") or {}).get("sink_site")
    if not {relation.entity_id, sink, steps[-1].get("symbol")} & set(claim.affected_entities):
        # Positive identity mismatch refutes this citation, not the finding or all paths to it.
        if (payload.get("exact") is True and re.fullmatch(r"asr:sink_site:[0-9a-f]{64}", str(sink))
                and claim.affected_entities and all(re.fullmatch(r"asr:sink_site:[0-9a-f]{64}", entity)
                                                   for entity in claim.affected_entities)):
            row["status"] = "statically_contradicted"
            return unavailable("Cited path ends at a different recorded sink than the finding.")
        return unavailable("Cited sink not bound to an affected entity of this finding.")
    truncated = result.get("truncated_steps") is not False or result.get("hop_count") != len(steps) - 1
    if truncated:
        gaps.append("Producer omitted path steps; adjacency to the sink is unverified.")
    if not (counted and satisfies(relation) and payload.get("admissibility", {}).get("direct_eligible") is True):
        gaps.append("Citation is not counted direct path support; retained steps are static context only.")
    if payload.get("exact") is not True or payload.get("coverage_status") != "complete":
        gaps.append("Producer mapping or path coverage incomplete.")
    gaps.extend(payload.get("gaps", ()))
    if not (result.get("source") or {}).get("entry_point"):
        gaps.append("No accepted entry-point mapping.")
    if counter_ids:
        gaps.append("Adjudicated reachability counterevidence; see cited counter-relations.")
    names: dict[str, str | None] = {}
    for n, step in enumerate(steps):
        span = _span(step.get("location"), row["target_snapshot"])
        symbol = step.get("symbol")
        if not isinstance(symbol, str) or not re.fullmatch(r"asr:symbol:[0-9a-f]{64}", symbol):
            symbol = None
        if symbol and symbol not in names:
            names[symbol] = None
            match = cached_find(symbol)
            if match is not None and not match["truncated"] and len(match["results"]) == 1:
                exact = match["results"][0]
                if exact.get("identity") == symbol and exact.get("kind") == "symbol":
                    names[symbol] = exact.get("name") or None
        role = step.get("role")
        if role not in {"source", "call", "step", "return", "sink"}:
            role = "step"
        row["steps"].append({"ordinal": n, "role": role, "symbol_id": symbol,
                             "symbol": names.get(symbol), "span": span,
                             "gap_before": truncated and n == len(steps) - 1})
        if not span or not symbol:
            gaps.append(f"Step {n + 1}: exact symbol or source span unavailable.")
    # The producer attaches controls to the path, not to a particular hop. Never infer bypass.
    for guard in result.get("guards", ()):
        control = None
        if isinstance(guard, str) and re.fullmatch(r"asr:guard_fact:[0-9a-f]{64}", guard):
            found = cached_find(guard, ("graph",))
            if found is not None and not found["truncated"] and len(found["results"]) == 1:
                fact = found["results"][0]
                data = fact.get("payload", {})
                detail = data.get("result", {})
                guard_shards = [s for s in core.indexes["graph"] if s["shard_id"] == fact.get("shard_id")
                                and s.get("producer", {}).get("job") == "job_code_graph_index"
                                and s["producer"].get("family") == "guard_fact"]
                if (len(guard_shards) == 1 and fact.get("identity") == guard and fact.get("kind") == "guard_fact"
                        and data.get("schema") == GRAPH_FACT_SCHEMA
                        and (detail.get("sink") or {}).get("sink_site") == result["sink"]["sink_site"]):
                    condition = (detail.get("condition") or {}).get("display") or "condition not recorded"
                    control = (f"{condition}; static guard state {detail.get('guard_state', 'unknown')}; "
                               f"polarity {detail.get('polarity', 'unknown')}; constrains sink operand: "
                               f"{detail.get('constrains_sink_operand', 'unknown')}. Runtime effect not established.")
        row["controls"].append({"description": control or f"{GAP} Guard disposition unavailable.",
                                "reference": guard})
    for sanitizer in result.get("sanitizers", ()):
        loc = _span(sanitizer.get("location"), row["target_snapshot"])
        where = f"{loc['path']}:{loc['start_line']}" if loc else GAP
        row["controls"].append({"description": f"Sanitizer: {sanitizer['api']} at {where} (effect not established)",
                                "reference": relation.relation_id})
    if not gaps:
        row["status"] = "statically_supported"
    return row


def _alternate(core, shard, entity, payload, claim, row, charge):
    """Preserve a stored alternate path as non-counted context; never compute one from edges."""
    gaps = row["limitations"]
    gaps.append("Alternate CPG: cited static context only, not counted reachability evidence.")
    if payload.get("schema") != ALT_SCHEMA or payload.get("cpg_record") != "cpg_path":
        gaps.append("Unsupported alternate path record.")
        return row
    path = payload.get("cpg_path")
    if path is None and isinstance(payload.get("cpg_path_json"), str):
        try:
            path = json.loads(payload["cpg_path_json"])
        except ValueError:
            pass
    path_id = payload.get("path_id")
    if (not isinstance(path, Mapping) or path.get("schema") != ALT_SCHEMA or path.get("record_type") != "cpg_path"
            or not isinstance(path_id, str) or path.get("path_id") != path_id or entity["native_id"] != path_id
            or LogicalIdentity.derive(EntityKind.DATAFLOW_PATH, row["target_snapshot"], {"cpg_path_id": path_id}).value
            != entity["identity"]):
        gaps.append("Stored alternate path identity or payload did not resolve.")
        return row
    hops = path.get("hops")
    if (not isinstance(hops, list) or not 1 <= len(hops) <= 16 or len(hops) != path.get("hop_count")
            or len(hops) != payload.get("hop_count") or any(not isinstance(h, Mapping) or h.get("step_index") != i
                or any(not isinstance(h.get(k), str) or not h[k] or len(h[k]) > 256 or h[k].startswith("<")
                       for k in ("source_id", "target_id", "edge_id")) for i, h in enumerate(hops))
            or hops[0]["source_id"] != path.get("source_id") or hops[-1]["target_id"] != path.get("sink_id")
            or any(a["target_id"] != b["source_id"] for a, b in zip(hops, hops[1:]))):
        gaps.append("Stored alternate path has missing, discontinuous or unordered endpoints.")
        return row
    ids = (hops[0]["source_id"], *(h["target_id"] for h in hops))
    if not charge():
        gaps.append("Stored path endpoint validation budget exhausted.")
        return row
    nodes = cited_cpg_nodes(core, shard, ids)
    sink = nodes.get(ids[-1], {})
    if not {entity["identity"], sink.get("identity")} & set(claim.affected_entities):
        gaps.append("Stored alternate path sink not bound to this finding.")
        return row
    if path.get("entrypoint_linked") is not True:
        gaps.append("Producer did not establish the path starts at an entry point.")
    if path.get("exact") is not True:
        gaps.append("Stored alternate path is inexact or its projection was limited.")
    def controls(records, reference):
        for guard in records if isinstance(records, list) else ():
            if not isinstance(guard, Mapping):
                gaps.append("Incomplete guard record on stored path.")
                continue
            text = "; ".join(str(guard[k]) for k in ("branch", "guard_polarity", "guard_expression") if guard.get(k))
            row["controls"].append({"reference": reference, "description": text or f"{GAP} Guard condition unavailable."})

    for i, native in enumerate(ids):
        node = nodes.get(native, {})
        loc = {**node, "ambiguous": node.get("ambiguous") != 0}
        span = _span(loc, row["target_snapshot"])
        name = node.get("name")
        incoming = hops[i - 1] if i else None
        role = "source" if not i else "sink" if i == len(hops) else "step"
        step = {"ordinal": i, "role": role, "symbol_id": node.get("identity") if node.get("kind") == "symbol" else None,
                "symbol": name, "span": span, "gap_before": False}
        if incoming:
            exact = incoming.get("exact") is True and incoming.get("resolution_tier") in {
                "clangd_semantic", "codeql_semantic", "hybrid_fused"}
            step["gap_before"] = not exact or not node or ids[i - 1] not in nodes
            step["incoming_edge"] = {"id": incoming["edge_id"], "kind": str(incoming.get("edge_kind") or "unknown"),
                                     "tier": str(incoming.get("resolution_tier") or "unknown")}
            # The hop names its call/flow site, not necessarily the target node's definition.
            # Only attach a file hash when the same pinned source node identifies that file.
            src = nodes.get(ids[i - 1], {})
            line = incoming.get("line")
            if incoming.get("path") == src.get("path") and type(line) is int:
                site = _span({**src, "ambiguous": src.get("ambiguous") != 0,
                              "start_line": line, "end_line": line}, row["target_snapshot"])
                if site and src.get("start_line") <= line <= src.get("end_line"):
                    step["incoming_edge"]["site"] = site
            controls(incoming.get("guard_dominators"), incoming["edge_id"])
        if not span or not name:
            gaps.append(f"Step {i + 1}: stored node or exact source span unavailable.")
        row["steps"].append(step)
    controls(path.get("guard_dominators"), path_id)
    return row
