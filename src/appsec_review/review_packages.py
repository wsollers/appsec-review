"""Deterministic pre-adjudication packages from verified, accepted index shards."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sysconfig
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from appsec_review.application_paths import application_asset
from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.model import LogicalIdentity, canonical_json
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import publish_named, consume_named, safe_path
from appsec_review.observability.spans import count_work


SCHEMA = "appsec-review/review-package/3"
ASSEMBLY_RULE = "appsec-review/assemble-review-packages/3"
MANIFEST_SCHEMA = "appsec-review/review-package-manifest/2"
_MENU_SEVERITIES = {"high_critical": {"critical", "high"}, "unknown": {"unknown"}}

def _schema_path() -> Path:
    installed = (Path(sysconfig.get_path("data")) / "share" / "appsec-review" / "schemas" /
                 "review-packages.schema.json")
    try:
        source = application_asset("docs/schemas/review-packages.schema.json")
    except FileNotFoundError:
        source = None
    for candidate in (source, installed):
        if candidate is None:
            continue
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("review package schema is unavailable")


_CONTRACT = Draft202012Validator(json.loads(_schema_path().read_text(encoding="utf-8")))


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _identity(package: Mapping[str, Any]) -> str:
    prefix = "d" if package["kind"] == "document_hunt" else package["kind"]
    return f"{prefix}-{_digest({key: value for key, value in package.items() if key != 'package_id'})}"


def _facts(view: AcceptedShards, query_set: str) -> list[tuple[Mapping[str, Any], Any]]:
    shards = view.select("precomputed")
    selected = [item for item in shards if item.get("producer", {}).get("query_set") == query_set]
    return [(row.payload, row) for row in view.entities(selected, ("precomputed_fact",))
            if row.payload.get("query_set") == query_set]


def _gap(producer: str, scope: str, state: str, reason: str) -> dict[str, str]:
    return {"gap_id": _digest([producer, scope, state, reason]), "producer": producer,
            "scope": scope, "state": state, "reason": reason}


def _coverage_gaps(view: AcceptedShards) -> list[dict[str, str]]:
    gaps = []
    for shard in view.shards:
        for reason in shard.get("gaps", ()):
            gaps.append(_gap(str(shard["name"]), str(shard.get("shard_id", "default")), "partial", str(reason)))
    for item in view.coverage(view.shards):
        if item["status"] != "complete":
            gaps.append(_gap(str(item["index"]), str(item["shard_id"]),
                             str(item["status"]) if item["status"] in {"partial", "unavailable", "stale"} else "failed",
                             str(item.get("gap") or item["area"])))
    return sorted({item["gap_id"]: item for item in gaps}.values(), key=lambda item: item["gap_id"])


def _lead(value: Mapping[str, Any]) -> dict[str, Any]:
    location = value["location"]
    return {"observation_id": value["observation_id"], "scanner": value["scanner"],
            "rule_id": value["rule_id"], "category": value["category"],
            "native_severity": value["native_severity"],
            "reported_severity": value["normalized_reported_severity"],
            "severity_rule": value["severity_rule"], "component_id": value["component_id"],
            "suppression_status": value["suppression_status"], "duplicate_of": value["duplicate_of"],
            "location_exact": bool(location["exact"]),
            "location": {key: location[key] for key in ("mapping_method", "source_path", "file_sha256",
                                                      "start_line", "end_line") if key in location},
            "flow_ids": sorted(value["flow_ids"])}


def _document_hunt(core: RetrievalCore, row: Any, members: list[Any], gaps: list[dict[str, str]],
                   omitted: int, max_page_size: int, inputs: list[tuple[str, str, str]]) -> dict[str, Any]:
    result = row.payload["result"]
    partition = f"{result['subject_type']}:{result['key']}"
    context_ids = sorted({row.identity, *(item.identity for item in members)})
    evidence = [{"entity_id": row.identity, "relation": "nominates", "shard_id": row.shard_id,
                 "shard_sha256": row.shard_sha256, "resolution": "unresolved"}]
    evidence.extend({"entity_id": item.identity, "relation": "qualifies", "shard_id": item.shard_id,
                     "shard_sha256": item.shard_sha256,
                     "resolution": "source_line" if item.location else "unresolved"} for item in members)
    package = {"schema": SCHEMA, "kind": "document_hunt", "run_id": core.run_id,
               "manifest_sha256": core.manifest_sha256, "target_snapshot": core.manifest["target_snapshot"],
               "input_fingerprint": _digest([core.manifest_sha256, inputs, partition, context_ids, ASSEMBLY_RULE]),
               "assembly_rule": ASSEMBLY_RULE,
               "scope": {"component_id": "document-corpus", "trust_boundary_id":
                         result["key"] if result["subject_type"] == "boundary" else None,
                         "build_unit_id": None, "partition_key": partition, "source_ids": [], "artifact_ids": []},
               "lead_menu": [], "evidence": sorted(evidence, key=lambda item: item["entity_id"]),
               "context_ids": context_ids, "metrics": [],
               "build_context": {"action_ids": [], "artifact_ids": [], "command_facts": [],
                                 "environment_facts": [], "bindings": []},
               "tag_context": {"assignments": [], "cloud": []}, "compiled_context": [],
               "proof_obligations": ["resolve affected construct", "establish input control",
                                     "establish reachability", "evaluate guards and configuration", "establish impact"],
               "retrieval": {"indexes": [name for name in ("documents", "precomputed", "source")
                                         if name in core.indexes],
                             "query_sets": ["document_context"], "entity_ids": context_ids,
                             "max_page_size": max_page_size, "max_pages": 5, "max_depth": 2,
                             "max_response_bytes": 131072},
               "coverage_gaps": sorted(gaps, key=lambda item: item["gap_id"]),
               "truncation": {"omitted_leads": 0, "omitted_context": omitted, "next_partition": None}}
    package["package_id"] = _identity(package)
    return package


def _package(core: RetrievalCore, *, kind: str, partition: str, leads: list[dict[str, Any]],
             evidence: list[dict[str, Any]], gaps: list[dict[str, str]], next_partition: str | None,
             max_page_size: int, metrics: list[dict[str, Any]], build_context: dict[str, Any],
             source_ids: list[str], context_ids: list[str], tag_context: dict[str, Any],
             compiled_context: list[dict[str, Any]], inputs: list[tuple[str, str, str]]) -> dict[str, Any]:
    component = leads[0]["component_id"]
    entity_ids = sorted({item["observation_id"] for item in leads} |
                        {item["entity_id"] for item in evidence} |
                        set(source_ids) | set(context_ids) | set(build_context["action_ids"]) |
                        {item["entity_id"] for item in tag_context["assignments"]} |
                        {item["entity_id"] for item in compiled_context} |
                        {item["scope_id"] for item in metrics} |
                        {flow for item in leads for flow in item["flow_ids"]})
    package = {"schema": SCHEMA, "kind": kind, "run_id": core.run_id,
               "manifest_sha256": core.manifest_sha256,
               "target_snapshot": core.manifest["target_snapshot"],
               "input_fingerprint": _digest([core.manifest_sha256, inputs, partition, entity_ids, ASSEMBLY_RULE]),
               "assembly_rule": ASSEMBLY_RULE,
               "scope": {"component_id": component, "trust_boundary_id": None, "build_unit_id": None,
                         "partition_key": partition, "source_ids": source_ids,
                         "artifact_ids": build_context["artifact_ids"]},
               "lead_menu": leads, "evidence": evidence,
               "context_ids": context_ids, "metrics": metrics, "build_context": build_context,
               "tag_context": tag_context, "compiled_context": compiled_context,
               "proof_obligations": ["resolve affected construct", "establish input control",
                                     "establish reachability", "evaluate guards and configuration", "establish impact"],
               "retrieval": {"indexes": [name for name in ("observations", "precomputed", "source", "priority", "build", "artifacts", "tags", "analysis") if name in core.indexes],
                             "query_sets": ["scanner_correlation", "history_context", "build_provenance"],
                             "entity_ids": entity_ids,
                             "max_page_size": max_page_size, "max_pages": 5, "max_depth": 2,
                             "max_response_bytes": 131072},
               "coverage_gaps": gaps,
               "truncation": {"omitted_leads": 0, "omitted_context": 0, "next_partition": next_partition}}
    package["package_id"] = _identity(package)
    return package


def validate_packages(core: RetrievalCore, packages: list[Mapping[str, Any]],
                      expected: Mapping[str, set[str]], audit: Mapping[str, Any] | None) -> None:
    """Verify bytes, stable identity, provenance and complete lead/menu membership."""
    ids: set[str] = set()
    finding: Counter[str] = Counter()
    document_hunts: list[str] = []
    hunt: dict[str, set[str]] = {key: set() for key in _MENU_SEVERITIES}
    allowed_shards = {item["sha256"] for item in core.manifest["indexes"]}
    for package in packages:
        _CONTRACT.validate(package)
        if package.get("schema") != SCHEMA or package.get("assembly_rule") != ASSEMBLY_RULE:
            raise ValueError("unsupported review package schema or rule")
        if package.get("run_id") != core.run_id or package.get("manifest_sha256") != core.manifest_sha256:
            raise ValueError("review package run or manifest mismatch")
        if package.get("target_snapshot") != core.manifest["target_snapshot"]:
            raise ValueError("review package target snapshot mismatch")
        if package.get("package_id") != _identity(package) or package["package_id"] in ids:
            raise ValueError("review package identity mismatch")
        ids.add(package["package_id"])
        leads = package["lead_menu"]
        if ((package["kind"] == "document_hunt" and leads) or
                (package["kind"] != "document_hunt" and
                 (not leads or (package["kind"] == "finding_lead" and len(leads) != 1)))):
            raise ValueError("review package lead bounds failed")
        if package["kind"] == "document_hunt":
            nominations = [item["entity_id"] for item in package["evidence"] if item["relation"] == "nominates"]
            if (len(nominations) != 1 or nominations[0] not in expected["documents"] or
                    nominations[0] not in package["context_ids"]):
                raise ValueError("document hunt nomination mismatch")
            document_hunts.append(nominations[0])
        if any(item["component_id"] != package["scope"]["component_id"] for item in leads):
            raise ValueError("review package component mismatch")
        if [item["observation_id"] for item in leads] != sorted({item["observation_id"] for item in leads}):
            raise ValueError("review package lead order or uniqueness failed")
        grant = set(package["retrieval"]["entity_ids"])
        for item in leads:
            LogicalIdentity.parse(item["observation_id"])
            if item["observation_id"] not in grant:
                raise ValueError("review package retrieval grant omits lead")
            if package["kind"] == "finding_lead":
                finding[item["observation_id"]] += 1
            elif package["kind"] == "hunt":
                for menu, severities in _MENU_SEVERITIES.items():
                    if item["reported_severity"] in severities:
                        hunt[menu].add(item["observation_id"])
        for evidence in package["evidence"]:
            if evidence["shard_sha256"] not in allowed_shards:
                raise ValueError("review package evidence shard mismatch")
            if package["kind"] == "document_hunt" and evidence["entity_id"] not in grant:
                raise ValueError("document hunt evidence is outside its retrieval grant")
    if len(document_hunts) != len(set(document_hunts)) or set(document_hunts) != expected["documents"]:
        raise ValueError("document hunt membership mismatch")
    if any(count != 1 for count in finding.values()) or set(finding) != expected["all"]:
        raise ValueError("finding-lead membership mismatch")
    for menu in _MENU_SEVERITIES:
        if hunt[menu] != expected[menu]:
            raise ValueError(f"{menu} hunt membership mismatch")
    if audit is None:
        if expected["all"] or not expected["documents"]:
            raise ValueError("scanner-correlation audit is unavailable")
    else:
        counts = audit.get("counts", {})
        if (audit.get("status") != "passed" or counts.get("source_sast_observations") != len(finding)
                or counts.get("high_critical") != len(expected["high_critical"])
                or counts.get("unknown_severity") != len(expected["unknown"])):
            raise ValueError("scanner-correlation audit mismatch")


def _membership(core: RetrievalCore, max_page_size: int):
    if not 1 <= max_page_size <= 100:
        raise ValueError("invalid package page bound")
    from appsec_review.storage.validation import current_validation
    validation = current_validation(core.run_root)
    cache_key = ("package-membership", core.manifest_sha256, str(max_page_size))
    if validation is not None and cache_key in validation.records:
        return validation.records[cache_key]
    view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
    facts = _facts(view, "scanner_correlation")
    document_facts = [(payload, row) for payload, row in _facts(view, "document_context")
                      if payload.get("fact_type") in {"route_context", "boundary_context"}]
    if not facts and not document_facts:
        raise ValueError("accepted scanner or document review facts are unavailable")
    leads: dict[str, tuple[dict[str, Any], Any]] = {}
    menus: list[Mapping[str, Any]] = []
    audits: list[Mapping[str, Any]] = []
    for payload, row in facts:
        kind, result = payload.get("fact_type"), payload.get("result")
        if kind == "lead":
            lead = _lead(result)
            if lead["observation_id"] in leads:
                raise ValueError("duplicate scanner lead")
            leads[lead["observation_id"]] = lead, row
        elif kind == "menu":
            menus.append(result)
        elif kind == "audit":
            audits.append(result)
    if facts and len(audits) != 1:
        raise ValueError("scanner-correlation membership audit missing or duplicated")
    expected = {"all": set(leads), **{menu: {identity for identity, (lead, _) in leads.items()
                                              if lead["reported_severity"] in severities}
                                     for menu, severities in _MENU_SEVERITIES.items()}}
    if len(document_facts) > 2_000:
        raise ValueError("document review subjects exceed the package bound")
    expected["documents"] = {row.identity for _payload, row in document_facts}
    listed: dict[str, list[str]] = {menu: [] for menu in _MENU_SEVERITIES}
    for menu in menus:
        kind = menu["menu"]
        if kind not in listed or len(menu["members"]) > max_page_size:
            raise ValueError("unsupported or oversized scanner menu")
        members = [item["observation_id"] for item in menu["members"]]
        if any(identity not in leads or leads[identity][0]["component_id"] != menu["component_id"]
               for identity in members):
            raise ValueError("scanner menu invented or cross-component lead")
        listed[kind].extend(members)
    for kind, identities in listed.items():
        if len(identities) != len(set(identities)) or set(identities) != expected[kind]:
            raise ValueError(f"{kind} scanner menu membership mismatch")
    result = view, facts, document_facts, leads, menus, audits, expected
    if validation is not None:
        validation.records[cache_key] = result
    return result


def assemble_review_packages(core: RetrievalCore, *, max_page_size: int = 20) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    count_work("assembly_count")
    view, facts, document_facts, leads, menus, audits, expected = _membership(core, max_page_size)
    inputs = sorted({(item["name"], item.get("shard_id", "default"), item["sha256"])
                     for item in core.manifest["indexes"]})
    document_rows = {row.identity: row for row in view.entities(view.select("documents"), ("document_record",))}
    gaps = _coverage_gaps(view)
    if not facts:
        gaps.append(_gap("scanner_correlation", "source_sast", "unavailable",
                         "no accepted scanner-correlation facts; document hunts have no scanner lead"))
    source_by_path: dict[str, list[str]] = {}
    for row in view.entities(view.select("source"), ("source_file",)):
        if row.location:
            source_by_path.setdefault(str(row.location["path"]), []).append(row.identity)
    metric_by_path: dict[str, list[tuple[Mapping[str, Any], Any]]] = {}
    for payload, row in _facts(view, "history_context"):
        if payload.get("fact_type") == "metric_vector" and isinstance(payload.get("subject_path"), str):
            metric_by_path.setdefault(payload["subject_path"], []).append((payload, row))
    priority_by_path: dict[str, list[Any]] = {}
    for row in view.entities(view.select("priority"), ("priority_item",)):
        if row.location:
            priority_by_path.setdefault(str(row.location["path"]), []).append(row)
    tag_by_path: dict[str, list[Any]] = {}
    tag_by_subject: dict[str, list[Any]] = {}
    for row in view.entities(view.select("tags"), ("tag_assignment",)):
        subject = row.payload.get("subject", {})
        if isinstance(subject, Mapping):
            if isinstance(subject.get("logical_id"), str):
                tag_by_subject.setdefault(subject["logical_id"], []).append(row)
            if subject.get("kind") == "source_file" and isinstance(subject.get("path"), str):
                tag_by_path.setdefault(subject["path"], []).append(row)
    compiled_by_path: dict[str, list[Any]] = {}
    for row in view.entities(view.select("analysis"), ("ast_node",)):
        if row.location and row.payload.get("kind") in {"FunctionDecl", "CXXMethodDecl"}:
            compiled_by_path.setdefault(str(row.location["path"]), []).append(row)
    build_by_path: dict[str, list[tuple[Mapping[str, Any], Any]]] = {}
    for payload, row in _facts(view, "build_provenance"):
        if payload.get("fact_type") != "build_action":
            continue
        for source_input in payload.get("result", {}).get("source_inputs", ()):
            for prefix in ("relative:", "target:"):
                if isinstance(source_input, str) and source_input.startswith(prefix):
                    build_by_path.setdefault(source_input[len(prefix):], []).append((payload, row))

    def context_for(selected: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any],
                                                                list[str], list[str], list[dict[str, Any]], list[dict[str, str]],
                                                                dict[str, Any], list[dict[str, Any]]]:
        paths = sorted({item["location"].get("source_path") for item in selected if item["location"].get("source_path")})
        sources = sorted({identity for path in paths for identity in source_by_path.get(path, ())})
        local_gaps = []
        scopes: dict[str, Any] = {}
        bindings = []
        for lead in selected:
            path = lead["location"].get("source_path")
            line = lead["location"].get("start_line")
            end_line = lead["location"].get("end_line", line)
            sha = lead["location"].get("file_sha256")
            candidates = [row for row in priority_by_path.get(path, ()) if row.payload.get("scope") == "function"
                          and row.location["file_sha256"] == sha and isinstance(line, int)
                          and isinstance(end_line, int) and row.location["start_line"] <= line
                          and end_line <= row.location["end_line"]]
            candidates.sort(key=lambda row: (row.location["end_line"] - row.location["start_line"], row.identity))
            scope = candidates[0] if len(candidates) == 1 or (candidates and
                candidates[0].location["end_line"] - candidates[0].location["start_line"] <
                candidates[1].location["end_line"] - candidates[1].location["start_line"]) else None
            if scope:
                scopes[lead["observation_id"]] = scope
            else:
                local_gaps.append(_gap("function_scope", lead["observation_id"],
                                       "ambiguous" if candidates else "unavailable",
                                       "no unique accepted function span contains the lead"))
        metric_rows = {row.identity: (payload, row) for path in paths for payload, row in metric_by_path.get(path, ())
                       if payload.get("subject_identity") in {scope.identity for scope in scopes.values()}
                       or payload.get("result", {}).get("scope") == "file"}
        build_rows = {row.identity: (payload, row) for path in paths for payload, row in build_by_path.get(path, ())}
        metrics = [metric for payload, _ in sorted(metric_rows.values(), key=lambda pair: pair[1].identity)
                   for metric in payload["result"].get("metrics", ())]
        commands = [command for payload, _ in sorted(build_rows.values(), key=lambda pair: pair[1].identity)
                    for command in payload["result"].get("command_facts", ())
                    if any(token.get("kind") == "source_input" and token.get("safe_value") in
                           {f"relative:{path}" for path in paths} | {f"target:{path}" for path in paths}
                           for token in command.get("ordered_tokens", ()))]
        environments = {item["name"]: item for payload, _ in sorted(build_rows.values(), key=lambda pair: pair[1].identity)
                        for item in payload["result"].get("environment_facts", ())}
        if len(metrics) > 200 or len(commands) > 100 or len(environments) > 100:
            raise ValueError("review package context exceeds its bound; partition the source scope")
        actions = sorted({payload["result"]["build_action_id"] for payload, _ in build_rows.values()})
        artifacts = sorted({item for payload, _ in build_rows.values()
                            for item in payload["result"].get("produced_artifact_ids", ())})
        context = {"action_ids": actions, "artifact_ids": artifacts,
                   "command_facts": commands, "environment_facts": [environments[key] for key in sorted(environments)],
                   "bindings": []}
        for lead in selected:
            path = lead["location"].get("source_path")
            matching_actions = sorted({payload["result"]["build_action_id"] for payload, _ in build_by_path.get(path, ())})
            bindings.append({"observation_id": lead["observation_id"],
                             "function_scope_id": scopes[lead["observation_id"]].identity if lead["observation_id"] in scopes else None,
                             "source_path": path, "action_ids": matching_actions,
                             "match": "source_file" if matching_actions else "unresolved"})
            if len(matching_actions) > 1:
                local_gaps.append(_gap("build_provenance", lead["observation_id"], "ambiguous",
                                       "multiple accepted build actions compile the lead's source file"))
        context["bindings"] = sorted(bindings, key=lambda item: item["observation_id"])
        tag_rows = {row.identity: row for lead in selected for row in
                    [*tag_by_subject.get(lead["observation_id"], ()),
                     *(item for item in tag_by_path.get(lead["location"].get("source_path"), ())
                       if item.location is None or
                       item.location["file_sha256"] == lead["location"].get("file_sha256"))]}
        if len(tag_rows) > 200:
            raise ValueError("review package tags exceed their bound; partition the source scope")
        assignments = [{"entity_id": row.identity, "tag": row.payload["tag"],
                        "basis": row.payload["basis"], "family": row.payload["family"],
                        "subject_id": row.payload["subject"]["logical_id"]}
                       for row in sorted(tag_rows.values(), key=lambda row: row.identity)]
        cloud = [{"tag": tag, "assignment_count": count} for tag, count in
                 sorted(Counter(item["tag"] for item in assignments).items())]
        tag_context = {"assignments": assignments, "cloud": cloud}
        compiled_rows = {}
        for lead in selected:
            scope = scopes.get(lead["observation_id"])
            if scope is None:
                continue
            for row in compiled_by_path.get(scope.location["path"], ()):
                if (row.location["file_sha256"] == scope.location["file_sha256"] and
                    scope.location["start_line"] <= row.location["start_line"] <= scope.location["end_line"]):
                    compiled_rows[row.identity] = row
        if len(compiled_rows) > 100:
            raise ValueError("review package compiled references exceed their bound")
        compiled_context = [{"entity_id": row.identity, "kind": row.payload["kind"],
                             "name": row.name, "compile_unit_id": row.payload.get("compile_unit_id"),
                             "source_path": row.location["path"], "line": row.location["start_line"]}
                            for row in sorted(compiled_rows.values(), key=lambda row: row.identity)]
        references = sorted([*metric_rows, *build_rows, *tag_rows, *compiled_rows,
                             *(scope.identity for scope in scopes.values())])
        context_evidence = {row.identity: row for row in [*(row for _payload, row in metric_rows.values()),
                                *(row for _payload, row in build_rows.values()),
                                *tag_rows.values(), *compiled_rows.values(), *scopes.values()]}
        evidence = [{"entity_id": row.identity, "relation": "qualifies", "shard_id": row.shard_id,
                     "shard_sha256": row.shard_sha256,
                     "resolution": "source_line" if row.location else "run_artifact"}
                    for row in sorted(context_evidence.values(), key=lambda row: row.identity)]
        if not metric_rows:
            local_gaps.append(_gap("history_context", ",".join(paths) or "unresolved-source", "unavailable",
                                   "no source-matched accepted metric vector"))
        if not build_rows:
            local_gaps.append(_gap("build_provenance", ",".join(paths) or "unresolved-source", "unavailable",
                                   "no source-matched safe build-action facts"))
        if not commands and build_rows:
            local_gaps.append(_gap("build_provenance", ",".join(paths), "unavailable",
                                   "no safe compile command explicitly names the source file"))
        if not tag_rows:
            local_gaps.append(_gap("security_tagging", ",".join(paths) or "unresolved-source", "unavailable",
                                   "no accepted tag assignment matches the lead or source file"))
        if not compiled_rows and any(Path(path).suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
                                     for path in paths):
            local_gaps.append(_gap("compiled_analysis", ",".join(paths) or "unresolved-source", "unavailable",
                                   "no accepted Clang function declaration matches a resolved function span"))
        return metrics, context, sources, references, evidence, local_gaps, tag_context, compiled_context

    packages = []
    for identity, (lead, row) in sorted(leads.items()):
        evidence = [{"entity_id": row.identity, "relation": "nominates", "shard_id": row.shard_id,
                     "shard_sha256": row.shard_sha256,
                     "resolution": "source_line" if lead["location_exact"] else "unresolved"}]
        metrics, build, sources, refs, additional_evidence, local_gaps, tags, compiled = context_for([lead])
        packages.append(_package(core, kind="finding_lead", partition=identity, leads=[lead],
                                 evidence=sorted([*evidence, *additional_evidence], key=lambda item: item["entity_id"]),
                                 gaps=sorted([*gaps, *local_gaps], key=lambda item: item["gap_id"]),
                                 next_partition=None, max_page_size=max_page_size,
                                 metrics=metrics, build_context=build, source_ids=sources,
                                 context_ids=sorted({row.identity, *refs}), tag_context=tags,
                                 compiled_context=compiled, inputs=inputs))
    for menu in sorted(menus, key=lambda item: (item["menu"], item["component_id"], item["partition"])):
        chunk = sorted((leads[item["observation_id"]] for item in menu["members"]),
                       key=lambda pair: pair[0]["observation_id"])
        evidence = sorted(({"entity_id": row.identity, "relation": "nominates",
                            "shard_id": row.shard_id, "shard_sha256": row.shard_sha256,
                            "resolution": "source_line" if lead["location_exact"] else "unresolved"}
                           for lead, row in chunk), key=lambda item: item["entity_id"])
        metrics, build, sources, refs, additional_evidence, local_gaps, tags, compiled = context_for([lead for lead, _ in chunk])
        packages.append(_package(core, kind="hunt", partition=f"{menu['menu']}:{menu['component_id']}:{menu['partition']:05d}",
                                 leads=[lead for lead, _ in chunk], evidence=sorted([*evidence, *additional_evidence],
                                 key=lambda item: item["entity_id"]),
                                 gaps=sorted([*gaps, *local_gaps], key=lambda item: item["gap_id"]),
                                 next_partition=menu["next_partition"], max_page_size=max_page_size,
                                 metrics=metrics, build_context=build, source_ids=sources,
                                 context_ids=sorted({*(row.identity for _, row in chunk), *refs}),
                                 tag_context=tags, compiled_context=compiled, inputs=inputs))
    for payload, row in sorted(document_facts, key=lambda pair: pair[1].identity):
        result = payload["result"]
        named = result.get("members") or {}
        if not isinstance(named, Mapping):
            raise ValueError("document context member map is invalid")
        member_ids = sorted({identity for values in named.values() for identity in values})
        if any(identity not in document_rows for identity in member_ids):
            raise ValueError("document context references an unaccepted source record")
        anchor = payload.get("subject_identity")
        if anchor not in document_rows or anchor not in member_ids:
            raise ValueError("document context source anchor is unresolved")
        selected_ids = sorted({anchor, *[identity for identity in member_ids if identity != anchor][:63]})
        selected = [document_rows[identity] for identity in selected_ids]
        omitted = len(member_ids) - len(selected)
        local_gaps = [_gap("document_context", row.identity, "partial", str(reason))
                      for reason in payload.get("gaps", ())]
        if omitted:
            local_gaps.append(_gap("document_context", row.identity, "truncated",
                                   f"{omitted} document source record(s) exceeded the package grant bound"))
        local_gaps.append(_gap("document_context", row.identity, "unavailable",
                               "route or boundary has not been mapped to a unique implementation component"))
        packages.append(_document_hunt(core, row, selected, [*gaps, *local_gaps], omitted, max_page_size, inputs))
    validate_packages(core, packages, expected, audits[0] if audits else None)
    manifest = {"schema": MANIFEST_SCHEMA, "run_id": core.run_id, "accepted_manifest_sha256": core.manifest_sha256,
                "assembly_rule": ASSEMBLY_RULE, "max_page_size": max_page_size,
                "packages": [{"package_id": item["package_id"],
                    "sha256": _digest(item), "kind": item["kind"]} for item in packages],
                "counts": {"finding_lead": len(leads), "hunt": len(menus),
                           "document_hunt": len(document_facts),
                           "high_critical": len(expected["high_critical"]), "unknown": len(expected["unknown"])},
                "coverage_gaps": sorted({gap["gap_id"]: gap for item in packages
                                         for gap in item["coverage_gaps"]}.values(),
                                        key=lambda item: item["gap_id"])}
    manifest["content_sha256"] = _digest(manifest)
    return packages, manifest


def _projection_path(core: RetrievalCore, max_page_size: int) -> str:
    identity = _digest([core.run_id, core.manifest_sha256, ASSEMBLY_RULE, max_page_size])
    return f"review-package-admission/{core.run_id}/{identity}.json"


def publish_review_packages(core: RetrievalCore, *, max_page_size: int = 20) -> Path:
    packages, manifest = assemble_review_packages(core, max_page_size=max_page_size)
    from appsec_review.storage.admission import publish_projection
    publish_projection(core.run_root, _projection_path(core, max_page_size), {
        "schema": "appsec-review/package-projection/1", "run_id": core.run_id,
        "target_snapshot": core.manifest["target_snapshot"], "manifest": manifest})
    destination = core.run_root / "data" / "review-packages" / manifest["content_sha256"]
    safe_path(core.run_root, destination.relative_to(core.run_root).as_posix())
    destination.mkdir(parents=True, exist_ok=True)
    for item in packages:
        path = destination / f"{item['package_id']}.json"
        publish_named(core.run_root, path, canonical_json(item) + b"\n", namespace="review-package",
                      computation={"assembly_rule": ASSEMBLY_RULE, "manifest_sha256": core.manifest_sha256})
    publish_named(core.run_root, destination / "manifest.json", canonical_json(manifest) + b"\n",
                  namespace="review-package",
                  computation={"assembly_rule": ASSEMBLY_RULE, "manifest_sha256": core.manifest_sha256})
    return destination


def verify_review_packages(core: RetrievalCore, directory: Path) -> dict[str, Any]:
    directory = safe_path(core.run_root, Path(directory).relative_to(core.run_root).as_posix())
    if directory.parent != (core.run_root / "data" / "review-packages").resolve():
        raise ValueError("review package directory escapes its run")
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("review package manifest schema mismatch")
    if manifest_path.read_bytes() != canonical_json(manifest) + b"\n":
        raise ValueError("review package manifest byte integrity mismatch")
    digest = manifest.pop("content_sha256", None)
    if digest != _digest(manifest) or manifest.get("run_id") != core.run_id or manifest.get("accepted_manifest_sha256") != core.manifest_sha256:
        raise ValueError("review package manifest integrity mismatch")
    manifest["content_sha256"] = digest
    if directory.name != digest or manifest.get("assembly_rule") != ASSEMBLY_RULE:
        raise ValueError("review package directory or assembly rule mismatch")
    from appsec_review.storage.admission import read_projection
    projection = read_projection(core.run_root, _projection_path(core, manifest["max_page_size"]))
    if projection != {"schema": "appsec-review/package-projection/1", "run_id": core.run_id,
                       "target_snapshot": core.manifest["target_snapshot"], "manifest": manifest}:
        raise ValueError("review packages differ from their validated assembly projection")
    packages = []
    expected_files = {"manifest.json", *(f"{entry['package_id']}.json" for entry in manifest["packages"])}
    if {path.name for path in directory.iterdir()} != expected_files:
        raise ValueError("review package directory membership mismatch")
    for entry in manifest["packages"]:
        name = entry["package_id"]
        if Path(name).name != name:
            raise ValueError("review package path is invalid")
        path = directory / f"{name}.json"
        safe_path(core.run_root, path.relative_to(core.run_root).as_posix())
        package = json.loads(path.read_text(encoding="utf-8"))
        if (path.read_bytes() != canonical_json(package) + b"\n" or
            _digest(package) != entry["sha256"] or package.get("package_id") != name or
            package.get("manifest_sha256") != core.manifest_sha256):
            raise ValueError("review package byte or manifest integrity mismatch")
        if package.get("kind") != entry.get("kind"):
            raise ValueError("review package kind mismatch")
        packages.append(package)
    _, _, documents, leads, menus, audits, expected = _membership(core, manifest["max_page_size"])
    validate_packages(core, packages, expected, audits[0] if audits else None)
    counts = {"finding_lead": len(leads), "hunt": len(menus), "document_hunt": len(documents),
              "high_critical": len(expected["high_critical"]), "unknown": len(expected["unknown"])}
    gaps = sorted({gap["gap_id"]: gap for item in packages
                   for gap in item["coverage_gaps"]}.values(), key=lambda item: item["gap_id"])
    expected_menus = {
        f"{menu['menu']}:{menu['component_id']}:{menu['partition']:05d}":
            ([item["observation_id"] for item in sorted(menu["members"], key=lambda item: item["observation_id"])],
             menu["next_partition"]) for menu in menus}
    actual_menus = {
        item["scope"]["partition_key"]:
            ([lead["observation_id"] for lead in item["lead_menu"]], item["truncation"]["next_partition"])
        for item in packages if item["kind"] == "hunt"}
    if (manifest["counts"] != counts or manifest["coverage_gaps"] != gaps
            or Counter(item["kind"] for item in packages) != Counter(
                {key: counts[key] for key in ("finding_lead", "hunt", "document_hunt") if counts[key]})
            or actual_menus != expected_menus):
        raise ValueError("review package membership or accepted input integrity mismatch")
    for package in packages:
        for lead in package["lead_menu"]:
            if lead != leads[lead["observation_id"]][0]:
                raise ValueError("review package lead differs from accepted input")
    for entry in manifest["packages"]:
        consume_named(core.run_root, directory / f"{entry['package_id']}.json", namespace="review-package")
    consume_named(core.run_root, manifest_path, namespace="review-package")
    return manifest
