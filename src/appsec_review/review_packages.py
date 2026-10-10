"""Deterministic pre-adjudication packages from verified, accepted index shards."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sysconfig
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.model import LogicalIdentity, canonical_json
from appsec_review.storage import atomic_json, file_sha256


SCHEMA = "appsec-review/review-package/1"
ASSEMBLY_RULE = "appsec-review/assemble-review-packages/1"
MANIFEST_SCHEMA = "appsec-review/review-package-manifest/1"
_MENU_SEVERITIES = {"high_critical": {"critical", "high"}, "unknown": {"unknown"}}

def _schema_path() -> Path:
    source = Path(__file__).parents[2] / "docs" / "schemas" / "review-packages.schema.json"
    installed = (Path(sysconfig.get_path("data")) / "share" / "appsec-review" / "schemas" /
                 "review-packages.schema.json")
    for candidate in (source, installed):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("review package schema is unavailable")


_CONTRACT = Draft202012Validator(json.loads(_schema_path().read_text(encoding="utf-8")))


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _identity(package: Mapping[str, Any]) -> str:
    return f"{package['kind']}-{_digest({key: value for key, value in package.items() if key != 'package_id'})}"


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


def _package(core: RetrievalCore, *, kind: str, partition: str, leads: list[dict[str, Any]],
             evidence: list[dict[str, Any]], gaps: list[dict[str, str]], next_partition: str | None,
             max_page_size: int, metrics: list[dict[str, Any]], build_context: dict[str, Any],
             source_ids: list[str], context_ids: list[str]) -> dict[str, Any]:
    component = leads[0]["component_id"]
    entity_ids = sorted({item["observation_id"] for item in leads} |
                        {item["entity_id"] for item in evidence} |
                        set(source_ids) | set(context_ids) | set(build_context["action_ids"]) |
                        {item["scope_id"] for item in metrics} |
                        {flow for item in leads for flow in item["flow_ids"]})
    inputs = sorted({(item["name"], item.get("shard_id", "default"), item["sha256"])
                     for item in core.manifest["indexes"]})
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
               "proof_obligations": ["resolve affected construct", "establish input control",
                                     "establish reachability", "evaluate guards and configuration", "establish impact"],
               "retrieval": {"indexes": [name for name in ("observations", "precomputed", "source") if name in core.indexes],
                             "query_sets": ["scanner_correlation", "history_context", "build_provenance"],
                             "entity_ids": entity_ids,
                             "max_page_size": max_page_size, "max_pages": 5, "max_depth": 2,
                             "max_response_bytes": 131072},
               "coverage_gaps": gaps,
               "truncation": {"omitted_leads": 0, "omitted_context": 0, "next_partition": next_partition}}
    package["package_id"] = _identity(package)
    return package


def validate_packages(core: RetrievalCore, packages: list[Mapping[str, Any]],
                      expected: Mapping[str, set[str]], audit: Mapping[str, Any]) -> None:
    """Verify bytes, stable identity, provenance and complete lead/menu membership."""
    ids: set[str] = set()
    finding: Counter[str] = Counter()
    hunt: dict[str, set[str]] = {key: set() for key in _MENU_SEVERITIES}
    for package in packages:
        _CONTRACT.validate(package)
        if package.get("schema") != SCHEMA or package.get("assembly_rule") != ASSEMBLY_RULE:
            raise ValueError("unsupported review package schema or rule")
        if package.get("run_id") != core.run_id or package.get("manifest_sha256") != core.manifest_sha256:
            raise ValueError("review package run or manifest mismatch")
        if package.get("package_id") != _identity(package) or package["package_id"] in ids:
            raise ValueError("review package identity mismatch")
        ids.add(package["package_id"])
        leads = package["lead_menu"]
        if not leads or (package["kind"] == "finding_lead" and len(leads) != 1):
            raise ValueError("review package lead bounds failed")
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
            if evidence["shard_sha256"] not in {item["sha256"] for item in core.manifest["indexes"]}:
                raise ValueError("review package evidence shard mismatch")
    if any(count != 1 for count in finding.values()) or set(finding) != expected["all"]:
        raise ValueError("finding-lead membership mismatch")
    for menu in _MENU_SEVERITIES:
        if hunt[menu] != expected[menu]:
            raise ValueError(f"{menu} hunt membership mismatch")
    counts = audit.get("counts", {})
    if (audit.get("status") != "passed" or counts.get("source_sast_observations") != len(finding)
            or counts.get("high_critical") != len(expected["high_critical"])
            or counts.get("unknown_severity") != len(expected["unknown"])):
        raise ValueError("scanner-correlation audit mismatch")


def assemble_review_packages(core: RetrievalCore, *, max_page_size: int = 20) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not 1 <= max_page_size <= 100:
        raise ValueError("invalid package page bound")
    view = AcceptedShards(core.run_root, core.manifest["indexes"], core.manifest["target_snapshot"])
    facts = _facts(view, "scanner_correlation")
    if not facts:
        raise ValueError("accepted scanner-correlation facts are unavailable")
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
    if len(audits) != 1:
        raise ValueError("scanner-correlation membership audit missing or duplicated")
    expected = {"all": set(leads), **{menu: {identity for identity, (lead, _) in leads.items()
                                              if lead["reported_severity"] in severities}
                                     for menu, severities in _MENU_SEVERITIES.items()}}
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
    gaps = _coverage_gaps(view)
    source_by_path: dict[str, list[str]] = {}
    for row in view.entities(view.select("source"), ("source_file",)):
        if row.location:
            source_by_path.setdefault(str(row.location["path"]), []).append(row.identity)
    metric_by_path: dict[str, list[tuple[Mapping[str, Any], Any]]] = {}
    for payload, row in _facts(view, "history_context"):
        if payload.get("fact_type") == "metric_vector" and isinstance(payload.get("subject_path"), str):
            metric_by_path.setdefault(payload["subject_path"], []).append((payload, row))
    build_by_path: dict[str, list[tuple[Mapping[str, Any], Any]]] = {}
    for payload, row in _facts(view, "build_provenance"):
        if payload.get("fact_type") != "build_action":
            continue
        for source_input in payload.get("result", {}).get("source_inputs", ()):
            for prefix in ("relative:", "target:"):
                if isinstance(source_input, str) and source_input.startswith(prefix):
                    build_by_path.setdefault(source_input[len(prefix):], []).append((payload, row))

    def context_for(selected: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any],
                                                                list[str], list[str], list[dict[str, Any]], list[dict[str, str]]]:
        paths = sorted({item["location"].get("source_path") for item in selected if item["location"].get("source_path")})
        sources = sorted({identity for path in paths for identity in source_by_path.get(path, ())})
        metric_rows = {row.identity: (payload, row) for path in paths for payload, row in metric_by_path.get(path, ())}
        build_rows = {row.identity: (payload, row) for path in paths for payload, row in build_by_path.get(path, ())}
        metrics = [metric for payload, _ in sorted(metric_rows.values(), key=lambda pair: pair[1].identity)
                   for metric in payload["result"].get("metrics", ())]
        commands = [command for payload, _ in sorted(build_rows.values(), key=lambda pair: pair[1].identity)
                    for command in payload["result"].get("command_facts", ())]
        environments = {item["name"]: item for payload, _ in sorted(build_rows.values(), key=lambda pair: pair[1].identity)
                        for item in payload["result"].get("environment_facts", ())}
        if len(metrics) > 200 or len(commands) > 100 or len(environments) > 100:
            raise ValueError("review package context exceeds its bound; partition the source scope")
        actions = sorted({payload["result"]["build_action_id"] for payload, _ in build_rows.values()})
        artifacts = sorted({item for payload, _ in build_rows.values()
                            for item in payload["result"].get("produced_artifact_ids", ())})
        context = {"action_ids": actions, "artifact_ids": artifacts,
                   "command_facts": commands, "environment_facts": [environments[key] for key in sorted(environments)]}
        references = sorted([*metric_rows, *build_rows])
        evidence = [{"entity_id": row.identity, "relation": "qualifies", "shard_id": row.shard_id,
                     "shard_sha256": row.shard_sha256,
                     "resolution": "source_line" if row.location else "run_artifact"}
                    for _payload, row in [*metric_rows.values(), *build_rows.values()]]
        local_gaps = []
        if not metric_rows:
            local_gaps.append(_gap("history_context", ",".join(paths) or "unresolved-source", "unavailable",
                                   "no source-matched accepted metric vector"))
        if not build_rows:
            local_gaps.append(_gap("build_provenance", ",".join(paths) or "unresolved-source", "unavailable",
                                   "no source-matched safe build-action facts"))
        return metrics, context, sources, references, evidence, local_gaps

    packages = []
    for identity, (lead, row) in sorted(leads.items()):
        evidence = [{"entity_id": row.identity, "relation": "nominates", "shard_id": row.shard_id,
                     "shard_sha256": row.shard_sha256,
                     "resolution": "source_line" if lead["location_exact"] else "unresolved"}]
        metrics, build, sources, refs, additional_evidence, local_gaps = context_for([lead])
        packages.append(_package(core, kind="finding_lead", partition=identity, leads=[lead],
                                 evidence=sorted([*evidence, *additional_evidence], key=lambda item: item["entity_id"]),
                                 gaps=sorted([*gaps, *local_gaps], key=lambda item: item["gap_id"]),
                                 next_partition=None, max_page_size=max_page_size,
                                 metrics=metrics, build_context=build, source_ids=sources,
                                 context_ids=sorted([row.identity, *refs])))
    for menu in sorted(menus, key=lambda item: (item["menu"], item["component_id"], item["partition"])):
        chunk = sorted((leads[item["observation_id"]] for item in menu["members"]),
                       key=lambda pair: pair[0]["observation_id"])
        evidence = sorted(({"entity_id": row.identity, "relation": "nominates",
                            "shard_id": row.shard_id, "shard_sha256": row.shard_sha256,
                            "resolution": "source_line" if lead["location_exact"] else "unresolved"}
                           for lead, row in chunk), key=lambda item: item["entity_id"])
        metrics, build, sources, refs, additional_evidence, local_gaps = context_for([lead for lead, _ in chunk])
        packages.append(_package(core, kind="hunt", partition=f"{menu['menu']}:{menu['component_id']}:{menu['partition']:05d}",
                                 leads=[lead for lead, _ in chunk], evidence=sorted([*evidence, *additional_evidence],
                                 key=lambda item: item["entity_id"]),
                                 gaps=sorted([*gaps, *local_gaps], key=lambda item: item["gap_id"]),
                                 next_partition=menu["next_partition"], max_page_size=max_page_size,
                                 metrics=metrics, build_context=build, source_ids=sources,
                                 context_ids=sorted([*(row.identity for _, row in chunk), *refs])))
    validate_packages(core, packages, expected, audits[0])
    manifest = {"schema": MANIFEST_SCHEMA, "run_id": core.run_id, "accepted_manifest_sha256": core.manifest_sha256,
                "assembly_rule": ASSEMBLY_RULE, "max_page_size": max_page_size,
                "packages": [{"package_id": item["package_id"],
                    "sha256": _digest(item), "kind": item["kind"]} for item in packages],
                "counts": {"finding_lead": len(leads), "hunt": len(menus),
                           "high_critical": len(expected["high_critical"]), "unknown": len(expected["unknown"])},
                "coverage_gaps": sorted({gap["gap_id"]: gap for item in packages
                                         for gap in item["coverage_gaps"]}.values(),
                                        key=lambda item: item["gap_id"])}
    manifest["content_sha256"] = _digest(manifest)
    return packages, manifest


def publish_review_packages(core: RetrievalCore, *, max_page_size: int = 20) -> Path:
    packages, manifest = assemble_review_packages(core, max_page_size=max_page_size)
    destination = core.run_root / "data" / "review-packages" / manifest["content_sha256"]
    if destination.exists():
        verify_review_packages(core, destination)
        return destination
    destination.mkdir(parents=True)
    for item in packages:
        atomic_json(destination / f"{item['package_id']}.json", item)
    atomic_json(destination / "manifest.json", manifest)
    verify_review_packages(core, destination)
    return destination


def verify_review_packages(core: RetrievalCore, directory: Path) -> dict[str, Any]:
    directory = Path(directory).resolve()
    if directory.parent != (core.run_root / "data" / "review-packages").resolve():
        raise ValueError("review package directory escapes its run")
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest_path.read_bytes() != canonical_json(manifest) + b"\n":
        raise ValueError("review package manifest byte integrity mismatch")
    digest = manifest.pop("content_sha256", None)
    if digest != _digest(manifest) or manifest.get("run_id") != core.run_id or manifest.get("accepted_manifest_sha256") != core.manifest_sha256:
        raise ValueError("review package manifest integrity mismatch")
    manifest["content_sha256"] = digest
    for entry in manifest["packages"]:
        name = entry["package_id"]
        if Path(name).name != name:
            raise ValueError("review package path is invalid")
        path = directory / f"{name}.json"
        package = json.loads(path.read_text(encoding="utf-8"))
        if (path.read_bytes() != canonical_json(package) + b"\n" or
            _digest(package) != entry["sha256"] or package.get("package_id") != name or
            package.get("manifest_sha256") != core.manifest_sha256):
            raise ValueError("review package byte or manifest integrity mismatch")
    _, expected = assemble_review_packages(core, max_page_size=manifest["max_page_size"])
    if manifest != expected:
        raise ValueError("review package membership or accepted input integrity mismatch")
    return manifest
