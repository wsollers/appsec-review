from __future__ import annotations

from collections import defaultdict
import hashlib
from itertools import islice
from pathlib import PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from appsec_review.storage import canonical_json

from .guidance import assign, load_registry
from .standards import StandardCatalog, control_records, digest


COMPONENT_ROLES = {
    "application_api_server", "web_frontend", "android_mobile", "ios_mobile",
    "authentication_identity", "cryptography_data_protection", "storage", "network",
    "platform_integration", "build_supply_chain", "deployment_operations",
    "administrative_tooling", "test_development_only",
}
APPLICATION_ROLES = {"application_api_server", "web_frontend", "authentication_identity",
                     "administrative_tooling"}
MOBILE_ROLES = {"android_mobile", "ios_mobile"}
APPLICABILITY_OUTCOMES = {
    "applicable", "not_applicable", "conditional", "cannot_determine",
    "unsupported_missing_evidence",
}
RESULT_STATUSES = {"satisfied", "not_satisfied", "cannot_verify", "not_assessed"}


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _citation_valid(citation: Mapping[str, Any]) -> bool:
    source = str(citation.get("source_identity", ""))
    artifact = str(citation.get("artifact_sha256", ""))
    lines = citation.get("lines")
    return (bool(source) and len(artifact) == 64 and all(character in "0123456789abcdef" for character in artifact)
            and isinstance(lines, list) and len(lines) == 2 and all(type(value) is int and value >= 1 for value in lines)
            and lines[1] >= lines[0])


def _bounded_strings(values: Iterable[Any], *, limit: int, length: int = 512) -> list[str]:
    return [str(value)[:length] for value in islice(values, limit)]


def _deterministic_roles(component: Mapping[str, Any]) -> tuple[set[str], list[str]]:
    paths = [str(value).lower().replace("\\", "/") for value in component.get("paths", ())]
    languages = {str(value).lower() for value in component.get("languages", ())}
    frameworks = {str(value).lower() for value in component.get("frameworks", ())}
    tags = {str(value).lower() for value in component.get("tags", ())}
    roles: set[str] = set()
    reasons: list[str] = []

    def mark(role: str, reason: str) -> None:
        roles.add(role)
        reasons.append(reason)

    if tags & {"api", "server", "backend", "application"} or frameworks & {
        "django", "flask", "fastapi", "spring", "express", "aspnet", "rails",
    }:
        mark("application_api_server", "accepted component metadata identifies an application/API/server")
    if tags & {"frontend", "web-ui"} or languages & {"typescript", "javascript"} and any(
            value.endswith(("package.json", "vite.config.ts", "next.config.js")) for value in paths):
        mark("web_frontend", "accepted web build/language signals identify a frontend")
    if tags & {"android", "mobile-android"} or languages & {"kotlin"} and any(
            "androidmanifest.xml" in value for value in paths):
        mark("android_mobile", "accepted Android manifest/language signals identify a mobile component")
    if tags & {"ios", "mobile-ios"} or languages & {"swift", "objective-c"} and any(
            value.endswith(("info.plist", ".xcodeproj/project.pbxproj")) for value in paths):
        mark("ios_mobile", "accepted iOS project/language signals identify a mobile component")
    keyword_roles = {
        "authentication_identity": ("auth", "identity", "session", "oauth", "oidc"),
        "cryptography_data_protection": ("crypto", "encrypt", "key-management", "secrets"),
        "storage": ("storage", "database", "persistence", "repository"),
        "network": ("network", "transport", "tls", "http-client"),
        "platform_integration": ("platform", "integration", "plugin"),
        "build_supply_chain": ("build", "dependency", "supply-chain", "ci"),
        "deployment_operations": ("deployment", "operations", "iac", "container"),
        "administrative_tooling": ("admin", "operator", "management"),
        "test_development_only": ("test-only", "development-only", "fixture"),
    }
    for role, signals in keyword_roles.items():
        if tags.intersection(signals):
            mark(role, f"accepted component tags identify the {role} role")
    if any(value.startswith(("tests/", "test/", "fixtures/")) for value in paths) and paths and all(
            value.startswith(("tests/", "test/", "fixtures/")) for value in paths):
        mark("test_development_only", "all accepted component paths are test/development fixtures")
    return roles, reasons


def characterize_components(
    components: Sequence[Mapping[str, Any]], *,
    inference: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    max_components: int = 128,
) -> tuple[dict[str, Any], ...]:
    """Classify coherent accepted components without reading a target tree.

    The optional resolver receives only bounded component metadata and cited index signals.
    """
    if not 1 <= len(components) <= max_components:
        raise ValueError("component characterization input exceeds its configured bound")
    seen: set[str] = set()
    results = []
    for raw in components:
        component_id = str(raw.get("component_id", ""))
        project_id = str(raw.get("project_id", ""))
        if not component_id or not project_id or component_id in seen:
            raise ValueError("component/project identities must be present and unique")
        seen.add(component_id)
        citations = [dict(value) for value in raw.get("evidence", ()) if isinstance(value, Mapping)]
        if not citations or any(not _citation_valid(value) for value in citations):
            raise ValueError(f"component {component_id} lacks resolving evidence citations")
        roles, reasons = _deterministic_roles(raw)
        inference_record = {"status": "not_needed", "proposal_sha256": None}
        ambiguity = []
        if not roles:
            ambiguity.append("deterministic signals do not resolve component purpose/trust role")
            if inference is not None:
                request = {
                    "schema": "appsec-review/component-inference-request/1",
                    "component_id": component_id,
                    "project_id": project_id,
                    "paths": _bounded_strings(raw.get("paths", ()), limit=50),
                    "languages": _bounded_strings(raw.get("languages", ()), limit=20, length=64),
                    "frameworks": _bounded_strings(raw.get("frameworks", ()), limit=20, length=64),
                    "tags": _bounded_strings(raw.get("tags", ()), limit=30, length=64),
                    "evidence": citations[:20],
                    "allowed_roles": sorted(COMPONENT_ROLES),
                }
                proposal = dict(inference(request))
                proposed = proposal.get("roles")
                if (not isinstance(proposed, list) or len(proposed) > 4 or
                        any(value not in COMPONENT_ROLES for value in proposed)):
                    inference_record = {"status": "rejected", "proposal_sha256": _hash(proposal)}
                else:
                    roles.update(str(value) for value in proposed)
                    reasons.append("bounded inference resolved an otherwise ambiguous purpose/trust role")
                    ambiguity.clear()
                    inference_record = {"status": "accepted", "proposal_sha256": _hash(proposal)}
        confidence = "high" if roles and inference_record["status"] == "not_needed" else (
            "medium" if roles else "low")
        result = {
            "schema": "appsec-review/component-classification/1",
            "target_id": str(raw.get("target_id", "target")),
            "project_id": project_id,
            "component_id": component_id,
            "roles": sorted(roles),
            "confidence": confidence,
            "reasons": reasons,
            "evidence": citations,
            "ambiguity": ambiguity,
            "negative_evidence_limits": [
                "absence from accepted bounded indexes is not evidence that a role is absent"
            ],
            "gaps": list(ambiguity),
            "inference": inference_record,
            "input_fingerprint": _hash(raw),
        }
        result["classification_fingerprint"] = _hash(result)
        results.append(result)
    return tuple(sorted(results, key=lambda item: (item["project_id"], item["component_id"])))


def select_profiles(catalogs: Mapping[str, StandardCatalog], *, asvs_level: int = 2,
                    masvs_profile: str = "L2") -> dict[str, Any]:
    controls = control_records(catalogs, asvs_level=asvs_level, masvs_profile=masvs_profile)
    selections = []
    for family in sorted(catalogs):
        catalog = catalogs[family]
        profile = (f"L{asvs_level}" if family == "ASVS" else
                   masvs_profile if family == "MASVS" else "supporting" if family == "MASTG" else "context")
        selections.append({
            "family": family, "version": catalog.version, "profile": profile,
            "authority": catalog.authority, "snapshot_id": catalog.snapshot_id,
            "catalog_sha256": catalog.catalog_sha256,
        })
    value = {"schema": "appsec-review/owasp-selection/1", "selections": selections,
             "control_count": len(controls), "policy": {"asvs_level": asvs_level,
             "masvs_profile": masvs_profile}}
    value["selection_fingerprint"] = _hash(value)
    return value


def build_applicability(catalogs: Mapping[str, StandardCatalog],
                        classifications: Sequence[Mapping[str, Any]],
                        selection: Mapping[str, Any], *,
                        dynamic_authorized: bool = False) -> tuple[dict[str, Any], ...]:
    policy = selection.get("policy", {})
    controls = control_records(catalogs, asvs_level=int(policy.get("asvs_level", 0)),
                               masvs_profile=str(policy.get("masvs_profile", "")))
    rows = []
    for control in controls:
        family = str(control["family"])
        allowed = APPLICATION_ROLES if family == "ASVS" else MOBILE_ROLES
        for component in classifications:
            roles = set(component.get("roles", ()))
            citations = list(component.get("evidence", ()))
            row_id = _hash({"control": control["control_identity"],
                            "component": component["component_id"]})
            matched = roles.intersection(set(control.get("component_roles", ())))
            family_match = bool(roles.intersection(allowed))
            if component.get("confidence") == "low" or not roles:
                outcome = "cannot_determine"
                reason = "component purpose/trust role is unresolved"
                gaps = ["bounded component classification did not resolve applicability"]
            elif not family_match:
                outcome = "not_applicable"
                reason = (f"positive classification evidence identifies roles outside the {family} routing boundary: "
                          + ", ".join(sorted(roles)))
                gaps = []
            elif not matched:
                outcome = "not_applicable"
                reason = ("positive classification evidence identifies no role named by this control: "
                          + ", ".join(sorted(roles)))
                gaps = []
            elif control.get("evidence_mode") in {"dynamic_runtime", "manual_observation"} and not dynamic_authorized:
                outcome = "unsupported_missing_evidence"
                reason = "the selected control requires separately authorized dynamic/runtime or manual evidence"
                gaps = ["required dynamic/runtime or manual evidence is not authorized"]
            else:
                outcome = "applicable"
                reason = "component roles and selected control routing rules intersect"
                gaps = []
            if outcome == "not_applicable" and (not citations or not reason):
                raise ValueError("not_applicable requires positive resolving evidence and a reason")
            row = {
                "schema": "appsec-review/control-applicability/1",
                "row_id": row_id,
                "target_id": component["target_id"], "project_id": component["project_id"],
                "component_id": component["component_id"],
                "control_identity": control["control_identity"], "control_id": control["id"],
                "standard": family, "version": control["version"],
                "profile": (f"L{policy['asvs_level']}" if family == "ASVS" else policy["masvs_profile"]),
                "domain": control["domain"], "evidence_mode": control["evidence_mode"],
                "required_tools": list(control.get("required_tools", ())),
                "outcome": outcome, "reason": reason, "evidence": citations,
                "confidence": component["confidence"], "gaps": gaps,
                "rule_version": "applicability-rules/1",
            }
            if outcome not in APPLICABILITY_OUTCOMES:
                raise AssertionError("invalid applicability outcome")
            row["applicability_fingerprint"] = _hash(row)
            rows.append(row)
    return tuple(sorted(rows, key=lambda item: (item["component_id"], item["control_identity"])))


def _chunks(values: list[Mapping[str, Any]], size: int) -> Iterable[list[Mapping[str, Any]]]:
    for offset in range(0, len(values), size):
        yield values[offset:offset + size]


def partition_work(rows: Sequence[Mapping[str, Any]], repository_root, *, max_batch_size: int = 12,
                   max_components: int = 5) -> dict[str, Any]:
    if not 1 <= max_batch_size <= 64 or not 1 <= max_components <= 16:
        raise ValueError("batch/component limits are outside supported bounds")
    registry = load_registry(repository_root)
    dispatchable = [row for row in rows if row["outcome"] in {"applicable", "conditional"}]
    nondispatch = [row for row in rows if row["outcome"] not in {"applicable", "conditional"}]
    grouped: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in dispatchable:
        assignment = assign(registry, role="control_assessor", domain=str(row["domain"]))
        key = (row["project_id"], row["component_id"], row["standard"], row["version"], row["profile"],
               row["domain"], row["evidence_mode"], tuple(sorted(row["required_tools"])),
               assignment["role"], assignment["persona"])
        grouped[key].append(row)
    batches = []
    for key in sorted(grouped, key=lambda value: tuple(str(item) for item in value)):
        values = sorted(grouped[key], key=lambda item: item["row_id"])
        for part in _chunks(values, max_batch_size):
            components = sorted({str(item["component_id"]) for item in part})
            if len(components) > max_components:
                raise ValueError("a batch exceeds the configured component limit")
            batch_base = {
                "schema": "appsec-review/control-validation-batch/1",
                "row_ids": [item["row_id"] for item in part],
                "component_ids": components,
                "standard": key[2], "version": key[3], "profile": key[4],
                "domain": key[5], "evidence_mode": key[6], "required_tools": list(key[7]),
                "assignment": {"role": key[8], "persona": key[9]},
                "limits": {"max_batch_size": max_batch_size, "max_components": max_components},
            }
            fingerprint = _hash({"rows": [item["applicability_fingerprint"] for item in part],
                                 "routing": batch_base})
            batch_base["batch_id"] = f"batch-{fingerprint[:20]}"
            batch_base["fingerprint"] = fingerprint
            batches.append(batch_base)
    assigned = [row_id for batch in batches for row_id in batch["row_ids"]]
    expected = [row["row_id"] for row in dispatchable]
    if sorted(assigned) != sorted(expected) or len(assigned) != len(set(assigned)):
        raise ValueError("batch partitioning failed exactly-once dispatch accounting")
    return {
        "schema": "appsec-review/validation-work/1",
        "batches": sorted(batches, key=lambda item: item["batch_id"]),
        "non_dispatch_dispositions": [
            {"row_id": row["row_id"], "outcome": row["outcome"], "reason": row["reason"]}
            for row in sorted(nondispatch, key=lambda item: item["row_id"])
        ],
        "accounting": {"selected_rows": len(rows), "dispatched_rows": len(dispatchable),
                       "non_dispatch_rows": len(nondispatch)},
    }


def build_finding_packages(batch: Mapping[str, Any], rows: Sequence[Mapping[str, Any]],
                           controls: Sequence[Mapping[str, Any]],
                           classifications: Sequence[Mapping[str, Any]],
                           evidence: Sequence[Mapping[str, Any]], *,
                           retrieval_manifest: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    row_by_id = {row["row_id"]: row for row in rows}
    control_by_id = {control["control_identity"]: control for control in controls}
    component_by_id = {item["component_id"]: item for item in classifications}
    packages = []
    for row_id in batch["row_ids"]:
        row = row_by_id[row_id]
        control = control_by_id[row["control_identity"]]
        component = component_by_id[row["component_id"]]
        observations = [dict(item) for item in evidence
                        if item.get("component_id") == row["component_id"] and
                        item.get("control_id") in {None, row["control_id"]}]
        package = {
            "schema": "appsec-review/finding-package/1",
            "row_id": row_id, "batch_id": batch["batch_id"],
            "standard": row["standard"], "version": row["version"], "profile": row["profile"],
            "control": {"identity": row["control_identity"], "id": row["control_id"],
                        "title": control["title"], "text": control["text"]},
            "component": {"target_id": row["target_id"], "project_id": row["project_id"],
                          "component_id": row["component_id"], "roles": component["roles"],
                          "evidence": component["evidence"]},
            "evidence_references": observations[:100],
            "allowed_retrieval_tools": sorted(set(batch["required_tools"]) |
                                              {"find", "read_excerpt", "resolve_evidence"}),
            "retrieval_manifest": dict(retrieval_manifest),
            "proof_obligations": [{"obligation_id": f"{row_id}:primary",
                                   "evidence_mode": row["evidence_mode"],
                                   "required_tools": row["required_tools"]}],
            "prohibited_claims": ["compliance certification", "uncited vulnerability",
                                  "severity without independent validation", "runtime state from static evidence"],
        }
        package["package_id"] = f"package-{_hash(package)[:24]}"
        packages.append(package)
    return tuple(packages)


def assess_batch(batch: Mapping[str, Any], packages: Sequence[Mapping[str, Any]], *,
                 worker: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
                 fail: bool = False) -> dict[str, Any]:
    if fail:
        return {"schema": "appsec-review/validator-batch-result/1", "batch_id": batch["batch_id"],
                "fingerprint": batch["fingerprint"], "terminal_state": "failed",
                "results": [{"row_id": package["row_id"], "status": "not_assessed",
                             "observations": [], "evidence_used": [],
                             "gaps": ["validator worker failed; successful sibling batches remain valid"],
                             "disagreements": []} for package in packages],
                "metrics": {"model_calls": 0, "retrieval_calls": 0, "input_tokens": 0,
                            "output_tokens": 0, "cost_usd": None, "duration_ms": 0, "retries": 0}}
    results = []
    retrieval_calls = 0
    for package in packages:
        mode = package["proof_obligations"][0]["evidence_mode"]
        admissible = []
        contradictions = []
        for evidence in package["evidence_references"]:
            citation = evidence.get("citation")
            if not isinstance(citation, Mapping) or not _citation_valid(citation):
                continue
            retrieval_calls += 1
            if evidence.get("disposition") == "supports":
                admissible.append(dict(evidence))
            elif evidence.get("disposition") == "refutes":
                contradictions.append(dict(evidence))
        observations = []
        metrics = {"input_tokens": 0, "output_tokens": 0}
        if worker is not None:
            proposal = dict(worker(package))
            raw_observations = proposal.get("observations", [])
            if not isinstance(raw_observations, list) or len(raw_observations) > 20:
                raw_observations = []
            observations = [{"state": "proposed_observation", **dict(value)}
                            for value in raw_observations if isinstance(value, Mapping)]
            metrics = {"input_tokens": int(proposal.get("input_tokens", 0)),
                       "output_tokens": int(proposal.get("output_tokens", 0))}
        if mode in {"dynamic_runtime", "manual_observation"}:
            status = "cannot_verify"
            gaps = [f"{mode} obligation requires separately authorized evidence"]
        elif admissible and contradictions:
            status = "cannot_verify"
            gaps = ["admissible evidence conflicts; disagreement preserved for adjudication"]
        elif contradictions:
            status = "not_satisfied"
            gaps = []
        elif admissible:
            status = "satisfied"
            gaps = []
        else:
            status = "cannot_verify"
            gaps = ["no admissible resolving evidence was supplied"]
        results.append({
            "row_id": package["row_id"], "package_id": package["package_id"], "status": status,
            "observations": observations, "evidence_used": [item["citation"] for item in admissible + contradictions],
            "gaps": gaps, "disagreements": ([{"kind": "evidence_conflict",
                "support_count": len(admissible), "refute_count": len(contradictions)}]
                if admissible and contradictions else []), "metrics": metrics,
        })
    return {"schema": "appsec-review/validator-batch-result/1", "batch_id": batch["batch_id"],
            "fingerprint": batch["fingerprint"], "terminal_state": "succeeded", "results": results,
            "metrics": {"model_calls": int(worker is not None), "retrieval_calls": retrieval_calls,
                        "input_tokens": sum(item["metrics"]["input_tokens"] for item in results),
                        "output_tokens": sum(item["metrics"]["output_tokens"] for item in results),
                        "cost_usd": None, "duration_ms": 0, "retries": 0}}


def verify_results(batch_results: Sequence[Mapping[str, Any]], *,
                   independent_reviews: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[dict[str, Any], ...]:
    reviews = independent_reviews or {}
    verified = []
    for batch in batch_results:
        for raw in batch.get("results", ()):
            result = dict(raw)
            for citation in result.get("evidence_used", ()):
                if not _citation_valid(citation):
                    raise ValueError("control result contains an unresolved evidence citation")
            accepted_observations = []
            for observation in result.get("observations", ()):
                severity = str(observation.get("severity", "")).lower()
                blocking = bool(observation.get("ship_blocking", False))
                elevated = severity in {"high", "critical"} or blocking
                review = reviews.get(str(observation.get("observation_id", "")))
                if elevated and (not review or review.get("disposition") != "confirmed" or
                                 not review.get("evidence_citations")):
                    accepted_observations.append({**observation, "state": "awaiting_independent_verification"})
                    result.setdefault("gaps", []).append(
                        "elevated or ship-blocking observation lacks independent verification")
                elif review and review.get("disposition") == "refuted":
                    accepted_observations.append({**observation, "state": "refuted",
                                                  "independent_review": dict(review)})
                elif review and review.get("disposition") == "confirmed":
                    accepted_observations.append({**observation, "state": "confirmed",
                                                  "independent_review": dict(review)})
                else:
                    accepted_observations.append(observation)
            result["observations"] = accepted_observations
            if result["status"] not in RESULT_STATUSES:
                raise ValueError("validator returned an unsupported control status")
            result["verification_status"] = (
                "verified" if not result.get("gaps") else "verified_with_gaps")
            verified.append(result)
    return tuple(sorted(verified, key=lambda item: item["row_id"]))


def deterministic_join(rows: Sequence[Mapping[str, Any]], verified_results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_row: dict[str, Mapping[str, Any]] = {}
    for result in verified_results:
        row_id = str(result["row_id"])
        if row_id in by_row:
            raise ValueError(f"duplicate control result: {row_id}")
        by_row[row_id] = result
    joined = []
    for row in rows:
        row_id = str(row["row_id"])
        dispatchable = row["outcome"] in {"applicable", "conditional"}
        result = by_row.pop(row_id, None)
        if dispatchable and result is None:
            raise ValueError(f"missing terminal control result: {row_id}")
        if not dispatchable and result is not None:
            raise ValueError(f"non-dispatch applicability row has a validator result: {row_id}")
        joined.append({
            "row_id": row_id, "control_identity": row["control_identity"],
            "component_id": row["component_id"], "applicability": row["outcome"],
            "control_status": result["status"] if result else "not_assessed",
            "verification_status": result.get("verification_status") if result else "not_required",
            "evidence_used": result.get("evidence_used", []) if result else row["evidence"],
            "observations": result.get("observations", []) if result else [],
            "disagreements": result.get("disagreements", []) if result else [],
            "gaps": list(row.get("gaps", ())) + (list(result.get("gaps", ())) if result else []),
        })
    if by_row:
        raise ValueError(f"validator returned results outside selection: {sorted(by_row)}")
    identity = _hash(joined)
    return {"schema": "appsec-review/control-result-set/1", "result_set_id": identity,
            "results": joined, "accounting": {"selected": len(rows), "joined": len(joined),
            "exactly_once": len({item["row_id"] for item in joined}) == len(rows)}}


def fingerprint_inputs(*, standards: Mapping[str, Any], selection: Mapping[str, Any],
                       classifications: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]],
                       batches: Sequence[Mapping[str, Any]], retrieval_manifest: Mapping[str, Any],
                       configuration_sha256: str, guidance_bundle_sha256: str,
                       model_identity: Mapping[str, Any], parser_versions: Mapping[str, str]) -> dict[str, Any]:
    component_values = {}
    for component in classifications:
        component_id = str(component["component_id"])
        component_rows = [row["applicability_fingerprint"] for row in rows
                          if row["component_id"] == component_id]
        component_batches = [batch["fingerprint"] for batch in batches
                             if component_id in batch["component_ids"]]
        component_values[component_id] = {
            "classification": component["classification_fingerprint"],
            "applicability": _hash(component_rows),
            "validation_work": _hash(component_batches),
        }
    global_inputs = {
        "standards": standards.get("fingerprint"),
        "selection": selection.get("selection_fingerprint"),
        "retrieval_manifest": dict(retrieval_manifest),
        "configuration_sha256": configuration_sha256,
        "guidance_bundle_sha256": guidance_bundle_sha256,
        "model_identity": dict(model_identity), "parser_versions": dict(parser_versions),
    }
    return {"schema": "appsec-review/workbench-fingerprints/1",
            "global": _hash(global_inputs), "global_inputs": global_inputs,
            "components": component_values}
