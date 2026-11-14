from __future__ import annotations

from collections import defaultdict
import hashlib
from pathlib import PurePosixPath
import re
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


CLASSIFICATION_SCHEMA = "appsec-review/component-classification/2"
# T-5008: the control family a target class admits. A component without the class gets every selected
# control of the family as not_applicable, citing the class assignment; no batch is dispatched for it.
FAMILY_TARGET_CLASSES = {"ASVS": "target:web-api", "MASVS": "target:mobile"}
# Collation facets and classes (docs/architecture/collation-pass.md) to the control roles the catalogs
# name. The workbench keeps no classifier of its own: a role exists only when a tag establishes it.
FACET_COMPONENT_ROLES: Mapping[str, tuple[str, ...]] = {
    "role:auth": ("authentication_identity",), "role:session": ("authentication_identity",),
    "role:authorization": ("authentication_identity",),
    "role:storage": ("storage",), "state:persistent-store": ("storage",),
    "role:crypto": ("cryptography_data_protection",), "asset:keys": ("cryptography_data_protection",),
    "asset:credentials": ("cryptography_data_protection",),
    "mechanism:http": ("application_api_server", "network"), "mechanism:rpc": ("application_api_server", "network"),
    "mechanism:networked-listener": ("network",), "target:web-api": ("application_api_server",),
    "component:android-mobile": ("android_mobile",), "component:ios-mobile": ("ios_mobile",),
    "role:build-glue": ("build_supply_chain",), "exposure:build-time": ("build_supply_chain",),
    "target:build-tooling": ("build_supply_chain",),
    "role:test": ("test_development_only",), "target:test-only": ("test_development_only",),
}
_TAG = re.compile(r"^[a-z][a-z0-9-]*(?::[a-z0-9][a-z0-9.-]*){1,3}$")
_ROUTING_BASES = frozenset({"declared", "invoked", "derived", "reported"})
_FACET_NAMESPACES = frozenset({"role", "exposure", "trust", "mechanism", "asset", "state"})


def _routing_tag(record: Any) -> tuple[str, str] | None:
    """``(tag, basis)`` of one accepted routing record, or None when it establishes nothing.

    The entity ``name`` carries the tag: the index sanitizer redacts payload strings that look like
    secrets (``asset:credentials``). Only a grammatical tag with a recorded basis counts.
    """
    if not isinstance(record, Mapping) or not isinstance(record.get("basis"), str) \
            or record["basis"] not in _ROUTING_BASES:
        return None
    for key in ("name", "tag"):
        value = record.get(key)
        if isinstance(value, str) and _TAG.match(value):
            return value, str(record["basis"])
    return None


def classify_components(
    components: Sequence[Mapping[str, Any]], *,
    max_components: int = 128,
    assessment_mode: str = "qualification",
) -> tuple[dict[str, Any], ...]:
    """Read each component's target class and control roles from its accepted collation tags.

    No target tree is read and nothing is inferred: ``target:*`` and facet assignments of the tags
    index (``routing_context``) are the only source, each cited by identity and assignment id. A
    component without a target class is ``low`` confidence and records the gap; it never guesses.
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
        if not citations or any(not (
                value.get("schema") == "appsec-review/owasp-evidence-reference/1"
                if assessment_mode == "assessment" else _citation_valid(value)) for value in citations):
            raise ValueError(f"component {component_id} lacks resolving evidence citations")
        routing = list(raw.get("routing_context", ()))
        tag_citations: list[dict[str, Any]] = []
        tags: dict[str, str] = {}
        for record in routing:
            parsed = _routing_tag(record)
            if parsed is None:
                continue
            tag, basis = parsed
            namespace = tag.split(":", 1)[0]
            if namespace == "target" and basis != "derived":
                continue  # a class is only ever derived by collation
            if namespace not in _FACET_NAMESPACES and namespace != "target" and tag not in FACET_COMPONENT_ROLES:
                continue
            tags.setdefault(tag, basis)
            tag_citations.append({"tag": tag, "basis": basis, "identity": record.get("identity"),
                                  "assignment_id": (record.get("subject") or {}).get("assignment_id")
                                  if isinstance(record.get("subject"), Mapping) else None,
                                  "usage": "routing_only"})
        target_classes = sorted(tag for tag in tags if tag.startswith("target:"))
        facets = sorted(tag for tag in tags if tag.split(":", 1)[0] in _FACET_NAMESPACES)
        roles: set[str] = set()
        reasons: list[str] = []
        for tag in sorted(tags):
            mapped = FACET_COMPONENT_ROLES.get(tag)
            if mapped:
                roles.update(mapped)
                reasons.append(f"accepted {tags[tag]} tag {tag} routes the roles {', '.join(mapped)}; "
                               "it is not control proof or deployment evidence")
        if "target:mobile" in tags and not roles & MOBILE_ROLES:
            roles.update(MOBILE_ROLES)
            reasons.append("target:mobile without a platform tag routes both mobile roles; the platform is unknown")
        gaps = ([] if target_classes else
                ["collation assigned no target class to this component; applicability cannot be determined"])
        result = {
            "schema": CLASSIFICATION_SCHEMA,
            "target_id": str(raw.get("target_id", "target")),
            "project_id": project_id,
            "component_id": component_id,
            "target_classes": target_classes,
            "facets": facets,
            "roles": sorted(roles),
            "confidence": "high" if target_classes else "low",
            "reasons": reasons,
            "tag_citations": sorted(tag_citations, key=lambda item: (item["tag"], str(item["identity"]))),
            "evidence": citations,
            "assessment_mode": assessment_mode,
            "routing_context": routing,
            "evidence_fingerprint": raw.get("evidence_fingerprint"),
            "limitations": list(raw.get("limitations", ())),
            "ambiguity": list(gaps),
            "negative_evidence_limits": [
                "absence from accepted bounded indexes is not evidence that a role or class is absent"
            ],
            "gaps": gaps,
            "input_fingerprint": _hash(raw),
        }
        if assessment_mode == "assessment":
            from .assessment import _semantic
            result["input_fingerprint"] = _hash(_semantic(raw))
            result["classification_fingerprint"] = _hash(_semantic(result))
        else:
            result["classification_fingerprint"] = _hash(result)
        results.append(result)
    return tuple(sorted(results, key=lambda item: (item["project_id"], item["component_id"])))


def target_class_ledger(classifications: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]
                        ) -> dict[str, Any]:
    """``target-class-ledger/1``: per component and control family, whether the class admits the family.

    A ``not_applicable`` verdict here is a result of positive class evidence, not a gap; the row
    outcomes it summarises carry the same citations.
    """
    entries = []
    for component in classifications:
        cid = component["component_id"]
        for family, required in sorted(FAMILY_TARGET_CLASSES.items()):
            family_rows = [row for row in rows if row["component_id"] == cid and row["standard"] == family]
            outcomes: dict[str, int] = {}
            for row in family_rows:
                outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
            classes = list(component.get("target_classes", ()))
            entries.append({
                "component_id": cid, "family": family, "required_class": required, "target_classes": classes,
                "verdict": ("applicable" if required in classes else
                            "not_applicable" if classes else "cannot_determine"),
                "outcomes": dict(sorted(outcomes.items())), "selected_controls": len(family_rows),
                "citations": [item for item in component.get("tag_citations", ()) if item["tag"].startswith("target:")],
            })
    return {"schema": "appsec-review/target-class-ledger/1", "rule": "target-class-gate/1", "entries": entries}


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
                        dynamic_authorized: bool = False,
                        assessment_mode: str = "qualification") -> tuple[dict[str, Any], ...]:
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
            classes = set(component.get("target_classes", ()))
            required_class = FAMILY_TARGET_CLASSES.get(family)
            class_citations = [item for item in component.get("tag_citations", ())
                               if str(item.get("tag", "")).startswith("target:")]
            gated = True
            if not classes:
                outcome = "cannot_determine"
                reason = "component target class is unresolved: collation assigned no target tag"
                gaps = ["target class unresolved; no control of this component is dispatched"]
            elif required_class is not None and required_class not in classes:
                outcome = "not_applicable"
                reason = (f"component target class {', '.join(sorted(classes))} excludes {family}: "
                          f"{required_class} is required; basis "
                          + ", ".join(str(item.get("assignment_id") or item.get("identity")) for item in class_citations))
                gaps = []
            elif component.get("confidence") == "low" or not roles:
                gated = False
                outcome = "cannot_determine"
                reason = "component purpose/trust role is unresolved"
                gaps = ["bounded component classification did not resolve applicability"]
            elif not family_match:
                gated = False
                outcome = "not_applicable"
                reason = (f"positive classification evidence identifies roles outside the {family} routing boundary: "
                          + ", ".join(sorted(roles)))
                gaps = []
            elif not matched:
                gated = False
                outcome = "not_applicable"
                reason = ("positive classification evidence identifies no role named by this control: "
                          + ", ".join(sorted(roles)))
                gaps = []
            elif control.get("evidence_mode") in {"dynamic_runtime", "manual_observation"} and not dynamic_authorized:
                gated = False
                outcome = "unsupported_missing_evidence"
                reason = "the selected control requires separately authorized dynamic/runtime or manual evidence"
                gaps = ["required dynamic/runtime or manual evidence is not authorized"]
            else:
                gated = False
                outcome = "applicable"
                reason = "component roles and selected control routing rules intersect"
                gaps = []
            if assessment_mode == "assessment" and not gated:
                from .obligations import procedure_for
                rule = procedure_for(control)
                # Routing uncertainty is not positive N/A evidence. A concrete accepted source
                # subject can still be assessed conditionally without inventing a component role.
                if outcome == "not_applicable" and not family_match and family == "MASVS" and roles & APPLICATION_ROLES:
                    pass
                elif rule is None:
                    outcome = "unsupported_missing_evidence"
                    reason = "no reviewed versioned proof procedure for this selected control"
                    gaps = [reason]
                elif rule.evidence_mode in {"dynamic_runtime", "manual_observation"}:
                    outcome = "unsupported_missing_evidence"
                    reason = "no accepted environment-bound runtime/manual evidence adapter is available"
                    gaps = [reason]
                else:
                    outcome = "applicable" if roles else "conditional"
                    reason = "assess only named accepted source subjects; classification is routing context"
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
                "target_classes": sorted(classes), "target_class_citations": class_citations,
                "assessment_mode": assessment_mode,
                "rule_version": "applicability-rules/2",
            }
            if outcome not in APPLICABILITY_OUTCOMES:
                raise AssertionError("invalid applicability outcome")
            if assessment_mode == "assessment":
                from .assessment import _semantic
                row["applicability_fingerprint"] = _hash(_semantic(row))
            else:
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
                           retrieval_manifest: Mapping[str, Any],
                           assessment_mode: str = "qualification",
                           max_subjects: int = 8, max_evidence: int = 200) -> tuple[dict[str, Any], ...]:
    if type(max_evidence) is not int or not 1 <= max_evidence <= 200:
        raise ValueError("package evidence bound must be between 1 and 200")
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
        omitted = max(0, len(observations) - max_evidence)
        observations = observations[:max_evidence]
        package = {
            "schema": "appsec-review/finding-package/1",
            "row_id": row_id, "batch_id": batch["batch_id"],
            "standard": row["standard"], "version": row["version"], "profile": row["profile"],
            "control": {"identity": row["control_identity"], "id": row["control_id"],
                        "family": row["standard"], "version": row["version"],
                        "title": control["title"], "text": control["text"]},
            "component": {"target_id": row["target_id"], "project_id": row["project_id"],
                          "component_id": row["component_id"], "roles": component["roles"],
                          "evidence": component["evidence"]},
            "evidence_references": observations,
            "allowed_retrieval_tools": sorted(set(batch["required_tools"]) |
                                              {"find", "read_excerpt", "resolve_evidence"}),
            "retrieval_manifest": dict(retrieval_manifest),
            "assessment_mode": assessment_mode,
            "routing_context": component.get("routing_context", []),
            "proof_obligations": [{"obligation_id": f"{row_id}:primary",
                                   "evidence_mode": row["evidence_mode"],
                                   "required_tools": row["required_tools"]}],
            "prohibited_claims": ["compliance certification", "uncited vulnerability",
                                  "severity without independent validation", "runtime state from static evidence"],
        }
        if assessment_mode == "assessment":
            from .obligations import instantiate
            package["proof_obligations"] = instantiate(control, row, observations, max_subjects=max_subjects)
            package["limitations"] = [
                *component.get("limitations", []),
                "Assessment covers named source subjects, not the entire component or deployed system.",
            ]
        if omitted:
            package.setdefault("limitations", []).append(
                f"package evidence bound omitted {omitted} accepted records; no obligations use omitted evidence")
        package["package_id"] = f"package-{_hash(package)[:24]}"
        packages.append(package)
    return tuple(packages)


def assess_batch(batch: Mapping[str, Any], packages: Sequence[Mapping[str, Any]], *,
                 worker: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
                 fail: bool = False, assessment_mode: str = "qualification") -> dict[str, Any]:
    if assessment_mode == "assessment" and not fail:
        if worker is None:
            raise ValueError("assessment mode requires a wired inference worker")
        return dict(worker({"batch": batch, "packages": packages}))
    if assessment_mode not in {"assessment", "qualification"}:
        raise ValueError("unknown OWASP assessment mode")
    if fail:
        return {"schema": "appsec-review/validator-batch-result/1", "batch_id": batch["batch_id"],
                "fingerprint": batch["fingerprint"], "terminal_state": "failed",
                "results": [{"row_id": package["row_id"], "status": "not_assessed",
                             "observations": [], "evidence_used": [],
                             "gaps": ["validator worker failed; successful sibling batches remain valid"],
                             "assessment_mode": assessment_mode, "lead_eligible": False,
                             "execution_completion": "failed", "verification_status": "pending",
                             "coverage_completeness": "unresolved",
                             "disagreements": []} for package in packages],
                "metrics": {"model_calls": 0, "retrieval_calls": 0, "input_tokens": None,
                            "output_tokens": None, "cost_usd": None, "duration_ms": 0, "retries": 0}}
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
            "assessment_mode": "qualification", "lead_eligible": False,
            "execution_completion": "qualification_completed",
            "coverage_completeness": "fixture_only", "verification_status": "qualification_only",
            "observations": observations, "evidence_used": [item["citation"] for item in admissible + contradictions],
            "gaps": gaps, "disagreements": ([{"kind": "evidence_conflict",
                "support_count": len(admissible), "refute_count": len(contradictions)}]
                if admissible and contradictions else []), "metrics": metrics,
        })
    return {"schema": "appsec-review/validator-batch-result/1", "batch_id": batch["batch_id"],
            "fingerprint": batch["fingerprint"], "terminal_state": "succeeded", "results": results,
            "metrics": {"model_calls": 0, "retrieval_calls": retrieval_calls,
                        "input_tokens": None, "output_tokens": None,
                        "cost_usd": None, "duration_ms": 0, "retries": 0}}


def verify_results(batch_results: Sequence[Mapping[str, Any]], *,
                   independent_reviews: Mapping[str, Mapping[str, Any]] | None = None,
                   assessment_mode: str = "qualification",
                   reviewer: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None) -> tuple[dict[str, Any], ...]:
    if assessment_mode == "assessment":
        if reviewer is None:
            raise ValueError("assessment mode requires a wired independent reviewer")
        reviewed = [dict(reviewer(batch)) for batch in batch_results]
        return tuple(sorted((dict(result) for batch in reviewed for result in batch["results"]),
                            key=lambda item: item["row_id"]))
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
                "qualification_only")
            result["assessment_mode"] = "qualification"
            result["lead_eligible"] = False
            result["observations"] = [{**item, "state": "qualification_only"} for item in accepted_observations]
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
            "target_snapshot": row["target_id"], "project_id": row["project_id"],
            "standard": row["standard"], "version": row["version"], "profile": row["profile"],
            "assessment_mode": row.get("assessment_mode", "qualification"),
            "execution_completion": result.get("execution_completion", "completed") if result else "not_dispatched",
            "worker_attempt_count": result.get("worker_attempt_count", 0) if result else 0,
            "reviewer_attempt_count": result.get("reviewer_attempt_count", 0) if result else 0,
            "coverage_completeness": result.get("coverage_completeness", "unresolved") if result else
                                     "not_applicable" if row["outcome"] == "not_applicable" else "unresolved",
            "control_status": result["status"] if result else "not_assessed",
            "verification_status": result.get("verification_status") if result else "not_required",
            "evidence_used": result.get("evidence_used", []) if result else row["evidence"],
            "observations": result.get("observations", []) if result else [],
            "obligations": result.get("obligations", []) if result else [],
            "lead_eligible": bool(result and result.get("lead_eligible")
                                  and row.get("assessment_mode") == "assessment"),
            "disagreements": result.get("disagreements", []) if result else [],
            "gaps": list(row.get("gaps", ())) + (list(result.get("gaps", ())) if result else []),
            "limitations": list(result.get("limitations", ())) if result else [],
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
