"""Verify optional producers once and freeze sanitized, hash-bound publication projections."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from appsec_review.applicability import ProcessingDisposition as Disposition
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs import completion_contracts as contracts
from appsec_review.jobs.engineering_contracts import POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation.candidates import read_candidates
from appsec_review.review.models import IntegrityError

PRODUCERS = {
    "poc_generation": ("job_poc_generation", POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA,
                       "publish.publish_handoff"),
    "remediation_planning": (contracts.REMEDIATION_PLANNING_JOB, contracts.REMEDIATION_PLANNING_HANDOFF_SCHEMA,
                             contracts.REMEDIATION_PLANNING_SCHEMA, "acceptance.publish_handoff"),
    "remediation_validation": (contracts.REMEDIATION_VALIDATION_JOB, contracts.REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
                               contracts.REMEDIATION_VALIDATION_SUMMARY_SCHEMA, "acceptance.publish_handoff"),
    "dossiers": (contracts.DOSSIER_PUBLICATION_JOB, contracts.DOSSIER_PUBLICATION_HANDOFF_SCHEMA,
                  contracts.DOSSIER_PUBLICATION_SCHEMA, "acceptance.publish_handoff"),
}
STATUSES = {
    "remediation_planning": {"proposal_generated", "manual_design_required", "insufficient_evidence",
                             "capped"},
    "remediation_validation": {item.value for item in contracts.RemediationValidationStatus},
}
GAPPED = {"compile_failed", "artifact_generated", "policy_denied", "insufficient_evidence", "unsafe_to_attempt",
          "manual_design_required", "rejected", "inconclusive", "manual_validation_required", "capped",
          "render_failed", "latex_only"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityError(message)


def reference(value: Any) -> dict[str, str]:
    require(isinstance(value, Mapping) and set(value) >= {"path", "sha256"}, "attachment reference is malformed")
    return {"path": value["path"], "sha256": value["sha256"]}


def bind_tree(run_root: Path, value: Any, bindings: list[dict[str, str]]) -> None:
    """Rehash every reference, including nested receipts, patches and diagnostic artifacts."""
    if isinstance(value, Mapping):
        if {"path", "sha256"} <= set(value):
            ref = reference(value)
            resolve_bound(run_root, ref)
            bindings.append(ref)
        for item in value.values():
            bind_tree(run_root, item, bindings)
    elif isinstance(value, list):
        for item in value:
            bind_tree(run_root, item, bindings)


def capability(enabled: bool, *, handoff: dict[str, str] | None = None,
               summary: dict[str, str] | None = None, count: int = 0, omitted: int = 0,
               gaps: int = 0) -> dict[str, Any]:
    disposition = (Disposition.SKIPPED_POLICY if not enabled else Disposition.GAP if summary is None or gaps or omitted
                   else Disposition.SKIPPED_NA if not count else Disposition.SUCCEEDED)
    reason = {
        Disposition.SKIPPED_POLICY: "Disabled by the run's frozen configuration; no discovered artifacts were admitted.",
        Disposition.GAP: "Expected work is missing, failed, capped or has explicitly recorded gaps.",
        Disposition.SKIPPED_NA: "The accepted producer accounted for an empty eligible scope; this is not clean coverage.",
        Disposition.SUCCEEDED: "Accepted outcomes and all artifact bindings were verified; no runtime proof is implied.",
    }[disposition]
    return {"enabled": enabled, "disposition": disposition.value, "reason": reason, "handoff": handoff,
            "summary": summary, "item_count": count, "omitted_count": omitted, "gap_count": gaps,
            **contracts.nonexecution_assurance()}


def _finding(binding: Any, findings: Mapping[str, Mapping[str, Any]], *, confirmed: bool = False) -> dict[str, str]:
    parsed = contracts.FindingBinding.from_mapping(binding)
    finding = findings.get(parsed.finding_package_id)
    require(finding is not None and finding["claim_id"] == parsed.claim_id and finding["sha256"] == parsed.sha256,
            "attachment belongs to a different finding or review")
    require(not confirmed or finding["state"] == "confirmed", "remediation requires a confirmed finding")
    return parsed.as_dict()


def _poc(run_root: Path, document: Mapping[str, Any], review: Mapping[str, Any], schemas: SchemaSet,
         bindings: list[dict[str, str]]) -> tuple[list[dict[str, Any]], int]:
    errors = schemas.errors("poc-generation", document)
    require(not errors, "PoC summary does not satisfy its schema: " + "; ".join(errors[:3]))
    contracts.verify_nonexecution_assurance({key: document[key] for key in contracts.nonexecution_assurance()})
    require(document["upstream"]["manifest"]["sha256"] == review["review"]["accepted_manifest_sha256"],
            "PoC summary belongs to another accepted manifest")
    language_sha = document["upstream"]["language_build_handoff_sha256"]
    if language_sha is not None:
        accepted = accepted_handoff(run_root, "job_language_build")
        require(accepted is not None and accepted.sha256 == language_sha,
                "PoC language-build handoff differs from its accepted input")
        bindings.append({"path": accepted.path, "sha256": accepted.sha256})
    source = read_bound_json(run_root, review["inputs"]["review_handoff"])
    candidates = read_candidates(source)
    require(candidates is not None, "accepted review has no supported PoC candidate contract")
    expected = {item.claim_id: item for item in candidates}
    rows = document["candidates"]
    claims = [row["claim_id"] for row in rows]
    omitted = document["omitted_claims"]
    require(len(set(claims + omitted)) == len(claims + omitted) and set(claims + omitted) == set(expected),
            "PoC candidates and explicitly omitted claims do not exactly account for the review candidates")
    counts = document["counts"]
    require(counts["candidates"] == len(rows) and counts["omitted"] == len(omitted) and
            {key: value for key, value in counts["by_status"].items() if value} == dict(Counter(row["status"] for row in rows)),
            "PoC candidate status accounting is not exact")
    projected = []
    for row in rows:
        candidate = expected[row["claim_id"]]
        require(row["finding_package"] == {"finding_package_id": candidate.finding_package_id,
                                           "sha256": candidate.finding_package_sha256} and
                row["state"] == candidate.state and row["judge_verdict"] == candidate.judge_verdict and
                row["poc_basis_sha256"] == candidate.poc_basis.sha256 and row["package_id"] == candidate.package_id,
                "PoC outcome disagrees with its accepted candidate")
        contracts.verify_nonexecution_assurance({key: row[key] for key in contracts.nonexecution_assurance()})
        if row["files"]:
            provenance = read_bound_json(run_root, row["files"]["provenance"])
            errors = schemas.errors("provenance", provenance)
            require(not errors, "PoC provenance does not satisfy its schema")
            contracts.verify_nonexecution_assurance({key: provenance[key] for key in contracts.nonexecution_assurance()})
            require(provenance["run_id"] == document["run_id"] and
                    provenance["claim_id"] == row["claim_id"] and
                    provenance["finding_package"] == row["finding_package"] and
                    provenance["upstream"] == document["upstream"] and provenance["status"] == row["status"] and
                    provenance["source_sha256"] == row["files"]["source"]["sha256"] and
                    provenance["poc_basis_sha256"] == row["poc_basis_sha256"] and
                    provenance["brief_sha256"] == (row["brief"] or {}).get("sha256") and
                    provenance["writer_receipt_sha256"] == (row["writer_receipt"] or {}).get("sha256") and
                    provenance["settings_sha256"] == document["settings_sha256"],
                    "PoC provenance disagrees with its summary")
            compile_record = read_bound_json(run_root, row["files"]["compile"])
            require(not schemas.errors("compile-record", compile_record) and
                    compile_record["status"] == row["status"] and compile_record["claim_id"] == row["claim_id"],
                    "PoC compile receipt disagrees with its outcome")
        require(row["status"] != "compile_verified" or row["files"] is not None,
                "compile_verified PoC has no compile artifacts")
        bind_tree(run_root, row, bindings)
        projected.append({
            "claim_id": row["claim_id"], "finding_package_id": candidate.finding_package_id,
            "status": row["status"], "description": f"Compile-only PoC outcome: {row['status']}. Nothing was executed.",
            "functions": ({key: row["functions"][key] for key in ("test_function", "negative_control")}
                          if row["functions"] else None),
            "files": row["files"], **contracts.nonexecution_assurance()})
    return sorted(projected, key=lambda row: row["claim_id"]), len(omitted)


def _remediation(run_root: Path, name: str, document: Mapping[str, Any], findings: Mapping[str, Mapping[str, Any]],
                 bindings: list[dict[str, str]], schemas: SchemaSet,
                 plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    key = "plan" if name == "remediation_planning" else "validation"
    expected_schema = contracts.REMEDIATION_PLAN_SCHEMA if key == "plan" else contracts.REMEDIATION_VALIDATION_SCHEMA
    result = []
    for row in document["items"]:
        finding = _finding(row["finding"], findings, confirmed=True)
        require(row["status"] in STATUSES[name], f"unsupported {name} status")
        ref = row[key]
        if ref is not None:
            artifact = read_bound_json(run_root, ref)
            require(not schemas.errors(key, artifact), f"{key} artifact does not satisfy its schema")
            require(artifact.get("schema") == expected_schema and artifact.get("run_id") == document["run_id"]
                    and artifact.get("finding") == finding
                    and artifact.get("adjudication_id") == findings[finding["finding_package_id"]]["adjudication_id"],
                    f"{key} artifact has mismatched identity")
            contracts.verify_nonexecution_assurance(artifact["assurance"])
            require(artifact.get("status") == row["status"] and artifact.get("upstream") == document["upstream"]
                    and artifact["reason"] == row["reason"],
                    f"{key} artifact status or upstream identity disagrees with summary")
            if key == "validation":
                plan = next((item["plan"] for item in plans if item["finding"] == finding), None)
                require(plan is not None and artifact["plan"] == plan,
                        "validation artifact consumes another finding's plan")
                accepted_plan = read_bound_json(run_root, plan)
                require(artifact["patch"] == accepted_plan["patch"], "validation patch differs from accepted plan")
                require(artifact["checks"]["runtime_regression"]["status"] == "not_performed_by_policy",
                        "validation cannot assert runtime regression execution")
            bind_tree(run_root, artifact, bindings)
        require(row["status"] not in {"proposal_generated", "build_checked", "static_checked"} or ref is not None,
                f"successful {key} has no artifact")
        bind_tree(run_root, row, bindings)
        result.append({"finding": finding, "status": row["status"], key: ref,
                       "gap_ids": list(row["gap_ids"]), **contracts.nonexecution_assurance()})
    ids = [row["finding"]["finding_package_id"] for row in result]
    require(len(ids) == len(set(ids)) and set(ids) == {
        identity for identity, finding in findings.items() if finding["state"] == "confirmed"},
        f"{name} does not exactly account for the confirmed finding intake")
    return sorted(result, key=lambda row: row["finding"]["finding_package_id"])


def _dossiers(run_root: Path, document: Mapping[str, Any], findings: Mapping[str, Mapping[str, Any]],
               poc: list[dict[str, Any]], bindings: list[dict[str, str]]) -> list[dict[str, Any]]:
    from appsec_review.jobs.job_dossier_publication.job import verify_publication
    verify_publication(run_root, document)
    expected = {("confirmed_finding", row["claim_id"]) for row in findings.values() if row["state"] == "confirmed"}
    expected |= {("poc", row["claim_id"]) for row in poc}
    require(len(document["items"]) == min(len(expected), document["caps"]["max_dossiers"]),
            "dossier cap does not exactly partition admitted candidates")
    seen = set()
    ids = set()
    result = []
    for row in document["items"]:
        finding = _finding(row["finding"], findings, confirmed=row["kind"] == "confirmed_finding")
        key = (row["kind"], finding["claim_id"])
        require(key in expected and key not in seen and row["dossier_id"] not in ids, "dossier accounting is not exact")
        seen.add(key)
        ids.add(row["dossier_id"])
        files = row["files"]
        require(set(files) == {"json", "latex", "pdf", "receipt"} and
                all(files[key] is not None for key in ("json", "latex", "receipt")), "dossier files are incomplete")
        dossier = read_bound_json(run_root, files["json"])
        require(dossier.get("schema") == contracts.DOSSIER_SCHEMA and dossier.get("run_id") == document["run_id"]
                and dossier.get("finding") == finding and dossier.get("dossier_id") == row["dossier_id"],
                "dossier artifact identity disagrees with its manifest")
        receipt = read_bound_json(run_root, files["receipt"])
        bind_tree(run_root, receipt, bindings)
        bind_tree(run_root, files, bindings)
        result.append({"dossier_id": row["dossier_id"], "kind": row["kind"], "finding": finding,
                       "status": row["status"], "files": files, "gap_ids": list(row["gap_ids"])})
    omitted = document["omitted"]
    for row in omitted:
        finding = _finding(row["finding"], findings, confirmed=row["kind"] == "confirmed_finding")
        key = (row["kind"], finding["claim_id"])
        require(key in expected and key not in seen and row["reason"] == "max_dossiers",
                "dossier omitted work is not exactly accounted")
        seen.add(key)
    require(seen == expected, "dossier manifest does not exactly account for confirmed findings and PoC outcomes")
    return sorted(result, key=lambda row: row["dossier_id"])


def verify_attachments(run_root: Path, review: Mapping[str, Any], *, repository_root: Path,
                       enabled: Mapping[str, bool]) -> dict[str, Any]:
    """All optional evidence accepted at gate load, never discovered during report assembly."""
    capabilities = {}
    attachments: dict[str, list[dict[str, Any]]] = {name: [] for name in (*PRODUCERS, "attack_chains")}
    bindings = list(review["bindings"])
    findings = {row["finding_package_id"]: row for row in review["packages"]}
    handoffs: dict[str, dict[str, str]] = {}
    for name, (job, handoff_schema, schema, unit) in PRODUCERS.items():
        if not enabled.get(name, False):
            capabilities[name] = capability(False)
            continue
        try:
            accepted = accepted_handoff(run_root, job)
        except ValueError as exc:
            raise IntegrityError(f"accepted {job} handoff cannot be verified: {exc}") from exc
        if accepted is None:
            capabilities[name] = capability(True)
            continue
        published = (accepted.handoff.get("outputs") or {}).get(unit)
        require(accepted.handoff.get("job_id") == job and isinstance(published, Mapping) and
                published.get("schema") == handoff_schema, f"unsupported {job} handoff")
        summary_ref = reference(published["artifact"])
        document = read_bound_json(run_root, summary_ref)
        require(document.get("schema") == schema and document.get("run_id") == review["run_id"],
                f"{job} summary schema or run identity is unsupported")
        remediation_schemas = SchemaSet(repository_root / "docs" / "schemas" / "remediation")
        if name in STATUSES:
            summary_name = "planning" if name == "remediation_planning" else "validations"
            require(not remediation_schemas.errors(summary_name, document),
                    f"{job} summary does not satisfy its schema")
        require(isinstance(document.get("gaps"), list) and isinstance(document.get("upstream"), Mapping) and
                document["upstream"].get("review_handoff") == review["inputs"]["review_handoff"],
                f"{job} summary belongs to a different accepted review")
        upstream_keys = (("poc_handoff", "poc_generation"), ("planning_handoff", "remediation_planning"),
                         ("remediation_planning_handoff", "remediation_planning"),
                         ("remediation_validation_handoff", "remediation_validation"))
        for upstream_name, capability_name in upstream_keys:
            if upstream_name in document["upstream"] and (name == "dossiers" or
                                                          document["upstream"][upstream_name] is not None):
                require(document["upstream"][upstream_name] == handoffs.get(capability_name),
                        f"{job} consumes a stale or unadmitted optional producer")
        if name == "remediation_validation":
            require(document["upstream"].get("planning_handoff") == handoffs.get("remediation_planning")
                    and handoffs.get("remediation_planning") is not None,
                    "validation summary has no accepted planning handoff")
        if name == "poc_generation":
            require(document["upstream"].get("review_job_handoff") == review["inputs"]["job_handoff"],
                    "PoC summary belongs to another accepted review job")
        bind_tree(run_root, document["upstream"], bindings)
        rows = document["candidates"] if name == "poc_generation" else document["items"]
        require(isinstance(rows, list) and published.get("item_count") == len(rows) and
                published.get("gaps") == document["gaps"] and
                published.get("terminal_status") in {"SUCCEEDED", "COMPLETED_WITH_GAPS"},
                f"{job} summary disagrees with its accepted envelope")
        omitted = 0
        if name == "poc_generation":
            projected, omitted = _poc(run_root, document, review,
                                     SchemaSet(repository_root / "docs" / "schemas" / "poc-generation"), bindings)
        elif name == "dossiers":
            projected = _dossiers(run_root, document, findings, attachments["poc_generation"], bindings)
            omitted = len(document["omitted"])
        else:
            projected = _remediation(run_root, name, document, findings, bindings, remediation_schemas,
                                    attachments["remediation_planning"])
        attachments[name] = projected
        handoff_ref = {"path": accepted.path, "sha256": accepted.sha256}
        bindings.extend((handoff_ref, summary_ref))
        handoffs[name] = handoff_ref
        gap_count = max(len(document["gaps"]), sum(
            row["status"] in GAPPED or bool(row.get("gap_ids")) for row in rows),
            int(published["terminal_status"] == "COMPLETED_WITH_GAPS"))
        capabilities[name] = capability(True, handoff=handoff_ref, summary=summary_ref,
                                        count=len(rows), omitted=omitted, gaps=gap_count)
    # Chain manifests are produced and bound inside the accepted review, never discovered as a job.
    source = read_bound_json(run_root, review["inputs"]["review_handoff"])
    chain_ref = source.get("attack_chain_manifest")
    capabilities["attack_chains"] = capability(enabled.get("attack_chains", False))
    if chain_ref is not None:
        manifest = read_bound_json(run_root, chain_ref)
        chain_schemas = SchemaSet(repository_root / "docs" / "schemas" / "inference-security-review")
        require(not chain_schemas.errors("attack-chain-manifest", manifest),
                "attack chain manifest does not satisfy its schema")
        require(manifest.get("schema") == contracts.ATTACK_CHAIN_MANIFEST_SCHEMA and
                manifest.get("run_id") == review["run_id"], "attack chain manifest identity is unsupported")
        accounting = manifest["accounting"]
        rows = manifest["items"]
        require(accounting["admitted"] == len(rows) == accounting["assessed"] + accounting["capped"] and
                accounting["proposed"] == accounting["admitted"] + accounting["rejected"] + accounting["deduplicated"],
                "attack chain candidate accounting is not exact")
        require(Counter(row["disposition"] for row in rows) ==
                Counter({key: value for key, value in (("assessed", accounting["assessed"]),
                                                       ("capped", accounting["capped"])) if value}),
                "attack chain dispositions disagree with accounting")
        claim_ids = {row["claim_id"] for row in findings.values()}
        exploration = manifest["exploration"]
        require(exploration["expanded"] <= exploration["limit"] and all(
            item["from_claim_id"] in claim_ids and item["to_claim_id"] in claim_ids
            for item in exploration["frontier"]), "attack chain exploration is unbounded or belongs to another review")
        identities = set()
        projected = []
        for row in rows:
            require(row["chain_id"] not in identities and set(row["component_claim_ids"]) <= claim_ids and
                    len(row["component_claim_ids"]) >= 2, "attack chain components or identity are inconsistent")
            identities.add(row["chain_id"])
            artifact = read_bound_json(run_root, row["artifact"])
            require(not chain_schemas.errors("attack-chain", artifact),
                    "attack chain artifact does not satisfy its schema")
            require(artifact.get("schema") == contracts.ATTACK_CHAIN_SCHEMA and artifact.get("run_id") == review["run_id"]
                    and artifact["proposal"]["chain_id"] == row["chain_id"] and artifact["status"] == row["status"]
                    and artifact["limitations"] == row["limitations"]
                    and [item["claim_id"] for item in artifact["proposal"]["components"]] == row["component_claim_ids"],
                    "attack chain artifact disagrees with manifest")
            bind_tree(run_root, artifact, bindings)
            for package in findings.values():
                if row["chain_id"] in package["attack_chains"]:
                    require(package["claim_id"] in row["component_claim_ids"], "finding asserts unrelated chain membership")
            projected.append({key: row[key] for key in ("chain_id", "status", "component_claim_ids", "artifact", "disposition")}
                             | {"gap_count": len(row["limitations"])})
        bind_tree(run_root, manifest, bindings)
        bindings.append(reference(chain_ref))
        attachments["attack_chains"] = sorted(projected, key=lambda row: row["chain_id"])
        capabilities["attack_chains"] = capability(True, summary=reference(chain_ref),
                                                   count=len(rows), omitted=accounting["capped"],
                                                   gaps=max(len(manifest["gaps"]), sum(
                                                       row["status"] == "insufficient_evidence" for row in rows)))
    unique = {(row["path"], row["sha256"]) for row in bindings}
    return {"capabilities": capabilities, "attachments": attachments,
            "bindings": [{"path": path, "sha256": digest} for path, digest in sorted(unique)]}


def reverify_snapshot(run_root: Path, verified: Mapping[str, Any]) -> None:
    """Refuse a concurrent upstream acceptance or changed artifact before sealing the gate."""
    for ref in verified["bindings"]:
        resolve_bound(run_root, ref)
    expected = {"job_inference_security_review": verified["inputs"]["job_handoff"]}
    expected.update({PRODUCERS[name][0]: record["handoff"] for name, record in verified["capabilities"].items()
                     if name in PRODUCERS and record["enabled"]})
    for job, ref in expected.items():
        try:
            current = accepted_handoff(run_root, job)
        except ValueError as exc:
            raise IntegrityError(f"accepted {job} changed during gate publication") from exc
        actual = None if current is None else {"path": current.path, "sha256": current.sha256}
        require(actual == ref, f"accepted {job} changed during gate publication")
