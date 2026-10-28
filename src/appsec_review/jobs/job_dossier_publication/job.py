"""Semantic dossier producer: accepted review/producers -> protected immutable documents -> handoff."""
from __future__ import annotations

import hashlib
from pathlib import Path
import time
from typing import Any, Callable, Mapping

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json, resolve_bound
from appsec_review.jobs.completion_contracts import (
    DOSSIER_PUBLICATION_HANDOFF_SCHEMA, DOSSIER_PUBLICATION_JOB, DOSSIER_PUBLICATION_SCHEMA, DossierKind,
)
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.reporting.dossiers import DossierLimits, build_dossier
from appsec_review.reporting.dossier_render import render_dossier
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json
from .datasets import CONSUMES, DATASETS
from .inputs import bound_json, finding_binding, load_inputs, verify_snapshot
from .settings import DossierPublicationSettings

JOB_ID = DOSSIER_PUBLICATION_JOB
TOPOLOGY = {"load": ("verify_inputs",), "dossiers": ("create",), "acceptance": ("publish_handoff",)}


def _settings(unit: UnitContext) -> DossierPublicationSettings:
    return DossierPublicationSettings.from_mapping(unit.job.config.settings)


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("dossier topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError("dossier task configuration mismatch: " + step)
    DossierPublicationSettings.from_mapping(context.config.settings)


def _write(unit: UnitContext, name: str, document: Any) -> dict[str, str]:
    path = unit.unit_root / name
    atomic_json(path, document)
    return artifact_ref(unit.job.run_root, path)


def _accepted_review(root: Path, schemas: SchemaSet, *, max_packages: int):
    from appsec_review.jobs.accepted_review import load_accepted_review
    return load_accepted_review(root, schemas, max_packages=max_packages)


def _core(root: Path, manifest: Mapping[str, str]):
    from appsec_review.retrieval.core import RetrievalCore
    return RetrievalCore(root.parent, root.name, manifest_sha256=manifest["sha256"],
                         manifest_path=root / manifest["path"])


def _poc(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    producer = document["producers"]["job_poc_generation"]
    return {} if producer is None else {finding_binding(row).finding_package_id: row
                                       for row in producer["document"]["candidates"]}


def _remediation(root: Path, document: Mapping[str, Any], finding_id: str,
                 settings: DossierPublicationSettings) -> list[dict[str, Any]]:
    result = []
    for job, stage, key in (("job_remediation_planning", "Planning", "plan"),
                            ("job_remediation_validation", "Validation", "validation")):
        producer = document["producers"][job]
        if producer is None:
            continue
        for row in producer["document"]["items"]:
            if finding_binding(row).finding_package_id != finding_id:
                continue
            ref = row.get(key)
            attachment = {} if ref is None else bound_json(root, ref, settings.max_artifact_bytes)
            result.append({"stage": stage, "status": row["status"], "reason": row.get("reason"),
                           "artifact": ref, **{name: attachment.get(name) for name in (
                               "violated_invariant", "corrected_invariant", "compatibility_effects",
                               "affected_interfaces", "residual_risks", "deployment_prerequisites",
                               "regression_spec", "validation_checks", "scope_limitations", "checks")}})
    return result


def _chains(root: Path, document: Mapping[str, Any], finding: Mapping[str, Any],
            settings: DossierPublicationSettings) -> list[Mapping[str, Any]]:
    manifest = document.get("chains")
    if manifest is None:
        return []
    result = []
    memberships = set(finding.get("attack_chains", ()))
    for row in manifest.get("items", ()):
        ref = row.get("artifact")
        chain = row if ref is None else bound_json(root, ref, settings.max_artifact_bytes)
        if row.get("chain_id") in memberships or finding["claim_id"] in row.get("component_claim_ids", ()):
            decision = chain.get("decision") or {}
            proposal = chain.get("proposal") or {}
            result.append({"chain_id": row["chain_id"], "status": decision.get("status", row.get("status")),
                           "objective": proposal.get("objective"),
                           "qualifications": decision.get("limitations", row.get("limitations", []))})
    return result


def _excerpts(core: Any, relations: list[Mapping[str, Any]], finding: Mapping[str, Any],
              settings: DossierPublicationSettings) -> tuple[list[Mapping[str, Any]], list[str]]:
    cited = set(finding.get("direct_evidence", ())) | set(finding.get("analyst_assessed_evidence", ()))
    identities = sorted({row["entity_id"] for row in relations if row["relation_id"] in cited})
    rows, gaps = [], []
    for identity in identities[:settings.max_source_excerpts]:
        response = core.read_excerpt(identity=identity, context_lines=2)
        results = response.get("results", ())
        if not results:
            gaps.append("source_excerpt_unavailable: " + identity)
        for row in results:
            if row.get("identity") != identity:
                raise IntegrityError("dossier source retrieval returned another identity")
            rows.append(row)
        if response.get("truncated"):
            gaps.append("source_excerpt_truncated: " + identity)
    if len(identities) > settings.max_source_excerpts:
        gaps.append(f"source_excerpt_cap: {len(identities) - settings.max_source_excerpts} cited identities omitted")
    return rows, gaps


def build_job(*, repository_root: Path | None = None, review_loader: Callable[..., Any] | None = None,
              core_factory: Callable[..., Any] | None = None, renderer: Callable[..., Any] | None = None) -> Job:
    """Factories are pure; Docker/retrieval run only inside commissioned execution units."""
    review_loader = review_loader or _accepted_review
    core_factory = core_factory or _core
    renderer = renderer or render_dossier

    def repo(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def load(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        verified = review_loader(unit.job.run_root, SchemaSet(repo(unit) / SCHEMA_DIRECTORY),
                                 max_packages=settings.max_packages)
        document = load_inputs(unit.job.run_root, verified.document, settings)
        unit.job.events.write(
            "DOSSIER_INPUTS_VERIFIED", finding_packages=len(verified.document["packages"]),
            confirmed_findings=sum(row["state"] == "confirmed" for row in verified.document["packages"]),
            poc_outcomes=len(_poc(document)), accepted_producers=sum(value is not None
                for value in document["producers"].values()),
            review_handoff_sha256=document["upstream"]["review_handoff"]["sha256"])
        return {"artifact": _write(unit, "inputs.json", document), "gaps": [], "terminal_status": "SUCCEEDED"}

    def create(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        started = time.monotonic()
        root = unit.job.run_root
        document = read_bound_json(root, unit.output("load.verify_inputs")["artifact"])
        verify_snapshot(root, document, settings)
        verified = document["verified_review"]
        findings = {row["finding_package_id"]: row for row in verified["packages"]}
        claims = {row["claim_id"]: row for row in document["projection"]["claims"]}
        pocs = _poc(document)
        admitted = sorted([(DossierKind.CONFIRMED_FINDING.value, key) for key, finding in findings.items()
                           if finding["state"] == "confirmed"] + [(DossierKind.POC.value, key) for key in pocs])
        selected, capped = admitted[:settings.max_dossiers], admitted[settings.max_dossiers:]
        unit.job.events.write("DOSSIER_BATCH_PLANNED", admitted=len(admitted), selected=len(selected),
                              omitted=len(capped), max_dossiers=settings.max_dossiers)
        core = core_factory(root, document["source_manifest"]) if selected else None
        limits = DossierLimits(settings.max_text_chars, settings.max_code_lines, settings.max_code_chars,
                               settings.max_evidence_rows, settings.max_source_excerpts)
        items = []
        for kind, key in selected:
            finding = findings[key]
            relations = document["projection"]["relations"].get(finding["claim_id"], [])
            sources, source_gaps = _excerpts(core, relations, finding, settings)
            poc = pocs.get(key)
            if poc is not None:
                source_gaps.extend(poc.get("gap_ids", poc.get("gaps", ())))
                if poc["status"] != "compile_verified":
                    source_gaps.append("poc_assurance_limited: " + poc["status"])
            poc_source = None
            if poc is not None and (poc.get("files") or {}).get("source") is not None:
                reference = poc["files"]["source"]
                path = resolve_bound(root, reference)
                if path.stat().st_size > settings.max_artifact_bytes:
                    source_gaps.append("poc_source_cap: generated text exceeds max_artifact_bytes")
                else:
                    try:
                        poc_source = read_bound(root, reference).decode("utf-8")
                    except UnicodeDecodeError:
                        source_gaps.append("poc_source_unavailable: generated text is not UTF-8")
            model = build_dossier(
                run_id=root.name, kind=kind, finding=finding, claim=claims[finding["claim_id"]],
                relations=relations, excerpts=sources, poc=poc, poc_source=poc_source,
                remediation=_remediation(root, document, key, settings),
                chains=_chains(root, document, finding, settings), gaps=source_gaps, limits=limits,
                provenance={**document["upstream"], "finding_artifact": {"path": finding["path"], "sha256": finding["sha256"]},
                            "projection": verified["inputs"]["projection"],
                            "ledger_head_sha256": verified["review"]["ledger_head_sha256"],
                            "configuration_sha256": verified["review"]["configuration_sha256"],
                            "settings_sha256": settings.settings_sha256(),
                            "source_manifest": document["source_manifest"],
                            "attack_chain_manifest": document["attack_chain_manifest"]})
            # Compact path segments keep full finding identities out of Windows directory names.
            name = hashlib.sha256(f"{kind}:{key}".encode()).hexdigest()[:16]
            unit.job.events.write("DOSSIER_RENDER_STARTED", dossier_id=model["dossier_id"], kind=kind,
                                  finding_package_id=key, pdf_requested=settings.render_pdf)
            render_started = time.monotonic()
            try:
                item = renderer(root, unit.unit_root / "items" / name, model, settings=settings,
                                repository_root=repo(unit))
            except (OSError, RuntimeError, ValueError) as exc:
                unit.job.events.write("DOSSIER_RENDER_FAILED", dossier_id=model["dossier_id"], kind=kind,
                                      finding_package_id=key, error_type=type(exc).__name__,
                                      duration_ms=max(0, round((time.monotonic() - render_started) * 1000)))
                raise
            items.append(item)
            sizes = {key + "_bytes": 0 if reference is None else resolve_bound(root, reference).stat().st_size
                     for key, reference in item["files"].items()}
            unit.job.events.write(
                "DOSSIER_RENDER_COMPLETED", dossier_id=model["dossier_id"], kind=kind,
                finding_package_id=key, status=item["status"], render_failed=item["status"] == "render_failed",
                duration_ms=max(0, round((time.monotonic() - render_started) * 1000)),
                source_excerpts=len(sources), gap_count=len(item["gap_ids"]), **sizes,
                receipt_sha256=item["files"]["receipt"]["sha256"], image_id=settings.image_id)
        omitted = [{"kind": kind, "finding": {name: findings[key][name] for name in (
            "claim_id", "finding_package_id", "sha256")}, "reason": "max_dossiers"} for kind, key in capped]
        gaps = sorted({gap for item in items for gap in item["gap_ids"]})
        if capped:
            gaps.append(f"dossier_cap: {len(capped)} admitted dossiers not launched; max_dossiers={settings.max_dossiers}")
        summary = {
            "schema": DOSSIER_PUBLICATION_SCHEMA, "run_id": root.name, "upstream": document["upstream"],
            "items": items, "omitted": omitted, "gaps": gaps, "settings_sha256": settings.settings_sha256(),
            "counts": {"admitted": len(admitted), "items": len(items), "omitted": len(omitted),
                       "by_kind": {kind.value: sum(1 for value, _key in admitted if value == kind.value)
                                   for kind in DossierKind},
                       "by_status": {status: sum(item["status"] == status for item in items)
                                     for status in ("rendered", "render_failed", "latex_only")}},
            "caps": {"max_dossiers": settings.max_dossiers, "max_source_excerpts": settings.max_source_excerpts,
                     "max_evidence_rows": settings.max_evidence_rows},
        }
        unit.job.events.write("DOSSIER_PUBLICATION_ASSEMBLED", admitted=len(admitted), items=len(items),
                              omitted=len(omitted), confirmed_finding_count=summary["counts"]["by_kind"]["confirmed_finding"],
                              poc_count=summary["counts"]["by_kind"]["poc"], gap_count=len(gaps),
                              duration_ms=max(0, round((time.monotonic() - started) * 1000)),
                              **{status + "_count": count for status, count in summary["counts"]["by_status"].items()})
        return {"artifact": _write(unit, "dossiers.json", summary), "item_count": len(items), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        root = unit.job.run_root
        document = read_bound_json(root, unit.output("load.verify_inputs")["artifact"])
        verify_snapshot(root, document, settings)
        created = unit.output("dossiers.create")
        summary = read_bound_json(root, created["artifact"])
        verify_publication(root, summary)
        expected = {
            (DossierKind.CONFIRMED_FINDING.value, row["finding_package_id"])
            for row in document["verified_review"]["packages"] if row["state"] == "confirmed"
        } | {(DossierKind.POC.value, key) for key in _poc(document)}
        actual = {(row["kind"], row["finding"]["finding_package_id"])
                  for row in [*summary["items"], *summary["omitted"]]}
        if expected != actual or summary["upstream"] != document["upstream"]:
            raise IntegrityError("dossier publication does not partition its accepted upstream candidates")
        unit.job.events.write("DOSSIER_PUBLICATION_PUBLISHED", item_count=len(summary["items"]),
                              omitted_count=len(summary["omitted"]), gap_count=len(summary["gaps"]),
                              artifact_sha256=created["artifact"]["sha256"],
                              **{status + "_count": count for status, count in summary["counts"]["by_status"].items()})
        return {"schema": DOSSIER_PUBLICATION_HANDOFF_SCHEMA, "artifact": created["artifact"],
                "item_count": len(summary["items"]), "gaps": summary["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if summary["gaps"] else "SUCCEEDED"}

    units = (Unit("load.verify_inputs", load), Unit("dossiers.create", create, ("load.verify_inputs",)),
             Unit("acceptance.publish_handoff", publish, ("load.verify_inputs", "dossiers.create")))
    return Job(JOB_ID, "dossier_publication", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=DOSSIER_PUBLICATION_HANDOFF_SCHEMA, units=units, datasets=DATASETS, consumes=CONSUMES)


def verify_publication(root: Path, summary: Mapping[str, Any]) -> None:
    """Reusable final-gate verifier for protected dossier artifact references and accounting."""
    if summary.get("schema") != DOSSIER_PUBLICATION_SCHEMA or summary.get("run_id") != Path(root).name:
        raise IntegrityError("dossier publication schema or run binding is invalid")
    counts = summary["counts"]
    items, omitted = summary["items"], summary["omitted"]
    if (counts["admitted"] != len(items) + len(omitted) or counts["items"] != len(items)
            or counts["omitted"] != len(omitted) or len(items) > summary["caps"]["max_dossiers"]):
        raise IntegrityError("dossier candidate accounting is not exact")
    seen = set()
    for item in [*items, *omitted]:
        identity = (item["kind"], item["finding"]["finding_package_id"])
        if identity in seen or item["kind"] not in {value.value for value in DossierKind}:
            raise IntegrityError("duplicate or unknown dossier kind/finding")
        seen.add(identity)
    if counts["by_kind"] != {kind.value: sum(item["kind"] == kind.value for item in [*items, *omitted])
                             for kind in DossierKind}:
        raise IntegrityError("dossier kind accounting is not exact")
    if counts["by_status"] != {status: sum(item["status"] == status for item in items)
                               for status in ("rendered", "render_failed", "latex_only")}:
        raise IntegrityError("dossier rendering accounting is not exact")
    for item in items:
        if item["status"] not in {"rendered", "render_failed", "latex_only"}:
            raise IntegrityError("unknown dossier render status")
        files = item["files"]
        if set(files) != {"json", "latex", "pdf", "receipt"} or (files["pdf"] is not None) != (item["status"] == "rendered"):
            raise IntegrityError("dossier PDF reference disagrees with render status")
        for ref in files.values():
            if ref is not None:
                resolve_bound(root, ref)
        model = read_bound_json(root, files["json"])
        receipt = read_bound_json(root, files["receipt"])
        if (model["dossier_id"] != item["dossier_id"] or model["finding"] != item["finding"]
                or model["kind"] != item["kind"] or model["run_id"] != summary["run_id"]
                or receipt["dossier_id"] != item["dossier_id"] or receipt["run_id"] != summary["run_id"]
                or receipt["status"] != item["status"] or receipt["files"] != {
                    name: files[name] for name in ("json", "latex", "pdf")}):
            raise IntegrityError("dossier receipt/model disagrees with publication")
        if receipt.get("execution") is not None:
            resolve_bound(root, receipt["execution"])


__all__ = ["JOB_ID", "TOPOLOGY", "build_job", "verify_publication"]
