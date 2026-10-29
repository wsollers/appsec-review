"""Exact scratch application, independent semantic assessment, and selected pinned build comparison."""
from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Callable, Mapping

from appsec_review.config.remediation import RemediationValidationSettings, exact
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.inference import Infer
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.completion_contracts import (
    NONEXECUTION_POLICY, REMEDIATION_VALIDATION_HANDOFF_SCHEMA, REMEDIATION_VALIDATION_JOB,
    REMEDIATION_VALIDATION_SCHEMA, REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
    RemediationValidationStatus as Status, nonexecution_assurance,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, BuildUnit
from appsec_review.jobs.job_remediation_planning.contracts import texts, text, verify_patch_scope, verify_plan
from appsec_review.jobs.job_remediation_planning.inputs import binding, confirmed_findings, evidence_relations, load_review
from appsec_review.jobs.job_remediation_planning.job import SCHEMA_ROOT, write_json
from appsec_review.jobs.job_remediation_planning.model import emit_model_event, guidance, run_model
from appsec_review.jobs.job_remediation_planning.patches import (
    PatchError, apply_exact, parse_patch, unsafe_build_changes,
)
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from .compiler import compare_build
from .datasets import CONSUMES, DATASETS
from .inputs import load_planning
from .workspace import WorkspaceLimit, cleanup, manifest, materialize

JOB_ID = REMEDIATION_VALIDATION_JOB
TOPOLOGY = {"load": ("verify_inputs",), "assess": ("validate",), "acceptance": ("publish_handoff",)}
ExecutorFactory = Callable[[UnitContext, BuildProfile], Any]


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY) or any(
            tuple(context.config.step(step).tasks) != tasks for step, tasks in TOPOLOGY.items()):
        raise ValueError("remediation validation topology does not match central configuration")
    RemediationValidationSettings.from_mapping(context.config.settings)


def _check(status: str, reason: str, artifact: Mapping[str, str] | None = None) -> dict[str, Any]:
    return {"status": status, "reason": reason, "artifact": artifact}


def _initial_checks() -> dict[str, Any]:
    checks = {name: _check("not_performed", "not commissioned or prior checks did not permit this dimension")
              for name in ("patch_applicability", "policy", "semantic_review", "static_checks", "build",
                           "regression_compile")}
    checks["regression_compile"] = _check("not_performed", "safe regression specification is retained; "
                                         "no generated regression function was commissioned")
    checks["runtime_regression"] = _check(NONEXECUTION_POLICY, "generated tests and PoCs are never linked or run")
    return checks


def semantic_answer(value: Any, settings: RemediationValidationSettings, evidence_ids: set[str]) -> Mapping[str, Any]:
    body = exact(value, {"decision", "reason", "evidence_ids", "residual_concerns"}, "semantic assessment")
    if body["decision"] not in {"supported", "contradicted", "unresolved"}:
        raise ValueError("semantic assessment decision must be supported, contradicted or unresolved")
    text(body["reason"], settings.bounds, "semantic reason")
    cited = texts(body["evidence_ids"], settings.bounds, "semantic evidence", nonempty=True)
    if not set(cited) <= evidence_ids:
        raise ValueError("semantic assessment cites evidence outside the accepted finding")
    texts(body["residual_concerns"], settings.bounds, "semantic residual concerns")
    return body


def build_job(*, infer: Infer | None = None, executor_factory: ExecutorFactory | None = None,
              builds_factory: Callable[[Path], AcceptedBuilds] | None = None,
              repository_root: Path | None = None) -> Job:
    def repo(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root)

    def settings(unit: UnitContext) -> RemediationValidationSettings:
        return RemediationValidationSettings.from_mapping(unit.job.config.settings)

    def loaded(unit: UnitContext) -> Mapping[str, Any]:
        return read_bound_json(unit.job.run_root, unit.output("load.verify_inputs")["artifact"])

    def load(unit: UnitContext) -> Mapping[str, Any]:
        configured = settings(unit)
        review = load_review(unit.job.run_root, repo(unit), configured.bounds)
        reference, planning = load_planning(unit.job.run_root, review, SchemaSet(repo(unit) / SCHEMA_ROOT))
        unit.job.events.write("REMEDIATION_VALIDATION_INPUTS_VERIFIED", confirmed_count=len(planning["items"]),
                              admitted_count=min(len(planning["items"]), configured.bounds.max_candidates),
                              omitted_count=max(0, len(planning["items"]) - configured.bounds.max_candidates),
                              proposal_count=sum(row["status"] == "proposal_generated" for row in planning["items"]))
        return {"artifact": write_json(unit, "inputs.json", {"review": review, "planning": planning,
                                                           "planning_handoff": reference}),
                "item_count": len(planning["items"]), "gaps": [], "terminal_status": "SUCCEEDED"}

    def validate_one(unit: UnitContext, index: int, item: Mapping[str, Any], document: Mapping[str, Any],
                     builds: AcceptedBuilds, configured: RemediationValidationSettings) -> dict[str, Any]:
        root, review = unit.job.run_root, document["review"]
        row = {"finding": item["finding"], "status": Status.MANUAL_VALIDATION_REQUIRED.value,
               "validation": None, "reason": "validation_candidate_bound_reached", "gap_ids": []}
        if index >= configured.bounds.max_candidates:
            row["gap_ids"] = [f"remediation_validation:{item['finding']['claim_id']}:candidate_bound_reached"]
            return row
        if item["plan"] is None:
            row.update(reason=f"no_patch_proposal:{item['status']}",
                       gap_ids=[f"remediation_validation:{item['finding']['claim_id']}:proposal_unavailable"])
            return row
        plan = verify_plan(root, item["plan"], review_handoff=review["inputs"]["review_handoff"],
                           finding=item["finding"], schemas=SchemaSet(repo(unit) / SCHEMA_ROOT))
        finding = next(value for value in confirmed_findings(review) if binding(value) == item["finding"])
        if plan["adjudication_id"] != finding["adjudication_id"]:
            raise IntegrityError("remediation plan adjudication differs from accepted finding")
        checks = _initial_checks()
        result = {"schema": REMEDIATION_VALIDATION_SCHEMA, "run_id": root.name,
                  "upstream": {"review_handoff": review["inputs"]["review_handoff"],
                               "planning_handoff": document["planning_handoff"], "poc_handoff": None},
                  "finding": item["finding"], "adjudication_id": finding["adjudication_id"],
                  "plan": item["plan"], "patch": plan["patch"], "status": Status.MANUAL_VALIDATION_REQUIRED.value,
                  "reason": "proposal_requires_manual_design", "checks": checks,
                  "assurance": nonexecution_assurance(), "settings_sha256": configured.settings_sha256(),
                  "cleanup": None, "gaps": list(plan["gaps"])}
        scratch = unit.unit_root / str(index) / "scratch"
        try:
            if plan["patch"] is not None:
                _validate_patch(unit, index, plan, finding, review, builds, configured, scratch, checks, result)
        except PatchError as exc:
            result.update(status=Status.REJECTED.value, reason=f"patch_rejected:{str(exc)[:180]}")
            checks["patch_applicability"] = _check("failed", result["reason"])
        except WorkspaceLimit as exc:
            result.update(status=Status.MANUAL_VALIDATION_REQUIRED.value, reason=str(exc))
        finally:
            receipt = cleanup(scratch, root)
            result["cleanup"] = write_json(unit, f"{index}/cleanup.json", receipt)
            if not receipt["removed"]:
                raise IntegrityError(f"remediation scratch cleanup failed: {receipt['error']}")
        if result["status"] != Status.BUILD_CHECKED.value:
            result["gaps"].append(f"remediation_validation:{finding['claim_id']}:{result['status']}")
        SchemaSet(repo(unit) / SCHEMA_ROOT).validate("validation", result)
        reference = write_json(unit, f"{index}/validation.json", result)
        row.update(status=result["status"], reason=result["reason"], validation=reference, gap_ids=result["gaps"])
        return row

    def _validate_patch(unit: UnitContext, index: int, plan: Mapping[str, Any], finding: Mapping[str, Any],
                        review: Mapping[str, Any], builds: AcceptedBuilds, configured: RemediationValidationSettings,
                        scratch: Path, checks: dict[str, Any], result: dict[str, Any]) -> None:
        root = unit.job.run_root
        patch = parse_patch(read_bound_json(root, plan["patch"]), configured.bounds)
        context = read_bound_json(root, plan["provenance"]["source_context"])
        relations = evidence_relations(root, review, finding)
        if (context.get("finding") != result["finding"] or context.get("relations") != relations
                or context.get("adjudication_id") != finding["adjudication_id"]):
            raise IntegrityError("proposal source context disagrees with accepted evidence")
        source_files = {item["path"]: item for item in context["files"]}
        if not source_files:
            result["reason"] = "run_owned_source_unavailable"
            return
        verify_patch_scope(patch, source_files, builds, configured.bounds)
        unsafe = unsafe_build_changes(patch)
        if unsafe:
            checks["policy"] = _check("unsafe", "build configuration or tool-loading mutation requires manual validation")
            result.update(status=Status.MANUAL_VALIDATION_REQUIRED.value,
                          reason="unsafe_build_configuration_mutation")
            return
        # A first slice validates one accepted compile unit, never invents a cross-build adapter.
        units: list[BuildUnit] = []
        for source in source_files.values():
            located = builds.locate(source["path"])
            if located.unit is not None and located.unit.identity() not in [value.identity() for value in units]:
                units.append(located.unit)
        if len(units) != 1:
            result["reason"] = "multi_build_proposal_requires_manual_validation"
            return
        build = units[0]
        checks["policy"] = _check("passed", "bounded source edits; no executable build/tool configuration changes")
        materialize(build, scratch / "baseline", configured.bounds, run_root=root)
        materialize(build, scratch / "patched", configured.bounds, run_root=root)
        apply_exact(patch, scratch / "patched", build.workspace_manifest, configured.bounds)
        baseline_manifest = manifest(scratch / "baseline", configured.bounds)
        patched_manifest = manifest(scratch / "patched", configured.bounds)
        if (baseline_manifest != dict(build.workspace_manifest)
                or set(patched_manifest) - set(build.workspace_manifest) - set(patch.paths)
                or any(patched_manifest.get(name) != digest for name, digest in build.workspace_manifest.items()
                       if name not in patch.paths)):
            raise IntegrityError("scratch patch produced undeclared edits")
        checks["patch_applicability"] = _check("passed", "exact baseline hashes, absence proofs and byte edits match")
        new_conflicts = []
        for name in patch.paths:
            path = scratch / "patched" / name
            data = path.read_bytes()
            old_path = scratch / "baseline" / name
            old = old_path.read_bytes() if old_path.is_file() else b""
            if b"\x00" in data or any(data.count(marker) > old.count(marker) for marker in (
                    b"<<<<<<<", b"=======", b">>>>>>>")):
                new_conflicts.append(name)
        static_ref = write_json(unit, f"{index}/static-checks.json", {
            "checks": ["utf8_source", "no_nul_bytes", "no_new_merge_markers", "exact_declared_edit_set"],
            "baseline": "accepted_utf8_source", "patched": "failed" if new_conflicts else "passed",
            "diagnostics": new_conflicts})
        checks["static_checks"] = _check("failed" if new_conflicts else "passed",
                                         "bounded text and declared-edit checks; not vulnerability proof", static_ref)
        if new_conflicts:
            result.update(status=Status.REJECTED.value, reason="static_patch_policy_failed")
            return
        role_text, guidance_sha = guidance(repo(unit), root, "remediation_reviewer", job_id=unit.job.config.job_id)
        from appsec_review.inference import infer as default_infer
        answer, receipt = run_model(
            infer=infer or default_infer, profile=configured.reviewer, role="remediation_reviewer",
            cell_id=f"remediation-reviewer:{finding['claim_id']}", guidance_text=role_text,
            guidance_sha256=guidance_sha,
            task={"kind": "independent_semantic_assessment",
                  "accepted_finding": {"finding": binding(finding), "title": finding["title"],
                                       "adjudication_id": finding["adjudication_id"],
                                       "direct_evidence": finding["direct_evidence"]},
                  "requirement": {"violated_invariant": plan["violated_invariant"],
                                  "corrected_invariant": plan["corrected_invariant"]},
                  "accepted_evidence": relations, "source_files": context["files"], "patch": patch.document,
                  "regression_spec": plan["regression_spec"],
                  "output_fields": ["decision", "reason", "evidence_ids", "residual_concerns"]},
            validate=lambda value: semantic_answer(value, configured, {row["relation_id"] for row in relations}))
        semantic_ref = write_json(unit, f"{index}/semantic-review.json",
                                  {"receipt": receipt, "assessment": answer, "basis": "analyst_assessed"})
        emit_model_event(unit.job.events, receipt)
        if answer is None:
            checks["semantic_review"] = _check("analyst_unresolved", receipt["reason"], semantic_ref)
            result.update(status=Status.INCONCLUSIVE.value, reason="independent_semantic_review_unavailable")
            return
        checks["semantic_review"] = _check(f"analyst_{answer['decision']}", answer["reason"], semantic_ref)
        if answer["decision"] != "supported":
            result.update(status=Status.REJECTED.value if answer["decision"] == "contradicted" else
                          Status.INCONCLUSIVE.value, reason=f"analyst_assessed_{answer['decision']}")
            return
        result.update(status=Status.STATIC_CHECKED.value, reason="selected_static_checks_only")
        if "native_syntax" not in configured.adapters:
            checks["build"] = _check("not_performed", "native_syntax adapter is not commissioned")
            return
        if set(patch.paths) != {build.command.source} or build.command.basis != "exact":
            checks["build"] = _check("unsafe", "the accepted exact translation unit does not cover every changed file")
            result.update(status=Status.MANUAL_VALIDATION_REQUIRED.value,
                          reason="patch_scope_not_covered_by_native_adapter")
            return
        try:
            profile = BuildProfile("native", build.image_tag, build.image_id, build.image_user,
                                   derived_from_image_id=build.image_derived_from)
        except ValueError:
            checks["build"] = _check("unsafe", "accepted build facts do not commission a pinned native profile")
            result.update(status=Status.MANUAL_VALIDATION_REQUIRED.value,
                          reason="accepted_build_profile_uncommissioned")
            return
        executor = (executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
            profile, timeout_seconds=configured.command_timeout_seconds, output_bytes=configured.output_bytes,
            network="none"))
        adapter_started = time.monotonic()
        build_result = compare_build(build, scratch / "baseline", scratch / "patched", executor,
                                     output_bytes=configured.output_bytes)
        build_ref = write_json(unit, f"{index}/build-comparison.json", build_result)
        streams = [build_result[name] for name in ("baseline", "patched") if build_result[name] is not None]
        unit.job.events.write("REMEDIATION_VALIDATION_ADAPTER_COMPLETED", claim_id=finding["claim_id"],
                              adapter="native_syntax", outcome=build_result["status"],
                              duration_ms=max(0, int((time.monotonic() - adapter_started) * 1000)),
                              timeout_count=sum(row["timed_out"] for row in streams),
                              failure_count=sum(row["exit_code"] != 0 for row in streams),
                              baseline_attempted=build_result["baseline"] is not None,
                              patched_attempted=build_result["patched"] is not None,
                              output_bytes=(root / build_ref["path"]).stat().st_size)
        checks["build"] = _check(build_result["status"], build_result["reason"], build_ref)
        if (manifest(scratch / "baseline", configured.bounds) != baseline_manifest
                or manifest(scratch / "patched", configured.bounds) != patched_manifest):
            raise IntegrityError("commissioned compiler changed its read-only source workspace")
        status = build_result["status"]
        if status == "passed":
            result.update(status=Status.BUILD_CHECKED.value,
                          reason="identical pinned native syntax checks passed before and after; no runtime proof")
        elif status == "baseline_failed":
            result.update(status=Status.INCONCLUSIVE.value, reason="baseline_build_failed")
        elif status == "patched_failed":
            result.update(status=Status.REJECTED.value, reason="patched_build_failed")
        elif status == "unsafe":
            result.update(status=Status.MANUAL_VALIDATION_REQUIRED.value, reason="accepted_build_replay_unsafe")
        else:
            result.update(status=Status.STATIC_CHECKED.value, reason="build_unavailable_static_checks_only")

    def assess(unit: UnitContext) -> Mapping[str, Any]:
        configured, document = settings(unit), loaded(unit)
        builds = (builds_factory or AcceptedBuilds)(unit.job.run_root)
        rows = []
        for index, item in enumerate(document["planning"]["items"]):
            started = time.monotonic()
            row = validate_one(unit, index, item, document, builds, configured)
            rows.append(row)
            unit.job.events.write("REMEDIATION_VALIDATION_CANDIDATE_COMPLETED",
                                  claim_id=item["finding"]["claim_id"], outcome=row["status"],
                                  gap_count=len(row["gap_ids"]),
                                  duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                                  output_bytes=sum(path.stat().st_size for path in (unit.unit_root / str(index)).rglob("*")
                                                   if path.is_file()))
        return {"artifact": write_json(unit, "outcomes.json", {"items": rows}), "gaps": [],
                "terminal_status": "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        configured, document = settings(unit), loaded(unit)
        root = unit.job.run_root
        fresh = load_review(root, repo(unit), configured.bounds)
        reference, _planning = load_planning(root, fresh, SchemaSet(repo(unit) / SCHEMA_ROOT))
        if (fresh["inputs"]["review_handoff"] != document["review"]["inputs"]["review_handoff"]
                or reference != document["planning_handoff"]):
            raise IntegrityError("accepted remediation inputs changed during validation")
        for reference in document["review"]["bindings"]:
            resolve_bound(root, reference)
        rows = read_bound_json(root, unit.output("assess.validate")["artifact"])["items"]
        if [row["finding"] for row in rows] != [row["finding"] for row in document["planning"]["items"]]:
            raise IntegrityError("validation outcomes do not exactly account for planning candidates")
        schemas = SchemaSet(repo(unit) / SCHEMA_ROOT)
        for row in rows:
            if row["validation"] is not None:
                record = read_bound_json(root, row["validation"])
                schemas.validate("validation", record)
                for check in record["checks"].values():
                    if check["artifact"] is not None:
                        resolve_bound(root, check["artifact"])
                resolve_bound(root, record["cleanup"])
        gaps = sorted({gap for row in rows for gap in row["gap_ids"]})
        summary = {"schema": REMEDIATION_VALIDATION_SUMMARY_SCHEMA, "run_id": root.name,
                   "upstream": {"review_handoff": fresh["inputs"]["review_handoff"],
                                "planning_handoff": document["planning_handoff"], "poc_handoff": None},
                   "items": rows, "gaps": gaps}
        schemas.validate("validations", summary)
        reference = write_json(unit, "remediation-validations.json", summary)
        unit.job.events.write("REMEDIATION_VALIDATION_PUBLISHED", item_count=len(rows), gap_count=len(gaps),
                              outcome_counts={status.value: sum(row["status"] == status.value for row in rows)
                                              for status in Status},
                              output_bytes=(root / reference["path"]).stat().st_size)
        return {"schema": REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
                "artifact": reference, "item_count": len(rows),
                "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else
                ("SUCCEEDED" if rows else "SKIPPED_NA")}

    units = (Unit("load.verify_inputs", load), Unit("assess.validate", assess, ("load.verify_inputs",)),
             Unit("acceptance.publish_handoff", publish, ("load.verify_inputs", "assess.validate")))
    return Job(JOB_ID, "remediation_validation", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=REMEDIATION_VALIDATION_HANDOFF_SCHEMA, units=units, datasets=DATASETS, consumes=CONSUMES)
