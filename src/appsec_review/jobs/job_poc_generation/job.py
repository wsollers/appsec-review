"""``job_poc_generation``: proof-of-concept unit-test functions for findings the judge agreed are correct.

Units, in order: ``load.verify_inputs`` re-verifies the accepted gate and review handoffs from bytes and
reads ``poc_candidates``; ``plan.briefs`` builds the writer's brief per candidate; ``write.poc_writer``
asks the ``poc_writer`` model (no tools, in-process retrieval) for two functions; ``validate.policy``
runs the deterministic validators on the clang AST in the build image; ``compile.build_check`` compiles
the functions with the project's own flags (syntax, plain object, sanitizer object) and checks the
undefined symbols; ``package.files`` writes ``data/poc/<claim-id>/``; ``publish.publish_handoff``
publishes one hash-bound handoff listing every candidate with its status.

Nothing is linked into an executable and nothing is run. The job reads no target tree: the accepted
build workspace of ``job_language_build`` supplies the source copy, the compile command and the image.
"""
from __future__ import annotations

from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
import hashlib
from pathlib import Path
import shutil
from typing import Any, Callable, Mapping, Sequence

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.engineering_contracts import POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json

from . import buildcheck, inputs as review_inputs
from .brief import Brief, build_brief
from .buildctx import AcceptedBuilds, BuildUnit, Headers, declarations
from .candidates import PocCandidate, parse_candidates
from .datasets import CONSUMES, DATASETS
from .package import describe, source_file_name, write_candidate
from .policy import check_ast
from .settings import PocGenerationSettings
from .source import WriterAnswer, assemble, check_answer, decline_of, file_violations
from .statuses import (
    ARTIFACT_GENERATED, COMPILE_FAILED, COMPILE_VERIFIED, GAP_CANDIDATE_BOUND,
    INSUFFICIENT_EVIDENCE, NOT_APPLICABLE, POLICY_DENIED, SOURCE_STATUSES, STATUSES,
)
from .writer import WorkspaceReader, load_guidance, run_writer

JOB_ID = "job_poc_generation"
SCHEMA_ROOT = Path("docs") / "schemas" / "poc-generation"
GATE_SCHEMA_ROOT = Path("docs") / "schemas" / "final-report"
TOPOLOGY = {"load": ("verify_inputs",), "plan": ("briefs",), "write": ("poc_writer",), "validate": ("policy",),
            "compile": ("build_check",), "package": ("files",), "publish": ("publish_handoff",)}
IMPLEMENTATION = "appsec-review/poc-generation/1"
GAP_STATUSES = frozenset({COMPILE_FAILED, ARTIFACT_GENERATED, POLICY_DENIED, INSUFFICIENT_EVIDENCE, "unsafe_to_attempt"})

ExecutorFactory = Callable[[UnitContext, BuildProfile], Any]


def _settings(unit: UnitContext) -> PocGenerationSettings:
    return PocGenerationSettings.from_mapping(unit.job.config.settings)


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("poc-generation topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"poc-generation task configuration mismatch: {step}")
    PocGenerationSettings.from_mapping(context.config.settings)


def _write_json(unit: UnitContext, name: str, document: Any) -> dict[str, str]:
    path = unit.unit_root / name
    atomic_json(path, document)
    return artifact_ref(unit.job.run_root, path)


def _candidate_record(candidate: PocCandidate) -> dict[str, Any]:
    return {"claim_id": candidate.claim_id, "package_id": candidate.package_id, "state": candidate.state,
            "judge_verdict": candidate.judge_verdict,
            "poc_basis": {"sha256": candidate.poc_basis.sha256, "brief": candidate.poc_basis.record()},
            "finding_package": {"finding_package_id": candidate.finding_package_id,
                                "sha256": candidate.finding_package_sha256},
            "evidence_refs": list(candidate.evidence_refs)}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _order(candidates: Sequence[PocCandidate]) -> list[PocCandidate]:
    return sorted(candidates, key=lambda item: (item.state != "confirmed", item.claim_id))


def _pool(settings: PocGenerationSettings, items: Sequence[Any], work: Callable[[Any], Any]) -> list[Any]:
    with ThreadPoolExecutor(max_workers=max(1, settings.workers)) as pool:
        return list(pool.map(work, items))


class Services:
    """The injectable edges of the job: the model, the build container, the accepted builds, retrieval."""

    def __init__(self, *, infer: Callable[..., Any] | None, executor_factory: ExecutorFactory | None,
                 builds_factory: Callable[[Path], AcceptedBuilds] | None,
                 core_factory: Callable[[Path, Mapping[str, Any]], Any] | None,
                 view_factory: Callable[..., Any] | None, sink_resolver: Callable[[Mapping[str, Any]], Any] | None,
                 repository_root: Path | None) -> None:
        self.infer = infer
        self.executor_factory = executor_factory
        self.builds_factory = builds_factory or (lambda run_root: AcceptedBuilds(run_root))
        self.core_factory = core_factory
        self.view_factory = view_factory
        self.sink_resolver = sink_resolver or review_inputs.sink_of
        self.repository_root = repository_root

    def repo(self, unit: UnitContext) -> Path:
        return Path(self.repository_root or unit.job.repository_root).resolve()

    def executor(self, unit: UnitContext, settings: PocGenerationSettings, build: BuildUnit,
                 cache: dict[str, Any]) -> Any:
        key = build.image_id
        if key not in cache:
            profile = BuildProfile("native", build.image_tag, build.image_id, build.image_user)
            executor = (self.executor_factory(unit, profile) if self.executor_factory else
                        BuildContainerExecutor(profile, timeout_seconds=settings.build.command_timeout_seconds,
                                               output_bytes=settings.build.output_bytes, network="none"))
            executor.resolve()
            cache[key] = executor
        return cache[key]


def _terminal(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"unknown PoC status: {status}")
    return {"status": status, "reason": reason[:300], **extra}


def build_job(*, infer: Callable[..., Any] | None = None, executor_factory: ExecutorFactory | None = None,
              builds_factory: Callable[[Path], AcceptedBuilds] | None = None,
              core_factory: Callable[[Path, Mapping[str, Any]], Any] | None = None,
              view_factory: Callable[..., Any] | None = None,
              sink_resolver: Callable[[Mapping[str, Any]], Any] | None = None,
              repository_root: Path | None = None) -> Job:
    """Build the job; every edge (model, container, build lookup, retrieval) is injectable for tests."""
    services = Services(infer=infer, executor_factory=executor_factory, builds_factory=builds_factory,
                        core_factory=core_factory, view_factory=view_factory, sink_resolver=sink_resolver,
                        repository_root=repository_root)

    # -- load -------------------------------------------------------------------------------------
    def load(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        root = services.repo(unit)
        run_root = unit.job.run_root
        verified = review_inputs.verify_inputs(
            run_root, review_schemas=SchemaSet(root / SCHEMA_DIRECTORY), gate_schemas=SchemaSet(root / GATE_SCHEMA_ROOT))
        gaps: list[str] = []
        planned: list[dict[str, Any]] = []
        omitted: list[str] = []
        language_sha = None
        ordered = _order(verified.candidates)
        for candidate in ordered[:settings.max_candidates]:
            finding = verified.findings[candidate.finding_package_id]
            planned.append({
                "candidate": _candidate_record(candidate),
                "finding": {key: finding.get(key) for key in (
                    "finding_package_id", "sha256", "path", "title", "label", "lane", "state",
                    "missing_predicates")},
                "package": dict(verified.package_records.get(candidate.package_id) or {}) or None})
        omitted = [item.claim_id for item in ordered[settings.max_candidates:]]
        if omitted:
            gaps.append(f"{GAP_CANDIDATE_BOUND}: {len(omitted)} candidates were not attempted because "
                        f"max_candidates is {settings.max_candidates}")
        try:
            language_sha = services.builds_factory(run_root).handoff_sha256 if planned else None
        except (ValueError, OSError, IntegrityError) as exc:
            gaps.append(f"accepted_build_unavailable: {str(exc)[:160]}")
        document = {
            "schema": "appsec-review/poc-generation-inputs/1", "run_id": verified.run_id,
            "upstream": {"gate_handoff": verified.gate_handoff, "gate_document": verified.gate_document,
                         "review_job_handoff": verified.review_job_handoff, "review_handoff": verified.review_handoff,
                         "manifest": {"path": verified.manifest_path, "sha256": verified.manifest_sha256},
                         "language_build_handoff_sha256": language_sha},
            "review_status": verified.review_status,
            "candidates_field": "present",
            "planned": planned, "omitted": omitted}
        unit.job.events.write("POC_GENERATION_INPUTS_VERIFIED", planned=len(planned), omitted=len(omitted),
                              candidates_field=document["candidates_field"])
        return {"artifact": _write_json(unit, "inputs.json", document), "planned": len(planned),
                "omitted": len(omitted), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def inputs_document(unit: UnitContext) -> Mapping[str, Any]:
        return read_bound_json(unit.job.run_root, unit.output("load.verify_inputs")["artifact"])

    # -- plan -------------------------------------------------------------------------------------
    def plan(unit: UnitContext) -> Mapping[str, Any]:
        from appsec_review.review.package_view import ViewLimits, build_view

        settings = _settings(unit)
        run_root = unit.job.run_root
        document = inputs_document(unit)
        builds = services.builds_factory(run_root)
        limits = ViewLimits(settings.brief.view_bytes, settings.brief.view_source_lines,
                            settings.brief.view_type_declarations)
        held: list[Any] = []

        def core() -> Any:
            if not held:
                held.append(_core(services, run_root, document))
            return held[0]

        entries: dict[str, Any] = {}
        for item in document["planned"]:
            candidate = parse_candidates([item["candidate"]])[0]
            entries[candidate.claim_id] = _plan_candidate(unit, settings, item, candidate, builds, limits, services,
                                                          core, build_view)
        return {"artifact": _write_json(unit, "plan.json", {"schema": "appsec-review/poc-generation-plan/1",
                                                            "entries": entries}),
                "attempts": sum(1 for entry in entries.values() if entry["terminal"] is None),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    # -- write ------------------------------------------------------------------------------------
    def write(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        run_root = unit.job.run_root
        planned = read_bound_json(run_root, unit.output("plan.briefs")["artifact"])["entries"]
        pending = [claim for claim, entry in planned.items() if entry["terminal"] is None]
        if not pending:
            return {"artifact": _write_json(unit, "write.json", {"schema": "appsec-review/poc-generation-write/1",
                                                                 "entries": {}}), "gaps": [],
                    "terminal_status": "SUCCEEDED"}
        guidance = load_guidance(services.repo(unit), run_root, JOB_ID, settings.writer)
        schemas = SchemaSet(services.repo(unit) / SCHEMA_ROOT)
        infer_callable = services.infer or _default_infer()
        builds = services.builds_factory(run_root)

        def one(claim: str) -> tuple[str, dict[str, Any]]:
            entry = planned[claim]
            brief_document = read_bound_json(run_root, entry["brief"])
            located = builds.locate(entry["sink"]["path"])
            if located.unit is None:
                return claim, {"outcome": "failed", "reason": located.reason, "result": None, "receipt": None}
            headers = Headers(located.unit)
            reader = WorkspaceReader(
                located.unit.workspace, located.unit.workspace_manifest, headers.search_directories(),
                lambda name: declarations(located.unit, headers, [name], source_bytes=65536,
                                          max_files=settings.brief.max_source_files,
                                          max_lines=settings.brief.declaration_lines))
            brief = Brief(brief_document, {}, (), ())
            outcome = run_writer(brief, guidance=guidance, settings=settings, infer=infer_callable, reader=reader,
                                 schemas=schemas, claim_id=claim)
            receipt = outcome.receipt(claim, entry["brief"]["sha256"], guidance.sha256, settings.writer)
            reference = _write_json(unit, f"receipts/{claim}.json", receipt)
            unit.job.events.write("POC_WRITER_COMPLETED", claim_id=claim, outcome=outcome.status,
                                  attempts=len(outcome.attempts))
            return claim, {"outcome": outcome.status, "reason": outcome.reason, "result": outcome.result,
                           "receipt": reference, "guidance_bundle_sha256": guidance.sha256}

        results = dict(_pool(settings, pending, one))
        return {"artifact": _write_json(unit, "write.json", {"schema": "appsec-review/poc-generation-write/1",
                                                             "entries": results}),
                "answered": sum(1 for item in results.values() if item["outcome"] == "answered"),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    # -- validate ---------------------------------------------------------------------------------
    def validate(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        run_root = unit.job.run_root
        planned = read_bound_json(run_root, unit.output("plan.briefs")["artifact"])["entries"]
        written = read_bound_json(run_root, unit.output("write.poc_writer")["artifact"])["entries"]
        inputs_doc = inputs_document(unit)
        builds = services.builds_factory(run_root)
        executors: dict[str, Any] = {}

        def one(claim: str) -> tuple[str, dict[str, Any]]:
            plan_entry, write_entry = planned[claim], written.get(claim)
            if plan_entry["terminal"] is not None:
                return claim, {"terminal": plan_entry["terminal"]}
            assert write_entry is not None
            if write_entry["outcome"] == "declined":
                status, why = decline_of(write_entry["result"]) or (INSUFFICIENT_EVIDENCE, "declined")
                return claim, {"terminal": _terminal(status, f"the writer declined: {why}")}
            if write_entry["outcome"] != "answered":
                return claim, {"terminal": _terminal(INSUFFICIENT_EVIDENCE, "the writer produced no usable answer: "
                                                     + str(write_entry["reason"])[:160])}
            candidate = parse_candidates([next(item["candidate"] for item in inputs_doc["planned"]
                                               if item["candidate"]["claim_id"] == claim)])[0]
            return claim, _validate_candidate(unit, settings, services, builds, executors, candidate, plan_entry,
                                              write_entry)

        results = dict(_pool(settings, list(planned), one))
        return {"artifact": _write_json(unit, "validate.json", {"schema": "appsec-review/poc-generation-validate/1",
                                                                "entries": results}),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    # -- compile ----------------------------------------------------------------------------------
    def compile_step(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        run_root = unit.job.run_root
        planned = read_bound_json(run_root, unit.output("plan.briefs")["artifact"])["entries"]
        validated = read_bound_json(run_root, unit.output("validate.policy")["artifact"])["entries"]
        builds = services.builds_factory(run_root)
        executors: dict[str, Any] = {}

        def one(claim: str) -> tuple[str, dict[str, Any]]:
            entry = validated[claim]
            if entry.get("terminal") is not None:
                return claim, {"terminal": entry["terminal"], "record": None}
            return claim, _compile_candidate(unit, settings, services, builds, executors, claim, planned[claim], entry)

        results = dict(_pool(settings, list(validated), one))
        return {"artifact": _write_json(unit, "compile.json", {"schema": "appsec-review/poc-generation-compile/1",
                                                               "entries": results}),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    # -- package ----------------------------------------------------------------------------------
    def package(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        run_root = unit.job.run_root
        document = inputs_document(unit)
        planned = read_bound_json(run_root, unit.output("plan.briefs")["artifact"])["entries"]
        written = read_bound_json(run_root, unit.output("write.poc_writer")["artifact"])["entries"]
        validated = read_bound_json(run_root, unit.output("validate.policy")["artifact"])["entries"]
        compiled = read_bound_json(run_root, unit.output("compile.build_check")["artifact"])["entries"]
        rows: dict[str, Any] = {}
        for item in document["planned"]:
            claim = item["candidate"]["claim_id"]
            rows[claim] = _package_candidate(run_root, settings, document, item, planned[claim], written.get(claim),
                                             validated[claim], compiled[claim])
        return {"artifact": _write_json(unit, "package.json", {"schema": "appsec-review/poc-generation-package/1",
                                                               "entries": rows}),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    # -- publish ----------------------------------------------------------------------------------
    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        run_root = unit.job.run_root
        loaded = unit.output("load.verify_inputs")
        document = inputs_document(unit)
        rows = read_bound_json(run_root, unit.output("package.files")["artifact"])["entries"]
        candidates = [rows[item["candidate"]["claim_id"]] for item in document["planned"]]
        counts: dict[str, int] = {status: 0 for status in STATUSES}
        for row in candidates:
            counts[row["status"]] += 1
        gaps = list(loaded["gaps"])
        gaps.extend(f"{row['claim_id']}: {row['status']}: {row['reason']}"[:300] for row in candidates
                    if row["status"] in GAP_STATUSES)
        summary = {
            "schema": POC_GENERATION_SCHEMA, "run_id": document["run_id"], "upstream": document["upstream"],
            "execution_policy": "nothing is linked into an executable and nothing is run",
            "settings_sha256": settings.settings_sha256(),
            "counts": {"candidates": len(candidates), "omitted": len(document["omitted"]), "by_status": counts},
            "candidates": candidates, "omitted_claims": document["omitted"], "gaps": gaps}
        errors = SchemaSet(services.repo(unit) / SCHEMA_ROOT).errors("poc-generation", summary)
        if errors:
            raise IntegrityError(f"PoC summary does not satisfy its schema: {'; '.join(errors[:3])}")
        reference = _write_json(unit, "poc-generation.json", summary)
        unit.job.events.write("POC_GENERATION_PUBLISHED", candidates=len(candidates),
                              verified=counts[COMPILE_VERIFIED], gap_count=len(gaps))
        return {"schema": POC_GENERATION_HANDOFF_SCHEMA, "artifact": reference, "counts": summary["counts"],
                "gate_handoff": document["upstream"]["gate_handoff"], "item_count": len(candidates),
                "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    units = (
        Unit("load.verify_inputs", load),
        Unit("plan.briefs", plan, ("load.verify_inputs",)),
        Unit("write.poc_writer", write, ("plan.briefs",)),
        Unit("validate.policy", validate, ("load.verify_inputs", "plan.briefs", "write.poc_writer")),
        Unit("compile.build_check", compile_step, ("plan.briefs", "validate.policy")),
        Unit("package.files", package, ("load.verify_inputs", "plan.briefs", "write.poc_writer", "validate.policy",
                                         "compile.build_check")),
        Unit("publish.publish_handoff", publish, ("load.verify_inputs", "package.files")),
    )
    package_dir = Path(__file__).parent
    implementation = None
    return Job(JOB_ID, "poc_generation", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=POC_GENERATION_HANDOFF_SCHEMA, implementation_identity=implementation,
               validation_identity=implementation, units=units, datasets=DATASETS, consumes=CONSUMES)


def _default_infer() -> Callable[..., Any]:
    from appsec_review.inference import infer
    return infer


def _core(services: Services, run_root: Path, document: Mapping[str, Any]) -> Any:
    manifest = document["upstream"]["manifest"]
    if services.core_factory is not None:
        return services.core_factory(run_root, manifest)
    from appsec_review.retrieval.core import RetrievalCore
    return RetrievalCore(Path(run_root).parent, document["run_id"], manifest_sha256=manifest["sha256"],
                         manifest_path=Path(run_root) / manifest["path"])


def _plan_candidate(unit: UnitContext, settings: PocGenerationSettings,
                    item: Mapping[str, Any], candidate: PocCandidate, builds: AcceptedBuilds, limits: Any,
                    services: Services, core_getter: Callable[[], Any], build_view: Callable[..., Any]
                    ) -> dict[str, Any]:
    run_root = unit.job.run_root
    entry: dict[str, Any] = {"terminal": None, "brief": None, "sink": None, "build": None}
    if candidate.judge_verdict not in settings.accepted_judge_verdicts:
        entry["terminal"] = _terminal(NOT_APPLICABLE, f"judge verdict {candidate.judge_verdict} is not configured "
                                      "for PoC generation")
        return entry
    if not candidate.poc_basis.usable:
        entry["terminal"] = _terminal(INSUFFICIENT_EVIDENCE,
                                      "the poc_basis lacks an entry point, a call path or a trigger")
        return entry
    record = item.get("package")
    package = (read_bound_json(run_root, {"path": record["path"], "sha256": record["sha256"]})
               if record else None)
    if package is None:
        entry["terminal"] = _terminal(INSUFFICIENT_EVIDENCE, "the review package of the claim is not in the run")
        return entry
    sink = services.sink_resolver(package)
    if sink is None:
        entry["terminal"] = _terminal(INSUFFICIENT_EVIDENCE, "the review package names no function that holds the sink")
        return entry
    entry["sink"] = sink
    located = builds.locate(sink["path"])
    if located.unit is None:
        entry["terminal"] = _terminal(NOT_APPLICABLE, located.reason)
        return entry
    entry["build"] = located.unit.identity()
    view = (services.view_factory or build_view)(package, core_getter(), limits)
    headers = Headers(located.unit)
    brief = build_brief(candidate, finding=item["finding"], package=package, view=view, sink=sink,
                        unit=located.unit, headers=headers, settings=settings)
    unresolved = [gap for gap in brief.gaps if gap.startswith("poc_basis label")]
    if unresolved and len(unresolved) >= len(candidate.poc_basis.entry) + len(candidate.poc_basis.path):
        entry["terminal"] = _terminal(INSUFFICIENT_EVIDENCE, "no poc_basis label resolves in the package view")
        return entry
    document_ref = _write_json(unit, f"briefs/{candidate.claim_id}.json", brief.document)
    entry["brief"] = document_ref
    entry["brief_facts"] = brief.document["build_facts"]
    entry["brief_gaps"] = list(brief.gaps)
    entry["expectation"] = {"sink_names": list(brief.sink_names), **dict(brief.expectation_inputs)}
    entry["package_sha256"] = record["sha256"]
    return entry


def _validate_candidate(unit: UnitContext, settings: PocGenerationSettings, services: Services, builds: AcceptedBuilds,
                        executors: dict[str, Any], candidate: PocCandidate, plan_entry: Mapping[str, Any],
                        write_entry: Mapping[str, Any]) -> dict[str, Any]:
    run_root = unit.job.run_root
    answer = WriterAnswer.from_result(write_entry["result"])
    located = builds.locate(plan_entry["sink"]["path"])
    if located.unit is None:
        return {"terminal": _terminal(NOT_APPLICABLE, located.reason)}
    build = located.unit
    headers = Headers(build)
    text = assemble(answer, settings, claim_id=candidate.claim_id, package_id=candidate.package_id)
    source_ref = _write_json(unit, f"sources/{candidate.claim_id}.json",
                             {"claim_id": candidate.claim_id, "language": build.command.language,
                              "source_name": source_file_name(answer, build.command.language), "text": text})
    violations = [*check_answer(answer, settings, headers), *file_violations(text, settings)]
    base = {"terminal": None, "answer": answer.record(), "source": source_ref, "violations": [], "ast": None,
            "policy_verdict": "not_evaluated", "source_sha256": hashlib.sha256(text.encode()).hexdigest()}
    if violations:
        records = [item.record() for item in violations]
        return {**base, "terminal": _terminal(POLICY_DENIED, "validators refused the answer before parsing: "
                                              + "; ".join(f"{v.rule}" for v in violations[:6])),
                "violations": records, "policy_verdict": "denied", "build": build.identity()}
    scratch_root = unit.unit_root / "scratch"
    scratch = None
    try:
        scratch = buildcheck.prepare(builds, build, scratch_root, name=candidate.claim_id, poc_text=text,
                                     settings=settings)
        executor = services.executor(unit, settings, build, executors)
        step = buildcheck.ast_step(executor, build, scratch, settings)
        reduced, why = buildcheck.reduced_ast(step)
    except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
        if isinstance(exc, IntegrityError):
            raise
        return {**base, "terminal": _terminal(ARTIFACT_GENERATED, f"the validators could not run: {exc}"[:300]),
                "gaps": [f"the build image or the accepted workspace was unavailable for the validators: "
                         f"{type(exc).__name__}"]}
    finally:
        if scratch is not None:
            shutil.rmtree(scratch.root, ignore_errors=True)
    if reduced is None:
        return {**base, "terminal": _terminal(ARTIFACT_GENERATED, f"the validators could not run: {why}"),
                "gaps": [why]}
    ast_ref = _write_json(unit, f"ast/{candidate.claim_id}.json", reduced)
    base["ast"] = ast_ref
    if reduced.get("compiler_exit_code") not in (0, None):
        diagnostics = buildcheck.diagnostics(step.stderr, scratch.names)
        return {**base, "terminal": _terminal(COMPILE_FAILED, "the functions do not parse: clang exited "
                                              f"{reduced.get('compiler_exit_code')}"),
                "diagnostics": diagnostics, "build": build.identity()}
    expectation = _expectation(plan_entry, answer)
    found = check_ast(reduced, settings, expectation)
    records = [item.record() for item in found]
    if found:
        return {**base, "terminal": _terminal(POLICY_DENIED, "validators refused the functions: "
                                              + "; ".join(sorted({v.rule for v in found})[:8])),
                "violations": records, "policy_verdict": "denied", "build": build.identity()}
    return {**base, "violations": [], "policy_verdict": "passed", "build": build.identity(),
            "unchecked_triggers": list(expectation.unchecked_triggers)}


def _expectation(plan_entry: Mapping[str, Any], answer: WriterAnswer) -> Any:
    expected = plan_entry["expectation"]
    return Brief({}, {"triggers": expected["triggers"], "path_calls": expected["path_calls"]},
                 tuple(expected["sink_names"]), ()).expectation(answer.functions)


def _compile_candidate(unit: UnitContext, settings: PocGenerationSettings, services: Services,
                       builds: AcceptedBuilds, executors: dict[str, Any], claim: str,
                       plan_entry: Mapping[str, Any], validated: Mapping[str, Any]) -> dict[str, Any]:
    run_root = unit.job.run_root
    located = builds.locate(plan_entry["sink"]["path"])
    if located.unit is None:
        return {"terminal": _terminal(NOT_APPLICABLE, located.reason), "record": None}
    build = located.unit
    source = read_bound_json(run_root, validated["source"])
    scratch = None
    try:
        scratch = buildcheck.prepare(builds, build, unit.unit_root / "scratch", name=claim, poc_text=source["text"],
                                     settings=settings)
        executor = services.executor(unit, settings, build, executors)
        outcome = buildcheck.check_build(executor, builds, build, scratch, settings, claim_id=claim)
    except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
        if isinstance(exc, IntegrityError):
            raise
        record = {"schema": buildcheck.COMPILE_SCHEMA, "claim_id": claim, "status": ARTIFACT_GENERATED,
                  "reason": f"the build image or workspace was unavailable: {type(exc).__name__}",
                  "execution_policy": "nothing is linked into an executable and nothing is run",
                  "build_unit": build.identity(), "steps": [], "objects": {}, "symbol_check": None,
                  "settings_sha256": settings.settings_sha256(), "gaps": [str(exc)[:200]]}
        return {"terminal": _terminal(ARTIFACT_GENERATED, record["reason"]),
                "record": _write_json(unit, f"compile/{claim}.json", record)}
    finally:
        if scratch is not None:
            shutil.rmtree(scratch.root, ignore_errors=True)
    unit.job.events.write("POC_COMPILE_CHECKED", claim_id=claim, status=outcome.status)
    return {"terminal": _terminal(outcome.status, outcome.reason),
            "record": _write_json(unit, f"compile/{claim}.json", outcome.record)}


def _package_candidate(run_root: Path, settings: PocGenerationSettings, document: Mapping[str, Any],
                       item: Mapping[str, Any], plan_entry: Mapping[str, Any], written: Mapping[str, Any] | None,
                       validated: Mapping[str, Any], compiled: Mapping[str, Any]) -> dict[str, Any]:
    candidate = parse_candidates([item["candidate"]])[0]
    terminal = compiled.get("terminal") or validated.get("terminal") or plan_entry.get("terminal")
    status, reason = terminal["status"], terminal["reason"]
    row: dict[str, Any] = {
        "claim_id": candidate.claim_id, "package_id": candidate.package_id, "state": candidate.state,
        "judge_verdict": candidate.judge_verdict,
        "finding_package": {"finding_package_id": candidate.finding_package_id,
                            "sha256": candidate.finding_package_sha256},
        "poc_basis_sha256": candidate.poc_basis.sha256, "status": status, "reason": reason[:300],
        "description": describe(status, None, reason), "functions": None, "files": None, "brief": plan_entry["brief"],
        "writer_receipt": (written or {}).get("receipt"), "gaps": list(validated.get("gaps", ()))[:5]}
    if status not in SOURCE_STATUSES or "answer" not in validated:
        return row
    answer = WriterAnswer.from_result({**validated["answer"], "claim": candidate.claim_id})
    source = read_bound_json(run_root, validated["source"])
    compile_record = (read_bound_json(run_root, compiled["record"]) if compiled.get("record") else
                      {"schema": buildcheck.COMPILE_SCHEMA, "claim_id": candidate.claim_id, "status": status,
                       "reason": reason, "steps": [], "objects": {}, "symbol_check": None,
                       "execution_policy": "nothing is linked into an executable and nothing is run",
                       "build_unit": validated.get("build"), "gaps": list(validated.get("gaps", ())),
                       "diagnostics": list(validated.get("diagnostics", ())),
                       "settings_sha256": settings.settings_sha256()})
    compile_record = {**compile_record, "status": status, "reason": reason}
    facts = _facts(plan_entry)
    provenance = {
        "claim_id": candidate.claim_id, "package_id": candidate.package_id,
        "finding_package": row["finding_package"], "state": candidate.state, "judge_verdict": candidate.judge_verdict,
        "poc_basis_sha256": candidate.poc_basis.sha256, "brief_sha256": plan_entry["brief"]["sha256"],
        "package_sha256": plan_entry.get("package_sha256"), "source_sha256": validated["source_sha256"],
        "settings_sha256": settings.settings_sha256(), "status": status,
        "guidance_bundle_sha256": (written or {}).get("guidance_bundle_sha256"),
        "writer_receipt_sha256": ((written or {}).get("receipt") or {}).get("sha256"),
        "model": {"provider": settings.writer.provider, "model": settings.writer.model,
                  "reasoning": settings.writer.reasoning},
        "upstream": document["upstream"], "source_tree": plan_entry.get("build"),
        "image": {"image_id": (plan_entry.get("build") or {}).get("image_id")}}
    files = write_candidate(
        run_root, candidate=candidate, finding=item["finding"], answer=answer, status=status, reason=reason,
        source_text=source["text"], language=source["language"], compile_record=compile_record,
        violations=validated.get("violations", []), policy_verdict=validated.get("policy_verdict", "not_evaluated"),
        provenance=provenance, facts=facts)
    row.update(files=files, description=describe(status, answer, reason),
               functions={"test_function": answer.test_name, "negative_control": answer.control_name,
                          "expected_observation": answer.expected_observation[:240]})
    return row


def _facts(plan_entry: Mapping[str, Any]) -> Mapping[str, Any] | None:
    brief = plan_entry.get("brief_facts")
    return brief if isinstance(brief, Mapping) else None
