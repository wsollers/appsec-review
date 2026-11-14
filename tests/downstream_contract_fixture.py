"""Small synthetic producer inputs with real review acceptance and consumer admission.

No target checkout, compiler, model or container is used. Original shard owners stay original;
the review binds their manifests rather than re-owning their bytes.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

from appsec_review.config import load_config
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.accepted_review import REVIEW_SCHEMA
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.datasets import DATASETS as REVIEW_DATASETS
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationRecord,
    RelationKind as IndexRelation, RetrievalCore, SourceLocation, write_manifest,
)
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.identity import make_id
from appsec_review.review.ledger import LedgerWriter, project
from appsec_review.review.models import (
    Admissibility, CellRecord, CellStatus, Claim, EvidenceRelation, JudgePredicateVerdict, JudgeVerdict,
    JudgeVerdictValue, Lane, Predicate, RelationKind, Role, SecurityPredicate,
)
from appsec_review.review.obligations import required_predicates_for
from appsec_review.review.packages import PackageSettings, assemble_packages, publish_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime import JobRunner
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.release_support import write_release

ROOT = Path(__file__).resolve().parents[1]
REVIEW = "job_inference_security_review"
LANGUAGE = "job_language_build"
SOURCE = "src/parse.c"
TEXT = "void parse(char *input) {\n  char out[8];\n  strcpy(out, input);\n}\n"
LEGACY_REVIEW_OUTPUTS = (
    "accepted_scope", "lead_triage", "review_packages", "review_cells",
    "claim_ledger", "attack_chains", "scores_and_findings",
)
COVERAGE_SHARDS = (
    ("job_tree_sitter_ast", "tree_sitter_coverage", "analysis", "tree-sitter-coverage-attempt_0001"),
    ("job_cpp_symbol_index", "clangd_coverage", "analysis", "clangd-coverage-attempt_0001"),
    ("job_clang_static_analysis", "clang_static_scope_coverage", "observations",
     "clang-static-coverage-attempt_0001"),
    ("job_cpg_analysis", "cpg_scope_coverage", "observations", "joern-coverage-attempt_0001"),
    ("job_svf_alias_analysis", "svf_alias_scope_coverage", "analysis", "svf-coverage-attempt_0001"),
    ("job_cpp_compiled_analysis", "cpp_blocked_branches", "analysis", "cpp-fixture-compiled"),
)


def configuration(tmp_path, *, engineering=()):
    text = (ROOT / "appsec-review.toml").read_text()
    for job in ("job_poc_generation", "job_remediation_planning", "job_remediation_validation",
                "job_dossier_publication"):
        pattern = rf"(?ms)(^\[jobs\.{job}\.settings\]\n)(.*?)(?=^\[|\Z)"
        text = re.sub(pattern, lambda match: match[1] + re.sub(
            r"(?m)^enabled = (true|false)$", "enabled = " + ("true" if job in engineering else "false"),
            match[2]), text)
    text = re.sub(r"(?ms)(^\[jobs\.job_dossier_publication\.settings\]\n.*?)(?=^\[|\Z)",
                  lambda match: match[0].replace("render_pdf = true", "render_pdf = false"), text)
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(text)
    config = load_config(config_path)
    write_release(tmp_path, builtin_registry().job_ids())
    return config


def fixture(tmp_path, *, engineering=(), coverage_producers=()):
    config = configuration(tmp_path, engineering=engineering)
    registry = builtin_registry()
    runner = JobRunner(config)
    run_id, root = runner.runs.create(datetime(2026, 11, 6, tzinfo=timezone.utc))
    runner._bind_configuration(root)
    target = tmp_path / "fixture-source"
    (target / "src").mkdir(parents=True)
    (target / SOURCE).write_text(TEXT)
    snapshot = "target-sha256:" + hashlib.sha256(TEXT.encode()).hexdigest()
    identities = {}
    shards = []

    def entity(kind, name, line=3, payload=None):
        logical = LogicalIdentity.derive(kind, snapshot, {"fixture": name})
        identities[name] = logical.value
        location = SourceLocation(snapshot, SOURCE, file_sha256(target / SOURCE),
                                  0, len(TEXT.encode()), line, line, 1, 1, {}, "fixture-exact", 1.0)
        return EntityRecord(logical, name, name, name, payload or {}, location)

    source_file = entity(EntityKind.SOURCE_FILE, "file", 1, {"language": "C"})
    spans = [entity(EntityKind.SOURCE_SPAN, "affected"), entity(EntityKind.SOURCE_SPAN, "entry", 1)]
    symbol = entity(EntityKind.SYMBOL, "parse", 1, {
        "producer": "codeql-export", "kind": "function", "qualified_name": "parse", "exact": True,
        "scope": {"scope_id": "scope-" + "1" * 24, "build_unit_id": "native-fixture"}, "gaps": []})
    observation = entity(EntityKind.TOOL_OBSERVATION, "copy", 3, {
        "tool_id": "tool-semgrep", "native_rule_id": "fixture-copy", "category": "source_sast",
        "native_severity": "HIGH", "message": "Synthetic unchecked copy", "language": "C",
        "rule_mapping": {"cwe": ["CWE-787"]}})
    rows = (
        ("job_target_catalog", "source_files", "source", "default", [source_file, *spans]),
        ("job_target_catalog", "declaration_symbols", "analysis", "default", [symbol]),
        ("job_target_catalog", "target_documents", "documents", "default", []),
        ("job_target_catalog", "components", "components", "default", []),
        ("job_target_catalog", "build_units", "build", "default", []),
        ("job_evidence_collection", "static_tool_observations", "observations", "semgrep", [observation]),
        ("job_code_graph_index", "code_graph_facts", "graph", "graph-fixture", [symbol]),
        ("job_review_data_indexing", "cross_domain_links", "links", "links-fixture", [
            EntityRecord(LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, snapshot, {"fixture": "dependency"}),
                         "dependency", "fixture", "fixture dependency", {"name": "fixture"})]),
        ("job_review_data_indexing", "precomputed_products", "precomputed", "qs-fixture", []),
        ("job_review_data_indexing", "dataset_inventory", "inventory", "default", []),
        ("job_source_history_analysis", "history_signals", "history", "git-history", [
            EntityRecord(LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, snapshot, {"fixture": "history"}),
                         "history", "unrelated history context", "one synthetic change", {"commits": 1})]),
    ) + tuple((*row, []) for row in COVERAGE_SHARDS if row[0] in coverage_producers)
    coverage_gaps = {row[1]: f"{row[1]}: fixture scope unavailable"
                     for row in COVERAGE_SHARDS if row[0] in coverage_producers}
    declarations = {}
    for owner, output_kind, index, shard_id, records in rows:
        declaration = next(item for item in registry.build(owner).datasets if item.output_kind == output_kind)
        declarations.setdefault(owner, []).append(declaration)
        path = root / f"data/indices/{index}/{shard_id}.sqlite"
        builder = IndexBuilder(path, name=index, fingerprint="a" * 64, target_snapshot=snapshot, shard_id=shard_id)
        for record in records:
            builder.add_entity(record)
        if index == "observations" and records:
            builder.add_relation(RelationRecord(IndexRelation.OBSERVED_AT, observation.identity.value,
                                                source_file.identity.value, True, 1.0))
        gap = coverage_gaps.get(output_kind, "fixture has no records in this scope")
        builder.add_coverage("fixture", "complete" if records else "unavailable", None if records else gap)
        shards.append(IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), "a" * 64,
                                    path.relative_to(root).as_posix(),
                                    {"job": owner, "unit": declaration.step + ".fixture"}, (), shard_id))
    manifest_path = root / "data/indices/manifests/fixture.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=shards)
    manifest = artifact_ref(root, manifest_path)

    def publish(job_id, outputs, *, datasets=None, upstream=None, artifacts=()):
        selected = tuple(registry.build(job_id).datasets if datasets is None else datasets)
        attempt = root / f"data/jobs/{job_id}/attempts/attempt_0001"
        atomic_json(attempt / "claim.json", {
            "dataset_contract": dataset_contract(job_id, sorted(
                {item.step for item in selected} | {key.split(".")[0] for key in outputs}), selected)})
        path = attempt / "handoff.json"
        write_fixture_handoff(root, path, {
            "job_id": job_id, "outputs": outputs, "artifacts": list(artifacts),
            "source_fingerprint": snapshot, "upstream_handoff_sha256": dict(upstream or {})})
        atomic_json(attempt.parent.parent / "latest.json", {
            "handoff_path": path.relative_to(root).as_posix(), "handoff_sha256": file_sha256(path)})
        return accepted_handoff(root, job_id)

    originals = {}
    for owner in declarations:
        own = [item for item in shards if item.producer["job"] == owner]
        outputs = {item.producer["unit"] + "_" + item.name: {
            "index_manifest": manifest, "index_identity": asdict(item)} for item in own}
        originals[owner] = publish(owner, outputs,
                                  artifacts=[{"path": item.relative_path, "sha256": item.sha256} for item in own])
    pointer = originals["job_review_data_indexing"]
    atomic_json(root / "data/indices/accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": pointer.path, "handoff_sha256": pointer.sha256,
        "manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    result = SimpleNamespace(config=config, runner=runner, root=root, target=target, snapshot=snapshot,
                             ids=identities, manifest=manifest, originals=originals, publish=publish,
                             coverage_gaps=coverage_gaps)
    result.review = publish_review(result)
    return result


def publish_review(case):
    """Bind this pre-audit producer's capabilities, not new outputs added to the real publisher."""
    root = case.root
    directory = root / "data/inputs/contract-review"
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    settings = case.config.job(REVIEW).typed_settings
    scope = accept_manifest(root)
    assembly = assemble_packages(scope, PackageSettings(hunt_max_units=0))
    manifest = publish_packages(assembly, directory / "packages")
    [package] = [item for item in assembly.packages if item.kind == "finding_lead"]

    def write(name, value):
        path = directory / name
        atomic_json(path, value)
        return artifact_ref(root, path)

    outputs = {"scope.accept_manifest": {"artifact": write("scope.json", {
        "manifest_path": scope.manifest_path.relative_to(root).as_posix(),
        "manifest_sha256": scope.manifest_sha256})}}
    for lane in ("lead", "hunt"):
        outputs[f"packages.assemble_{lane}_packages"] = {"artifact": write(lane + ".json", {
            "package_manifest": artifact_ref(root, manifest),
            "package_manifest_content_sha256": assembly.manifest["content_sha256"],
            "packages": [{"package_id": item.package_id, **artifact_ref(
                root, manifest.parent / "packages" / f"{item.package_id}.json")}
                for item in assembly.packages if item.lane == lane]})}
    writer = LedgerWriter(directory / "model-events.jsonl", "lead_review.teams")
    for gap in scope.gaps:
        writer.record_gap(gap.to_gap())
    claim_id = make_id("claim", 1, {"fixture": case.ids["affected"]})
    cells = {role: make_id("cell", 1, {"claim": claim_id, "role": role.value})
             for role in (Role.RED_TEAM_ANALYST, Role.INDEPENDENT_VERIFIER, Role.ADJUDICATION_JUDGE)}
    claim = Claim(claim_id, Lane.LEAD, package.package_id, (case.ids["affected"], case.ids["entry"]),
                  "CWE-787", SecurityPredicate.MEMORY_CORRUPTION, ("attacker_controls_request_field",),
                  "Synthetic copy violates the destination capacity.", origin_cell_ids=(cells[Role.RED_TEAM_ANALYST],))
    writer.propose_claim(claim)
    for role, cell_id in cells.items():
        receipt = write(f"{cell_id}.json", {"synthetic": True, "role": role.value})
        writer.cell_terminal(CellRecord(cell_id, Lane.LEAD, package.package_id, role, "memory_safety_native",
                                        "cpp_native_service", "fixture", claim_id, CellStatus.SUCCEEDED, 1, (),
                                        receipt["sha256"], (("A", "red"), ("B", "blue"))
                                        if role is Role.ADJUDICATION_JUDGE else None))
    for predicate in sorted(required_predicates_for(claim), key=lambda item: item.value):
        identity = case.ids["entry" if predicate is Predicate.ATTACKER_INPUT_CONTROL else "affected"]
        core = RetrievalCore(root.parent, root.name)
        excerpt = write(predicate.value + ".json", core.read_excerpt(identity=identity, context_lines=0))
        location = core.find(identity=identity, limit=1)["results"][0]["location"]
        writer.add_relation(EvidenceRelation(
            make_id("evidence_relation", 1, {"claim": claim_id, "predicate": predicate.value}), claim_id, predicate,
            RelationKind.SUPPORTS, identity, "source_span", Admissibility.DIRECT, "default",
            location["file_sha256"], f"{SOURCE}:1-3", True, cells[Role.INDEPENDENT_VERIFIER], excerpt["sha256"]))
    writer.judge_verdict(JudgeVerdict(
        make_id("judge_verdict", 1, {"claim": claim_id}), claim_id, JudgeVerdictValue.RED_CORRECT,
        (JudgePredicateVerdict(Predicate.AFFECTED_CONSTRUCT, JudgeVerdictValue.RED_CORRECT,
                               (case.ids["affected"],)),), "Synthetic agreed verdict.",
        cells[Role.ADJUDICATION_JUDGE], True))
    writer.seal()
    metadata = {"independence": {claim_id: [{"independent": True, "review_id": make_id("review", 1, {}),
                                           "provider_distinct": False, "verifier_model_distinct": False}]},
                "verifier_gaps": {}, "scope_entities": {claim_id: claim.affected_entities}}
    initial = stages.merge_verified([writer.path])
    decision_path = directory / "adjudications.jsonl"
    decisions = stages.apply_policy(metadata, project(initial.events), decision_path, "adjudicate.apply_policy")
    merged = stages.merge_verified([writer.path, decision_path])
    projection = project(merged.events)
    stages.write_ledger(merged, projection, directory / "ledger")
    outputs["publication.publish_claim_ledger"] = {"artifact": artifact_ref(root, directory / "ledger/ledger-head.json")}
    findings = stages.finding_packages(projection, decisions["adjudications"], metadata, (),
                                       manifest_sha256=scope.manifest_sha256, out_dir=directory / "findings",
                                       schemas=schemas)
    outputs["scoring.score_claims"] = {"artifact": write("scores.json", {"scores": []})}
    coverage = stages.coverage_matrix({}, assembly.manifest["units"])
    coverage_ref = {**write("coverage.json", coverage), "rows": len(coverage["rows"])}
    chains = write("chains.json", {
        "schema": "appsec-review/attack-chain-manifest/1", "run_id": root.name, "items": [], "gaps": [],
        "accounting": dict.fromkeys(("proposed", "admitted", "assessed", "capped", "rejected", "deduplicated",
                                    "seeds_received", "seeds_rejected"), 0),
        "exploration": {"expanded": 0, "limit": 1, "frontier": [], "frontier_truncated": False}})
    finding = json.loads((directory / "findings" / findings[0]["file"]).read_bytes())
    accounting = exact_accounting(projection, {value: Lane.LEAD for value in cells.values()},
                                  {package.package_id: Lane.LEAD},
                                  incomplete_gap_ratio=settings.lanes.incomplete_gap_ratio)
    basis = {"entry": [case.ids["entry"]], "path": [case.ids["parse"]],
             "trigger": [{"field": "input", "where": "parse", "constraint": "length > 8", "why": "capacity"}],
             "input_format": "synthetic bytes", "preconditions": ["attacker_controls_request_field"],
             "expected_observation": "bounded input exceeds capacity", "unknowns": []}
    # The candidate is synthetic model input; real accepted-review/PoC verifiers bind it to this finding.
    candidates = [{"claim_id": claim_id, "package_id": package.package_id, "state": finding["state"],
                   "judge_verdict": "red_correct", "poc_basis": {
                       "sha256": hashlib.sha256(canonical_json(basis)).hexdigest(), "brief": basis},
                   "finding_package": {"finding_package_id": finding["finding_package_id"],
                                       "sha256": findings[0]["sha256"]},
                   "evidence_refs": finding["direct_evidence"]}]
    handoff = stages.build_handoff(
        run_id=root.name, manifest_sha256=scope.manifest_sha256,
        configuration_sha256=file_sha256(root / "data/configuration/resolved.json"),
        projection=projection, accounting=accounting, shards=stages.shard_records(root, [writer.path, decision_path]),
        findings=findings, scores=(), package_manifest_sha256=assembly.manifest["content_sha256"],
        lead_package_manifest_sha256=assembly.manifest["content_sha256"], coverage=coverage_ref, possible=(),
        schemas=schemas, ship_block_policy_sha256=finding["ship_block"]["policy_sha256"],
        verification=settings.verifier_distinctness(), attack_chain_manifest=chains, poc_candidate_list=candidates)
    outputs["publication.publish_handoff"] = {"schema": REVIEW_SCHEMA,
                                              "artifact": write("review.json", handoff)}
    accepted = case.publish(
        REVIEW, outputs, datasets=tuple(row for row in REVIEW_DATASETS if row.output_kind in LEGACY_REVIEW_OUTPUTS),
        upstream={name: value.sha256 for name, value in case.originals.items()})
    from appsec_review.jobs.job_remediation_planning.inputs import load_review
    review = load_review(root, ROOT, case.config.job("job_remediation_planning").typed_settings.bounds)
    case.package = package.document()
    case.finding = finding
    case.accepted_review = accepted
    return review


def publish_build(case):
    base = case.root / "data/build/native/units/native-fixture"
    workspace = base / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / SOURCE).write_text(TEXT)
    files = {SOURCE: file_sha256(workspace / SOURCE)}
    manifest = base / "workspace-manifest.json"
    atomic_json(manifest, {"files": files})
    commands = base / "compile.json"
    atomic_json(commands, {"schema": "appsec-review/protected-compile-commands/1", "rows": [{
        "tool_kind": "compiler", "argv": ["/usr/bin/clang", "-c", "/workspace/" + SOURCE, "-o", "parse.o"],
        "inputs": [{"workspace_path": SOURCE}]}]})
    receipt = {"build_unit_id": "native-fixture", "family": "native", "terminal_status": "SUCCEEDED",
               "build_system": "cmake", "root": ".", "fingerprint": "b" * 64,
               "workspace": workspace.relative_to(case.root).as_posix(),
               "workspace_manifest": artifact_ref(case.root, manifest),
               "protected_compile_commands": artifact_ref(case.root, commands),
               "image": {"image_tag": "audit-buildenv-cpp:local", "image_id": "sha256:" + "a" * 64,
                         "user": "10001:10001"}, "recipe": {"build_dir": "."}, "artifacts": []}
    path = case.root / "data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/receipts.json"
    atomic_json(path, {"schema": "appsec-review/language-build-handoff/2", "receipts": [receipt]})
    return case.publish(LANGUAGE, {"acceptance.publish_handoff": {"artifact": artifact_ref(case.root, path)}})


def publish_poc(case, *, build_sha=None):
    from appsec_review.jobs.completion_contracts import nonexecution_assurance
    from appsec_review.jobs.engineering_contracts import POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA
    from appsec_review.jobs.job_poc_generation.statuses import STATUSES
    review = json.loads((case.root / case.review["inputs"]["review_handoff"]["path"]).read_bytes())
    [candidate] = review["poc_candidates"]
    status = "unsafe_to_attempt"
    row = {key: candidate[key] for key in ("claim_id", "package_id", "state", "judge_verdict", "finding_package")}
    row.update(poc_basis_sha256=candidate["poc_basis"]["sha256"], status=status,
               reason="Synthetic model declined runtime work.", description="Bounded fixture outcome.",
               functions=None, files=None, brief=None, writer_receipt=None, gaps=["fixture_declined"],
               **nonexecution_assurance())
    document = {"schema": POC_GENERATION_SCHEMA, "run_id": case.root.name,
                "upstream": {"review_job_handoff": case.review["inputs"]["job_handoff"],
                             "review_handoff": case.review["inputs"]["review_handoff"],
                             "manifest": case.manifest, "language_build_handoff_sha256": build_sha},
                "execution_policy": "nothing is linked into an executable and nothing is run",
                "settings_sha256": "a" * 64,
                "counts": {"candidates": 1, "omitted": 0, "by_status": {name: int(name == status) for name in STATUSES}},
                "candidates": [row], "omitted_claims": [], "gaps": ["fixture_declined"],
                **nonexecution_assurance()}
    schema = SchemaSet(ROOT / "docs/schemas/poc-generation")
    schema.validate("poc-generation", document)
    path = case.root / "data/jobs/job_poc_generation/attempts/attempt_0001/steps/publish/tasks/publish_handoff/summary.json"
    atomic_json(path, document)
    return case.publish("job_poc_generation", {"publish.publish_handoff": {
        "schema": POC_GENERATION_HANDOFF_SCHEMA, "artifact": artifact_ref(case.root, path),
        "terminal_status": "COMPLETED_WITH_GAPS", "gaps": document["gaps"], "item_count": 1}},
        upstream={REVIEW: case.accepted_review.sha256, **({LANGUAGE: build_sha} if build_sha else {})})
