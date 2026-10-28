"""Schemas, the writer skill's worked examples and the wiring of job_poc_generation into the graph.

The schemas are cross-checked against ``jsonschema`` (the job uses a closed subset validator); the skill's
good example is the hand-written reproducer that compiled in the build image and its non-examples are the
variants the validators refuse, so the guidance can never drift from the contract it teaches.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.cli import GRAPH_JOB_IDS, MANUAL_JOB_IDS, POST_INDEX_JOB_IDS, main
from appsec_review.config import load_config
from appsec_review.guidance import load_registry
from appsec_review.guidance.skills import runtime_skill_records
from appsec_review.indexing import input_matrix
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.completion_contracts import nonexecution_assurance
from appsec_review.jobs.job_poc_generation import JOB_ID, build_job, buildcheck
from appsec_review.jobs.job_poc_generation.datasets import CONSUMES, DATASETS
from appsec_review.jobs.job_poc_generation.policy import Expectation, check_ast, numeric_requirement
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble, check_answer
from appsec_review.jobs.job_poc_generation.statuses import DECLINES, STATUSES
from appsec_review.orchestration.topology import describe_wave1, wave1_dependencies
from appsec_review.runtime import active_job_ids, job_is_enabled
from appsec_review.runtime.datasets import validate_declarations
from appsec_review.runtime.launch import TARGET_JOBS
from appsec_review.runtime.registry import builtin_registry
from appsec_review.review.models import IntegrityError
from tests import poc_support
from tests.fixtures.poc_generation import relay

ROOT = Path(__file__).parents[1]
SCHEMA_ROOT = ROOT / "docs" / "schemas" / "poc-generation"
SCHEMAS = SchemaSet(SCHEMA_ROOT)
DOCUMENTS = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in sorted(SCHEMA_ROOT.glob("*.json"))}
REGISTRY = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in DOCUMENTS.values())
SETTINGS = poc_support.settings()
SKILL = (ROOT / "pipeline" / "skills" / "poc-writer" / "SKILL.md").read_text(encoding="utf-8")
CLAIM = "claim-" + "1" * 64
FINDING = "finding-" + "3" * 64


def jsonschema_errors(name: str, value) -> list:
    return list(Draft202012Validator(DOCUMENTS[f"{name}.schema.json"], registry=REGISTRY).iter_errors(value))


# ------------------------------------------------------------------------------------------------ schemas


def test_every_schema_is_a_valid_draft_2020_12_document_with_a_unique_id() -> None:
    assert set(DOCUMENTS) == {"common.schema.json", "writer-answer.schema.json", "poc-candidate.schema.json",
                              "poc-generation.schema.json", "compile-record.schema.json", "provenance.schema.json"}
    for document in DOCUMENTS.values():
        Draft202012Validator.check_schema(document)
    assert len({document["$id"] for document in DOCUMENTS.values()}) == len(DOCUMENTS)
    assert set(DOCUMENTS["common.schema.json"]["$defs"]["status"]["enum"]) == set(STATUSES)


def candidate(**changes) -> dict:
    row = {"claim_id": CLAIM, "package_id": "finding_lead-" + "2" * 64, "state": "confirmed",
           "judge_verdict": "red_correct", "finding_package": {"finding_package_id": FINDING, "sha256": "4" * 64},
           "poc_basis_sha256": "5" * 64, "status": "compile_verified", "reason": "the functions compile",
           "description": "compile_verified: poc_x (negative control poc_y).",
           "functions": {"test_function": "poc_x", "negative_control": "poc_y", "expected_observation": "overflow"},
           "files": {key: {"path": f"data/poc/{CLAIM}/{key}.json", "sha256": "6" * 64}
                     for key in ("source", "compile", "readme", "provenance")},
           "brief": None, "writer_receipt": None, "gaps": [], **nonexecution_assurance()}
    row.update(changes)
    return row


def summary(*rows) -> dict:
    counts = {status: 0 for status in STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    ref = {"path": "data/jobs/x/handoff.json", "sha256": "7" * 64}
    return {"schema": "appsec-review/poc-generation/2", "run_id": "2026-10-21-0001",
            "upstream": {"review_job_handoff": ref,
                         "review_handoff": ref, "manifest": ref, "language_build_handoff_sha256": None},
            "execution_policy": "nothing is linked into an executable and nothing is run",
            "settings_sha256": "8" * 64, "counts": {"candidates": len(rows), "omitted": 0, "by_status": counts},
            "candidates": list(rows), "omitted_claims": [], "gaps": [], **nonexecution_assurance()}


def mutated(document, *edits):
    for path, value in edits:
        node = document
        for key in path[:-1]:
            node = node[key]
        if value is KeyError:
            node.pop(path[-1])
        else:
            node[path[-1]] = value
    return document


def agree(name: str, valid, invalid) -> None:
    assert SCHEMAS.errors(name, valid) == [] and jsonschema_errors(name, valid) == []
    for document in invalid:
        assert SCHEMAS.errors(name, document), document
        assert jsonschema_errors(name, document), document


def test_the_writer_answer_schema_accepts_functions_and_declines_and_refuses_the_rest() -> None:
    good = relay.answer()["result"]
    decline = {"decline": {"status": "unsafe_to_attempt", "why": "needs a socket"}}
    invalid = [mutated(deepcopy(good), (("test_function",), KeyError)),
               mutated(deepcopy(good), (("extra",), 1)),
               mutated(deepcopy(good), (("breakpoints",), [{"function": "f", "line": 0, "why": "x"}])),
               mutated(deepcopy(good), (("test_function", "source"), "")),
               mutated(deepcopy(decline), (("decline", "status"), "policy_denied")),
               mutated(deepcopy(decline), (("decline", "why"), "")), {}, [], "x"]
    agree("writer-answer", good, invalid)
    assert SCHEMAS.errors("writer-answer", decline) == [] and jsonschema_errors("writer-answer", decline) == []
    # names are judged by the validators, not by the schema, so a writer cannot repair its way past them
    assert SCHEMAS.errors("writer-answer", relay.answer(test_name="main")["result"]) == []


def test_the_summary_schema_agrees_with_jsonschema() -> None:
    good = summary(candidate(), candidate(claim_id="claim-" + "2" * 64, status="not_applicable", functions=None,
                                          files=None, reason="judge verdict partly"))
    invalid = [mutated(deepcopy(good), (("candidates", 0, "status"), "mostly_fine")),
               mutated(deepcopy(good), (("candidates", 0, "description"), "x" * 301)),
               mutated(deepcopy(good), (("candidates", 0, "files", "source", "path"), "../escape")),
               mutated(deepcopy(good), (("execution_policy",), "the pipeline runs it")),
               mutated(deepcopy(good), (("counts", "by_status", "compile_verified"), -1)),
               mutated(deepcopy(good), (("upstream",), KeyError)), mutated(deepcopy(good), (("extra",), True))]
    agree("poc-generation", good, invalid)


def test_the_compile_record_and_provenance_written_by_the_job_satisfy_their_schemas(tmp_path) -> None:
    from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
    from appsec_review.jobs.job_poc_generation.package import write_candidate
    from tests.test_poc_generation_units import candidate_entry

    workspace, manifest = poc_support.relay_workspace(tmp_path / "w")
    unit = poc_support.relay_unit(workspace, manifest)
    builds = poc_support.builds(unit)
    answer = WriterAnswer.from_result(relay.answer()["result"])
    text = assemble(answer, SETTINGS, claim_id=CLAIM, package_id="finding_lead-" + "2" * 64)
    scratch = buildcheck.prepare(builds, unit, tmp_path / "s", name="c", poc_text=text, settings=SETTINGS)
    outcome = buildcheck.check_build(poc_support.FakeExecutor(), builds, unit, scratch, SETTINGS, claim_id=CLAIM)
    record = {**outcome.record, "policy": {"schema": "appsec-review/poc-policy/1", "verdict": "passed",
                                           "violations": []}}
    agree("compile-record", record, [mutated(deepcopy(record), (("status",), "done")),
                                     mutated(deepcopy(record), (("steps", 0, "exit_code"), "zero")),
                                     mutated(deepcopy(record), (("execution_policy",), KeyError)),
                                     mutated(deepcopy(record), (("policy", "verdict"), "maybe"))])
    (candidate_,) = parse_candidates([candidate_entry(claim_id=CLAIM)])
    run_root = tmp_path / "run"
    arguments = dict(
        candidate=candidate_, finding={"title": "memory_corruption"}, answer=answer, status="compile_verified",
        reason="ok", source_text=text, language="cxx", compile_record=outcome.record, violations=[],
        policy_verdict="passed", facts=unit.command.facts(),
        provenance={"claim_id": CLAIM, "package_id": candidate_.package_id, "run_id": "test-run",
                    "finding_package": {"finding_package_id": FINDING, "sha256": "4" * 64}, "state": "confirmed",
                    "judge_verdict": "red_correct", "poc_basis_sha256": "5" * 64, "brief_sha256": "6" * 64,
                    "package_sha256": "7" * 64, "source_sha256": "8" * 64, "settings_sha256": "9" * 64,
                    "status": "compile_verified", "guidance_bundle_sha256": None, "writer_receipt_sha256": None,
                    "model": {"provider": "p", "model": "m", "reasoning": "r"}, "upstream": {},
                    "source_tree": None, "image": {"image_id": None}})
    first_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "a1" / "candidates"
    files = write_candidate(run_root, output_root=first_root, **arguments)
    original = {key: (run_root / ref["path"]).read_bytes() for key, ref in files.items()}
    with pytest.raises(IntegrityError, match="immutable"):
        write_candidate(run_root, output_root=first_root, **arguments)
    retried = write_candidate(run_root, output_root=first_root.parent.parent / "a2" / "candidates", **arguments)
    assert retried["source"]["path"] != files["source"]["path"]
    assert all((run_root / ref["path"]).read_bytes() == original[key] for key, ref in files.items())
    provenance = json.loads((run_root / files["provenance"]["path"]).read_text(encoding="utf-8"))
    agree("provenance", provenance, [mutated(deepcopy(provenance), (("claim_id",), "claim-x")),
                                     mutated(deepcopy(provenance), (("files",), KeyError))])
    written = json.loads((run_root / files["compile"]["path"]).read_text(encoding="utf-8"))
    assert SCHEMAS.errors("compile-record", written) == [] and written["policy"]["verdict"] == "passed"
    assert sorted(path.name for path in (run_root / files["source"]["path"]).parent.iterdir()) == [
        "README.md", "compile.json", "poc_parse_header_overlong_name.cpp", "provenance.json"]


# ------------------------------------------------------------------------------------- the skill's examples


def blocks(part: str) -> list[dict]:
    return [json.loads(block) for block in re.findall(r"```json\n(.*?)\n```", part, re.S)]


GOOD_PART, _, BAD_PART = SKILL.partition("Do not do this")


def test_the_skill_is_a_registered_runtime_worker_skill_for_this_job_only() -> None:
    records = runtime_skill_records(load_registry(ROOT))
    assert records["poc-writer"] == {"path": "pipeline/skills/poc-writer/SKILL.md", "jobs": (JOB_ID,)}
    assert load_registry(ROOT)["roles"]["poc_writer"] == {"responsibility": load_registry(ROOT)["roles"][
        "poc_writer"]["responsibility"]}
    assert (ROOT / "pipeline" / "prompt-fragments" / "roles" / "poc_writer.md").is_file()


def test_the_skills_good_example_is_the_reproducer_the_validators_and_the_build_image_accepted() -> None:
    good = blocks(GOOD_PART)
    finals = [item["result"] for item in good if item["action"] == "final"]
    assert good[0] == relay.answer()
    for result in finals:
        assert SCHEMAS.errors("writer-answer", result) == []
    answer = WriterAnswer.from_result(good[0]["result"])
    assert answer.test_source == relay.GOOD_TEST and answer.control_source == relay.GOOD_CONTROL

    class Resolver:
        def resolve(self, include):
            return include

    assert check_answer(answer, SETTINGS, Resolver()) == []
    expectation = Expectation(answer.functions, (relay.SINK,), frozenset(), (numeric_requirement("greater than 16"),))
    assert check_ast(poc_support.ast_document("good"), SETTINGS, expectation) == []
    declines = [item["result"]["decline"] for item in good if "decline" in item.get("result", {})]
    assert declines and {item["status"] for item in declines} <= set(DECLINES)
    retrieve = next(item for item in good if item["action"] == "retrieve")
    assert [request["tool"] for request in retrieve["requests"]] == ["find_declaration", "read_source"]


def test_each_non_example_in_the_skill_is_refused_by_a_validator() -> None:
    bad = blocks(BAD_PART)
    assert len(bad) == 5
    expectation = Expectation(FUNCTIONS := (relay.TEST_NAME, relay.CONTROL_NAME), (relay.SINK,), frozenset(),
                              (numeric_requirement("greater than 16"),))

    class Resolver:
        known = {"relay/relay.hpp"}

        def resolve(self, include):
            return include if include in self.known else None

    refused = {}
    for index, item in enumerate(bad):
        assert SCHEMAS.errors("writer-answer", item["result"]) == []          # well formed, and still refused
        answer = WriterAnswer.from_result(item["result"])
        text = [violation.rule for violation in check_answer(answer, SETTINGS, Resolver())]
        variant = next((name for name, (test, control, _rule) in relay.VARIANTS.items()
                        if test == answer.test_source and control == answer.control_source), None)
        refused[index] = (variant, text, [violation.rule for violation in check_ast(
            poc_support.ast_document(variant), SETTINGS, expectation)] if variant != "good" else [])
    assert [value[0] for value in refused.values()] == ["main_defined", "system_call", "ifstream", "good",
                                                        "never_calls_sink"]
    # the header example is refused by the text check (an include outside the project); the rest by the AST
    assert refused[3][1] == ["include"] and all(refused[i][2] for i in (0, 1, 2, 4))
    assert FUNCTIONS


# ------------------------------------------------------------------------------------------------- wiring


def test_the_job_is_registered_configured_and_enabled_compile_only_by_default() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    assert JOB_ID in builtin_registry().job_ids() and config.job(JOB_ID).name == "poc_generation"
    assert job_is_enabled(config, JOB_ID) is True
    assert JOB_ID in active_job_ids(config, (*GRAPH_JOB_IDS, *POST_INDEX_JOB_IDS))
    assert POST_INDEX_JOB_IDS.index("job_inference_security_review") < POST_INDEX_JOB_IDS.index(JOB_ID) < \
        POST_INDEX_JOB_IDS.index("job_final_publication_gate") < POST_INDEX_JOB_IDS.index("job_final_report_publication")
    assert {unit.unit_id for unit in build_job().units} == {
        "load.verify_inputs", "plan.briefs", "write.poc_writer", "validate.policy", "compile.build_check",
        "package.files", "publish.publish_handoff"}


def test_the_job_reads_no_target_tree_so_it_is_not_a_target_job() -> None:
    # It uses the run's accepted native build workspace (hash-checked) and the retrieval core pinned to the
    # accepted manifest, exactly like the review, the gate and the report.
    assert JOB_ID not in TARGET_JOBS and JOB_ID in set(builtin_registry().job_ids()) - TARGET_JOBS


def test_poc_precedes_the_gate_and_the_report_reads_only_the_gate() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    enabled = {job for job in registry.job_ids() if job_is_enabled(config, job)}
    off = wave1_dependencies(enabled - {JOB_ID})
    on = wave1_dependencies(enabled | {JOB_ID})
    assert JOB_ID not in off and off["job_final_report_publication"] == ("job_final_publication_gate",)
    assert "job_inference_security_review" in on[JOB_ID] and "job_final_publication_gate" not in on[JOB_ID]
    assert on["job_final_report_publication"] == ("job_final_publication_gate",)
    order = list(on)
    assert order.index(JOB_ID) < order.index("job_final_publication_gate") < order.index("job_final_report_publication")
    # one terminal job in both graphs
    for graph in (off, on):
        depended = {dependency for values in graph.values() for dependency in values}
        assert set(graph) - depended == {"job_final_report_publication"}


def test_a_disabled_poc_job_still_gets_its_upstream_handoffs_for_a_manual_run() -> None:
    from dataclasses import replace
    config = load_config(ROOT / "appsec-review.toml")
    poc = config.job(JOB_ID)
    config = replace(config, jobs={**config.jobs, JOB_ID: replace(poc, settings={**poc.settings, "enabled": False})})
    registry = builtin_registry()
    assert JOB_ID not in [job["job_id"] for job in describe_wave1(config, registry)["jobs"]]
    entry = next(job for job in describe_wave1(config, registry, include={JOB_ID})["jobs"] if job["job_id"] == JOB_ID)
    assert "job_final_publication_gate" not in entry["dependencies"]
    assert {"job_inference_security_review", "job_language_build"} <= set(
        entry["upstream_handoffs"])
    assert MANUAL_JOB_IDS == {JOB_ID}


def test_direct_dispatch_refuses_other_disabled_jobs_but_not_the_manual_poc_job() -> None:
    with pytest.raises(ValueError, match="job is disabled by configuration: job_cpg_analysis"):
        main(["--config", str(ROOT / "appsec-review.toml"), "run", "job_cpg_analysis"])
    # the manual job is not refused as disabled: dispatch proceeds to the next argument check (a run id is needed)
    with pytest.raises(SystemExit):
        main(["--config", str(ROOT / "appsec-review.toml"), "run", JOB_ID, "--upstream-from-run"])


def test_the_dataset_declarations_are_valid_and_name_the_real_steps_and_consumers() -> None:
    validate_declarations(JOB_ID, DATASETS)
    config = load_config(ROOT / "appsec-review.toml")
    steps = set(config.job(JOB_ID).steps)
    assert {item.step for item in DATASETS} <= steps
    assert {item.disposition for item in DATASETS} == {"artifact_only", "protected"}
    assert set(CONSUMES) == {"job_inference_security_review", "job_language_build"}
    assert "job_poc_generation" in __import__(
        "appsec_review.jobs.job_final_publication_gate.datasets", fromlist=["CONSUMES"]).CONSUMES


def test_the_input_matrix_names_the_job_as_the_producer_of_its_outputs() -> None:
    rows = {row[0]: row for row in input_matrix.INPUT_SOURCES}
    assert rows["poc_generation"][1] == (JOB_ID,) and rows["poc_generation"][2] == "artifact_only"


def test_the_committed_reproducer_file_is_exactly_what_the_job_assembles_from_the_recorded_answer() -> None:
    """``relay_overflow.cpp`` is the hand-written reproducer for packet.cpp:16 as a developer would receive it."""
    answer = WriterAnswer.from_result(relay.answer()["result"])
    text = assemble(answer, SETTINGS, claim_id="claim-" + "0" * 64, package_id="finding_lead-" + "0" * 64)
    assert (poc_support.FIXTURES / "relay_overflow.cpp").read_text(encoding="utf-8") == text
    assert "int main" not in text and "main(" not in text
