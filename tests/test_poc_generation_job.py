"""job_poc_generation end to end over the offline review chain.

The scripted inference review produces the accepted review; ``poc_candidates`` is written into its handoff
where the judge work will write it; the gate and then the PoC job run through the application runner with
a scripted writer, a recording fake build container and an accepted-build lookup over a copy of
cpp-multivuln; the final report then reads the PoC handoff. Nothing is a model, a container or Dagster,
and nothing produced is ever executed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.inference.recording import ModelReplayMiss
from appsec_review.jobs.job_final_report_publication.report import POC_REASON
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation.datasets import DATASETS
from appsec_review.review.models import IntegrityError
from appsec_review.storage import file_sha256
from tests import poc_support
from tests.final_report_support import GATE, REPORT
from tests.fixtures.poc_generation import relay
from tests.poc_chain import POC, Writer, build_chain, generated_text, ast_by_source

ROOT = Path(__file__).parents[1]
CLAIM_DIR = f"data/jobs/{POC}/attempts"


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    root = tmp_path_factory.mktemp("poc-chain")
    return build_chain(root / "review", root / "logs", max_candidates=2)


def freeze(chain, tmp_path_factory, **values) -> SimpleNamespace:
    """A copy of the finished run, so a later scenario's restore cannot disturb what these tests read."""
    target = tmp_path_factory.mktemp("frozen") / "runs"
    shutil.copytree(chain.run_root.parent, target)
    return SimpleNamespace(run_root=target / chain.run_root.name, chain=chain, **values)


def read(frozen, relative):
    return json.loads((frozen.run_root / relative).read_text(encoding="utf-8"))


def attempt_root(frozen, job=POC):
    return sorted((frozen.run_root / "data" / "jobs" / job / "attempts").iterdir())[-1]


def unit_json(frozen, unit, name, job=POC):
    step, task = unit.split(".")
    return json.loads((attempt_root(frozen, job) / "steps" / step / "tasks" / task / name).read_text(encoding="utf-8"))


def handoff_of(frozen, job=POC):
    return read(frozen, read(frozen, f"data/jobs/{job}/latest.json")["handoff_path"])


def summary_of(frozen):
    published = handoff_of(frozen)["outputs"]["publish.publish_handoff"]
    return published, read(frozen, published["artifact"]["path"])


def rows_of(frozen):
    return {row["claim_id"]: row for row in summary_of(frozen)[1]["candidates"]}


def scenario(chain, tmp_path_factory, candidates, scripts, executor=None, *, report=False, **kwargs):
    """Restore the accepted review, add ``candidates``, run the gate, the PoC job and (optionally) the report."""
    chain.prepare(candidates)
    writer = Writer(scripts)
    executor = executor or poc_support.FakeExecutor(ast_by_source)
    outcome = chain.run_poc(writer, executor, **kwargs)
    if report:
        chain.run_report()
    return freeze(chain, tmp_path_factory, writer=writer, executor=executor, outcome=outcome,
                  candidates=candidates, unit=chain.built["unit"])


# --------------------------------------------------------------------------------------------- the mixed run


@pytest.fixture(scope="module")
def mixed(chain, tmp_path_factory):
    """Candidate 1 is good, candidate 2 carries the judge verdict ``partly``, the third is beyond the bound."""
    a = chain.findings[0]["claim_id"]
    candidates = [chain.candidate(0), chain.candidate(1, basis={**chain.candidate(1)["poc_basis"]["brief"], "trigger": []}),
                  chain.candidate(2)]
    return scenario(chain, tmp_path_factory, candidates, {a: [relay.answer()]}, report=True)


def test_the_job_publishes_one_handoff_with_every_attempted_candidate_and_names_the_bound(mixed) -> None:
    published, summary = summary_of(mixed)
    assert published["schema"] == "appsec-review/poc-generation-handoff/2" and published["item_count"] == 2
    assert set(published) == {"schema", "artifact", "item_count", "gaps", "terminal_status"}   # what a handoff keeps
    counts = summary["counts"]
    assert counts["candidates"] == 2 and counts["omitted"] == 1
    assert counts["by_status"]["compile_verified"] == 1 and counts["by_status"]["insufficient_evidence"] == 1
    assert any(gap.startswith("candidate_bound_reached") for gap in published["gaps"])
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert [row["claim_id"] for row in summary["candidates"]] == [mixed.candidates[0]["claim_id"],
                                                                  mixed.candidates[1]["claim_id"]]
    assert summary["omitted_claims"] == [mixed.candidates[2]["claim_id"]]
    assert "gate_handoff" not in summary["upstream"]
    assert summary["upstream"]["review_handoff"]["path"].startswith("data/jobs/job_inference_security_review/")
    assert summary["execution_policy"] == "nothing is linked into an executable and nothing is run"


def test_a_verified_candidate_has_the_four_files_and_the_handoff_binds_their_hashes(mixed) -> None:
    claim = mixed.candidates[0]["claim_id"]
    row = rows_of(mixed)[claim]
    assert row["status"] == "compile_verified" and row["finding_package"]["finding_package_id"].startswith("finding-")
    directory = (mixed.run_root / row["files"]["source"]["path"]).parent
    assert sorted(path.name for path in directory.iterdir()) == [
        "README.md", "compile.json", f"{relay.TEST_NAME}.cpp", "provenance.json"]
    for key, name in (("source", f"{relay.TEST_NAME}.cpp"), ("compile", "compile.json"), ("readme", "README.md"),
                      ("provenance", "provenance.json")):
        reference = row["files"][key]
        assert reference["path"].startswith(CLAIM_DIR + "/")
        assert reference["path"].endswith(f"/candidates/{claim}/{name}")
        assert file_sha256(mixed.run_root / reference["path"]) == reference["sha256"]
    source = (mixed.run_root / row["files"]["source"]["path"]).read_text(encoding="utf-8")
    assert source == generated_text(claim, mixed.candidates[0]["package_id"], relay.GOOD_TEST, relay.GOOD_CONTROL)
    assert "int main" not in source and source.count("#include") == 2
    assert row["functions"] == {"test_function": relay.TEST_NAME, "negative_control": relay.CONTROL_NAME,
                                "expected_observation": row["functions"]["expected_observation"]}
    assert len(row["description"]) <= 300 and row["description"].startswith("compile_verified: poc_parse_header")
    assert row["execution"] == "not_performed_by_policy" and row["runtime_verified"] is False


def test_compile_json_records_the_policy_the_commands_and_the_symbol_check(mixed) -> None:
    claim = mixed.candidates[0]["claim_id"]
    record = read(mixed, rows_of(mixed)[claim]["files"]["compile"]["path"])
    assert record["status"] == "compile_verified" and record["policy"]["verdict"] == "passed"
    assert [step["name"] for step in record["steps"]] == [
        "syntax", "object", "sanitized_object", "undefined_symbols", "project_symbols", "runtime_symbols"]
    assert all(step["exit_code"] == 0 for step in record["steps"])
    assert record["symbol_check"]["unresolved"] == [] and record["translation_unit"]["basis"] == "exact"
    assert record["translation_unit"]["source"] == "src/packet.cpp" and "argv" not in json.dumps(record)
    schemas = SchemaSet(ROOT / "docs" / "schemas" / "poc-generation")
    assert schemas.errors("compile-record", record) == []


def test_the_readme_and_provenance_tie_the_files_to_their_inputs(mixed) -> None:
    claim = mixed.candidates[0]["claim_id"]
    row = rows_of(mixed)[claim]
    readme = (mixed.run_root / row["files"]["readme"]["path"]).read_text(encoding="utf-8")
    assert "`compile_verified`" in readme and relay.TEST_NAME in readme and relay.CONTROL_NAME in readme
    assert "It never ran it" in readme and "does not contradict the finding" in readme
    assert "## Breakpoints" in readme and "relay::parse_header" in readme and "## Source" in readme
    provenance = read(mixed, row["files"]["provenance"]["path"])
    assert SchemaSet(ROOT / "docs" / "schemas" / "poc-generation").errors("provenance", provenance) == []
    assert provenance["source_sha256"] == row["files"]["source"]["sha256"]
    assert provenance["brief_sha256"] == row["brief"]["sha256"] and provenance["writer_receipt_sha256"] == \
        row["writer_receipt"]["sha256"]
    assert provenance["poc_basis_sha256"] == mixed.candidates[0]["poc_basis"]["sha256"]
    assert provenance["package_sha256"] and provenance["settings_sha256"] == poc_support.settings().settings_sha256()
    assert (mixed.run_root / "data" / "guidance" / provenance["guidance_bundle_sha256"] / "skill.md").is_file()
    assert provenance["model"]["model"] == "claude-haiku-5-5"
    assert provenance["source_tree"]["build_unit_id"].startswith("build-unit-")
    assert provenance["upstream"]["review_handoff"] == summary_of(mixed)[1]["upstream"]["review_handoff"]


def test_the_brief_carries_the_finding_the_basis_the_declarations_and_the_build_facts(mixed) -> None:
    claim = mixed.candidates[0]["claim_id"]
    row = rows_of(mixed)[claim]
    brief = read(mixed, row["brief"]["path"])
    assert brief["schema"] == "appsec-review/poc-writer-brief/1" and brief["claim"]["state"] == "confirmed"
    assert brief["poc_basis"] == mixed.candidates[0]["poc_basis"]["brief"]
    assert sorted(row["label"] for row in brief["poc_basis_labels"].values()) == ["E1", "F1", "F2"]
    assert brief["sink"] == {"name": relay.SINK, "path": "src/packet.cpp", "line": 7, "symbol": "asr:symbol:" + "4" * 64}
    text = "\n".join(line for item in brief["declarations"] for line in item["text"])
    assert "parse_header(const std::uint8_t *data, std::size_t size, Header &out);" in text and "char name[16];" in text
    facts = brief["build_facts"]
    assert facts["compiler"] == "clang++" and facts["standard"] == "-std=c++17" and facts["include_paths"] == [
        "target:include"]
    assert "-DNDEBUG" in facts["defines"] and brief["limits"]["max_function_lines"] == 80
    assert "memset" in brief["limits"]["allowed_standard_calls"] and brief["gaps"] == []
    request = mixed.writer.requests[0]
    assert request.task_input["input"] == brief and request.task_input["output_schema"] == \
        "appsec-review/poc-writer-answer/1"
    assert len(mixed.writer.requests) == 1                        # only the attempted, applicable candidate


def test_a_candidate_the_job_cannot_attempt_gets_a_status_and_no_files(mixed) -> None:
    claim = mixed.candidates[1]["claim_id"]
    row = rows_of(mixed)[claim]
    assert row["status"] == "insufficient_evidence" and "trigger" in row["reason"]
    assert row["files"] is None and row["functions"] is None and row["brief"] is None
    assert not (mixed.run_root / CLAIM_DIR / claim).exists()
    assert mixed.candidates[2]["claim_id"] not in rows_of(mixed)
    assert not (mixed.run_root / CLAIM_DIR / mixed.candidates[2]["claim_id"]).exists()


def test_nothing_is_linked_or_run_and_the_accepted_workspace_is_untouched(mixed) -> None:
    mixed.executor.assert_nothing_is_linked_or_run()
    names = [call["argv"][0] for call in mixed.executor.calls]
    assert names.count("python3") == 1 and names.count("/usr/bin/clang++") == 3 and names.count("nm") == 3
    assert mixed.executor.calls[0]["argv"][0] == "python3"
    workspace = mixed.chain.workspace
    assert poc_support.manifest_of(workspace) == mixed.unit.workspace_manifest
    for scratch in (attempt_root(mixed) / "steps").glob("*/tasks/*/scratch/*"):
        raise AssertionError(f"a scratch workspace was left behind: {scratch}")
    assert not list(workspace.rglob(".appsec-poc"))


def test_the_job_reads_no_target_tree(mixed) -> None:
    claim = read(mixed, f"{attempt_root(mixed).relative_to(mixed.run_root)}/claim.json")
    assert claim["target_root"] is None and claim["source_fingerprint"] == "none"
    assert claim["upstream_handoffs"].get("job_inference_security_review")


def test_every_file_the_job_writes_is_claimed_by_a_dataset_declaration(mixed) -> None:
    steps = tuple(load_config(mixed.chain.config).job(POC).steps)
    claims = runtime_claims({POC: steps}) + [Claim(POC, item.step, item.output_kind, item) for item in DATASETS]
    tree = scan_run_tree(mixed.run_root, FileClaims(claims), max_files=1_000_000)
    mine = [path for path in tree.unaccounted if path.startswith((CLAIM_DIR, f"data/jobs/{POC}"))]
    assert mine == []
    assert {"poc_generation_summary", "poc_writer_cells", "poc_reproducers"} <= {key[2] for key in tree.groups
                                                                                  if key[0] == POC}


def test_the_writer_receipt_records_hashes_and_the_validated_answer_never_a_prompt(mixed) -> None:
    claim = mixed.candidates[0]["claim_id"]
    receipt = read(mixed, rows_of(mixed)[claim]["writer_receipt"]["path"])
    assert receipt["claim_id"] == claim and receipt["status"] == "answered"
    assert receipt["brief_sha256"] == rows_of(mixed)[claim]["brief"]["sha256"] and receipt["result_sha256"]
    assert "parse_header" not in json.dumps(receipt)


def test_poc_and_report_emit_exact_bounded_status_and_certified_output_metrics(mixed) -> None:
    def event(job, name):
        records = [json.loads(line) for line in (attempt_root(mixed, job) / "logs" / "events.jsonl").read_text(
            encoding="utf-8").splitlines()]
        return next(record for record in records if record["event"] == name)

    published = event(POC, "POC_GENERATION_PUBLISHED")
    assert published["by_status"] == summary_of(mixed)[1]["counts"]["by_status"]
    assert published["candidate_count"] == 2 and published["omitted_count"] == 1
    assert published["compile_verified_count"] == 1 and published["runtime_verified"] is False
    assert published["policy_failure_count"] == published["build_failure_count"] == 0
    gate = event(GATE, "FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED")
    report = event(REPORT, "FINAL_REPORT_ASSEMBLED")
    assert gate["attachment_counts"]["poc_generation"] == report["certified_outcome_counts"]["poc_generation"] == 2
    assert report["attachment_count"] == sum(report["certified_outcome_counts"].values())
    assert all(record["duration_ms"] >= 0 for record in (published, gate, report))
    assert all(claim not in str(report) for claim in rows_of(mixed))


# --------------------------------------------------------------------------------------------- the report


def test_the_report_shows_the_poc_outcomes_when_the_poc_job_ran_on_this_gate(mixed) -> None:
    report = unit_json(mixed, "report.assemble", "final-report.json", REPORT)
    outcomes = report["poc_outcomes"]
    assert outcomes["status"] == "available" and outcomes["reason"] == POC_REASON
    assert sorted(item["status"] for item in outcomes["items"]) == ["compile_verified", "insufficient_evidence"]
    first = next(row for row in outcomes["items"] if row["claim_id"] == mixed.candidates[0]["claim_id"])
    assert first["claim_id"] == mixed.candidates[0]["claim_id"] and first["result_id"] is None
    assert first["functions"] == {"test_function": relay.TEST_NAME, "negative_control": relay.CONTROL_NAME}
    assert sorted(first["files"]) == ["compile", "provenance", "readme", "source"] and len(first["description"]) <= 300
    pointer = read(mixed, f"data/jobs/{POC}/latest.json")
    assert outcomes["poc_handoff"]["sha256"] == pointer["handoff_sha256"] == report["provenance"]["poc_handoff"]["sha256"]
    markdown = (attempt_root(mixed, REPORT) / "steps" / "report" / "tasks" / "render" / "final-report.md").read_text(
        encoding="utf-8")
    assert "compile_verified" in markdown and f"`{relay.TEST_NAME}`" in markdown and relay.GOOD_TEST not in markdown
    assert first["files"]["compile"]["path"] in markdown
    published = handoff_of(mixed, REPORT)["outputs"]["acceptance.publish_handoff"]
    assert published["item_count"] >= 1


def test_a_changed_reproducer_file_fails_the_report_never_a_quietly_different_one(chain, tmp_path_factory) -> None:
    claim = chain.findings[0]["claim_id"]
    chain.prepare([chain.candidate(0)])
    chain.run_poc(Writer({claim: [relay.answer()]}))
    source = chain.run_root / chain.rows()[claim]["files"]["source"]["path"]
    source.write_text(source.read_text(encoding="utf-8") + "// edited\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        chain.run_report()


def test_without_a_poc_handoff_the_report_is_what_it_was_before_the_job_existed(chain) -> None:
    chain.prepare(None)
    chain.run_report()
    report = chain.read(REPORT, "report.assemble", "final-report.json")
    assert report["poc_outcomes"]["status"] == "none_available" and report["poc_outcomes"]["items"] == []
    assert "poc_handoff" not in report["provenance"]


def test_report_uses_the_gate_snapshot_not_a_later_poc_pointer(chain) -> None:
    claim = chain.findings[0]["claim_id"]
    chain.prepare([chain.candidate(0)])
    chain.run_poc(Writer({claim: [relay.answer()]}))
    chain.run_gate()
    (chain.run_root / "data" / "jobs" / POC / "latest.json").unlink()
    chain.run_report(refresh_gate=False)
    report = chain.read(REPORT, "report.assemble", "final-report.json")
    assert report["poc_outcomes"]["status"] == "available"
    assert "poc_handoff" in report["provenance"]


# ---------------------------------------------------------------------------------------- other statuses


def test_a_policy_denied_and_a_compile_failed_candidate_keep_their_source_as_data(chain, tmp_path_factory) -> None:
    a, b = chain.findings[0]["claim_id"], chain.findings[1]["claim_id"]
    denied = relay.answer(*relay.VARIANTS["main_defined"][:2])
    executor = poc_support.FakeExecutor(ast_by_source, fail={"poc_san.o": 1})
    run = scenario(chain, tmp_path_factory, [chain.candidate(0), chain.candidate(1)],
                   {a: [denied], b: [relay.answer()]}, executor)
    rows = rows_of(run)
    assert (rows[a]["status"], rows[b]["status"]) == ("policy_denied", "compile_failed")
    # policy_denied: the validators refused it from the AST, so it was never compiled
    refused = read(run, rows[a]["files"]["compile"]["path"])
    assert refused["policy"]["verdict"] == "denied" and refused["steps"] == [] and refused["status"] == "policy_denied"
    assert {item["rule"] for item in refused["policy"]["violations"]} >= {"entry_point", "unexpected_declaration"}
    assert "int main() { return 0; }" in (run.run_root / rows[a]["files"]["source"]["path"]).read_text(encoding="utf-8")
    assert "## Why a validator refused it" in (run.run_root / rows[a]["files"]["readme"]["path"]).read_text()
    # compile_failed: it passed the validators and then failed under the sanitizer flags
    failed = read(run, rows[b]["files"]["compile"]["path"])
    assert failed["policy"]["verdict"] == "passed" and failed["steps"][-1]["name"] == "sanitized_object"
    assert failed["steps"][-1]["exit_code"] == 1 and "error" in failed["steps"][-1]["diagnostics"][0]
    readme = (run.run_root / rows[b]["files"]["readme"]["path"]).read_text(encoding="utf-8")
    assert "does not contradict the finding" in readme and "`compile_failed`" in readme
    names = [call["argv"][0] for call in executor.calls]
    assert names.count("python3") == 2 and names.count("nm") == 0                # no symbols read after a failure
    executor.assert_nothing_is_linked_or_run()
    published = summary_of(run)[0]
    assert sum(gap.startswith(("claim-")) for gap in published["gaps"]) == 2


def test_writer_declines_unusable_bases_and_missing_answers_are_named_statuses(chain, tmp_path_factory) -> None:
    a, b = chain.findings[0]["claim_id"], chain.findings[1]["claim_id"]
    decline = {"action": "final", "result": {"decline": {"status": "unsafe_to_attempt", "why": "needs a socket"}}}
    no_trigger = {"entry": ["asr:entry_point:" + "1" * 64], "path": ["asr:call_site:" + "2" * 64],
                  "trigger": [], "input_format": "x", "preconditions": [],
                  "expected_observation": "x", "unknowns": []}
    run = scenario(chain, tmp_path_factory, [chain.candidate(0), chain.candidate(1, basis=no_trigger)],
                   {a: [decline]})
    rows = rows_of(run)
    assert rows[a]["status"] == "unsafe_to_attempt" and "needs a socket" in rows[a]["reason"] and rows[a]["files"] is None
    assert rows[b]["status"] == "insufficient_evidence" and "trigger" in rows[b]["reason"]
    assert len(run.writer.requests) == 1 and run.executor.calls == []             # nothing was parsed or compiled


def test_a_writer_that_never_answers_leaves_the_candidate_insufficient_evidence(chain, tmp_path_factory) -> None:
    a = chain.findings[0]["claim_id"]
    run = scenario(chain, tmp_path_factory, [chain.candidate(0)], {a: [TimeoutError("slow"), RuntimeError("down")]})
    row = rows_of(run)[a]
    assert row["status"] == "insufficient_evidence" and "writer_" in row["reason"] and row["files"] is None
    assert len(run.writer.requests) == 2
    assert read(run, row["writer_receipt"]["path"])["status"] == "failed"


def test_an_unavailable_build_image_leaves_the_source_as_artifact_generated_with_a_gap(chain, tmp_path_factory) -> None:
    a = chain.findings[0]["claim_id"]
    run = scenario(chain, tmp_path_factory, [chain.candidate(0)], {a: [relay.answer()]},
                   poc_support.FakeExecutor(ast_by_source, unavailable=True))
    row = rows_of(run)[a]
    assert row["status"] == "artifact_generated" and row["files"] is not None and row["gaps"]
    record = read(run, row["files"]["compile"]["path"])
    assert record["status"] == "artifact_generated" and record["policy"]["verdict"] == "not_evaluated"
    assert (run.run_root / row["files"]["source"]["path"]).read_text(encoding="utf-8").count("poc_parse_header") >= 2
    assert summary_of(run)[0]["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_missing_accepted_objects_are_artifact_generated_after_a_clean_compile(chain, tmp_path_factory) -> None:
    a = chain.findings[0]["claim_id"]
    run = scenario(chain, tmp_path_factory, [chain.candidate(0)], {a: [relay.answer()]},
                   poc_support.FakeExecutor(ast_by_source, project=""), unit_kwargs={"objects": ()})
    row = rows_of(run)[a]
    assert row["status"] == "artifact_generated"
    record = read(run, row["files"]["compile"]["path"])
    assert [step["name"] for step in record["steps"][:3]] == ["syntax", "object", "sanitized_object"]
    assert any("project symbols" in gap for gap in record["gaps"])


def test_an_include_outside_the_project_is_refused_before_any_compiler_runs(chain, tmp_path_factory) -> None:
    a = chain.findings[0]["claim_id"]
    bad = relay.answer(includes=(*relay.INCLUDES, "unistd.h"))
    run = scenario(chain, tmp_path_factory, [chain.candidate(0)], {a: [bad]})
    row = rows_of(run)[a]
    assert row["status"] == "policy_denied" and run.executor.calls == []
    record = read(run, row["files"]["compile"]["path"])
    assert [item["rule"] for item in record["policy"]["violations"]] == ["include"]


# ------------------------------------------------------------------------------------ the candidate input


def test_a_review_with_no_candidates_produces_an_empty_valid_handoff(chain) -> None:
    chain.prepare(None)
    chain.run_poc(Writer({}))
    published = chain.handoff(POC)["outputs"]["publish.publish_handoff"]
    summary = chain.summary()
    assert published["terminal_status"] == "SUCCEEDED" and published["item_count"] == 0
    assert published["gaps"] == []
    assert summary["candidates"] == [] and summary["counts"]["candidates"] == 0
    assert SchemaSet(ROOT / "docs" / "schemas" / "poc-generation").errors("poc-generation", summary) == []
    executor = chain.built["executor"]
    assert executor.calls == []
    chain.run_report()
    outcomes = chain.read(REPORT, "report.assemble", "final-report.json")["poc_outcomes"]
    assert outcomes["status"] == "none_available" and "empty eligible scope" in outcomes["reason"]


def test_an_empty_candidate_list_is_a_run_with_nothing_to_document_not_a_gap(chain) -> None:
    chain.prepare([])
    chain.run_poc(Writer({}))
    published = chain.handoff(POC)["outputs"]["publish.publish_handoff"]
    assert published["terminal_status"] == "SUCCEEDED" and published["gaps"] == [] and published["item_count"] == 0


@pytest.mark.parametrize("mutate", [
    lambda c: c.candidate(0, finding_package={"finding_package_id": c.findings[0]["finding_package_id"],
                                              "sha256": "0" * 64}),
    lambda c: c.candidate(0, state="supported" if c.findings[0]["state"] == "confirmed" else "confirmed"),
    lambda c: c.candidate(0, claim_id=c.findings[1]["claim_id"]),
    lambda c: {**c.candidate(0), "poc_basis": {"sha256": "1" * 64, "brief": c.candidate(0)["poc_basis"]["brief"]}},
    lambda c: {**c.candidate(0), "surprise": True},
])
def test_candidates_that_disagree_with_the_verified_review_fail_the_job(chain, mutate) -> None:
    chain.prepare([mutate(chain)])
    with pytest.raises(IntegrityError):
        chain.run_poc(Writer({}))


def test_the_job_requires_the_accepted_review_not_a_gate(chain) -> None:
    chain.restore()
    (chain.run_root / "data" / "jobs" / "job_inference_security_review" / "latest.json").unlink()
    with pytest.raises(IntegrityError, match="accepted job_inference_security_review handoff is required"):
        chain.run_poc(Writer({}))


def test_a_changed_review_artifact_after_the_gate_fails_the_job(chain) -> None:
    chain.prepare([chain.candidate(0)])
    finding = next(chain.run_root.rglob(f"{chain.findings[0]['finding_package_id']}.json"))
    finding.write_text(finding.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(IntegrityError):
        chain.run_poc(Writer({}))


# ------------------------------------------------------------------------------- recording and replay


def test_the_writer_requests_are_recorded_and_replayed_with_identical_keys(chain, tmp_path_factory) -> None:
    from appsec_review.inference.recording import MODE_ENVIRONMENT, REPLAY_ENVIRONMENT, recorded

    a = chain.findings[0]["claim_id"]
    candidates = [chain.candidate(0)]
    chain.prepare(candidates)
    first = Writer({a: [relay.answer()]})
    chain.run_poc(first, infer=recorded(first), env={MODE_ENVIRONMENT: "record"})
    recordings = chain.run_root / "data" / "inference-recordings" / POC
    files = sorted(recordings.glob("*.json"))
    assert len(files) == 1
    document = json.loads(files[0].read_text(encoding="utf-8"))
    assert document["job_id"] == POC and document["request"]["type"] == "ReviewModelRequest"
    assert document["request"]["role"] == "poc_writer" and "<run>" not in json.dumps(document["result"])
    replay_dir = tmp_path_factory.mktemp("replay")
    shutil.copytree(recordings, replay_dir / POC)

    def never(request, *, timeout_seconds):
        raise AssertionError("the replay must answer from the recording")

    chain.prepare(candidates)
    chain.run_poc(never, infer=recorded(never),
                  env={MODE_ENVIRONMENT: "replay", REPLAY_ENVIRONMENT: str(replay_dir)})
    assert rows_of(SimpleNamespace(run_root=chain.run_root))[a]["status"] == "compile_verified"
    assert issubclass(ModelReplayMiss, RuntimeError)


def test_the_unit_outputs_are_deterministic_across_two_runs_of_the_same_scenario(chain) -> None:
    a = chain.findings[0]["claim_id"]
    results = []
    for _ in range(2):
        chain.prepare([chain.candidate(0)])
        chain.run_poc(Writer({a: [relay.answer()]}))
        row = chain.rows()[a]
        results.append({key: row[key] for key in ("status", "reason", "description", "poc_basis_sha256")} | {
            "source": row["files"]["source"]["sha256"], "brief": row["brief"]["sha256"],
            "readme": row["files"]["readme"]["sha256"]})
    assert results[0] == results[1]
    assert hashlib.sha256(json.dumps(results[0], sort_keys=True).encode()).hexdigest()


# ------------------------------------------------------------------------------ the report contract


def test_the_final_report_schema_accepts_the_poc_block_and_agrees_with_jsonschema(mixed) -> None:
    from copy import deepcopy

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    schemas = {path.name: json.loads(path.read_text(encoding="utf-8"))
               for path in (ROOT / "docs" / "schemas" / "final-report").glob("*.json")}
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas.values())
    validator = Draft202012Validator(schemas["final-report.schema.json"], registry=registry)
    closed = SchemaSet(ROOT / "docs" / "schemas" / "final-report")
    report = unit_json(mixed, "report.assemble", "final-report.json", REPORT)
    assert list(validator.iter_errors(report)) == [] and closed.errors("final-report", report) == []
    broken = []
    for edit in (lambda r: r["poc_outcomes"]["items"][0].update(status="Done!"),
                 lambda r: r["poc_outcomes"]["items"][0].update(claim_id="claim-short"),
                 lambda r: r["poc_outcomes"]["items"][0]["files"].pop("source"),
                 lambda r: r["poc_outcomes"]["items"][0].update(description=""),
                 lambda r: r["poc_outcomes"]["items"][0].update(surprise=1),
                 lambda r: r["poc_outcomes"].update(poc_handoff={"path": "../x", "sha256": "0" * 64})):
        mutated = deepcopy(report)
        edit(mutated)
        broken.append(mutated)
    for document in broken:
        assert list(validator.iter_errors(document)) and closed.errors("final-report", document)


def test_a_report_in_the_previous_shape_is_explicitly_unsupported(mixed) -> None:
    from copy import deepcopy

    from appsec_review.jobs.job_final_report_publication.render import render_markdown

    report = deepcopy(unit_json(mixed, "report.assemble", "final-report.json", REPORT))
    report["poc_outcomes"] = {"status": "available", "reason": "an earlier report",
                              "items": [{"finding_package_id": "finding-" + "1" * 64, "status": "compile_verified",
                                         "result_id": None}]}
    report["provenance"].pop("poc_handoff")
    assert SchemaSet(ROOT / "docs" / "schemas" / "final-report").errors("final-report", report)


def test_the_default_package_view_is_built_from_the_accepted_review_and_unresolved_labels_are_named(chain) -> None:
    """Without the stub view the job builds the real labelled view; the fixture package has no entry point or call
    path, so none of the basis labels resolve and the candidate is insufficient_evidence, not a guess."""
    a = chain.findings[0]["claim_id"]
    chain.prepare([chain.candidate(0)])
    chain.run_poc(Writer({}), view_factory=None)
    row = chain.rows()[a]
    assert row["status"] == "insufficient_evidence" and "reference" in row["reason"] and row["files"] is None
    assert chain.built["executor"].calls == []
