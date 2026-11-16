"""``build_outcome`` and gap classes: ``terminal_status`` describes the receipt, ``build_outcome`` the build.

Run 2026-11-16-0003 compiled and linked everything, yet its native receipt read ``COMPLETED_WITH_GAPS``
with 17 ``producer_reported_gap`` records that were all about provenance (delivery facts, directory-name
heuristics, CMake's compiler-identification probes in the capture), and the PoC build context refused it
as "no native build". These cases pin the distinction at the producer, in the records and at the readers.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs import build_outcome as outcome
from appsec_review.jobs.build_output_scope import heuristic_gap
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.delivery_scope import delivery_gap
from appsec_review.jobs.job_language_build import job as lb_job
from appsec_review.jobs.job_poc_generation import buildctx
from appsec_review.jobs.job_project_build.enforcement import enforcement_gaps, scoped_gaps
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_bytes
from tests.capture_fakes import simulated_executor
from tests.unit.job_language_build import support

UNIT = "build-unit-" + "b9c931fa55" * 2
LANE = "execute.native"


@pytest.mark.parametrize(("status", "expected"), [
    ("BLOCKED", "not_run"), ("COMPLETED_WITH_GAPS", "built"), ("FAILED", "failed"), ("GAP", "not_run"),
    ("NOT_APPLICABLE", "not_run"), ("SKIPPED_NA", "not_run"), ("SKIPPED_POLICY", "not_run"),
    ("SUCCEEDED", "built"), ("TIMED_OUT", "failed"), (None, "not_run"),
])
def test_build_outcome_follows_the_receipt_status_it_was_decided_from(status, expected) -> None:
    assert outcome.build_outcome_from_status(status) == expected


def test_with_build_outcome_derives_once_keeps_the_producer_value_and_rejects_an_unknown_one() -> None:
    derived = outcome.with_build_outcome({"build_unit_id": UNIT, "terminal_status": "FAILED"})
    assert derived["build_outcome"] == "failed"
    kept = outcome.with_build_outcome({"terminal_status": "COMPLETED_WITH_GAPS", "build_outcome": "built"})
    assert kept["build_outcome"] == "built"
    with pytest.raises(ValueError, match="build_outcome 'green'"):
        outcome.with_build_outcome({"terminal_status": "SUCCEEDED", "build_outcome": "green"})
    assert sorted(outcome.BUILD_OUTCOMES) == ["built", "failed", "not_run"]


def test_build_succeeded_reads_the_outcome_and_falls_back_to_the_legacy_status_test() -> None:
    assert outcome.build_succeeded({"terminal_status": "COMPLETED_WITH_GAPS", "build_outcome": "built"})
    assert not outcome.build_succeeded({"terminal_status": "SUCCEEDED", "build_outcome": "failed"})
    assert outcome.build_succeeded({"terminal_status": "SUCCEEDED"})
    assert not outcome.build_succeeded({"terminal_status": "COMPLETED_WITH_GAPS"})
    assert outcome.build_succeeded({"terminal_status": "COMPLETED_WITH_GAPS"},
                                   legacy_statuses=frozenset({"SUCCEEDED", "COMPLETED_WITH_GAPS"}))


def test_gap_codes_come_from_the_producer_that_wrote_the_gap() -> None:
    delivery = delivery_gap({"path": "build/libsmoke_bz2.a", "scope_role": "unknown"})
    assert delivery == "build/libsmoke_bz2.a: delivery status is unknown (delivery_fact_unavailable)"
    heuristic = heuristic_gap("build/CMakeFiles/smoke_bz2.dir/third_party/bzip2", "per_file", "low")
    provenance = [delivery, f"{UNIT}: {delivery}", heuristic, "unknown_compiler_in_capture", "capture_empty",
                  "mixed_targets_in_capture"]
    assert {str(outcome.gap_code_for(text)) for text in provenance} == {"provenance_unavailable"}
    build = ["build command 1 exited 2", "cross_target_not_permitted", "build-output-classification-conflict: x",
             "image build timed out", "dependency build unavailable: a"]
    assert {str(outcome.gap_code_for(text)) for text in build} == {"producer_reported_gap"}
    records = scoped_gaps([heuristic, "build command 1 exited 2"], LANE, UNIT)
    assert [(gap["code"], gap["scope_id"]) for gap in records] == [
        ("provenance_unavailable", UNIT), ("producer_reported_gap", UNIT)]
    enforcement = enforcement_gaps(["capture_empty", "cross_target_not_permitted", "unknown_compiler_in_capture"], UNIT)
    assert [gap["code"] for gap in enforcement] == [
        "provenance_unavailable", "producer_reported_gap", "provenance_unavailable"]
    assert all(gap["schema"] == "appsec-review/producer-gap/1" and gap["scope_id"] == UNIT for gap in enforcement)


def _run_0003_receipt(run_root: Path) -> dict:
    """A native receipt shaped like run 2026-11-16-0003's, as ``_execute_one`` holds it before enforcement."""
    workspace = run_root / "data/build/probes/units" / UNIT / "attempts/attempt_0001/workspace"
    source = workspace / "src/request.cpp"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"int handle(char *p) { return p[0]; }\n")
    (workspace / "build").mkdir()
    (workspace / "build/request.o").write_bytes(b"\x7fELF")
    (workspace / "build/smoke_server").write_bytes(b"\x7fELF")
    files = {"src/request.cpp": hashlib.sha256(source.read_bytes()).hexdigest(),
             "build/request.o": hashlib.sha256(b"\x7fELF").hexdigest(),
             "build/smoke_server": hashlib.sha256(b"\x7fELF").hexdigest()}
    manifest = json.dumps({"schema": "appsec-review/build-workspace-manifest/1", "build_unit_id": UNIT,
                           "files": files}).encode()
    manifest_path = run_root / "data/build/probes/units" / UNIT / "workspace-manifest.json"
    atomic_bytes(manifest_path, manifest)
    database = json.dumps({"schema": buildctx.COMPILE_DATABASE_SCHEMA, "rows": [
        {"tool_kind": "compiler", "argv": ["/usr/bin/c++", "-Isrc", "-c", "src/request.cpp", "-o", "build/request.o"],
         "inputs": [{"workspace_path": "src/request.cpp"}]}]}).encode()
    database_path = run_root / "data/build/probes/units" / UNIT / "protected-compile-commands.json"
    atomic_bytes(database_path, database)
    artifacts = [{"kind": "object", "workspace_path": "build/request.o", "path": "x", "sha256": files["build/request.o"]},
                 {"kind": "executable", "workspace_path": "build/smoke_server", "path": "y",
                  "sha256": files["build/smoke_server"]}]
    heuristics = [heuristic_gap(f"build/CMakeFiles/smoke_{name}.dir/third_party/{name}", "per_file", "low")
                  for name in ("bz2", "cjson", "lz4", "zlib")]
    delivery = [delivery_gap({"path": f"build/libsmoke_{name}.a", "scope_role": "unknown"})
                for name in ("bz2", "cjson", "lz4", "zlib", "ssl", "crypto")]
    status = "SUCCEEDED"
    return {"schema": lb_job.RECEIPT_SCHEMA, "build_unit_id": UNIT, "family": "native", "root": ".",
            "build_system": "cmake", "fingerprint": "f" * 64, "probe_disposition": "CAPTURED",
            "recipe": {"source_dir": ".", "build_dir": "build"},
            "image": {"image_tag": "native:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000"},
            "workspace": workspace.relative_to(run_root).as_posix(),
            "workspace_manifest": {"path": manifest_path.relative_to(run_root).as_posix(),
                                   "sha256": hashlib.sha256(manifest).hexdigest()},
            "protected_compile_commands": {"path": database_path.relative_to(run_root).as_posix(),
                                           "sha256": hashlib.sha256(database).hexdigest()},
            "artifacts": artifacts, "delivery_gaps": delivery, "gaps": heuristics,
            "terminal_status": status, "build_outcome": outcome.build_outcome_from_status(status)}


def test_a_build_that_compiled_everything_stays_built_when_only_its_provenance_has_gaps(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    receipt = _run_0003_receipt(run_root)
    assert receipt["build_outcome"] == "built"
    proof = {"status": "unknown", "unresolved_inputs": ["unknown_compiler_in_capture"]}
    status = lb_job.apply_target_enforcement(
        receipt, unit_id=LANE, proof=proof, target_gaps=enforcement_gaps(proof["unresolved_inputs"], UNIT))
    # The receipt: flipped by the named gaps, artifacts rejected (enforcement is not widened).
    assert status == receipt["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert receipt["artifacts"] == [] and [item["kind"] for item in receipt["rejected_artifacts"]] == ["object", "executable"]
    assert receipt["enforcement"] == [proof]
    # The build: still built. The gaps: every one is provenance, none says the build failed.
    assert receipt["build_outcome"] == "built"
    assert len(receipt["gaps"]) == 5
    assert {gap["code"] for gap in receipt["gaps"]} == {"provenance_unavailable"}
    assert {gap["scope_id"] for gap in receipt["gaps"]} == {UNIT}
    assert receipt["gaps"][-1]["reason"] == "unknown_compiler_in_capture"
    # The delivery facts the family step merges into the handoff are provenance records too.
    delivery = scoped_gaps(receipt["delivery_gaps"], LANE, UNIT)
    assert len(delivery) == 6 and {gap["code"] for gap in delivery} == {"provenance_unavailable"}
    # The PoC build context finds the translation unit in this build.
    builds = buildctx.AcceptedBuilds(run_root, loader=lambda _root: {"receipts": [receipt]})
    located = builds.locate("src/request.cpp")
    assert located.code == "found" and located.reason == ""
    assert located.unit.build_unit_id == UNIT and located.unit.command.source == "src/request.cpp"
    assert located.unit.command.basis == "exact"
    # The rejected artifacts are not offered as objects to check symbols against.
    assert located.unit.objects == () and located.unit.gaps == (
        "the accepted build recorded no object or library output to check symbols against",)


def test_a_forbidden_target_is_a_reported_gap_on_a_built_receipt(tmp_path: Path) -> None:
    receipt = _run_0003_receipt(tmp_path / "run")
    receipt["gaps"] = []
    lb_job.apply_target_enforcement(
        receipt, unit_id=LANE, proof={"status": "unknown", "unresolved_inputs": ["cross_target_not_permitted"]},
        target_gaps=enforcement_gaps(["cross_target_not_permitted"], UNIT))
    assert (receipt["terminal_status"], receipt["build_outcome"]) == ("COMPLETED_WITH_GAPS", "built")
    assert [gap["code"] for gap in receipt["gaps"]] == ["producer_reported_gap"]


def test_a_proven_target_leaves_a_succeeded_receipt_alone(tmp_path: Path) -> None:
    receipt = _run_0003_receipt(tmp_path / "run")
    proof = {"status": "proven", "unresolved_inputs": []}
    assert lb_job.apply_target_enforcement(receipt, unit_id=LANE, proof=proof, target_gaps=[]) == "SUCCEEDED"
    assert receipt["build_outcome"] == "built" and len(receipt["artifacts"]) == 2
    assert "rejected_artifacts" not in receipt
    assert [gap["code"] for gap in receipt["gaps"]] == ["provenance_unavailable"] * 4


def test_the_poc_build_context_refuses_an_unknown_outcome_and_a_receipt_whose_build_failed(tmp_path: Path) -> None:
    receipt = _run_0003_receipt(tmp_path / "run")
    builds = buildctx.AcceptedBuilds(tmp_path / "run", loader=lambda _root: {"receipts": [{**receipt, "build_outcome": "ok"}]})
    with pytest.raises(IntegrityError, match="build_outcome 'ok'"):
        builds.locate("src/request.cpp")
    failed = buildctx.AcceptedBuilds(tmp_path / "run", loader=lambda _root: {"receipts": [
        {**receipt, "terminal_status": "SUCCEEDED", "build_outcome": "failed"}]})
    assert failed.locate("src/request.cpp").code == "no_native_build"


def test_a_build_whose_command_fails_is_failed_not_a_provenance_gap(tmp_path: Path, monkeypatch) -> None:
    """A real ``_execute_one`` run over the simulated capture executor: the command exits 2."""
    monkeypatch.setattr("appsec_review.jobs.build_topology_artifacts.guard_cache_action",
                        lambda _rr, _d, **_kw: {"enforcement": []})
    target = tmp_path / "target"
    target.mkdir()
    (target / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "setuptools.build_meta"\n[project]\nname = "demo"\n', encoding="utf-8")
    fingerprint = source_fingerprint(target)
    unit = support.unit_context(tmp_path, "execute.python", target_root=target, source_fingerprint=fingerprint)
    dispatch = {
        **support.dispatch("build-unit-" + "1" * 20, "python", build_system="pyproject",
                           commands=[["python3", "-m", "build"]]),
        "source_fingerprint": fingerprint,
        "topology_refinement": {"path": "data/build/topology/refinements/r.json", "sha256": "7" * 64},
        "image": {"image_tag": "py:1", "image_id": "sha256:" + "5" * 64, "user": "1000:1000", "dependency_hashes": {}},
        "recipe": {"source_dir": ".", "build_dir": "dist", "environment": {}, "dependency_files": ["pyproject.toml"],
                   "configure_commands": [], "build_commands": [["python3", "-m", "build"]],
                   "expected_outputs": ["dist"], "network_required": False},
    }

    def failing(argv, _ws, _cwd, _env, sim):
        sim.exec("/usr/bin/python3", argv)
        return 2, b"", b"error: no backend\n"

    receipt = lb_job._execute_one(unit, dispatch, support.accepted(dispatch),
                                  lambda _u, profile: simulated_executor(profile, failing))
    assert receipt["terminal_status"] == "FAILED" and receipt["build_outcome"] == "failed"
    assert receipt["artifacts"] == [] and receipt["commands"][0]["exit_code"] == 2
    assert any("build command 1 exited 2" in gap for gap in receipt["gaps"])
    assert not outcome.build_succeeded(receipt)
