from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import struct

import pytest

from appsec_review.config import AppConfig, load_config
from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.jobs.job_cpp_compiled_analysis.datasets import DATASETS
from appsec_review.jobs.job_post_build_security_assessment import build_job
from appsec_review.jobs.job_post_build_security_assessment.assessment import INFERENCE_PROPOSAL_SCHEMA
from appsec_review.observability import aggregate_run_metrics
from appsec_review.retrieval import RetrievalCore, write_manifest
from appsec_review.runtime import JobRunner
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.repair import WORKER_PROTOCOL, bind_release, worker_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.capture_fakes import build_capture_toml
from tests.handoff_fixture import write_fixture_handoff

pytestmark = pytest.mark.integration

RUN_ID = "2026-10-08-9001"

BLOCKED_GAP = ("unit-blocked (projects/native/blocked): C/C++ analysis unavailable because the native "
               "build failed upstream in job_language_build (BLOCKED)")


def _elf64(path: Path, *, executable: bool = True) -> None:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<HHIQQQIHHHHHH", 2 if executable else 1, 62, 1, 0, 64, 0, 0,
                         64, 56, 1, 64, 0, 0)
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    path.write_bytes(ident + header + stack)


def _archive(path: Path) -> None:
    payload = b"object"
    header = ("member.o/".ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6) +
              "100644".ljust(8) + str(len(payload)).ljust(10) + "`\n").encode("ascii")
    path.write_bytes(b"!<arch>\n" + header + payload)


def _post_build_config(root: Path, *, model_enabled: bool = False) -> Path:
    lines = ["[runtime]", 'runs_dir = "runs"', 'data_dir = "data"', 'metadata_dir = "runs/metadata"',
             "", "[jobs.job_cpp_compiled_analysis]", 'name = "fixture"',
             "[jobs.job_cpp_compiled_analysis.settings]", 'lane = "cpp"',
             "", "[jobs.job_post_build_security_assessment]", 'name = "post_build_security_assessment"',
             "workers = 4", "", "[jobs.job_post_build_security_assessment.settings.model]",
             f"enabled = {'true' if model_enabled else 'false'}", 'provider = "fixture"', 'model = "fixture"',
             'reasoning = "medium"', "max_input_tokens = 32000", "max_output_tokens = 1000",
             "timeout_seconds = 10", "retries = 0", "",
             "[jobs.job_post_build_security_assessment.steps.load]", "workers = 1",
             "[jobs.job_post_build_security_assessment.steps.load.tasks.accepted_cpp_build]", ""]
    for step in ("provenance", "inspection", "deterministic", "inference", "index"):
        lines.extend((f"[jobs.job_post_build_security_assessment.steps.{step}]", "workers = 4"))
        lines.append(f"[jobs.job_post_build_security_assessment.steps.{step}.tasks.native_units]")
        lines.append("")
    lines.extend(("[jobs.job_post_build_security_assessment.steps.publication]", "workers = 1",
                  "[jobs.job_post_build_security_assessment.steps.publication.tasks.publish_handoff]"))
    path = root / "appsec-review.toml"
    path.write_text("\n".join(lines) + "\n\n" + build_capture_toml(), encoding="utf-8")
    return path


def _accepted_cpp_fixture(tmp_path: Path, *, colliding_object_names: bool = False,
                          worker_config: AppConfig | None = None,
                          blocked_case: bool = False) -> tuple[Path, Path]:
    runs, run_root = tmp_path / "runs", tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    target.mkdir()
    case_root = run_root / "data" / "cpp" / "projects" / "unit-a"
    (case_root / "build").mkdir(parents=True)
    (case_root / "source").mkdir()
    source = case_root / "source" / "main.cpp"
    source.write_text("int main(){return 0;}\n", encoding="utf-8")
    binary = case_root / "build" / "app"
    _elf64(binary)
    object_file = case_root / "build" / "app.o"
    _elf64(object_file, executable=False)
    archive = case_root / "build" / "libapp.a"
    _archive(archive)
    link_dir = case_root / "build" / "CMakeFiles" / "app.dir"
    link_dir.mkdir(parents=True)
    archive_inputs = "app.o"
    if colliding_object_names:
        for directory in ("variant_alpha", "variant_beta"):
            duplicate = case_root / "build" / directory / "profile.cpp.o"
            duplicate.parent.mkdir(parents=True)
            _elf64(duplicate, executable=False)
        archive_inputs += " variant_alpha/profile.cpp.o variant_beta/profile.cpp.o"
    (link_dir / "link.txt").write_text(
        f"llvm-ar rcs libapp.a {archive_inputs}\nclang++ app.o -Wl,-z,relro,-z,now -pie -o app\n",
        encoding="utf-8")
    (case_root / "analysis" / "binary").mkdir(parents=True)
    (case_root / "analysis" / "binary" / "records.json").write_text(json.dumps([{
        "path": "build/app", "kind": "executable", "sha256": file_sha256(binary),
        "symbols": ["main T 0 1"], "metadata": "ELF fixture metadata",
    }]), encoding="utf-8")
    exact = ["clang++", "-c", str(source), "-o", "app.o", "-fstack-protector-strong",
             "-fPIE", "-DAPI_TOKEN=super-secret"]
    (case_root / "build" / "compile_commands.json").write_text(json.dumps([{
        "directory": str(case_root / "build"), "file": str(source), "arguments": exact,
    }]), encoding="utf-8")
    outputs = {"catalog.projects": {"projects": {"unit-a": {
        "terminal_status": "SUCCEEDED", "mapping": {"root": "projects/cpp/case-001", "build_system": "cmake"},
        "outputs": [{"path": "build/app", "kind": "executable", "sha256": file_sha256(binary),
                     "size_bytes": binary.stat().st_size},
                    {"path": "build/app.o", "kind": "object", "sha256": file_sha256(object_file),
                     "size_bytes": object_file.stat().st_size},
                    {"path": "build/libapp.a", "kind": "library", "sha256": file_sha256(archive),
                     "size_bytes": archive.stat().st_size}], "image_id": "sha256:" + "1" * 64,
    }}}}
    if blocked_case:
        outputs["catalog.projects"]["projects"]["unit-blocked"] = {
            "terminal_status": "COMPLETED_WITH_GAPS", "gaps": [BLOCKED_GAP]}
    fixture_config = worker_config or load_config(tmp_path / "appsec-review.toml")
    JobRunner(fixture_config)._bind_configuration(run_root)
    material = tuple(path for path in sorted(case_root.rglob("*")) if path.is_file())
    result = {"schema": "appsec-review/unit-execution/2", "status": "SUCCEEDED", "steps": {},
              "units": {}, "outputs": outputs, "failed_units": [], "skipped_units": []}
    attempt = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001"
    result_path = attempt / "result.json"
    atomic_json(result_path, result)
    manifest_path = run_root / "data" / "indices" / "manifests" / "cpp.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot="snapshot", target_root=target, indexes=())
    manifest_artifact = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    outputs["acceptance.publish_handoff"] = {"index_manifest": manifest_artifact}
    atomic_json(result_path, result)
    result_artifact = {"path": result_path.relative_to(run_root).as_posix(), "sha256": file_sha256(result_path)}
    handoff_path = attempt / "handoff.json"
    if worker_config is not None:
        bind_release(worker_config, run_root)
    with (worker_scope(worker_config, run_root, preparing_job="job_cpp_compiled_analysis")
          if worker_config is not None else nullcontext()):
        atomic_json(attempt / "claim.json", {
            "dataset_contract": dataset_contract(
                "job_cpp_compiled_analysis",
                sorted({item.step for item in DATASETS} | {unit.split(".")[0] for unit in outputs}), DATASETS),
            **({"worker_protocol": WORKER_PROTOCOL} if worker_config is not None else {}),
        })
        write_fixture_handoff(run_root, handoff_path, {"job_id": "job_cpp_compiled_analysis",
            "attempt_id": "attempt_0001", "status": "ACCEPTED", "completion_status": "SUCCEEDED",
            "source_fingerprint": "snapshot", "artifacts": [result_artifact, manifest_artifact, *(
                {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}
                for path in material)],
            "resolving_paths": {"result": result_artifact["path"]},
            "outputs": outputs})
    handoff_sha = file_sha256(handoff_path)
    latest = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "latest.json"
    atomic_json(latest, {"schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
                         "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": handoff_sha})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": handoff_sha,
        "manifest_path": manifest_artifact["path"], "manifest_sha256": manifest_artifact["sha256"],
    })
    return runs, target


def _cpp_handoffs(runs: Path) -> dict[str, str]:
    latest = runs / RUN_ID / "data" / "jobs" / "job_cpp_compiled_analysis" / "latest.json"
    return {"job_cpp_compiled_analysis": json.loads(latest.read_text(encoding="utf-8"))["handoff_sha256"]}


def _context_inference(request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
    assert request.schema == INFERENCE_PROPOSAL_SCHEMA
    assert (request.provider, request.model) == ("fixture", "fixture") and timeout_seconds == 10
    assert request.guidance and request.summary["schema"] == "appsec-review/build-security-inference-request/1"
    action = request.summary["actions"][0]
    artifact = request.summary["artifacts"][0]
    return ModelResult({"observations": [
        {"claim": "stack protection is missing", "check_id": "gnu.stack_protector",
         "evidence_ids": [action["build_action_id"]]},
        {"claim": "the non-PIE executable contradicts release posture", "check_id": "elf.pie",
         "evidence_ids": [artifact["sha256"]]},
    ]}, input_tokens=21, output_tokens=8, cache_tokens=3)


def test_job_consumes_accepted_handoff_logs_gaps_and_reuses_immutable_shards(tmp_path: Path) -> None:
    config = load_config(_post_build_config(tmp_path))
    runs, target = _accepted_cpp_fixture(tmp_path, worker_config=config)
    workers = [json.loads(path.read_bytes()) for path in
               (runs / RUN_ID / "data" / "recovery" / "workers").glob("*.json")]
    assert len(workers) == 1 and workers[0]["status"] == "EXITED"
    runner, job = JobRunner(config), build_job()
    first = runner.run(job, run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
                       upstream_handoffs=_cpp_handoffs(runs))
    assert first["status"]["status"] == "COMPLETED_WITH_GAPS"
    protected = list((runs / RUN_ID / "data" / "cpp" / "projects" / "unit-a" /
                      "build-security" / "protected-commands").glob("*.json"))
    assert any("super-secret" in item.read_text(encoding="utf-8") for item in protected)
    log_path = runs / RUN_ID / "data" / "logs" / "pipeline.jsonl"
    assert "super-secret" not in log_path.read_text(encoding="utf-8")
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert any(item["event_type"] == "BUILD_COMMAND_PROVENANCE_CAPTURED" for item in events)
    assert any(item["event_type"] == "BUILD_SECURITY_CHECKS_COMPLETED" for item in events)
    assert any(item["event_type"] == "BUILD_SECURITY_INFERENCE_COMPLETED" for item in events)
    assert any(item["event_type"] == "POST_BUILD_SECURITY_ASSESSMENT_COMPLETED" for item in events)
    inspection = first["result"]["outputs"]["inspection.native_units"]["projects"]["unit-a"]["records"][0]
    assert inspection["pinned_tool_observation"]["tool"].startswith("tool-native-cpp:1.0.0")
    assert inspection["symbols"]["defined_names"] == ["main"]
    metrics = aggregate_run_metrics(runs / RUN_ID)
    assert metrics["event_counts"]["TASK_STARTED"] >= 7
    assert metrics["domain_counts"]["inspected_count"] == 3
    assert metrics["domain_counts"]["check_count"] > 0
    second = runner.run(job, run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
                        upstream_handoffs=_cpp_handoffs(runs))
    reused = second["result"]["outputs"]["index.native_units"]["projects"]
    assert len(reused) == 1 and all(item["index_reused"] for item in reused.values())
    metrics = aggregate_run_metrics(runs / RUN_ID)
    assert metrics["domain_counts"]["resumption_count"] == 1
    core = RetrievalCore(runs, RUN_ID)
    library = core.find(name="libapp.a", indexes=("build_security",))["results"][0]
    membership = core.trace(identity=library["identity"], relations=("CONTAINS",), depth=1)
    assert membership["results"] and all(item["exact"] for item in membership["results"])
    object_entity = core.find(name="app.o", indexes=("build_security",))["results"][0]
    linked = core.trace(identity=object_entity["identity"], relations=("LINKS_INTO",), depth=1)
    assert linked["results"] and all(item["exact"] for item in linked["results"])
    accepted = json.loads((runs / RUN_ID / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
    assert accepted["manifest_path"].endswith("build-security-attempt_0002.json")


def test_index_resolves_colliding_object_basenames_by_build_relative_path(tmp_path: Path) -> None:
    config = load_config(_post_build_config(tmp_path))
    runs, target = _accepted_cpp_fixture(tmp_path, colliding_object_names=True)
    result = JobRunner(config).run(
        build_job(), run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
        upstream_handoffs=_cpp_handoffs(runs),
    )
    assert result["status"]["status"] == "COMPLETED_WITH_GAPS"

    core = RetrievalCore(runs, RUN_ID)
    duplicates = core.find(name="profile.cpp.o", indexes=("build_security",))["results"]
    assert len(duplicates) == 2
    links = [core.trace(identity=item["identity"], relations=("LINKS_INTO",), depth=1)
             for item in duplicates]
    assert all(len(value["results"]) == 1 for value in links)
    assert {value["results"][0]["target_id"] for value in links} == {
        core.find(name="libapp.a", indexes=("build_security",))["results"][0]["identity"]}


def test_job_rejects_target_drift_after_cpp_acceptance(tmp_path: Path) -> None:
    config = load_config(_post_build_config(tmp_path))
    runs, target = _accepted_cpp_fixture(tmp_path)
    with pytest.raises(ValueError, match="claimed upstream handoff belongs to a different target"):
        JobRunner(config).run(
            build_job(), run_id=RUN_ID, target_root=target,
            source_fingerprint="changed-after-cpp-acceptance",
            upstream_handoffs=_cpp_handoffs(runs),
        )
    receipt = json.loads((runs / RUN_ID / "data" / "jobs" /
                          "job_post_build_security_assessment" / "attempts" / "attempt_0001" /
                          "status.json").read_text(encoding="utf-8"))
    assert receipt["error"]["message"] == "claimed upstream handoff belongs to a different target"
    assert not (runs / RUN_ID / "data" / "jobs" / "job_post_build_security_assessment" /
                "attempts" / "attempt_0001" / "steps").exists()


def test_a_case_whose_build_was_blocked_upstream_completes_with_gaps_and_no_model_call(tmp_path: Path) -> None:
    config = load_config(_post_build_config(tmp_path, model_enabled=True))
    runs, target = _accepted_cpp_fixture(tmp_path, blocked_case=True)
    outcome = JobRunner(config).run(build_job(infer=_context_inference),
        run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
        upstream_handoffs=_cpp_handoffs(runs))
    assert outcome["status"]["status"] == "COMPLETED_WITH_GAPS"
    outputs = outcome["result"]["outputs"]
    run_root = runs / RUN_ID
    for stage in ("provenance", "inspection", "deterministic", "inference"):
        blocked = outputs[f"{stage}.native_units"]["projects"]["unit-blocked"]
        assert blocked["terminal_status"] == "COMPLETED_WITH_GAPS", stage
        assert file_sha256(run_root / blocked["artifact"]["path"]) == blocked["artifact"]["sha256"], stage
    provenance = outputs["provenance.native_units"]["projects"]["unit-blocked"]
    assert provenance["actions"] == [] and provenance["artifacts"] == [] and provenance["gaps"] == [BLOCKED_GAP]
    inference = outputs["inference.native_units"]["projects"]["unit-blocked"]
    assert inference["model_calls"] == 0 and inference["observations"] == []
    assert any("inference was not run" in gap for gap in inference["gaps"])
    assert outputs["inference.native_units"]["projects"]["unit-a"]["model_calls"] == 1


def test_bounded_inference_records_tokens_and_validates_observations(tmp_path: Path) -> None:
    config = load_config(_post_build_config(tmp_path, model_enabled=True))
    runs, target = _accepted_cpp_fixture(tmp_path)
    outcome = JobRunner(config).run(build_job(infer=_context_inference),
        run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
        upstream_handoffs=_cpp_handoffs(runs))
    inference = outcome["result"]["outputs"]["inference.native_units"]["projects"]["unit-a"]
    assert inference["model_calls"] == 1
    assert inference["confirmed_count"] == 1 and inference["refuted_count"] == 1
    assert {item["validation"] for item in inference["observations"]} == {"CONFIRMED", "REFUTED"}
    metrics = aggregate_run_metrics(runs / RUN_ID)
    assert metrics["model_tokens"] == {"cache_tokens": 3, "input_tokens": 21, "output_tokens": 8}
    assert metrics["domain_counts"]["confirmed_count"] == 1
    assert metrics["domain_counts"]["refuted_count"] == 1
