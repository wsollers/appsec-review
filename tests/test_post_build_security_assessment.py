from __future__ import annotations

import json
from pathlib import Path
import struct

import pytest

from appsec_review.jobs.job_post_build_security_assessment.assessment import (
    InferenceResult, classify_action, deterministic_checks, inspect_binary, normalize_action,
    redact_argv, sanitize_environment, shard_fingerprint, validate_inference,
)
from appsec_review.jobs.job_post_build_security_assessment import build_job
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.config import load_config
from appsec_review.observability import aggregate_run_metrics
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore,
    write_manifest,
)
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.runtime import JobRunner


RUN_ID = "2026-10-08-9001"


def _elf64(path: Path, *, executable: bool = True) -> None:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = struct.pack("<HHIQQQIHHHHHH", 2 if executable else 1, 62, 1, 0, 64, 0, 0,
                         64, 56, 1, 64, 0, 0)
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    path.write_bytes(ident + header + stack)


def _pe64(path: Path) -> None:
    data = bytearray(0x80 + 24 + 0xF0)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 0, 0, 0, 0, 0xF0, 0x0002)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<H", data, 0x98 + 70, 0x0160)
    path.write_bytes(data)


def _archive(path: Path) -> None:
    payload = b"object"
    header = ("member.o/".ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6) +
              "100644".ljust(8) + str(len(payload)).ljust(10) + "`\n").encode("ascii")
    path.write_bytes(b"!<arch>\n" + header + payload)


def _coff(path: Path) -> None:
    header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 60, 1, 0, 0)
    section = b".text\0\0\0" + struct.pack("<IIIIIIHHI", 1, 0, 1, 60, 0, 0, 0, 0, 0x60000020)
    path.write_bytes(header + section + b"\x90")


def test_redaction_normalization_and_malicious_inputs_do_not_escape() -> None:
    argv = ["clang++", "-DAPI_TOKEN=top-secret", "--password", "also-secret",
            "C:\\Users\\victim\\project\\main.cpp", "-I/home/victim/private/include", "@/tmp/secret.rsp"]
    redacted = redact_argv(argv)
    encoded = json.dumps(redacted)
    assert "top-secret" not in encoded and "also-secret" not in encoded
    assert "C:/Users/victim" not in encoded and "/tmp/secret.rsp" not in encoded and "/home/victim" not in encoded
    assert "<redacted>" in encoded and "<external-path>" in encoded
    environment = sanitize_environment({"CFLAGS": "-O2", "API_TOKEN": "secret", "RANDOM": "host"})
    assert environment["facts"]["CFLAGS"]["value"] == "-O2"
    assert "API_TOKEN" not in environment["facts"] and environment["omitted_count"] == 2
    with pytest.raises(ValueError, match="invalid"):
        redact_argv(["clang", "bad\0argument"])


@pytest.mark.parametrize(("argv", "kind"), [
    (["clang", "-c", "a.c"], "compiler"), (["clang++", "a.o", "-o", "app"], "linker_driver"),
    (["as", "a.s"], "assembler"), (["windres", "a.rc"], "resource_compiler"),
    (["llvm-ar", "rcs", "lib.a", "a.o"], "archiver"), (["lib.exe", "/OUT:x.lib"], "librarian"),
    (["ld.lld", "a.o"], "linker"), (["llvm-strip", "app"], "post_link"),
])
def test_compiler_linker_and_post_link_classification(argv: list[str], kind: str) -> None:
    assert classify_action(argv) == kind


def test_action_provenance_keeps_exact_identity_but_indexes_only_redacted_values() -> None:
    action = normalize_action(
        {"arguments": ["clang", "-c", "src/a.c", "-o", "a.o", "-DSECRET=value"],
         "directory": "/home/user/build"}, action_id="action", run_id=RUN_ID,
        target_snapshot="snapshot", project="project", build_root="build", configuration="Release",
        producer={"job": "compile", "task": "a"},
        toolchain={"executable": "clang", "image_digest": "sha256:" + "1" * 64},
        protected_artifact={"path": "protected/action.json", "sha256": "2" * 64},
    )
    assert action["argv_sha256"]
    assert "value" not in json.dumps(action["argv"])
    assert action["declared_inputs"] == ["src/a.c"] and action["outputs"] == ["a.o"]
    assert action["working_directory"].startswith("<external-path>")


def test_elf_pe_coff_and_archive_are_inspected_without_execution(tmp_path: Path) -> None:
    elf, pe, obj, archive = (tmp_path / name for name in ("app", "app.exe", "a.obj", "lib.a"))
    _elf64(elf)
    _pe64(pe)
    _coff(obj)
    _archive(archive)
    values = [inspect_binary(path) for path in (elf, pe, obj, archive)]
    assert [item["format"] for item in values] == ["ELF", "PE/COFF", "COFF", "archive"]
    assert all(item["executed"] is False for item in values)
    assert values[0]["hardening"]["nx_stack"] is True and values[0]["hardening"]["pie"] is False
    assert values[1]["hardening"] == {"dynamic_base": True, "high_entropy_va": True,
                                      "nx_compat": True, "guard_cf": False,
                                      "safe_seh": None, "gs": None, "sdl": None}
    assert values[2]["relocations"] == [] and values[3]["archive_members"][0]["name"] == "member.o"


def _action(action_id: str, flags: list[str], *, project: str = "p") -> dict:
    return {"classification": "compiler", "argv": ["clang", "-c", "a.c", *flags],
            "build_action_id": action_id, "compile_unit_id": "cu-" + action_id, "project": project}


def test_platform_applicability_mismatch_and_cross_tu_inconsistency() -> None:
    actions = [_action("strong", ["-fstack-protector-strong", "-fPIE"]),
               _action("weak", ["-fno-stack-protector"])]
    artifact = {"artifact_id": "exe", "sha256": "a" * 64, "format": "ELF", "kind": "executable",
                "hardening": {"pie": False, "relro": True, "now": False, "nx_stack": True,
                              "control_flow": None, "stack_canary": None, "fortify": None}}
    checks = deterministic_checks(actions, [artifact])
    by_id = {item["check_id"]: item for item in checks}
    assert by_id["command_binary.pie_mismatch"]["status"] == "FAIL"
    assert by_id["cross_tu.inconsistent.gnu_stack_protector"]["status"] == "FAIL"
    pe = {"artifact_id": "pe", "sha256": "b" * 64, "format": "PE/COFF", "kind": "executable",
          "bits": 64, "hardening": {}}
    pe_checks = deterministic_checks([], [pe])
    assert next(item for item in pe_checks if item["check_id"] == "pe.safe_seh")["status"] == "NOT_APPLICABLE"


def test_inference_is_observation_until_evidence_validation_confirms_or_refutes() -> None:
    checks = [{"check_id": "bad", "status": "FAIL"}, {"check_id": "good", "status": "PASS"},
              {"check_id": "unknown", "status": "UNKNOWN"}]
    proposal = {"observations": [
        {"claim": "bad posture", "check_id": "bad", "evidence_ids": ["e1"]},
        {"claim": "incorrect model claim", "check_id": "good", "evidence_ids": ["e2"]},
        {"claim": "needs evidence", "check_id": "unknown", "evidence_ids": ["e1"]},
        {"claim": "invented", "check_id": "bad", "evidence_ids": ["made-up"]},
    ]}
    result = validate_inference(proposal, checks=checks, evidence_ids={"e1", "e2"})
    assert [item["validation"] for item in result["observations"]] == ["CONFIRMED", "REFUTED", "UNVALIDATED"]
    assert result["confirmed_count"] == result["refuted_count"] == 1 and len(result["rejections"]) == 1


def test_fingerprint_selectively_invalidates_changed_command_and_dependent_binary() -> None:
    base = dict(command_artifacts=[{"sha256": "1" * 64}], binary_hashes=["2" * 64],
                tool_identity={"image": "3" * 64}, model_identity={"model": "m"},
                upstream_manifest_sha256="4" * 64)
    first = shard_fingerprint(**base)
    assert first == shard_fingerprint(**base)
    assert first != shard_fingerprint(**{**base, "command_artifacts": [{"sha256": "5" * 64}]})
    assert first != shard_fingerprint(**{**base, "binary_hashes": ["6" * 64]})
    unrelated = shard_fingerprint(**{**base, "command_artifacts": [{"sha256": "7" * 64}]})
    assert unrelated != first  # another project/shard retains its own independent fingerprint


def _retrieval_fixture(tmp_path: Path) -> RetrievalCore:
    runs, run_root = tmp_path / "runs", tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    target.mkdir()
    attempt = run_root / "data" / "jobs" / "post" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    fingerprint = "1" * 64
    shard = "build-security-case-001"
    path = run_root / "data" / "indices" / "build_security" / "fixture.sqlite"
    builder = IndexBuilder(path, name="build_security", fingerprint=fingerprint,
                           target_snapshot="snapshot", shard_id=shard)
    identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, "snapshot", {"id": "action-1"})
    builder.add_entity(EntityRecord(identity, "action-1", "action-1", "clang redacted",
        {"project": "project-a", "build_root": "build-a", "configuration": "Release",
         "build_action_id": "action-1", "compile_unit_id": "cu-1", "linked_artifact_ids": ["bin-1"],
         "producer": {"job": "compile-job"}, "shard": shard}))
    builder.add_coverage("post-build-security", "partial", "exact link timing unavailable")
    sha = builder.build()
    index = IndexIdentity("build_security", "appsec-review/retrieval-index/1", sha, fingerprint,
                          path.relative_to(run_root).as_posix(), {"job": "post"},
                          ("exact link timing unavailable",), shard)
    manifest_path = run_root / "data" / "indices" / "manifest.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot="snapshot", target_root=target, indexes=(index,))
    artifact = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    handoff_path = attempt / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                               "job_id": "post", "artifacts": [artifact]})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path), "manifest_path": artifact["path"],
        "manifest_sha256": artifact["sha256"],
    })
    return RetrievalCore(runs, RUN_ID)


def test_build_security_core_and_thin_mcp_support_every_scope(tmp_path: Path) -> None:
    core = _retrieval_fixture(tmp_path)
    adapter = RetrievalMcpAdapter(core)
    scopes = {"project": "project-a", "build_root": "build-a", "build_action": "action-1",
              "configuration": "Release", "compile_unit": "cu-1", "linked_artifact": "bin-1",
              "producer": "compile-job", "shard": "build-security-case-001"}
    for key, value in scopes.items():
        response = adapter.call("query_build_security", {key: value})
        assert len(response["results"]) == 1
        assert any("exact link timing unavailable" in gap for gap in response["coverage_gaps"])
    assert adapter.call("query_build_security", {"project": "missing"})["results"] == []


def test_job_topology_is_parallel_per_case_and_publishes_after_all_shards() -> None:
    job = build_job()
    ids = {unit.unit_id: unit for unit in job.units}
    assert len(job.units) == 7
    assert ids["inspection.native_units"].dependencies == ("provenance.native_units",)
    assert ids["inference.native_units"].dependencies == (
        "provenance.native_units", "inspection.native_units", "deterministic.native_units")
    assert ids["publication.publish_handoff"].dependencies == ("index.native_units",)


def _post_build_config(root: Path, *, model_enabled: bool = False) -> Path:
    lines = ["[runtime]", 'runs_dir = "runs"', 'data_dir = "data"', 'metadata_dir = "runs/metadata"',
             "", "[jobs.job_post_build_security_assessment]", 'name = "post_build_security_assessment"',
             "workers = 4", "", "[jobs.job_post_build_security_assessment.settings.model]",
             f"enabled = {'true' if model_enabled else 'false'}", 'provider = "fixture"', 'model = "fixture"', 'reasoning = "medium"',
             "max_input_tokens = 32000", "max_output_tokens = 1000", "timeout_seconds = 10", "retries = 0", "",
             "[jobs.job_post_build_security_assessment.steps.load]", "workers = 1",
             "[jobs.job_post_build_security_assessment.steps.load.tasks.accepted_cpp_build]", ""]
    for step in ("provenance", "inspection", "deterministic", "inference", "index"):
        lines.extend((f"[jobs.job_post_build_security_assessment.steps.{step}]", "workers = 4"))
        lines.append(f"[jobs.job_post_build_security_assessment.steps.{step}.tasks.native_units]")
        lines.append("")
    lines.extend(("[jobs.job_post_build_security_assessment.steps.publication]", "workers = 1",
                  "[jobs.job_post_build_security_assessment.steps.publication.tasks.publish_handoff]"))
    path = root / "appsec-review.toml"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _accepted_cpp_fixture(tmp_path: Path) -> tuple[Path, Path]:
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
    (link_dir / "link.txt").write_text(
        "llvm-ar rcs libapp.a app.o\nclang++ app.o -Wl,-z,relro,-z,now -pie -o app\n", encoding="utf-8")
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
    result = {"schema": "appsec-review/unit-execution/2", "status": "SUCCEEDED", "steps": {},
              "units": {}, "outputs": outputs, "failed_units": [], "skipped_units": []}
    attempt = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001"
    result_path = attempt / "result.json"
    atomic_json(result_path, result)
    manifest_path = run_root / "data" / "indices" / "manifests" / "cpp.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot="snapshot", target_root=target, indexes=())
    result_artifact = {"path": result_path.relative_to(run_root).as_posix(), "sha256": file_sha256(result_path)}
    manifest_artifact = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}
    handoff_path = attempt / "handoff.json"
    atomic_json(handoff_path, {"schema": "appsec-review/job-handoff/1", "job_id": "job_cpp_compiled_analysis",
        "attempt_id": "attempt_0001", "status": "ACCEPTED", "completion_status": "SUCCEEDED",
        "source_fingerprint": "snapshot", "artifacts": [result_artifact, manifest_artifact],
        "resolving_paths": {"result": result_artifact["path"]},
        "outputs": {"acceptance.publish_handoff": {"index_manifest": manifest_artifact}}})
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


def test_job_consumes_accepted_handoff_logs_gaps_and_reuses_immutable_shards(tmp_path: Path) -> None:
    runs, target = _accepted_cpp_fixture(tmp_path)
    config = load_config(_post_build_config(tmp_path))
    runner, job = JobRunner(config), build_job()
    first = runner.run(job, run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
                       upstream_handoffs={"job_cpp_compiled_analysis": "a" * 64})
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
                        upstream_handoffs={"job_cpp_compiled_analysis": "a" * 64})
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


def test_job_rejects_target_drift_after_cpp_acceptance(tmp_path: Path) -> None:
    runs, target = _accepted_cpp_fixture(tmp_path)
    config = load_config(_post_build_config(tmp_path))
    with pytest.raises(RuntimeError, match="load.accepted_cpp_build"):
        JobRunner(config).run(
            build_job(), run_id=RUN_ID, target_root=target,
            source_fingerprint="changed-after-cpp-acceptance",
            upstream_handoffs={"job_cpp_compiled_analysis": "a" * 64},
        )
    result = json.loads((runs / RUN_ID / "data" / "jobs" /
                         "job_post_build_security_assessment" / "attempts" /
                         "attempt_0001" / "result.json").read_text(encoding="utf-8"))
    assert result["units"]["load.accepted_cpp_build"]["error"]["message"] == (
        "post-build target snapshot differs from accepted build"
    )


class _ContextInferenceClient:
    def complete(self, request, *, timeout_seconds: int) -> InferenceResult:
        action = request["actions"][0]
        artifact = request["artifacts"][0]
        return InferenceResult({"observations": [
            {"claim": "stack protection is missing", "check_id": "gnu.stack_protector",
             "evidence_ids": [action["build_action_id"]]},
            {"claim": "the non-PIE executable contradicts release posture", "check_id": "elf.pie",
             "evidence_ids": [artifact["sha256"]]},
        ]}, input_tokens=21, output_tokens=8, cache_tokens=3)


def test_bounded_inference_records_tokens_and_validates_observations(tmp_path: Path) -> None:
    runs, target = _accepted_cpp_fixture(tmp_path)
    config = load_config(_post_build_config(tmp_path, model_enabled=True))
    outcome = JobRunner(config).run(build_job(inference_client=_ContextInferenceClient()),
        run_id=RUN_ID, target_root=target, source_fingerprint="snapshot",
        upstream_handoffs={"job_cpp_compiled_analysis": "a" * 64})
    inference = outcome["result"]["outputs"]["inference.native_units"]["projects"]["unit-a"]
    assert inference["model_calls"] == 1
    assert inference["confirmed_count"] == 1 and inference["refuted_count"] == 1
    assert {item["validation"] for item in inference["observations"]} == {"CONFIRMED", "REFUTED"}
    metrics = aggregate_run_metrics(runs / RUN_ID)
    assert metrics["model_tokens"] == {"cache_tokens": 3, "input_tokens": 21, "output_tokens": 8}
    assert metrics["domain_counts"]["confirmed_count"] == 1
    assert metrics["domain_counts"]["refuted_count"] == 1
