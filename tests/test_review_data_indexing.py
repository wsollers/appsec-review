"""First indexing batch: dataset inventory/audit, SAST lead menus, build facts, metric vectors,
stage-1 products, cross-domain links, MCP routes and offline FTS image validation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.indexing import fts_worker, input_matrix, inventory, products
from appsec_review.indexing.build_facts import classify_command, classify_environment
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    RetrievalCore, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.observations import SEVERITY_RULE, normalize_reported_severity
from appsec_review.jobs.job_review_data_indexing import build_job
from appsec_review.jobs.job_review_package_assembly import build_job as build_package_job
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "containers" / "tools" / "sqlite-fts" / "sqlite_fts.py"
SNAPSHOT = "target-sha256:" + "7" * 64
SECRETS = ("supersecretvalue", "hunter2plaintext", "/tmp/evil.so", "/home/user/secret")


def test_scanner_menu_partition_fits_review_package_page() -> None:
    jobs = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["jobs"]
    partition = jobs["job_review_data_indexing"]["settings"]["menu_partition_size"]
    page = jobs["job_review_package_assembly"]["settings"]["max_page_size"]
    assert 1 <= partition <= page <= 100


def _configured(tmp_path: Path, extra: str = ""):
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8") + extra
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    shutil.copytree(ROOT / "containers", tmp_path / "containers")
    base = load_config(tmp_path / "appsec-review.toml")
    return replace(base, runtime=replace(base.runtime, runs_dir=tmp_path / "runs", data_dir=tmp_path / "data",
                                         metadata_dir=tmp_path / "runs" / "metadata"))


@dataclass
class FakeResult:
    exit_code: int | None
    timed_out: bool
    oom_killed: bool
    image_id: str
    stdout_path: str
    receipt_path: str


class LocalSqliteFts:
    """Runs the pinned tool's script in-process-equivalent, mapping /target and /scratch mounts."""

    def __init__(self, run_root: Path, image_id: str):
        self.run_root, self.image_id, self.calls = run_root, image_id, []

    def execute(self, request) -> FakeResult:
        assert request.tool_id == "tool-sqlite-fts" and request.argv[0] == "/opt/tool/bin/sqlite-fts"
        scratch = request.scratch_root
        scratch.mkdir(parents=True, exist_ok=True)

        def mapped(value: str) -> str:
            for mount, source in (("/target", request.target_root), ("/scratch", scratch)):
                if value == mount or value.startswith(mount + "/"):
                    return str(source) + value[len(mount):]
            return value
        argv = [sys.executable, str(TOOL), *(mapped(item) for item in request.argv[1:])]
        completed = subprocess.run(argv, capture_output=True, check=False)
        (scratch / "raw").mkdir(exist_ok=True)
        (scratch / "raw" / "stdout.bin").write_bytes(completed.stdout)
        atomic_json(scratch / "execution.json", {"tool_id": request.tool_id, "exit_code": completed.returncode})
        self.calls.append(request.argv[1])
        return FakeResult(completed.returncode, False, False, self.image_id,
                          (scratch / "raw" / "stdout.bin").relative_to(self.run_root).as_posix(),
                          (scratch / "execution.json").relative_to(self.run_root).as_posix())


def _location(target: Path, path: str, line: int) -> SourceLocation:
    data = (target / path).read_bytes()
    offsets = [0, *(match.end() for match in re.finditer(b"\n", data))]
    end = offsets[line] if line < len(offsets) else len(data)
    return SourceLocation(SNAPSHOT, path, hashlib.sha256(data).hexdigest(), offsets[line - 1], end, line, line,
                          1, 1, {"fixture": True}, "producer-line-location", 1.0)


def _file_location(target: Path, path: str) -> SourceLocation:
    data = (target / path).read_bytes()
    return SourceLocation(SNAPSHOT, path, hashlib.sha256(data).hexdigest(), 0, len(data), 1,
                          len(data.splitlines()), 1, 1, {"fixture": True}, "tree-sitter-file-span", 1.0)


def _accepted_run(tmp_path: Path, config) -> tuple[str, Path, Path, dict[str, str]]:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "auth.c").write_text("int check(char *in) {\n  char buf[8]; strcpy(buf, in);\n  return 0;\n}\n",
                                           encoding="utf-8")
    (target / "src" / "util.c").write_text("void run(char *c) {\n  /* x */\n  system(c); // nosemgrep\n}\n",
                                           encoding="utf-8")
    runner = JobRunner(config)
    run_id, run_root = runner.runs.create(datetime(2026, 10, 10, tzinfo=timezone.utc))
    runner._bind_configuration(run_root)
    ids: dict[str, str] = {}

    def identity(kind: EntityKind, native: Any) -> str:
        return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native}).value

    for path in ("src/auth.c", "src/util.c"):
        ids[path] = identity(EntityKind.SOURCE_FILE, path)
    shards: list[IndexIdentity] = []

    def shard(name: str, shard_id: str, producer: dict[str, Any], entities: list[EntityRecord],
              relations: list[RelationRecord] = (), coverage: tuple[str, str, str | None] | None = None) -> None:
        fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity=producer, parser_identity="fixture/1",
                                        normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(*(coverage or (shard_id, "complete", None)))
        shards.append(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                    path.relative_to(run_root).as_posix(), producer, (), shard_id))

    catalog = {"job": "job_target_catalog"}
    shard("source", "default", catalog, [EntityRecord(LogicalIdentity.parse(ids[path]), path, path, path,
                                                      {"language": "C"}, _file_location(target, path))
                                         for path in ("src/auth.c", "src/util.c")])

    def observation(key: str, tool: str, rule: str, severity: str, path: str | None, line: int, **extra: Any):
        ids[key] = identity(EntityKind.TOOL_OBSERVATION, key)
        payload = {"tool_id": tool, "native_rule_id": rule, "native_severity": severity, "category": "source_sast",
                   "message": f"{rule} lead", "language": "C", **extra}
        return EntityRecord(LogicalIdentity.parse(ids[key]), key, rule, f"{rule} {tool}", payload,
                            _location(target, path, line) if path else None)

    semgrep_artifact = identity(EntityKind.EVIDENCE_ARTIFACT, "semgrep-evidence")
    semgrep = [observation("o1", "tool-semgrep", "c.strcpy", "ERROR", "src/auth.c", 2, rule_mapping={"cwe": ["CWE-120"]}),
               observation("o2", "tool-semgrep", "c.system", "CRITICAL", "src/util.c", 3),
               observation("o3", "tool-semgrep", "c.weird", "SEVERE-ISH", "src/util.c", 1),
               observation("o4", "tool-semgrep", "c.style", "WARNING", "src/auth.c", 3),
               EntityRecord(LogicalIdentity.parse(semgrep_artifact), "semgrep", "semgrep evidence", "semgrep", {})]
    shard("observations", "semgrep", {"job": "job_evidence_collection", "producer": "tool-semgrep"}, semgrep,
          [RelationRecord(RelationKind.OBSERVED_AT, ids["o1"], ids["src/auth.c"], True, 1.0),
           RelationRecord(RelationKind.OBSERVED_AT, ids["o2"], ids["src/util.c"], True, 1.0),
           *(RelationRecord(RelationKind.DERIVED_FROM, ids[key], semgrep_artifact, True, 1.0)
             for key in ("o1", "o2", "o3", "o4"))])
    shard("observations", "opengrep", {"job": "job_evidence_collection", "producer": "tool-opengrep"},
          [observation("o5", "tool-opengrep", "c.strcpy-og", "HIGH", "src/auth.c", 2, rule_mapping={"cwe": ["CWE-120"]})],
          coverage=("tool-opengrep", "partial", "opengrep scan timed out on one file"))
    shard("observations", "codeql-cpp-native", {"job": "job_codeql_analysis", "language": "cpp",
                                                "build_unit_id": "native-main"},
          [observation("o6", "codeql", "cpp/overflow", "error", "src/auth.c", 2, producer="codeql",
                       producer_level="error", security_severity="9.8")])
    ids["dep"] = identity(EntityKind.TOOL_OBSERVATION, "dep")
    ids["inv"] = identity(EntityKind.TOOL_OBSERVATION, "inv")
    shard("observations", "osv_scanner", {"job": "job_evidence_collection", "producer": "tool-osv-scanner"},
          [EntityRecord(LogicalIdentity.parse(ids["dep"]), "dep", "GHSA-test-0001", "openssl advisory",
                        {"tool_id": "tool-osv-scanner", "category": "vulnerability_matching", "package": "openssl",
                         "advisory": "GHSA-test-0001", "native_severity": "HIGH"})])
    shard("observations", "syft", {"job": "job_evidence_collection", "producer": "tool-syft"},
          [EntityRecord(LogicalIdentity.parse(ids["inv"]), "inv", "openssl", "openssl package",
                        {"tool_id": "tool-syft", "category": "software_inventory", "package": "openssl",
                         "native_severity": "INFO"})])

    ids["action"] = LogicalIdentity.derive(EntityKind.BUILD_ACTION, SNAPSHOT, {"build_unit_id": "native-main",
                                                                               "command_id": "cmd-1"}).value
    ids["unit"] = identity(EntityKind.COMPILE_UNIT, "auth.c")
    ids["exe"] = identity(EntityKind.EXECUTABLE, "server")
    events_path = run_root / "data" / "build" / "native" / "native-main" / "capture" / "events.jsonl"
    events_path.parent.mkdir(parents=True)
    events_path.write_text(json.dumps({
        "schema": "appsec-review/build-syscall-event/2", "ordinal": 1, "kind": "process_exec", "result": 0,
        "argv": ["/usr/bin/cc", "-c", "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
                 "-DAPI_TOKEN=supersecretvalue", "-I/target/source/include", "-o", "/target/source/build/auth.o",
                 "/target/source/src/auth.c"],
        "envp": [{"name": "CC", "value": "/usr/bin/gcc", "redacted": False},
                 {"name": "GITHUB_TOKEN", "value": "<redacted>", "redacted": True},
                 {"name": "MY_PASSWORD", "value": "hunter2plaintext", "redacted": False},
                 {"name": "LD_PRELOAD", "value": "/tmp/evil.so", "redacted": False},
                 {"name": "CFLAGS", "value": "-O2 -fstack-protector-strong -I/home/user/secret", "redacted": False}],
    }, sort_keys=True) + "\n", encoding="utf-8")
    events_sha = file_sha256(events_path)
    shard("build", "language-build", {"job": "job_language_build", "unit": "acceptance.publish_handoff"}, [
        EntityRecord(LogicalIdentity.parse(ids["action"]), "cmd-1", "cc command", "cc compile",
                     {"command_id": "cmd-1", "tool": "cc", "tool_kind": "compiler", "argv_sha256": "a" * 64,
                      "build_unit_id": "native-main", "working_directory": "/target/source",
                      "execution_capture": {"events_sha256": events_sha, "complete": True}}),
        EntityRecord(LogicalIdentity.parse(ids["unit"]), "auth.c", "auth.c compile unit", "compile unit", {})],
        [RelationRecord(RelationKind.GENERATED_FROM, ids["unit"], ids["src/auth.c"], True, 1.0)])
    ids["sec"] = identity(EntityKind.TOOL_OBSERVATION, "sec")
    shard("artifacts", "catalog-native-main", {"job": "job_artifact_indexing"}, [
        EntityRecord(LogicalIdentity.parse(ids["exe"]), "build/server", "server", "executable server",
                     {"build_unit_id": "native-main", "workspace_path": "build/server", "sha256": "b" * 64,
                      "kind": "executable"})],
        [RelationRecord(RelationKind.GENERATED_FROM, ids["exe"], ids["action"], True, 1.0),
         RelationRecord(RelationKind.COMPILES_TO, ids["unit"], ids["exe"], True, 1.0)])
    shard("observations", "artifact-security", {"job": "job_artifact_security_analysis"}, [
        EntityRecord(LogicalIdentity.parse(ids["sec"]), "sec", "no-relro", "binary hardening",
                     {"tool_id": "tool-blint", "category": "binary_hardening", "native_severity": "MEDIUM",
                      "sha256": "b" * 64})],
        [RelationRecord(RelationKind.OBSERVED_AT, ids["sec"], ids["exe"], True, 1.0)])

    ids["priority"] = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, SNAPSHOT, {"item_id": "file:src/auth.c"}).value
    shard("priority", "review-prioritization", {"job": "job_review_prioritization"}, [
        EntityRecord(LogicalIdentity.parse(ids["priority"]), "file:src/auth.c", "src/auth.c", "priority auth",
                     {"item_id": "file:src/auth.c", "scope": "file", "path": "src/auth.c", "language": "C",
                      "rank": 1, "score": 77.0, "features": {"cyclomatic": 7, "cognitive": 9,
                                                              "complexity_density": 0.3,
                                                              "share_above_threshold": None}, "gaps": []},
                     _file_location(target, "src/auth.c"))])
    ids["auth-function"] = identity(EntityKind.PRIORITY_ITEM, "function:src/auth.c:check")
    ids["other-function"] = identity(EntityKind.PRIORITY_ITEM, "function:src/auth.c:other")
    function_location = _file_location(target, "src/auth.c")
    shard("priority", "functions", {"job": "job_review_prioritization"}, [
        EntityRecord(LogicalIdentity.parse(ids["auth-function"]), "function:check", "check", "priority check",
                     {"scope": "function", "language": "C", "features": {}}, function_location),
        EntityRecord(LogicalIdentity.parse(ids["other-function"]), "function:other", "other", "priority other",
                     {"scope": "function", "language": "C", "features": {}},
                     _location(target, "src/auth.c", 4))])
    ids["auth-tag"] = identity(EntityKind.TAG_ASSIGNMENT, "auth-tag")
    ids["lead-tag"] = identity(EntityKind.TAG_ASSIGNMENT, "lead-tag")
    ids["util-tag"] = identity(EntityKind.TAG_ASSIGNMENT, "util-tag")
    shard("tags", "security-tags", {"job": "job_security_tagging"}, [
        EntityRecord(LogicalIdentity.parse(ids["auth-tag"]), "auth-tag", "surface:memory", "tag auth",
                     {"tag": "surface:memory", "basis": "reported", "family": "attack_surface",
                      "subject": {"kind": "source_file", "logical_id": ids["src/auth.c"],
                                  "path": "src/auth.c"}}),
        EntityRecord(LogicalIdentity.parse(ids["lead-tag"]), "lead-tag", "surface:memory", "tag lead",
                     {"tag": "surface:memory", "basis": "reported", "family": "attack_surface",
                      "subject": {"kind": "tool_observation", "logical_id": ids["o1"]}}),
        EntityRecord(LogicalIdentity.parse(ids["util-tag"]), "util-tag", "surface:command", "tag util",
                     {"tag": "surface:command", "basis": "reported", "family": "attack_surface",
                      "subject": {"kind": "source_file", "logical_id": ids["src/util.c"],
                                  "path": "src/util.c"}})])
    ids["ast-check"] = identity(EntityKind.AST_NODE, "check")
    shard("analysis", "cpp-auth-ast", {"job": "job_cpp_compiled_analysis"}, [
        EntityRecord(LogicalIdentity.parse(ids["ast-check"]), "check", "check", "FunctionDecl check",
                     {"kind": "FunctionDecl", "compile_unit_id": "auth-unit"},
                     _location(target, "src/auth.c", 1))])
    ids["history"] = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, SNAPSHOT, {"scope": "file", "path": "src/auth.c"}).value
    ids["hotspot"] = identity(EntityKind.HOTSPOT, "hotspot-auth")
    shard("history", "git-history", {"job": "job_source_history_analysis", "vcs": "git"}, [
        EntityRecord(LogicalIdentity.parse(ids["history"]), "file:src/auth.c", "src/auth.c", "history auth",
                     {"lines_added": 40, "lines_deleted": 12, "churn_lines": 52, "relative_churn": 13.0,
                      "change_count": 9, "revision_frequency": 0.75, "author_count": 3, "author_entropy": 1.2,
                      "fix_on_fix_count": 2, "sii": {"rank": 1, "tier": 1, "score": 0.91}},
                     _file_location(target, "src/auth.c")),
        EntityRecord(LogicalIdentity.parse(ids["hotspot"]), "hotspot:file:src/auth.c", "src/auth.c", "hotspot",
                     {"window": {"months": 12}, "rank": 1, "tier": 1, "score": 0.91},
                     _file_location(target, "src/auth.c"))])

    manifest_path = run_root / "data" / "indices" / "manifests" / "fixture-attempt_0001.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=shards)
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path)}

    def handoff(job_id: str, artifacts: list[dict[str, str]], outputs: dict[str, Any]) -> tuple[Path, str]:
        attempt = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
        path = attempt / "handoff.json"
        atomic_json(path, {"schema": "appsec-review/job-handoff/1", "job_id": job_id, "attempt_id": "attempt_0001",
                           "status": "ACCEPTED", "completion_status": "SUCCEEDED", "outputs": outputs,
                           "artifacts": artifacts, "source_fingerprint": SNAPSHOT})
        sha = file_sha256(path)
        atomic_json(attempt.parent.parent / "latest.json", {"schema": "appsec-review/latest-handoff/1",
                                                            "attempt_id": "attempt_0001",
                                                            "handoff_path": path.relative_to(run_root).as_posix(),
                                                            "handoff_sha256": sha})
        return path, sha

    syntax_path = (run_root / "data" / "jobs" / "job_review_prioritization" / "attempts" / "attempt_0001" / "steps" /
                   "extract" / "tasks" / "syntax_metrics" / "artifacts" / "syntax.json")
    atomic_json(syntax_path, {"files": {
        "src/util.c": {"component_id": "core", "language": "C", "suppression_count": 1, "suppressions": [
            {"signal_id": "sup-1", "tool": "semgrep", "scope": "line", "start_line": 3, "path": "src/util.c"}]},
        "src/auth.c": {"component_id": "core", "language": "C", "suppression_count": 0, "suppressions": []}}})
    syntax = {"path": syntax_path.relative_to(run_root).as_posix(), "sha256": file_sha256(syntax_path)}
    handoff("job_evidence_collection", [], {"evidence_publication.assemble_manifest": {"dispositions": [
        {"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED"},
        {"tool_id": "tool-opengrep", "terminal_status": "PARTIAL"}]}})
    handoff("job_language_build", [{"path": events_path.relative_to(run_root).as_posix(), "sha256": events_sha}], {})
    priority_handoff, priority_sha = handoff(
        "job_review_prioritization", [manifest, syntax],
        {"extract.syntax_metrics": {"artifact": syntax}, "publish.index_priority": {"index_manifest": manifest}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": priority_handoff.relative_to(run_root).as_posix(), "handoff_sha256": priority_sha,
        "manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    return run_id, run_root, target, ids


def _run(config, run_id: str, target: Path, executor=None):
    factory = (lambda unit: executor) if executor is not None else None
    return JobRunner(config).run(build_job(executor_factory=factory), run_id=run_id, target_root=target,
                                 source_fingerprint=SNAPSHOT)


def _facts(core: RetrievalCore, query_set: str) -> list[dict[str, Any]]:
    results, cursor = [], None
    while True:
        page = core.query_precomputed(query_set=query_set, limit=100, cursor=cursor)
        results.extend(page["results"])
        cursor = page["pagination"]["next_cursor"]
        if cursor is None:
            return results


@pytest.fixture()
def accepted(tmp_path_factory):
    # Shard paths are deep; a short root keeps Windows paths under MAX_PATH.
    tmp_path = tmp_path_factory.mktemp("r")
    config = _configured(tmp_path)
    run_id, run_root, target, ids = _accepted_run(tmp_path, config)
    image_id = "sha256:29c26f5f95b21855ada7cafce12f3bfa44c97a0f12e685f6a6c9084123109a27"
    executor = LocalSqliteFts(run_root, image_id)
    outcome = _run(config, run_id, target, executor)
    return config, run_id, run_root, target, ids, outcome, executor


def test_sast_lead_menus_are_complete_and_traceable(accepted) -> None:
    config, run_id, _run_root, _target, ids, outcome, _executor = accepted
    assert outcome["handoff"]["status"] == "ACCEPTED"
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    facts = _facts(core, "scanner_correlation")
    leads = {item["payload"]["result"]["observation_id"]: item["payload"]["result"] for item in facts
             if item["payload"]["fact_type"] == "lead"}
    assert set(leads) == {ids[key] for key in ("o1", "o2", "o3", "o4", "o5", "o6")}
    assert leads[ids["o2"]]["suppressed"] is True and leads[ids["o2"]]["suppression_ids"] == ["sup-1"]
    assert leads[ids["o3"]]["normalized_reported_severity"] == "unknown"
    assert leads[ids["o6"]]["normalized_reported_severity"] == "critical"
    assert leads[ids["o6"]]["severity_basis"] == "security-severity-cvss-band"
    duplicated = [key for key in ("o1", "o5") if leads[ids[key]]["duplicate_of"]]
    assert len(duplicated) == 1
    menus = [item["payload"]["result"] for item in facts if item["payload"]["fact_type"] == "menu"]
    high = {member["observation_id"] for menu in menus if menu["menu"] == "high_critical" for member in menu["members"]}
    assert high == {ids[key] for key in ("o1", "o2", "o5", "o6")}
    assert {member["observation_id"] for menu in menus if menu["menu"] == "unknown"
            for member in menu["members"]} == {ids["o3"]}
    audit = next(item["payload"]["result"] for item in facts if item["payload"]["fact_type"] == "audit")
    assert audit["status"] == "passed" and audit["counts"]["high_critical_suppressed"] == 1
    assert audit["counts"]["high_critical_duplicates"] == 1


def test_review_packages_keep_complete_membership_and_detect_tampering(accepted) -> None:
    from copy import deepcopy
    from appsec_review.review_packages import (_identity, assemble_review_packages, publish_review_packages,
                                                validate_packages, verify_review_packages)

    config, run_id, _run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    packages, manifest = assemble_review_packages(core, max_page_size=20)
    finding = [item for item in packages if item["kind"] == "finding_lead"]
    hunts = [item for item in packages if item["kind"] == "hunt"]
    assert {item["lead_menu"][0]["observation_id"] for item in finding} == {
        ids[key] for key in ("o1", "o2", "o3", "o4", "o5", "o6")}
    assert {lead["observation_id"] for item in hunts for lead in item["lead_menu"]} == {
        ids[key] for key in ("o1", "o2", "o3", "o5", "o6")}
    assert manifest["counts"] == {"finding_lead": 6, "hunt": len(hunts), "high_critical": 4, "unknown": 1}
    assert any(gap["state"] == "partial" for gap in manifest["coverage_gaps"])
    assert any(item["metrics"] for item in packages)
    assert any(item["build_context"]["command_facts"] for item in packages)
    auth = next(item for item in finding if item["lead_menu"][0]["observation_id"] == ids["o1"])
    assert auth["build_context"]["bindings"][0]["function_scope_id"] == ids["auth-function"]
    assert auth["build_context"]["bindings"][0]["action_ids"] == [ids["action"]]
    assert auth["tag_context"]["cloud"] == [{"tag": "surface:memory", "assignment_count": 2}]
    assert auth["compiled_context"][0]["entity_id"] == ids["ast-check"]
    assert all(metric["scope_id"] != ids["other-function"] for metric in auth["metrics"])
    assert not any(secret in json.dumps(auth) for secret in SECRETS)
    assert not any(item["tag"] == "surface:command" for item in auth["tag_context"]["assignments"])
    util = next(item for item in finding if item["lead_menu"][0]["observation_id"] == ids["o2"])
    assert not util["build_context"]["command_facts"]
    assert util["build_context"]["bindings"][0]["function_scope_id"] is None
    assert any(gap["producer"] == "function_scope" for gap in util["coverage_gaps"])
    assert assemble_review_packages(core, max_page_size=20) == (packages, manifest)
    expected = {"all": {item["lead_menu"][0]["observation_id"] for item in finding},
                "high_critical": {lead["observation_id"] for item in hunts for lead in item["lead_menu"]
                                  if lead["reported_severity"] in {"high", "critical"}},
                "unknown": {lead["observation_id"] for item in hunts for lead in item["lead_menu"]
                            if lead["reported_severity"] == "unknown"}}
    audit = {"status": "passed", "counts": {"source_sast_observations": 6,
             "high_critical": 4, "unknown_severity": 1}}
    missing = deepcopy(packages)
    changed = next(item for item in missing if item["kind"] == "hunt" and len(item["lead_menu"]) > 1)
    changed["lead_menu"].pop()
    changed["package_id"] = _identity(changed)
    with pytest.raises(ValueError, match="membership"):
        validate_packages(core, missing, expected, audit)
    extra = deepcopy(packages)
    extra[0]["unexpected"] = True
    with pytest.raises(Exception, match="unexpected"):
        validate_packages(core, extra, expected, audit)
    from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
    secret = b"integration-capability-secret-32-bytes"
    selected = finding[0]
    token = issue_capability(selected, role="red", round_id="1", secret=secret,
                             expires_at=int(datetime.now(timezone.utc).timestamp()) + 300)
    scoped = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), selected, capability=token,
                                       secret=secret, role="red", round_id="1")
    subject = selected["lead_menu"][0]["observation_id"]
    assert scoped.call("query_precomputed", {"query_set": "scanner_correlation", "subject": subject,
                                             "limit": 1})["results"]
    auth_token = issue_capability(auth, role="red", round_id="1", secret=secret,
                                  expires_at=int(datetime.now(timezone.utc).timestamp()) + 300)
    auth_scoped = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), auth, capability=auth_token,
                                            secret=secret, role="red", round_id="1")
    assert auth_scoped.call("find", {"identity": ids["auth-tag"]})["results"]
    assert auth_scoped.call("find", {"identity": ids["ast-check"]})["results"]
    assert auth_scoped.call("find", {"identity": ids["auth-function"]})["results"]
    assert auth_scoped.call("find", {"identity": ids["action"]})["results"]
    with pytest.raises(ValueError, match="outside review package"):
        auth_scoped.call("find", {"identity": ids["util-tag"]})
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("find", {"identity": next(item["lead_menu"][0]["observation_id"] for item in finding
                                                if item["package_id"] != selected["package_id"])})
    directory = publish_review_packages(core, max_page_size=20)
    assert verify_review_packages(core, directory) == manifest
    target = directory / f"{finding[0]['package_id']}.json"
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        verify_review_packages(core, directory)


def test_query_observations_filters_and_paginates_without_raw_output(accepted) -> None:
    config, run_id, _run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    adapter = RetrievalMcpAdapter(core)
    high = adapter.call("query_observations", {"severity": "high", "observation_class": "source_sast"})
    assert {item["identity"] for item in high["results"]} == {ids["o1"], ids["o5"]}
    assert all(item["reported_severity"]["rule"] == SEVERITY_RULE for item in high["results"])
    assert {item["reported_severity"]["native"] for item in high["results"]} == {"ERROR", "HIGH"}
    assert any("opengrep scan timed out" in gap for gap in high["coverage_gaps"])
    suppressed = core.query_observations(suppressed=True)
    assert [item["identity"] for item in suppressed["results"]] == [ids["o2"]]
    assert core.query_observations(duplicate=True)["results"][0]["lead_state"]["duplicate_of"]
    assert [item["identity"] for item in core.query_observations(severity="unknown")["results"]] == [ids["o3"]]
    located = core.query_observations(path="src/auth.c", start_line=2, end_line=2, scanner="tool-semgrep")
    assert [item["identity"] for item in located["results"]] == [ids["o1"]]
    assert [item["identity"] for item in core.query_observations(source=ids["src/util.c"])["results"]] == [ids["o2"]]
    first = core.query_observations(observation_class="source_sast", limit=2)
    assert first["results"][0]["reported_severity"]["value"] == "critical"
    second = core.query_observations(observation_class="source_sast", limit=2, cursor=first["pagination"]["next_cursor"])
    assert not {item["identity"] for item in first["results"]} & {item["identity"] for item in second["results"]}
    with pytest.raises(ValueError):
        core.query_observations(observation_class="source_sast", limit=3, cursor=first["pagination"]["next_cursor"])
    with pytest.raises(ValueError):
        core.query_observations(severity="severe")
    with pytest.raises(ValueError):
        core.query_observations(start_line=2)


def test_build_facts_keep_order_and_never_expose_exact_argv_or_environment(accepted) -> None:
    config, run_id, run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    facts = _facts(core, "build_provenance")
    action = next(item["payload"]["result"] for item in facts if item["payload"]["fact_type"] == "build_action")
    command = action["command_facts"][0]
    assert set(command) == {"build_action_id", "tool_id", "ordered_tokens", "exact_artifact_sha256",
                            "normalization_rule"}
    assert [token["ordinal"] for token in command["ordered_tokens"]] == list(range(10))
    kinds = [token["kind"] for token in command["ordered_tokens"]]
    assert kinds[:4] == ["tool", "mode", "optimization", "security_flag"]
    assert "-D_FORTIFY_SOURCE=2" in action["security_flags"] and "-fstack-protector-strong" in action["security_flags"]
    assert action["source_inputs"] == ["target:src/auth.c"]
    define = next(token for token in command["ordered_tokens"] if token["kind"] == "define")
    assert define["redacted"] is True and "supersecretvalue" not in json.dumps(define)
    environment = {item["class"]: item for item in action["environment_facts"]}
    assert environment["loader_injection"]["present"] and "safe_value" not in environment["loader_injection"]
    assert environment["toolchain_selection"]["safe_value"] == "gcc"
    assert environment["compiler_flags"]["safe_value"] == "-fstack-protector-strong"
    assert "sensitive_variable" in environment
    chain = next(item["payload"]["result"] for item in facts if item["payload"].get("subject_identity") == ids["exe"])
    assert chain["sources"] == [ids["src/auth.c"]] and chain["observations"] == [ids["sec"]]
    for database in (run_root / "data" / "indices").rglob("*.sqlite"):
        if "precomputed" in database.parts or "inventory" in database.parts or "links" in database.parts:
            raw = database.read_bytes()
            assert not any(secret.encode() in raw for secret in SECRETS), database


def test_metric_vectors_mark_missing_values_unknown_not_zero(accepted) -> None:
    config, run_id, _run_root, _target, ids, _outcome, _executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    vector = next(item["payload"]["result"] for item in _facts(core, "history_context")
                  if item["payload"]["fact_type"] == "metric_vector"
                  and item["payload"].get("subject_identity") == ids["priority"])
    metrics = {item["name"]: item for item in vector["metrics"]}
    assert metrics["revision_count"]["value"] == 9 and metrics["revision_count"]["window_days"] == 365
    assert metrics["sii_score"]["producer"] == "job_source_history_analysis"
    assert metrics["cognitive"]["algorithm_version"] == "appsec-review/cognitive-complexity-approx/1"
    assert metrics["cyclomatic_high_risk_share"]["status"] == "unavailable"
    assert metrics["cyclomatic_high_risk_share"]["value"] is None and metrics["cyclomatic_high_risk_share"]["gap_id"]
    assert metrics["cyclomatic_mean"]["gap_id"] == "cyclomatic_mean_not_produced_by_prioritization"


def test_package_job_publishes_accepted_manifest_and_receipts(accepted) -> None:
    config, run_id, run_root, target, ids, indexing, _executor = accepted
    from appsec_review.review_packages import assemble_review_packages
    seed_core = RetrievalCore(config.runtime.runs_dir, run_id)
    seed_packages, seed_manifest = assemble_review_packages(seed_core)
    partial = run_root / "data" / "review-packages" / seed_manifest["content_sha256"]
    partial.mkdir(parents=True)
    atomic_json(partial / f"{seed_packages[0]['package_id']}.json", seed_packages[0])
    outcome = JobRunner(config).run(
        build_package_job(), run_id=run_id, target_root=target, source_fingerprint=SNAPSHOT,
        upstream_handoffs={"job_review_data_indexing": indexing["handoff_sha256"]})
    assert outcome["handoff"]["status"] == "ACCEPTED"
    result = outcome["result"]["outputs"]["publication.publish_packages"]
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    from appsec_review.review_packages import verify_review_packages
    manifest = verify_review_packages(core, run_root / result["package_directory"])
    assert manifest["accepted_manifest_sha256"] == core.manifest_sha256
    assert manifest["counts"]["finding_lead"] == 6
    assert result["package_count"] == len(manifest["packages"])
    assert result["coverage_gap_count"] == len(manifest["coverage_gaps"])
    assert {item["path"] for item in outcome["handoff"]["artifacts"]} >= {
        item["path"] for item in result["artifacts"]}
    auth = next(json.loads((run_root / result["package_directory"] / f"{item['package_id']}.json").read_text())
                for item in manifest["packages"]
                if json.loads((run_root / result["package_directory"] / f"{item['package_id']}.json").read_text())
                ["lead_menu"][0]["observation_id"] == ids["o1"])
    assert auth["build_context"]["bindings"][0]["function_scope_id"] == ids["auth-function"]
    assert auth["tag_context"]["cloud"]
    assert auth["compiled_context"]


def test_inventory_audit_matrices_links_and_fts_validation(accepted) -> None:
    config, run_id, _run_root, _target, ids, outcome, executor = accepted
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    adapter = RetrievalMcpAdapter(core)
    audit = adapter.call("query_dataset_inventory", {"record_type": "audit"})["results"][0]["payload"]
    assert audit["status"] == "PASSED", audit["violations"]
    rows = [item["payload"] for item in core.query_dataset_inventory(record_type="dataset",
                                                                    job="job_review_data_indexing", limit=100)["results"]]
    assert {row["query_set"] for row in rows if row["output_kind"] == "precomputed_products"} >= set(products.FIRST_STAGE_SETS)
    assert {row["output_kind"] for row in rows} >= {
        "accepted_input_summary", "cross_domain_links", "precomputed_products", "derived_checkpoints",
        "fts_image_validation", "dataset_audit_report", "coverage_matrices", "dataset_inventory"}
    self_row = next(row for row in rows if row["output_kind"] == "dataset_inventory")
    assert self_row["index"]["hash_resolution"] == "accepted_manifest"
    unavailable = core.query_dataset_inventory(record_type="dataset", disposition="unavailable", limit=100)
    assert unavailable["results"] and all(item["payload"]["coverage"]["reason"] for item in unavailable["results"])
    assert not any(item["payload"].get("job_id") == "job_review_package_assembly"
                   for item in unavailable["results"])
    sources = []
    cursor = None
    while True:
        page = core.query_dataset_inventory(cell_type="input_source", limit=100, cursor=cursor)
        sources.extend(page["results"])
        cursor = page["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert len(sources) == len(input_matrix.INPUT_SOURCES)
    language = core.query_dataset_inventory(cell_type="language", limit=100)["results"]
    native = next(item["payload"] for item in language if item["payload"]["language"] == "c/c++")
    assert native["lanes"]["cpg_graph"]["state"] == "unavailable" and native["lanes"]["codeql"]["state"] == "complete"
    fts = core.query_dataset_inventory(cell_type="fts_validation")["results"][0]["payload"]
    assert fts["status"] == "verified" and fts["image_id"].startswith("sha256:29c26f5f")
    assert executor.calls == ["probe", "build", "verify"]
    package = core.find(kind="dependency_package", indexes=("links",))["results"]
    assert package and package[0]["payload"]["identity_basis"] == "name-only"
    traced = core.trace(identity=package[0]["identity"], relations=("AFFECTED_BY",), depth=1)
    assert traced["results"] and not traced["results"][0]["exact"]
    assert outcome["result"]["outputs"]["publish.inventory_index"]["index_manifest"]["path"]


def test_rerun_reuses_unchanged_products_and_rebuilds_only_changed_rule(accepted, monkeypatch) -> None:
    config, run_id, _run_root, target, _ids, _outcome, executor = accepted
    second = _run(config, run_id, target, executor)
    outputs = second["result"]["outputs"]
    assert all(outputs[f"precompute.{name}"]["reused"] for name in products.FIRST_STAGE_SETS)
    assert all(item["reused"] for item in outputs["links.cross_domain"]["links"])
    changed = tuple(replace(rule, version="dependency-advisories/2") if rule.query_set == "dependency_advisories"
                    else rule for rule in products.PRODUCT_RULES)
    monkeypatch.setattr(products, "PRODUCT_RULES", changed)
    third = _run(config, run_id, target, executor)["result"]["outputs"]
    assert not third["precompute.dependency_advisories"]["reused"]
    assert all(third[f"precompute.{name}"]["reused"] for name in products.FIRST_STAGE_SETS
               if name != "dependency_advisories")


def test_audit_violation_blocks_acceptance_but_keeps_report(tmp_path_factory) -> None:
    tmp_path = tmp_path_factory.mktemp("v")
    config = _configured(tmp_path)
    run_id, run_root, target, _ids = _accepted_run(tmp_path, config)
    stray = run_root / "data" / "stray" / "unexpected.bin"
    stray.parent.mkdir(parents=True)
    stray.write_bytes(b"x")
    pointer = (run_root / "data" / "indices" / "accepted.json").read_bytes()
    with pytest.raises(Exception, match="partial failure|audit"):
        _run(config, run_id, target, LocalSqliteFts(run_root, "sha256:" + "0" * 64))
    reports = list(run_root.glob("data/jobs/job_review_data_indexing/attempts/*/steps/audit/tasks/inventory/inventory.json"))
    assert reports
    violations = json.loads(reports[0].read_text(encoding="utf-8"))["audit"]["violations"]
    assert any(item["code"] == "unaccounted_file" and item["subject"] == "data/stray/unexpected.bin"
               for item in violations)
    assert (run_root / "data" / "indices" / "accepted.json").read_bytes() == pointer


def test_inventory_rejects_truncated_or_unreadable_run_tree(tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / "run"
    data = run_root / "data"
    data.mkdir(parents=True)
    (data / "first.json").write_text("{}", encoding="utf-8")
    (data / "second.json").write_text("{}", encoding="utf-8")
    inputs = inventory.InventoryInputs(run_root, "2026-10-10-0001", SNAPSHOT, {}, {}, {}, {}, {}, [], max_files=1)
    truncated = inventory.build_inventory(inputs)
    assert truncated["audit"]["status"] == "FAILED"
    assert "run_tree_truncated" in {item["code"] for item in truncated["audit"]["violations"]}

    original_scandir = os.scandir

    def unreadable(path):
        if Path(path) == data:
            raise PermissionError("simulated unreadable run data")
        return original_scandir(path)

    monkeypatch.setattr(inventory.os, "scandir", unreadable)
    blocked = inventory.build_inventory(replace(inputs, max_files=10))
    assert blocked["audit"]["status"] == "FAILED"
    assert "run_tree_unreadable" in {item["code"] for item in blocked["audit"]["violations"]}


def test_inventory_rehashes_accepted_handoff_artifacts(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    artifact = run_root / "data" / "artifacts" / "capture.bin"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"changed after acceptance")
    handoff = AcceptedHandoff("job_test", {"source_fingerprint": SNAPSHOT,
                                          "artifacts": [{"path": artifact.relative_to(run_root).as_posix(),
                                                         "sha256": "0" * 64}]},
                              "1" * 64, "data/jobs/job_test/handoff.json")
    result = inventory.build_inventory(inventory.InventoryInputs(
        run_root, "2026-10-10-0001", SNAPSHOT, {"job_test": []}, {"job_test": []}, {},
        {"job_test": handoff}, {}, []))
    assert "artifact_hash_mismatch" in {item["code"] for item in result["audit"]["violations"]}


def test_fts_image_validation_gaps_and_required_mode(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    path = run_root / "data" / "indices" / "precomputed" / "x.sqlite"
    builder = IndexBuilder(path, name="precomputed", fingerprint="f" * 64, target_snapshot=SNAPSHOT, shard_id="qs-x")
    builder.add_entity(EntityRecord(LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"k": 1}), "k",
                                    "lead", "authorization lead text", {}))
    builder.add_coverage("x", "complete")
    shard = {"name": "precomputed", "shard_id": "qs-x", "sha256": builder.build(),
             "relative_path": path.relative_to(run_root).as_posix()}

    def missing():
        raise RuntimeError("cataloged image is not locally available: tool-sqlite-fts")
    from appsec_review.container_runtime import ExecutionRequest
    kwargs = dict(expected_image_id="sha256:" + "1" * 64, request_type=ExecutionRequest, max_records=10,
                  max_input_bytes=10000, max_text_bytes=1000)
    optional = fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "a", [shard],
                                          mode="optional", executor_factory=missing, **kwargs)
    assert optional["status"] == "unavailable" and "not locally available" in optional["gaps"][0]
    with pytest.raises(fts_worker.FtsValidationError):
        fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "b", [shard], mode="required",
                                   executor_factory=missing, **kwargs)
    wrong = LocalSqliteFts(run_root, "sha256:" + "2" * 64)
    mismatch = fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "c", [shard],
                                          mode="optional", executor_factory=lambda: wrong, **kwargs)
    assert mismatch["status"] == "unavailable" and "differs from the pinned catalog id" in mismatch["gaps"][0]
    right = LocalSqliteFts(run_root, "sha256:" + "1" * 64)
    verified = fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "d", [shard],
                                          mode="optional", executor_factory=lambda: right, **kwargs)
    assert verified["status"] == "verified" and verified["probes"][0]["equal"]
    assert verified["secret_pattern_documents"] == 0 and not verified["gaps"]

    class MalformedOutput(LocalSqliteFts):
        def execute(self, request):
            result = super().execute(request)
            if request.argv[1] == "build":
                (self.run_root / result.stdout_path).write_text("not-json", encoding="utf-8")
            return result

    malformed = fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "malformed", [shard],
                                           mode="optional", executor_factory=lambda: MalformedOutput(run_root,
                                                                                                       "sha256:" + "1" * 64),
                                           **kwargs)
    assert malformed["status"] == "unavailable" and "invalid report" in malformed["gaps"][0]
    skipped = fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "e", [shard],
                                         mode="optional", executor_factory=lambda: right,
                                         **{**kwargs, "max_records": 0})
    assert skipped["status"] == "skipped"
    with pytest.raises(fts_worker.FtsValidationError):
        fts_worker.validate_shards(run_root, run_root / "data" / "indexing" / "fts" / "required-bound", [shard],
                                   mode="required", executor_factory=lambda: right,
                                   **{**kwargs, "max_records": 0})

    unsafe_path = path.with_name("unsafe.sqlite")
    unsafe_builder = IndexBuilder(unsafe_path, name="precomputed", fingerprint="e" * 64,
                                  target_snapshot=SNAPSHOT, shard_id="qs-unsafe")
    unsafe_builder.add_entity(EntityRecord(
        LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, SNAPSHOT, {"k": "unsafe"}),
        "unsafe", "unsafe", "token=supersecretvalue", {}))
    unsafe_builder.add_coverage("unsafe", "complete")
    unsafe_shard = {"name": "precomputed", "shard_id": "qs-unsafe", "sha256": unsafe_builder.build(),
                    "relative_path": unsafe_path.relative_to(run_root).as_posix()}
    unsafe_scratch = run_root / "data" / "indexing" / "fts" / "unsafe"
    refused = fts_worker.validate_shards(run_root, unsafe_scratch, [unsafe_shard], mode="optional",
                                         executor_factory=lambda: right, **kwargs)
    assert refused["status"] == "skipped" and "sensitive key/value" in refused["gaps"][0]
    assert not (unsafe_scratch / "input" / "documents.jsonl").exists()


def test_severity_normalization_and_safe_classification_rules() -> None:
    assert normalize_reported_severity({"native_severity": "ERROR"})["value"] == "high"
    assert normalize_reported_severity({"native_severity": "weird"})["value"] == "unknown"
    assert normalize_reported_severity({"tool_id": "tool-spotbugs", "native_severity": "1"})["value"] == "high"
    assert normalize_reported_severity({"tool_id": "tool-x", "native_severity": "1"})["value"] == "unknown"
    assert normalize_reported_severity({"producer_level": "note", "security_severity": "7.5"})["value"] == "high"
    tokens = classify_command(["gcc", "-o", "/home/u/out", "@/tmp/rsp", "-L/opt/x", "-lssl", "main.c"])
    assert [token["kind"] for token in tokens] == ["tool", "output_flag", "output", "response_file", "library_path",
                                                   "library", "source_input"]
    assert tokens[2] == {"ordinal": 2, "kind": "output", "redacted": True, "safe_value": "<external-path>"}
    defines = classify_command(["cc", "-DRELEASE_NAME=publicvalue", "-DNDEBUG=1"])
    assert defines[1] == {"ordinal": 1, "kind": "define", "redacted": True,
                          "safe_value": "-DRELEASE_NAME=<redacted>"}
    assert defines[2] == {"ordinal": 2, "kind": "define", "redacted": False, "safe_value": "-DNDEBUG=1"}
    env = classify_environment(["AWS_SECRET_ACCESS_KEY=abc", "SOURCE_DATE_EPOCH=1700000000", "HOME=/root"])
    assert env["unclassified_variable_count"] == 1
    assert {item["class"] for item in env["environment_facts"]} == {"sensitive_variable", "reproducibility"}
    assert all("abc" not in json.dumps(item) for item in env["environment_facts"])


def test_input_source_matrix_matches_design_document_and_registry() -> None:
    document = (ROOT / "docs" / "architecture" / "indexing-and-query-reuse.md").read_text(encoding="utf-8")
    section = document.split("### Input-source and retrieval matrix", 1)[1].split("\n\n", 3)
    table = next(part for part in section if part.lstrip().startswith("| Input source"))
    rows = [line for line in table.splitlines() if line.startswith("| ") and not line.startswith("| Input source")
            and not line.startswith("|---")]
    assert len(rows) == len(input_matrix.INPUT_SOURCES)
    from appsec_review.runtime.registry import builtin_registry
    registered = set(builtin_registry().job_ids())
    named = {producer for _source, producers, *_ in input_matrix.INPUT_SOURCES for producer in producers}
    assert registered - {"job_review_data_indexing", "job_review_package_assembly"} <= named
    assert {producer for producer in named if producer.startswith("job_")} <= registered
