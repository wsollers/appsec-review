"""Offline remediation fixtures with bounded Infer and executor doubles."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from appsec_review.config.remediation import RemediationPlanningSettings, RemediationValidationSettings
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, CompileCommand, Located
from tests.poc_support import relay_unit

ROOT = Path(__file__).parents[1]
PLAN = "job_remediation_planning"
VALIDATE = "job_remediation_validation"
BOUNDS = {"max_candidates": 16, "max_packages": 1000, "max_source_files": 8, "max_source_bytes": 32000,
          "max_patch_files": 4, "max_patch_bytes": 16000, "max_file_bytes": 64000, "max_edits": 16,
          "max_list_items": 32, "max_text_chars": 2000, "max_workspace_files": 1000,
          "max_workspace_bytes": 1024 * 1024}
MODEL = {"provider": "claude-cli", "model": "claude-haiku-5-5", "reasoning": "high", "max_input_tokens": 32000,
         "max_output_tokens": 8000, "max_turns": 4, "max_queries": 2, "timeout_seconds": 600}
REGRESSION = {"fixtures": ["synthetic input at the accepted buffer boundary"],
              "assertions": ["input is rejected without a write outside the output buffer"],
              "positive_cases": ["within-bound input preserves output bytes"],
              "negative_cases": ["oversize input is rejected before copying"],
              "before": "the missing check permits an invalid copy",
              "after": "invalid input has no observable write side effect",
              "safety_assertion": "synthetic fixtures; never trigger a fault or execute a PoC"}


def planning_settings(**overrides: Any) -> dict[str, Any]:
    return {"enabled": True, "bounds": {**BOUNDS, **overrides}, "writer": dict(MODEL)}


def validation_settings(*, adapters: list[str] | None = None, **overrides: Any) -> dict[str, Any]:
    return {"enabled": True, "bounds": {**BOUNDS, **overrides}, "reviewer": dict(MODEL),
            "adapters": ["native_syntax"] if adapters is None else adapters,
            "command_timeout_seconds": 60, "output_bytes": 4096}


def bounds():
    return RemediationPlanningSettings.from_mapping(planning_settings()).bounds


def patch(path: str, digest: str | None, old: str = "strcpy(b, s);", new: str = "if (strlen(s) < sizeof b) strcpy(b, s);",
          start: int = 0) -> dict[str, Any]:
    return {"schema": "appsec-review/remediation-exact-patch/1",
            "files": [{"path": path, "before_sha256": digest, "absence_proof": digest is None,
                       "edits": [{"start": start, "end": start + len(old.encode()), "old": old, "new": new}]}]}


def answer(evidence: list[str], proposal: dict[str, Any] | None, status: str | None = None) -> dict[str, Any]:
    return {"status": status or ("proposal_generated" if proposal else "manual_design_required"),
            "reason": "bounded local guard correction" if proposal else "architectural source context is unavailable",
            "violated_invariant": "writes must remain within the destination buffer",
            "corrected_invariant": "reject oversized inputs before any destination write",
            "evidence_ids": evidence, "patch": proposal, "compatibility_effects": ["oversized inputs are now rejected"],
            "affected_interfaces": ["input parsing"], "residual_risks": ["caller error handling remains analyst assessed"],
            "deployment_prerequisites": ["developer review and a new snapshot review"],
            "regression_spec": deepcopy(REGRESSION), "validation_checks": ["native syntax and declared source edits"],
            "scope_limitations": ["no runtime regression or release clearance"]}


class Writer:
    def __init__(self, *, invalid: bool = False, semantic: str = "supported", retrieve: bool = False):
        self.requests = []
        self.invalid, self.semantic, self.retrieve = invalid, semantic, retrieve

    def __call__(self, request, *, timeout_seconds):
        self.requests.append(request)
        task = request.task_input["task"]
        if self.invalid:
            return ModelResult({"action": "final", "result": {"commands": ["shell code is not an output field"]}})
        relations = [item["relation_id"] for item in task["accepted_evidence"]]
        if request.role == "remediation_reviewer":
            result = {"decision": self.semantic, "reason": "evidence supports the bounded corrected invariant",
                      "evidence_ids": relations[:1], "residual_concerns": ["runtime behavior remains unverified"]}
        else:
            files = task["source_files"]
            if self.retrieve and files and not request.transcript:
                return ModelResult({"action": "retrieve", "request": {"path": files[0]["path"], "start_line": 1,
                                                                     "end_line": 10}})
            proposal = None
            for source in files:
                old = "strcpy(b, s);"
                if old in source["text"]:
                    offset = source["text"].encode().index(old.encode())
                    proposal = patch(source["path"], source["sha256"], old=old, start=offset)
                    break
            result = answer(relations[:1], proposal)
        return ModelResult({"action": "final", "result": result}, input_tokens=100, output_tokens=100)


class Executor:
    def __init__(self, codes=(0, 0), unavailable=False, mutate=False):
        self.codes, self.unavailable, self.mutate = list(codes), unavailable, mutate
        self.calls = []
        self.resolved = 0

    def resolve(self):
        self.resolved += 1
        if self.unavailable:
            raise RuntimeError("native image unavailable")

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append({"argv": tuple(argv), "workspace": workspace, "working_directory": working_directory,
                           "environment": dict(environment)})
        if self.mutate:
            (workspace / "undeclared.txt").write_text("unexpected source output")
        code = self.codes.pop(0) if self.codes else 0
        return SimpleNamespace(exit_code=code, timed_out=False, stdout=b"", stderr=b"error" if code else b"")


def builds_for(run_root: Path, workspace: Path, manifest: dict[str, str]):
    builds = AcceptedBuilds(run_root, loader=lambda _root: {"receipts": []})

    def locate(name):
        if name != "native/src/parse.c":
            return Located(None, "fixture has no native compiler for this file", "not_c_family")
        command = CompileCommand(("/usr/bin/clang", "-O2", "-Wall", "-c", "/workspace/native/src/parse.c"),
                                 name, "c", ".", "exact")
        return Located(relay_unit(workspace, manifest, compile_command=command, objects=()), "")

    builds.locate = locate
    return builds


def toml_tables() -> str:
    def job(job_id, name, task, table):
        lines = [f"[jobs.{job_id}]", f'name = "{name}"', "workers = 1"]
        import json
        for key, value in table.items():
            if not isinstance(value, dict):
                lines.extend((f"[jobs.{job_id}.settings]" if not any(
                    line == f"[jobs.{job_id}.settings]" for line in lines) else "", f"{key} = {json.dumps(value)}"))
        for key, value in table.items():
            if isinstance(value, dict):
                lines.append(f"[jobs.{job_id}.settings.{key}]")
                lines.extend(f"{field} = {json.dumps(item)}" for field, item in value.items())
        for step, unit in (("load", "verify_inputs"), ("assess", task), ("acceptance", "publish_handoff")):
            lines.extend((f"[jobs.{job_id}.steps.{step}]", "workers = 1",
                          f"[jobs.{job_id}.steps.{step}.tasks.{unit}]", "workers = 1"))
        return "\n".join(lines)
    return job(PLAN, "remediation_planning", "propose", planning_settings()) + "\n" + job(
        VALIDATE, "remediation_validation", "validate", validation_settings()) + "\n"


def add_native_graph_facts(fixture) -> dict[str, str]:
    """Commission actual mapped graph facts before review, rather than relabelling a supported claim."""
    import json
    from appsec_review.graph.contract import Family
    from appsec_review.retrieval import (
        IndexBuilder, IndexIdentity, SourceLocation, index_fingerprint, write_manifest,
    )
    from appsec_review.storage import atomic_json, file_sha256
    from tests.review.test_graph_admissibility import graph_entity, results_for

    root = fixture.run_root
    source = fixture.target / "native" / "src" / "parse.c"
    location = SourceLocation(fixture.snapshot, "native/src/parse.c", file_sha256(source),
                              0, len(source.read_bytes()), 1, 4, 1, 1, {}, "fixture-exact", 1.0)
    entities, ids = [], {}
    span = {"path": "native/src/parse.c", "start_byte": 0, "end_byte": len(source.read_bytes())}
    for key, family in (("fix_sink", Family.SINK_SITE), ("fix_entry", Family.ENTRY_POINT),
                        ("fix_path", Family.DATAFLOW_PATH), ("fix_guard", Family.GUARD_FACT)):
        native = {
            Family.SINK_SITE: {**span, "sink_class": "memory_write", "argument_index": 0},
            Family.ENTRY_POINT: {**span, "source_class": "remote"},
            Family.DATAFLOW_PATH: {"source_identity": ids.get("fix_entry"), "sink_identity": ids.get("fix_sink"),
                                  "step_locations_sha256": "1" * 64},
            Family.GUARD_FACT: {"sink_identity": ids.get("fix_sink"), "condition_path": span["path"],
                               "condition_start_byte": 0, "condition_end_byte": len(source.read_bytes())},
        }[family]
        entity = graph_entity(family, native, results_for(family, sink=ids.get("fix_sink"), entry=ids.get("fix_entry")),
                              location, snapshot=fixture.snapshot)
        entities.append(entity)
        ids[key] = entity.identity.value
    fingerprint = index_fingerprint(name="graph", target_snapshot=fixture.snapshot,
                                    producer_artifacts=[{"fixture": "remediation-native"}],
                                    tool_identity={"tool": "codeql-export"}, parser_identity="fixture/1",
                                    normalizer_identity="fixture/1", mapping_identity="fixture/1")
    shard = root / "data" / "indices" / "graph" / "remediation" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(shard, name="graph", fingerprint=fingerprint,
                           target_snapshot=fixture.snapshot, shard_id="remediation")
    for entity in entities:
        builder.add_entity(entity)
    builder.add_coverage("remediation-native", "complete", None)
    identity = IndexIdentity("graph", "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                             shard.relative_to(root).as_posix(), {"job": "job_code_graph_index"}, (), "remediation")
    manifest_path = root / "data" / "indices" / "manifests" / "fixture.json"
    old = json.loads(manifest_path.read_text())
    indexes = [IndexIdentity(**{**row, "gaps": tuple(row.get("gaps", ()))}) for row in old["indexes"]]
    write_manifest(manifest_path, run_id=fixture.run_id, target_snapshot=fixture.snapshot,
                   target_root=fixture.target, indexes=[*indexes, identity])
    pointer_path = root / "data" / "indices" / "accepted.json"
    pointer = json.loads(pointer_path.read_text())
    handoff_path = root / pointer["handoff_path"]
    handoff = json.loads(handoff_path.read_text())
    for ref in handoff["artifacts"]:
        if ref["path"] == manifest_path.relative_to(root).as_posix():
            ref["sha256"] = file_sha256(manifest_path)
    atomic_json(handoff_path, handoff)
    pointer.update(handoff_sha256=file_sha256(handoff_path), manifest_sha256=file_sha256(manifest_path))
    atomic_json(pointer_path, pointer)
    return ids


def native_review_infer(ids):
    """Real review cells must retrieve and cite each mapped obligation independently."""
    from tests.fixtures.inference_review.fake_infer import ScriptedInfer

    class NativeReview(ScriptedInfer):
        support = [("affected_construct", "fix_sink"), ("attacker_input_control", "fix_path"),
                   ("source_to_sink_reachability", "fix_path"), ("missing_or_ineffective_guard", "fix_guard")]

        def _retrieve_facts(self):
            return self._retrieve([{"tool": "find", "parameters": {"identity": self.ids[key]}}
                                   for key in ("fix_sink", "fix_path", "fix_guard")])

        def _lead_red(self, request, task, payload):
            if self._lead(payload) == "sast_critical" and task in ("lead_red_stack", "lead_red_preconditions"):
                if not request.transcript:
                    return self._retrieve_facts()
                return self._red(request, [self._proposal(
                    "c1", "native/src/parse.c", "CWE-120", "memory_corruption",
                    ["attacker_controls_request_field"], "C1-lead", self.support, lead="sast_critical")])
            return super()._lead_red(request, task, payload)

        def _verifier(self, request, payload):
            if payload["claim"]["security_predicate"] == "memory_corruption":
                if not request.transcript:
                    return self._retrieve_facts()
                predicates = {predicate: {"stance": "supports", "cites": [self.ids[key]]}
                              for predicate, key in self.support}
                return self._final({"disposition": "confirmed", "per_predicate": predicates,
                                    "why": "independent accepted graph facts satisfy the native claim obligations"})
            return super()._verifier(request, payload)

    return NativeReview({"ids": ids})
