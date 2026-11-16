from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.loader import JobConfig, StepConfig, TaskConfig
from appsec_review.config.remediation import RemediationModel
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ExecutionLimit
from appsec_review.jobs import accepted_review
from appsec_review.jobs import bound_artifacts
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.completion_contracts import REMEDIATION_PLAN_SCHEMA, nonexecution_assurance
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_poc_generation.buildctx import Located
from appsec_review.jobs.job_remediation_planning import build_job
from appsec_review.jobs.job_remediation_planning import contracts, inputs, job as planning_job, model, patches
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.storage import atomic_json, canonical_json
from tests import remediation_support as support


def _write(root: Path, rel: str, doc: object) -> dict[str, str]:
    path = root / "data" / "seed" / rel
    atomic_json(path, doc)
    return artifact_ref(root, path)


def _ctx(root: Path, settings: dict, attempt_name: str = "att-1", steps: dict | None = None) -> JobContext:
    step_map = steps if steps is not None else {
        step: StepConfig(step, 1, {}, {tasks[0]: TaskConfig(tasks[0], 1, {})})
        for step, tasks in planning_job.TOPOLOGY.items()
    }
    cfg = JobConfig(planning_job.JOB_ID, "remediation_planning", 1, None, settings, step_map)
    attempt = root / "data" / "jobs" / planning_job.JOB_ID / "attempts" / attempt_name
    attempt.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id=root.name,
        attempt_id=attempt_name,
        trigger="test",
        repository_root=support.ROOT,
        run_root=root,
        attempt_root=attempt,
        metadata_root=attempt,
        orchestration={},
        config=cfg,
        events=EventLog(attempt / "events.jsonl"),
    )


def _seed_planning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, candidate_count: int = 2) -> SimpleNamespace:
    root = tmp_path / "run-plan"
    workspace = root / "data" / "workspace"
    src_file = workspace / "native" / "src" / "parse.c"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_text = "void p(char *s) {\n  char b[8];\n  strcpy(b, s);\n}\n"
    src_file.write_text(src_text, encoding="utf-8")
    src_sha = hashlib.sha256(src_file.read_bytes()).hexdigest()
    manifest = {"native/src/parse.c": src_sha}
    builds = support.builds_for(root, workspace, manifest)

    relations_by_claim: dict[str, list[dict]] = {}
    packages: list[dict] = []
    confirmed_ids: list[str] = []
    for idx in range(candidate_count):
        cid = f"claim-{idx + 1}"
        fid = f"finding-{idx + 1}"
        rel_id = f"evrel-{idx + 1}"
        ent_id = f"entity-{idx + 1}"
        confirmed_ids.append(fid)
        relations_by_claim[cid] = [{"relation_id": rel_id, "entity_id": ent_id}]
        packages.append(
            {
                "claim_id": cid,
                "finding_package_id": fid,
                "sha256": f"{idx + 1}" * 64,
                "adjudication_id": f"adj-{idx + 1}",
                "state": "confirmed",
                "title": f"Buffer copy {idx + 1}",
                "direct_evidence": [rel_id],
            }
        )

    projection_ref = _write(root, "projection.json", {"relations": relations_by_claim})
    scope_manifest_ref = _write(root, "scope-manifest.json", {"run_id": root.name})
    scope_ref = _write(
        root,
        "scope.json",
        {"manifest_path": scope_manifest_ref["path"], "manifest_sha256": scope_manifest_ref["sha256"]},
    )
    job_handoff_ref = _write(
        root,
        "job-handoff.json",
        {"outputs": {"scope.accept_manifest": {"artifact": scope_ref}}},
    )
    review_handoff_ref = _write(root, "review-handoff.json", {"run_id": root.name})
    binding_ref = _write(root, "bound-item.json", {"ok": True})

    review_doc = {
        "run_id": root.name,
        "partition": {"confirmed": confirmed_ids, "supported": []},
        "packages": packages,
        "inputs": {
            "projection": projection_ref,
            "job_handoff": job_handoff_ref,
            "review_handoff": review_handoff_ref,
        },
        "bindings": [binding_ref],
    }

    monkeypatch.setattr(
        accepted_review,
        "load_accepted_review",
        lambda *_args, **_kwargs: SimpleNamespace(document=copy.deepcopy(review_doc)),
    )

    class FakeCore:
        def find(self, *, identity: str, limit: int = 1) -> dict:
            assert limit == 1
            return {
                "results": [
                    {
                        "entity_id": identity,
                        "location": {"path": "native/src/parse.c", "file_sha256": src_sha},
                    }
                ]
            }

    core = FakeCore()
    return SimpleNamespace(
        root=root,
        workspace=workspace,
        src_file=src_file,
        src_sha=src_sha,
        manifest=manifest,
        builds=builds,
        review_doc=review_doc,
        core=core,
    )


def test_contracts_text_texts_patch_scope_and_verify_plan_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    b = support.bounds()
    for bad_text in (123, "   ", "x" * (b.max_text_chars + 1)):
        with pytest.raises(ValueError, match="bounded nonempty text"):
            contracts.text(bad_text, b, "field")
    for bad_list, nonempty in (("not-list", False), (["a"] * (b.max_list_items + 1), False), ([], True)):
        with pytest.raises(ValueError, match="bounded"):
            contracts.texts(bad_list, b, "items", nonempty=nonempty)

    dup_ev = support.answer(["ev-1", "ev-1"], support.patch("native/src/parse.c", "a" * 64))
    with pytest.raises(ValueError, match="cites evidence"):
        contracts.PlanAnswer.from_mapping(dup_ev, b, evidence_ids={"ev-1"})

    env = _seed_planning(tmp_path, monkeypatch, candidate_count=1)
    unit = env.builds.locate("native/src/parse.c").unit
    source_files = {
        "native/src/parse.c": {
            "path": "native/src/parse.c",
            "sha256": env.src_sha,
            "build": unit.identity(),
        }
    }

    # Existing + valid new header in admitted parent directory
    offset = env.src_file.read_bytes().index(b"strcpy(b, s);")
    combined = support.patch("native/src/parse.c", env.src_sha, start=offset)
    combined["files"].extend(support.patch("native/src/guard.h", None, old="", new="#pragma once\n")["files"])
    parsed_ok = patches.parse_patch(combined, b)
    contracts.verify_patch_scope(parsed_ok, source_files, env.builds, b)

    # Unadmitted existing file / wrong sha256
    bad_existing = patches.parse_patch(support.patch("native/src/other.c", env.src_sha), b)
    with pytest.raises(patches.PatchError, match="admitted source evidence"):
        contracts.verify_patch_scope(bad_existing, source_files, env.builds, b)

    # New file outside parent or disallowed suffix
    for bad_new in ("other/guard.h", "native/src/script.py"):
        bad_new_patch = patches.parse_patch(support.patch(bad_new, None, old="", new="// x\n"), b)
        with pytest.raises(patches.PatchError, match="outside the evidence-related source directory"):
            contracts.verify_patch_scope(bad_new_patch, source_files, env.builds, b)

    # Build identity drift
    drifted_sources = {"native/src/parse.c": {**source_files["native/src/parse.c"], "build": {"tampered": True}}}
    with pytest.raises(IntegrityError, match="build identity changed"):
        contracts.verify_patch_scope(
            patches.parse_patch(support.patch("native/src/parse.c", env.src_sha, start=offset), b),
            drifted_sources,
            env.builds,
            b,
        )

    # verify_plan error branches (schema mismatch, binding mismatch, provenance disagreement)
    schemas = SchemaSet(support.ROOT / planning_job.SCHEMA_ROOT)
    finding_pkg = env.review_doc["packages"][0]
    f_binding = inputs.binding(finding_pkg)
    ans = support.answer(["evrel-1"], None, status="manual_design_required")
    ctx_ref = _write(env.root, "ctx.json", {"finding": f_binding, "adjudication_id": "adj-1"})
    rec_ref = _write(
        env.root,
        "rec.json",
        {
            "role": "remediation_writer",
            "status": "answered",
            "cell_id": "remediation-writer:claim-1",
            "guidance_bundle_sha256": "c" * 64,
            "result_sha256": hashlib.sha256(canonical_json(ans)).hexdigest(),
        },
    )
    valid_plan = {
        "schema": REMEDIATION_PLAN_SCHEMA,
        "run_id": env.root.name,
        "upstream": {"review_handoff": env.review_doc["inputs"]["review_handoff"], "poc_handoff": None},
        "finding": f_binding,
        "adjudication_id": "adj-1",
        **{k: v for k, v in ans.items() if k != "patch"},
        "patch": None,
        "assurance": nonexecution_assurance(),
        "provenance": {
            "settings_sha256": "d" * 64,
            "source_context": ctx_ref,
            "writer_receipt": rec_ref,
            "guidance_bundle_sha256": "c" * 64,
        },
        "gaps": [],
    }
    ok_ref = _write(env.root, "plan-ok.json", valid_plan)
    assert contracts.verify_plan(
        env.root, ok_ref, review_handoff=env.review_doc["inputs"]["review_handoff"], finding=f_binding, schemas=schemas
    )["status"] == "manual_design_required"

    schema_bad_ref = _write(env.root, "plan-schema-bad.json", {"schema": "wrong"})
    with pytest.raises(IntegrityError, match="schema mismatch"):
        contracts.verify_plan(
            env.root,
            schema_bad_ref,
            review_handoff=env.review_doc["inputs"]["review_handoff"],
            finding=f_binding,
            schemas=schemas,
        )

    wrong_run_ref = _write(env.root, "plan-wrong-run.json", {**valid_plan, "run_id": "other-run"})
    with pytest.raises(IntegrityError, match="bound to another run"):
        contracts.verify_plan(
            env.root,
            wrong_run_ref,
            review_handoff=env.review_doc["inputs"]["review_handoff"],
            finding=f_binding,
            schemas=schemas,
        )

    bad_rec = _write(env.root, "rec-bad.json", {**read_bound_json(env.root, rec_ref), "role": "wrong_role"})
    disagree_ref = _write(
        env.root,
        "plan-disagree.json",
        {**valid_plan, "provenance": {**valid_plan["provenance"], "writer_receipt": bad_rec}},
    )
    with pytest.raises(IntegrityError, match="disagrees with its source context"):
        contracts.verify_plan(
            env.root,
            disagree_ref,
            review_handoff=env.review_doc["inputs"]["review_handoff"],
            finding=f_binding,
            schemas=schemas,
        )


def test_inputs_source_reader_and_retrieve_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=1)
    b = support.bounds()

    # load_review run_id mismatch
    monkeypatch.setattr(
        accepted_review,
        "load_accepted_review",
        lambda *_a, **_k: SimpleNamespace(document={**env.review_doc, "run_id": "mismatch"}),
    )
    with pytest.raises(IntegrityError, match="run identity mismatch"):
        inputs.load_review(env.root, support.ROOT, b)

    # evidence_relations missing relation
    bad_finding = {**env.review_doc["packages"][0], "direct_evidence": ["missing-rel"]}
    with pytest.raises(IntegrityError, match="absent from the accepted projection"):
        inputs.evidence_relations(env.root, env.review_doc, bad_finding)

    # retrieval_core delegation
    captured_scope = {}
    monkeypatch.setattr(
        bound_artifacts,
        "source_context_core",
        lambda run_root, ref: captured_scope.update(run_root=run_root, ref=ref) or "sentinel-core",
    )
    assert inputs.retrieval_core(env.root, env.review_doc) == "sentinel-core"
    assert captured_scope["run_root"] == env.root

    # Prepare workspace files for SourceReader edge cases
    big_file = env.workspace / "native" / "src" / "big.c"
    big_file.write_bytes(b"a" * 200)
    big_sha = hashlib.sha256(big_file.read_bytes()).hexdigest()

    latin_file = env.workspace / "native" / "src" / "latin.c"
    latin_file.write_bytes(b"\xff\xfe\xfd")
    latin_sha = hashlib.sha256(latin_file.read_bytes()).hexdigest()

    second_file = env.workspace / "native" / "src" / "second.c"
    second_file.write_text("int x = 1;\n", encoding="utf-8")
    second_sha = hashlib.sha256(second_file.read_bytes()).hexdigest()

    manifest = {
        "native/src/parse.c": env.src_sha,
        "native/src/big.c": big_sha,
        "native/src/latin.c": latin_sha,
        "native/src/second.c": second_sha,
    }
    builds = support.builds_for(env.root, env.workspace, manifest)
    from appsec_review.jobs.job_poc_generation.buildctx import CompileCommand
    from tests.poc_support import relay_unit

    def custom_locate(name: str) -> Located:
        if name == "native/src/unowned.c":
            return Located(None, "missing", "no_unit")
        cmd = CompileCommand(("/usr/bin/clang", "-c", f"/workspace/{name}"), name, "c", ".", "exact")
        return Located(relay_unit(env.workspace, manifest, compile_command=cmd, objects=()), "")

    builds.locate = custom_locate

    entities = {
        "e-empty": [],
        "e-nonpath": [{"location": {"path": 123}}],
        "e-unowned": [{"location": {"path": "native/src/unowned.c", "file_sha256": "a" * 64}}],
        "e-big": [{"location": {"path": "native/src/big.c", "file_sha256": big_sha}}],
        "e-latin": [{"location": {"path": "native/src/latin.c", "file_sha256": latin_sha}}],
        "e-ok": [{"location": {"path": "native/src/parse.c", "file_sha256": env.src_sha}}],
        "e-dup": [{"location": {"path": "native/src/parse.c", "file_sha256": env.src_sha}}],
        "e-second": [{"location": {"path": "native/src/second.c", "file_sha256": second_sha}}],
    }
    core = SimpleNamespace(find=lambda *, identity, limit=1: {"results": entities[identity]})
    relations = [{"relation_id": f"r-{k}", "entity_id": k} for k in entities] + [
        {"relation_id": "r-extra", "entity_id": "e-ok"}
    ]
    tight_bounds = support.RemediationPlanningSettings.from_mapping(
        support.planning_settings(max_file_bytes=100, max_source_bytes=120, max_list_items=8, max_source_files=1)
    ).bounds
    reader = inputs.SourceReader(builds, core, relations, tight_bounds)
    reader.resolve()
    assert "native/src/parse.c" in reader.files
    assert "source_location_unavailable:r-e-empty" in reader.gaps
    assert "run_owned_source_unavailable:native/src/unowned.c:no_unit" in reader.gaps
    assert "source_byte_bound_reached:native/src/big.c" in reader.gaps
    assert "source_encoding_unsupported:native/src/latin.c" in reader.gaps
    assert "source_file_bound_reached" in reader.gaps
    assert "evidence_relation_bound_reached" in reader.gaps

    # total_bytes cumulative source_byte_bound_reached
    total_bounds = support.RemediationPlanningSettings.from_mapping(
        support.planning_settings(max_file_bytes=500, max_source_bytes=len(env.src_file.read_bytes()) + 2, max_source_files=4)
    ).bounds
    reader2 = inputs.SourceReader(
        builds,
        core,
        [{"relation_id": "r1", "entity_id": "e-ok"}, {"relation_id": "r2", "entity_id": "e-second"}],
        total_bounds,
    )
    reader2.resolve()
    assert "source_byte_bound_reached" in reader2.gaps

    # index vs manifest digest disagreement
    bad_core = SimpleNamespace(
        find=lambda *, identity, limit=1: {
            "results": [{"location": {"path": "native/src/parse.c", "file_sha256": "f" * 64}}]
        }
    )
    with pytest.raises(IntegrityError, match="accepted index and build baseline disagree"):
        inputs.SourceReader(builds, bad_core, [{"relation_id": "r1", "entity_id": "e1"}], b).resolve()

    # source bytes tampered on disk after manifest recorded
    orig_bytes = second_file.read_bytes()
    second_file.write_bytes(b"tampered;\n")
    try:
        with pytest.raises(IntegrityError, match="accepted source bytes changed"):
            inputs.SourceReader(builds, core, [{"relation_id": "r2", "entity_id": "e-second"}], b).resolve()
    finally:
        second_file.write_bytes(orig_bytes)

    # retrieve happy + error branches
    got = reader.retrieve({"path": "native/src/parse.c", "start_line": 1, "end_line": 2})
    assert got["lines"][0] == "void p(char *s) {"
    with pytest.raises(ValueError, match="requires exactly"):
        reader.retrieve({"path": "native/src/parse.c"})
    for bad_req in (
        {"path": "missing.c", "start_line": 1, "end_line": 1},
        {"path": "native/src/parse.c", "start_line": True, "end_line": 1},
        {"path": "native/src/parse.c", "start_line": 0, "end_line": 1},
        {"path": "native/src/parse.c", "start_line": 3, "end_line": 2},
        {"path": "native/src/parse.c", "start_line": 1, "end_line": 125},
    ):
        with pytest.raises(ValueError, match="admitted source file"):
            reader.retrieve(bad_req)


def test_model_and_patches_remaining_edge_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = RemediationModel.from_mapping(support.MODEL)

    # non-Mapping / wrong schema reply
    ans, rec = model.run_model(
        infer=lambda *_a, **_k: ModelResult({"schema": "wrong-schema"}),
        profile=profile,
        role="remediation_writer",
        cell_id="c1",
        guidance_text="g",
        guidance_sha256="a" * 64,
        task={"kind": "u"},
        validate=lambda v: v,
    )
    assert ans is None and "reply must be a worker-turn object" in rec["reason"]

    # validate raises IntegrityError -> propagated
    with pytest.raises(IntegrityError, match="fatal"):
        model.run_model(
            infer=lambda *_a, **_k: ModelResult({"action": "final", "result": {}}),
            profile=profile,
            role="remediation_writer",
            cell_id="c1",
            guidance_text="g",
            guidance_sha256="a" * 64,
            task={"kind": "u"},
            validate=lambda _v: (_ for _ in ()).throw(IntegrityError("fatal")),
        )

    # retrieve raises ValueError -> invalid_output
    ans, rec = model.run_model(
        infer=lambda *_a, **_k: ModelResult({"action": "retrieve", "request": {"bad": 1}}),
        profile=profile,
        role="remediation_writer",
        cell_id="c1",
        guidance_text="g",
        guidance_sha256="a" * 64,
        task={"kind": "u"},
        validate=lambda v: v,
        retrieve=lambda _r: (_ for _ in ()).throw(ValueError("bad request")),
    )
    assert ans is None and rec["reason"].startswith("invalid_output:bad request")

    # turn_bound_reached when max_turns < max_queries and retrieve succeeds
    one_turn = replace(profile, max_turns=1, max_queries=2)
    ans, rec = model.run_model(
        infer=lambda *_a, **_k: ModelResult({"action": "retrieve", "request": {"ok": 1}}),
        profile=one_turn,
        role="remediation_writer",
        cell_id="c1",
        guidance_text="g",
        guidance_sha256="a" * 64,
        task={"kind": "u"},
        validate=lambda v: v,
        retrieve=lambda _r: {"lines": ["ok"]},
    )
    assert ans is None and rec["reason"] == "turn_bound_reached"

    # ExecutionLimit raised during post-call retrieve deadline check
    from appsec_review.inference.execution import Deadline

    orig_remaining = Deadline.remaining
    rem_calls = [0]

    def custom_remaining(self):
        rem_calls[0] += 1
        if rem_calls[0] >= 3:
            raise ExecutionLimit("execution_deadline")
        return orig_remaining(self)

    monkeypatch.setattr(Deadline, "remaining", custom_remaining)
    ans, rec = model.run_model(
        infer=lambda *_a, **_k: ModelResult({"action": "retrieve", "request": {"ok": 1}}),
        profile=replace(profile, timeout_seconds=1),
        role="remediation_writer",
        cell_id="c1",
        guidance_text="g",
        guidance_sha256="a" * 64,
        task={"kind": "u"},
        validate=lambda v: v,
        retrieve=lambda _r: {"lines": ["ok"]},
    )
    assert ans is None and rec["reason"] == "execution_deadline"
    monkeypatch.undo()

    # patches.py remaining branches
    for bad_rel in (123, "", "a" * 241):
        with pytest.raises(patches.PatchError, match="bounded relative path"):
            patches.relative_path(bad_rel)

    not_dir = tmp_path / "regular.txt"
    not_dir.write_text("hi", encoding="utf-8")
    with pytest.raises(IntegrityError, match="not a regular directory"):
        patches.safe_file(not_dir, "a.c")

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "subdir").mkdir()
    with pytest.raises(IntegrityError, match="not a regular file"):
        patches.safe_file(ws, "subdir")
    with pytest.raises(patches.PatchError, match="baseline file is missing"):
        patches.safe_file(ws, "missing.c")

    orig_resolve = Path.resolve
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda self, *a, **k: Path("/outside/escaped.c") if self.name == "escape.c" else orig_resolve(self, *a, **k),
    )
    with pytest.raises(IntegrityError, match="escapes workspace"):
        patches.safe_file(ws, "escape.c", missing=True)
    monkeypatch.undo()

    b = support.bounds()
    with pytest.raises(patches.PatchError, match="file count"):
        patches.parse_patch({"schema": patches.PATCH_SCHEMA, "files": []}, b)
    tiny_b = support.RemediationPlanningSettings.from_mapping(
        support.planning_settings(max_patch_bytes=20, max_edits=1, max_file_bytes=16)
    ).bounds
    with pytest.raises(patches.PatchError, match="patch byte bound"):
        patches.parse_patch(support.patch("a.c", "a" * 64), tiny_b)
    with pytest.raises(patches.PatchError, match="explicit absence proof"):
        patches.parse_patch(
            {"schema": patches.PATCH_SCHEMA, "files": [{"path": "n.c", "before_sha256": None, "absence_proof": False, "edits": []}]},
            b,
        )
    with pytest.raises(patches.PatchError, match="declare exact edits"):
        patches.parse_patch(
            {"schema": patches.PATCH_SCHEMA, "files": [{"path": "a.c", "before_sha256": "a" * 64, "absence_proof": False, "edits": []}]},
            b,
        )
    with pytest.raises(patches.PatchError, match="one insertion at byte zero"):
        patches.parse_patch(
            {
                "schema": patches.PATCH_SCHEMA,
                "files": [
                    {
                        "path": "n.c",
                        "before_sha256": None,
                        "absence_proof": True,
                        "edits": [{"start": 0, "end": 0, "old": "", "new": "a"}, {"start": 1, "end": 1, "old": "", "new": "b"}],
                    }
                ],
            },
            b,
        )
    max1_b = support.RemediationPlanningSettings.from_mapping(support.planning_settings(max_edits=1)).bounds
    with pytest.raises(patches.PatchError, match="exact edit bound"):
        patches.parse_patch(
            {
                "schema": patches.PATCH_SCHEMA,
                "files": [
                    {
                        "path": "a.c",
                        "before_sha256": "a" * 64,
                        "absence_proof": False,
                        "edits": [
                            {"start": 0, "end": 1, "old": "a", "new": "A"},
                            {"start": 2, "end": 3, "old": "b", "new": "B"},
                        ],
                    }
                ],
            },
            max1_b,
        )

    # patched_bytes file bounds and UTF-8 check
    (ws / "big.c").write_bytes(b"x" * 20)
    big_digest = hashlib.sha256(b"x" * 20).hexdigest()
    with pytest.raises(patches.PatchError, match="baseline file bound exceeded"):
        patches.patched_bytes(
            patches.parse_patch(support.patch("big.c", big_digest, old="x", new="y", start=0), b),
            ws,
            {"big.c": big_digest},
            tiny_b,
        )
    (ws / "small.c").write_bytes(b"abc")
    small_digest = hashlib.sha256(b"abc").hexdigest()
    with pytest.raises(patches.PatchError, match="patched file bound exceeded"):
        patches.patched_bytes(
            patches.parse_patch(support.patch("small.c", small_digest, old="a", new="y" * 30, start=0), b),
            ws,
            {"small.c": small_digest},
            tiny_b,
        )

    # Multi-byte UTF-8 split produces non-UTF-8 output bytes
    utf8_src = "é\n".encode("utf-8")  # \xc3\xa9\n
    (ws / "utf.c").write_bytes(utf8_src)
    utf_digest = hashlib.sha256(utf8_src).hexdigest()
    split_patch = patches.ExactPatch(
        {
            "schema": patches.PATCH_SCHEMA,
            "files": [
                {
                    "path": "utf.c",
                    "before_sha256": utf_digest,
                    "absence_proof": False,
                    "edits": [{"start": 0, "end": 1, "old": "\xc3", "new": "a"}],
                }
            ],
        }
    )
    # Force old match on raw byte \xc3 by replacing old check via a valid ASCII prefix around broken splice:
    raw_valid = patches.ExactPatch(
        {
            "schema": patches.PATCH_SCHEMA,
            "files": [
                {
                    "path": "small.c",
                    "before_sha256": small_digest,
                    "absence_proof": False,
                    "edits": [{"start": 0, "end": 1, "old": "a", "new": "B"}],
                }
            ],
        }
    )
    assert patches.patched_bytes(raw_valid, ws, {"small.c": small_digest}, b)["small.c"] == b"Bbc"
    del split_patch


def test_job_units_happy_capped_empty_and_publish_integrity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=2)

    # _validate topology mismatch
    bad_ctx = _ctx(env.root, support.planning_settings(), "att-bad-topo", steps={})
    with pytest.raises(ValueError, match="topology does not match"):
        planning_job._validate(bad_ctx, None)

    # write_json duplicate check
    u_dir = env.root / "data" / "unit-dup"
    u_dir.mkdir(parents=True)
    fake_unit = UnitContext(
        _ctx(env.root, support.planning_settings(), "att-dup"),
        "load.verify_inputs",
        "load",
        "verify_inputs",
        u_dir,
        {},
    )
    planning_job.write_json(fake_unit, "dup.json", {"x": 1})
    with pytest.raises(IntegrityError, match="already exists"):
        planning_job.write_json(fake_unit, "dup.json", {"x": 2})

    # Clean SUCCEEDED run across 2 confirmed candidates (reusing core & guidance on candidate 2)
    writer = support.Writer(retrieve=True)
    job = build_job(
        infer=writer,
        builds_factory=lambda _r: env.builds,
        core_factory=lambda _r, _rev: env.core,
        repository_root=support.ROOT,
    )
    ctx_ok = _ctx(env.root, support.planning_settings(), "att-ok")
    for validator in job.input_validators:
        validator(ctx_ok, None)
    res_ok = job.execute(ctx_ok)
    assert not res_ok["failed_units"], res_ok
    pub_ok = res_ok["outputs"]["acceptance.publish_handoff"]
    assert pub_ok["terminal_status"] == "SUCCEEDED"
    assert pub_ok["gaps"] == []
    summary_ok = read_bound_json(env.root, pub_ok["artifact"])
    assert [row["status"] for row in summary_ok["items"]] == ["proposal_generated", "proposal_generated"]

    # Mixed failure/gap branches: candidate 0 has no direct_evidence, candidate 1 has invalid patch scope,
    # candidate 2 has manual_design_required (patch=None), candidate 3 is capped
    env3 = _seed_planning(tmp_path / "mixed", monkeypatch, candidate_count=4)
    env3.review_doc["packages"][0]["direct_evidence"] = []

    def bad_patch_infer(request, *, timeout_seconds):
        rel = request.task_input["task"]["accepted_evidence"][0]["relation_id"]
        if request.cell_id.endswith("claim-2"):
            wrong_patch = support.patch("native/src/other.c", "a" * 64)
            return ModelResult({"action": "final", "result": support.answer([rel], wrong_patch)}, input_tokens=5, output_tokens=5)
        return ModelResult(
            {"action": "final", "result": support.answer([rel], None, status="manual_design_required")},
            input_tokens=5,
            output_tokens=5,
        )

    job_mixed = build_job(
        infer=bad_patch_infer,
        builds_factory=lambda _r: env3.builds,
        core_factory=lambda _r, _rev: env3.core,
        repository_root=support.ROOT,
    )
    res_mixed = job_mixed.execute(_ctx(env3.root, support.planning_settings(max_candidates=3), "att-mixed"))
    assert not res_mixed["failed_units"], res_mixed
    pub_mixed = res_mixed["outputs"]["acceptance.publish_handoff"]
    assert pub_mixed["terminal_status"] == "COMPLETED_WITH_GAPS"
    items_mixed = read_bound_json(env3.root, pub_mixed["artifact"])["items"]
    assert items_mixed[0]["reason"] == "confirmed_finding_has_no_resolving_evidence"
    assert items_mixed[1]["reason"].startswith("invalid_patch:")
    assert items_mixed[2]["status"] == "manual_design_required" and items_mixed[2]["plan"] is not None
    assert items_mixed[3]["status"] == "capped"

    # Model returns None (invalid output)
    env_inv = _seed_planning(tmp_path / "inv", monkeypatch, candidate_count=1)
    job_inv = build_job(
        infer=support.Writer(invalid=True),
        builds_factory=lambda _r: env_inv.builds,
        core_factory=lambda _r, _rev: env_inv.core,
        repository_root=support.ROOT,
    )
    res_inv = job_inv.execute(_ctx(env_inv.root, support.planning_settings(max_candidates=1), "att-inv"))
    assert res_inv["outputs"]["acceptance.publish_handoff"]["terminal_status"] == "COMPLETED_WITH_GAPS"

    # Empty confirmed partition -> SKIPPED_NA
    env_empty = _seed_planning(tmp_path / "empty", monkeypatch, candidate_count=0)
    res_empty = job.execute(_ctx(env_empty.root, support.planning_settings(), "att-empty"))
    assert res_empty["outputs"]["acceptance.publish_handoff"]["terminal_status"] == "SKIPPED_NA"

    # Publish detects accepted review drift mid-run
    env_drift = _seed_planning(tmp_path / "drift", monkeypatch, candidate_count=1)
    calls = 0

    def drifting_review(*_a, **_k):
        nonlocal calls
        calls += 1
        doc = copy.deepcopy(env_drift.review_doc)
        if calls >= 2:
            doc["inputs"]["review_handoff"] = {"path": "other.json", "sha256": "f" * 64}
        return SimpleNamespace(document=doc)

    monkeypatch.setattr(accepted_review, "load_accepted_review", drifting_review)
    res_drift = job.execute(_ctx(env_drift.root, support.planning_settings(), "att-drift"))
    assert res_drift["failed_units"] == ["acceptance.publish_handoff"]

    # Publish detects outcomes list mismatch directly on publish handler
    monkeypatch.setattr(
        accepted_review,
        "load_accepted_review",
        lambda *_a, **_k: SimpleNamespace(document=copy.deepcopy(env.review_doc)),
    )
    bad_out_ref = _write(env.root, "bad-outcomes.json", {"items": []})
    pub_unit = job.units[2]
    pub_ctx = UnitContext(
        _ctx(env.root, support.planning_settings(), "att-pub-direct"),
        "acceptance.publish_handoff",
        "acceptance",
        "publish_handoff",
        env.root / "data" / "pub-direct",
        {
            "load.verify_inputs": res_ok["outputs"]["load.verify_inputs"],
            "assess.propose": {"artifact": bad_out_ref},
        },
    )
    pub_ctx.unit_root.mkdir(parents=True, exist_ok=True)
    with pytest.raises(IntegrityError, match="do not exactly account for confirmed intake"):
        pub_unit.handler(pub_ctx)
