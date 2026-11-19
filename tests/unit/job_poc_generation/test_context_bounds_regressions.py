"""T-5157/T-5159: inert accepted files, real readers/handlers, no compiler or model execution."""
from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_poc_generation import brief, buildcheck, buildctx, job, writer
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_json, canonical_json
from tests.handoff_fixture import write_fixture_handoff
from tests.poc_support import FakeExecutor, ROOT, ast_document, relay_unit
from tests.fixtures.poc_generation import relay
from tests.unit.job_poc_generation.test_brief_inputs_and_helpers import _cfg
from tests.unit.job_poc_generation.test_job_units import (
    _basis_dict, _candidate_dict, _compiling_config, _fast_workspace, _job_context,
    _view_with_resolved_labels,
)


def _bound(root, relative, document):
    path = root / relative
    atomic_json(path, document)
    return artifact_ref(root, path)


def _receipt(root, name, *, compiled=True):
    workspace, manifest = _fast_workspace(root / name / "workspace")
    manifest_ref = _bound(root, f"{name}/manifest.json", {"files": manifest})
    command_ref = _bound(root, f"{name}/commands.json", {
        "schema": buildctx.COMPILE_DATABASE_SCHEMA,
        "rows": [{"tool_kind": "compiler", "argv": list(relay.PACKET_ARGV),
                  "inputs": [{"workspace_path": "src/packet.cpp"}]}] if compiled else [],
    })
    return {
        "family": "native", "terminal_status": "SUCCEEDED", "build_unit_id": name,
        "build_outcome": "built", "build_system": "cmake", "root": ".", "fingerprint": "a" * 64,
        "workspace": workspace.relative_to(root).as_posix(), "workspace_manifest": manifest_ref,
        "protected_compile_commands": command_ref,
        "artifacts": [{"kind": "object", "workspace_path": path} for path in manifest if path.endswith(".o")],
        "image": {"image_tag": "inert:fixture", "image_id": "sha256:" + "a" * 64, "user": "1:1"},
    }


def test_unrelated_workspace_does_not_mask_a_later_covering_build(tmp_path):
    receipts = [_receipt(tmp_path, "a", compiled=False), _receipt(tmp_path, "b")]
    builds = buildctx.AcceptedBuilds(tmp_path, loader=lambda _: {"receipts": receipts})
    found = builds.locate("src/packet.cpp")
    assert found.code == "found" and found.unit.build_unit_id == "b"
    assert found.unit.command.argv == relay.PACKET_ARGV
    assert found.unit.workspace == tmp_path / "b" / "workspace"
    only_unrelated = buildctx.AcceptedBuilds(tmp_path, loader=lambda _: {"receipts": receipts[:1]})
    assert only_unrelated.locate("src/packet.cpp").code == "no_compile_command"


@pytest.mark.parametrize("kind", ["changed", "symlink", "parent-symlink", "escape"])
def test_declarations_refuse_unaccepted_source_bytes_and_paths(tmp_path, kind):
    workspace, manifest = _fast_workspace(tmp_path / "workspace")
    path = workspace / "include" / "relay" / "relay.hpp"
    outside = tmp_path / "foreign.hpp"
    outside.write_bytes(path.read_bytes())
    if kind == "changed":
        path.write_text("void parse_header(int changed);\n")
    elif kind == "symlink":
        path.unlink()
        path.symlink_to(outside)
    elif kind == "parent-symlink":
        parent = path.parent
        moved = tmp_path / "foreign-headers"
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
    else:
        manifest = {"../foreign.hpp": hashlib.sha256(outside.read_bytes()).hexdigest()}
    unit = relay_unit(workspace, manifest)
    headers = buildctx.Headers(replace(unit, command=replace(unit.command, argv=("clang++", "-I."))))
    with pytest.raises(IntegrityError):
        buildctx.declarations(unit, headers, ["parse_header"], source_bytes=65536, max_files=10, max_lines=30)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_declaration_file_limit_is_measured_in_actual_bytes(tmp_path, offset):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data = "// é\nvoid sink();\n".encode()
    (workspace / "api.hpp").write_bytes(data)
    unit = relay_unit(workspace, {"api.hpp": hashlib.sha256(data).hexdigest()},
                      compile_command=buildctx.CompileCommand(("clang++", "-I."), "x.cpp", "cxx", ".", "exact"))
    rows = buildctx.declarations(unit, buildctx.Headers(unit), ["sink"], source_bytes=len(data) + offset,
                                 max_files=1, max_lines=2)
    assert bool(rows) is (offset >= 0)
    if rows:
        assert rows[0] == {"path": "api.hpp", "lines": "2-2", "text": ["2| void sink();"]}


def test_declaration_reads_never_request_more_than_the_byte_bound_and_sentinel(tmp_path, monkeypatch):
    workspace, manifest = _fast_workspace(tmp_path / "workspace")
    unit = relay_unit(workspace, manifest)
    opened = Path.open
    reads = []

    class Observed:
        def __init__(self, path, *args, **kwargs):
            self.stream = opened(path, *args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            reads.append(size)
            return self.stream.read(size)

    monkeypatch.setattr(Path, "open", lambda path, *args, **kwargs: Observed(path, *args, **kwargs))
    assert buildctx.declarations(unit, buildctx.Headers(unit), ["parse_header"], source_bytes=8,
                                  max_files=10, max_lines=30) == []
    assert reads and all(size == 9 for size in reads)


def test_scoped_declarations_do_not_consume_a_foreign_manifest_header(tmp_path):
    workspace, manifest = _fast_workspace(tmp_path / "workspace")
    outside_scope = workspace / "private" / "other.hpp"
    outside_scope.parent.mkdir()
    outside_scope.write_text("void parse_header(int foreign);\n")
    manifest["private/other.hpp"] = "0" * 64  # Must not even be read under include/src scope.
    unit = relay_unit(workspace, manifest)
    rows = buildctx.declarations(unit, buildctx.Headers(unit), ["parse_header"], source_bytes=65536,
                                 max_files=10, max_lines=30)
    assert rows and {row["path"] for row in rows} == {"include/relay/relay.hpp"}


@pytest.mark.parametrize("part", ["workspace", "database", "manifest", "workspace-parent"])
def test_accepted_build_rejects_symlink_substitution_even_with_identical_bytes(tmp_path, part):
    receipt = _receipt(tmp_path, "a")
    relative = receipt["workspace"] if part.startswith("workspace") else receipt[
        "protected_compile_commands" if part == "database" else "workspace_manifest"]["path"]
    path = tmp_path / relative
    if part == "workspace-parent":
        path = path.parent
    moved = tmp_path / f"foreign-{part}"
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=part.startswith("workspace"))
    with pytest.raises(IntegrityError):
        buildctx.AcceptedBuilds(tmp_path, loader=lambda _: {"receipts": [receipt]}).locate("src/packet.cpp")


def test_prepare_honors_configured_file_limit_not_loader_default(tmp_path):
    workspace, manifest = _fast_workspace(tmp_path / "workspace")
    unit = relay_unit(workspace, manifest)
    builds = buildctx.AcceptedBuilds(tmp_path)
    with pytest.raises(ValueError, match="bound is 1"):
        buildcheck.prepare(builds, unit, tmp_path / "scratch", name="candidate", poc_text="",
                           settings=_cfg(build={"workspace_file_limit": 1}))
    assert not (tmp_path / "scratch" / "candidate").exists()


@pytest.mark.parametrize("limit", [1, 2, 257])
def test_symbol_scan_uses_one_bounded_prefix_across_objects_and_shared_libraries(tmp_path, limit):
    workspace, manifest = _fast_workspace(tmp_path / "workspace")
    unit = replace(relay_unit(workspace, manifest),
                   objects=tuple(f"build/{i:03}.o" for i in range(258)),
                   shared_libraries=("build/z.so",))
    builds = buildctx.AcceptedBuilds(tmp_path)
    settings = _cfg(build={"object_limit": limit})
    scratch = buildcheck.prepare(builds, unit, tmp_path / "scratch", name="candidate", poc_text="",
                                 settings=settings)
    executor = FakeExecutor()
    result = buildcheck.check_build(executor, builds, unit, scratch, settings, claim_id=_candidate_dict(1)["claim_id"])
    paths = [arg for call in executor.calls if "--defined-only" in call["argv"]
             for arg in call["argv"] if arg.startswith("/workspace/build/")]
    assert paths == [f"/workspace/build/{i:03}.o" for i in range(limit)]
    assert any(f"{259 - limit} omitted" in gap for gap in result.gaps)
    executor.assert_nothing_is_linked_or_run()


@pytest.mark.parametrize("flags", [["-D", "FEATURE=1", "-U", "OLD"], ["-DFEATURE=1", "-UOLD"]])
def test_ast_replay_keeps_both_preprocessor_flag_spellings(flags):
    names = buildcheck.Names(".appsec-poc", "poc.cpp")
    argv = buildcheck.derive_ast(("g++", *flags, "-c", "/workspace/x.cpp"), "cxx", names, _cfg())
    assert argv[argv.index("--") + 2:-4] == flags


@pytest.mark.parametrize("flags", [["-D"], ["-U", "-c"], ["-D", ""], ["-U", "OLD=1"]])
def test_ast_replay_refuses_missing_or_invalid_macro_operands(flags):
    with pytest.raises(ValueError, match="macro"):
        buildcheck.derive_ast(("g++", *flags), "cxx", buildcheck.Names(".appsec-poc", "poc.cpp"), _cfg())


def _brief_arguments():
    return dict(candidate=parse_candidates([_candidate_dict(1)])[0], finding={"title": "évidence"},
                package={}, view=_view_with_resolved_labels(),
                sink={"name": "sink", "path": "x.cpp"}, unit=None, headers=None)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_complete_brief_is_bounded_at_canonical_serialization_boundary(offset):
    arguments = _brief_arguments()
    size = len(canonical_json(brief.build_brief(**arguments, settings=_cfg()).document))
    settings = _cfg(brief={"max_brief_bytes": size + offset})
    if offset < 0:
        with pytest.raises(ValueError, match="brief_byte_bound_exceeded"):
            brief.build_brief(**arguments, settings=settings)
    else:
        built = brief.build_brief(**arguments, settings=settings)
        assert len(canonical_json(built.document)) == size
        assert built.document["package_view"] == arguments["view"].document


def test_oversized_source_is_not_silently_trimmed_into_an_overbudget_brief():
    arguments = _brief_arguments()
    arguments["view"].document["source"] = [{"text": ["x" * 8000]}]
    with pytest.raises(ValueError, match="brief_byte_bound_exceeded"):
        brief.build_brief(**arguments, settings=_cfg(brief={"max_brief_bytes": 400}))


def test_writer_rechecks_brief_bound_before_any_model_consumption(tmp_path):
    settings = _cfg(brief={"max_brief_bytes": 400})
    reader = writer.WorkspaceReader(tmp_path, {}, (), lambda _: [])
    oversized = brief.Brief({"source": "é" * 400}, {}, (), ())

    def forbidden(*args, **kwargs):
        pytest.fail("overbudget brief reached model consumption")

    outcome = writer.run_writer(oversized, settings=settings, infer=forbidden, reader=reader,
                                guidance=None, schemas=None, claim_id=_candidate_dict(1)["claim_id"])
    assert outcome.status == "failed" and "brief_byte_bound_exceeded" in outcome.reason
    assert outcome.attempts == ()


def _publication_fixture(tmp_path, settings=None, candidate=None):
    ctx = _job_context(tmp_path)
    if settings:
        ctx = replace(ctx, config=replace(ctx.config, settings=settings))
    candidate = candidate or _candidate_dict(1)
    review_path = ctx.run_root / "data/jobs/job_inference_security_review/attempts/attempt_0001/handoff.json"
    write_fixture_handoff(ctx.run_root, review_path, {
        "job_id": "job_inference_security_review", "attempt_id": "attempt_0001", "status": "ACCEPTED",
        "completion_status": "SUCCEEDED", "outputs": {}, "artifacts": [],
    })
    review_ref = artifact_ref(ctx.run_root, review_path)
    atomic_json(review_path.parent.parent.parent / "latest.json",
                {"handoff_path": review_ref["path"], "handoff_sha256": review_ref["sha256"]})
    pkg = {"neighborhood": {"function": {"name": relay.SINK, "path": "src/packet.cpp",
                                        "start_line": 8, "end_line": 20}}}
    pkg_ref = _bound(ctx.run_root, "fixtures/package.json", pkg)
    item = {"candidate": candidate, "finding": {"title": "Fixture", "missing_predicates": []},
            "package": pkg_ref}
    inputs = {"run_id": ctx.run_root.name, "planned": [item], "omitted": [], "bindings": [pkg_ref],
              "upstream": {"review_job_handoff": review_ref, "review_handoff": review_ref,
                           "manifest": pkg_ref, "language_build_handoff_sha256": None}}
    outputs = {"load.verify_inputs": {"artifact": _bound(ctx.run_root, "fixtures/inputs.json", inputs), "gaps": []}}
    return ctx, candidate, item, inputs, outputs


def _invoke(built_job, ctx, outputs, unit_id):
    unit = next(unit for unit in built_job.units if unit.unit_id == unit_id)
    step, task = unit_id.split(".")
    context = UnitContext(ctx, unit_id, step, task, ctx.attempt_root / step / task, outputs)
    result = unit.handler(context)
    outputs[unit_id] = result
    return result


@pytest.mark.parametrize("gapped", [False, True])
def test_real_package_and_publish_preserve_nested_qualifications_without_upgrading_findings(tmp_path, gapped):
    ctx, candidate, item, inputs, outputs = _publication_fixture(tmp_path)
    claim = candidate["claim_id"]
    workspace, manifest = _fast_workspace(tmp_path / "workspace")
    unit = relay_unit(workspace, manifest)
    settings = _cfg()
    answer = WriterAnswer.from_result(relay.answer()["result"])
    source = assemble(answer, settings, claim_id=claim, package_id=candidate["package_id"])
    source_ref = _bound(ctx.run_root, "fixtures/source.json", {"text": source, "language": "cxx"})
    brief_gaps = ["brief qualification"] if gapped else []
    compile_gaps = [f"symbol qualification {i}" for i in range(12)] if gapped else []
    unchecked = ["non-numeric condition"] if gapped else []
    validated = {"answer": answer.record(), "source": source_ref, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                 "policy_verdict": "passed", "gaps": brief_gaps, "unchecked_triggers": unchecked}
    scratch = buildcheck.prepare(buildctx.AcceptedBuilds(tmp_path), unit, tmp_path / "scratch", name="c",
                                 poc_text=source, settings=settings)
    outcome = buildcheck.check_build(FakeExecutor(), buildctx.AcceptedBuilds(tmp_path),
                                    replace(unit, gaps=tuple(compile_gaps)), scratch, settings, claim_id=claim)
    compiled = {"terminal": {"status": outcome.status, "reason": outcome.reason},
                "record": _bound(ctx.run_root, "fixtures/compile.json", outcome.record)}
    planned = {"brief": _bound(ctx.run_root, "fixtures/brief.json", {"gaps": brief_gaps}),
               "brief_gaps": brief_gaps, "build": unit.identity()}
    for name, value in [("plan.briefs", planned), ("write.poc_writer", {}), ("validate.policy", validated),
                        ("compile.build_check", compiled)]:
        outputs[name] = {"artifact": _bound(ctx.run_root, f"fixtures/{name}.json", {"entries": {claim: value}})}
    built_job = job.build_job(repository_root=ROOT)
    _invoke(built_job, ctx, outputs, "package.files")
    published = _invoke(built_job, ctx, outputs, "publish.publish_handoff")
    summary = read_bound_json(ctx.run_root, published["artifact"])
    row = summary["candidates"][0]
    assert row["status"] == "compile_verified" and row["state"] == candidate["state"]
    assert row["runtime_verified"] is False and row["result_id"] is None
    record = read_bound_json(ctx.run_root, row["files"]["compile"])
    if gapped:
        assert published["terminal_status"] == "COMPLETED_WITH_GAPS" and summary["gaps"]
        assert 1 <= len(row["gaps"]) <= 10
        assert any("additional qualifications" in gap for gap in row["gaps"])
        assert record["unchecked_triggers"] == unchecked
        assert set(brief_gaps + compile_gaps) <= set(record["gaps"])
        assert len(record["gaps"]) == 14  # duplicate brief gap appears once; trigger caveat is retained
    else:
        assert published["terminal_status"] == "SUCCEEDED" and not row["gaps"] and not summary["gaps"]


@pytest.mark.parametrize("budget", [400, 131072])
def test_real_handlers_publish_brief_bound_or_decline_without_losing_planning_gaps(tmp_path, budget):
    settings = _cfg(brief={"max_brief_bytes": budget})
    ctx, candidate, item, inputs, outputs = _publication_fixture(tmp_path)
    raw_settings = dict(ctx.config.settings)
    raw_settings["brief"] = {**raw_settings["brief"], "max_brief_bytes": budget}
    ctx = replace(ctx, config=replace(ctx.config, settings=raw_settings))
    receipt = _receipt(ctx.run_root, "accepted-build")
    accepted = buildctx.AcceptedBuilds(ctx.run_root, loader=lambda _: {"receipts": [receipt]})
    calls = []

    def infer(request, **kwargs):
        calls.append(request)
        assert len(canonical_json(request.task_input["input"])) <= budget
        return ModelResult(proposal={"action": "final", "result": {
            "decline": {"status": "insufficient_evidence", "why": "inert fixture decline"}}},
            input_tokens=1, output_tokens=1)

    view = _view_with_resolved_labels()
    view.document["labels"] = view.document["labels"][:1]  # One basis identity remains unresolved.
    built_job = job.build_job(infer=infer, builds_factory=lambda _: accepted,
                              core_factory=lambda *_: None, view_factory=lambda *_: view, repository_root=ROOT)
    for unit in built_job.units[1:]:
        _invoke(built_job, ctx, outputs, unit.unit_id)
    published = outputs["publish.publish_handoff"]
    row = read_bound_json(ctx.run_root, published["artifact"])["candidates"][0]
    assert row["status"] == "insufficient_evidence" and row["files"] is None
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS" and row["gaps"]
    if budget == 400:
        assert calls == [] and row["brief"] is None
        assert "brief_byte_bound_exceeded" in row["reason"]
    else:
        assert len(calls) == 1
        assert len((ctx.run_root / row["brief"]["path"]).read_bytes()) <= settings.brief.max_brief_bytes
        assert any("poc_basis identity" in gap for gap in row["gaps"])


@pytest.mark.parametrize("qualified", [False, True])
def test_native_handler_flow_preserves_real_brief_validation_and_compile_gaps(tmp_path, qualified):
    constraint = "non-numeric condition" if qualified else relay.TRIGGER["constraint"]
    candidate = _candidate_dict(1, basis=_basis_dict(trigger=[{**relay.TRIGGER, "constraint": constraint}]))
    config = _compiling_config()
    settings = dict(config.settings)
    if qualified:
        settings["build"] = {**settings["build"], "object_limit": 1}
    ctx, candidate, item, inputs, outputs = _publication_fixture(tmp_path, settings=settings, candidate=candidate)
    receipt = _receipt(ctx.run_root, "accepted-build")
    accepted = buildctx.AcceptedBuilds(ctx.run_root, loader=lambda _: {"receipts": [receipt]})
    executor = FakeExecutor(ast=ast_document("good"))
    requests = []

    def infer(request, **kwargs):
        requests.append(request)
        return ModelResult(proposal=relay.answer(), input_tokens=1, output_tokens=1)

    view = _view_with_resolved_labels()
    if qualified:
        view.document["labels"] = view.document["labels"][:1]
    built_job = job.build_job(infer=infer, builds_factory=lambda _: accepted,
                              executor_factory=lambda *_: executor,
                              core_factory=lambda *_: None, view_factory=lambda *_: view, repository_root=ROOT)
    for unit in built_job.units[1:]:
        _invoke(built_job, ctx, outputs, unit.unit_id)
    published = outputs["publish.publish_handoff"]
    row = read_bound_json(ctx.run_root, published["artifact"])["candidates"][0]
    assert row["status"] == "compile_verified"
    assert row["state"] == candidate["state"] and row["runtime_verified"] is False
    compiled = read_bound_json(ctx.run_root, row["files"]["compile"])
    job.SchemaSet(ROOT / job.SCHEMA_ROOT).validate("compile-record", compiled)
    assert len(requests) == 1
    executor.assert_nothing_is_linked_or_run()
    if qualified:
        assert published["terminal_status"] == "COMPLETED_WITH_GAPS" and published["gaps"]
        assert compiled["unchecked_triggers"] == [constraint]
        assert set(row["gaps"]) == set(compiled["gaps"])
        assert any("poc_basis identity" in gap for gap in row["gaps"])
        assert any("1 omitted" in gap for gap in row["gaps"])
        assert f"unchecked trigger: {constraint}" in row["gaps"]
    else:
        assert published["terminal_status"] == "SUCCEEDED" and not row["gaps"] and not published["gaps"]
