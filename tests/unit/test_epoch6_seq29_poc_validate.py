"""Focused unit regressions for Epoch-6 seq=29 job_poc_generation validation fixes."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_poc_generation import buildcheck, buildctx, job
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.source import (
    WriterAnswer,
    assemble,
    check_answer,
    normalize_includes,
)
from appsec_review.jobs.job_poc_generation.statuses import POLICY_DENIED
from tests.fixtures.poc_generation import relay
from tests.poc_support import (
    FakeExecutor,
    ROOT,
    ast_document,
    relay_unit,
    settings as poc_settings,
)
from tests.unit.job_poc_generation.test_job_units import (
    _candidate_dict,
    _fast_workspace,
    _job_context,
)


SETTINGS = poc_settings()


def _build_unit(tmp_path: Path) -> buildctx.BuildUnit:
    workspace, manifest = _fast_workspace(tmp_path / "ws")
    return relay_unit(workspace, manifest)


def _accepted_builds(unit: buildctx.BuildUnit) -> buildctx.AcceptedBuilds:
    builds = buildctx.AcceptedBuilds(
        unit.workspace.parent,
        loader=lambda _r: {"receipts": [], "language_build_handoff_sha256": "b" * 64},
    )
    builds.locate = lambda _p: buildctx.Located(unit, "")  # type: ignore[method-assign]
    return builds


def test_headers_include_spelling_maps_workspace_paths_without_widening_resolve(tmp_path: Path) -> None:
    unit = _build_unit(tmp_path)
    extra_manifest = {
        **unit.workspace_manifest,
        "src/cache.h": "b" * 64,
        "unbuilt/secret.h": "c" * 64,
    }
    unit = replace(unit, workspace_manifest=extra_manifest)
    headers = buildctx.Headers(unit)

    assert headers.resolve("include/relay/relay.hpp") is None
    assert headers.resolve("src/cache.h") is None
    assert headers.resolve("relay/relay.hpp") == "include/relay/relay.hpp"
    assert headers.resolve("cache.h") == "src/cache.h"

    assert headers.include_spelling("src/cache.h") == "cache.h"
    assert headers.include_spelling("cache.h") == "cache.h"
    assert headers.include_spelling("include/relay/relay.hpp") == "relay/relay.hpp"
    assert headers.include_spelling("relay/relay.hpp") == "relay/relay.hpp"

    for rejected in ("unbuilt/secret.h", "../README.md", "/etc/passwd", "", "src//cache.h"):
        assert headers.include_spelling(rejected) is None


def test_normalize_includes_rewrites_workspace_header_and_preserves_duplicate_check(tmp_path: Path) -> None:
    unit = _build_unit(tmp_path)
    headers = buildctx.Headers(unit)
    base_res = relay.answer()["result"]
    raw = WriterAnswer.from_result({
        **base_res,
        "test_function": {
            **base_res["test_function"],
            "includes": ["cstddef", "include/relay/relay.hpp"],
        },
    })

    normalized = normalize_includes(raw, SETTINGS, headers)
    assert normalized.includes == ("cstddef", "relay/relay.hpp")
    assert check_answer(normalized, SETTINGS, headers) == []
    text = assemble(normalized, SETTINGS, claim_id="claim-" + "1" * 64, package_id="pkg-" + "2" * 64)
    assert '#include "relay/relay.hpp"' in text
    assert '#include "include/relay/relay.hpp"' not in text

    dup = WriterAnswer.from_result({
        **base_res,
        "test_function": {
            **base_res["test_function"],
            "includes": ["include/relay/relay.hpp", "relay/relay.hpp"],
        },
    })
    dup_norm = normalize_includes(dup, SETTINGS, headers)
    violations = check_answer(dup_norm, SETTINGS, headers)
    assert [v.rule for v in violations] == ["include"]
    assert "listed twice" in violations[0].message


def test_prepare_and_derive_pass_sink_tu_iquote_flags_for_synthesized_decls(tmp_path: Path) -> None:
    unit = _build_unit(tmp_path)
    builds = _accepted_builds(unit)
    scratch = buildcheck.prepare(
        builds,
        unit,
        tmp_path / "scratch",
        name="claim-1",
        poc_text="void poc_x(void) {}\n",
        settings=SETTINGS,
        synthesized_header='#include "packet_internal.hpp"\nvoid helper(void);\n',
    )
    assert scratch.names.quote_directories == ("src", ".")

    syntax_argv, _ = buildcheck.derive(unit.command.argv, unit.command.source, "syntax", scratch.names, SETTINGS)
    inc_idx = syntax_argv.index("-include")
    assert syntax_argv[inc_idx - 4:inc_idx] == ["-iquote", "/workspace/src", "-iquote", "/workspace"]

    ast_argv = buildcheck.derive_ast(unit.command.argv, unit.command.source, scratch.names, SETTINGS)
    ast_inc_idx = ast_argv.index("-include")
    assert ast_argv[ast_inc_idx - 4:ast_inc_idx] == ["-iquote", "/workspace/src", "-iquote", "/workspace"]

    step = buildcheck.Step(
        name="syntax",
        argv=tuple(syntax_argv),
        working_directory="/workspace",
        exit_code=0,
        timed_out=False,
        duration_ms=5,
        stdout=b"",
        stderr=b"",
    )
    visible = step.record(scratch.names)["command"]
    iq_pos = visible.index("-iquote")
    assert visible[iq_pos:iq_pos + 4] == ["-iquote", "target:src", "-iquote", "/workspace"]
    assert "<external-path>" not in visible
    assert "<redacted>" not in visible


def test_validate_candidate_accepts_workspace_relative_declaration_include_and_passes_iquote(
    tmp_path: Path,
) -> None:
    ctx = _job_context(tmp_path)
    unit_root = ctx.attempt_root / "unit"
    unit_root.mkdir(parents=True, exist_ok=True)
    unit_ctx = SimpleNamespace(job=ctx, unit_root=unit_root)
    build_unit = _build_unit(tmp_path / "accepted")
    builds = _accepted_builds(build_unit)
    executor = FakeExecutor(ast=ast_document("good"))
    services = job.Services(
        infer=None,
        executor_factory=lambda *_: executor,
        builds_factory=None,
        core_factory=None,
        view_factory=None,
        sink_resolver=job.review_inputs.sink_of,
        repository_root=ROOT,
    )
    candidate = parse_candidates([_candidate_dict(1)])[0]
    plan_entry = {
        "sink": {"path": "src/packet.cpp", "name": relay.SINK, "line": 8},
        "expectation": {
            "sink_names": [relay.SINK],
            "path_calls": [relay.SINK],
            "triggers": [],
        },
        "synthesized_header": '#include "relay/relay.hpp"\n',
    }
    proposal = relay.answer()["result"]
    proposal = {
        **proposal,
        "test_function": {
            **proposal["test_function"],
            "includes": ["include/relay/relay.hpp"],
        },
    }
    validated = job._validate_candidate(
        unit_ctx,
        SETTINGS,
        services,
        builds,
        {},
        candidate,
        plan_entry,
        {"result": proposal},
    )
    assert validated["policy_verdict"] == "passed"
    assert validated["terminal"] is None
    assert validated["answer"]["test_function"]["includes"] == ["relay/relay.hpp"]
    source_doc = read_bound_json(ctx.run_root, validated["source"])
    assert '#include "relay/relay.hpp"' in source_doc["text"]
    ast_cmd = executor.calls[0]["argv"]
    assert "-iquote" in ast_cmd
    iq = ast_cmd.index("-iquote")
    assert list(ast_cmd[iq:iq + 4]) == ["-iquote", "/workspace/src", "-iquote", "/workspace"]

    denied_proposal = {
        **proposal,
        "test_function": {
            **proposal["test_function"],
            "includes": ["unbuilt/secret.hpp"],
        },
    }
    denied = job._validate_candidate(
        unit_ctx,
        SETTINGS,
        services,
        builds,
        {},
        candidate,
        plan_entry,
        {"result": denied_proposal},
    )
    assert denied["policy_verdict"] == "denied"
    assert denied["terminal"]["status"] == POLICY_DENIED
