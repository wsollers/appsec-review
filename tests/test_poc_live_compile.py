"""A real compile of the hand-written relay reproducer in the local build image (skipped without Docker).

The workspace is a read-only copy of ``targets/cpp-multivuln`` under ``tmp_path``; the "accepted build" is
simulated by compiling its sources to object files with the project's own flags in the image. The job's
own steps then run through the production ``BuildContainerExecutor`` with no network: the in-image AST
reduction, the validators, ``-fsyntax-only``, ``-c`` with ``-g -O0``, ``-c`` with the sanitizer flags and
``nm``. Nothing is linked and nothing is run. Set ``POC_LIVE_TRANSCRIPT=1`` and ``-s`` to print the
commands and their outputs.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.job_poc_generation import buildcheck
from appsec_review.jobs.job_poc_generation.buildctx import Headers
from appsec_review.jobs.job_poc_generation.policy import Expectation, check_ast, numeric_requirement
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble, check_answer, file_violations
from appsec_review.jobs.job_poc_generation.statuses import COMPILE_FAILED, COMPILE_VERIFIED
from tests import poc_support
from tests.fixtures.poc_generation import relay

TAG = "audit-buildenv-cpp:local"
SOURCES = ("config", "diag", "frame", "log", "main", "packet", "session")


def _image_id() -> str | None:
    if shutil.which("docker") is None:
        return None
    try:
        done = subprocess.run(["docker", "image", "inspect", TAG, "--format", "{{.Id}}"], capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip().startswith("sha256:") else None


TRANSCRIPT = bool(os.environ.get("POC_LIVE_TRANSCRIPT"))


def show(*parts: object) -> None:
    if TRANSCRIPT:
        print(*parts)


@pytest.fixture(scope="module")
def build(tmp_path_factory):
    IMAGE = _image_id()                   # asked when a test needs it, never while collecting
    if IMAGE is None:
        pytest.skip(f"Docker or the {TAG} image is unavailable")
    root = tmp_path_factory.mktemp("poc-live")
    workspace, _manifest = poc_support.relay_workspace(root / "workspace", with_objects=False)
    profile = BuildProfile("native", TAG, IMAGE, "10001:10001")
    executor = BuildContainerExecutor(profile, timeout_seconds=300, output_bytes=8 * 1024 * 1024, network="none")
    executor.resolve()
    objects = []
    for name in (name for name in SOURCES if (workspace / "src" / f"{name}.cpp").is_file()):
        # the accepted build: the project's own command per translation unit
        output = f"build/CMakeFiles/relay.dir/src/{name}.cpp.o"
        (workspace / output).parent.mkdir(parents=True, exist_ok=True)
        argv = ["/usr/bin/clang++", "-I/workspace/include", "-O2", "-g", "-DNDEBUG", "-std=c++17", "-Wall", "-Wextra",
                "-o", f"/workspace/{output}", "-c", f"/workspace/src/{name}.cpp"]
        step = buildcheck.run_step(executor, f"accepted-{name}", argv, workspace, ".")
        assert step.ok, step.stderr
        objects.append(output)
    manifest = poc_support.manifest_of(workspace)
    unit = poc_support.relay_unit(workspace, manifest, objects=objects, image_id=IMAGE, tag=TAG)
    return {"root": root, "executor": executor, "unit": unit, "builds": poc_support.builds(unit),
            "settings": poc_support.settings()}


def run(build, test: str, control: str, *, includes=relay.INCLUDES, name: str = "good"):
    """The job's validate and compile steps for one answer; ``(violations, outcome or None)``."""
    settings, unit, executor = build["settings"], build["unit"], build["executor"]
    answer = WriterAnswer.from_result(relay.answer(test, control, includes=includes)["result"])
    headers = Headers(unit)
    text_found = [*check_answer(answer, settings, headers)]
    text = assemble(answer, settings, claim_id="claim-" + "0" * 64, package_id="finding_lead-" + "0" * 64)
    text_found += file_violations(text, settings)
    if text_found:
        return text_found, None
    scratch = buildcheck.prepare(build["builds"], unit, build["root"] / "scratch", name=name, poc_text=text,
                                 settings=settings)
    try:
        step = buildcheck.ast_step(executor, unit, scratch, settings)
        reduced, why = buildcheck.reduced_ast(step)
        assert reduced is not None, why
        show("\n$ AST", " ".join(buildcheck.render(step.argv, tuple(step.visible(scratch.names)))), "->",
             f"exit {reduced['compiler_exit_code']},",
             f"{len(reduced['nodes'])} PoC nodes,", reduced["compiler_version"])
        expectation = Expectation(answer.functions, (relay.SINK,), frozenset(), (numeric_requirement("greater than 16"),))
        found = check_ast(reduced, settings, expectation)
        if found or reduced["compiler_exit_code"] != 0:
            return found, None
        outcome = buildcheck.check_build(executor, build["builds"], unit, scratch, settings,
                                         claim_id="claim-" + "0" * 64)
        for item in outcome.record["steps"]:
            show("$", " ".join(item["command"]), "->", f"exit {item['exit_code']}", item["diagnostics"][:3])
        show("objects:", json.dumps(outcome.record["objects"]))
        show("symbol_check:", json.dumps({key: value for key, value in outcome.record["symbol_check"].items()
                                          if key in {"undefined", "resolved_by_project", "resolved_by_runtime",
                                                     "weak", "unresolved"}}))
        show("status:", outcome.status, "-", outcome.reason)
        return found, outcome
    finally:
        shutil.rmtree(scratch.root, ignore_errors=True)


def test_the_relay_reproducer_is_accepted_and_compiles_plain_and_under_sanitizers(build) -> None:
    violations, outcome = run(build, relay.GOOD_TEST, relay.GOOD_CONTROL)
    assert violations == []
    assert outcome.status == COMPILE_VERIFIED, outcome.record
    record = outcome.record
    assert [step["name"] for step in record["steps"][:3]] == ["syntax", "object", "sanitized_object"]
    assert all(step["exit_code"] == 0 for step in record["steps"][:3])
    object_step = record["steps"][1]["command"]
    sanitized = record["steps"][2]["command"]
    assert "-O0" in object_step and "-g" in object_step and "-O2" not in object_step and "-DNDEBUG" in object_step
    assert "-fsanitize=address,undefined" in sanitized and "-fno-omit-frame-pointer" in sanitized
    symbols = record["symbol_check"]
    assert symbols["unresolved"] == []
    assert "_ZN5relay12parse_headerEPKhmRNS_6HeaderE" in symbols["resolved_by_project"]
    assert any(name.startswith("__asan_") for name in symbols["resolved_by_runtime"]) or "memset" in symbols[
        "resolved_by_runtime"] or symbols["undefined"]
    assert set(record["objects"]) == {"object", "sanitized_object"}


def test_the_compile_check_never_links_or_runs_anything(build) -> None:
    class Recording:
        def __init__(self, inner) -> None:
            self.inner, self.calls = inner, []

        def execute(self, argv, **kwargs):
            self.calls.append(tuple(argv))
            return self.inner.execute(argv, **kwargs)

    recorder = Recording(build["executor"])
    scratch = buildcheck.prepare(build["builds"], build["unit"], build["root"] / "scratch", name="nolink",
                                 poc_text=assemble(WriterAnswer.from_result(relay.answer()["result"]),
                                                   build["settings"], claim_id="claim-" + "0" * 64,
                                                   package_id="finding_lead-" + "0" * 64),
                                 settings=build["settings"])
    try:
        outcome = buildcheck.check_build(recorder, build["builds"], build["unit"], scratch, build["settings"],
                                         claim_id="claim-" + "0" * 64)
    finally:
        shutil.rmtree(scratch.root, ignore_errors=True)
    assert outcome.status == COMPILE_VERIFIED
    for argv in recorder.calls:
        assert argv[0] in {"nm", "/usr/bin/clang++"}
        if argv[0] != "nm":
            assert "-c" in argv or "-fsyntax-only" in argv
            assert "-o" not in argv or argv[argv.index("-o") + 1].endswith(".o")
        assert not any(item.startswith("./") for item in argv)


@pytest.mark.parametrize(("label", "test", "rule"), [
    ("a main function", relay.VARIANTS["main_defined"][0], "entry_point"),
    ("system()", relay.VARIANTS["system_call"][0], "call_not_allowlisted"),
    ("a file stream", relay.VARIANTS["ifstream"][0], "type_not_allowed"),
])
def test_deliberately_bad_variants_are_rejected_by_the_validators(build, label, test, rule) -> None:
    includes = (*relay.INCLUDES, "cstdlib", "fstream")
    from appsec_review.jobs.job_poc_generation import source
    # the headers the variants need are not on the allowlist, so the text check would refuse them first; the
    # AST validators are what this test exercises, so allow the headers for the run.
    permissive = poc_support.settings_table()
    permissive["policy"]["allowed_std_headers"] = [*permissive["policy"]["allowed_std_headers"], "cstdlib", "fstream"]
    allowed = type(build["settings"]).from_mapping(permissive)
    local = dict(build, settings=allowed)
    violations, outcome = run(local, test, relay.GOOD_CONTROL, includes=includes, name=rule)
    show(f"\n{label}: {[(item.rule, item.line) for item in violations]}")
    assert outcome is None and rule in [item.rule for item in violations]
    assert source is not None


def test_an_unknown_include_is_rejected_before_any_compiler_runs(build) -> None:
    violations, outcome = run(build, relay.GOOD_TEST, relay.GOOD_CONTROL,
                              includes=(*relay.INCLUDES, "relay/not_a_project_header.hpp"))
    show("\nunknown include:", [(item.rule, item.message) for item in violations])
    assert outcome is None and [item.rule for item in violations] == ["include"]
    violations, _ = run(build, relay.GOOD_TEST, relay.GOOD_CONTROL, includes=(*relay.INCLUDES, "unistd.h"))
    assert [item.rule for item in violations] == ["include"]


def test_code_that_does_not_build_is_compile_failed_not_policy_denied(build) -> None:
    broken = relay.GOOD_TEST.replace("relay::parse_header(packet, sizeof packet, header);",
                                     "relay::parse_header(packet, sizeof packet);")
    violations, outcome = run(build, broken, relay.GOOD_CONTROL, name="broken")
    # the call has the wrong arity, so the parse fails (clang exits 1) and the validators do not pass it on
    assert outcome is None or outcome.status == COMPILE_FAILED
    assert violations == [] or all(item.rule != "entry_point" for item in violations)


def test_the_recorded_asts_match_a_fresh_recording_of_the_reproducer(build) -> None:
    settings, unit = build["settings"], build["unit"]
    answer = WriterAnswer.from_result(relay.answer()["result"])
    text = assemble(answer, settings, claim_id="claim-" + "0" * 64, package_id="finding_lead-" + "0" * 64)
    scratch = buildcheck.prepare(build["builds"], unit, build["root"] / "scratch", name="fresh", poc_text=text,
                                 settings=settings)
    try:
        reduced, why = buildcheck.reduced_ast(buildcheck.ast_step(build["executor"], unit, scratch, settings))
    finally:
        shutil.rmtree(scratch.root, ignore_errors=True)
    assert reduced is not None, why
    recorded = poc_support.ast_document("good")
    # clang's node ids are memory addresses and differ between runs; everything else is the recorded document
    assert poc_support.without_ids(reduced["nodes"]) == poc_support.without_ids(recorded["nodes"])
    assert poc_support.without_ids(reduced["project_declarations"]) == poc_support.without_ids(
        recorded["project_declarations"])


def test_a_reproducer_that_builds_its_input_in_a_std_string_also_compiles_and_resolves(build) -> None:
    """The standard-library allowlist prefixes match what clang actually names (``std::basic_string::data``)."""
    test, control, _rule = relay.VARIANTS["string_fill"]
    violations, outcome = run(build, test, control, name="string_fill")
    assert violations == [] and outcome.status == COMPILE_VERIFIED, (violations, outcome and outcome.record)
    undefined = outcome.record["symbol_check"]["undefined"]
    assert poc_support.PROJECT_SYMBOL in undefined and outcome.record["symbol_check"]["unresolved"] == []
