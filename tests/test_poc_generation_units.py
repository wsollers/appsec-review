"""job_poc_generation building blocks: settings, candidates, the accepted build lookup and the compile check.

The container is replaced by ``tests.poc_support.FakeExecutor`` (and, for the docker arguments, by the
sanitizer tests' Docker CLI fake under the real ``BuildContainerExecutor``). Nothing here needs Docker and
nothing produced is ever executed.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import tomllib

import pytest

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.job_poc_generation import buildcheck
from appsec_review.jobs.job_poc_generation.buildctx import (
    AcceptedBuilds, Headers, declarations, language_of,
)
from appsec_review.jobs.job_poc_generation.candidates import (
    FIELD, check_against_review, parse_basis, parse_candidates, read_candidates,
)
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from appsec_review.jobs.job_poc_generation.source import WriterAnswer, assemble
from appsec_review.jobs.job_poc_generation.statuses import (
    ARTIFACT_GENERATED, COMPILE_FAILED, COMPILE_VERIFIED, STATUSES,
)
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json
from tests import poc_support
from tests.fixtures.poc_generation import relay
from tests.sanitizer_support import DockerFake

ROOT = Path(__file__).parents[1]
CLAIM = "claim-" + "1" * 64
SETTINGS = poc_support.settings()
IDENTITY = "claim-" + "0" * 64


# ----------------------------------------------------------------------------------------------- settings


def test_shipped_configuration_is_valid_and_declares_the_steps() -> None:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    job = document["jobs"]["job_poc_generation"]
    settings = PocGenerationSettings.from_mapping(job["settings"])
    assert type(settings.enabled) is bool
    assert tuple(job["steps"]) == ("load", "plan", "write", "validate", "compile", "package", "publish")
    assert settings.writer.provider == "claude-cli" and settings.writer_profile == "default"
    assert settings.accepted_judge_verdicts == ("red_correct",)
    assert settings.policy.project_calls == "sink_and_path"
    assert "system" in settings.policy.call_denylist["shell"] and "system" not in settings.policy.call_allowlist


@pytest.mark.parametrize(("mutate", "message"), [
    (lambda t: t.pop("max_candidates"), "exactly its documented keys"),
    (lambda t: t.update(extra=1), "exactly its documented keys"),
    (lambda t: t.update(enabled="no"), "enabled must be a boolean"),
    (lambda t: t.update(workers=0), "workers must be an integer"),
    (lambda t: t.update(accepted_judge_verdicts=["everyone"]), "accepted_judge_verdicts must be drawn from"),
    (lambda t: t["roles"]["poc_writer"].update(model_profile="missing"), "must name a model profile"),
    (lambda t: t["models"]["default"].pop("provider"), "exactly its documented keys"),
    (lambda t: t["policy"].update(project_calls="anything"), "project_calls must be one of"),
    (lambda t: t["policy"]["call_denylist"].pop("shell"), "exactly its documented keys"),
    (lambda t: t["policy"].update(call_allowlist=["ok", "ok"]), "unique list"),
    (lambda t: t["policy"].update(call_allowlist=["has space"]), "well-formed names"),
    (lambda t: t["build"].update(debug_flags=["not-a-flag"]), "unique list"),
    (lambda t: t["build"].update(scratch_directory="poc"), "hidden directory"),
    (lambda t: t["build"].update(ast_compilers={"c": "clang"}), "compiler for c and cxx"),
    (lambda t: t["bounds"].update(max_function_lines=0), "max_function_lines must be an integer"),
])
def test_settings_are_closed_and_typed(mutate, message) -> None:
    table = deepcopy(poc_support.settings_table())
    mutate(table)
    with pytest.raises(ValueError, match=message):
        PocGenerationSettings.from_mapping(table)


def test_the_settings_identity_changes_with_every_validator_input() -> None:
    base = SETTINGS.settings_sha256()
    for path, value in ((("policy", "call_allowlist"), [*SETTINGS.policy.call_allowlist, "getenv"]),
                        (("bounds", "max_function_lines"), 10), (("build", "sanitizer_flags"), ["-fsanitize=address"]),
                        (("accepted_judge_verdicts",), ["red_correct", "partly"])):
        table = deepcopy(poc_support.settings_table())
        node = table
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        assert PocGenerationSettings.from_mapping(table).settings_sha256() != base, path


# --------------------------------------------------------------------------------------------- candidates


def basis_value() -> dict:
    return {"entry": ["asr:entry_point:" + "1" * 64],
            "path": ["asr:call_site:" + "2" * 64, "asr:call_site:" + "3" * 64],
            "trigger": [relay.TRIGGER], "input_format": "4-byte header",
            "preconditions": ["attacker_controls_file_content"], "expected_observation": "stack-buffer-overflow",
            "unknowns": ["X1"]}


def candidate_entry(**changes) -> dict:
    value = basis_value()
    entry = {"claim_id": CLAIM, "package_id": "finding_lead-" + "2" * 64, "state": "confirmed",
             "judge_verdict": "red_correct",
             "poc_basis": {"sha256": hashlib.sha256(canonical_json(value)).hexdigest(), "brief": value},
             "finding_package": {"finding_package_id": "finding-" + "3" * 64, "sha256": "4" * 64},
             "evidence_refs": ["evrel-" + "5" * 64, "asr:sink_site:" + "6" * 64]}
    entry.update(changes)
    return entry


def test_a_well_formed_candidate_list_is_read_into_typed_candidates() -> None:
    (candidate,) = parse_candidates([candidate_entry()])
    assert candidate.claim_id == CLAIM and candidate.poc_basis.usable
    assert candidate.poc_basis.entry == ("asr:entry_point:" + "1" * 64,)
    assert candidate.poc_basis.trigger[0]["constraint"] == "greater than 16"
    assert candidate.poc_basis.record() == basis_value()


def test_a_handoff_without_the_field_is_an_older_run_and_an_empty_list_is_a_run_with_no_claim() -> None:
    assert read_candidates({"schema": "x"}) is None
    assert read_candidates({FIELD: []}) == ()


@pytest.mark.parametrize("bad", [
    {"claim_id": "claim-short"}, {"package_id": "no spaces"}, {"state": "contradicted"}, {"judge_verdict": "maybe"},
    {"evidence_refs": ["not-a-ref"]}, {"evidence_refs": ["evrel-" + "5" * 64] * 2},
    {"finding_package": {"finding_package_id": "finding-" + "3" * 64}}, {"extra": True},
    {"poc_basis": {"sha256": "0" * 64, "brief": basis_value()}},                       # hash does not match
    {"poc_basis": {"sha256": "x", "brief": basis_value()}},
])
def test_a_malformed_candidate_is_an_integrity_failure(bad) -> None:
    with pytest.raises(IntegrityError):
        parse_candidates([candidate_entry(**bad)])


def test_the_poc_basis_is_bounded_like_protocol_section_6_6() -> None:
    def rebuild(**changes):
        value = {**basis_value(), **changes}
        return {"sha256": hashlib.sha256(canonical_json(value)).hexdigest(), "brief": value}

    for changes in ({"entry": [f"E{n}" for n in range(1, 10)]}, {"path": ["f1"]}, {"input_format": "x" * 241},
                    {"trigger": [{"field": "a"}]}, {"preconditions": ["x"] * 9}, {"unknowns": "X1"}):
        with pytest.raises(IntegrityError):
            parse_basis(rebuild(**changes), 0)
    assert not parse_basis(rebuild(entry=[]), 0).usable and not parse_basis(rebuild(trigger=[]), 0).usable


def test_duplicate_claims_and_a_non_list_are_refused() -> None:
    with pytest.raises(IntegrityError, match="twice"):
        parse_candidates([candidate_entry(), candidate_entry()])
    with pytest.raises(IntegrityError, match="array"):
        parse_candidates({"claim_id": CLAIM})


def test_candidates_are_checked_against_the_verified_finding_packages() -> None:
    candidates = parse_candidates([candidate_entry()])
    finding = {"finding-" + "3" * 64: {"sha256": "4" * 64, "claim_id": CLAIM, "state": "confirmed"}}
    assert check_against_review(candidates, finding) == []
    assert "not in the review handoff" in check_against_review(candidates, {})[0]
    assert "digest" in check_against_review(candidates, {k: {**v, "sha256": "9" * 64} for k, v in finding.items()})[0]
    assert "state" in check_against_review(candidates, {k: {**v, "state": "supported"} for k, v in finding.items()})[0]


# ------------------------------------------------------------------------------------------------ commands


def test_the_derived_commands_keep_the_projects_flags_and_drop_what_would_write_or_link() -> None:
    names = buildcheck.Names(".appsec-poc", "poc.cpp")
    argv = [*relay.PACKET_ARGV[:-1], "/workspace/src/packet.cpp"]
    syntax, dropped = buildcheck.derive(argv, "src/packet.cpp", "syntax", names, SETTINGS)
    assert syntax == ["/usr/bin/clang++", "-I/workspace/include", "-O2", "-g", "-DNDEBUG", "-std=c++17", "-Wall",
                      "-Wextra", "-fsyntax-only", "/workspace/.appsec-poc/poc.cpp"]
    assert {"-MD", "-MT", "-MF", "-o", "-c", "<translation unit>"} <= set(dropped)
    plain, _ = buildcheck.derive(argv, "src/packet.cpp", "object", names, SETTINGS)
    assert plain[-5:] == ["-c", "-o", "/workspace/.appsec-poc/poc.o", "/workspace/.appsec-poc/poc.cpp"][-4:] or \
        plain[-4:] == ["-c", "-o", "/workspace/.appsec-poc/poc.o", "/workspace/.appsec-poc/poc.cpp"]
    assert "-O2" not in plain and plain.count("-g") == 1 and "-O0" in plain and "-DNDEBUG" in plain
    sanitized, _ = buildcheck.derive(argv, "src/packet.cpp", "sanitized", names, SETTINGS)
    assert "-fsanitize=address,undefined" in sanitized and "-fno-omit-frame-pointer" in sanitized
    assert sanitized[-2] == "/workspace/.appsec-poc/poc_san.o" and "-o" in sanitized


def test_plugins_werror_and_project_sanitizers_do_not_survive_the_replay() -> None:
    names = buildcheck.Names(".appsec-poc", "poc.cpp")
    argv = ["/usr/bin/g++", "-Werror", "-Werror=format", "-fplugin=evil.so", "-Xclang", "-load", "-Xclang", "p.so",
            "-fsanitize=thread", "-I/workspace/inc", "-pedantic-errors", "-c", "/workspace/a.c"]
    out, dropped = buildcheck.derive(argv, "a.c", "sanitized", names, SETTINGS)
    assert out[0] == "/usr/bin/g++" and "-fsanitize=thread" not in out and "-I/workspace/inc" in out
    assert not any(item in out for item in ("-Werror", "-Werror=format", "-fplugin=evil.so", "-load", "p.so",
                                              "-pedantic-errors"))
    assert "-Xclang -load" in dropped
    with pytest.raises(ValueError):
        buildcheck.derive(argv, "a.c", "link", names, SETTINGS)


def test_the_ast_command_runs_the_reducer_around_clang_with_only_parsing_flags() -> None:
    names = buildcheck.Names(".appsec-poc", "poc.cpp")
    command = buildcheck.derive_ast(["/usr/bin/g++", "-I/workspace/include", "-isystem", "/usr/x", "-DA=1", "-O2",
                                     "-std=c++17", "-fno-rtti", "-Wall", "-march=native", "-include", "pre.h"],
                                    "cxx", names, SETTINGS)
    assert command[:2] == ["python3", "/workspace/.appsec-poc/ast_reduce.py"]
    after = command[command.index("--") + 1:]
    assert after[0] == "clang++"                            # the project's gcc is not used to dump a clang AST
    assert after[1:-4] == ["-I/workspace/include", "-isystem", "/usr/x", "-DA=1", "-std=c++17", "-fno-rtti",
                           "-include", "pre.h"]
    assert after[-4:] == ["-fsyntax-only", "-Xclang", "-ast-dump=json", "/workspace/.appsec-poc/poc.cpp"]
    assert buildcheck.derive_ast(["/usr/bin/clang++", "-c"], "cxx", names, SETTINGS)[command.index("--") + 1] == \
        "/usr/bin/clang++"


def test_rendered_commands_show_logical_paths_and_never_a_redacted_value() -> None:
    shown = buildcheck.render(["/usr/bin/clang++", "-I/workspace/include", "-DTOKEN=secret", "-DNDEBUG",
                               "-std=c++17", "/workspace/.appsec-poc/poc.cpp"],
                              ["/usr/bin/clang++", "/workspace/.appsec-poc/poc.cpp"])
    assert shown[0] == "/usr/bin/clang++" and shown[1] == "-Itarget:include" and shown[-1].endswith("poc.cpp")
    assert "secret" not in " ".join(shown) and shown[2] == "<redacted>"
    assert buildcheck.render(["c", "-DMODE=2"])[1] == "-DMODE=<redacted>"


def test_nm_output_is_parsed_and_symbols_are_resolved_against_project_and_runtime() -> None:
    text = "poc.o:\nfoo U\nbar@@GLIBC_2.2.5 T 0 0\n__gmon_start__ w\nbaz i 10 4\n"
    assert buildcheck.parse_nm(text) == [("foo", "U"), ("bar", "T"), ("__gmon_start__", "w"), ("baz", "i")]
    result = buildcheck.resolve_symbols([("a", "U"), ("b", "U"), ("c", "U"), ("__asan_init", "U"), ("w", "w")],
                                        {"a"}, {"b"}, ["__asan_"])
    assert result == {"undefined": ["__asan_init", "a", "b", "c"], "resolved_by_project": ["a"],
                      "resolved_by_runtime": ["__asan_init", "b"], "weak": ["w"], "unresolved": ["c"]}


# ----------------------------------------------------------------------------------------- the compile check


@pytest.fixture()
def prepared(tmp_path):
    workspace, manifest = poc_support.relay_workspace(tmp_path / "accepted")
    unit = poc_support.relay_unit(workspace, manifest)
    builds = poc_support.builds(unit)
    answer = WriterAnswer.from_result(relay.answer()["result"])
    text = assemble(answer, SETTINGS, claim_id=IDENTITY, package_id="finding_lead-" + "0" * 64)
    scratch = buildcheck.prepare(builds, unit, tmp_path / "scratch", name="c1", poc_text=text, settings=SETTINGS)
    return unit, builds, scratch, workspace


def test_the_scratch_copy_is_a_verified_copy_with_the_poc_file_and_reducer(prepared) -> None:
    unit, _builds, scratch, workspace = prepared
    folder = scratch.root / ".appsec-poc"
    assert (folder / "poc.cpp").read_text(encoding="utf-8").startswith("// Proof-of-concept unit-test functions")
    assert (folder / "ast_reduce.py").read_bytes() == buildcheck.REDUCER.read_bytes()
    assert (scratch.root / "src" / "packet.cpp").read_bytes() == (workspace / "src" / "packet.cpp").read_bytes()
    assert not (workspace / ".appsec-poc").exists()                       # the accepted workspace is never written


def test_a_compile_that_passes_every_step_is_verified_and_records_each_command(prepared) -> None:
    unit, builds, scratch, _ = prepared
    executor = poc_support.FakeExecutor()
    outcome = buildcheck.check_build(executor, builds, unit, scratch, SETTINGS, claim_id=IDENTITY)
    assert outcome.status == COMPILE_VERIFIED and outcome.status in STATUSES
    record = outcome.record
    assert [step["name"] for step in record["steps"]] == [
        "syntax", "object", "sanitized_object", "undefined_symbols", "project_symbols", "runtime_symbols"]
    assert record["symbol_check"]["unresolved"] == [] and record["symbol_check"]["resolved_by_project"] == [
        poc_support.PROJECT_SYMBOL]
    assert set(record["objects"]) == {"object", "sanitized_object"} and record["gaps"] == []
    assert record["execution_policy"] == "nothing is linked into an executable and nothing is run"
    assert record["translation_unit"]["dropped_flags"]["object"]
    executor.assert_nothing_is_linked_or_run()
    # the placeholders the build produced were only ever inputs to nm, never commands
    names = [call["argv"][0] for call in executor.calls]
    assert names.count("nm") == 3 and names[:3] == ["/usr/bin/clang++"] * 3


def test_every_compiler_command_is_a_syntax_check_or_an_object_compile(prepared) -> None:
    unit, builds, scratch, _ = prepared
    executor = poc_support.FakeExecutor()
    buildcheck.check_build(executor, builds, unit, scratch, SETTINGS, claim_id=IDENTITY)
    modes = []
    for call in executor.calls:
        argv = call["argv"]
        if argv[0] == "nm":
            assert all(not item.startswith("-o") for item in argv)
            continue
        assert call["environment"] == {} and call["working_directory"] == "."
        modes.append("syntax" if "-fsyntax-only" in argv else "object" if "-c" in argv else "LINK")
    assert modes == ["syntax", "object", "object"]


@pytest.mark.parametrize(("failing", "step"), [("-fsyntax-only", "syntax"), ("poc.o", "object"),
                                              ("poc_san.o", "sanitized_object")])
def test_a_step_that_fails_to_compile_is_compile_failed_with_its_diagnostics(prepared, failing, step) -> None:
    unit, builds, scratch, _ = prepared
    executor = poc_support.FakeExecutor(fail={failing: 1})
    outcome = buildcheck.check_build(executor, builds, unit, scratch, SETTINGS, claim_id=IDENTITY)
    assert outcome.status == COMPILE_FAILED and step in outcome.reason
    last = outcome.record["steps"][-1]
    assert last["name"] == step and last["exit_code"] == 1 and "error" in last["diagnostics"][0]
    assert outcome.record["symbol_check"] is None                         # nothing after the failure ran


def test_a_symbol_the_project_and_the_runtime_do_not_define_fails_the_check(prepared) -> None:
    unit, builds, scratch, _ = prepared
    executor = poc_support.FakeExecutor(undefined=poc_support.NM_UNDEFINED + "_Z9not_therev U\n")
    outcome = buildcheck.check_build(executor, builds, unit, scratch, SETTINGS, claim_id=IDENTITY)
    assert outcome.status == COMPILE_FAILED and outcome.record["symbol_check"]["unresolved"] == ["_Z9not_therev"]


def test_an_unavailable_image_or_missing_objects_is_artifact_generated_with_a_named_gap(tmp_path) -> None:
    workspace, manifest = poc_support.relay_workspace(tmp_path / "w", with_objects=False)
    unit = poc_support.relay_unit(workspace, manifest, objects=())
    builds = poc_support.builds(unit)
    text = assemble(WriterAnswer.from_result(relay.answer()["result"]), SETTINGS, claim_id=IDENTITY,
                    package_id="finding_lead-" + "0" * 64)
    scratch = buildcheck.prepare(builds, unit, tmp_path / "s", name="c", poc_text=text, settings=SETTINGS)
    outcome = buildcheck.check_build(poc_support.FakeExecutor(project=""), builds, unit, scratch, SETTINGS,
                                     claim_id=IDENTITY)
    assert outcome.status == ARTIFACT_GENERATED and outcome.gaps and "project" in outcome.reason

    class Broken:
        def execute(self, *args, **kwargs):
            raise RuntimeError("docker is not available")

    outcome = buildcheck.check_build(Broken(), builds, unit, scratch, SETTINGS, claim_id=IDENTITY)
    assert outcome.status == ARTIFACT_GENERATED and "unavailable" in outcome.reason


def test_the_production_executor_runs_these_commands_with_no_network_and_a_read_only_root(prepared) -> None:
    unit, builds, scratch, _ = prepared
    profile = BuildProfile("native", unit.image_tag, unit.image_id, "10001:10001")
    fake = DockerFake(profile)
    executor = BuildContainerExecutor(profile, timeout_seconds=60, output_bytes=100000, runner=fake, network="none")
    executor.resolve()
    step = buildcheck.run_step(executor, "syntax", ["/usr/bin/clang++", "-fsyntax-only", "/workspace/x.cpp"],
                               scratch.root, ".")
    assert step.ok
    docker = fake.runs[0]["docker"]
    assert docker[docker.index("--network") + 1] == "none" and "--read-only" in docker and "--cap-drop" in docker
    assert docker[docker.index("--entrypoint") + 1] == "/usr/bin/clang++"
    with pytest.raises(ValueError, match="bridge or none"):
        BuildContainerExecutor(profile, timeout_seconds=1, output_bytes=1, network="host")
    default = BuildContainerExecutor(profile, timeout_seconds=1, output_bytes=1, runner=fake)
    default.execute(["true"], workspace=scratch.root, working_directory=".", environment={})
    assert fake.runs[-1]["docker"][fake.runs[-1]["docker"].index("--network") + 1] == "bridge"


# --------------------------------------------------------------------------------------- the accepted build


def test_the_sinks_translation_unit_is_found_from_the_protected_compile_database(tmp_path) -> None:
    accepted = poc_support.accepted_run(tmp_path)
    builds = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted)
    located = builds.locate("src/packet.cpp")
    assert located.code == "found" and located.unit is not None
    unit = located.unit
    assert builds.handoff_sha256 == "9" * 64
    assert unit.command.argv[0] == "/usr/bin/clang++"                      # the real compiler, not the wrapper
    assert unit.command.source == "src/packet.cpp" and unit.command.basis == "exact"
    assert unit.command.language == "cxx" and unit.command.working_directory == "."
    assert (unit.image_tag, unit.image_user) == ("audit-buildenv-cpp:local", "10001:10001")
    assert unit.objects == tuple(sorted(poc_support.OBJECTS)) and unit.shared_libraries == ()
    facts = unit.command.facts()
    assert facts["compiler"] == "clang++" and facts["standard"] == "-std=c++17" and facts["basis"] == "exact"
    assert "-Itarget:include" not in facts["include_paths"] and facts["include_paths"] == ["target:include"]
    assert "-DNDEBUG" in facts["defines"] and "argv" not in facts


def test_a_header_gets_a_default_translation_unit_of_the_unit(tmp_path) -> None:
    accepted = poc_support.accepted_run(tmp_path)
    builds = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted)
    located = builds.locate("include/relay/relay.hpp")
    assert located.unit.command.basis == "unit_default" and located.unit.command.source == "src/config.cpp"


@pytest.mark.parametrize(("kwargs", "path", "code"), [
    ({}, "README.md", "not_c_family"),
    ({}, "src/missing.cpp", "no_native_build"),
    ({"terminal": "FAILED"}, "src/packet.cpp", "no_native_build"),
    ({"family": "python"}, "src/packet.cpp", "no_native_build"),
    ({"compile_rows": False}, "src/packet.cpp", "no_compile_command"),
])
def test_a_file_without_an_accepted_native_build_is_named_not_guessed(tmp_path, kwargs, path, code) -> None:
    accepted = poc_support.accepted_run(tmp_path, **kwargs)
    located = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted).locate(path)
    assert located.unit is None and located.code == code and located.reason


def test_a_changed_workspace_database_or_manifest_is_an_integrity_failure_never_a_different_build(tmp_path) -> None:
    accepted = poc_support.accepted_run(tmp_path)
    builds = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted)
    unit = builds.locate("src/packet.cpp").unit
    (accepted.workspace / "src" / "packet.cpp").write_text("int changed;\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        builds.materialize(unit, tmp_path / "copy", byte_limit=10**9)
    fresh = poc_support.accepted_run(tmp_path / "second")
    fresh.database.write_text("{}", encoding="utf-8")
    with pytest.raises(IntegrityError, match="compile database changed"):
        AcceptedBuilds(fresh.run_root, loader=lambda _root: fresh.accepted).locate("src/packet.cpp")
    third = poc_support.accepted_run(tmp_path / "third")
    third.manifest_path.write_text("{}", encoding="utf-8")
    with pytest.raises(IntegrityError, match="workspace manifest changed"):
        AcceptedBuilds(third.run_root, loader=lambda _root: third.accepted).locate("src/packet.cpp")


def test_the_workspace_copy_is_bounded_and_refuses_paths_outside_it(tmp_path) -> None:
    accepted = poc_support.accepted_run(tmp_path)
    builds = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted, file_limit=3)
    unit = builds.locate("src/packet.cpp").unit
    with pytest.raises(ValueError, match="the bound is 3"):
        builds.materialize(unit, tmp_path / "a", byte_limit=10**9)
    builds = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted)
    with pytest.raises(ValueError, match="exceeds"):
        builds.materialize(unit, tmp_path / "b", byte_limit=10)
    escaped = type(unit)(**{**{field: getattr(unit, field) for field in unit.__slots__},
                            "workspace_manifest": {"../outside": "0" * 64}})
    with pytest.raises(IntegrityError, match="outside the workspace"):
        builds.materialize(escaped, tmp_path / "c", byte_limit=10**9)


def test_project_headers_are_resolved_on_the_include_path_and_nowhere_else(tmp_path) -> None:
    accepted = poc_support.accepted_run(tmp_path)
    unit = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted).locate("src/packet.cpp").unit
    headers = Headers(unit)
    assert headers.resolve("relay/relay.hpp") == "include/relay/relay.hpp"
    assert headers.search_directories()[0] == "include" and "src" in headers.search_directories()
    for name in ("../README.md", "/etc/passwd", "relay/nothing.hpp", "include/relay/relay.hpp"):
        assert headers.resolve(name) is None
    assert language_of("a.c") == "c" and language_of("a.hpp") == "cxx" and language_of("a.py") is None


def test_declarations_find_prototypes_and_type_layouts_with_their_lines(tmp_path) -> None:
    accepted = poc_support.accepted_run(tmp_path)
    unit = AcceptedBuilds(accepted.run_root, loader=lambda _root: accepted.accepted).locate("src/packet.cpp").unit
    rows = declarations(unit, Headers(unit), ["relay::parse_header", "Header"], source_bytes=65536, max_files=10,
                        max_lines=30)
    text = "\n".join(line for row in rows for line in row["text"])
    assert all(row["path"] == "include/relay/relay.hpp" for row in rows)
    assert "parse_header(const std::uint8_t *data, std::size_t size, Header &out);" in text
    assert "char name[16];" in text and "struct Header {" in text
    assert declarations(unit, Headers(unit), ["no_such_name"], source_bytes=65536, max_files=10, max_lines=30) == []
    assert declarations(unit, Headers(unit), [], source_bytes=65536, max_files=10, max_lines=30) == []


def test_relative_include_paths_run_the_derived_commands_in_the_build_directory() -> None:
    from appsec_review.jobs.job_poc_generation.buildctx import _working_directory

    assert _working_directory(["c", "-I/workspace/include", "-c"], "build") == "."
    assert _working_directory(["c", "-I../include", "-c"], "build") == "build"
    assert _working_directory(["c", "-isystem", "inc", "-c"], "build") == "build"
    assert _working_directory(["c", "-I../include", "-c"], ".") == "."
    assert _working_directory(["c", "-I../include", "-c"], "../escape") == "."


def test_a_run_without_an_accepted_language_build_is_a_named_gap_but_a_broken_one_is_an_integrity_failure(tmp_path) -> None:
    def missing(_root):
        raise ValueError("accepted job_language_build handoff is required")

    def broken(_root):
        raise ValueError("accepted language-build artifact identity changed")

    located = AcceptedBuilds(tmp_path, loader=missing).locate("src/packet.cpp")
    assert located.unit is None and located.code == "no_native_build" and "no accepted language build" in located.reason
    with pytest.raises(IntegrityError, match="cannot be verified"):
        AcceptedBuilds(tmp_path, loader=broken).locate("src/packet.cpp")
    assert AcceptedBuilds(tmp_path, loader=missing).locate("README.md").code == "not_c_family"
