"""Operator procedures stay canonical, non-executing and truthful about public tooling."""
from __future__ import annotations

import argparse
from dataclasses import fields
import importlib.util
from pathlib import Path
import re
import shlex
import subprocess
import tomllib

import pytest

from appsec_review.config.assurance import ComponentReleases
from appsec_review.guidance import GuidanceError, load_registry, load_runtime_skill
from appsec_review.guidance.skills import (
    DEVELOPMENT_AUDIENCE,
    DEVELOPMENT_POINTER_DIRECTORY,
    DEVELOPMENT_POINTER_SKILL,
    DEVELOPMENT_SKILLS_DIRECTORY,
    RUNTIME_SKILLS_DIRECTORY,
    front_matter,
    runtime_skill_records,
)
from appsec_review.runtime.job import Job


ROOT = Path(__file__).resolve().parents[1]
SKILLS = (
    "run-triage-and-repair",
    "add-a-job-contract",
    "add-runtime-guidance",
    "codeql-release-recompile",
)
DEVELOPMENT = ROOT / DEVELOPMENT_SKILLS_DIRECTORY
COMMAND_COUNTS = dict(zip(SKILLS, (3, 1, 2, 2), strict=True))
NONEXECUTION_NOTICES = {
    "run-triage-and-repair": "Do not execute the manual command examples just because this skill is loaded.",
    "add-a-job-contract": "Manual examples below describe capabilities, not actions to execute on load.",
    "add-runtime-guidance": "Do not execute manual examples just because this skill is loaded.",
    "codeql-release-recompile": "The manual commands below are not executed automatically when this skill is loaded.",
}


def _path(name: str) -> Path:
    return DEVELOPMENT / name / "SKILL.md"


def _text(name: str) -> str:
    return _path(name).read_text(encoding="utf-8")


def _commands(name: str) -> list[list[str]]:
    blocks = re.findall(r"```text\n(.*?)\n```", _text(name), flags=re.S)
    return [shlex.split(line) for block in blocks for line in block.splitlines() if line.strip()]


def _links(name: str) -> list[str]:
    return re.findall(r"\[[^\]]+\]\(([^)]+)\)", _text(name))


@pytest.mark.parametrize("name", SKILLS)
def test_new_skills_have_closed_repository_agent_frontmatter_and_lf_bytes(name: str) -> None:
    path = _path(name)
    assert path.is_file() and not path.is_symlink() and not path.parent.is_symlink()
    raw = path.read_bytes()
    assert raw.startswith(b"---\n") and b"\r" not in raw and raw.endswith(b"\n")
    values = front_matter(raw.decode("utf-8"))
    assert set(values) == {"name", "description", "audience"}
    assert values["name"] == name and values["audience"] == DEVELOPMENT_AUDIENCE
    assert "Use " in values["description"]
    assert sorted(p.relative_to(path.parent).as_posix() for p in path.parent.rglob("*")) == ["SKILL.md"]


def test_only_the_unchanged_pointer_is_available_to_shared_agent_discovery() -> None:
    pointer = ROOT / DEVELOPMENT_POINTER_DIRECTORY
    assert sorted(path.name for path in pointer.iterdir()) == [DEVELOPMENT_POINTER_SKILL]
    assert sorted(path.relative_to(pointer).as_posix() for path in pointer.rglob("*") if path.is_file()) == [
        f"{DEVELOPMENT_POINTER_SKILL}/SKILL.md",
    ]
    text = (pointer / DEVELOPMENT_POINTER_SKILL / "SKILL.md").read_text(encoding="utf-8")
    assert front_matter(text)["audience"] == DEVELOPMENT_AUDIENCE
    assert DEVELOPMENT_SKILLS_DIRECTORY in text and "AGENTS.md" in text
    assert len(text) < 2000
    assert all(name not in text for name in SKILLS)
    for location in (".github/skills", ".gemini/skills", ".codex/skills", ".cursor/skills", "skills"):
        assert not (ROOT / location).exists(), f"duplicate skill discovery location: {location}"


@pytest.mark.parametrize("name", SKILLS)
def test_development_skills_cannot_be_registered_or_loaded_for_workers(name: str) -> None:
    records = runtime_skill_records(load_registry(ROOT))
    assert name not in records
    assert not (ROOT / RUNTIME_SKILLS_DIRECTORY / name).exists()
    assert RUNTIME_SKILLS_DIRECTORY not in _text(name)
    assert not any(runtime_name in _text(name) for runtime_name in records)
    with pytest.raises(GuidanceError, match="not registered"):
        load_runtime_skill(ROOT, name, job_id="job_codeql_analysis", fallback_to_package=False)


def test_pipeline_never_references_the_operator_skill_set() -> None:
    forbidden = (*SKILLS, DEVELOPMENT_SKILLS_DIRECTORY, DEVELOPMENT_POINTER_DIRECTORY)
    for path in (ROOT / "pipeline").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert not any(value in text for value in forbidden), path.relative_to(ROOT)
            assert f"audience: {DEVELOPMENT_AUDIENCE}" not in text, path.relative_to(ROOT)


@pytest.mark.parametrize("name", SKILLS)
def test_skills_link_existing_ownership_docs_and_tooling_without_copies(name: str) -> None:
    links = _links(name)
    assert "../../../AGENTS.md" in links
    assert "../multi-session-coordination/SKILL.md" in links
    assert "../docs-sync/SKILL.md" in links
    for link in links:
        assert "://" not in link, f"tooling references must resolve in the checkout: {link}"
        target = (_path(name).parent / link.split("#", 1)[0]).resolve()
        assert target.is_relative_to(ROOT.resolve()) and target.is_file(), (name, link)
    assert _text(name) != (DEVELOPMENT / "multi-session-coordination" / "SKILL.md").read_text()
    assert _text(name) != (DEVELOPMENT / "docs-sync" / "SKILL.md").read_text()


@pytest.mark.parametrize("name", SKILLS)
def test_each_procedure_has_explicit_authorization_and_truthful_handoff(name: str) -> None:
    text = " ".join(_text(name).split())
    for required in (
        "## Authorization and reuse",
        "Integration tests, acceptance tests and live operations require an explicit user request",
        "never automatic repair, merge or completion gates",
        "## Current limitations",
        "## Verification and handoff",
        "**NOT RUN**",
        "test/tmp/",
        "elapsed time",
    ):
        assert required in text, (name, required)
    assert "worker authority" in text
    assert NONEXECUTION_NOTICES[name] in text


def _builder():
    spec = importlib.util.spec_from_file_location("operator_skill_builder", ROOT / "containers" / "build.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _ParsedEvaluation(Exception):
    def __init__(self, arguments: argparse.Namespace):
        self.arguments = arguments


def _evaluation_arguments(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> argparse.Namespace:
    from appsec_review.review import evaluation

    original = argparse.ArgumentParser.parse_args

    def parse_only(parser, args=None, namespace=None):
        # The evaluation parser is inside main; stop before it reads cases or dispatches models.
        raise _ParsedEvaluation(original(parser, args, namespace))

    with monkeypatch.context() as patch:
        patch.setattr(argparse.ArgumentParser, "parse_args", parse_only)
        with pytest.raises(_ParsedEvaluation) as parsed:
            evaluation.main(argv)
    return parsed.value.arguments


@pytest.mark.parametrize("name", SKILLS)
def test_every_documented_command_template_matches_a_real_parser_without_dispatch(
    name: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from appsec_review.cli import parser

    def forbidden(*args, **kwargs):
        pytest.fail("a documentation parser check must not launch a command")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    commands = _commands(name)
    assert len(commands) == COMMAND_COUNTS[name]
    for argv in commands:
        if argv[0] == "appsec-review":
            parsed = parser().parse_args(argv[1:])
            assert parsed.config == "appsec-review.toml"
            assert parsed.run_id == "RUN_ID"
            assert parsed.command in {"logs", "plan-resume", "resume", "run"}
            if parsed.command != "logs":
                assert parsed.target == Path("TARGET_PATH")
            if parsed.command in {"plan-resume", "resume"}:
                assert parsed.force_from == "job_language_build"
            if parsed.command == "run":
                assert parsed.job_id == "job_language_build" and parsed.upstream_from_run
        elif argv[:2] == ["bash", "scripts/compile-codeql-queries.sh"]:
            parsed = _builder().parser().parse_args(["query-packs", "--warm", *argv[2:]])
            assert parsed.warm and parsed.language == ["go"] and not parsed.allow_concurrent
            if not parsed.dry_run:
                assert parsed.ids == ["graph-export-go"]
                assert (parsed.ram, parsed.threads) == (7000, 8)
        else:
            assert argv[:3] == ["python", "-m", "appsec_review.review.evaluation"]
            parsed = _evaluation_arguments(monkeypatch, argv[3:])
            if parsed.responses:
                assert parsed.responses == Path("REPORT_PATH") and not parsed.live
            else:
                assert parsed.live and parsed.output == Path("runs/NEW_EVALUATION")
                assert (parsed.profile, parsed.role, parsed.variant) == (
                    "dev", "independent_verifier", "paired",
                )


@pytest.mark.parametrize("command", ("plan-resume", "resume"))
@pytest.mark.parametrize("arguments", ([], ["--run-id", "RUN_ID"], ["--target", "TARGET_PATH"],
                                      ["--run-id", "RUN_ID", "--target", "TARGET_PATH", "--system", "SYSTEM_ID"]))
def test_documented_recovery_requires_an_explicit_run_and_exactly_one_target(
    command: str, arguments: list[str],
) -> None:
    from appsec_review.cli import parser

    with pytest.raises(SystemExit) as error:
        parser().parse_args([command, *arguments])
    assert error.value.code == 2


def test_repair_instructions_name_actual_cli_limits_and_release_identity_behavior() -> None:
    from appsec_review.cli import parser

    commands = next(action.choices for action in parser()._actions if isinstance(action, argparse._SubParsersAction))
    assert not {"restart", "repair", "validate-job"} & commands.keys()
    assert {"build-failure-context", "replay-build-recipe", "promote-build-recipe"} <= commands.keys()
    log_options = {option for action in commands["logs"]._actions for option in action.option_strings}
    assert not {"--limit", "--cursor", "--max-bytes"} & log_options
    text = " ".join(_text("run-triage-and-repair").split())
    assert "does not paginate or provide a byte limit" in text
    assert "RESUME_PLANNED" in text and "not a mutation-free read" in text
    assert "RESUME_PLANNED" in (ROOT / "src/appsec_review/runtime/resume.py").read_text()
    job = Job("job_skill_probe", "skill_probe", lambda context: {}, implementation_identity="edited-source")
    assert job.identities(ROOT)["implementation"] == "undeclared"
    releases = ComponentReleases({"platform": "platform-v2", "validation": "validation-v3",
                                  "job_skill_probe": "job-v4"})
    assert job.identities(ROOT, releases) == {
        "implementation": "job-v4", "schema": "appsec-review/job-result/1", "validation": "validation-v3",
    }
    assert "does not fingerprint edited Python source" in text


def test_job_checklist_covers_real_contract_fields_and_missing_output_semantics() -> None:
    from appsec_review.runtime.datasets import DatasetDeclaration, DISPOSITIONS

    text = _text("add-a-job-contract")
    for item in ("Responsibility and lifecycle", "Typed configuration", "Registry and topology",
                 "Accepted inputs", "Output datasets", "Validation and publication",
                 "Reuse and provenance", "Consumer usability", "Tests and documentation"):
        assert f"- [ ] **{item}.**" in text
    assert {"datasets", "consumes", "input_validators", "output_validators",
            "input_identity", "run_input_identity"} <= {field.name for field in fields(Job)}
    assert {"output_kind", "step", "family", "schema", "sensitivity", "disposition",
            "artifacts", "indexes", "query_route", "required", "reason"} <= {
                field.name for field in fields(DatasetDeclaration)
            }
    assert set(DISPOSITIONS) == {"indexed", "artifact_only", "protected", "unavailable"}
    for disposition in DISPOSITIONS:
        assert f"`{disposition}`" in text
    with pytest.raises(ValueError, match="declared disposition"):
        DatasetDeclaration("probe", "publish", "source", "probe/1", "internal",
                           "unavailable", "Missing output is an audit result")


def test_guidance_checklist_names_real_bundle_operations_and_runtime_boundaries() -> None:
    from appsec_review.guidance import compose

    text = _text("add-runtime-guidance")
    for operation in ("compose_bundle", "verify_bundle", "render_prompt", "pin_bundle"):
        assert callable(getattr(compose, operation)) and operation in text
    for item in ("Identify the missing question", "Preserve authority", "Register and select",
                 "Assemble and pin", "Keep schemas and capabilities closed",
                 "Test generated guidance", "Evaluate honestly"):
        assert f"- [ ] **{item}.**" in text
    assert {"authority", "granted_tools", "permissions", "model"} <= compose.TASK_INPUT_FORBIDDEN
    normalized = " ".join(text.split())
    assert "Retrieval remains application-mediated" in normalized
    assert "`--responses` and `--live` cannot be combined" in normalized
    assert "no retrieval tools" in normalized


def test_compile_skill_uses_existing_wrappers_and_exact_supported_source_fields() -> None:
    from appsec_review.config.codeql import CodeQLAnalysisSettings, CodeQLPreinstalledRuntime

    text = _text("codeql-release-recompile")
    shell = (ROOT / "scripts/compile-codeql-queries.sh").read_text()
    powershell = (ROOT / "scripts/compile-codeql-queries.ps1").read_text()
    assert 'exec "$python" "$OPS_ROOT/containers/build.py" query-packs --warm "$@"' in shell
    assert "compile-codeql-queries.sh" in powershell and "wsl.exe" in powershell
    assert "--dry-run" in powershell and "--language" in powershell
    settings_fields = {field.name for field in fields(CodeQLAnalysisSettings)}
    for field in ("source_image_tag", "source_image_id", "version", "commit"):
        assert field in settings_fields and f"`{field}`" in text
    for field in fields(CodeQLPreinstalledRuntime):
        assert f"`{field.name}`" in text
    normalized = " ".join(text.split())
    assert "does not independently compare that ID" in normalized
    assert "not a daemon-free unit test" in normalized
    assert "Never warm the precompiled standard query suites" in normalized
    assert "Application-supplied runners are not supported in native execution" in normalized
    registry = tomllib.loads((ROOT / "rules/registry.toml").read_text())
    packs = {pack["id"]: pack for pack in registry["packs"]}
    for argv in _commands("codeql-release-recompile"):
        parsed = _builder().parser().parse_args(["query-packs", "--warm", *argv[2:]])
        for pack_id in parsed.ids:
            pack = packs[pack_id]
            assert pack["state"] == "enabled" and pack["warm"] is True and pack["engine"] == "codeql"
    parser = _builder().parser()
    commands = next(action.choices for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    options = {option for action in commands["query-packs"]._actions for option in action.option_strings}
    assert not {"--config", "--run-id", "--image", "--verify-only"} & options
