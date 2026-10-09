from __future__ import annotations

import ast
import json
from pathlib import Path
import stat

import pytest

from appsec_review import inference
from appsec_review.inference import ModelRequest, ModelResult, claude_cli, infer
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.runtime.registry import builtin_registry


SOURCE = Path(__file__).parents[1] / "src" / "appsec_review"
VALUE = {"schema": PROPOSAL_SCHEMA, "component_proposals": [], "build_recipes": []}


def _request(provider: str) -> ModelRequest:
    return ModelRequest(
        schema=PROPOSAL_SCHEMA, persona="devops", role="build engineer", guidance="bounded",
        summary={"build_units": []}, allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
        allowed_paths=(), allowed_build_units=(), provider=provider, model="claude-haiku-5-5",
        reasoning="medium", max_input_tokens=32000, max_output_tokens=8000)


def test_infer_selects_the_transport_named_on_the_request(monkeypatch) -> None:
    seen: list[tuple[str, str, int]] = []

    def transport(name: str):
        def send(request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
            seen.append((name, request.model, timeout_seconds))
            return ModelResult(VALUE)
        return send

    monkeypatch.setitem(inference.PROVIDERS, "anthropic-api", transport("api"))
    monkeypatch.setitem(inference.PROVIDERS, "claude-cli", transport("cli"))
    assert infer(_request("claude-cli"), timeout_seconds=7).proposal == VALUE
    assert infer(_request("anthropic-api"), timeout_seconds=9).proposal == VALUE
    assert seen == [("cli", "claude-haiku-5-5", 7), ("api", "claude-haiku-5-5", 9)]


def test_infer_rejects_a_provider_without_a_transport() -> None:
    with pytest.raises(ValueError, match="unsupported inference provider: openai"):
        infer(_request("openai"), timeout_seconds=5)


def test_every_configured_provider_has_a_transport() -> None:
    from appsec_review.config import load_config

    config = load_config(SOURCE.parents[1] / "appsec-review.toml")
    providers = {str(job.settings["model"]["provider"]) for job in config.jobs.values()
                 if isinstance(job.settings.get("model"), dict)}
    assert providers and providers <= set(inference.PROVIDERS)


@pytest.mark.skipif(__import__("os").name == "nt", reason="uses a POSIX executable stand-in")
def test_claude_cli_transport_grants_no_tools_and_never_uses_api_credentials(tmp_path: Path, monkeypatch) -> None:
    record = tmp_path / "invocation.json"
    binary = tmp_path / "claude"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        f"json.dump({{'argv': sys.argv[1:], 'stdin': json.load(sys.stdin),"
        f" 'key': os.environ.get('ANTHROPIC_API_KEY')}}, open({str(record)!r}, 'w'))\n"
        f"print(json.dumps({{'result': json.dumps({VALUE!r}), 'usage': {{'input_tokens': 5, 'output_tokens': 3}}}}))\n",
        encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-reach-the-subscription-cli")
    result = infer(_request("claude-cli"), timeout_seconds=30)
    assert result.proposal == VALUE and (result.input_tokens, result.output_tokens) == (5, 3)
    invocation = json.loads(record.read_text(encoding="utf-8"))
    argv = invocation["argv"]
    assert argv[argv.index("--model") + 1] == "claude-haiku-5-5"
    assert argv[argv.index("--effort") + 1] == "medium"
    assert argv[argv.index("--allowedTools") + 1] == ""
    assert invocation["key"] is None
    assert invocation["stdin"]["response_schema"] == PROPOSAL_SCHEMA
    assert claude_cli.send.__module__ == "appsec_review.inference.claude_cli"


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def test_infer_is_the_only_path_from_the_application_to_a_model() -> None:
    """Jobs depend on `infer`; only the inference package knows a provider or its endpoint."""
    transports = {"appsec_review.inference.anthropic_api", "appsec_review.inference.claude_cli"}
    endpoints = ("api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com")
    sdks = {"anthropic", "openai"}
    offenders = []
    for path in sorted(SOURCE.rglob("*.py")):
        if SOURCE / "inference" in path.parents:
            continue
        imported = _imports(path)
        text = path.read_text(encoding="utf-8")
        if imported & transports or {name.split(".")[0] for name in imported} & sdks or \
                any(endpoint in text for endpoint in endpoints) or ".complete(" in text:
            offenders.append(path.relative_to(SOURCE).as_posix())
    assert offenders == []
    # Inside the package, each provider module exposes exactly one transport function.
    for module in (inference.anthropic_api, inference.claude_cli):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        assert not [node for node in tree.body if isinstance(node, ast.ClassDef)
                    and node.name != "ModelOutputError"]
        assert callable(module.send)
    assert set(inference.PROVIDERS.values()) == {inference.anthropic_api.send, inference.claude_cli.send}


def test_registry_gives_every_model_calling_job_the_same_infer(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(inference, "infer", lambda request, *, timeout_seconds: calls.append(request.provider))
    registry = builtin_registry()
    for job_id in ("job_target_analysis_plan", "job_project_build", "job_post_build_security_assessment"):
        assert registry.build(job_id).job_id == job_id
