from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor
from appsec_review.reporting.dossier_render import render_dossier
from appsec_review.reporting.dossiers import DossierLimits, build_dossier, dossier_document
from appsec_review.reporting.latex import render_latex
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json
from tests.dossier_fixture import ROOT, make_model, seed, settings


def test_origin_independent_model_is_bounded_and_deterministic(tmp_path):
    root = tmp_path / "run"
    source = seed(root)
    first = build_dossier(kind="confirmed_finding", **source)
    source["relations"].reverse()
    source["excerpts"].reverse()
    second = build_dossier(kind="confirmed_finding", **source)
    assert first == second
    assert canonical_json(first) == canonical_json(second)
    assert first["sources"][0]["path"] == "design/access-policy.md"
    assert first["visibility"] == "protected_developer"
    assert first["scores"][0]["remediation_priority"] is None
    assert first["scores"][0]["provider"] == "application_risk_matrix/3"
    assert first["poc"]["runtime_verified"] is False
    assert first["poc"]["result_id"] is None
    assert first["evidence"][0]["strength"] == "counted_direct"


def test_model_excludes_prompts_and_redacts_credentials(tmp_path):
    source = seed(tmp_path / "run")
    source["finding"]["raw_prompt"] = "PRIVATE_PROMPT_DO_NOT_COPY"
    source["poc"]["writer_receipt"] = {"prompt": "PRIVATE_MODEL_TRANSCRIPT"}
    source["poc_source"] = 'const char *password = "my-password-value";\napi_key=abcdefgh12345678901234567890'
    source["finding"]["title"] = 'Document says "literal-secret-value"'
    model = build_dossier(kind="poc", **source)
    text = canonical_json(model).decode()
    for denied in ("PRIVATE_PROMPT", "PRIVATE_MODEL_TRANSCRIPT", "my-password-value", "abcdefgh12345678901234567890",
                   "literal-secret-value"):
        assert denied not in text
    assert "redacted" in text


def test_hostile_text_is_inert_in_existing_renderer(tmp_path):
    source = seed(tmp_path / "run")
    hostile = r"\input{/etc/passwd}\write18{bad} </script> & % # _ { }" + "\x00\u202e"
    source["claim"]["statement"] = hostile
    source["poc_source"] = hostile
    model = build_dossier(kind="poc", **source)
    latex = render_latex(dossier_document(model))
    assert r"\input{/etc/passwd}" not in latex and r"\write18{bad}" not in latex
    assert r"\textbackslash{}input" in latex
    assert "\x00" not in latex and "\u202e" not in latex
    assert latex == render_latex(dossier_document(model))


@pytest.mark.parametrize("status", ["compile_verified", "compile_failed", "artifact_generated", "policy_denied",
                                   "insufficient_evidence", "not_applicable", "unsafe_to_attempt"])
def test_every_poc_status_has_truthful_nonexecution_labels(tmp_path, status):
    source = seed(tmp_path / "run")
    source["poc"]["status"] = status
    model = build_dossier(kind="poc", **source)
    latex = render_latex(dossier_document(model))
    assert "NOT RUNTIME PROOF" in model["poc"]["notice"]
    assert "never observed to pass" in model["poc"]["negative_control"]
    assert "NOT RUN" in latex
    assert "Not fixed, resolved, or regression verified." in latex
    assert model["poc"]["runtime_verified"] is False


def test_caps_missing_and_analyst_evidence_are_explicit(tmp_path):
    source = seed(tmp_path / "run")
    extra = {**source["relations"][0], "relation_id": "evrel-second"}
    source["relations"].append(extra)
    source["finding"]["analyst_assessed_evidence"] = [extra["relation_id"]]
    source["claim"]["statement"] = "x" * 200
    source["poc_source"] = "line\n" * 100
    limits = DossierLimits(text_chars=32, code_lines=2, code_chars=80, evidence_rows=1, source_excerpts=1)
    model = build_dossier(kind="poc", limits=limits, **source)
    assert len(model["evidence"]) == 1
    assert any(cut["field"] == "evidence" and cut["omitted"] == 1 for cut in model["truncations"])
    assert any(cut["field"] == "statement" for cut in model["truncations"])
    assert any(cut["field"] == "poc.source" for cut in model["truncations"])
    source["excerpts"] = []
    source["poc"] = None
    source["finding"]["missing_predicates"] = ["security_impact"]
    source["finding"]["state"] = source["claim"]["state"] = "supported"
    with pytest.raises(IntegrityError, match="confirmed"):
        build_dossier(kind="confirmed_finding", **source)
    source["poc"] = seed(tmp_path / "run")["poc"]
    model = build_dossier(kind="poc", **source)
    assert "security_impact" in model["missing_predicates"]
    assert any("source_excerpt_unavailable" in gap for gap in model["gaps"])
    assert any(row["strength"] == "analyst_assessed_not_counted" for row in model["evidence"])


def test_model_rejects_runtime_or_missing_citations(tmp_path):
    source = seed(tmp_path / "run")
    source["poc"]["runtime_verified"] = True
    with pytest.raises(IntegrityError, match="runtime"):
        build_dossier(kind="poc", **source)
    source["poc"]["runtime_verified"] = False
    source["relations"] = []
    with pytest.raises(IntegrityError, match="relations absent"):
        build_dossier(kind="poc", **source)


def executor_factory(argv_seen, *, render_status=1, pdf=None, timed_out=False, wrong_image=False):
    class FixtureExecutor(ContainerExecutor):
        def _docker_bind_source(self, path):
            return path

    def factory(catalog, root):
        def runner(argv, timeout):
            argv_seen.append(tuple(argv))
            if argv[1:3] == ("image", "inspect"):
                identity = "sha256:" + "0" * 64 if wrong_image else settings().image_id
                return CommandOutcome(0, identity.encode(), b"")
            if "run" in argv and pdf is not None:
                mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
                mount = next(spec for spec in mounts if "dst=/scratch" in spec)
                scratch = Path(mount.split("src=", 1)[1].split(",dst=")[0])
                (scratch / "report.pdf").write_bytes(pdf)
            return CommandOutcome(render_status, b"renderer output", b"renderer diagnostic", timed_out=timed_out)
        return FixtureExecutor(catalog, root, runner=runner)
    return factory


def test_container_policy_argv_and_failed_render_retention(tmp_path):
    root = tmp_path / "run"
    model = make_model(root)
    seen = []
    result = render_dossier(root, root / "data" / "a", model, settings=settings(), repository_root=ROOT,
                            executor_factory=executor_factory(seen, render_status=1))
    assert result["status"] == "render_failed" and result["files"]["pdf"] is None
    for key in ("json", "latex", "receipt"):
        assert (root / result["files"][key]["path"]).is_file()
    command = next(argv for argv in seen if "run" in argv)
    for option, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
                          ("--memory", "1g"), ("--cpus", "2"), ("--pids-limit", "256"),
                          ("--entrypoint", "/opt/tool/bin/render-pdf")):
        assert command[command.index(option) + 1] == value
    assert "--read-only" in command
    assert settings().image_id in command
    assert "--ulimit" in command
    assert "--privileged" not in command and "sh" not in command and "bash" not in command
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--mount"]
    assert all(",readonly" in item for item in mounts if "dst=/scratch" not in item)
    assert not (root / "data" / "a" / "scratch").exists()
    receipt = json.loads((root / result["files"]["receipt"]["path"]).read_text())
    assert receipt["execution"] is not None
    assert receipt["template"]["sha256"]
    assert receipt["tool"]["image_id"] == settings().image_id
    assert receipt["files"]["latex"]["sha256"] == result["files"]["latex"]["sha256"]


def test_injected_executor_is_independent_of_host_container_mounts(tmp_path, monkeypatch):
    monkeypatch.setenv("HOSTNAME", "fixture-code-location")
    monkeypatch.setattr(ContainerExecutor, "_docker_bind_source",
                        lambda *args: pytest.fail("a fake runner must not inspect host container mounts"))
    root = tmp_path / "run"
    seen = []
    result = render_dossier(root, root / "data" / "a", make_model(root), settings=settings(),
                            repository_root=ROOT, executor_factory=executor_factory(
                                seen, render_status=0, pdf=b"%PDF-1.5\n" + b"fixture " * 8 + b"\n%%EOF\n"))
    assert result["status"] == "rendered"
    assert any("run" in argv for argv in seen)


@pytest.mark.parametrize("pdf", [b"", b"not a pdf", b"%PDF-1.7\n" + b"x" * 40])
def test_empty_or_invalid_pdf_never_succeeds(tmp_path, pdf):
    root = tmp_path / "run"
    result = render_dossier(root, root / "data" / "a", make_model(root), settings=settings(),
                            repository_root=ROOT, executor_factory=executor_factory([], render_status=0, pdf=pdf))
    assert result["status"] == "render_failed" and result["files"]["pdf"] is None


def test_latex_only_policy_retry_preserves_prior_artifacts_and_pin_mismatch_fails(tmp_path):
    root = tmp_path / "run"
    model = make_model(root)
    before = render_dossier(root, root / "data" / "a", model, settings=settings(render_pdf=False), repository_root=ROOT)
    assert before["status"] == "latex_only"
    first = (root / before["files"]["latex"]["path"]).read_bytes()
    render_dossier(root, root / "data" / "b", model, settings=settings(render_pdf=False), repository_root=ROOT)
    assert first == (root / before["files"]["latex"]["path"]).read_bytes()
    with pytest.raises(IntegrityError, match="new"):
        render_dossier(root, root / "data" / "a", model, settings=settings(), repository_root=ROOT)
    with pytest.raises(IntegrityError, match="image integrity"):
        render_dossier(root, root / "data" / "c", model, settings=settings(), repository_root=ROOT,
                        executor_factory=executor_factory([], wrong_image=True))


@pytest.mark.parametrize("key,value", [("max_dossiers", 0), ("max_packages", True), ("max_code_lines", 201),
                                      ("image_id", "latest"), ("render_pdf", "true")])
def test_typed_settings_reject_invalid_bounds(key, value):
    with pytest.raises(ValueError):
        settings(**{key: value})
