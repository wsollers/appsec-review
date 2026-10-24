"""Pinned, role-selected procedures and evidence-conditioned specialist knowledge."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from appsec_review.guidance import GuidanceError, load_registry, load_runtime_skill, render_prompt, verify_bundle
from appsec_review.guidance.compose import bundle_sha256, section_sha256
from appsec_review.guidance.skills import select_review_procedures
from appsec_review.owasp_workbench.guidance import compose as workbench_compose
from appsec_review.review.models import IntegrityError
from tests.test_guidance_compose import ROOT, _compose, repo, taxonomy


def _section(bundle, name):
    return next(section for section in bundle["sections"] if section["name"] == name)


@pytest.mark.parametrize(("role", "task", "expected"), [
    ("hypothesis_hunter", "sink_up", ["generative-investigation"]),
    ("hypothesis_hunter", "control_gap", ["generative-investigation", "effective-control-verification"]),
    ("red_team_analyst", "lead_red_stack", ["generative-investigation"]),
    ("blue_team_refuter", "blue_control", ["effective-control-verification"]),
    ("blue_team_refuter", "blue_reachability", ["effective-control-verification"]),
    ("independent_verifier", "blind_verifier", ["predicate-verification"]),
    ("adjudication_judge", "adjudicate_claim", ["conflict-resolution"]),
])
def test_role_task_selects_exact_bounded_procedures(repo, taxonomy, role, task, expected):
    bundle = _compose(repo, taxonomy, role=role, task=task, capability={"granted_tools": []})
    assert bundle["schema"] == "appsec-review/guidance-bundle/3"
    items = _section(bundle, "procedures")["items"]
    assert [item["id"] for item in items] == expected
    for item in items:
        skill = load_runtime_skill(repo, item["id"], job_id="job_inference_security_review")
        assert item == {"id": skill.name, "path": skill.path, "text": skill.text, "source_sha256": skill.sha256}
        assert len(skill.text) <= 2400
    assert len(render_prompt(bundle)) <= 26000
    assert _section(bundle, "receipt")["capability"] == {"granted_tools": []}
    assert select_review_procedures(role="poc_designer", task="sink_up") == ()
    assert verify_bundle(bundle) == bundle["sha256"]


def test_every_registered_review_task_has_bounded_real_rendered_guidance(taxonomy):
    registry = load_registry(ROOT)
    from appsec_review.guidance.compose import load_task

    for task_id in registry["tasks"]["inference-security-review"]:
        task = load_task(ROOT, registry, task_id=task_id)
        for role in task.roles:
            bundle = _compose(ROOT, taxonomy, role=role, task=task_id, capability={"granted_tools": []})
            prompt = render_prompt(bundle)
            assert len(prompt) <= 32000, (role, task_id, len(prompt))
            assert len(_section(bundle, "procedures")["items"]) <= 2


def test_only_selected_skill_changes_bundle_identity(repo, taxonomy):
    first = _compose(repo, taxonomy)
    selected = repo / "pipeline" / "skills" / "generative-investigation" / "SKILL.md"
    selected.write_text(selected.read_text(encoding="utf-8") + "\nCompare the same object at use time.\n",
                        encoding="utf-8")
    changed = _compose(repo, taxonomy)
    assert first["sha256"] != changed["sha256"]
    assert {name for name, sha in first["section_sha256"].items()
            if sha != changed["section_sha256"][name]} == {"procedures"}
    unselected = repo / "pipeline" / "skills" / "conflict-resolution" / "SKILL.md"
    unselected.write_text(unselected.read_text(encoding="utf-8") + "\nCompare versions.\n", encoding="utf-8")
    assert _compose(repo, taxonomy) == changed


def test_selected_skill_source_hash_is_verified_even_if_outer_hashes_are_resealed(repo, taxonomy):
    bundle = _compose(repo, taxonomy)
    procedures = _section(bundle, "procedures")
    procedures["items"][0]["text"] += "\nChanged after selection."
    procedures["sha256"] = section_sha256(procedures)
    bundle["section_sha256"]["procedures"] = procedures["sha256"]
    bundle["sha256"] = bundle_sha256(bundle)
    with pytest.raises(IntegrityError, match="procedure source hash"):
        verify_bundle(bundle)


def test_old_bundle_verification_rendering_and_pinning_still_work(repo, taxonomy, tmp_path):
    from appsec_review.guidance import pin_bundle

    bundle = _compose(repo, taxonomy)
    legacy = deepcopy(bundle)
    legacy["schema"] = "appsec-review/guidance-bundle/2"
    legacy["sections"] = [section for section in legacy["sections"] if section["name"] != "procedures"]
    legacy["section_sha256"].pop("procedures")
    legacy["sha256"] = bundle_sha256(legacy)
    assert verify_bundle(legacy) == legacy["sha256"]
    assert "<<<procedures" not in render_prompt(legacy)
    pinned = pin_bundle(tmp_path / "run", legacy)
    assert json.loads((tmp_path / "run" / pinned["path"]).read_text(encoding="utf-8")) == legacy
    old_workbench = {"schema": "appsec-review/guidance-bundle/1", "role": {"id": "control_assessor"}}
    old_workbench["sha256"] = bundle_sha256(old_workbench)
    assert verify_bundle(old_workbench) == old_workbench["sha256"]


@pytest.mark.parametrize("mutation", ["missing", "unauthorized", "tool", "budget", "policy", "new_policy"])
def test_composer_fails_closed_for_invalid_procedure(repo, taxonomy, mutation):
    path = repo / "pipeline" / "skills" / "generative-investigation" / "SKILL.md"
    if mutation == "missing":
        path.unlink()
    elif mutation == "unauthorized":
        registry_path = repo / "pipeline" / "guidance" / "registry.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        registry["runtime_skills"]["generative-investigation"]["jobs"] = ["job_project_build"]
        registry_path.write_text(json.dumps(registry), encoding="utf-8")
    else:
        addition = {"tool": "\nCall `read_excerpt`.", "budget": "\nUse a token budget of 20.",
                    "policy": "\npackage_id: new-scope", "new_policy": "\ntimeout_seconds: 99"}[mutation]
        path.write_text(path.read_text(encoding="utf-8") + addition, encoding="utf-8")
    with pytest.raises(GuidanceError):
        _compose(repo, taxonomy)


def test_loader_rejects_selected_link_before_reading_content(repo, monkeypatch):
    path = repo / "pipeline" / "skills" / "generative-investigation" / "SKILL.md"
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == path or original(self))
    with pytest.raises(GuidanceError, match="symbolic link"):
        load_runtime_skill(repo, "generative-investigation", job_id="job_inference_security_review")


@pytest.mark.parametrize(("role", "expected"), [
    ("component_classifier", []),
    ("applicability_router", ["effective-control-verification"]),
    ("evidence_verifier", ["predicate-verification"]),
    ("independent_reviewer", ["predicate-verification"]),
    ("result_adjudicator", ["conflict-resolution"]),
])
def test_workbench_selects_role_appropriate_procedure_without_changing_responsibility(repo, role, expected):
    task = {"task_id": "t", "question": "Assess the assigned control.", "proof_obligations": [],
            "prohibited_claims": []}
    bundle = workbench_compose(repo, role=role, persona=None, task=task)
    assert bundle["persona"] is None
    assert bundle["role"] == {"id": role, "text": load_registry(repo)["roles"][role]["responsibility"]}
    assert [item["id"] for item in bundle["procedures"]] == expected
    if expected:
        bundle["procedures"][0]["source_sha256"] = "0" * 64
        bundle["sha256"] = bundle_sha256(bundle)
        with pytest.raises(IntegrityError, match="procedure source hash"):
            verify_bundle(bundle)


def test_hand_offs_are_visible_but_not_delegation(repo, taxonomy):
    for role, task in [("hypothesis_hunter", "sink_up"), ("blue_team_refuter", "blue_control")]:
        bundle = _compose(repo, taxonomy, role=role, task=task, capability={"granted_tools": []})
        assert "Hand-offs" in [part["heading"] for part in _section(bundle, "persona")["sections"]]
        assert "no worker delegates" in _section(bundle, "governing_rules")["text"]
        assert "never a blanket exemption" in render_prompt(bundle)


@pytest.mark.parametrize(("persona", "source_id"), [
    ("api_web", "network_api_surface"), ("deployment_operations", "cloud_container_deployment"),
    ("authentication_session", "authentication_session"),
])
def test_workbench_reuses_pinned_specialist_knowledge_with_closed_task(repo, persona, source_id):
    task = {"task_id": "t", "question": "Assess the assigned control.", "proof_obligations": [],
            "prohibited_claims": []}
    bundle = workbench_compose(repo, role="control_assessor", persona=persona, task=task)
    assert bundle["persona"]["id"] == persona
    assert bundle["persona"]["source_id"] == source_id
    assert "## Effective controls" in bundle["persona"]["text"]
    assert "## Hand-offs" in bundle["persona"]["text"]
    assert [item["id"] for item in bundle["procedures"]] == ["effective-control-verification"]
    assert len(json.dumps(bundle)) < 13000
    assert verify_bundle(bundle) == bundle["sha256"]
    source = repo / bundle["persona"]["path"]
    source.write_text(source.read_text(encoding="utf-8").replace("## Viewpoint\n", "## Viewpoint\nA bounded lens.\n"),
                      encoding="utf-8")
    changed = workbench_compose(repo, role="control_assessor", persona=persona, task=task)
    assert changed["persona"]["source_sha256"] != bundle["persona"]["source_sha256"]
    assert changed["sha256"] != bundle["sha256"]
    with pytest.raises(ValueError, match="bounded question contract"):
        workbench_compose(repo, role="control_assessor", persona=persona, task={**task, "tools": ["find"]})


def test_technical_guidance_is_conditioned_on_exact_mechanism_and_version():
    fragments = ROOT / "pipeline" / "prompt-fragments"
    parser = (fragments / "personas" / "parsing_deserialization.md").read_text(encoding="utf-8")
    assert "`SerializationBinder` does not make `BinaryFormatter` safe" in parser
    python = (fragments / "stacks" / "python_service.md").read_text(encoding="utf-8")
    assert "introduced in Python 3.12" in python and "default became `data` in 3.14" in python
    assert "ZIP extraction is separate" in python and "default\n  permission policy is `AllowAny`" in python
    ci = (fragments / "personas" / "ci_cd_pipeline.md").read_text(encoding="utf-8")
    assert "inheriting write-all" not in ci and "inherits repository or organization defaults" in ci
    assert "a tag pin is not a SHA pin" in ci
    dotnet = (fragments / "roles" / "build-engineer-dotnet.md").read_text(encoding="utf-8")
    assert "project-image preparation, not configure/build command egress" in dotnet
    assert "does not alone prove an image-preparation download" in dotnet


def test_postbuild_guidance_requires_a_complete_family_specific_evidence_chain():
    text = load_runtime_skill(ROOT, "post-build-security-assessment",
                              job_id="job_post_build_security_assessment").text
    for phrase in ("Requested setting", "Observed compile/link", "Actual artifact",
                   "Supported consequence or gap", "Native ELF", "Native PE", "Mach-O",
                   "Managed .NET/JVM", "Go/Rust", "WebAssembly", "never proof of attacker reachability"):
        assert phrase in text
    assert len(text) < 4200


def test_inference_tasks_request_cell_local_citations_not_raw_identities():
    directory = ROOT / "pipeline" / "guidance" / "tasks" / "inference-security-review"
    for path in directory.glob("*.md"):
        text = path.read_text(encoding="utf-8")
        assert "resolvable identities" not in text and "resolvable identity" not in text, path
    assert len(load_runtime_skill(ROOT, "poc-writer", job_id="job_poc_generation").text) < 12500
