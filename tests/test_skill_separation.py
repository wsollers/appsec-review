"""Development skills and runtime skills stay separate so job runs are never polluted."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from appsec_review.guidance import GuidanceError, load_registry, load_runtime_skill
from appsec_review.guidance.skills import (
    DEVELOPMENT_AUDIENCE, DEVELOPMENT_POINTER_DIRECTORY, DEVELOPMENT_POINTER_SKILL, DEVELOPMENT_SKILLS_DIRECTORY,
    RUNTIME_AUDIENCE, RUNTIME_SKILLS_DIRECTORY, front_matter, runtime_skill_records,
)

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / RUNTIME_SKILLS_DIRECTORY
DEVELOPMENT = ROOT / DEVELOPMENT_SKILLS_DIRECTORY
POINTER = ROOT / DEVELOPMENT_POINTER_DIRECTORY
# Skill locations other coding agents scan. They must stay empty so nothing drifts from the
# canonical set; `.agents/skills` (read by Codex, Gemini CLI, Copilot and Cursor) holds one pointer.
UNMANAGED_SKILL_LOCATIONS = (".github/skills", ".gemini/skills", ".codex/skills", ".cursor/skills", "skills")
LOADER = ROOT / "src" / "appsec_review" / "guidance" / "skills.py"


def _skills(root: Path) -> dict[str, Path]:
    return {path.parent.name: path for path in sorted(root.glob("*/SKILL.md"))}


def test_no_other_skill_locations_exist() -> None:
    assert not [location for location in UNMANAGED_SKILL_LOCATIONS if (ROOT / location).exists()]


def test_shared_agent_location_holds_only_the_pointer_to_the_canonical_set() -> None:
    entries = sorted(path.name for path in POINTER.iterdir())
    assert entries == [DEVELOPMENT_POINTER_SKILL]
    files = sorted(path.relative_to(POINTER).as_posix() for path in POINTER.rglob("*") if path.is_file())
    assert files == [f"{DEVELOPMENT_POINTER_SKILL}/SKILL.md"]
    text = (POINTER / DEVELOPMENT_POINTER_SKILL / "SKILL.md").read_text(encoding="utf-8")
    values = front_matter(text)
    assert values["name"] == DEVELOPMENT_POINTER_SKILL and values["audience"] == DEVELOPMENT_AUDIENCE
    assert f"`{DEVELOPMENT_SKILLS_DIRECTORY}/`" in text and "AGENTS.md" in text
    # A pointer, not a copy: it names no individual skill, so it never needs refreshing.
    assert not [name for name in _skills(DEVELOPMENT) if name in text]
    assert len(text) < 2000
    assert DEVELOPMENT_POINTER_SKILL not in _skills(DEVELOPMENT) and DEVELOPMENT_POINTER_SKILL not in _skills(RUNTIME)


def test_runtime_skills_are_registered_runtime_worker_skills() -> None:
    records = runtime_skill_records(load_registry(ROOT))
    on_disk = _skills(RUNTIME)
    assert set(records) == set(on_disk)
    assert all(path.is_file() and not path.is_symlink() for path in on_disk.values())
    for name, path in on_disk.items():
        values = front_matter(path.read_text(encoding="utf-8"))
        assert values["name"] == name and values["audience"] == RUNTIME_AUDIENCE
    assert not [path for path in RUNTIME.rglob("*") if path.is_file() and path.name != "SKILL.md"]


def test_development_skills_are_repository_agent_only_and_never_registered() -> None:
    on_disk = _skills(DEVELOPMENT)
    assert on_disk, "the development skill location must exist"
    for name, path in on_disk.items():
        values = front_matter(path.read_text(encoding="utf-8"))
        assert values["name"] == name and values["audience"] == DEVELOPMENT_AUDIENCE
    assert not set(on_disk) & set(_skills(RUNTIME))
    assert not set(on_disk) & set(runtime_skill_records(load_registry(ROOT)))


def test_pipeline_guidance_never_carries_repository_agent_material() -> None:
    for path in (ROOT / "pipeline").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert f"audience: {DEVELOPMENT_AUDIENCE}" not in text, path
            assert DEVELOPMENT_SKILLS_DIRECTORY not in text and DEVELOPMENT_POINTER_DIRECTORY not in text, path


def _string_constants(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def test_only_the_runtime_loader_names_skill_locations_in_application_code() -> None:
    offenders = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        if path == LOADER:
            continue
        for value in _string_constants(path):
            if ".claude" in value or ".agents" in value or value == "skills" or "skills/" in value:
                offenders.append(f"{path.relative_to(ROOT)}: {value!r}")
    assert not offenders, "application code must load skills only through guidance.skills: " + "; ".join(offenders)


def test_runtime_images_never_receive_development_skills() -> None:
    dockerfile = (ROOT / "deploy" / "dagster" / "Dockerfile").read_text(encoding="utf-8")
    assert ".claude" not in dockerfile and ".agents" not in dockerfile and "COPY skills" not in dockerfile
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert ".claude" in ignored and ".agents" in ignored


def test_loader_rejects_development_unregistered_and_unauthorized_skills(tmp_path: Path) -> None:
    with pytest.raises(GuidanceError, match="not registered"):
        load_runtime_skill(ROOT, "parallel-implementation", job_id="job_project_build")
    with pytest.raises(GuidanceError, match="not allowed"):
        load_runtime_skill(ROOT, "build-image-repair", job_id="job_inference_security_review")
    skill = load_runtime_skill(ROOT, "build-image-repair", job_id="job_project_build")
    assert skill.path == f"{RUNTIME_SKILLS_DIRECTORY}/build-image-repair/SKILL.md" and len(skill.sha256) == 64


def test_loader_rejects_wrong_audience_and_symlinked_runtime_skill(tmp_path: Path) -> None:
    import shutil
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "pipeline", repo / "pipeline")
    skill = repo / RUNTIME_SKILLS_DIRECTORY / "build-image-repair" / "SKILL.md"
    skill.write_text(skill.read_text().replace(f"audience: {RUNTIME_AUDIENCE}", f"audience: {DEVELOPMENT_AUDIENCE}"))
    with pytest.raises(GuidanceError, match="audience"):
        load_runtime_skill(repo, "build-image-repair", job_id="job_project_build")
    outside = tmp_path / "outside.md"
    outside.write_text((RUNTIME / "build-image-repair" / "SKILL.md").read_text())
    skill.unlink()
    skill.symlink_to(outside)
    with pytest.raises(GuidanceError, match="symbolic link"):
        load_runtime_skill(repo, "build-image-repair", job_id="job_project_build")
