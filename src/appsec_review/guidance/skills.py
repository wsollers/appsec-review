"""Runtime skills: bounded guidance that configured jobs send to model workers.

Runtime skills live only under ``pipeline/skills/<name>/SKILL.md``, are registered in
``pipeline/guidance/registry.json`` under ``runtime_skills`` with the jobs allowed to load them, and
declare ``audience: runtime-worker``. Repository-development skills live under ``.claude/skills/``
with ``audience: repository-agent`` and are never readable through this module, so development
procedures cannot reach a job's prompt. ``.agents/skills/`` holds only one pointer skill that sends
other coding agents to ``.claude/skills/``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from appsec_review.application_paths import application_root

from .fragments import GuidanceError

RUNTIME_SKILLS_DIRECTORY = "pipeline/skills"
DEVELOPMENT_SKILLS_DIRECTORY = ".claude/skills"  # canonical development skills
# Entry point read by Codex, Gemini CLI, Copilot and Cursor; it only redirects to the canonical set.
DEVELOPMENT_POINTER_DIRECTORY = ".agents/skills"
DEVELOPMENT_POINTER_SKILL = "repository-development-skills"
RUNTIME_AUDIENCE = "runtime-worker"
DEVELOPMENT_AUDIENCE = "repository-agent"
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_FRONT_MATTER = re.compile(r"\A---\n(?P<body>.*?)\n---\n", re.S)
_PACKAGE_REPOSITORY = application_root("pipeline/guidance/registry.json")


@dataclass(frozen=True, slots=True)
class RuntimeSkill:
    name: str
    text: str
    sha256: str
    path: str  # repository-relative POSIX path, always under pipeline/skills

    @property
    def body(self) -> str:
        return self.text.split("---\n", 2)[-1]


def front_matter(text: str) -> dict[str, str]:
    """Closed Agent Skills front matter: ``name``, ``description`` and ``metadata.audience``.

    ``audience`` sits under the standard ``metadata`` map so tools that implement the shared Agent
    Skills format (Claude Code, Codex, Gemini CLI, Copilot) accept the file unchanged.
    """
    match = _FRONT_MATTER.match(text)
    if match is None:
        raise GuidanceError("skill front matter is missing")
    values: dict[str, str] = {}
    lines = match.group("body").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        key, separator, value = line.partition(":")
        if line.startswith(" ") or not separator or not key.strip() or key in values:
            raise GuidanceError(f"skill front matter line is invalid: {line[:80]!r}")
        if key == "metadata" and not value.strip():
            nested = []
            while index + 1 < len(lines) and lines[index + 1].startswith("  "):
                index += 1
                nested.append(lines[index])
            if len(nested) != 1 or not nested[0].startswith("  audience:"):
                raise GuidanceError("skill metadata must contain exactly audience")
            values["audience"] = nested[0].partition(":")[2].strip()
            values["metadata"] = ""
        else:
            values[key] = value.strip()
        index += 1
    values.pop("metadata", None)
    if set(values) != {"name", "description", "audience"} or not all(values.values()):
        raise GuidanceError("skill front matter must contain exactly name, description, and metadata.audience")
    return values


def runtime_skill_records(registry: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    records = registry.get("runtime_skills")
    if not isinstance(records, Mapping):
        raise GuidanceError("guidance registry has no runtime_skills table")
    result: dict[str, dict[str, Any]] = {}
    for name, record in records.items():
        if not _NAME.match(str(name)) or not isinstance(record, Mapping) or set(record) != {"path", "jobs"}:
            raise GuidanceError(f"runtime skill record is invalid: {name}")
        path = PurePosixPath(str(record["path"]))
        if path != PurePosixPath(RUNTIME_SKILLS_DIRECTORY, str(name), "SKILL.md"):
            raise GuidanceError(f"runtime skill {name} must live at {RUNTIME_SKILLS_DIRECTORY}/{name}/SKILL.md")
        jobs = record["jobs"]
        if not isinstance(jobs, list) or not jobs or not all(isinstance(job, str) for job in jobs):
            raise GuidanceError(f"runtime skill {name} must name the jobs allowed to load it")
        result[str(name)] = {"path": path.as_posix(), "jobs": tuple(jobs)}
    return result


def _resolve(root: Path, relative: str) -> Path | None:
    base = (root / RUNTIME_SKILLS_DIRECTORY).resolve()
    candidate = root / relative
    if not candidate.is_file():
        return None
    if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents if base in parent.parents
                                     or parent == base):
        raise GuidanceError(f"runtime skill path must not be a symbolic link: {relative}")
    resolved = candidate.resolve()
    if base not in resolved.parents:
        raise GuidanceError(f"runtime skill escapes {RUNTIME_SKILLS_DIRECTORY}: {relative}")
    return resolved


def load_runtime_skill(repository_root: Path, name: str, *, job_id: str,
                       fallback_to_package: bool = True) -> RuntimeSkill:
    """Load one registered runtime skill for ``job_id``; development skills are unreachable."""
    from .compose import load_registry

    roots = [Path(repository_root)]
    if fallback_to_package and Path(repository_root).resolve() != _PACKAGE_REPOSITORY:
        roots.append(_PACKAGE_REPOSITORY)
    for root in roots:
        if not (root / "pipeline" / "guidance" / "registry.json").is_file():
            continue
        records = runtime_skill_records(load_registry(root))
        record = records.get(name)
        if record is None:
            raise GuidanceError(f"runtime skill is not registered: {name}")
        if job_id not in record["jobs"]:
            raise GuidanceError(f"runtime skill {name} is not allowed for {job_id}")
        path = _resolve(root, record["path"])
        if path is None:
            continue
        text = path.read_text(encoding="utf-8")
        values = front_matter(text)
        if values["name"] != name or values["audience"] != RUNTIME_AUDIENCE:
            raise GuidanceError(f"runtime skill {name} must declare name {name} and audience {RUNTIME_AUDIENCE}")
        return RuntimeSkill(name, text, hashlib.sha256(text.encode("utf-8")).hexdigest(), record["path"])
    raise GuidanceError(f"runtime skill file is unavailable: {name}")


def select_review_procedures(*, role: str, task: str) -> tuple[str, ...]:
    """Select bounded procedures from trusted role/task IDs, never from target text."""
    if role in {"hypothesis_hunter", "red_team_analyst"}:
        return (("generative-investigation", "effective-control-verification") if task == "control_gap"
                else ("generative-investigation",))
    return {
        "blue_team_refuter": ("effective-control-verification",),
        "independent_verifier": ("predicate-verification",),
        "adjudication_judge": ("conflict-resolution",),
    }.get(role, ())
