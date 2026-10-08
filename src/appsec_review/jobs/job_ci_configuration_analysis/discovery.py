from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath
from typing import Any


PROVIDERS = ("github", "azure", "gitlab", "circleci", "bitbucket", "jenkins", "teamcity", "other")


def classify(path_value: str) -> str | None:
    """Classify only cataloged, target-relative paths; never inspect or execute content."""
    path = PurePosixPath(path_value)
    name = path.name.lower()
    parts = tuple(part.lower() for part in path.parts)
    suffix = path.suffix.lower()
    yaml = suffix in {".yml", ".yaml"}
    if yaml and len(parts) >= 3 and parts[0:2] == (".github", "workflows"):
        return "github"
    if yaml and len(parts) >= 3 and parts[0:2] == (".github", "actions") and name in {"action.yml", "action.yaml"}:
        return "github"
    if yaml and (name in {"azure-pipelines.yml", "azure-pipelines.yaml"} or parts[0] == ".azure-pipelines"):
        return "azure"
    if yaml and (name in {".gitlab-ci.yml", ".gitlab-ci.yaml"} or parts[0:2] == (".gitlab", "ci")):
        return "gitlab"
    if yaml and tuple(parts) == (".circleci", "config.yml"):
        return "circleci"
    if yaml and name in {"bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"}:
        return "bitbucket"
    if path.name == "Jenkinsfile" or path.name.startswith("Jenkinsfile."):
        return "jenkins"
    if suffix == ".kts" and (parts[0] == ".teamcity" or name == "settings.kts"):
        return "teamcity"
    if yaml and (name in {".travis.yml", "appveyor.yml", "appveyor.yaml", ".drone.yml", ".drone.yaml"}
                 or parts[0] == ".buildkite"):
        return "other"
    return None


def discover(files: Iterable[Mapping[str, Any]], *, max_files: int) -> tuple[list[dict[str, Any]], list[str]]:
    found: list[dict[str, Any]] = []
    gaps: list[str] = []
    for item in files:
        provider = classify(str(item["path"]))
        if provider is None:
            continue
        if len(found) >= max_files:
            gaps.append(f"CI definition discovery stopped at configured max_files={max_files}")
            break
        found.append({
            "definition_id": f"ci:{provider}:{item['path']}", "provider": provider,
            "path": str(item["path"]), "sha256": str(item["sha256"]),
            "size_bytes": int(item.get("size_bytes", 0)),
        })
    return sorted(found, key=lambda value: (value["provider"], value["path"])), gaps
