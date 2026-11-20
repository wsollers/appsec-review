"""Bounded accepted catalog reads shared by environment analysis and planning."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from typing import Any


def read_artifact(run_root: Path, identity: Mapping[str, Any], *,
                  byte_limit: int = 16 * 1024 * 1024) -> Mapping[str, Any]:
    """Read a hash-bound catalog or planning document within its supported byte ceiling."""
    from appsec_review.storage.shared import safe_path
    if byte_limit not in {16 * 1024 * 1024, 32 * 1024 * 1024}:
        raise ValueError("unsupported accepted-artifact byte limit")
    path = safe_path(run_root, str(identity.get("path", "")))
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    size = path.stat().st_size
    if size > byte_limit:
        raise ValueError("accepted upstream artifact exceeds its byte bound")
    data = path.read_bytes()
    if (len(data) != size or len(data) > byte_limit or identity.get("size_bytes", size) != size
            or hashlib.sha256(data).hexdigest() != identity.get("sha256")):
        raise ValueError("accepted upstream artifact identity changed")
    value = json.loads(data)
    if not isinstance(value, Mapping):
        raise ValueError("accepted upstream artifact must be a JSON object")
    return value


def load_accepted_catalog(run_root: Path) -> dict[str, Any]:
    """Resolve the admitted catalog pin and validate its bounded documents without widening grants."""
    from appsec_review.storage.shared import safe_path
    from appsec_review.runtime.consume import accepted_upstream
    accepted = accepted_upstream(run_root, "job_target_catalog")
    if safe_path(run_root, accepted.path).stat().st_size > 32 * 1024 * 1024:
        raise ValueError("accepted catalog handoff exceeds its byte bound")
    handoff = accepted.handoff
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    catalog = read_artifact(run_root, published.get("artifact", {}), byte_limit=32 * 1024 * 1024)
    if catalog.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("target catalog schema is unsupported")
    if catalog.get("source_fingerprint") != handoff["source_fingerprint"]:
        raise ValueError("accepted catalog and handoff source identities differ")
    artifacts = catalog.get("artifacts", {})
    partition = read_artifact(run_root, artifacts["repository_discovery.partition_repository"],
                              byte_limit=32 * 1024 * 1024)
    projects = read_artifact(run_root, artifacts["repository_discovery.discover_projects"])
    components = read_artifact(run_root, artifacts["component_discovery.catalog_components"])
    builds = read_artifact(run_root, artifacts["build_discovery.discover_build_systems"])
    compile_databases = read_artifact(run_root, artifacts["build_discovery.discover_compile_commands"])
    targets = read_artifact(run_root, artifacts["build_discovery.catalog_build_targets"])
    expected_schemas = (
        (partition, "repository-partition/1"), (projects, "project-catalog/1"),
        (components, "component-catalog/1"), (builds, "build-systems/4"),
        (compile_databases, "compile-commands/1"), (targets, "build-targets/2"),
    )
    if any(value.get("schema") != "appsec-review/" + schema for value, schema in expected_schemas):
        raise ValueError("accepted catalog child artifact schema is unsupported")
    if partition.get("source_fingerprint") != catalog["source_fingerprint"]:
        raise ValueError("accepted catalog partition source identity differs")
    recognized_names = {
        "CMakeLists.txt", "Makefile", "configure.ac", "configure.in", "Makefile.am", "meson.build",
        "BUILD", "WORKSPACE", "MODULE.bazel", "pom.xml", "build.gradle", "build.gradle.kts",
        "package.json", "tsconfig.json", "Cargo.toml", "go.mod", "pyproject.toml", "Dockerfile",
    }
    files = tuple(partition.get("files", ()))
    extra_builds = [item for item in files if Path(str(item["path"])).name in recognized_names or
                    Path(str(item["path"])).suffix.lower() in {".csproj", ".sln", ".vcxproj"}]
    by_path = {str(item["path"]): item for item in (*builds.get("systems", ()), *extra_builds)}
    gaps = [*partition.get("gaps", ()), *projects.get("gaps", ()), *components.get("gaps", ()),
            *builds.get("gaps", ()), *compile_databases.get("gaps", ()), *targets.get("gaps", ())]
    return {
        "source_fingerprint": catalog["source_fingerprint"],
        "catalog_handoff_sha256": accepted.sha256,
        "files": files, "projects": tuple(projects.get("projects", ())),
        "components": tuple(components.get("components", ())),
        "build_files": tuple(by_path[key] for key in sorted(by_path)),
        "build_units": tuple(targets.get("targets", ())),
        "source_only_scopes": tuple(builds.get("source_only_scopes", ())),
        "compile_databases": tuple(compile_databases.get("files", ())),
        "accepted_artifacts": tuple(item for item in targets.get("targets", ()) if item.get("artifact_kind") == "built"),
        "gaps": tuple(gaps),
    }
