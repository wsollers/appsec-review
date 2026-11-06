"""Build-time source identities. Review execution reads only the resulting bounded manifest."""
from __future__ import annotations

import argparse
import ast
import fnmatch
from glob import has_magic
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from appsec_review.storage import atomic_bytes, canonical_json, file_sha256

DEPENDENCIES_SCHEMA = "appsec-review/release-dependencies/1"
RELEASE_SCHEMA = "appsec-review/implementation-release/1"
MANIFEST_NAME = "implementation-release.json"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")
_JOB = re.compile(r"job_[a-z0-9_]+")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def read_document(path: Path, *, limit: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"manifest exceeds {limit} bytes: {path.name}")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("manifest must be an object")
    return value


def validate_release(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {"schema", "dependency_manifest", "files", "jobs", "scripts_sha256",
                "environment_requirements", "sha256"}
    if set(value) != required or value["schema"] != RELEASE_SCHEMA:
        raise ValueError("unsupported implementation release contract")
    if digest({key: item for key, item in value.items() if key != "sha256"}) != value["sha256"]:
        raise ValueError("implementation release digest mismatch")
    if not isinstance(value["jobs"], dict) or not value["jobs"]:
        raise ValueError("implementation release has no jobs")
    if any(not isinstance(value[name], str) or not _SHA.fullmatch(value[name])
           for name in ("dependency_manifest", "scripts_sha256")):
        raise ValueError("release dependency and script identities must be SHA-256")
    for job_id, identity in value["jobs"].items():
        if not _JOB.fullmatch(job_id) or set(identity) != {"implementation", "validation"}:
            raise ValueError("invalid released job identity")
        if any(not isinstance(item, str) or not _SHA.fullmatch(item) for item in identity.values()):
            raise ValueError("released job identities must be SHA-256")
    if not isinstance(value["files"], dict) or any(
        not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts
        or not isinstance(item, str) or not _SHA.fullmatch(item)
        for path, item in value["files"].items()
    ):
        raise ValueError("invalid released file identities")
    if not isinstance(value["environment_requirements"], list) or any(
        not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name)
        for name in value["environment_requirements"]
    ):
        raise ValueError("environment requirements contain names only")
    return dict(value)


def load_release(repository_root: Path) -> dict[str, Any] | None:
    path = Path(repository_root) / MANIFEST_NAME
    if not path.exists():
        return None
    return validate_release(read_document(path))


def identities(job_id: str, schema: str, repository_root: Path,
               declarations: Mapping[str, str]) -> dict[str, str]:
    return identities_from_release(load_release(repository_root), job_id, schema, declarations)


def identities_from_release(release: Mapping[str, Any] | None, job_id: str, schema: str,
                            declarations: Mapping[str, str]) -> dict[str, str]:
    identity = release["jobs"].get(job_id) if release else None
    if identity is None:
        return {"implementation": "undeclared", "schema": schema, "validation": "undeclared"}
    # Labels may deliberately invalidate a release, but cannot replace measured build provenance.
    return {
        "implementation": digest({"source": identity["implementation"],
                                  "label": declarations.get(job_id, declarations.get("platform"))}),
        "schema": schema,
        "validation": digest({"source": identity["validation"], "label": declarations.get("validation")}),
    }


def validate_claim_release(run_root: Path, claim: Mapping[str, Any]) -> dict[str, Any] | None:
    """Verify implementation metadata as control-plane provenance, not customer evidence."""
    artifact = claim.get("implementation_release")
    if artifact is None:
        return None
    from appsec_review.storage.shared import verify_reference
    try:
        release = validate_release(read_document(verify_reference(run_root, artifact)))
        components = claim["component_identities"]
        declarations = claim["review_policy"]["releases"]
        if (not isinstance(components, Mapping)
                or any(not isinstance(components.get(key), str) or not components[key].strip()
                       for key in ("implementation", "schema", "validation"))
                or not isinstance(declarations, Mapping)):
            raise ValueError("claim has invalid implementation declarations")
        from appsec_review.config.assurance import ComponentReleases
        declarations = ComponentReleases(declarations).view()
        expected = identities_from_release(
            release, claim["job_id"], components["schema"], declarations)
        if "undeclared" in expected.values() or components != expected:
            raise ValueError("claim components differ from their measured release")
        if claim["deployment_identity"]["scripts_sha256"] != release["scripts_sha256"]:
            raise ValueError("claim scripts differ from their measured release")
        return release
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"implementation release evidence is invalid: {exc}") from exc


def build_release(root: Path, manifest: Mapping[str, Any], job_ids: Sequence[str]) -> dict[str, Any]:
    """Only called by the release command/build, never by a job or resume planner."""
    root = root.resolve()
    if manifest.get("schema") != DEPENDENCIES_SCHEMA or not job_ids:
        raise ValueError("unsupported dependency manifest or empty job selection")
    for key in ("common", "validators", "scripts", "exclude_common", "environment_requirements"):
        values = manifest.get(key, [])
        if not isinstance(values, (list, tuple)) or any(not isinstance(item, str) for item in values):
            raise ValueError(f"dependency manifest {key} must contain strings")
    files: dict[str, str] = {}

    def select(patterns: Sequence[str], excludes: Sequence[str] = ()) -> dict[str, str]:
        result = {}
        for pattern in patterns:
            if not isinstance(pattern, str) or Path(pattern).is_absolute() or ".." in Path(pattern).parts:
                raise ValueError("dependency patterns must be repository-relative")
            found = False
            for path in sorted(root.glob(pattern)):
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                relative = path.relative_to(root).as_posix()
                if any(fnmatch.fnmatchcase(relative, excluded) for excluded in excludes):
                    continue
                found = True
                if not path.resolve().is_relative_to(root) or path.is_symlink():
                    raise ValueError(f"release dependency escapes its source tree: {relative}")
                files.setdefault(relative, file_sha256(path))
                result[relative] = files[relative]
            if not found and not has_magic(pattern):
                raise ValueError(f"missing release dependency: {pattern}")
        return dict(sorted(result.items()))

    common = select(manifest["common"], manifest.get("exclude_common", ()))
    validators = select(manifest["validators"])
    scripts = select(manifest["scripts"])
    if not common or not validators:
        raise ValueError("release must cover shared code and validators, not just job packages")
    jobs = {}
    for job_id in sorted(set(job_ids)):
        if not _JOB.fullmatch(job_id):
            raise ValueError(f"invalid release job: {job_id}")
        pending, visited, code = [job_id], set(), {}
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            selected = select([manifest["job_pattern"].format(job_id=current)])
            if not selected:
                raise ValueError(f"job dependency has no source files: {current}")
            code.update(selected)
            # Include cross-job helper imports, not just the job package's own bytes.
            for name in selected:
                if not name.endswith(".py"):
                    continue
                tree = ast.parse((root / name).read_bytes(), filename=name)
                for node in ast.walk(tree):
                    modules = ([node.module or ""] if isinstance(node, ast.ImportFrom) else
                               [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
                    if isinstance(node, ast.ImportFrom):
                        if node.level and name.startswith("src/"):
                            package = name.removeprefix("src/").split("/")[:-1]
                            prefix = package[:len(package) - node.level + 1]
                            modules = [".".join((*prefix, node.module or "")).rstrip(".")]
                        modules.extend(f"{modules[0]}.{alias.name}" for alias in node.names)
                    for module in modules:
                        match = re.match(r"appsec_review\.jobs\.(job_[a-z0-9_]+)(?:\.|$)", module)
                        if match:
                            pending.append(match[1])
        closure = {"job": code, "common": common, "validators": validators, "scripts": scripts}
        jobs[job_id] = {"implementation": digest(closure), "validation": digest(closure)}
    value = {"schema": RELEASE_SCHEMA, "dependency_manifest": digest(manifest), "files": files,
             "jobs": jobs, "scripts_sha256": digest(scripts),
             "environment_requirements": sorted(set(manifest.get("environment_requirements", ())))}
    return validate_release({**value, "sha256": digest(value)})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=Path("release-dependencies.json"))
    parser.add_argument("--output", type=Path, default=Path(MANIFEST_NAME))
    args = parser.parse_args(argv)
    from appsec_review.runtime.registry import builtin_registry
    release = build_release(args.root, read_document(args.manifest), builtin_registry().job_ids())
    atomic_bytes(args.output, canonical_json(release))
    print(release["sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
