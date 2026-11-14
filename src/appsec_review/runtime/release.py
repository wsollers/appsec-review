"""Launch-time source identities. Review execution reads only the resulting bounded manifest.

The manifest is measured from the mounted source checkout by the deployment's launch step (the
code-location service start), never by a job handler or a resume planner. Its location is the
repository root by default and ``APPSEC_REVIEW_RELEASE_MANIFEST`` in mounted deployments, where
the source tree is read-only and the manifest lives on the deployment's own storage.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
from glob import has_magic
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence

from appsec_review.storage import atomic_bytes, canonical_json, file_sha256

DEPENDENCIES_SCHEMA = "appsec-review/release-dependencies/1"
RELEASE_SCHEMA = "appsec-review/implementation-release/1"
MANIFEST_NAME = "implementation-release.json"
MANIFEST_ENV = "APPSEC_REVIEW_RELEASE_MANIFEST"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}")
_JOB = re.compile(r"job_[a-z0-9_]+")
_JOB_MODULE = re.compile(r"appsec_review\.jobs\.(job_[a-z0-9_]+)(?:\.|$)")
PACKAGE = "appsec_review"


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


def manifest_path(repository_root: Path, environ: Mapping[str, str] | None = None) -> Path:
    """Where the measured manifest lives: ``APPSEC_REVIEW_RELEASE_MANIFEST`` or the repository root.

    A mounted deployment keeps its source read-only and points this variable at the manifest its
    launch step wrote; a source checkout or a baked image reads ``implementation-release.json``
    beside the sources. A relative value is rejected so the variable cannot resolve inside an
    attempt's working directory.
    """
    environ = os.environ if environ is None else environ
    configured = environ.get(MANIFEST_ENV, "")
    if configured:
        path = Path(configured)
        if not path.is_absolute():
            raise ValueError(f"{MANIFEST_ENV} must be an absolute path")
        return path
    return Path(repository_root) / MANIFEST_NAME


def load_release(repository_root: Path) -> dict[str, Any] | None:
    path = manifest_path(repository_root)
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


def module_name(path: str) -> str | None:
    """The ``appsec_review`` module a release-relative ``.py`` path defines, or ``None`` for other files."""
    parts = PurePosixPath(path).parts
    if not path.endswith(".py") or PACKAGE not in parts:
        return None
    parts = parts[parts.index(PACKAGE):]
    parts = (*parts[:-1], parts[-1][:-3])
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def module_imports(name: str, source: bytes) -> tuple[dict[str, bool], bool]:
    """The ``appsec_review`` names a module imports, and whether it also imports dynamically.

    Each name maps to whether it must itself be a module: ``import a.b`` and the ``a.b`` of
    ``from a.b import c`` name modules, while ``a.b.c`` may be a submodule or an attribute of
    ``a.b``. Relative imports resolve against the module's own package. A call to
    ``importlib.import_module`` or ``__import__`` cannot be followed statically and is reported so
    the caller keeps the whole shared closure for that job.
    """
    tree = ast.parse(source, filename=name)
    own = module_name(name)
    imported: dict[str, bool] = {}
    dynamic = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.name] = True
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                if own is None:
                    dynamic = True
                    continue
                package = own.split(".")[:-1] if not name.endswith("__init__.py") else own.split(".")
                prefix = package[:len(package) - node.level + 1]
                base = ".".join((*prefix, node.module or "")).rstrip(".")
            imported[base] = True
            for alias in node.names:
                imported.setdefault(f"{base}.{alias.name}", False)
        elif isinstance(node, ast.Call):
            target = node.func
            callee = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
            if callee in {"__import__", "import_module"}:
                # A literal module name is followed like a static import; anything else is dynamic.
                argument = node.args[0] if node.args else None
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    imported[argument.value] = True
                else:
                    dynamic = True
    return ({module: exact for module, exact in imported.items()
             if module == PACKAGE or module.startswith(PACKAGE + ".")}, dynamic)


def package_names(modules: Mapping[str, str]) -> frozenset[str]:
    """Every dotted prefix of a release module: the packages, with or without an ``__init__``."""
    return frozenset(".".join(name.split(".")[:count])
                     for name in modules for count in range(1, len(name.split("."))))


def resolve_module(module: str, modules: Mapping[str, str], *, exact: bool = True,
                   packages: frozenset[str] | None = None) -> list[str] | None:
    """The release files an ``appsec_review`` import executes: the module and every enclosing
    package's ``__init__`` (a namespace package contributes none). With ``exact=False`` the last
    component may be an attribute of the package or module before it. ``None`` when the release
    has no such module or package, so the caller falls back to the whole shared closure."""
    packages = package_names(modules) if packages is None else packages
    parts = module.split(".")
    if ".".join(parts) not in modules and ".".join(parts) not in packages:
        if exact or len(parts) < 2:
            return None
        parts = parts[:-1]
        if ".".join(parts) not in modules and ".".join(parts) not in packages:
            return None
    return [modules[".".join(parts[:count])] for count in range(1, len(parts) + 1)
            if ".".join(parts[:count]) in modules]


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
    modules = {name: path for path in common if (name := module_name(path)) is not None}
    packages = package_names(modules)
    shared = {path: sha for path, sha in common.items() if module_name(path) is None}
    parsed: dict[str, tuple[set[str], bool]] = {}

    def imports(name: str) -> tuple[set[str], bool]:
        if name not in parsed:
            parsed[name] = module_imports(name, (root / name).read_bytes())
        return parsed[name]

    jobs = {}
    for job_id in sorted(set(job_ids)):
        if not _JOB.fullmatch(job_id):
            raise ValueError(f"invalid release job: {job_id}")
        # The job package, every job package its own files import, and only the shared
        # ``appsec_review`` modules the walk reaches; a module the walk cannot follow statically
        # (a dynamic import of a computed name, an import no release file satisfies) keeps all of
        # ``common`` for this job.
        pending, visited, code, reached, conservative = [job_id], set(), {}, {}, False
        queue: list[str] = []
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            selected = select([manifest["job_pattern"].format(job_id=current)])
            if not selected:
                raise ValueError(f"job dependency has no source files: {current}")
            code.update(selected)
            queue.extend(name for name in selected if name.endswith(".py"))
            while queue:
                name = queue.pop()
                imported, dynamic = imports(name)
                conservative = conservative or dynamic
                for module, exact in imported.items():
                    match = _JOB_MODULE.match(module)
                    if match:
                        # A job's own import of another job package joins the closure. A shared
                        # module that imports job packages (the registry, dataset tables) does not
                        # make every job depend on every other job; it contributes only itself.
                        if name in code:
                            pending.append(match[1])
                        continue
                    resolved = resolve_module(module, modules, exact=exact, packages=packages)
                    if resolved is None:
                        conservative = True
                        continue
                    for path in resolved:
                        if path not in reached:
                            reached[path] = common[path]
                            queue.append(path)
        selected_common = common if conservative else dict(sorted({**shared, **reached}.items()))
        closure = {"job": code, "common": selected_common, "validators": validators, "scripts": scripts}
        jobs[job_id] = {"implementation": digest(closure), "validation": digest(closure)}
    value = {"schema": RELEASE_SCHEMA, "dependency_manifest": digest(manifest), "files": files,
             "jobs": jobs, "scripts_sha256": digest(scripts),
             "environment_requirements": sorted(set(manifest.get("environment_requirements", ())))}
    return validate_release({**value, "sha256": digest(value)})


def main(argv: Sequence[str] | None = None, *, execvp=os.execvp) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=None,
                        help="dependency manifest; defaults to release-dependencies.json under --root")
    parser.add_argument("--output", type=Path, default=None,
                        help=f"manifest to write; defaults to ${MANIFEST_ENV} or {MANIFEST_NAME} under --root")
    parser.add_argument("--verify-assets", action="store_true",
                        help="also verify the mounted runtime assets and catalogs (the former image-build checks)")
    parser.add_argument("--exec", dest="then", nargs=argparse.REMAINDER, default=None,
                        help="after writing the manifest, replace this process with the given command")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    manifest = args.manifest if args.manifest is not None else root / "release-dependencies.json"
    output = args.output if args.output is not None else manifest_path(root)
    if args.then is not None and not args.then:
        parser.error("--exec requires a command")
    if args.verify_assets:
        verify_deployment_assets()
    from appsec_review.runtime.registry import builtin_registry
    release = build_release(root, read_document(manifest), builtin_registry().job_ids())
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(output, canonical_json(release))
    print(release["sha256"], flush=True)
    if args.then is not None:
        execvp(args.then[0], list(args.then))
    return 0


def verify_deployment_assets() -> None:
    """The checks the image build used to run while it still contained the sources.

    A tooling-only image cannot run them at build time, so the launch step runs them against the
    mounted checkout before the code server starts; a missing asset or a broken catalog refuses
    the launch instead of surfacing as a failed job later.
    """
    from appsec_review.application_paths import application_root, verify_runtime_assets
    verify_runtime_assets()
    from appsec_review.container_runtime.catalog import load_catalog as load_container_catalog
    load_container_catalog(application_root("containers/catalog.toml"))
    from appsec_review.graph.catalog import load_catalog as load_graph_catalog
    load_graph_catalog()
    from appsec_review.orchestration.dagster.definitions import defs
    defs.get_job_def("wave1_review")


if __name__ == "__main__":
    raise SystemExit(main())
