"""Typed, bounded repairs a model may propose for a failing project build image.

A proposal is data, never a command. It may only choose from closed vocabularies:

- ``system_packages``: the complete apt package set for the next image;
- ``environment``: the complete set of repair environment variables, each named in the family's
  allowlist below with a value that matches that variable's pattern;
- ``package_manager``: one of the package managers already pinned in the family's build image;
- ``dependency_restores``: accepted dependency manifests to restore with the family's own package
  manager into the image's shared dependency location. The argv for each restore is built by
  :func:`appsec_review.container_runtime.project_images.repair_restore_commands`.

The applied repair is recorded on the recipe as ``image_repairs`` so it is part of the recipe
identity, the generated Dockerfile, the repair cache, and every attempt record.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.container_runtime.project_images import (
    PINNED_PACKAGE_MANAGERS,
    repair_restore_commands,
    restore_manager,
)


REPAIR_SCHEMA = "appsec-review/build-image-repair/2"
REPAIR_FIELDS = frozenset({"schema", "system_packages", "environment", "package_manager",
                           "dependency_restores", "reason"})
MAX_SYSTEM_PACKAGES = 64
MAX_REPAIR_ENVIRONMENT = 16
MAX_DEPENDENCY_RESTORES = 8
_PACKAGE = re.compile(
    r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?(?:=[A-Za-z0-9.+:~_-]+)?$")


def _choice(*values: str) -> re.Pattern[str]:
    return re.compile("^(?:" + "|".join(re.escape(value) for value in values) + ")$")


def _tokens(*patterns: str, limit: int = 8) -> re.Pattern[str]:
    token = "(?:" + "|".join(patterns) + ")"
    return re.compile(rf"^{token}(?: {token}){{0,{limit - 1}}}$")


_INTEGER = r"(?:[1-9][0-9]{0,3})"
_MAVEN_SKIPS = ("enforcer", "checkstyle", "spotbugs", "pmd", "rat", "gpg", "jacoco", "javadoc",
                "maven.javadoc", "license", "spotless.check", "animal.sniffer", "japicmp",
                "revapi", "cyclonedx", "dependency-check", "sortpom", "formatter", "impsort")
_JAVA_LEVELS = "(?:1\\.8|8|11|17|21)"

# Repair environment per image profile. Every value pattern is anchored and free of quotes,
# backslashes, dollar signs, and newlines, so a value is inert in a Dockerfile ENV instruction.
# Names that select URLs, registries, credentials, toolchain downloads, or checksum databases are
# deliberately absent.
REPAIR_ENVIRONMENT: dict[str, dict[str, re.Pattern[str]]] = {
    "python": {
        # Ubuntu's Python is externally managed (PEP 668); a recipe pip install needs this.
        "PIP_BREAK_SYSTEM_PACKAGES": _choice("1"),
        # Offline probes cannot fetch an isolated build backend; restored backends are used.
        "PIP_NO_BUILD_ISOLATION": _choice("0", "1"),
        "PIP_PREFER_BINARY": _choice("1"),
        # setuptools-scm cannot derive a version from a workspace without .git.
        "SETUPTOOLS_SCM_PRETEND_VERSION": re.compile(
            r"^[0-9]{1,4}(?:\.[0-9]{1,6}){0,3}(?:(?:a|b|rc|\.post|\.dev)[0-9]{1,6})?$"),
    },
    "node": {
        "NPM_CONFIG_LEGACY_PEER_DEPS": _choice("true"),
        "NPM_CONFIG_ENGINE_STRICT": _choice("false"),
        "NPM_CONFIG_FUND": _choice("false"),
        "YARN_IGNORE_ENGINES": _choice("true"),
        "NODE_OPTIONS": re.compile(r"^--max-old-space-size=(?:[5-9][0-9]{2}|[1-7][0-9]{3}|8000)$"),
    },
    "rust": {
        "CARGO_NET_GIT_FETCH_WITH_CLI": _choice("true"),
        "CARGO_NET_RETRY": re.compile(r"^(?:[0-9]|10)$"),
        "CARGO_HTTP_MULTIPLEXING": _choice("false"),
        "CARGO_BUILD_JOBS": re.compile(r"^(?:[1-9]|1[0-6])$"),
    },
    "java": {
        # Maven 3.9 reads MAVEN_ARGS before the command's own arguments.
        "MAVEN_ARGS": _tokens(
            r"-D(?:" + "|".join(re.escape(name) for name in _MAVEN_SKIPS) + r")\.skip=true",
            rf"-Dmaven\.compiler\.(?:source|target|release)={_JAVA_LEVELS}",
            r"-Dmaven\.wagon\.http\.retryHandler\.count=[0-9]",
            r"-Dmaven\.test\.skip=true", r"-DskipTests"),
    },
    "dotnet": {
        # MSBuild reads environment variables as properties, and property names are
        # case-insensitive. The image already sets NuGetAudit=false.
        "TREATWARNINGSASERRORS": _choice("false"),
        "ENABLENETANALYZERS": _choice("false"),
        "CHECKEOLTARGETFRAMEWORK": _choice("false"),
        "RESTORELOCKEDMODE": _choice("false"),
    },
    "go": {
        # A workspace without .git cannot stamp VCS metadata; -mod selects the module mode.
        "GOFLAGS": _tokens(r"-mod=(?:mod|readonly|vendor)", r"-buildvcs=false", limit=2),
        "CGO_ENABLED": _choice("0", "1"),
    },
    "php": {
        "COMPOSER_IGNORE_PLATFORM_REQS": _choice("1"),
        "COMPOSER_IGNORE_PLATFORM_REQ": re.compile(
            r"^(?:php|ext-[a-z0-9_]{1,32}|lib-[a-z0-9-]{1,32})(?:,(?:php|ext-[a-z0-9_]{1,32}|"
            r"lib-[a-z0-9-]{1,32})){0,15}$"),
        "COMPOSER_NO_DEV": _choice("1"),
        "COMPOSER_PROCESS_TIMEOUT": re.compile(rf"^{_INTEGER}$"),
    },
}
REPAIR_ENVIRONMENT["android"] = {}
REPAIR_ENVIRONMENT["native"] = {}
REPAIR_ENVIRONMENT["wasm"] = {}


def repair_options(recipe: Mapping[str, Any], build_system: str) -> dict[str, Any]:
    """The closed repair vocabulary for this recipe, sent to the model with the failure."""
    profile = str(recipe.get("image_profile", ""))
    manifests = [path for path in recipe.get("dependency_files", ())
                 if restore_manager(build_system, recipe, str(path)) is not None]
    return {"environment_names": sorted(REPAIR_ENVIRONMENT.get(profile, {})),
            "package_managers": dict(PINNED_PACKAGE_MANAGERS.get(build_system, {})),
            "restorable_manifests": sorted(str(path) for path in manifests),
            "limits": {"system_packages": MAX_SYSTEM_PACKAGES,
                       "environment": MAX_REPAIR_ENVIRONMENT,
                       "dependency_restores": MAX_DEPENDENCY_RESTORES}}


def validate_repair_proposal(proposal: Mapping[str, Any], *, recipe: Mapping[str, Any],
                             build_system: str) -> tuple[str, ...]:
    """Return every reason the proposal is outside the typed repair vocabulary for this recipe."""
    errors: list[str] = []
    if not isinstance(proposal, Mapping) or set(proposal) != REPAIR_FIELDS:
        return ("repair proposal fields are invalid",)
    if proposal.get("schema") != REPAIR_SCHEMA:
        errors.append("repair proposal schema is unsupported")
    packages = proposal.get("system_packages")
    if not isinstance(packages, list) or len(packages) > MAX_SYSTEM_PACKAGES:
        errors.append(f"system_packages must contain at most {MAX_SYSTEM_PACKAGES} packages")
    elif any(not isinstance(value, str) or len(value) > 128 or not _PACKAGE.fullmatch(value)
             for value in packages):
        errors.append("system_packages contains an invalid apt package specifier")
    elif len(set(packages)) != len(packages):
        errors.append("system_packages contains duplicates")
    profile = str(recipe.get("image_profile", ""))
    allowed = REPAIR_ENVIRONMENT.get(profile, {})
    environment = proposal.get("environment")
    if not isinstance(environment, Mapping) or len(environment) > MAX_REPAIR_ENVIRONMENT:
        errors.append(f"environment must be an object of at most {MAX_REPAIR_ENVIRONMENT} entries")
    else:
        for key, value in environment.items():
            pattern = allowed.get(key) if isinstance(key, str) else None
            if pattern is None:
                errors.append(f"environment name is not repairable for {profile}: {str(key)[:64]}")
            elif not isinstance(value, str) or not pattern.fullmatch(value):
                errors.append(f"environment value is not allowed for {key}")
    manager = proposal.get("package_manager")
    pinned = PINNED_PACKAGE_MANAGERS.get(build_system, {})
    if manager is not None:
        if not isinstance(manager, str) or manager not in pinned:
            errors.append(f"package_manager must be null or one of the pinned {build_system} "
                          f"package managers: {', '.join(sorted(pinned)) or 'none'}")
        elif build_system == "node":
            names = {PurePosixPath(str(path)).name for path in recipe.get("dependency_files", ())}
            locks = names & {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
            if locks:
                errors.append("package_manager cannot override the manager of an accepted lockfile")
            commands = [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]
            used = {PurePosixPath(str(argv[0])).name for argv in commands
                    if isinstance(argv, list) and argv} & set(pinned)
            if used - {manager}:
                errors.append("package_manager conflicts with the package manager the recipe runs")
    restores = proposal.get("dependency_restores")
    if not isinstance(restores, list) or len(restores) > MAX_DEPENDENCY_RESTORES:
        errors.append(f"dependency_restores must list at most {MAX_DEPENDENCY_RESTORES} manifests")
    else:
        accepted = {str(path) for path in recipe.get("dependency_files", ())}
        seen: set[str] = set()
        for item in restores:
            if not isinstance(item, Mapping) or set(item) != {"manifest"} or not isinstance(
                    item.get("manifest"), str):
                errors.append("dependency_restores entries must be objects with only manifest")
                continue
            manifest = item["manifest"]
            if manifest in seen:
                errors.append(f"dependency_restores repeats {manifest[:512]}")
            seen.add(manifest)
            if manifest not in accepted:
                errors.append(f"dependency restore manifest is not an accepted dependency file: "
                              f"{manifest[:512]}")
            elif restore_manager(build_system, recipe, manifest) is None:
                errors.append(f"{build_system} cannot restore dependencies from {manifest[:512]}")
    reason = proposal.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 4096:
        errors.append("repair reason must be non-empty and at most 4096 bytes")
    return tuple(errors)


def image_repair_errors(recipe: Mapping[str, Any], build_system: str) -> list[str]:
    """Validate an applied ``image_repairs`` record on a recipe (accepted, cached, or replayed)."""
    value = recipe.get("image_repairs")
    if not isinstance(value, Mapping) or set(value) != {
            "environment", "package_manager", "dependency_restores"}:
        return ["image_repairs fields are invalid"]
    proposal = {"schema": REPAIR_SCHEMA, "system_packages": list(recipe.get("system_packages", ())),
                "environment": value["environment"], "package_manager": value["package_manager"],
                "dependency_restores": [{"manifest": item.get("manifest")} if isinstance(item, Mapping)
                                        else item for item in value["dependency_restores"]]
                if isinstance(value["dependency_restores"], list) else value["dependency_restores"],
                "reason": "recorded image repair"}
    errors = [f"image_repairs: {error}" for error in
              validate_repair_proposal(proposal, recipe=recipe, build_system=build_system)]
    environment = recipe.get("environment")
    if isinstance(value["environment"], Mapping) and isinstance(environment, Mapping) and any(
            environment.get(key) != item for key, item in value["environment"].items()):
        errors.append("image_repairs environment is not applied to the recipe environment")
    if not errors:
        try:
            expected = [dict(item) for item in _restore_records(recipe, build_system,
                                                                value["dependency_restores"])]
        except ValueError as exc:
            errors.append(f"image_repairs: {exc}")
        else:
            if expected != [dict(item) for item in value["dependency_restores"]]:
                errors.append("image_repairs dependency_restores are not normalized")
    return errors


def _restore_records(recipe: Mapping[str, Any], build_system: str,
                     restores: list[Mapping[str, Any]]) -> list[dict[str, str]]:
    records = []
    for item in restores:
        manifest = str(item["manifest"])
        manager = restore_manager(build_system, recipe, manifest)
        if manager is None:
            raise ValueError(f"{build_system} cannot restore dependencies from {manifest}")
        records.append({"manager": manager, "manifest": manifest})
    return sorted(records, key=lambda record: record["manifest"])


def apply_repair(recipe: Mapping[str, Any], proposal: Mapping[str, Any], *,
                 build_system: str) -> dict[str, Any]:
    """Return the recipe with the proposal's complete repair set in place of the previous one."""
    errors = validate_repair_proposal(proposal, recipe=recipe, build_system=build_system)
    if errors:
        raise ValueError("; ".join(errors))
    previous = recipe.get("image_repairs") if isinstance(recipe.get("image_repairs"), Mapping) else {}
    environment = {key: value for key, value in dict(recipe.get("environment", {})).items()
                   if key not in dict(previous.get("environment", {}))}
    repair_environment = {str(key): str(value) for key, value in sorted(proposal["environment"].items())}
    conflicts = sorted(set(environment) & set(repair_environment))
    if conflicts:
        raise ValueError("repair environment would replace accepted recipe environment: " +
                         ", ".join(conflicts))
    environment.update(repair_environment)
    selected = {**recipe, "image_repairs": {"environment": repair_environment,
                                            "package_manager": proposal["package_manager"],
                                            "dependency_restores": []}}
    restores = _restore_records(selected, build_system, list(proposal["dependency_restores"]))
    image_repairs = {"environment": repair_environment,
                     "package_manager": proposal["package_manager"],
                     "dependency_restores": restores}
    packages = sorted({str(value) for value in proposal["system_packages"]})
    current_packages = sorted({str(value) for value in recipe.get("system_packages", ())})
    current_repairs = previous or {"environment": {}, "package_manager": None, "dependency_restores": []}
    if packages == current_packages and image_repairs == dict(current_repairs):
        raise ValueError("repair proposal repeated the current repair set")
    result = {key: value for key, value in recipe.items() if key != "image_repairs"}
    result.update(system_packages=packages, environment=environment,
                  reason=f"{recipe.get('reason', 'accepted recipe')} Image repair: {proposal['reason']}")
    if any((repair_environment, proposal["package_manager"], restores)):
        result["image_repairs"] = image_repairs
        # Rendering the restore argv now proves every restore is constructible.
        repair_restore_commands({**result, "build_system": build_system})
    return result
