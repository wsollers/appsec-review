"""Bounded, deterministic processing applicability and disposition records.

The evaluator consumes only accepted inventory facts and typed policy. It never
uses command output, wrapper text, model output, or an unbounded target scan.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.storage import canonical_json, file_sha256


DECISION_SCHEMA = "appsec-review/applicability-decision/1"
FACTS_SCHEMA = "appsec-review/project-processing-facts/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def resolved_configuration_identity(run_root: Path) -> str:
    """Resolve and verify the immutable run configuration identity."""
    root = Path(run_root).resolve()
    manifest_path = root / "data" / "configuration" / "manifest.json"
    resolved_path = root / "data" / "configuration" / "resolved.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("run-owned resolved configuration manifest is unavailable") from exc
    identity = manifest.get("resolved_sha256")
    if (not isinstance(identity, str) or not _SHA256.fullmatch(identity) or
            not resolved_path.is_file() or resolved_path.is_symlink() or
            file_sha256(resolved_path) != identity):
        raise ValueError("run-owned resolved configuration identity is invalid")
    return identity


class ProcessingFeature(str, Enum):
    BUILD_CAPTURE = "build-execution-capture"
    COMPILER_ARTIFACTS = "compiler-artifact-collection"
    CODEQL = "codeql"


class ProcessingDisposition(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    SKIPPED_NA = "SKIPPED_NA"
    SKIPPED_POLICY = "SKIPPED_POLICY"
    GAP = "GAP"


class ApplicabilityAction(str, Enum):
    RUN = "RUN"
    SKIP = "SKIP"
    GAP = "GAP"


class ReasonCode(str, Enum):
    POLICY_REQUIRED = "POLICY_REQUIRED"
    POLICY_DISABLED = "POLICY_DISABLED"
    MATERIAL_BUILD_CONFIRMED = "MATERIAL_BUILD_CONFIRMED"
    MATERIAL_BUILD_ABSENT = "MATERIAL_BUILD_ABSENT"
    INVENTORY_UNAVAILABLE = "INVENTORY_UNAVAILABLE"
    ARTIFACT_CAPABILITY_CONFIRMED = "ARTIFACT_CAPABILITY_CONFIRMED"
    ARTIFACT_CAPABILITY_ABSENT = "ARTIFACT_CAPABILITY_ABSENT"
    CODEQL_BUILD_SELECTED = "CODEQL_BUILD_SELECTED"
    CODEQL_SOURCE_SELECTED = "CODEQL_SOURCE_SELECTED"
    CODEQL_NOT_APPLICABLE = "CODEQL_NOT_APPLICABLE"
    CAPABILITY_UNSUPPORTED = "CAPABILITY_UNSUPPORTED"
    TOOLCHAIN_UNAVAILABLE = "TOOLCHAIN_UNAVAILABLE"
    PROCESSING_FAILED = "PROCESSING_FAILED"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    ARTIFACT_VALIDATION_FAILED = "ARTIFACT_VALIDATION_FAILED"
    PROCESSING_SUCCEEDED = "PROCESSING_SUCCEEDED"


@dataclass(frozen=True, slots=True)
class SourceArtifactIdentity:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        path = PurePosixPath(self.path)
        if (not self.path or path.is_absolute() or ".." in path.parts or
                not _SHA256.fullmatch(self.sha256)):
            raise ValueError("applicability source artifact identity is invalid")


@dataclass(frozen=True, slots=True)
class ProjectProcessingFacts:
    schema: str
    project_id: str
    language: str
    family: str
    root: str
    build_system: str
    inventory_complete: bool
    material_build_facts: tuple[str, ...]
    syntax_only_facts: tuple[str, ...]
    artifact_types: tuple[str, ...]
    capabilities: tuple[str, ...]
    sources: tuple[SourceArtifactIdentity, ...]

    def __post_init__(self) -> None:
        if self.schema != FACTS_SCHEMA or not self.project_id or not self.language or not self.family:
            raise ValueError("project processing facts identity is invalid")
        root = PurePosixPath(self.root)
        if not self.root or root.is_absolute() or ".." in root.parts:
            raise ValueError("project processing facts root is invalid")
        for values in (self.material_build_facts, self.syntax_only_facts,
                       self.artifact_types, self.capabilities):
            if tuple(sorted(set(values))) != values or any(not value for value in values):
                raise ValueError("project processing facts must be sorted unique values")
        if tuple(sorted(self.sources, key=lambda item: (item.path, item.sha256))) != self.sources:
            raise ValueError("project processing source identities must be sorted")

    @property
    def material_build(self) -> bool:
        return bool(self.material_build_facts)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ApplicabilityDecision:
    schema: str
    feature: ProcessingFeature
    project_id: str
    language: str
    resolved_policy: str
    configuration_sha256: str
    action: ApplicabilityAction
    disposition: ProcessingDisposition | None
    reason_code: ReasonCode
    selected_capability: str | None
    inspected_facts: tuple[str, ...]
    sources: tuple[SourceArtifactIdentity, ...]
    decision_sha256: str

    def __post_init__(self) -> None:
        if self.schema != DECISION_SCHEMA or not _SHA256.fullmatch(self.configuration_sha256):
            raise ValueError("applicability decision configuration identity is invalid")
        if self.action is ApplicabilityAction.RUN and self.disposition not in {
                None, ProcessingDisposition.SUCCEEDED, ProcessingDisposition.GAP}:
            raise ValueError("a processing run has an invalid terminal disposition")
        if self.action is ApplicabilityAction.SKIP and self.disposition not in {
                ProcessingDisposition.SKIPPED_NA, ProcessingDisposition.SKIPPED_POLICY}:
            raise ValueError("a processing skip requires a canonical skip disposition")
        if self.action is ApplicabilityAction.GAP and self.disposition is not ProcessingDisposition.GAP:
            raise ValueError("an applicability gap requires the GAP disposition")
        if tuple(sorted(set(self.inspected_facts))) != self.inspected_facts:
            raise ValueError("applicability decision facts must be sorted and unique")
        if not _SHA256.fullmatch(self.decision_sha256):
            raise ValueError("applicability decision identity is invalid")
        value = self.as_dict()
        value["decision_sha256"] = "0" * 64
        if hashlib.sha256(canonical_json(value)).hexdigest() != self.decision_sha256:
            raise ValueError("applicability decision hash is invalid")

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["feature"] = self.feature.value
        value["action"] = self.action.value
        value["disposition"] = self.disposition.value if self.disposition else None
        value["reason_code"] = self.reason_code.value
        return value


def decision_from_mapping(value: Mapping[str, Any]) -> ApplicabilityDecision:
    """Validate and restore a serialized applicability decision."""
    try:
        sources = tuple(SourceArtifactIdentity(str(item["path"]), str(item["sha256"]))
                        for item in value["sources"])
        return ApplicabilityDecision(
            str(value["schema"]), ProcessingFeature(str(value["feature"])),
            str(value["project_id"]), str(value["language"]),
            str(value["resolved_policy"]), str(value["configuration_sha256"]),
            ApplicabilityAction(str(value["action"])),
            (ProcessingDisposition(str(value["disposition"]))
             if value.get("disposition") is not None else None),
            ReasonCode(str(value["reason_code"])),
            str(value["selected_capability"]) if value.get("selected_capability") is not None else None,
            tuple(str(item) for item in value["inspected_facts"]), sources,
            str(value["decision_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("serialized applicability decision is invalid") from exc


_COMPILED_SYSTEMS = {
    "autotools", "cargo", "cmake", "direct-native", "dotnet", "go", "gradle",
    "javac", "kotlin", "make", "maven", "meson", "msbuild", "node-gyp",
    "php-extension", "rustc", "typescript", "wasm",
}
_ARTIFACT_TYPES: Mapping[str, tuple[str, ...]] = {
    "native": ("executable", "object", "shared-library", "static-library"),
    "rust": ("executable", "rlib", "rmeta"),
    "go": ("executable", "go-archive"),
    "java": ("class", "jar", "war"),
    "dotnet": ("assembly", "debug-information"),
    "node": (), "python": (), "php": (),
    "wasm": ("wasm",),
}
_CODEQL_CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    "native": ("codeql-build",), "go": ("codeql-build",),
    "java": ("codeql-build",), "dotnet": ("codeql-build",),
    "node": ("codeql-source",), "python": ("codeql-source",),
    "rust": ("codeql-source",),
}


def _sources(documents: Sequence[Mapping[str, Any]]) -> tuple[SourceArtifactIdentity, ...]:
    values = []
    for item in documents:
        if not isinstance(item, Mapping):
            raise ValueError("descriptor package contains a malformed document")
        path, digest = item.get("path"), item.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ValueError("descriptor package document identity is missing")
        values.append(SourceArtifactIdentity(path, digest))
    if len(values) != len({(item.path, item.sha256) for item in values}):
        raise ValueError("descriptor package contains duplicate source identities")
    return tuple(sorted(values, key=lambda item: (item.path, item.sha256)))


def facts_from_build_unit(unit: Mapping[str, Any]) -> ProjectProcessingFacts:
    """Derive generic material-build facts from one bounded catalog build unit."""
    package = unit.get("descriptor_package")
    if not isinstance(package, Mapping):
        return ProjectProcessingFacts(
            FACTS_SCHEMA, str(unit.get("build_unit_id") or "unknown"),
            str(unit.get("family") or "unknown"), str(unit.get("family") or "unknown"),
            str(unit.get("root") or "."), str(unit.get("build_system") or "unknown"),
            False, (), (), (), (), (),
        )
    documents = package.get("documents")
    gaps = package.get("gaps")
    if not isinstance(documents, list) or not isinstance(gaps, list):
        raise ValueError("descriptor package inventory shape is invalid")
    identities = _sources(documents)
    contents: dict[str, str] = {}
    for item in documents:
        content = item.get("content")
        if not isinstance(content, str):
            raise ValueError("descriptor package content is invalid")
        contents[str(item["path"])] = content
    family = str(unit.get("family") or "unknown")
    system = str(unit.get("build_system") or "unknown")
    triggers: set[str] = set()
    syntax: set[str] = set()
    capabilities = set(_CODEQL_CAPABILITIES.get(family, ()))
    artifact_types = set(_ARTIFACT_TYPES.get(family, ()))

    if system in _COMPILED_SYSTEMS:
        triggers.add(f"compiled-descriptor:{system}")
    if family in {"native", "rust", "go", "java", "dotnet", "wasm"}:
        triggers.add(f"declared-compiled-project:{family}")

    for path, content in sorted(contents.items()):
        name = PurePosixPath(path).name
        lowered = content.lower()
        if name == "package.json":
            try:
                value = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ValueError(f"bounded package manifest is malformed: {path}") from exc
            if not isinstance(value, Mapping):
                raise ValueError(f"bounded package manifest is not an object: {path}")
            scripts = value.get("scripts", {})
            dependencies = {**(value.get("dependencies", {}) if isinstance(value.get("dependencies"), Mapping) else {}),
                            **(value.get("devDependencies", {}) if isinstance(value.get("devDependencies"), Mapping) else {})}
            if isinstance(scripts, Mapping):
                lifecycle = set(scripts) & {"preinstall", "install", "postinstall", "prepare", "prepack"}
                if lifecycle:
                    triggers.add("package-lifecycle-hook")
                build = scripts.get("build")
                if isinstance(build, str):
                    text = build.lower()
                    if re.search(r"(?:^|[\s;&])(?:tsc|swc|babel)(?:[\s;&]|$)", text):
                        triggers.add("transpilation")
                    if re.search(r"(?:^|[\s;&])(?:esbuild|webpack|rollup|vite|parcel)(?:[\s;&]|$)", text):
                        triggers.add("bundler-build")
                    if "node-gyp" in text:
                        triggers.add("native-extension")
                    if re.fullmatch(r"\s*node\s+--check\s+.+", text):
                        syntax.add("syntax-only:node--check")
            names = {str(key).lower() for key in dependencies}
            if names & {"typescript", "@swc/core", "babel", "@babel/core"}:
                triggers.add("transpilation")
            if names & {"esbuild", "webpack", "rollup", "vite", "parcel"}:
                triggers.add("bundler-build")
            if names & {"node-gyp", "node-addon-api", "nan"} or value.get("gypfile") is True:
                triggers.add("native-extension")
        elif name == "composer.json":
            try:
                value = json.loads(content)
            except json.JSONDecodeError as exc:
                raise ValueError(f"bounded Composer manifest is malformed: {path}") from exc
            if not isinstance(value, Mapping):
                raise ValueError(f"bounded Composer manifest is not an object: {path}")
            if isinstance(value.get("scripts"), Mapping) and value["scripts"]:
                triggers.add("package-lifecycle-hook")
        if name == "tsconfig.json":
            triggers.add("transpilation")
        if name == "binding.gyp":
            triggers.add("native-extension")
        if name in {"pyproject.toml", "setup.py", "setup.cfg"}:
            if ("[build-system]" in lowered or "build-backend" in lowered or
                    "setup(" in lowered):
                triggers.add("package-build-hook")
            if re.search(r"\b(extension|ext_modules|cythonize)\b", lowered):
                triggers.add("native-extension")
        if name == "config.m4" and "php_new_extension" in lowered:
            triggers.add("native-extension")
        if name in {"build.gradle", "build.gradle.kts"} and "com.android.application" in lowered:
            triggers.add("android-gradle-build")
        if name == "build.sh":
            if re.search(r"(^|\s)kotlinc(\s|$)", lowered):
                triggers.add("compiler-invocation:kotlinc")
            if ("--target=wasm" in lowered or "wasm32" in lowered or
                    re.search(r"(^|\s)(emcc|wasm-pack)(\s|$)", lowered)):
                triggers.add("webassembly-compilation")
            if "phpize" in lowered and re.search(r"(^|\s)make(\s|$)", lowered):
                triggers.add("native-extension")
        if re.search(r"python(?:3)?\s+-m\s+py_compile\b", lowered):
            syntax.add("syntax-only:python-py_compile")
        if re.search(r"(?:^|\s)php\s+-l\b", lowered):
            syntax.add("syntax-only:php-lint")
        if re.search(r"(?:^|\s)node\s+--check\b", lowered):
            syntax.add("syntax-only:node--check")

    if "native-extension" in triggers:
        capabilities.add("native-extension")
        artifact_types.add({"node": "native-addon", "python": "native-extension",
                            "php": "native-extension"}.get(family, "shared-library"))
    if "package-build-hook" in triggers and family == "python":
        artifact_types.add("wheel")
    if "package-lifecycle-hook" in triggers and family == "php":
        artifact_types.add("autoload-map")
    if "webassembly-compilation" in triggers or family == "wasm":
        artifact_types.add("wasm")
        capabilities.add("webassembly")
    if "transpilation" in triggers:
        artifact_types.add("generated-javascript")
    if "bundler-build" in triggers:
        artifact_types.add("bundle")
    if triggers:
        capabilities.add("material-build")
    inventory_complete = not gaps and bool(identities)
    language = str(unit.get("language") or family)
    return ProjectProcessingFacts(
        FACTS_SCHEMA, str(unit.get("build_unit_id") or "unknown"), language, family,
        str(unit.get("root") or "."), system, inventory_complete,
        tuple(sorted(triggers)), tuple(sorted(syntax)), tuple(sorted(artifact_types)),
        tuple(sorted(capabilities)), identities,
    )


def source_only_facts(*, project_id: str, language: str, root: str,
                      sources: Iterable[Mapping[str, str]], inventory_complete: bool = True,
                      capabilities: Iterable[str] = ()) -> ProjectProcessingFacts:
    """Create positive, bounded non-build facts for accepted source-only scopes."""
    identities = _sources(tuple(sources))
    return ProjectProcessingFacts(
        FACTS_SCHEMA, project_id, language, language, root, "source-only",
        inventory_complete, (), (f"syntax-only:{language}",), (),
        tuple(sorted(set(capabilities))), identities,
    )


def _decision(*, feature: ProcessingFeature, facts: ProjectProcessingFacts, policy: str,
              configuration_sha256: str, action: ApplicabilityAction,
              disposition: ProcessingDisposition | None, reason: ReasonCode,
              selected: str | None = None,
              inspected_facts: tuple[str, ...] | None = None) -> ApplicabilityDecision:
    inspected = inspected_facts or tuple(sorted({
        f"inventory_complete={str(facts.inventory_complete).lower()}",
        f"family={facts.family}", f"build_system={facts.build_system}",
        *(f"material={value}" for value in facts.material_build_facts),
        *(f"syntax={value}" for value in facts.syntax_only_facts),
        *(f"artifact={value}" for value in facts.artifact_types),
        *(f"capability={value}" for value in facts.capabilities),
    }))
    base = {
        "schema": DECISION_SCHEMA, "feature": feature.value, "project_id": facts.project_id,
        "language": facts.language, "resolved_policy": policy,
        "configuration_sha256": configuration_sha256, "action": action.value,
        "disposition": disposition.value if disposition else None, "reason_code": reason.value,
        "selected_capability": selected, "inspected_facts": inspected,
        "sources": [asdict(item) for item in facts.sources], "decision_sha256": "0" * 64,
    }
    digest = hashlib.sha256(canonical_json(base)).hexdigest()
    return ApplicabilityDecision(
        DECISION_SCHEMA, feature, facts.project_id, facts.language, policy,
        configuration_sha256, action, disposition, reason, selected, inspected,
        facts.sources, digest,
    )


def evaluate_applicability(*, feature: ProcessingFeature, policy: str,
                           facts: ProjectProcessingFacts,
                           configuration_sha256: str) -> ApplicabilityDecision:
    """Evaluate one feature from typed policy and accepted bounded facts."""
    if not _SHA256.fullmatch(configuration_sha256):
        raise ValueError("resolved configuration identity is invalid")
    if policy == "disabled":
        return _decision(feature=feature, facts=facts, policy=policy,
                         configuration_sha256=configuration_sha256,
                         action=ApplicabilityAction.SKIP,
                         disposition=ProcessingDisposition.SKIPPED_POLICY,
                         reason=ReasonCode.POLICY_DISABLED)
    if not facts.inventory_complete:
        return _decision(feature=feature, facts=facts, policy=policy,
                         configuration_sha256=configuration_sha256,
                         action=ApplicabilityAction.GAP, disposition=ProcessingDisposition.GAP,
                         reason=ReasonCode.INVENTORY_UNAVAILABLE)

    if feature is ProcessingFeature.BUILD_CAPTURE:
        if policy == "required":
            return _decision(feature=feature, facts=facts, policy=policy,
                             configuration_sha256=configuration_sha256,
                             action=ApplicabilityAction.RUN, disposition=None,
                             reason=ReasonCode.POLICY_REQUIRED, selected="execution-capture")
        if policy != "auto":
            raise ValueError("build capture policy is unsupported")
        if facts.material_build:
            return _decision(feature=feature, facts=facts, policy=policy,
                             configuration_sha256=configuration_sha256,
                             action=ApplicabilityAction.RUN, disposition=None,
                             reason=ReasonCode.MATERIAL_BUILD_CONFIRMED,
                             selected="execution-capture")
        return _decision(feature=feature, facts=facts, policy=policy,
                         configuration_sha256=configuration_sha256,
                         action=ApplicabilityAction.SKIP,
                         disposition=ProcessingDisposition.SKIPPED_NA,
                         reason=ReasonCode.MATERIAL_BUILD_ABSENT)

    if feature is ProcessingFeature.COMPILER_ARTIFACTS:
        if policy not in {"required", "auto"}:
            raise ValueError("compiler artifact policy is unsupported")
        applicable = facts.material_build and bool(facts.artifact_types)
        if policy == "required" or applicable:
            reason = (ReasonCode.POLICY_REQUIRED if policy == "required"
                      else ReasonCode.ARTIFACT_CAPABILITY_CONFIRMED)
            return _decision(feature=feature, facts=facts, policy=policy,
                             configuration_sha256=configuration_sha256,
                             action=ApplicabilityAction.RUN, disposition=None, reason=reason,
                             selected=",".join(facts.artifact_types) or "declared-artifacts")
        return _decision(feature=feature, facts=facts, policy=policy,
                         configuration_sha256=configuration_sha256,
                         action=ApplicabilityAction.SKIP,
                         disposition=ProcessingDisposition.SKIPPED_NA,
                         reason=ReasonCode.ARTIFACT_CAPABILITY_ABSENT)

    if feature is not ProcessingFeature.CODEQL:
        raise ValueError("processing feature is unsupported")
    if policy == "auto":
        if "codeql-build" in facts.capabilities and facts.material_build:
            selected, reason = "build", ReasonCode.CODEQL_BUILD_SELECTED
        elif "codeql-source" in facts.capabilities:
            selected, reason = "source", ReasonCode.CODEQL_SOURCE_SELECTED
        else:
            return _decision(feature=feature, facts=facts, policy=policy,
                             configuration_sha256=configuration_sha256,
                             action=ApplicabilityAction.SKIP,
                             disposition=ProcessingDisposition.SKIPPED_NA,
                             reason=ReasonCode.CODEQL_NOT_APPLICABLE)
    elif policy in {"build", "source"}:
        selected = policy
        reason = (ReasonCode.CODEQL_BUILD_SELECTED if policy == "build"
                  else ReasonCode.CODEQL_SOURCE_SELECTED)
    else:
        raise ValueError("CodeQL policy is unsupported")
    capability = f"codeql-{selected}"
    if capability not in facts.capabilities:
        return _decision(feature=feature, facts=facts, policy=policy,
                         configuration_sha256=configuration_sha256,
                         action=ApplicabilityAction.GAP, disposition=ProcessingDisposition.GAP,
                         reason=ReasonCode.CAPABILITY_UNSUPPORTED, selected=selected)
    return _decision(feature=feature, facts=facts, policy=policy,
                     configuration_sha256=configuration_sha256,
                     action=ApplicabilityAction.RUN, disposition=None, reason=reason,
                     selected=selected)


def finalize_processing(decision: ApplicabilityDecision, *, succeeded: bool,
                        evidence_complete: bool = True, artifacts_valid: bool = True,
                        toolchain_available: bool = True) -> ApplicabilityDecision:
    """Bind an applicable planned decision to its canonical terminal disposition."""
    if decision.action is not ApplicabilityAction.RUN:
        return decision
    if not toolchain_available:
        reason = ReasonCode.TOOLCHAIN_UNAVAILABLE
    elif not succeeded:
        reason = ReasonCode.PROCESSING_FAILED
    elif not evidence_complete:
        reason = ReasonCode.EVIDENCE_INCOMPLETE
    elif not artifacts_valid:
        reason = ReasonCode.ARTIFACT_VALIDATION_FAILED
    else:
        reason = ReasonCode.PROCESSING_SUCCEEDED
    disposition = (ProcessingDisposition.SUCCEEDED if reason is ReasonCode.PROCESSING_SUCCEEDED
                   else ProcessingDisposition.GAP)
    facts = ProjectProcessingFacts(
        FACTS_SCHEMA, decision.project_id, decision.language, "resolved", ".", "resolved",
        True, (), (), (), (), decision.sources,
    )
    return _decision(
        feature=decision.feature, facts=facts, policy=decision.resolved_policy,
        configuration_sha256=decision.configuration_sha256,
        action=ApplicabilityAction.RUN, disposition=disposition, reason=reason,
        selected=decision.selected_capability, inspected_facts=decision.inspected_facts,
    )
