from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
from pathlib import PurePosixPath
from typing import Any

from appsec_review.storage import canonical_json


PLAN_SCHEMA = "appsec-review/codeql-plan/1"
SCOPE_SCHEMA = "appsec-review/codeql-scope/1"

_LANGUAGE_SUFFIXES: Mapping[str, frozenset[str]] = {
    "cpp": frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"}),
    "go": frozenset({".go"}),
    "java": frozenset({".java", ".kt", ".kts"}),
    "csharp": frozenset({".cs"}),
    "javascript": frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}),
    "python": frozenset({".py", ".pyi"}),
    "rust": frozenset({".rs"}),
    "ruby": frozenset({".rb"}),
    "swift": frozenset({".swift"}),
}
_COMPILED_FAMILIES = {"native": "cpp", "go": "go", "java": "java", "dotnet": "csharp"}
_SOURCE_FAMILIES = {"node": "javascript", "python": "python", "rust": "rust"}
_DOTNET_UNSUPPORTED = {".vb": "Visual Basic", ".fs": "F#", ".fsx": "F#"}
_WORKFLOW_PREFIXES = (".github/workflows/",)
_WORKFLOW_SUFFIXES = {".yml", ".yaml"}


def _path(value: object) -> str:
    raw = str(value or "").replace("\\", "/")
    logical = PurePosixPath(raw)
    if not raw or logical.is_absolute() or ".." in logical.parts:
        raise ValueError("CodeQL plan contains an invalid target-relative path")
    return logical.as_posix()


def _under(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root.rstrip("/") + "/")


def _files_for(files: Sequence[Mapping[str, Any]], root: str,
               suffixes: Iterable[str]) -> tuple[dict[str, Any], ...]:
    allowed = set(suffixes)
    selected = []
    for raw in files:
        path = _path(raw.get("path"))
        if _under(path, root) and PurePosixPath(path).suffix.lower() in allowed:
            digest = str(raw.get("sha256", ""))
            if len(digest) != 64:
                raise ValueError("CodeQL source scope is missing an accepted file hash")
            selected.append({"path": path, "sha256": digest, "size_bytes": int(raw.get("size_bytes", 0))})
    return tuple(sorted(selected, key=lambda item: item["path"]))


def _source_labels(language: str, files: Sequence[Mapping[str, Any]]) -> set[str]:
    suffixes = {PurePosixPath(str(item["path"])).suffix.lower() for item in files}
    if language == "java":
        return ({"Java"} if ".java" in suffixes else set()) | (
            {"Kotlin"} if suffixes & {".kt", ".kts"} else set())
    if language == "javascript":
        return ({"JavaScript"} if suffixes & {".js", ".jsx", ".mjs", ".cjs"} else set()) | (
            {"TypeScript"} if suffixes & {".ts", ".tsx", ".mts", ".cts"} else set())
    if language == "cpp":
        return ({"C"} if ".c" in suffixes else set()) | (
            {"C++"} if suffixes & {".cc", ".cpp", ".cxx", ".c++"} else set()) | (
            {"C/C++"} if suffixes & {".h", ".hh", ".hpp", ".hxx"} else set())
    return {{"csharp": "C#", "go": "Go", "python": "Python", "rust": "Rust"}.get(
        language, language)}


def _rust_prerequisite_gaps(files: Sequence[Mapping[str, Any]], root: str) -> tuple[str, ...]:
    names = {PurePosixPath(_path(item.get("path"))).name for item in files
             if _under(_path(item.get("path")), root)}
    gaps = []
    if "Cargo.toml" not in names:
        gaps.append(f"{root}/rust: Cargo.toml prerequisite is absent")
    if "Cargo.lock" not in names:
        gaps.append(f"{root}/rust: Cargo.lock prerequisite is absent; dependency resolution is partial")
    return tuple(gaps)


@dataclass(frozen=True, slots=True)
class CodeQLScope:
    schema: str
    scope_id: str
    language: str
    source_languages: tuple[str, ...]
    mode: str
    root: str
    files: tuple[Mapping[str, Any], ...]
    build_unit_id: str | None
    build_receipt_fingerprint: str | None
    environment_identity: str
    commands_permitted: bool

    def __post_init__(self) -> None:
        if self.schema != SCOPE_SCHEMA or self.mode not in {"manual", "none"}:
            raise ValueError("invalid CodeQL scope contract")
        if self.mode == "none" and self.commands_permitted:
            raise ValueError("CodeQL source/no-build scopes cannot permit commands")
        if self.mode == "manual" and (not self.commands_permitted or not self.build_unit_id):
            raise ValueError("CodeQL manual scopes require an accepted build unit")
        if self.language == "rust" and self.mode != "none":
            raise ValueError("the pinned CodeQL Rust extractor requires source/no-build mode")
        if self.language == "java" and "Kotlin" in self.source_languages and "Java" not in self.source_languages:
            # The extractor id is `java`, but the source coverage must still say Kotlin explicitly.
            object.__setattr__(self, "source_languages", tuple(sorted(set(self.source_languages))))


@dataclass(frozen=True, slots=True)
class CodeQLPlan:
    schema: str
    source_fingerprint: str
    extractor_inventory: tuple[str, ...]
    scopes: tuple[CodeQLScope, ...]
    gaps: tuple[str, ...]
    non_applicable: tuple[Mapping[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "source_fingerprint": self.source_fingerprint,
            "extractor_inventory": list(self.extractor_inventory),
            "scopes": [asdict(scope) for scope in self.scopes],
            "gaps": list(self.gaps),
            "non_applicable": [dict(item) for item in self.non_applicable],
        }


def _environment_identity(receipt: Mapping[str, Any]) -> str:
    image = receipt.get("image")
    if not isinstance(image, Mapping):
        raise ValueError("accepted CodeQL build/source scope has no image identity")
    value = {
        "image_id": image.get("image_id"),
        "recipe_identity": receipt.get("recipe_identity"),
        "dependency_identity": receipt.get("dependency_identity"),
        "workspace_manifest": receipt.get("workspace_manifest"),
    }
    if not isinstance(value["image_id"], str) or not value["image_id"].startswith("sha256:"):
        raise ValueError("accepted CodeQL environment image identity is invalid")
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _scope(*, language: str, source_languages: Iterable[str], mode: str, root: str,
           files: tuple[dict[str, Any], ...], receipt: Mapping[str, Any] | None,
           environment_identity: str) -> CodeQLScope:
    build_unit_id = str(receipt.get("build_unit_id")) if receipt is not None else None
    receipt_fingerprint = str(receipt.get("fingerprint")) if receipt is not None else None
    native = {
        "language": language, "source_languages": sorted(set(source_languages)), "mode": mode,
        "root": root, "files": files, "build_unit_id": build_unit_id,
        "build_receipt_fingerprint": receipt_fingerprint,
        "environment_identity": environment_identity,
    }
    scope_id = "codeql-unit-" + hashlib.sha256(canonical_json(native)).hexdigest()[:24]
    return CodeQLScope(
        SCOPE_SCHEMA, scope_id, language, tuple(native["source_languages"]), mode, root, files,
        build_unit_id, receipt_fingerprint, environment_identity, mode == "manual",
    )


def build_codeql_plan(*, source_fingerprint: str, files: Sequence[Mapping[str, Any]],
                      receipts: Sequence[Mapping[str, Any]], supported_extractors: Iterable[str],
                      source_image_id: str,
                      projects: Sequence[Mapping[str, Any]] = ()) -> CodeQLPlan:
    """Map accepted scopes using the extractor inventory reported by the pinned CLI."""
    inventory = tuple(sorted(set(str(value) for value in supported_extractors)))
    if not source_fingerprint:
        raise ValueError("CodeQL planning requires an accepted snapshot")
    if not source_image_id.startswith("sha256:"):
        raise ValueError("CodeQL source image identity is invalid")
    normalized_files = tuple(dict(item) for item in files)
    gaps: list[str] = []
    scopes: list[CodeQLScope] = []
    covered_paths: set[str] = set()

    seen_build_units: set[str] = set()
    for receipt in sorted(receipts, key=lambda item: str(item.get("build_unit_id", ""))):
        family = str(receipt.get("family", ""))
        if family not in {*_COMPILED_FAMILIES, *_SOURCE_FAMILIES}:
            continue
        build_unit = str(receipt.get("build_unit_id", ""))
        if not build_unit or build_unit in seen_build_units:
            raise ValueError("language-build handoff contains a duplicate CodeQL build unit")
        seen_build_units.add(build_unit)
        language = _COMPILED_FAMILIES.get(family) or _SOURCE_FAMILIES[family]
        root = _path(receipt.get("root"))
        selected = _files_for(normalized_files, root, _LANGUAGE_SUFFIXES[language])
        if not selected:
            continue
        if language not in inventory:
            gaps.append(f"{build_unit}/{language}: pinned runtime did not report the required extractor")
            continue
        if receipt.get("terminal_status") != "SUCCEEDED" or not receipt.get("workspace"):
            gaps.append(f"{build_unit}/{language}: no successful accepted materialized environment")
            continue
        commands = receipt.get("commands")
        if not isinstance(commands, list):
            raise ValueError("accepted language-build command inventory is invalid")
        if family in _COMPILED_FAMILIES and not commands:
            gaps.append(f"{build_unit}/{language}: accepted compiled build has no replayable commands")
            continue
        if language == "rust":
            rust_gaps = _rust_prerequisite_gaps(normalized_files, root)
            if rust_gaps:
                gaps.extend(rust_gaps)
                continue
        source_languages = _source_labels(language, selected)
        mode = "manual" if family in _COMPILED_FAMILIES else "none"
        scopes.append(_scope(language=language, source_languages=source_languages, mode=mode,
                             root=root, files=selected, receipt=receipt,
                             environment_identity=_environment_identity(receipt)))
        covered_paths.update(item["path"] for item in selected)

    # Source/no-build languages remain applicable even when language_build had no command-bearing
    # receipt. Prefer accepted project roots; Python and loose source fall back to one repository
    # scope so every accepted byte is covered exactly once.
    accepted_roots = tuple(sorted({_path(project.get("root")) for project in projects}))
    source_image_identity = source_image_id.removeprefix("sha256:")
    for language in ("javascript", "python", "rust"):
        remaining = tuple(item for item in _files_for(normalized_files, ".", _LANGUAGE_SUFFIXES[language])
                          if item["path"] not in covered_paths)
        if not remaining:
            continue
        if language not in inventory:
            gaps.append(f"{language}: accepted source exists but the runtime reported no extractor")
            continue
        project_roots = tuple(root for root in accepted_roots
                              if any(_under(item["path"], root) for item in remaining))
        loose_roots = tuple(sorted({PurePosixPath(item["path"]).parent.as_posix()
                                    for item in remaining
                                    if not any(_under(item["path"], root) for root in project_roots)}))
        roots = (*project_roots, *loose_roots)
        assigned: set[str] = set()
        for root in roots:
            selected = tuple(item for item in remaining
                             if item["path"] not in assigned and _under(item["path"], root))
            if not selected:
                continue
            source_languages = _source_labels(language, selected)
            if language == "rust":
                rust_gaps = _rust_prerequisite_gaps(normalized_files, root)
                if rust_gaps:
                    gaps.extend(rust_gaps)
                    assigned.update(item["path"] for item in selected)
                    continue
            scopes.append(_scope(language=language, source_languages=source_languages, mode="none",
                                 root=root, files=selected, receipt=None,
                                 environment_identity=source_image_identity))
            assigned.update(item["path"] for item in selected)
        if len(assigned) != len(remaining):
            raise ValueError(f"CodeQL {language} source partition left accepted files unassigned")

    # Actions is a source extractor over accepted workflow bytes and has no build command.
    workflow_files = tuple(sorted(({
        "path": _path(item.get("path")), "sha256": str(item.get("sha256")),
        "size_bytes": int(item.get("size_bytes", 0)),
    } for item in normalized_files if any(_path(item.get("path")).startswith(prefix)
        for prefix in _WORKFLOW_PREFIXES) and PurePosixPath(_path(item.get("path"))).suffix.lower()
        in _WORKFLOW_SUFFIXES), key=lambda item: item["path"]))
    if workflow_files:
        if "actions" in inventory:
            scopes.append(_scope(language="actions", source_languages=("GitHub Actions",), mode="none",
                                 root=".", files=workflow_files, receipt=None,
                                 environment_identity=source_image_id.removeprefix("sha256:")))
        else:
            gaps.append("actions: accepted GitHub Actions workflows exist but the runtime reported no extractor")

    # Do not imply C# coverage for other .NET languages.
    for suffix, name in sorted(_DOTNET_UNSUPPORTED.items()):
        count = sum(PurePosixPath(_path(item.get("path"))).suffix.lower() == suffix for item in normalized_files)
        if count:
            gaps.append(f"{name}: {count} accepted source file(s) are outside CodeQL C# coverage")

    for language, display in (("ruby", "Ruby"), ("swift", "Swift")):
        found = _files_for(normalized_files, ".", _LANGUAGE_SUFFIXES[language])
        if found:
            qualifier = ("extractor is present but no accepted source/build executor and platform capability exists"
                         if language in inventory else "pinned runtime reported no extractor")
            gaps.append(f"{display}: {len(found)} accepted source file(s); {qualifier}")

    non_applicable = (
        {"language": "php", "status": "NOT_APPLICABLE",
         "reason": "PHP is not a CodeQL source language in the pinned runtime"},
        {"language": "wasm", "status": "NOT_APPLICABLE",
         "reason": "raw WebAssembly bytes are not a CodeQL source language; source producers are covered separately"},
    )
    ordered = tuple(sorted(scopes, key=lambda item: (item.language, item.root, item.scope_id)))
    if len(ordered) != len({item.scope_id for item in ordered}):
        raise ValueError("CodeQL plan contains duplicate independent scope identities")
    return CodeQLPlan(PLAN_SCHEMA, source_fingerprint, inventory, ordered,
                      tuple(dict.fromkeys(gaps)), non_applicable)
