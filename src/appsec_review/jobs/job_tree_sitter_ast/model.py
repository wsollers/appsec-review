from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any, Iterable, Mapping

from appsec_review.retrieval.model import canonical_json


SUPPORTED_LANGUAGES = frozenset({
    "C", "C++", "C/C++", "Rust", "Go", "Java", "JavaScript", "TypeScript",
    "C#", "Python", "PHP", "TSX",
})


@dataclass(frozen=True, slots=True)
class GrammarLock:
    language: str
    grammar: str
    repository: str
    revision: str
    license: str
    artifact: str
    sha256: str


@dataclass(frozen=True, slots=True)
class Scope:
    scope_id: str
    project_id: str
    project_root: str
    translation_scope_id: str
    translation_root: str
    language: str
    files: tuple[Mapping[str, Any], ...]
    exclusions: tuple[Mapping[str, Any], ...] = ()


def _under(path: str, root: str) -> bool:
    return root in {"", "."} or path == root or path.startswith(root.rstrip("/") + "/")


def _slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")[:40]
    return slug or "root"


def plan_scopes(catalog: Mapping[str, Any], *, max_files_per_scope: int = 128,
                max_source_bytes_per_scope: int = 16 * 1024 * 1024) -> tuple[Scope, ...]:
    """Route only accepted inventory files into stable project/language source scopes."""
    files = tuple(item for item in catalog.get("files", ()) if isinstance(item, Mapping))
    components = tuple(item for item in catalog.get("components", ()) if isinstance(item, Mapping))
    if not components:
        components = ({"component_id": "component:0001", "root": "."},)
    translations = tuple(item for item in catalog.get("build_units", ()) if isinstance(item, Mapping))
    buckets: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    metadata: dict[tuple[str, str, str], tuple[str, str]] = {}
    for item in sorted(files, key=lambda value: str(value.get("path", ""))):
        path = str(item.get("path", ""))
        language = item.get("language")
        if not path or language is None or item.get("generated") is True:
            continue
        owners = [component for component in components if _under(path, str(component.get("root", ".")))]
        owner = max(owners, key=lambda value: len(PurePosixPath(str(value.get("root", "."))).parts), default=components[0])
        project_id = str(owner.get("component_id", "component:0001"))
        project_root = str(owner.get("root", "."))
        candidates = [unit for unit in translations if _under(path, str(unit.get("root", "."))) and
                      _under(str(unit.get("root", ".")), project_root)]
        translation = max(candidates, key=lambda value: len(PurePosixPath(str(value.get("root", "."))).parts), default=None)
        translation_id = str(translation.get("build_unit_id")) if translation else f"source:{project_id}"
        translation_root = str(translation.get("root", project_root)) if translation else project_root
        routed_language = "TSX" if path.lower().endswith(".tsx") else str(language)
        key = (project_id, translation_id, routed_language)
        buckets.setdefault(key, []).append(item)
        metadata[key] = (project_root, translation_root)
    exclusions = tuple(item for item in catalog.get("gaps", ()) if isinstance(item, Mapping) and
                       item.get("reason") in {"excluded_directory", "generated_file_excluded", "file_too_large"})
    scopes = []
    if max_files_per_scope < 1 or max_source_bytes_per_scope < 1:
        raise ValueError("scope chunk bounds must be positive")
    for key in sorted(buckets):
        project_id, translation_id, language = key
        project_root, translation_root = metadata[key]
        relevant = tuple(item for item in exclusions if _under(str(item.get("path", "")), translation_root))
        chunks: list[list[Mapping[str, Any]]] = []
        current: list[Mapping[str, Any]] = []
        current_bytes = 0
        for item in buckets[key]:
            size = int(item.get("size_bytes", 0))
            if current and (len(current) >= max_files_per_scope or
                            current_bytes + size > max_source_bytes_per_scope):
                chunks.append(current)
                current, current_bytes = [], 0
            current.append(item)
            current_bytes += size
        if current:
            chunks.append(current)
        for chunk_index, chunk in enumerate(chunks):
            native = {"project": project_id, "translation": translation_id, "language": language,
                      "root": translation_root, "chunk": chunk_index,
                      "files": [{"path": item["path"], "sha256": item["sha256"]} for item in chunk]}
            digest = hashlib.sha256(canonical_json(native)).hexdigest()[:20]
            scopes.append(Scope(
                f"{_slug(project_id)}-{_slug(translation_id)}-{_slug(language)}-{digest}",
                project_id, project_root, translation_id, translation_root, language,
                tuple(chunk), relevant,
            ))
    return tuple(scopes)


def partition_scopes(scopes: Iterable[Scope], locks: Mapping[str, GrammarLock]) -> tuple[tuple[Scope, ...], tuple[Mapping[str, Any], ...]]:
    runnable, gaps = [], []
    for scope in scopes:
        if scope.language not in SUPPORTED_LANGUAGES or scope.language not in locks:
            gaps.append({"scope_id": scope.scope_id, "language": scope.language,
                         "terminal_status": "UNAVAILABLE", "reason": "grammar unavailable",
                         "gaps": [f"{item.get('path')}: {item.get('reason')}"
                                  for item in scope.exclusions]})
        else:
            runnable.append(scope)
    return tuple(runnable), tuple(gaps)


def scope_fingerprint(*, target_snapshot: str, scope: Scope, grammar: GrammarLock,
                      image_id: str, normalizer_schema: str, limits: Mapping[str, int]) -> str:
    return hashlib.sha256(canonical_json({
        "schema": "appsec-review/tree-sitter-scope-fingerprint/1",
        "target_snapshot": target_snapshot,
        "scope": {"scope_id": scope.scope_id, "project_id": scope.project_id,
                  "project_root": scope.project_root, "translation_scope_id": scope.translation_scope_id,
                  "translation_root": scope.translation_root, "language": scope.language,
                  "files": [{"path": item["path"], "sha256": item["sha256"]} for item in scope.files],
                  "exclusions": list(scope.exclusions)},
        "grammar": grammar.__dict__ if hasattr(grammar, "__dict__") else {
            field: getattr(grammar, field) for field in grammar.__slots__
        },
        "image_id": image_id, "normalizer_schema": normalizer_schema, "limits": dict(limits),
    })).hexdigest()
