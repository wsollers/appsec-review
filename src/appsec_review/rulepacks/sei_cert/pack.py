"""Load the SEI CERT rule pack and maintain its content lock.

The pack directory is ``rules/sei-cert``. ``pack.lock.json`` records the SHA-256 of every file in
the pack so the evidence-collection job, evaluations, and reviewers can bind results to the exact
rules, mappings, and fixtures that produced them. Any file the lock does not name is unexpected.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
PACK_ROOT = REPOSITORY_ROOT / "rules" / "sei-cert"
LOCK_NAME = "pack.lock.json"
LOCK_SCHEMA = "appsec-review/sei-cert-rule-pack-lock/1"
MANIFEST_SCHEMA = "appsec-review/sei-cert-rule-pack/1"


class PackError(ValueError):
    """A structural problem that prevents the pack from being loaded."""


def _yaml_module() -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - exercised only without the optional extra
        raise PackError("PyYAML is required to read rule YAML; install the 'rulepacks' extra") from exc
    return yaml


def load_rule_yaml(path: Path) -> Mapping[str, Any]:
    """Parse rule YAML strictly.

    Duplicate keys, non-mapping documents, and YAML anchors, aliases, or merge keys are errors.
    Semgrep CE and OpenGrep both ignore keys that override a ``<<`` merge, so a rule using merges
    would emit different metadata than the validator reads.
    """
    yaml = _yaml_module()
    text = path.read_text(encoding="utf-8")
    try:
        for event in yaml.parse(text):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise PackError(f"{path.name}:{event.start_mark.line + 1}: YAML anchors and aliases are not portable")
            if isinstance(event, yaml.ScalarEvent) and event.value == "<<" and event.style is None:
                raise PackError(f"{path.name}:{event.start_mark.line + 1}: YAML merge keys are not portable")
    except yaml.YAMLError as exc:
        raise PackError(f"{path.name}: malformed YAML: {exc}") from exc

    class StrictLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                raise PackError(f"{path.name}:{key_node.start_mark.line + 1}: duplicate key {key!r}")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

    StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    try:
        document = yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise PackError(f"{path.name}: malformed YAML: {exc}") from exc
    if not isinstance(document, Mapping) or not isinstance(document.get("rules"), list):
        raise PackError(f"{path.name}: expected a mapping with a 'rules' list")
    return document


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackError(f"{path.name}: unreadable JSON: {exc}") from exc


def safe_relative(root: Path, relative: str) -> Path:
    """Resolve a pack-relative path, rejecting absolute, parent, and symlinked components."""
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise PackError(f"unsafe path: {relative!r}")
    candidate = root / pure
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise PackError(f"symlinked path component: {relative!r}")
    if root.resolve() not in candidate.resolve().parents and candidate.resolve() != root.resolve():
        raise PackError(f"path escapes the pack: {relative!r}")
    return candidate


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pack_files(root: Path) -> list[str]:
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file() or path.is_symlink():
            relative = path.relative_to(root).as_posix()
            if relative != LOCK_NAME:
                files.append(relative)
    return files


def tree_digest(entries: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(entries):
        digest.update(relative.encode() + b"\0" + entries[relative].encode() + b"\n")
    return digest.hexdigest()


def compute_lock(root: Path = PACK_ROOT) -> dict[str, Any]:
    manifest = read_json(root / "pack.json")
    files = {}
    for relative in pack_files(root):
        path = root / relative
        if path.is_symlink():
            raise PackError(f"symlinks are not allowed in the pack: {relative}")
        files[relative] = file_digest(path)
    rule_files = {relative: files[relative] for relative in manifest.get("rule_files", []) if relative in files}
    return {
        "schema": LOCK_SCHEMA,
        "pack": manifest.get("id"),
        "version": manifest.get("version"),
        "rule_files_sha256": tree_digest(rule_files),
        "tree_sha256": tree_digest(files),
        "files": files,
    }


def write_lock(root: Path = PACK_ROOT) -> dict[str, Any]:
    lock = compute_lock(root)
    (root / LOCK_NAME).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock


def verify_lock(root: Path = PACK_ROOT) -> list[str]:
    """Return lock problems; an empty list means every pack file matches the lock exactly."""
    path = root / LOCK_NAME
    if not path.is_file():
        return [f"{LOCK_NAME} is missing"]
    recorded = read_json(path)
    errors: list[str] = []
    if recorded.get("schema") != LOCK_SCHEMA:
        errors.append(f"{LOCK_NAME}: unexpected schema")
    try:
        actual = compute_lock(root)
    except PackError as exc:
        return [str(exc)]
    recorded_files = recorded.get("files", {})
    for relative in sorted(set(actual["files"]) - set(recorded_files)):
        errors.append(f"unexpected file not recorded in {LOCK_NAME}: {relative}")
    for relative in sorted(set(recorded_files) - set(actual["files"])):
        errors.append(f"locked file is missing: {relative}")
    for relative in sorted(set(actual["files"]) & set(recorded_files)):
        if actual["files"][relative] != recorded_files[relative]:
            errors.append(f"locked file changed: {relative}")
    for field in ("rule_files_sha256", "tree_sha256", "pack", "version"):
        if not errors and recorded.get(field) != actual[field]:
            errors.append(f"{LOCK_NAME}: {field} does not match the pack contents")
    return errors


@dataclass(frozen=True, slots=True)
class EngineRule:
    rule_id: str
    file: str
    document: Mapping[str, Any]

    @property
    def metadata(self) -> Mapping[str, Any]:
        value = self.document.get("metadata")
        return value if isinstance(value, Mapping) else {}

    @property
    def certs(self) -> tuple[str, ...]:
        primary = self.metadata.get("cert")
        return tuple(item for item in (primary, *self.metadata.get("cert_also", [])) if isinstance(item, str))


@dataclass(frozen=True, slots=True)
class Pack:
    root: Path
    manifest: Mapping[str, Any]
    index: Mapping[str, Any]
    mappings: Mapping[str, Mapping[str, Any]]
    rules: tuple[EngineRule, ...]
    multivuln: Mapping[str, Any]

    @property
    def entries(self) -> dict[str, Mapping[str, Any]]:
        """Mapping entries keyed by unique CERT key."""
        return {entry["key"]: entry for mapping in self.mappings.values() for entry in mapping.get("rules", [])}

    @property
    def entries_by_id(self) -> dict[str, list[Mapping[str, Any]]]:
        result: dict[str, list[Mapping[str, Any]]] = {}
        for entry in self.entries.values():
            result.setdefault(entry["id"], []).append(entry)
        return result

    @property
    def rule_paths(self) -> list[Path]:
        return [self.root / relative for relative in self.manifest.get("rule_files", [])]

    def rules_by_id(self) -> dict[str, EngineRule]:
        return {rule.rule_id: rule for rule in self.rules}


def load_pack(root: Path = PACK_ROOT) -> Pack:
    manifest = read_json(root / "pack.json")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise PackError("pack.json: unexpected schema")
    index = read_json(safe_relative(root, manifest["source_index"]))
    mappings = {language: read_json(safe_relative(root, item["mapping"]))
                for language, item in manifest.get("standards", {}).items()}
    rules: list[EngineRule] = []
    for relative in manifest.get("rule_files", []):
        document = load_rule_yaml(safe_relative(root, relative))
        for item in document["rules"]:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
                raise PackError(f"{relative}: every rule needs a string id")
            rules.append(EngineRule(item["id"], relative, item))
    multivuln = read_json(safe_relative(root, manifest["multivuln"]))
    return Pack(root, manifest, index, mappings, tuple(rules), multivuln)
