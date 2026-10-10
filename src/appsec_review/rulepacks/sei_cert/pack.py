"""Load the SEI CERT rule pack and maintain its content lock.

The pack directory is ``rules/sei-cert``. ``pack.lock.json`` records the SHA-256 of every file in
the pack so the evidence-collection job, evaluations, and reviewers can bind results to the exact
rules, mappings, and fixtures that produced them. Any file the lock does not name is unexpected.

Identity contract (``verify_pack`` is the single strict verifier used by the evidence job, the
validator, and ``verify_lock``):

* Tree entries: every regular file under the pack directory, recursively, excluding only the
  top-level ``pack.lock.json``. Each entry is keyed by its POSIX pack-relative path and valued with
  the lowercase hex SHA-256 of the file's bytes (hashed streaming, without following symlinks).
  Symlinks, FIFOs, sockets, devices, and other non-regular entries anywhere in the pack are errors,
  never silently skipped.
* ``tree_digest``: SHA-256 over the entries sorted by path, each contributing
  ``<path> NUL <sha256hex> LF`` encoded as UTF-8.
* ``tree_sha256`` (``verified_scope: "complete-pack"``): ``tree_digest`` over all tree entries.
  It changes when any rule, mapping, source index, fixture, manifest, document, or license changes,
  or when any file is added or removed.
* ``rule_files_sha256`` (``"executable-rules-subset"``): ``tree_digest`` over only the entries
  listed in ``pack.json`` ``rule_files``, which must equal exactly the files under ``rules/``.
  It identifies the rules handed to engines and is never the complete pack identity.
* ``lock_sha256``: SHA-256 of the ``pack.lock.json`` bytes that were verified.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
PACK_ROOT = REPOSITORY_ROOT / "rules" / "sei-cert"
LOCK_NAME = "pack.lock.json"
LOCK_SCHEMA = "appsec-review/sei-cert-rule-pack-lock/1"
MANIFEST_SCHEMA = "appsec-review/sei-cert-rule-pack/1"
IDENTITY_SCHEMA = "appsec-review/sei-cert-rule-pack-identity/1"
TREE_DIGEST_ALGORITHM = "sha256(sorted(posix-relative-path NUL sha256hex LF))"
LOCK_KEYS = frozenset({"schema", "pack", "version", "rule_files_sha256", "tree_sha256", "files"})
RULES_PREFIX = "rules/"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1024 * 1024


class PackError(ValueError):
    """A structural problem that prevents the pack from being loaded."""


class PackVerificationError(PackError):
    """The pack does not match its lock; ``problems`` lists every finding."""

    def __init__(self, problems: list[str]):
        self.problems = tuple(problems)
        super().__init__("; ".join(self.problems))


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
        data = path.read_bytes()
    except OSError as exc:
        raise PackError(f"{path.name}: unreadable JSON: {exc}") from exc
    return parse_strict_json(data, path.name)


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


def _open_regular(path: Path) -> int:
    """Open ``path`` read-only without following a final symlink and require a regular file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PackError(f"cannot open {path.name} as a regular file: {exc.strerror or exc}") from exc
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PackError(f"{path.name} is not a regular file")
    return descriptor


def _hash_regular(path: Path, *, capture: bool = False) -> tuple[str, bytes | None]:
    """Stream-hash a regular file; optionally keep its bytes so parsing sees exactly what was hashed."""
    digest = hashlib.sha256()
    kept = bytearray() if capture else None
    with os.fdopen(_open_regular(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(_CHUNK), b""):
            digest.update(chunk)
            if kept is not None:
                kept.extend(chunk)
    return digest.hexdigest(), bytes(kept) if kept is not None else None


def file_digest(path: Path) -> str:
    """SHA-256 of a regular file's bytes, streamed; symlinks and special files are errors."""
    return _hash_regular(path)[0]


def _walk(root: Path) -> tuple[dict[str, Path], list[str]]:
    """Return regular files under ``root`` keyed by POSIX relative path, plus structural problems.

    The walk never follows symlinks. Symlinks and non-regular entries are reported, not skipped.
    """
    files: dict[str, Path] = {}
    problems: list[str] = []
    if root.is_symlink() or not root.is_dir():
        return files, [f"pack root is not a real directory: {root}"]

    def visit(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            problems.append(f"unreadable directory {prefix or '.'}: {exc.strerror or exc}")
            return
        for entry in entries:
            relative = prefix + entry.name
            if entry.is_symlink():
                problems.append(f"symlinks are not allowed in the pack: {relative}")
            elif entry.is_dir(follow_symlinks=False):
                visit(Path(entry.path), relative + "/")
            elif entry.is_file(follow_symlinks=False):
                files[relative] = Path(entry.path)
            else:
                problems.append(f"non-regular file is not allowed in the pack: {relative}")

    visit(root, "")
    return files, problems


def pack_files(root: Path) -> list[str]:
    files, problems = _walk(root)
    if problems:
        raise PackVerificationError(problems)
    return sorted(relative for relative in files if relative != LOCK_NAME)


def tree_digest(entries: Mapping[str, str]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(entries):
        digest.update(relative.encode() + b"\0" + entries[relative].encode() + b"\n")
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def parse_strict_json(data: bytes, name: str) -> Any:
    """Parse UTF-8 JSON, rejecting duplicate keys and non-finite numbers."""
    def reject_constant(value: str) -> Any:
        raise PackError(f"non-finite JSON number {value}")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                          parse_constant=reject_constant)
    except PackError as exc:
        raise PackError(f"{name}: {exc}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PackError(f"{name}: unreadable JSON: {exc}") from exc


def _hash_tree(root: Path, files: Mapping[str, Path], problems: list[str],
               capture: frozenset[str] = frozenset()) -> tuple[dict[str, str], dict[str, bytes]]:
    hashes: dict[str, str] = {}
    captured: dict[str, bytes] = {}
    for relative, path in sorted(files.items()):
        try:
            hashes[relative], data = _hash_regular(path, capture=relative in capture)
        except PackError as exc:
            problems.append(f"{relative}: {exc}")
            continue
        if data is not None:
            captured[relative] = data
    return hashes, captured


def compute_lock(root: Path = PACK_ROOT) -> dict[str, Any]:
    files, problems = _walk(root)
    files.pop(LOCK_NAME, None)
    hashes, captured = _hash_tree(root, files, problems, frozenset({"pack.json"}))
    if problems:
        raise PackVerificationError(problems)
    if "pack.json" not in captured:
        raise PackError("pack.json is missing")
    manifest = parse_strict_json(captured["pack.json"], "pack.json")
    if not isinstance(manifest, Mapping):
        raise PackError("pack.json: expected a JSON object")
    rule_list = manifest.get("rule_files", [])
    rule_files = {relative: hashes[relative] for relative in rule_list
                  if isinstance(relative, str) and relative in hashes}
    return {
        "schema": LOCK_SCHEMA,
        "pack": manifest.get("id"),
        "version": manifest.get("version"),
        "rule_files_sha256": tree_digest(rule_files),
        "tree_sha256": tree_digest(hashes),
        "files": hashes,
    }


def write_lock(root: Path = PACK_ROOT) -> dict[str, Any]:
    lock = compute_lock(root)
    (root / LOCK_NAME).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock


def _unsafe_lock_path(relative: object) -> str | None:
    if not isinstance(relative, str) or not relative:
        return "lock path must be a non-empty string"
    if "\\" in relative or "\0" in relative:
        return "lock path contains a backslash or NUL"
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
        return "lock path is absolute or has empty, '.', or '..' components"
    if pure.as_posix() != relative:
        return "lock path is not in canonical POSIX form"
    if relative == LOCK_NAME:
        return "the lock must not record itself"
    return None


@dataclass(frozen=True, slots=True)
class PackIdentity:
    """The verified identity of the complete pack and of its executable-rule subset."""

    pack_id: str
    version: str
    tree_sha256: str
    tree_file_count: int
    rule_files_sha256: str
    rule_file_count: int
    lock_sha256: str
    rules_root: Path

    def as_record(self) -> dict[str, Any]:
        """The identity recorded with evidence and folded into checkpoint identities."""
        return {
            "schema": IDENTITY_SCHEMA,
            "id": self.pack_id,
            "version": self.version,
            "verified": True,
            "verified_scope": "complete-pack",
            "digest_algorithm": TREE_DIGEST_ALGORITHM,
            "tree_sha256": self.tree_sha256,
            "tree_scope": f"complete-pack: every regular file under the pack directory except {LOCK_NAME}",
            "tree_file_count": self.tree_file_count,
            "rule_files_sha256": self.rule_files_sha256,
            "rule_files_scope": "executable-rules-subset: pack.json rule_files (exactly the files under rules/)",
            "rule_file_count": self.rule_file_count,
            "lock_sha256": self.lock_sha256,
        }


def verify_pack(root: Path = PACK_ROOT) -> PackIdentity:
    """Strictly verify every pack file against ``pack.lock.json`` and return the pack identity.

    Raises ``PackVerificationError`` listing every problem found. See the module docstring for the
    exact identity contract.
    """
    problems: list[str] = []
    files, walk_problems = _walk(root)
    problems.extend(walk_problems)
    if LOCK_NAME not in files:
        if not walk_problems or not any(p.endswith(f": {LOCK_NAME}") for p in walk_problems):
            problems.append(f"{LOCK_NAME} is missing")
        raise PackVerificationError(problems)
    lock_path = files.pop(LOCK_NAME)
    try:
        lock_sha256, lock_bytes = _hash_regular(lock_path, capture=True)
        recorded = parse_strict_json(lock_bytes or b"", LOCK_NAME)
    except PackError as exc:
        raise PackVerificationError([*problems, str(exc)]) from exc
    actual, captured = _hash_tree(root, files, problems, frozenset({"pack.json"}))

    # Lock schema.
    if not isinstance(recorded, dict):
        raise PackVerificationError([*problems, f"{LOCK_NAME}: expected a JSON object"])
    if set(recorded) != LOCK_KEYS:
        problems.append(f"{LOCK_NAME}: keys must be exactly {sorted(LOCK_KEYS)}, got {sorted(recorded)}")
    if recorded.get("schema") != LOCK_SCHEMA:
        problems.append(f"{LOCK_NAME}: unexpected schema")
    for field in ("pack", "version"):
        if not isinstance(recorded.get(field), str) or not recorded.get(field):
            problems.append(f"{LOCK_NAME}: {field} must be a non-empty string")
    for field in ("rule_files_sha256", "tree_sha256"):
        if not isinstance(recorded.get(field), str) or not _HEX64.fullmatch(recorded[field]):
            problems.append(f"{LOCK_NAME}: {field} must be a lowercase SHA-256 hex digest")
    recorded_files = recorded.get("files")
    locked: dict[str, str] = {}
    if not isinstance(recorded_files, dict) or not recorded_files:
        problems.append(f"{LOCK_NAME}: files must be a non-empty object")
    else:
        for relative, digest in recorded_files.items():
            reason = _unsafe_lock_path(relative)
            if reason is not None:
                problems.append(f"{LOCK_NAME}: unsafe path {relative!r}: {reason}")
            elif not isinstance(digest, str) or not _HEX64.fullmatch(digest):
                problems.append(f"{LOCK_NAME}: {relative}: digest must be a lowercase SHA-256 hex digest")
            else:
                locked[relative] = digest

    # Per-file comparison.
    for relative in sorted(set(files) - set(locked)):
        problems.append(f"unexpected file not recorded in {LOCK_NAME}: {relative}")
    for relative in sorted(set(locked) - set(files)):
        problems.append(f"locked file is missing: {relative}")
    for relative in sorted(set(actual) & set(locked)):
        if actual[relative] != locked[relative]:
            problems.append(f"locked file changed: {relative}")

    # Manifest: identity and the executable-rule subset.
    manifest: Any = None
    if "pack.json" in captured:
        try:
            manifest = parse_strict_json(captured["pack.json"], "pack.json")
        except PackError as exc:
            problems.append(str(exc))
    elif "pack.json" not in files:
        problems.append("pack.json is missing")
    rule_list: list[str] = []
    if manifest is not None:
        if not isinstance(manifest, dict):
            problems.append("pack.json: expected a JSON object")
            manifest = {}
        if manifest.get("id") != recorded.get("pack"):
            problems.append(f"{LOCK_NAME}: pack does not match pack.json id")
        if manifest.get("version") != recorded.get("version"):
            problems.append(f"{LOCK_NAME}: version does not match pack.json version")
        raw_rules = manifest.get("rule_files")
        if not isinstance(raw_rules, list) or not raw_rules or not all(isinstance(item, str) for item in raw_rules):
            problems.append("pack.json: rule_files must be a non-empty list of paths")
        else:
            rule_list = raw_rules
            if len(set(rule_list)) != len(rule_list):
                problems.append("pack.json: rule_files has duplicate entries")
            under_rules = {relative for relative in files if relative.startswith(RULES_PREFIX)}
            for relative in sorted(set(rule_list) - under_rules):
                problems.append(f"pack.json: rule file is not a file under {RULES_PREFIX}: {relative}")
            for relative in sorted(under_rules - set(rule_list)):
                problems.append(f"pack.json: file under {RULES_PREFIX} is not listed in rule_files: {relative}")
            for relative in sorted(set(rule_list) - set(locked)):
                problems.append(f"pack.json: rule file is not locked: {relative}")

    # Digests: the lock must be internally consistent and match the recomputed pack.
    if locked and len(locked) == len(recorded_files or {}):
        if tree_digest(locked) != recorded.get("tree_sha256"):
            problems.append(f"{LOCK_NAME}: tree_sha256 does not match the locked file entries")
        if rule_list and set(rule_list) <= set(locked) and \
                tree_digest({relative: locked[relative] for relative in rule_list}) != recorded.get("rule_files_sha256"):
            problems.append(f"{LOCK_NAME}: rule_files_sha256 does not match the locked rule entries")
    tree_sha256 = tree_digest(actual)
    rule_files_sha256 = tree_digest({relative: actual[relative] for relative in rule_list if relative in actual})
    if tree_sha256 != recorded.get("tree_sha256"):
        problems.append(f"{LOCK_NAME}: tree_sha256 does not match the pack contents")
    if rule_files_sha256 != recorded.get("rule_files_sha256"):
        problems.append(f"{LOCK_NAME}: rule_files_sha256 does not match the pack contents")
    if problems:
        raise PackVerificationError(list(dict.fromkeys(problems)))
    return PackIdentity(str(recorded["pack"]), str(recorded["version"]), tree_sha256, len(actual),
                        rule_files_sha256, len(rule_list), lock_sha256, root / "rules")


def verify_lock(root: Path = PACK_ROOT) -> list[str]:
    """Return lock problems; an empty list means every pack file matches the lock exactly."""
    try:
        verify_pack(root)
    except PackVerificationError as exc:
        return list(exc.problems)
    except PackError as exc:
        return [str(exc)]
    return []


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
