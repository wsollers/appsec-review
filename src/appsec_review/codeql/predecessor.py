"""Explicit DB-only re-admission from an operator-authorized first-party run."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from tempfile import TemporaryDirectory
import time
from typing import Any, Mapping

from appsec_review.observability.spans import count_work, operation_span
from appsec_review.runtime.resources import Reservation, ResourceAdmission
from appsec_review.storage import atomic_json, bounded_file_lock, canonical_json, file_sha256
from appsec_review.storage.shared import reference, safe_path


SCHEMA = "appsec-review/codeql-predecessor-import/1"
JOB = "job_codeql_analysis"


class _Reader:
    def __init__(self, selection):
        self.remaining = selection.metadata_bytes_limit
        self.deadline = time.monotonic() + selection.timeout_seconds
        self.nodes = 0
        self.node_limit = selection.max_files * 4

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("predecessor database re-admission deadline exceeded")

    def seconds_left(self) -> float:
        self.check()
        return max(0, self.deadline - time.monotonic())

    def node(self) -> None:
        self.check()
        self.nodes += 1
        if self.nodes > self.node_limit:
            raise ValueError("predecessor enumeration exceeds its configured bound")

    def document(self, root: Path, relative: str, expected: str | None = None):
        self.check()
        path = safe_path(root, relative)
        if not path.is_file():
            raise ValueError("predecessor metadata is not a regular file")
        with path.open("rb") as stream:
            payload = stream.read(self.remaining + 1)
        if len(payload) > self.remaining:
            raise ValueError("predecessor metadata exceeds its aggregate byte bound")
        self.remaining -= len(payload)
        digest = hashlib.sha256(payload).hexdigest()
        count_work("target_hash_objects")
        count_work("target_hash_bytes", len(payload))
        if expected is not None and digest != expected:
            raise ValueError("predecessor metadata identity changed")
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise ValueError("predecessor metadata must be an object")
        return document, digest

    def payload(self, path: Path, limit: int, destination: Path | None = None) -> str:
        from contextlib import nullcontext
        digest, size = hashlib.sha256(), 0
        with path.open("rb") as source, (
                destination.open("xb") if destination is not None else nullcontext()) as output:
            while True:
                self.check()
                chunk = source.read(min(1024 * 1024, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError("predecessor database payload exceeds its byte bound")
                digest.update(chunk)
                if output is not None:
                    output.write(chunk)
        count_work("target_hash_objects")
        count_work("target_hash_bytes", size)
        if destination is not None:
            count_work("copy_objects")
            count_work("copy_bytes", size)
        return digest.hexdigest()


def _private_store(root: Path) -> None:
    if os.name != "posix" or root.is_symlink() or not root.is_dir():
        raise ValueError("predecessor import requires a private POSIX run store")
    metadata = root.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise ValueError("predecessor run store is not operator-owned private custody")


def _handoff(reader: _Reader, source: Path, selection):
    attempts = safe_path(source, f"data/jobs/{JOB}/attempts")
    matches = []
    with os.scandir(attempts) as entries:
        for entry in entries:
            reader.node()
            if not re.fullmatch(r"attempt_[0-9]{4}", entry.name):
                continue
            relative = f"data/jobs/{JOB}/attempts/{entry.name}/handoff.json"
            path = safe_path(source, relative)
            if not path.is_file():
                continue
            value, digest = reader.document(source, relative)
            if digest == selection.handoff_sha256:
                matches.append((value, relative))
    if len(matches) != 1:
        raise ValueError("predecessor selection requires exactly one matching accepted handoff")
    handoff, path = matches[0]
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED"
            or handoff.get("job_id") != JOB
            or ("run_id" in handoff and handoff["run_id"] != source.name)
            or path != f"data/jobs/{JOB}/attempts/{handoff.get('attempt_id')}/handoff.json"):
        raise ValueError("predecessor handoff is not an accepted CodeQL attempt")
    references = handoff.get("artifacts")
    if (not isinstance(references, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("path"), str)
            or not isinstance(item.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in references)):
        raise ValueError("predecessor handoff artifact references are malformed")
    artifacts = {item["path"]: item for item in references}
    if len(artifacts) != len(references):
        raise ValueError("predecessor handoff repeats artifact identities")
    return handoff, artifacts


def _tree(reader: _Reader, source: Path, database: Path, manifest: Mapping[str, Any],
          *, file_limit: int, bytes_limit: int):
    if manifest.get("schema") != "appsec-review/codeql-database-manifest/1":
        raise ValueError("predecessor database declaration is unsupported")
    declared = manifest.get("files")
    if not isinstance(declared, dict) or not declared or len(declared) > file_limit:
        raise ValueError("predecessor database declaration exceeds its file bound")
    files, directories, total = {}, [], 0

    def visit(directory, depth=0):
        nonlocal total
        if depth > 128:
            raise ValueError("predecessor database directory nesting exceeds its bound")
        with os.scandir(directory) as entries:
            for entry in entries:
                reader.node()
                if entry.is_symlink():
                    raise ValueError("predecessor database contains a symlink")
                path = safe_path(source, Path(entry.path).relative_to(source).as_posix())
                if entry.is_dir(follow_symlinks=False):
                    relative = path.relative_to(database).as_posix()
                    reader.remaining -= len(relative.encode("utf-8")) + 64
                    if reader.remaining < 0:
                        raise ValueError("predecessor directory metadata exceeds its aggregate byte bound")
                    directories.append(relative)
                    visit(path, depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    relative = path.relative_to(database).as_posix()
                    if relative not in declared:
                        raise ValueError("predecessor database contains an undeclared file")
                    size = path.stat().st_size
                    total += size
                    if total > bytes_limit:
                        raise ValueError("predecessor database exceeds its byte bound")
                    digest = reader.payload(path, size)
                    if digest != declared[relative]:
                        raise ValueError("predecessor database content changed")
                    files[relative] = digest
                else:
                    raise ValueError("predecessor database contains a non-regular object")
    visit(database)
    actual = {"schema": manifest["schema"], "files": files, "file_count": len(files), "size_bytes": total,
              "tree_sha256": hashlib.sha256(canonical_json(files)).hexdigest()}
    if actual != manifest:
        raise ValueError("predecessor database differs from its accepted declaration")
    return tuple(directories)


def import_databases(context, expected: Mapping[str, str], *, checkpoint_schema: str,
                     file_limit: int, bytes_limit: int) -> Mapping[str, Any] | None:
    selection = context.review_policy.predecessor_databases
    if selection is None:
        return None
    reader = _Reader(selection)
    lock = safe_path(context.run_root, "data/codeql/predecessor-import.lock")
    with bounded_file_lock(lock, reader.seconds_left()):
        return _import_databases(context, expected, checkpoint_schema=checkpoint_schema,
                                 file_limit=file_limit, bytes_limit=bytes_limit, reader=reader)


def _import_databases(context, expected: Mapping[str, str], *, checkpoint_schema: str,
                      file_limit: int, bytes_limit: int, reader: _Reader) -> Mapping[str, Any] | None:
    policy, destination = context.review_policy, context.run_root
    selection, authority = policy.predecessor_databases, policy.store_authorization
    if selection is None:
        return None
    if authority is None or policy.project_id not in policy.approved_first_party_projects:
        raise ValueError("predecessor import lacks operator first-party store authorization")
    store = Path(authority.runs_root)
    if store.resolve() != destination.parent.resolve() or selection.run_id == destination.name:
        raise ValueError("predecessor import crosses its authorized store or selects the current run")
    _private_store(store)
    source = safe_path(store, selection.run_id)
    _private_store(source)
    if not set(selection.scope_ids) <= expected.keys():
        raise ValueError("predecessor selection contains scopes outside the current accepted plan")
    budget = policy.resources
    with ResourceAdmission(context.metadata_root, budget).reserve(
            Reservation(1, budget.staging_memory_mb), events=context.events, action="codeql.predecessor_import",
            timeout_seconds=reader.seconds_left()) as lease, \
            operation_span(context.events, "codeql.predecessor_import", resource_lease_id=lease):
        handoff, artifacts = _handoff(reader, source, selection)
        original, original_sha = reader.document(
            source, "data/configuration/resolved.json", handoff["resolved_config_sha256"])
        original_policy = original.get("review_policy", {})
        if (original_policy.get("mode") != policy.mode.value
                or original_policy.get("project_id") != policy.project_id
                or policy.project_id not in original_policy.get("approved_first_party_projects", [])
                or original_policy.get("store_authorization") != authority.view()
                or handoff.get("source_fingerprint") != context.source_fingerprint):
            raise ValueError("predecessor project, tenant, assurance or target binding differs")
        claim_path = f"data/jobs/{JOB}/attempts/{handoff['attempt_id']}/claim.json"
        if claim_path not in artifacts:
            raise ValueError("predecessor handoff lacks its original claim")
        claim, _ = reader.document(source, claim_path, artifacts[claim_path]["sha256"])
        if (claim.get("run_id") != source.name or claim.get("job_id") != JOB
                or claim.get("attempt_id") != handoff["attempt_id"]
                or claim.get("attempt_path") != str(Path(claim_path).parent.as_posix())
                or claim.get("source_fingerprint") != context.source_fingerprint
                or claim.get("resolved_config_sha256") != original_sha
                or claim.get("review_policy") != original_policy):
            raise ValueError("predecessor original claim is not bound to its configuration and attempt")
        result_path = handoff["resolving_paths"]["result"]
        if (result_path != f"data/jobs/{JOB}/attempts/{handoff['attempt_id']}/result.json"
                or result_path not in artifacts):
            raise ValueError("predecessor handoff lacks its accepted result")
        result, _ = reader.document(source, result_path, artifacts[result_path]["sha256"])
        databases = {}
        for output in result.get("outputs", {}).values():
            if not isinstance(output, dict):
                continue
            for database in output.get("databases", []):
                scope_id = database.get("scope", {}).get("scope_id")
                if scope_id in databases:
                    raise ValueError("predecessor result repeats a database scope")
                databases[scope_id] = database
        selected, directories, total_files, total_bytes = [], {}, 0, 0
        for scope_id in selection.scope_ids:
            value = databases.get(scope_id)
            if (value is None or value.get("terminal_status") != "SUCCEEDED"
                    or value.get("database_identity") != expected[scope_id]):
                raise ValueError("predecessor selected database is missing, failed or materially incompatible")
            relative = f"data/codeql/scopes/{scope_id}/database-manifest.json"
            ref = value.get("database_manifest")
            if (not isinstance(ref, dict) or ref.get("path") != relative or artifacts.get(relative) != ref):
                raise ValueError("predecessor database declaration is not bound to its handoff")
            manifest, _ = reader.document(source, relative, ref["sha256"])
            if value.get("database_tree_sha256") != manifest.get("tree_sha256"):
                raise ValueError("predecessor database tree identity differs from its declaration")
            for key, limit in (("file_count", min(file_limit, selection.max_files - total_files)),
                               ("size_bytes", min(bytes_limit, selection.max_bytes - total_bytes))):
                if type(manifest.get(key)) is not int or not 0 <= manifest[key] <= limit:
                    raise ValueError("predecessor selection exceeds its aggregate import bounds")
            database = safe_path(source, f"data/codeql/scopes/{scope_id}/database")
            directories[scope_id] = _tree(
                reader, source, database, manifest, file_limit=file_limit, bytes_limit=bytes_limit)
            total_files += manifest["file_count"]
            total_bytes += manifest["size_bytes"]
            if total_files > selection.max_files or total_bytes > selection.max_bytes:
                raise ValueError("predecessor selection exceeds its aggregate import bounds")
            selected.append((scope_id, database, manifest, ref))
        current_claim, _ = reader.document(
            destination, (context.attempt_root / "claim.json").relative_to(destination).as_posix())
        if (current_claim.get("run_id") != destination.name or current_claim.get("job_id") != JOB
                or current_claim.get("attempt_id") != context.attempt_id
                or current_claim.get("source_fingerprint") != context.source_fingerprint
                or current_claim.get("review_policy") != policy.view()):
            raise ValueError("predecessor destination claim binding differs")
        current, current_sha = reader.document(
            destination, "data/configuration/resolved.json", current_claim["resolved_config_sha256"])
        if current.get("review_policy") != policy.view():
            raise ValueError("predecessor selection differs from the current frozen configuration")
        root = safe_path(destination, "data/codeql")
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix=".predecessor-", dir=root) as temporary:
            staged = Path(temporary)
            for scope_id, database, manifest, _ in selected:
                pending = staged / scope_id / "database"
                pending.mkdir(parents=True)
                for relative in directories[scope_id]:
                    reader.check()
                    safe_path(staged, f"{scope_id}/database/{relative}").mkdir(parents=True, exist_ok=True)
                for relative, digest in sorted(manifest["files"].items()):
                    reader.check()
                    source_file = safe_path(source, (database / relative).relative_to(source).as_posix())
                    output = safe_path(staged, f"{scope_id}/database/{relative}")
                    output.parent.mkdir(parents=True, exist_ok=True)
                    if reader.payload(source_file, manifest["size_bytes"], output) != digest:
                        raise ValueError("predecessor database changed during detached copy")
                    output.chmod(stat.S_IMODE(output.stat().st_mode) & ~0o222)
            provenance = {
                "schema": SCHEMA, "source_run_id": source.name, "destination_run_id": destination.name,
                "source_handoff_sha256": selection.handoff_sha256, "source_config_sha256": original_sha,
                "destination_config_sha256": current_sha, "store_authorization": authority.view(),
                "project_id": policy.project_id, "assurance_mode": policy.mode.value,
                "target_snapshot": context.source_fingerprint, "file_count": total_files, "bytes": total_bytes,
                "databases": [{"scope_id": scope_id, "database_identity": expected[scope_id],
                               "source_manifest": ref, "tree_sha256": manifest["tree_sha256"]}
                              for scope_id, _, manifest, ref in selected],
            }
            # Check all destinations before replacing any selected database.
            for scope_id, _, manifest, _ in selected:
                reader.check()
                target = safe_path(destination, f"data/codeql/scopes/{scope_id}")
                if (target / "database").exists():
                    _tree(reader, destination, target / "database", manifest,
                          file_limit=file_limit, bytes_limit=bytes_limit)
            for scope_id, _, manifest, _ in selected:
                reader.check()
                target = safe_path(destination, f"data/codeql/scopes/{scope_id}")
                target.mkdir(parents=True, exist_ok=True)
                if (target / "database").exists():
                    os.replace(target / "database", staged / scope_id / "previous-database")
                try:
                    os.replace(staged / scope_id / "database", target / "database")
                except BaseException:
                    previous = staged / scope_id / "previous-database"
                    if previous.exists():
                        os.replace(previous, target / "database")
                    raise
                atomic_json(target / "database-manifest.json", manifest)
            receipt_path = root / "predecessor-import.json"
            atomic_json(receipt_path, provenance)
            receipt = reference(destination, receipt_path)
            for scope_id, _, _, _ in selected:
                target = root / "scopes" / scope_id
                atomic_json(target / "database-checkpoint.json", {
                    "schema": checkpoint_schema, "identity": expected[scope_id], "terminal_status": "SUCCEEDED",
                    "manifest_sha256": file_sha256(target / "database-manifest.json"), "predecessor_import": receipt,
                })
            reader.check()
        return receipt
