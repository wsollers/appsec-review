"""Materialize a Perforce depot path at a pinned submitted changelist without a client workspace.

Only read commands run (``info``, ``describe``, ``changes``, ``fstat``, ``print``), so the
acquisition creates no client spec and changes nothing on the server. The ticket is passed to ``p4``
through ``P4PASSWD`` in the child environment only, never on a command line, and target-side
``P4CONFIG``/``P4ENVIRO`` files are ignored. Every printed file is checked against the server's
size and MD5 digest; files whose digest cannot match by construction (keyword expansion, UTF-16 and
unicode translation) are kept and named as gaps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .safety import AcquisitionError, base_environment, run_command, safe_relative


SKIPPED_ACTIONS = {"delete", "move/delete"}
UNAVAILABLE_ACTIONS = {"purge", "archive"}
UNVERIFIABLE_BASE_TYPES = {"unicode", "utf16", "utf8"}
_UNESCAPE = (("%40", "@"), ("%23", "#"), ("%2A", "*"), ("%2a", "*"), ("%25", "%"))


@dataclass(slots=True)
class PerforceResult:
    server: dict[str, Any]
    changelist: int
    effective_change: int | None
    files: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[dict[str, str]] = field(default_factory=list)
    version: str = ""


def unescape_depot(path: str) -> str:
    for escaped, plain in _UNESCAPE:
        path = path.replace(escaped, plain)
    return path


class P4:
    def __init__(self, executable: str, *, port: str, user: str, ticket: str, scratch: Path, timeout: int) -> None:
        scratch.mkdir(parents=True, exist_ok=True)
        enviro = scratch / "p4enviro"
        enviro.write_text("", encoding="utf-8")
        self.env = base_environment()
        self.env.update({"P4PORT": port, "P4USER": user, "P4CONFIG": "", "P4ENVIRO": str(enviro),
                         "P4CLIENT": "appsec-review-no-client", "P4TRUST": str(scratch / "p4trust"),
                         "P4LOGINSSO": ""})
        if ticket:
            self.env["P4PASSWD"] = ticket
            self.env["P4TICKETS"] = str(scratch / "p4tickets")
        self.executable = executable
        self.timeout = timeout
        self.secrets = tuple(item for item in (ticket,) if item)

    def raw(self, *args: str, check: bool = True):
        return run_command([self.executable, *args], env=self.env, cwd=None, timeout=self.timeout,
                           secrets=self.secrets, check=check)

    def tagged(self, *args: str, stdout_limit: int | None = None) -> list[dict[str, Any]]:
        """Run ``p4 -ztag -Mj``; one JSON object per line. Any error record refuses the acquisition."""
        result = run_command([self.executable, "-ztag", "-Mj", *args], env=self.env, cwd=None, timeout=self.timeout,
                             secrets=self.secrets, check=True, stdout_limit=stdout_limit)
        records = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AcquisitionError(f"p4 {args[0]} returned a malformed record") from exc
            if not isinstance(record, dict):
                raise AcquisitionError(f"p4 {args[0]} returned a malformed record")
            if record.get("code") == "error" or record.get("severity") in {3, 4, "3", "4"}:
                message = str(record.get("data") or record.get("generic") or "error").strip()
                raise AcquisitionError(f"p4 {args[0]} reported: {message[:300]}")
            records.append(record)
        return records


def materialize(p4: P4, *, depot_path: str, changelist: int, trust_fingerprint: str, port: str, dest: Path,
                max_files: int, max_total_bytes: int, max_file_bytes: int, max_path_bytes: int) -> PerforceResult:
    version = p4.raw("-V", check=False).stdout.decode("utf-8", "replace").strip().splitlines()
    if trust_fingerprint:
        p4.raw("trust", "-i", trust_fingerprint)
    info = (p4.tagged("info", "-s") or [{}])[0]
    if info.get("unicode") == "enabled":
        p4.env["P4CHARSET"] = "utf8"
    server = {key: info[key] for key in ("serverID", "serverVersion", "serverServices", "caseHandling",
                                         "unicode", "serverAddress") if isinstance(info.get(key), str)}
    describe = p4.tagged("describe", "-s", str(changelist))
    if not describe or str(describe[0].get("change")) != str(changelist):
        raise AcquisitionError(f"changelist {changelist} was not found", status="REFUSED")
    if describe[0].get("status") != "submitted":
        raise AcquisitionError(f"changelist {changelist} is not submitted", status="REFUSED")
    changes = p4.tagged("changes", "-m1", "-s", "submitted", f"{depot_path}@{changelist}")
    effective = int(changes[0]["change"]) if changes and str(changes[0].get("change", "")).isdigit() else None
    if effective is None:
        raise AcquisitionError(f"no submitted change affects {depot_path} at or before @{changelist}", status="REFUSED")
    records = p4.tagged("fstat", "-Ol", "-T", "depotFile,headRev,headType,headAction,headChange,digest,fileSize",
                        f"{depot_path}@{changelist}", stdout_limit=1024 ** 3)
    result = PerforceResult(server=server, changelist=changelist, effective_change=effective,
                            version=version[-1] if version else "")
    prefix = depot_path[:-3]
    dest.mkdir(parents=True, exist_ok=False)
    total = 0
    seen: set[str] = set()
    for record in sorted(records, key=lambda item: str(item.get("depotFile", ""))):
        depot_file = record.get("depotFile")
        if not isinstance(depot_file, str) or not depot_file.startswith(prefix):
            raise AcquisitionError("p4 fstat returned a file outside the configured depot path")
        relative_text = unescape_depot(depot_file[len(prefix):])
        action = str(record.get("headAction", ""))
        if action in SKIPPED_ACTIONS:
            continue
        relative = safe_relative(relative_text, max_bytes=max_path_bytes)
        folded = relative.as_posix().casefold()
        if folded in seen:
            raise AcquisitionError(f"depot paths collide when case-folded: {relative.as_posix()}")
        seen.add(folded)
        if action in UNAVAILABLE_ACTIONS:
            result.gaps.append({"path": relative.as_posix(), "reason": "perforce_revision_unavailable",
                                "detail": f"head action {action}"})
            continue
        file_type = str(record.get("headType", ""))
        base_type, _, modifiers = file_type.partition("+")
        revision = str(record.get("headRev", ""))
        if not revision.isdigit():
            raise AcquisitionError(f"p4 fstat returned no head revision for {relative.as_posix()}")
        if base_type == "symlink":
            result.gaps.append({"path": relative.as_posix(), "reason": "perforce_symlink_skipped"})
            continue
        size_text = str(record.get("fileSize", ""))
        size = int(size_text) if size_text.isdigit() else None
        if size is not None and size > max_file_bytes:
            raise AcquisitionError(f"file exceeds max_file_bytes: {relative.as_posix()}")
        if len(result.files) + 1 > max_files:
            raise AcquisitionError("depot path exceeds max_files")
        target = dest.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.parent.resolve().is_relative_to(dest.resolve()):
            raise AcquisitionError(f"depot path escapes the target: {relative.as_posix()}")
        p4.raw("print", "-q", "-o", str(target), f"{depot_file}#{revision}")
        if target.is_symlink() or not target.is_file():
            raise AcquisitionError(f"p4 print did not produce a regular file for {relative.as_posix()}")
        if os.name != "nt":
            target.chmod(0o755 if "x" in modifiers else 0o644)
        data_size = target.stat().st_size
        if data_size > max_file_bytes:
            raise AcquisitionError(f"file exceeds max_file_bytes: {relative.as_posix()}")
        total += data_size
        if total > max_total_bytes:
            raise AcquisitionError("depot path exceeds max_total_bytes")
        md5 = hashlib.md5(usedforsecurity=False)
        sha256 = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                md5.update(chunk)
                sha256.update(chunk)
        digest = str(record.get("digest", "")).lower()
        unverifiable = "k" in modifiers or base_type in UNVERIFIABLE_BASE_TYPES
        verified = bool(digest) and md5.hexdigest() == digest and (size is None or size == data_size)
        if not verified:
            if unverifiable or not digest:
                result.gaps.append({"path": relative.as_posix(), "reason": "perforce_digest_unverified",
                                    "detail": f"type {file_type}"})
            else:
                raise AcquisitionError(f"printed content does not match the server digest: {relative.as_posix()}")
        result.files.append({"path": relative.as_posix(), "depot_file": depot_file, "revision": int(revision),
                             "change": int(record["headChange"]) if str(record.get("headChange", "")).isdigit() else None,
                             "type": file_type, "size": data_size, "sha256": sha256.hexdigest(),
                             "digest_verified": verified})
    if not result.files:
        raise AcquisitionError(f"{depot_path}@{changelist} contains no files", status="REFUSED")
    return result
