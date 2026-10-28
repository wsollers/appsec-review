"""Bounded source discovery; acquisition records take precedence over target-owned metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
from urllib.parse import urlsplit

from appsec_review.jobs.source_lanes import target_path
from .sources import (
    GitSource, MAX_METADATA_BYTES, MAX_SOURCES, _read, locate_git_dir, metadata_roots, resolve_git_source,
)


_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_REVISION = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def github_repository(url: str, api_base: str) -> str | None:
    """Recognize only GitHub's host, or the operator-configured enterprise API's host."""
    api = urlsplit(api_base)
    host = "github.com" if api.hostname == "api.github.com" else api.hostname
    scp = re.fullmatch(r"git@([A-Za-z0-9.-]+):([^?#\\\s]+)", url)
    if scp:
        hostname, path = scp.groups()
    else:
        try:
            parsed = urlsplit(url)
        except ValueError:
            return None
        if (parsed.scheme not in {"https", "ssh"} or parsed.password or parsed.query or parsed.fragment
                or parsed.netloc != (("git@" if parsed.username == "git" else "") + (parsed.hostname or ""))
                or parsed.username not in {None, "git"}):
            return None
        hostname, path = parsed.hostname, parsed.path.lstrip("/")
    path = path.removesuffix(".git")
    return path if hostname and hostname.lower() == host and _REPOSITORY.fullmatch(path) and ".." not in path else None


def origin_url(root: Path) -> str:
    git_dir, _ = locate_git_dir(root)
    if git_dir is None:
        return ""
    data = _read(git_dir / "config") or b""
    section = False
    urls: list[str] = []
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = bool(re.fullmatch(r'\[\s*remote\s+"origin"\s*\]', line, re.I))
        elif section:
            match = re.fullmatch(r'url\s*=\s*"?([^"\\\s]+)"?\s*', line, re.I)
            if match:
                urls.append(match.group(1))
    return urls[0] if len(urls) == 1 else ""


def read_pinned(root: Path, relative: str, digest: str, *, limit: int = MAX_METADATA_BYTES) -> Any:
    path = PurePosixPath(relative)
    if path.is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError("source metadata path is unsafe")
    candidate = root / relative
    resolved = candidate.resolve()
    if root.resolve() not in resolved.parents:
        raise ValueError("source metadata escapes its owner")
    data = _read(candidate, limit)
    if data is None or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("source metadata identity mismatch")
    return json.loads(data)


def _safe_root(target: Path, root: str) -> Path:
    if root == ".":
        return target.resolve()
    path = PurePosixPath(root)
    if path.is_absolute() or "\\" in root or any(part in {"", ".", ".."} for part in root.split("/")):
        raise ValueError("source root is unsafe")
    candidate = target / root
    if target.resolve() not in candidate.resolve().parents or any(
            parent.is_symlink() for parent in (candidate, *candidate.parents)):
        raise ValueError("source root escapes target")
    return candidate


def discover_sources(*, target: Path, repository: Path, acquisition: Mapping[str, Any] | None,
                     components: Sequence[Mapping[str, Any]], api_base: str,
                     acquisition_sha256: str | None = None) -> list[dict[str, Any]]:
    specifications: list[dict[str, Any]] = []
    if acquisition is not None:
        if acquisition.get("schema") == "appsec-review/target-system-acquisition/1":
            entries = acquisition.get("components", {})
            if not isinstance(entries, Mapping) or not entries or len(entries) > MAX_SOURCES:
                raise ValueError("acquisition source count is invalid")
            identifiers = set(entries) | set(acquisition.get("spec", {}).get("components", {}))
            if len(identifiers) > MAX_SOURCES:
                raise ValueError("acquisition source count is invalid")
            for component_id in sorted(identifiers):
                entry = entries.get(component_id, {})
                descriptor = {"source_id": component_id, "component_id": component_id, "root": component_id,
                              "manifest_sha256": entry.get("manifest_sha256")}
                try:
                    manifest = read_pinned(repository, entry["manifest"], entry["manifest_sha256"])
                    expected = acquisition.get("identity", {}).get(component_id, {}).get("identity")
                    if expected is None or manifest.get("identity") != expected:
                        raise ValueError("component identity disagrees with accepted system")
                    if (repository / manifest["target_path"]).resolve() != _safe_root(target, component_id).resolve():
                        raise ValueError("component target path disagrees with accepted system")
                    descriptor["manifest"] = manifest
                except (KeyError, TypeError, OSError, ValueError) as exc:
                    descriptor["gap"] = f"acquisition_source_unavailable:{type(exc).__name__}"
                specifications.append(descriptor)
        elif acquisition.get("schema") == "appsec-review/target-acquisition/1":
            specifications.append({"source_id": acquisition["target_id"], "component_id": acquisition["target_id"],
                                   "root": ".", "manifest": acquisition, "manifest_sha256": acquisition_sha256})
        else:
            raise ValueError("source acquisition schema is unsupported")
    else:
        # Inspect root and catalogued component roots only: never walk the target tree here.
        roots = metadata_roots(target, tuple(str(item["root"]) for item in components))
        found: list[str] = []
        for root in sorted(roots, key=lambda value: (value.count("/"), value)):
            candidate = target / root
            if (candidate / ".git").exists() or (candidate / ".git").is_symlink():
                found.append(root)
        # A root repository owns its nested catalog components; separate nested repositories still
        # get their own lane, with longest-root ownership assigned by the caller.
        for root in found or ["."]:
            component = next((item["component_id"] for item in components if item["root"] == root), None)
            specifications.append({"source_id": root, "component_id": component, "root": root})
    sources = []
    for descriptor in specifications:
        root = descriptor["root"]
        manifest = descriptor.pop("manifest", {})
        identity = manifest.get("identity", {})
        descriptor["identity"] = identity
        descriptor.setdefault("manifest_sha256", None)
        kind = identity.get("kind", "git")
        pinned = identity.get("commit") if kind == "git" else identity.get("revision") if kind == "review_export" else None
        descriptor["pinned_revision"] = pinned
        descriptor["review_export"] = manifest.get("change_context")
        url = manifest.get("spec", {}).get("url") or manifest.get("spec", {}).get("clone_url")
        try:
            source_root = _safe_root(target, root)
            if descriptor.get("gap"):
                git = GitSource("GAP", descriptor["gap"])
            elif kind not in {"git", "review_export"}:
                git = GitSource("GAP", f"history_backend_unsupported:{kind}")
            else:
                git = resolve_git_source(source_root)
                if manifest and (not isinstance(pinned, str) or not _REVISION.fullmatch(pinned)):
                    git = GitSource("GAP", "acquisition_revision_invalid")
                elif manifest and git.decision != "SUCCEEDED":
                    git = GitSource("GAP", f"acquired_git_history_unavailable:{git.reason}")
                elif pinned and git.head_commit != pinned:
                    git = GitSource("GAP", "acquisition_revision_mismatch")
                elif pinned and git.decision == "SUCCEEDED":
                    git = replace(git, snapshot_commit=pinned,
                                  mainline_ref=git.mainline_ref if git.snapshot_commit == pinned else None)
                if git.git_dir:
                    git = replace(git, git_dir=target_path(root, git.git_dir))
                if not manifest:
                    url = origin_url(source_root)
            descriptor["github_repository"] = github_repository(url or "", api_base)
        except (OSError, ValueError) as exc:
            git = GitSource("GAP", f"source_metadata_unreadable:{type(exc).__name__}")
            descriptor["github_repository"] = None
        sources.append({**descriptor, "git": git.as_dict()})
    return sources
