"""Canonical target identity and source revision resolution for target-grouped archival."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any
from urllib.parse import urlparse

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_TARGETS_SCAN = 64
_TARGET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HEX_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ResolvedTargetIdentity:
    target_id: str
    source_revision: str
    repository: str | None
    snapshot_commit: str | None
    source_fingerprint: str | None
    resolution_source: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_target_id(raw: str | None) -> str:
    """Normalize any repository URL, owner/repo slug or label into history's ``_TARGET_ID`` grammar."""
    if not isinstance(raw, str) or not raw.strip():
        return "unknown-target"
    text = raw.strip()
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.path or text
    text = text.rstrip("/")
    if text.lower().endswith(".git"):
        text = text[:-4]
    if "/" in text:
        text = text.split("/")[-1]
    lowered = text.lower()
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", lowered)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = re.sub(r"^[^a-z0-9]+", "", cleaned)
    cleaned = cleaned.rstrip(".-")
    if not cleaned:
        return "unknown-target"
    cleaned = cleaned[:64].rstrip(".-")
    if not cleaned or not _TARGET_ID_RE.match(cleaned):
        return "unknown-target"
    return cleaned


def _normalize_repository(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().rstrip("/")
    if text.lower().endswith(".git"):
        text = text[:-4]
    if "://" in text:
        parsed = urlparse(text)
        slug = (parsed.path or "").strip("/")
        return slug or text
    return text


def _read_bounded_json(path: Path) -> Mapping[str, Any] | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, Mapping) else None


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[Path, Mapping[str, Any]] | None:
    job_dir = run_root / "data" / "jobs" / job_id
    latest = _read_bounded_json(job_dir / "latest.json")
    if latest is not None and isinstance(latest.get("handoff_path"), str):
        handoff_path = run_root / latest["handoff_path"]
        expected_sha = latest.get("handoff_sha256")
        if isinstance(expected_sha, str) and _SHA256_RE.match(expected_sha):
            if _sha256_file(handoff_path) != expected_sha:
                return None
        handoff = _read_bounded_json(handoff_path)
        if handoff is not None:
            return handoff_path, handoff
    direct = _read_bounded_json(job_dir / "handoff.json")
    if direct is not None:
        return job_dir / "handoff.json", direct
    return None


def _handoff_artifacts_matching(run_root: Path, handoff: Mapping[str, Any], suffix: str) -> list[Mapping[str, Any]]:
    matched: list[Mapping[str, Any]] = []
    for item in handoff.get("artifacts", ()) if isinstance(handoff.get("artifacts"), list) else ():
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            continue
        rel = item["path"]
        if not rel.endswith(suffix):
            continue
        target = run_root / rel
        expected_sha = item.get("sha256")
        if isinstance(expected_sha, str) and _SHA256_RE.match(expected_sha):
            if _sha256_file(target) != expected_sha:
                continue
        doc = _read_bounded_json(target)
        if doc is not None:
            matched.append(doc)
    return matched


def _valid_fingerprint(value: Any) -> str | None:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if _SHA256_RE.match(lowered):
            return lowered
    return None


def _valid_commit(value: Any) -> str | None:
    if isinstance(value, str):
        cleaned = value.strip().lower()
        if _HEX_COMMIT_RE.match(cleaned):
            return cleaned
    return None


def _git_head_commit(repo_dir: Path) -> str | None:
    git_entry = repo_dir / ".git"
    if not git_entry.exists():
        return None
    if git_entry.is_dir():
        try:
            head = (git_entry / "HEAD").read_text(encoding="utf-8").strip()
            if _HEX_COMMIT_RE.match(head):
                return head.lower()
            if head.startswith("ref:"):
                ref = head.split(":", 1)[1].strip()
                ref_file = git_entry / ref
                if ref_file.is_file():
                    resolved = ref_file.read_text(encoding="utf-8").strip()
                    if _HEX_COMMIT_RE.match(resolved):
                        return resolved.lower()
                packed = git_entry / "packed-refs"
                if packed.is_file() and packed.stat().st_size <= 1_048_576:
                    for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                        if not line or line.startswith("#") or line.startswith("^"):
                            continue
                        parts = line.split()
                        if len(parts) == 2 and parts[1] == ref and _HEX_COMMIT_RE.match(parts[0]):
                            return parts[0].lower()
        except OSError:
            pass
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if proc.returncode == 0:
            return _valid_commit(proc.stdout)
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def resolve_target_identity(
    run_root: Path,
    *,
    repository_root: Path | None = None,
) -> ResolvedTargetIdentity:
    """Resolve canonical ``target_id`` and ``source_revision`` from accepted run handoffs."""
    run_root = Path(run_root)
    raw_target: str | None = None
    repository: str | None = None
    snapshot_commit: str | None = None
    source_fingerprint: str | None = None
    resolution_source = "fallback_unknown"

    # 1. Inspect accepted job_target_acquisition handoff/artifacts if present.
    acq = _accepted_handoff(run_root, "job_target_acquisition")
    if acq is not None:
        _, acq_handoff = acq
        source_fingerprint = source_fingerprint or _valid_fingerprint(acq_handoff.get("source_fingerprint"))
        docs = [acq_handoff, *_handoff_artifacts_matching(run_root, acq_handoff, "target-acquisition-handoff.json"),
                *_handoff_artifacts_matching(run_root, acq_handoff, "target-acquisition-plan.json")]
        for doc in docs:
            if doc.get("status") == "NOT_REQUESTED" and not doc.get("system_id") and not doc.get("repository"):
                continue
            repo_val = _normalize_repository(doc.get("repository") or doc.get("github_repository"))
            sys_val = doc.get("system_id") if isinstance(doc.get("system_id"), str) and doc.get("system_id") else None
            components = doc.get("components") if isinstance(doc.get("components"), list) else ()
            for comp in components:
                if isinstance(comp, Mapping):
                    repo_val = repo_val or _normalize_repository(
                        comp.get("repository") or comp.get("github_repository") or comp.get("url")
                    )
                    snapshot_commit = snapshot_commit or _valid_commit(
                        comp.get("commit") or comp.get("revision") or comp.get("pinned_revision")
                    )
                    if not sys_val and isinstance(comp.get("name"), str) and comp.get("name"):
                        sys_val = comp["name"]
            if repo_val and repository is None:
                repository = repo_val
            candidate = sys_val or repo_val
            if candidate and raw_target is None:
                raw_target = candidate
                resolution_source = "target_acquisition"

    # 2. Inspect accepted job_source_history_analysis -> binding.json.
    hist = _accepted_handoff(run_root, "job_source_history_analysis")
    binding_docs: list[Mapping[str, Any]] = []
    if hist is not None:
        hist_path, hist_handoff = hist
        source_fingerprint = source_fingerprint or _valid_fingerprint(hist_handoff.get("source_fingerprint"))
        binding_docs.extend(_handoff_artifacts_matching(run_root, hist_handoff, "binding.json"))
        if not binding_docs:
            sibling_binding = _read_bounded_json(hist_path.parent / "binding.json")
            if sibling_binding is not None:
                binding_docs.append(sibling_binding)
    else:
        direct_binding = _read_bounded_json(run_root / "data" / "jobs" / "job_source_history_analysis" / "binding.json")
        if direct_binding is not None:
            binding_docs.append(direct_binding)
    for binding in binding_docs:
        commit_val = _valid_commit(binding.get("snapshot_commit"))
        source_obj = binding.get("source") if isinstance(binding.get("source"), Mapping) else {}
        if commit_val is None:
            commit_val = _valid_commit(source_obj.get("pinned_revision"))
        if commit_val and snapshot_commit is None:
            snapshot_commit = commit_val
        repo_val = _normalize_repository(
            source_obj.get("github_repository") or binding.get("github_repository") or binding.get("repository")
        )
        if repo_val and repository is None:
            repository = repo_val
        if repo_val and raw_target is None:
            raw_target = repo_val
            resolution_source = "source_history_binding"

    # 3. Inspect accepted job_review_intake -> handoff.json (and outcomes.json target_snapshot).
    intake = _accepted_handoff(run_root, "job_review_intake")
    if intake is not None:
        _, intake_handoff = intake
        fp = _valid_fingerprint(intake_handoff.get("source_fingerprint"))
        if fp is None and isinstance(intake_handoff.get("outcomes"), Mapping):
            outcomes_path = intake_handoff["outcomes"].get("path")
            if isinstance(outcomes_path, str):
                outcomes = _read_bounded_json(run_root / outcomes_path)
                if outcomes is not None:
                    fp = _valid_fingerprint(outcomes.get("target_snapshot"))
        if fp is not None:
            source_fingerprint = fp

    if source_fingerprint is None:
        gate = _accepted_handoff(run_root, "job_final_publication_gate")
        if gate is not None:
            source_fingerprint = _valid_fingerprint(gate[1].get("source_fingerprint"))

    # 4. Bounded local targets/ commit check ONLY when target_id is still unknown and snapshot_commit is known.
    if raw_target is None and snapshot_commit is not None:
        targets_root = (Path(repository_root) if repository_root is not None else Path.cwd()) / "targets"
        if targets_root.is_dir():
            try:
                entries = sorted(p for p in targets_root.iterdir() if p.is_dir())[:MAX_TARGETS_SCAN]
            except OSError:
                entries = []
            for candidate_dir in entries:
                head = _git_head_commit(candidate_dir)
                if head and (head == snapshot_commit or head.startswith(snapshot_commit) or snapshot_commit.startswith(head)):
                    raw_target = candidate_dir.name
                    resolution_source = "local_targets_commit_match"
                    break

    if raw_target is None:
        if source_fingerprint is not None:
            raw_target = f"target-{source_fingerprint[:16]}"
            resolution_source = "source_fingerprint"
        elif snapshot_commit is not None:
            raw_target = f"target-{snapshot_commit[:16]}"
            resolution_source = "snapshot_commit"
        else:
            raw_target = "unknown-target"
            resolution_source = "fallback_unknown"

    target_id = normalize_target_id(raw_target)
    source_revision = snapshot_commit or source_fingerprint or "unknown-revision"
    return ResolvedTargetIdentity(
        target_id=target_id,
        source_revision=source_revision,
        repository=repository,
        snapshot_commit=snapshot_commit,
        source_fingerprint=source_fingerprint,
        resolution_source=resolution_source,
    )


__all__ = [
    "ResolvedTargetIdentity",
    "normalize_target_id",
    "resolve_target_identity",
]
