"""Dependency normalization, repository identity resolution, and deduplication."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any
from urllib.parse import unquote, urlparse

from appsec_review.jobs.engineering_contracts import ResolutionBasis
from appsec_review.storage import canonical_json


_PUBLIC_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")


def repository_identity(value: object, *, supported_hosts: Sequence[str]) -> dict[str, str] | None:
    """Normalize an HTTPS/git repository URL to a supported public forge identity."""
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    text = value.strip()
    if text.startswith("git@") and ":" in text:
        host, _, path = text[4:].partition(":")
        text = f"https://{host}/{path}"
    if text.startswith("git+"):
        text = text[4:]
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower()
    allowed = {item.lower() for item in supported_hosts}
    if parsed.scheme != "https" or host not in allowed or parsed.username or parsed.password or parsed.port:
        return None
    parts = [unquote(item) for item in parsed.path.strip("/").split("/") if item]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1].removesuffix(".git")
    if not _PUBLIC_REPOSITORY.fullmatch(owner) or not _PUBLIC_REPOSITORY.fullmatch(name):
        return None
    return {"host": host, "owner": owner, "name": name,
            "url": f"https://{host}/{owner}/{name}"}


def _observation_id(record: Mapping[str, Any], source: str) -> str:
    supplied = record.get("observation_id") or record.get("candidate_id")
    return str(supplied) if supplied else source + ":" + hashlib.sha256(canonical_json(record)).hexdigest()[:24]


def normalize_dependencies(
    declared: Sequence[Mapping[str, Any]], packages: Sequence[Mapping[str, Any]],
    native: Sequence[Mapping[str, Any]], *, supported_hosts: Sequence[str], max_dependencies: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Merge all accepted dependency observations into stable dependency records."""
    observations: list[tuple[str, Mapping[str, Any]]] = [
        *(('declared', item) for item in declared), *(('package', item) for item in packages),
        *(('native', item) for item in native),
    ]
    grouped: dict[str, dict[str, Any]] = {}
    gaps: list[str] = []
    for source, raw in observations:
        name = str(raw.get("name") or raw.get("package") or raw.get("native_name") or "").strip()
        purl = str(raw.get("purl") or "").strip() or None
        version = str(raw.get("version") or raw.get("constraint") or "").strip() or None
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
        repository_record = raw.get("repository")
        repo_value = (raw.get("repository_url") or
                      (repository_record.get("url") if isinstance(repository_record, Mapping) else repository_record) or
                      metadata.get("repository_url"))
        repo = repository_identity(repo_value, supported_hosts=supported_hosts)
        key = ("purl:" + purl.casefold() if purl else
               f"name:{name.casefold()}@{(version or '').casefold()}")
        if not name or key == "name:@":
            gaps.append(f"{source} dependency observation has no usable identity")
            continue
        entry = grouped.setdefault(key, {
            "name": name, "version": version, "purl": purl, "repository": repo,
            "resolution_basis": (ResolutionBasis.PACKAGE_METADATA.value if repo else
                                 ResolutionBasis.DECLARED.value if source == "declared" else
                                 ResolutionBasis.LINKER_EVIDENCE.value if source == "native" else
                                 ResolutionBasis.UNRESOLVED.value),
            "exact_repository_identity": bool(repo), "observations": [], "aliases": [],
            "repository_url_observed": str(repo_value)[:4096] if repo_value else None,
        })
        entry["aliases"] = sorted(set([*entry["aliases"], name]))
        if entry["version"] is None and version:
            entry["version"] = version
        if entry["purl"] is None and purl:
            entry["purl"] = purl
        if entry["repository"] is None and repo:
            entry.update(repository=repo, resolution_basis=ResolutionBasis.PACKAGE_METADATA.value,
                         exact_repository_identity=True)
        if entry.get("repository_url_observed") is None and repo_value:
            entry["repository_url_observed"] = str(repo_value)[:4096]
        observation = {"source": source, "evidence_id": _observation_id(raw, source)}
        for key_name in ("source", "location", "path", "component_id", "candidate_id"):
            if raw.get(key_name) is not None:
                observation[key_name] = raw[key_name]
        if observation not in entry["observations"]:
            entry["observations"].append(observation)
        if source == "native":
            entry["native_candidate"] = dict(raw)
    values = []
    for key, item in sorted(grouped.items()):
        item["dependency_id"] = "dependency-" + hashlib.sha256(key.encode()).hexdigest()[:24]
        item["observations"] = sorted(item["observations"], key=lambda value: canonical_json(value))
        values.append(item)
        if len(values) >= max_dependencies:
            if len(grouped) > max_dependencies:
                gaps.append(f"dependency bound exceeded ({max_dependencies})")
            break
    return values, list(dict.fromkeys(gaps))


def apply_model_resolution(dependency: Mapping[str, Any], proposal: Mapping[str, Any], *,
                           supported_hosts: Sequence[str]) -> dict[str, Any]:
    candidate = dependency.get("native_candidate")
    if not isinstance(candidate, Mapping):
        raise ValueError("model proposal has no native candidate")
    if (proposal.get("schema") != "appsec-review/native-dependency-resolution-proposal/1" or
            proposal.get("candidate_id") != candidate.get("candidate_id")):
        raise ValueError("model proposal schema or candidate identity is invalid")
    repository_value = proposal.get("repository")
    repository = repository_identity(repository_value.get("url")
                                     if isinstance(repository_value, Mapping) else None,
                                     supported_hosts=supported_hosts)
    if repository is None:
        raise ValueError("model repository is absent or unsupported")
    if any(str(repository_value.get(key, "")) != repository[key] for key in ("host", "owner", "name", "url")):
        raise ValueError("model repository fields are inconsistent")
    evidence = proposal.get("evidence_refs")
    allowed = {str(item.get("evidence_id")) for item in dependency.get("observations", ())}
    allowed.update(str(item.get("command_id") or item.get("artifact_sha256"))
                   for item in candidate.get("observations", ()) if isinstance(item, Mapping))
    if not isinstance(evidence, list) or not evidence or any(str(item) not in allowed for item in evidence):
        raise ValueError("model proposal cites evidence outside the candidate")
    confidence = proposal.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 0.95:
        raise ValueError("model confidence must be between 0 and 0.95")
    return {**dict(dependency), "repository": repository,
            "resolution_basis": ResolutionBasis.MODEL_INFERENCE.value,
            "exact_repository_identity": False, "resolution_confidence": float(confidence),
            "resolution_evidence_refs": [str(item) for item in evidence],
            "resolution_rationale": str(proposal.get("rationale", ""))[:4096]}


__all__ = ["apply_model_resolution", "normalize_dependencies", "repository_identity"]
