"""Dependency normalization, repository identity resolution, and deduplication."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any
from urllib.parse import unquote, urlparse

from appsec_review.jobs.engineering_contracts import MaximalExposure, ResolutionBasis
from appsec_review.storage import canonical_json


_PUBLIC_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_EXPOSURE_ORDER = tuple(item.value for item in MaximalExposure)
_EXPOSURE_RANK = {value: rank for rank, value in enumerate(_EXPOSURE_ORDER)}
_EXPOSURE_FIELDS = frozenset({
    "category", "configuration", "dependency_group", "dependency_scope", "dependency_type",
    "environment", "location", "path", "profile", "scope", "target", "usage",
})
_EXPOSURE_TERMS = {
    MaximalExposure.DEV.value: frozenset({
        "dev", "development", "developmentonly", "devdependencies", "devdependency",
    }),
    MaximalExposure.DEBUG.value: frozenset({
        "debug", "debugonly", "debugimplementation", "debugcompile", "debugruntime",
    }),
    MaximalExposure.QA.value: frozenset({
        "test", "tests", "testing", "testonly", "testdependencies", "testdependency",
        "testimplementation", "testruntime", "qa", "qualityassurance", "integrationtest",
    }),
    MaximalExposure.PREPROD.value: frozenset({
        "stage", "staging", "preprod", "preproduction", "uat",
    }),
    MaximalExposure.PROD.value: frozenset({
        "dependencies", "dependency", "implementation", "runtime", "runtimeonly", "required",
        "prod", "production", "release",
    }),
}
_RUNTIME_OBSERVATION_KINDS = frozenset({"loader_needed", "soname"})


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


def deduplicate_repositories(dependencies: Sequence[Mapping[str, Any]], *, max_repositories: int
                             ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Group dependencies by canonical forge identity before any remote request is made."""
    if type(max_repositories) is not int or max_repositories < 1:
        raise ValueError("repository bound must be a positive integer")
    grouped: dict[str, dict[str, Any]] = {}
    for dependency in dependencies:
        repository = dependency.get("repository")
        if not isinstance(repository, Mapping):
            continue
        parts = tuple(str(repository.get(field, "")).strip() for field in ("host", "owner", "name"))
        if not all(parts):
            continue
        key = "/".join(part.casefold() for part in parts)
        canonical_repository = {field: value for field, value in zip(("host", "owner", "name"), parts)}
        canonical_repository["url"] = str(repository.get("url") or f"https://{'/'.join(parts)}")
        entry = grouped.setdefault(key, {
            "repository_id": "repository-" + hashlib.sha256(key.encode()).hexdigest()[:24],
            "repository": canonical_repository,
            "dependency_ids": [],
        })
        entry["dependency_ids"].append(str(dependency["dependency_id"]))
    repositories, gaps = [], []
    for index, key in enumerate(sorted(grouped)):
        entry = grouped[key]
        entry["dependency_ids"] = sorted(set(entry["dependency_ids"]))
        if index < max_repositories:
            repositories.append(entry)
        else:
            gaps.extend({"dependency_id": dependency_id, "kind": "repository_bound",
                         "detail": f"repository deduplication bound exceeded ({max_repositories})"}
                        for dependency_id in entry["dependency_ids"])
    return repositories, gaps


def _observation_id(record: Mapping[str, Any], source: str) -> str:
    supplied = record.get("observation_id") or record.get("candidate_id")
    return str(supplied) if supplied else source + ":" + hashlib.sha256(canonical_json(record)).hexdigest()[:24]


def _terms(value: object) -> set[str]:
    """Return bounded normalized terms from a scalar accepted observation field."""
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return set()
    text = str(value)[:4096]
    # Split camelCase before punctuation so manifest keys such as devDependencies remain useful.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    parts = {part.casefold() for part in re.split(r"[^A-Za-z0-9]+", text) if part}
    collapsed = re.sub(r"[^A-Za-z0-9]+", "", str(value)[:4096]).casefold()
    if collapsed:
        parts.add(collapsed)
    return parts


def _classify_field(source: str, evidence_id: str, field: str, value: object,
                    *, basis: str = "structured-scope") -> list[dict[str, str]]:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return []
    terms = _terms(value)
    collapsed = re.sub(r"[^A-Za-z0-9]+", "", str(value)[:4096]).casefold()
    if any(collapsed in vocabulary for vocabulary in _EXPOSURE_TERMS.values()):
        terms = {collapsed}
    evidence: list[dict[str, str]] = []
    for exposure in _EXPOSURE_ORDER:
        matched = sorted(terms & _EXPOSURE_TERMS[exposure])
        if matched:
            evidence.append({
                "exposure": exposure,
                "basis": basis,
                "source": source,
                "evidence_id": evidence_id,
                "field": field,
                "value": str(value)[:4096],
                "matched_term": matched[0],
            })
    return evidence


def infer_maximal_exposure(record: Mapping[str, Any], source: str, *,
                           evidence_id: str | None = None) -> list[dict[str, str]]:
    """Classify bounded, structured exposure evidence from one accepted observation.

    Only named observation fields and native loader kinds are considered. Dependency names,
    versions, repository text, and arbitrary target prose cannot affect the classification.
    """
    identity = evidence_id or _observation_id(record, source)
    evidence: list[dict[str, str]] = []
    for field in sorted(_EXPOSURE_FIELDS):
        if record.get(field) is not None:
            evidence.extend(_classify_field(source, identity, field, record[field]))
    if source == "native":
        for observation in record.get("observations", ()) or ():
            if not isinstance(observation, Mapping):
                continue
            kind = str(observation.get("kind", ""))
            nested_id = str(observation.get("command_id") or observation.get("artifact_sha256") or identity)
            if kind in _RUNTIME_OBSERVATION_KINDS:
                evidence.append({
                    "exposure": MaximalExposure.PROD.value,
                    "basis": "runtime-loader",
                    "source": source,
                    "evidence_id": nested_id,
                    "field": "observations.kind",
                    "value": kind,
                    "matched_term": kind,
                })
            for field in sorted(_EXPOSURE_FIELDS):
                if observation.get(field) is not None:
                    evidence.extend(_classify_field(
                        source, nested_id, f"observations.{field}", observation[field],
                        basis="native-build-configuration"))
    unique = {canonical_json(item): item for item in evidence}
    return [unique[key] for key in sorted(unique)]


def _finalize_exposure(item: dict[str, Any]) -> None:
    evidence = item.pop("_exposure_evidence", [])
    if evidence:
        evidence.sort(key=lambda value: canonical_json(value))
        item["maximal_exposure"] = max(
            (entry["exposure"] for entry in evidence), key=_EXPOSURE_RANK.__getitem__)
        item["exposure_inference_basis"] = "maximum-observed-evidence"
        item["exposure_evidence"] = evidence
    else:
        item["maximal_exposure"] = MaximalExposure.PROD.value
        item["exposure_inference_basis"] = "conservative-default"
        item["exposure_evidence"] = []


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
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
        release = raw.get("release")
        scoped_native = source == "native" and "package_root" in raw and "root_id" in raw
        if source == "native" and isinstance(release, Mapping):
            version = (str(release["value"]) if release.get("status") == "corroborated"
                       and release.get("value") else None)
        else:
            version = str(raw.get("version") or raw.get("constraint") or
                          (metadata.get("version") if source == "native" else "") or "").strip() or None
        repository_record = raw.get("repository")
        repo_value = (raw.get("repository_url") or
                      (repository_record.get("url") if isinstance(repository_record, Mapping) else repository_record) or
                      metadata.get("repository_url"))
        repo = repository_identity(repo_value, supported_hosts=supported_hosts)
        key = ("purl:" + purl if purl else
               f"name:{name.casefold()}@{(version or '').casefold()}")
        if scoped_native:
            key = "native:" + hashlib.sha256(canonical_json(
                (raw["root_id"], raw["package_root"], key))).hexdigest()
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
            "_exposure_evidence": [],
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
        entry["_exposure_evidence"].extend(
            infer_maximal_exposure(raw, source, evidence_id=observation["evidence_id"]))
        for key_name in ("source", "location", "path", "component_id", "candidate_id"):
            if raw.get(key_name) is not None:
                observation[key_name] = raw[key_name]
        if observation not in entry["observations"]:
            entry["observations"].append(observation)
        if source == "native":
            candidates = entry.setdefault("native_candidates", [])
            if dict(raw) not in candidates:
                candidates.append(dict(raw))
            candidates.sort(key=canonical_json)
            entry["native_candidate"] = candidates[0]
    values = []
    for key, item in sorted(grouped.items()):
        unique_exposure = {canonical_json(value): value for value in item["_exposure_evidence"]}
        item["_exposure_evidence"] = [unique_exposure[value] for value in sorted(unique_exposure)]
        _finalize_exposure(item)
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


__all__ = ["apply_model_resolution", "deduplicate_repositories", "infer_maximal_exposure",
           "normalize_dependencies", "repository_identity"]
