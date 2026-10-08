"""Immutable happy-path worker for ``01-component-characterization``.

The model performs the bounded semantic judgment; this module owns provenance, source/upstream
identity, citation hashes, independent schema/semantic validation and publication.  The output is
only a static scope/component map and review routing.  It cannot carry findings, severity, runtime
state, compliance verdicts or remediation status.

Dagster/graph/catalog/SAT wiring is intentionally outside this isolated core.
"""
from __future__ import annotations

from copy import deepcopy

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import threading
from typing import Any

from claude_cli_invoker import ClaudeCliInvoker, code_index_pin
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import cwe_catalog
import intake
import model_version_registry as mvr
import persona_dispatch as pd
import persona_invocation as pi
import persona_prompt_assembly as ppa
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import review_cli as rc
from schema_validate import SchemaStore, validate_document
from worker_result import validate_worker_result
import registry_paths

JOB = "01-component-characterization"
DAGSTER_JOB = "component_characterization"
PERSONA_JOB_ID = "f03-components"
TEMPLATE = JOB
CONTRACT = "component-map"
RESULT = "component-purpose-map.json"
SUMMARY = "component-purpose-map.md"
SCHEMA = "appsec-review/component-purpose-map/1.0"
UPSTREAM_JOB = "02-evidence-assembly"
UPSTREAM_MANIFEST = "intel-manifest.json"
EXPECTED_SCOPE_CATEGORIES = {
    "first-party", "vendored", "generated", "test-sample", "documentation", "build-tooling",
}
PROHIBITED_KEYS = {
    "finding", "findings", "verified_finding", "verified_findings", "vulnerability",
    "vulnerabilities", "severity", "cvss", "cvss_score", "runtime_state",
    "runtime_observation", "observed_runtime", "compliance_verdict", "remediation_status",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SCHEMAS = ROOT.parent / "schemas"
INTEL_MANIFEST_SCHEMAS = (
    "intel-manifest.schema.json",
    "intel-manifest-producer.schema.json",
    "intel-manifest-artifact.schema.json",
    "intel-manifest-gap.schema.json",
    "evidence-assembly-terminal-binding.schema.json",
)
ABSENT_SCHEMA_SHA256 = "ABSENT"
CODE_FILES = (
    "component_characterization.py", "persona_dispatch.py", "persona_invocation.py",
    "persona_prompt_assembly.py", "claude_cli_invoker.py", "publish_job_output.py",
    "validate_job_output.py", "cwe_catalog.py", registry_paths.template_rel("01-component-characterization"),
    "personas/roles/component-characterizer/role.json", registry_paths.rel(registry_paths.DOMAINS, "component-characterization"),
    registry_paths.rel(registry_paths.TOOLING_PROFILES, "component-evidence-router"),
    registry_paths.contract_rel("component-map"),
    "01-component-characterization/task-component-characterization.md",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _clock() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target(run_id: str) -> tuple[Path, dict[str, Any]]:
    manifest_path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    manifest = read_json(manifest_path)
    target = manifest.get("target") if isinstance(manifest, dict) else None
    value = target.get("repo_path") if isinstance(target, dict) else None
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    resolved = path.resolve()
    identity = intake.source_identity(str(resolved))
    return resolved, identity


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values["schemas/component-purpose-map.schema.json"] = file_hash(
        SCHEMAS / "component-purpose-map.schema.json")
    for name in INTEL_MANIFEST_SCHEMAS:
        path = SCHEMAS / name
        values[f"schemas/{name}"] = (
            file_hash(path) if path.is_file() and not path.is_symlink() else ABSENT_SCHEMA_SHA256)
    return values


def _manifest_self_sha256(manifest: dict[str, Any]) -> str:
    return "sha256:" + digest({key: value for key, value in manifest.items()
                               if key != "manifest_sha256"})


def _intel_manifest_errors(manifest: Any, *, run_id: str, source_snapshot_sha256: str,
                           attempt: Path, envelope_artifacts: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    """Validate the canonical F02 document, then enforce F03 consumer constraints.

    F03 treats producer payloads as opaque evidence.  It verifies the COMPLETE rendezvous,
    generation/source identity, ordered producer receipts, and every assembly-relative artifact
    against both the manifest and the accepted F02 envelope before exposing those files.
    """
    errors: list[str] = []
    readable: dict[str, str] = {}
    try:
        schema_errors = validate_document(manifest, "intel-manifest.schema.json")
    except FileNotFoundError:
        return ["canonical intel-manifest schema is unavailable; F03 remains blocked on F02"], readable
    if schema_errors:
        return [f"canonical intel-manifest schema failed: {error}" for error in schema_errors], readable
    if manifest.get("run_id") != run_id:
        errors.append("intel manifest run identity differs from the engagement")
    if manifest.get("source_snapshot_sha256") != source_snapshot_sha256:
        errors.append("intel manifest source snapshot differs from the staged target")
    if manifest.get("assembly_status") != "COMPLETE":
        errors.append("intel manifest is not a COMPLETE evidence assembly")
    # intel-manifest/2.0: the terminal generation is the retained terminal-binding.json audit record,
    # hash-bound by the envelope and naming this manifest; it is outside manifest_sha256.
    binding_path = manifest["terminal_binding"]["path"]
    binding_file = _beneath(attempt, binding_path)
    binding = None
    if (binding_file is None or not binding_file.is_file() or binding_file.is_symlink() or
            file_hash(binding_file) != envelope_artifacts.get(binding_path)):
        errors.append("intel manifest terminal binding is not the hash-bound assembly artifact")
    else:
        binding = read_json(binding_file)
        if validate_document(binding, "evidence-assembly-terminal-binding.schema.json"):
            errors.append("intel manifest terminal binding fails its schema")
            binding = None
        elif binding["manifest_sha256"] != manifest.get("manifest_sha256") or binding["run_id"] != run_id:
            errors.append("intel manifest terminal binding names another manifest or run")
            binding = None
        else:
            readable[binding_path] = envelope_artifacts[binding_path]
    if binding is not None:
        terminal_instances = binding["terminal_instances"]
        if terminal_instances["outcome"] != "COMPLETE":
            errors.append("intel manifest terminal instance outcome is not COMPLETE")
        terminal_path = terminal_instances["path"]
        terminal_file = _beneath(attempt, terminal_path)
        terminal_expected = terminal_instances["sha256"]
        if (terminal_file is None or not terminal_file.is_file() or terminal_file.is_symlink() or
                "sha256:" + file_hash(terminal_file) != terminal_expected or
                "sha256:" + envelope_artifacts.get(terminal_path, "") != terminal_expected):
            errors.append("intel manifest terminal instances are not the hash-bound assembly artifact")
        else:
            readable[terminal_path] = envelope_artifacts[terminal_path]
    manifest_sha = manifest.get("manifest_sha256")
    if not isinstance(manifest_sha, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_sha):
        errors.append("intel manifest self hash is malformed")
    elif manifest_sha != _manifest_self_sha256(manifest):
        errors.append("intel manifest self hash does not match its canonical record")

    producers = manifest.get("producers")
    job_ids = [item["job_id"] for item in producers]
    if len(job_ids) != len(set(job_ids)):
        errors.append("intel manifest repeats a producer job id")
    seen_paths: set[str] = set()
    for index, producer in enumerate(producers):
        label = f"producer[{index}]"
        job_id, attempt_id = producer["job_id"], producer["attempt_id"]
        if producer["disposition"] == "missing":
            errors.append(f"{label} is missing from a COMPLETE assembly")
            continue
        if producer["source_snapshot_sha256"] != source_snapshot_sha256:
            errors.append(f"{label} has mixed source lineage")
        disposition = producer["disposition"]
        if disposition == "accepted":
            if producer["execution_status"] not in {"OK", "OK_WITH_GAPS"} or producer["skip_reason"] is not None:
                errors.append(f"{label} accepted disposition conflicts with terminal state")
        elif disposition == "authorized-skip":
            if producer["execution_status"] != "SKIPPED" or not isinstance(producer["skip_reason"], str):
                errors.append(f"{label} authorized skip has no evidenced skip reason")
        elif disposition != "authorized-skip":
            errors.append(f"{label} has an unsupported disposition")
        artifacts = producer["artifacts"]
        for artifact_index, artifact in enumerate(artifacts):
            artifact_label = f"{label}.artifacts[{artifact_index}]"
            path, expected = artifact["path"], artifact["sha256"]
            if artifact["producer_job_id"] != job_id or artifact["producer_attempt_id"] != attempt_id:
                errors.append(f"{artifact_label} producer identity mismatch")
            if not _pattern_ok(artifact["producer_path"]) or not _pattern_ok(path):
                errors.append(f"{artifact_label} path is not normalized and relative")
                continue
            if path in seen_paths:
                errors.append(f"{artifact_label} duplicates an assembly path")
            seen_paths.add(path)
            candidate = _beneath(attempt, path)
            if (candidate is None or not candidate.is_file() or candidate.is_symlink() or
                    "sha256:" + file_hash(candidate) != expected or
                    "sha256:" + envelope_artifacts.get(path, "") != expected):
                errors.append(f"{artifact_label} is not the hash-bound accepted assembly artifact")
            else:
                readable[path] = envelope_artifacts[path]
    return errors, readable


_STANDARDS_CORPUS = re.compile(r"evidence/02-standards-source-ingest/[^/]+/standards/|.*\.records\.jsonl$")


def _accepted_evidence(run_id: str, source_snapshot_sha256: str) -> tuple[Path, dict[str, Any]]:
    base = data_path(run_id, "jobs", UPSTREAM_JOB)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked(f"{JOB}: requires an accepted {UPSTREAM_JOB} result")
    pointer = read_json(pointer_path)
    if (pointer.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            pointer.get("run_id") != run_id or pointer.get("job") != UPSTREAM_JOB or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"}):
        raise Blocked(f"{JOB}: {UPSTREAM_JOB} pointer is not a current accepted result")
    attempt_id = pointer.get("attempt_id")
    if not isinstance(attempt_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}", attempt_id):
        raise Blocked(f"{JOB}: {UPSTREAM_JOB} pointer has an invalid attempt id")
    attempt = base / "attempts" / attempt_id
    envelope_path = attempt / pointer.get("envelope_path", "")
    if (not attempt.is_dir() or attempt.is_symlink() or not envelope_path.is_file() or
            file_hash(envelope_path) != pointer.get("envelope_sha256")):
        raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} attempt or envelope changed")
    envelope = read_json(envelope_path)
    if (validate_worker_result(envelope) or envelope.get("attempt_id") != attempt_id or
            envelope.get("job_id") != UPSTREAM_JOB or envelope.get("run_id") != run_id or
            envelope.get("acceptance_status") != "CURRENT" or
            envelope.get("execution_status") != pointer.get("status") or
            envelope.get("input_fingerprint") != pointer.get("fingerprint") or
            pointer.get("envelope_path") != "result.json" or
            envelope.get("output_contract") != "pregather"):
        raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} envelope is invalid")
    artifacts = envelope.get("artifacts", [])
    envelope_artifacts: dict[str, str] = {}
    for record in artifacts:
        relative = record.get("path") if isinstance(record, dict) else None
        path = _beneath(attempt, relative)
        if path is None or not path.is_file() or path.is_symlink() or file_hash(path) != record.get("sha256"):
            raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} artifact set changed")
        envelope_artifacts[relative] = record["sha256"]
    manifest = attempt / UPSTREAM_MANIFEST
    if (UPSTREAM_MANIFEST not in {item.get("path") for item in artifacts if isinstance(item, dict)} or
            not manifest.is_file() or manifest.is_symlink()):
        raise Blocked(f"{JOB}: accepted {UPSTREAM_JOB} has no {UPSTREAM_MANIFEST}")
    manifest_value = read_json(manifest)
    manifest_errors, readable = _intel_manifest_errors(
        manifest_value, run_id=run_id, source_snapshot_sha256=source_snapshot_sha256,
        attempt=attempt, envelope_artifacts=envelope_artifacts)
    if manifest_errors:
        raise Blocked(f"{JOB}: accepted {UPSTREAM_MANIFEST} is invalid ({len(manifest_errors)} errors)")
    readable[UPSTREAM_MANIFEST] = file_hash(manifest)
    terminal = read_json(attempt / manifest_value["terminal_binding"]["path"])["terminal_instances"]
    # The standards corpus (OWASP/ASVS/STIG/OpenCRE text, ~1.2k files) is reference material for the
    # standards jobs, not evidence about the target; exposing it breaks the persona input ceiling.
    readable = {key: value for key, value in readable.items() if not _STANDARDS_CORPUS.match(key)}
    return attempt, {
        "job": UPSTREAM_JOB, "attempt_id": attempt_id,
        "pointer_sha256": file_hash(pointer_path), "envelope_sha256": file_hash(envelope_path),
        "manifest_sha256": file_hash(manifest),
        "manifest_self_sha256": manifest_value["manifest_sha256"],
        "input_fingerprint": pointer["fingerprint"],
        **manifest_value["generation"],
        "terminal_manifest_sha256": terminal["manifest_sha256"],
        "terminal_instances_path": terminal["path"],
        "terminal_instances_sha256": terminal["sha256"],
        "terminal_instances_manifest_sha256": terminal["manifest_sha256"],
        "producers_sha256": digest(manifest_value["producers"]),
        "artifact_set_sha256": digest(sorted(readable.items())),
        "artifacts": [list(item) for item in sorted(readable.items())],  # JSON-equal to inputs.json
    }


def _stage_evidence(run_id: str, source: Path, evidence: dict[str, Any]) -> Path:
    """Expose only the upstream envelope's published artifacts to the persona.

    Raw tool attempts and logs may coexist under the assembly attempt.  They are deliberately not
    readable inputs merely because they share a parent directory with published evidence.
    """
    artifact_map = dict(evidence["artifacts"])
    stage = root(run_id) / "upstream" / digest({"attempt": evidence["attempt_id"],
                                                  "artifacts": evidence["artifacts"]})[:20]
    stage.mkdir(parents=True, exist_ok=True)
    for relative, expected in artifact_map.items():
        source_path = _beneath(source, relative)
        destination = _beneath(stage, relative)
        if source_path is None or destination is None or not source_path.is_file():
            raise Blocked(f"{JOB}: published upstream artifact path is invalid")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            atomic_bytes(destination, source_path.read_bytes())
        if (not destination.is_file() or destination.is_symlink() or
                file_hash(destination) != expected):
            raise Blocked(f"{JOB}: staged upstream evidence changed")
    present = {path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_file()}
    if present != set(artifact_map):
        raise Blocked(f"{JOB}: staged upstream evidence contains undeclared files")
    return stage


def current_inputs(run_id: str) -> dict[str, Any]:
    target, identity = _target(run_id)
    source_snapshot_sha256 = "sha256:" + identity["fingerprint"]
    evidence_attempt, evidence = _accepted_evidence(run_id, source_snapshot_sha256)
    evidence_root = _stage_evidence(run_id, evidence_attempt, evidence)
    # The accepted 02-code-index summary (graph edge, required): pinned so the profile's code_* tools are
    # granted. Without one the job runs on the evidence lookups and the map records the gap.
    code_index, code_index_gap = code_index_pin(run_id)
    return {
        "job": JOB, "run_id": run_id, "target_root": str(target),
        "target_name": target.name, "source_revision": identity.get("revision"),
        "source_snapshot_sha256": source_snapshot_sha256,
        "evidence_root": str(evidence_root), "evidence": evidence, "code": _code_hashes(),
        "code_index": code_index, "code_index_gap": code_index_gap,
    }


def _beneath(root_path: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts or any(not part for part in pure.parts):
        return None
    path = (root_path / Path(*pure.parts)).resolve()
    try:
        path.relative_to(root_path.resolve())
    except ValueError:
        return None
    return path


def _pattern_ok(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    return ".." not in PurePosixPath(value).parts and not re.match(r"^[A-Za-z]:", value)


def _walk_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace("-", "_") in PROHIBITED_KEYS:
                errors.append(f"{path}.{key}: prohibited conclusion field")
            errors.extend(_walk_keys(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_walk_keys(item, f"{path}[{index}]"))
    return errors


# Component purposes, rationales and notes are commentary: they are not scanned for conclusion
# wording (ADR-0036). A conclusion could only be carried by a PROHIBITED_KEYS field (_walk_keys);
# classifications are the closed schema's enums.


def _citations(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_citations" and isinstance(item, list):
                yield from item
            else:
                yield from _citations(item)
    elif isinstance(value, list):
        for item in value:
            yield from _citations(item)


def _retype_citations(value: dict[str, Any], target_root: Path, evidence_root: Path) -> None:
    """The model sometimes labels a citation with another schema source type (tool_output,
    reference_data, ...). The map accepts only source_file and upstream_lane, and the label is
    derivable: it is whichever root the cited file actually exists beneath. Relabel only when the file
    resolves, and recompute its hash; a citation that resolves nowhere is left for the validator."""
    for citation in _citations(value):
        if not isinstance(citation, dict) or citation.get("source_type") in ("source_file", "upstream_lane"):
            continue
        evidence_first = citation.get("source_type") in ("tool_output", "reference_data", "manual_diagnostic")
        roots = [("upstream_lane", evidence_root), ("source_file", target_root)]
        for source_type, root in (roots if evidence_first else roots[::-1]):
            path = _beneath(root, citation.get("path"))
            if path is not None and path.is_file() and not path.is_symlink():
                citation["source_type"], citation["content_hash"] = source_type, file_hash(path)
                break


_JOB_SEGMENT = re.compile(r"^\d{2}[a-z]?-[a-z0-9][a-z0-9-]*\Z")
_ATTEMPT_SEGMENT = re.compile(r"^[0-9a-f]{32}\Z|^auto-[0-9a-f]{24}\Z|^[0-9A-Za-z][0-9A-Za-z._-]*-[0-9a-f]{12,}\Z")


def _resolve_evidence_paths(value: dict[str, Any], target_root: Path, evidence_root: Path) -> None:
    """An upstream citation names a producer job and a file; the attempt directory and the
    ``evidence/`` prefix are layout. Run 20261001T064759Z-4a8586: the model cited
    ``outputs/02-dev-project-discovery/project-discovery-summary.md`` for
    ``evidence/02-dev-project-discovery/<attempt>/project-discovery-summary.md`` (30 citations), and the
    job failed. A citation that resolves under neither root is rewritten to the evidence file with the
    same job and relative path when exactly one exists; otherwise it is left for the validator."""
    for citation in _citations(value):
        if not isinstance(citation, dict) or not isinstance(citation.get("path"), str):
            continue
        cited = citation["path"]
        for root in (target_root, evidence_root):
            path = _beneath(root, cited)
            if path is not None and path.is_file() and not path.is_symlink():
                break
        else:
            parts = [part for part in cited.replace("\\", "/").split("/") if part]
            index = next((i for i, part in enumerate(parts) if _JOB_SEGMENT.match(part)), None)
            if index is None or index + 1 >= len(parts):
                continue
            job, tail = parts[index], parts[index + 1:]
            if len(tail) > 1 and _ATTEMPT_SEGMENT.match(tail[0]):
                tail = tail[1:]
            job_dir = evidence_root / "evidence" / job
            if not job_dir.is_dir() or job_dir.is_symlink():
                continue
            matches = [candidate for candidate in sorted(job_dir.glob("*/" + "/".join(tail)))
                       if candidate.is_file() and not candidate.is_symlink()
                       and _beneath(evidence_root, candidate.relative_to(evidence_root).as_posix()) is not None]
            if len(matches) == 1:
                citation["path"] = matches[0].relative_to(evidence_root).as_posix()
                citation["source_type"] = "upstream_lane"
                citation["content_hash"] = file_hash(matches[0])


def _backfill_citations(value: Any, target_hashes: dict[str, str], evidence_hashes: dict[str, str]) -> None:
    for citation in _citations(value):
        if not isinstance(citation, dict):
            continue
        table = target_hashes if citation.get("source_type") == "source_file" else (
            evidence_hashes if citation.get("source_type") == "upstream_lane" else {})
        expected = table.get(citation.get("path"))
        if expected:
            citation["content_hash"] = expected.split(":", 1)[-1]


def _manifest_lineage(inputs: dict[str, Any]) -> dict[str, Any]:
    evidence = inputs["evidence"]
    return {
        "producer_job_id": UPSTREAM_JOB, "producer_attempt_id": evidence["attempt_id"],
        "artifact_path": UPSTREAM_MANIFEST,
        "manifest_sha256": "sha256:" + evidence["manifest_sha256"],
        "manifest_self_sha256": evidence["manifest_self_sha256"],
        "envelope_sha256": "sha256:" + evidence["envelope_sha256"],
        "accepted_pointer_sha256": "sha256:" + evidence["pointer_sha256"],
        "input_fingerprint": evidence["input_fingerprint"],
        "generation_sha256": evidence["generation_sha256"],
        "graph_sha256": evidence["graph_sha256"],
        "terminal_manifest_sha256": evidence["terminal_manifest_sha256"],
        "terminal_instances_path": evidence["terminal_instances_path"],
        "terminal_instances_sha256": evidence["terminal_instances_sha256"],
        "terminal_instances_manifest_sha256": evidence["terminal_instances_manifest_sha256"],
        "producers_sha256": "sha256:" + evidence["producers_sha256"],
        "artifact_set_sha256": "sha256:" + evidence["artifact_set_sha256"],
    }


def _slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


def _target_files(target_root: Path) -> set[str]:
    return {path.relative_to(target_root).as_posix() for path in target_root.rglob("*")
            if path.is_file() and not path.is_symlink() and ".git" not in path.relative_to(target_root).parts}


def _glob_regex(pattern: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*"); i += 3
        elif pattern.startswith("**", i):
            out.append(".*"); i += 2
        elif pattern[i] == "*":
            out.append("[^/]*"); i += 1
        elif pattern[i] == "?":
            out.append("[^/]"); i += 1
        else:
            out.append(re.escape(pattern[i])); i += 1
    return re.compile("".join(out) + r"\Z")


def _matches(relative: str, pattern: str) -> bool:
    # Anchored at the repository root. PurePosixPath.match matches from the right,
    # so 'LICENSE' also claimed vendor/x/LICENSE and produced false scope overlaps.
    return _glob_regex(pattern).match(relative) is not None


_LOCATION_LINES = re.compile(r":\d+(?:-\d+)?\Z")


def _location_path(location: str) -> str:
    return _LOCATION_LINES.sub("", location)


def category_coverage_errors(value: dict[str, Any]) -> list[str]:
    """Cross-checks `category_coverage` against the scopes/negative-evidence it cites. The schema
    already guarantees all six expected categories are present in the required classified/absent
    shape (ADR-0013: a prose-only "record the search" instruction let the model silently omit
    'first-party' on every real run; see 01-component-characterization/task-component-characterization.md).
    This only has to check the citation is real and actually matches the category it is cited for --
    a model could otherwise cite a scope classified 'vendored' as satisfying 'first-party'."""
    scope_by_id = {item["scope_id"]: item for item in value["code_scope_classification"]}
    negative_by_id = {item["negative_evidence_id"]: item for item in value["negative_evidence"]}
    errors: list[str] = []
    for category, entry in value["category_coverage"].items():
        if entry["status"] == "classified":
            for scope_id in entry["scope_ids"]:
                scope = scope_by_id.get(scope_id)
                if scope is None:
                    errors.append(f"category_coverage {category!r} cites unresolved scope {scope_id!r}")
                elif scope["classification"] != category:
                    errors.append(f"category_coverage {category!r} cites scope {scope_id!r}, "
                                  f"which is classified {scope['classification']!r}")
        else:
            negative_evidence_id = entry["negative_evidence_id"]
            negative = negative_by_id.get(negative_evidence_id)
            if negative is None:
                errors.append(f"category_coverage {category!r} cites unresolved negative evidence "
                              f"{negative_evidence_id!r}")
            elif negative["category"] != category:
                errors.append(f"category_coverage {category!r} cites negative evidence "
                              f"{negative_evidence_id!r}, which is recorded for category "
                              f"{negative['category']!r}")
    return errors


def validate_payload(value: dict[str, Any], *, target_root: Path,
                     evidence_root: Path | None = None) -> list[str]:
    errors = list(validate_document(value, "component-purpose-map.schema.json"))
    if errors:
        return errors
    errors.extend(_walk_keys(value))

    def unique(items: list[dict[str, Any]], key: str, label: str) -> set[str]:
        ids = [item[key] for item in items]
        if len(ids) != len(set(ids)):
            errors.append(f"{label} identifiers must be unique")
        return set(ids)

    scopes = unique(value["code_scope_classification"], "scope_id", "scope")
    components = unique(value["functional_components"], "component_id", "component")
    relationships = unique(value["component_relationships"], "relationship_id", "relationship")
    groups = unique(value["parallel_review_groups"], "group_id", "parallel review group")
    triggers = unique(value["rescope_triggers"], "trigger_id", "rescope trigger")
    unique(value["unknowns"], "unknown_id", "unknown")
    unique(value["classification_gaps"], "gap_id", "classification gap")
    unique(value["negative_evidence"], "negative_evidence_id", "negative evidence")
    errors.extend(category_coverage_errors(value))
    target_files = _target_files(target_root)
    assignments: dict[str, list[str]] = {path: [] for path in target_files}
    for item in value["code_scope_classification"]:
        matched: set[str] = set()
        for pattern in item["path_patterns"]:
            if not _pattern_ok(pattern):
                errors.append(f"scope {item['scope_id']} has a non-relative path pattern")
                continue
            matched |= {path for path in target_files if _matches(path, pattern)}
        if not matched:
            errors.append(f"scope {item['scope_id']} does not resolve to a target file")
        for path in matched:
            assignments[path].append(item["scope_id"])
    overlapping = sorted(path for path, owners in assignments.items() if len(owners) > 1)
    unassigned = sorted(path for path, owners in assignments.items() if not owners)
    if overlapping:
        errors.append("target files have overlapping scope classifications: " + ", ".join(overlapping))
    gapped_subjects = {item.get("subject") for item in value["classification_gaps"]}
    unassigned = [path for path in unassigned if f"scope:{path}" not in gapped_subjects]
    if unassigned:
        errors.append("target files are not assigned to a physical scope: " + ", ".join(unassigned))
    for item in value["analysis_exclusions"]:
        if item["scope_id"] not in scopes:
            errors.append(f"exclusion scope does not resolve: {item['scope_id']}")
        if item["rescope_trigger_id"] not in triggers:
            errors.append(f"exclusion rescope trigger does not resolve: {item['rescope_trigger_id']}")
    for item in value["functional_components"]:
        if item["component_id"] != _slug(item["name"]):
            errors.append(f"component {item['component_id']} is not the deterministic slug of its name")
        if item["parallel_review_group"] not in groups:
            errors.append(f"component group does not resolve: {item['parallel_review_group']}")
        component_paths: set[str] = set()
        for pattern in item["path_patterns"]:
            if not _pattern_ok(pattern):
                errors.append(f"component {item['component_id']} has a non-relative path pattern")
                continue
            component_paths |= {path for path in target_files if _matches(path, pattern)}
        if not component_paths:
            errors.append(f"component {item['component_id']} has no resolved target paths")
        inside = 0
        for location in item["representative_locations"]:
            location = _location_path(location)
            if not _pattern_ok(location):
                errors.append(f"component {item['component_id']} has a non-relative location")
            elif location in component_paths:
                inside += 1
            elif location not in target_files:
                errors.append(f"component {item['component_id']} representative location is not a target file")
        # A call site elsewhere (src/main.cpp:45) may be representative; one location must be the component's own.
        if item["representative_locations"] and not inside:
            errors.append(f"component {item['component_id']} has no representative location inside its paths")
        ownership = item["ownership"]
        if ownership["kind"] == "unknown" and ownership["responsible_party"] is not None:
            errors.append(f"component {item['component_id']} unknown ownership names a responsible party")
        if ownership["kind"] != "unknown" and not ownership["basis"].strip():
            errors.append(f"component {item['component_id']} ownership has no evidence basis")
    for item in value["component_relationships"]:
        if item["from_component_id"] not in components or item["to_component_id"] not in components:
            errors.append(f"relationship {item['relationship_id']} has an unresolved component")
        expected_id = (f"{item['from_component_id']}--{item['relationship_type']}--"
                       f"{item['to_component_id']}")
        if item["relationship_id"] != expected_id:
            errors.append(f"relationship {item['relationship_id']} does not have its deterministic id")
    for item in value["parallel_review_groups"]:
        missing_components = set(item["component_ids"]) - components
        if missing_components:
            errors.append(f"review group {item['group_id']} has unresolved component ids")
    for item in value["rescope_triggers"]:
        if set(item["affected_scope_ids"]) - scopes:
            errors.append(f"rescope trigger {item['trigger_id']} has unresolved scope ids")
        if set(item["affected_component_ids"]) - components:
            errors.append(f"rescope trigger {item['trigger_id']} has unresolved component ids")
        if (item["invalidation_scope"] == "affected-only" and
                not item["affected_scope_ids"] and not item["affected_component_ids"]):
            errors.append(f"rescope trigger {item['trigger_id']} has an empty affected-only boundary")
    for item in value["unknowns"]:
        if set(item["affected_component_ids"]) - components:
            errors.append(f"unknown {item['unknown_id']} has unresolved component ids")
    tags = [item["tag"] for item in value["tag_cloud"]]
    if tags != sorted(set(tags)):
        errors.append("tag cloud must have unique tags in deterministic lexical order")
    tagged_components: set[str] = set()
    for item in value["tag_cloud"]:
        if item["component_ids"] != sorted(set(item["component_ids"])):
            errors.append(f"tag {item['tag']} component ids are not unique and ordered")
        unresolved = set(item["component_ids"]) - components
        if unresolved:
            errors.append(f"tag {item['tag']} has unresolved component ids")
        tagged_components.update(item["component_ids"])
    gapped = {item["subject"] for item in value["classification_gaps"]}
    untagged = sorted(c for c in components - tagged_components if f"tag_cloud:{c}" not in gapped)
    if untagged:
        errors.append("every component must appear in the tag cloud: " + ", ".join(untagged))
    for citation in _citations(value):
        if not isinstance(citation, dict):
            continue
        source_type, citation_path = citation.get("source_type"), citation.get("path")
        owner = target_root if source_type == "source_file" else (
            evidence_root if source_type == "upstream_lane" else None)
        if owner is None:
            errors.append("component map citations must be source_file or upstream_lane evidence "
                          f"(got source_type={source_type!r} path={citation_path!r})")
            continue
        path = _beneath(owner, citation_path)
        if path is None or not path.is_file() or path.is_symlink():
            errors.append(f"citation does not resolve beneath its evidence root: {citation_path}")
            continue
        if citation.get("content_hash") != file_hash(path):
            errors.append(f"citation content hash is stale: {citation_path}")
    return errors


# Fields Python binds after the reply (``_dispatch_persona``). The model is told to leave them out and
# ``_orchestrator_fill`` sets them before the schema check: run 20261006T150309Z-fdd8d6 failed three
# rounds because the model refused to invent 11 of the 16 lineage hashes it could not read.
ORCHESTRATOR_FIELDS = ("target", "source_revision", "source_snapshot_sha256", "evidence_manifest_lineage")
ORCHESTRATOR_INSTRUCTIONS = (
    "\n\nRuntime note from the orchestrator: the fields " + ", ".join(ORCHESTRATOR_FIELDS) +
    " of component-purpose-map.json are bound by the orchestrator from hash-checked inputs after your "
    "reply. Omit them (or set them to null); never reconstruct or invent their values. Return the single "
    "JSON object with every other required field.")


def _orchestrator_fill(record: dict[str, Any]):
    """fill_result hook: set the Python-owned fields before the reply is validated."""
    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        value = envelope.get(result_field)
        if isinstance(value, dict):
            value.update(target=record["target_name"], source_revision=record["source_revision"],
                         source_snapshot_sha256=record["source_snapshot_sha256"],
                         evidence_manifest_lineage=_manifest_lineage(record))
        return []
    return fill


def _postprocess(value: dict[str, Any], inputs: dict[str, Any]) -> None:
    """The deterministic normalization applied to an accepted reply before independent validation."""
    target_root, evidence_root = Path(inputs["target_root"]), Path(inputs["evidence_root"])
    _normalize_component_ids(value)
    _normalize_tag_cloud(value)
    _retype_citations(value, target_root, evidence_root)
    _resolve_evidence_paths(value, target_root, evidence_root)
    _drop_unresolved_relationships(value)
    _normalize_lanes(value)
    _normalize_references(value)
    _repair_against_target(value, target_root)
    _resolve_security_tags(value)
    _record_untagged_gaps(value)
    if inputs.get("code_index_gap"):
        _gap(value, "gap-code-index-unavailable", "tooling:code_*", inputs["code_index_gap"],
             "Characterization ran on the evidence lookups without the structural code_* query tools.",
             "Publish 02-code-index for this source generation and re-run characterization.")


def _dispatch_persona(run_id: str, allocation: dict[str, Any], record: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any]]:
    attempt, attempt_id = allocation["attempt"], allocation["attempt_id"]
    target_root, evidence_root = Path(record["target_root"]), Path(record["evidence_root"])
    mvr.resolve_run_model_versions(run_id)
    store = SchemaStore()
    template = ppa.load_job_template(TEMPLATE, store)
    budget = template["budget_default"]
    model = rc.resolve_model(TEMPLATE, budget)
    budget_usd = (rc.load_model_config().get("budget_max_usd_per_call") or {}).get(budget)
    request = pd.build_request(
        TEMPLATE, run_id=run_id, job_id=PERSONA_JOB_ID, attempt_id=attempt_id,
        target_root=target_root, source_snapshot_sha256=record["source_snapshot_sha256"],
        now=_clock(), store=store, upstream_root=evidence_root)
    roots = {pd.DEFAULT_READABLE_ROOT: target_root, pd.UPSTREAM_ROOT_ID: evidence_root}
    if record.get("code_index"):
        request["readable_inputs"].append(dict(record["code_index"]))
        roots[record["code_index"]["root"]] = data_path(run_id, "jobs").absolute()
    model_identity = request["model"]
    def extra_validate(result: dict[str, Any]) -> list[str]:
        # The full independent validation runs here, on a post-processed copy, so a structural mistake (run
        # 20261008: overlapping scope classifications) gets a repair round inside the paid call instead of
        # failing the job after the reply was accepted.
        errors = category_coverage_errors(result) + security_tag_errors(result)
        candidate = deepcopy(result)
        try:
            candidate.update(target=record["target_name"], source_revision=record["source_revision"],
                             source_snapshot_sha256=record["source_snapshot_sha256"],
                             evidence_manifest_lineage=_manifest_lineage(record))
            _backfill_citations(candidate,
                {item["path"]: item["sha256"] for item in request["readable_inputs"] if item["root"] == pd.DEFAULT_READABLE_ROOT},
                {item["path"]: item["sha256"] for item in request["readable_inputs"] if item["root"] == pd.UPSTREAM_ROOT_ID})
            _postprocess(candidate, record)
            errors += validate_payload(candidate, target_root=target_root, evidence_root=evidence_root)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            errors.append(f"result could not be normalized for validation: {type(exc).__name__}: {str(exc)[:200]}")
        return list(dict.fromkeys(errors))

    def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
        return rc._dispatch_streaming(argv, prompt + ORCHESTRATOR_INSTRUCTIONS, timeout, transcript)

    runtime = pi.PersonaRuntime(
        invoker=ClaudeCliInvoker(effort=model["effort"], budget_usd=budget_usd, dispatch_fn=dispatch,
                                 fill_result=_orchestrator_fill(record), extra_validate=extra_validate),
        registry_dir=pd.REGISTRY_DIR, prompt_root=ppa.PROMPT_ROOT,
        readable_roots=roots,
        allowed_models=(model_identity,), source_snapshot_sha256=record["source_snapshot_sha256"],
        registry_ceiling=None, clock=_clock, cancel=threading.Event(), stop_grace_seconds=5)
    result = pi.run_invocation(runtime, run_id=run_id, job_id=PERSONA_JOB_ID,
                               attempt_id=attempt_id, attempt_root=attempt, request=request)
    if result["execution_status"] != "OK":
        # Name the cause and where the invoker's reasons are (run 20261001T032047Z-fd64eb recorded only
        # "persona dispatch ended FAILED"; the reasons survived only in an uncleaned /tmp dir).
        raise RuntimeError(
            f"{JOB}: persona dispatch ended {result['execution_status']} (cause {result.get('cause')}); "
            f"rejection reasons, if any: data/llm-transcripts/{PERSONA_JOB_ID}/{attempt_id}/repair-log.json")
    output = attempt / Path(*request["output_root"].split("/"))
    value = read_json(output / RESULT)
    value["target"] = record["target_name"]
    value["source_revision"] = record["source_revision"]
    value["source_snapshot_sha256"] = record["source_snapshot_sha256"]
    value["evidence_manifest_lineage"] = _manifest_lineage(record)
    target_hashes = {item["path"]: item["sha256"] for item in request["readable_inputs"]
                     if item["root"] == pd.DEFAULT_READABLE_ROOT}
    evidence_hashes = {item["path"]: item["sha256"] for item in request["readable_inputs"]
                       if item["root"] == pd.UPSTREAM_ROOT_ID}
    _backfill_citations(value, target_hashes, evidence_hashes)
    summary = (output / SUMMARY).read_text(encoding="utf-8")
    facts = {"budget": budget, "persona": request["persona"], "model": dict(model_identity),
             "persona_result_sha256": result["result_sha256"],
             "artifacts_read": sorted({item["path"] for item in request["readable_inputs"]})}
    return value, summary, facts


def _normalize_component_ids(value: dict[str, Any]) -> None:
    """The id must be the slug of the name; the model sometimes edits one and not the other
    (hello-autotools: 'fixed-buffer-store' named 'Fixed Buffer Store Macro'). Re-derive the id
    from the name and rewrite every reference, so the map stays internally consistent."""
    components = value.get("functional_components") or []
    rename = {c["component_id"]: _slug(c["name"]) for c in components
              if isinstance(c.get("name"), str) and c.get("component_id") != _slug(c["name"])}
    taken = {c.get("component_id") for c in components} - set(rename)
    if not rename or len(set(rename.values())) != len(rename) or set(rename.values()) & taken:
        return  # a collision stays a validation error
    fix = lambda cid: rename.get(cid, cid)
    for c in components:
        c["component_id"] = fix(c["component_id"])
    for r in value.get("component_relationships") or []:
        r["from_component_id"], r["to_component_id"] = fix(r["from_component_id"]), fix(r["to_component_id"])
        r["relationship_id"] = f"{r['from_component_id']}--{r['relationship_type']}--{r['to_component_id']}"
    for key in ("parallel_review_groups", "tag_cloud"):
        for item in value.get(key) or []:
            item["component_ids"] = sorted({fix(c) for c in item.get("component_ids") or []})
    for key in ("rescope_triggers", "unknowns"):
        for item in value.get(key) or []:
            item["affected_component_ids"] = [fix(c) for c in item.get("affected_component_ids") or []]


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _normalize_tag_cloud(value: dict[str, Any]) -> None:
    """The tag cloud must be unique by tag and in lexical order; the model sometimes repeats a tag or
    lists them out of order. Merge repeats (union of components, largest weight, weakest confidence,
    concatenated citations without duplicates) and sort, so ordering is Python's job, not the model's."""
    merged: dict[str, dict[str, Any]] = {}
    for item in value.get("tag_cloud") or []:
        tag = item.get("tag")
        if not isinstance(tag, str):
            continue
        have = merged.get(tag)
        if have is None:
            merged[tag] = {**item, "component_ids": sorted(set(item.get("component_ids") or [])),
                           "evidence_citations": list(item.get("evidence_citations") or [])}
            continue
        have["component_ids"] = sorted(set(have["component_ids"]) | set(item.get("component_ids") or []))
        if isinstance(item.get("weight"), int):
            have["weight"] = max(have.get("weight", 0), item["weight"])
        if _CONFIDENCE_RANK.get(item.get("confidence"), 2) < _CONFIDENCE_RANK.get(have.get("confidence"), 2):
            have["confidence"] = item["confidence"]
        for citation in item.get("evidence_citations") or []:
            if citation not in have["evidence_citations"]:
                have["evidence_citations"].append(citation)
    if "tag_cloud" in value:
        value["tag_cloud"] = [merged[tag] for tag in sorted(merged)]


def _drop_unresolved_relationships(value: dict[str, Any]) -> None:
    """ADR-0013: a relationship whose endpoint is not a characterised component (hello-autotools:
    'writes-to' a /tmp log file) is a classification gap, not a failed map. Drop the edge, keep the map."""
    components = {c.get("component_id") for c in value.get("functional_components") or []}
    kept, gaps = [], value.setdefault("classification_gaps", [])
    have = {g.get("gap_id") for g in gaps}
    seen: set[str] = set()
    for r in value.get("component_relationships") or []:
        if r.get("from_component_id") in components and r.get("to_component_id") in components:
            # The id is derived, never authored (hello 9de8ccea: 'report-runner--writes-to--logger').
            r["relationship_id"] = f"{r['from_component_id']}--{r['relationship_type']}--{r['to_component_id']}"
            if r["relationship_id"] not in seen:
                seen.add(r["relationship_id"])
                kept.append(r)
            continue
        gap_id = f"gap-unresolved-relationship-{r.get('relationship_id')}"
        if gap_id not in have:
            have.add(gap_id)
            gaps.append({
                "gap_id": gap_id,
                "subject": f"component_relationships:{r.get('relationship_id')}",
                "reason": "The model named a relationship endpoint that is not a characterised component.",
                "routing_impact": "This edge is not available to relationship-driven routing.",
                "resolution_action": "Characterise the endpoint as a component or restate the relationship.",
            })
    value["component_relationships"] = kept


def _gap(value: dict[str, Any], gap_id: str, subject: str, reason: str, impact: str, action: str) -> None:
    gaps = value.setdefault("classification_gaps", [])
    if any(g.get("gap_id") == gap_id for g in gaps):
        return
    gaps.append({"gap_id": gap_id, "subject": subject, "reason": reason,
                 "routing_impact": impact, "resolution_action": action})


def _lane_vocabulary() -> dict[str, str]:
    """The closed lane vocabulary: the numbered lane folders and the numbered job-template ids (a
    component may route to a job such as ``02-native-build``), keyed by the id itself and by its name
    without the number when that name is unambiguous."""
    ids = {folder.name for folder in ROOT.iterdir() if folder.is_dir() and re.fullmatch(r"\d\d-[a-z0-9-]+", folder.name)}
    ids |= {path.stem for path in registry_paths.JOB_TEMPLATES_DIR.glob("*.json")
            if re.fullmatch(r"\d\d-[a-z0-9-]+", path.stem)}
    table = {lane: lane for lane in ids}
    names: dict[str, set[str]] = {}
    for lane in ids:
        names.setdefault(lane[3:], set()).add(lane)
    table.update({name: next(iter(lanes)) for name, lanes in names.items() if len(lanes) == 1})
    return table


def _lane_key(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[\s_/]+", "-", value.strip().lower())).strip("-")


def _normalize_lanes(value: dict[str, Any]) -> None:
    """ADR-0013: ``downstream_lanes`` is a closed vocabulary (the lane folders). Map every accepted
    spelling to the lane id, drop repeats, and record any name that is not a lane as a gap. A list
    that would end up empty is left as the model wrote it (the schema needs one lane)."""
    vocabulary = _lane_vocabulary()
    for key, label in (("functional_components", "component_id"), ("parallel_review_groups", "group_id")):
        for item in value.get(key) or []:
            lanes = item.get("downstream_lanes")
            if not isinstance(lanes, list):
                continue
            mapped: list[str] = []
            unknown: list[str] = []
            for lane in lanes:
                found = vocabulary.get(_lane_key(lane)) if isinstance(lane, str) else None
                if found is None:
                    unknown.append(str(lane))
                elif found not in mapped:
                    mapped.append(found)
            if not mapped:
                continue
            item["downstream_lanes"] = mapped
            for name in unknown:
                _gap(value, f"gap-unknown-lane-{_slug(str(item.get(label)))[:60]}-{_slug(name)[:40]}",
                     f"{key}:{item.get(label)}",
                     "The model named a downstream lane that is not in the closed lane vocabulary.",
                     "The named lane is not routed to; the remaining lanes still apply.",
                     "Name the lane by its id (NN-name) in a later pass.")


def _normalize_references(value: dict[str, Any]) -> None:
    """ADR-0013: cross-references and lineage the model keeps getting wrong are derived.

    Exact duplicate list entries are dropped; a component's ``parallel_review_group`` is the source of
    truth for group membership (group ``component_ids`` are rebuilt from it, and a group that a
    component names but the map lacks is created from its components); unresolved ids in rescope
    triggers and unknowns are removed and recorded as gaps; an ``unknown`` ownership never names a party."""
    for key in ("code_scope_classification", "functional_components", "parallel_review_groups",
                "rescope_triggers", "unknowns", "classification_gaps"):
        items, kept = value.get(key), []
        if isinstance(items, list):
            for item in items:
                if item not in kept:
                    kept.append(item)
            value[key] = kept
    components = [c for c in value.get("functional_components") or [] if isinstance(c, dict)]
    component_ids = {c.get("component_id") for c in components}
    for c in components:
        ownership = c.get("ownership")
        if isinstance(ownership, dict) and ownership.get("kind") == "unknown":
            ownership["responsible_party"] = None
    groups = value.get("parallel_review_groups")
    if isinstance(groups, list):
        by_id = {g.get("group_id"): g for g in groups if isinstance(g, dict)}
        for c in components:
            gid = c.get("parallel_review_group")
            if isinstance(gid, str) and gid not in by_id and re.fullmatch(r"[a-z0-9][a-z0-9-]*", gid):
                members = [m for m in components if m.get("parallel_review_group") == gid]
                lanes = sorted({lane for m in members for lane in m.get("downstream_lanes") or []})
                if lanes:
                    by_id[gid] = {"group_id": gid, "component_ids": sorted(m["component_id"] for m in members),
                                  "downstream_lanes": lanes,
                                  "rationale": "Group derived from the parallel_review_group its components name."}
                    groups.append(by_id[gid])
                    _gap(value, f"gap-derived-group-{gid}", f"parallel_review_groups:{gid}",
                         "The model assigned components to a review group it did not define.",
                         "The group's lanes are the union of its components' lanes.",
                         "Review the derived group definition in a later pass.")
        for gid, group in by_id.items():
            members = sorted(m["component_id"] for m in components if m.get("parallel_review_group") == gid)
            if members:
                group["component_ids"] = members
            else:
                group["component_ids"] = sorted(set(group.get("component_ids") or []) & component_ids) \
                    or group.get("component_ids") or []
    scope_ids = {s.get("scope_id") for s in value.get("code_scope_classification") or [] if isinstance(s, dict)}
    for key, id_key, fields in (
            ("rescope_triggers", "trigger_id", (("affected_scope_ids", scope_ids), ("affected_component_ids", component_ids))),
            ("unknowns", "unknown_id", (("affected_component_ids", component_ids),))):
        for item in value.get(key) or []:
            for field, known in fields:
                have = item.get(field)
                if not isinstance(have, list):
                    continue
                item[field] = [i for i in have if i in known]
                if len(item[field]) != len(have):
                    _gap(value, f"gap-unresolved-{key}-{_slug(str(item.get(id_key)))[:60]}-{field}",
                         f"{key}:{item.get(id_key)}",
                         f"The model named {field} that do not resolve in this map.",
                         "The unresolved references are removed from this entry.",
                         "Characterise the missing scope or component in a later pass.")


def _repair_against_target(value: dict[str, Any], target_root: Path) -> None:
    """ADR-0013 repairs that need the file list (freeciv21 a63ffa38): order tag ids, drop
    representative locations that are not target files, and record files no scope claims as gaps."""
    target_files = _target_files(target_root)
    for item in value.get("tag_cloud") or []:
        item["component_ids"] = sorted(set(item.get("component_ids") or []))
    for item in value.get("functional_components") or []:
        item["representative_locations"] = [
            loc for loc in item.get("representative_locations") or []
            if not _pattern_ok(_location_path(loc)) or _location_path(loc) in target_files]
    claimed: set[str] = set()
    for item in value.get("code_scope_classification") or []:
        for pattern in item.get("path_patterns") or []:
            if _pattern_ok(pattern):
                claimed |= {path for path in target_files if _matches(path, pattern)}
    gaps = value.setdefault("classification_gaps", [])
    have = {g.get("subject") for g in gaps}
    ids = {g.get("gap_id") for g in gaps}
    for path in sorted(set(target_files) - claimed):
        if f"scope:{path}" in have:
            continue
        gap_id = base = "gap-unscoped-" + _slug(path)[:80]
        n = 1
        while gap_id in ids:
            n += 1; gap_id = f"{base}-{n}"
        ids.add(gap_id)
        gaps.append({
            "gap_id": gap_id,
            "subject": f"scope:{path}",
            "reason": "No physical scope pattern in the model's map claims this target file.",
            "routing_impact": "Scope-driven routing will not reach this file; lane routing still applies.",
            "resolution_action": "Re-run characterization or add the file to a scope in a later pass.",
        })


def security_tag_errors(value: dict[str, Any]) -> list[str]:
    """Cheap, pre-repair check for the extra_validate repair loop: only that each cwe_id actually
    resolves against the pinned catalog in force. cwe_name/cwe_catalog are never trusted from the
    model (see _resolve_security_tags) so they are not checked here."""
    errors: list[str] = []
    catalog = None
    for component in value.get("functional_components") or []:
        for tag in component.get("candidate_security_tags") or []:
            cwe_id = tag.get("cwe_id")
            if not isinstance(cwe_id, str):
                continue
            if catalog is None:
                catalog = cwe_catalog.current()
            try:
                catalog.validate(cwe_id)
            except cwe_catalog.CWEError as exc:
                errors.append(f"candidate_security_tags: {cwe_id!r} does not resolve in the "
                              f"CWE catalog in force: {exc}")
    return errors


def _resolve_security_tags(value: dict[str, Any]) -> None:
    """ADR-0013/O2: a candidate security tag's cwe_id is the model's lead; cwe_name and cwe_catalog
    are never the model's to assert (it cannot know our pinned catalog's exact identity string, and
    guessing the canonical name invites drift) -- Python resolves and overwrites both from the CWE
    catalog in force, the same discipline claim_lifecycle_core._cwe_judgment uses for 07/09/12.
    Raises if a cwe_id does not resolve; security_tag_errors already gives the repair loop a chance
    to fix this before execute() reaches this unconditional, no-recovery step."""
    catalog = None
    for component in value.get("functional_components") or []:
        for tag in component.get("candidate_security_tags") or []:
            cwe_id = tag.get("cwe_id")
            if not isinstance(cwe_id, str):
                raise ValueError(f"component {component.get('component_id')}: candidate_security_tags "
                                 f"entry has a non-string cwe_id")
            if catalog is None:
                catalog = cwe_catalog.current()
            try:
                resolved = catalog.validate(cwe_id)
            except cwe_catalog.CWEError as exc:
                raise ValueError(f"component {component.get('component_id')}: candidate_security_tags "
                                 f"cwe_id {cwe_id!r} does not resolve: {exc}") from None
            tag["cwe_id"] = resolved
            tag["cwe_name"] = catalog.name(resolved)
            tag["cwe_catalog"] = catalog.used


def _record_untagged_gaps(value: dict[str, Any]) -> None:
    """ADR-0013: a component the model left out of the tag cloud is a routing gap, not a failed map."""
    tagged = {c for item in value.get("tag_cloud") or [] for c in item.get("component_ids") or []}
    gaps = value.setdefault("classification_gaps", [])
    have = {g.get("gap_id") for g in gaps}
    for item in value.get("functional_components") or []:
        cid = item.get("component_id")
        if cid in tagged or f"gap-untagged-{cid}" in have:
            continue
        gaps.append({
            "gap_id": f"gap-untagged-{cid}",
            "subject": f"tag_cloud:{cid}",
            "reason": "The model characterised this component but gave it no tag-cloud entry.",
            "routing_impact": "Tag-driven routing will not reach this component; path and lane routing still apply.",
            "resolution_action": "Re-run characterization or tag the component in a later pass.",
        })


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    value = read_json(attempt / RESULT)
    expected_identity = {
        "target": inputs["target_name"],
        "source_revision": inputs["source_revision"],
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "evidence_manifest_lineage": _manifest_lineage(inputs),
    }
    if any(value.get(key) != expected for key, expected in expected_identity.items()):
        raise Blocked(f"{JOB}: result identity does not match its immutable inputs")
    errors = validate_payload(value, target_root=Path(inputs["target_root"]),
                              evidence_root=Path(inputs["evidence_root"]))
    if errors:
        raise Blocked(f"{JOB}: component map failed independent validation ({len(errors)} errors)")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {DAGSTER_JOB} --wait"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        value, summary, facts = _dispatch_persona(run_id, allocation, inputs)
        _postprocess(value, inputs)
        errors = validate_payload(value, target_root=Path(inputs["target_root"]),
                                  evidence_root=Path(inputs["evidence_root"]))
        if errors:
            raise ValueError(f"{JOB}: persona result failed independent validation: " + "; ".join(errors))
        attempt = allocation["attempt"]
        atomic_json(attempt / RESULT, value)
        atomic_bytes(attempt / SUMMARY, summary.encode("utf-8"))
        gaps = [item["reason"] for item in value["classification_gaps"]]
        status_name = "OK_WITH_GAPS" if gaps else "OK"
        persona = facts["persona"]
        status = {
            "process": JOB, "status": status_name, "budget": facts["budget"],
            "persona_id": persona["persona_id"], "role_id": persona["role_id"],
            "domain_id": persona["domain_id"], "tooling_profile_id": persona["tooling_profile_id"],
            "artifacts_read": facts["artifacts_read"], "classification_gaps": len(gaps),
            "dispatch_mode": "automatic", "persona_job_id": PERSONA_JOB_ID,
            "persona_result_sha256": facts["persona_result_sha256"], "model": facts["model"],
        }
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="persona", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status_name,
            summary="Component purpose and downstream review routing map produced.",
            status_record=status, artifact_paths=[RESULT, SUMMARY, "status.json"], gaps=gaps,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="persona", output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, attempt, inputs),
        blocked_summary="Component characterization preflight did not complete.",
        failed_summary="Component characterization did not publish; no older result may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-component-characterization")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
