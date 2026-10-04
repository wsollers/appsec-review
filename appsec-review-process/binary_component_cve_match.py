#!/usr/bin/env python3
"""02-binary-component-cve-match: known-vulnerable components embedded in the run's built binaries.

cve-bin-tool 3.4 (pinned `tool-cve-bin-tool`, B13, `--network none`) scans the same immutable
native-build binary projection `02-binary-hardening` reads, against the database
`cve_bin_tool_db.py` derived from the NVD snapshot (docs/proposals/vendor-prepass/blint-cve-bin-tool.md
section 3). There is no download and no second staleness rule: preflight resolves the NVD snapshot
under the shared reference ceiling (over age: FAILED, ADR-0010 M4) and requires the published
database to be the one built from exactly that snapshot with the pinned image (else BLOCKED).

What is published is a closed projection: per match the binary path, NVD vendor/product/version and
the CVE id, and per detected component its vendor/product/version/CPE. cve-bin-tool's severity, score,
vector, remarks and descriptions are never published (severity is assigned in stage 12, ADR-0020),
and its raw reports stay in the unpublished execution root, bound by hash. A match is a lead, never a
finding or a reachability claim (ADR-0015). Nothing detected is a named coverage gap, never "no
known vulnerabilities".

A launch whose binaries, NVD-derived database, pinned image and code equal those of the accepted
attempt reuses it without starting the container (``reuse_inputs``, ``producer_reuse``); attempt ids
are fresh, never the Dagster run id.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Callable
import uuid

import binary_hardening_input
import container_execution as ce
import container_mobile_binary_contracts as cmb
import cve_bin_tool_db as cvedb
import evidence_redaction
from execution_state import Blocked, data_path, file_hash, identifier, read_json, run_path
import permission_capabilities as pc
import producer_reuse
from publish_job_output import mark_attempt_started, publish_validated, record_noncurrent, validate_published
import registry_paths
import sca_nvd_snapshot as nvd
import tunables
from worker_result import artifact_records, terminal_envelope, validate_worker_result

JOB = "02-binary-component-cve-match"
CONTRACT = "binary-component-cve-match"
SCHEMA_ID = "appsec-review/binary-component-cve-match/1.0"
RESULT = "binary-component-cve-match.json"
DATABASE = "database-identity.json"
TOOL_EVIDENCE = "tool-evidence.json"
IMPLEMENTATION = "binary-component-cve-match-v1"
MATCH_BASIS = "nvd-cpe-vendor-product-version-range"
SKIP = "not-applicable-no-matching-inputs"
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
MANIFEST_SCHEMA = "appsec-review/attempt-manifest/1"
LAUNCHER = cvedb.BUILDER_DIR
REPORT, DETECTED = "cves.json", "detected.cdx.json"
# cve-bin-tool: 0 = no CVE, 1 = CVEs found (cli.py); every other code is a tool failure.
ACCEPTED_EXITS = (0, 1)
HASH = lambda data: "sha256:" + hashlib.sha256(data).hexdigest()
ALWAYS_GAPS = (
    {"gap_id": "gap-cve-bin-tool-sources-limited", "kind": "sources-limited",
     "detail": "NVD only; curl, EPSS, GitLab, OSV, PURL2CPE, RedHat and RSD advisories are not loaded"},
    {"gap_id": "gap-cve-bin-tool-sqlite-source-id-map", "kind": "checker-degraded",
     "detail": "sqlite is detected by its version string only; the SQLITE_SOURCE_ID map needs sqlite.org"},
)


def _dump(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _utc(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scanned_binaries(source_root: Path) -> list[dict[str, Any]]:
    """Every file of the projection whose leading bytes are PE, ELF or Mach-O."""
    found = []
    for path in sorted(p for p in Path(source_root).rglob("*") if p.is_file() and not p.is_symlink()):
        data = path.read_bytes()
        fmt = cmb.detect_format(data[:8])
        if fmt != "unsupported":
            found.append({"path": path.relative_to(source_root).as_posix(), "sha256": HASH(data),
                          "bytes": len(data), "format": fmt})
    return found


def normalize(report: bytes, detected: bytes, scanned: set[str]) -> tuple[list[dict], list[dict]]:
    """(matches, components) from cve-bin-tool's JSON report and CycloneDX SBOM. Recorded real output:
    tests/fixtures/cve-bin-tool-real/. Raises ValueError on any shape this projection does not know."""
    rows = json.loads(report) if report.strip() else []
    if not isinstance(rows, list):
        raise ValueError("report is not a list")
    matches = []
    for row in rows:
        if not isinstance(row, dict) or row.get("source") != "NVD":
            raise ValueError("report row is not an NVD match")
        cve = row.get("cve_number")
        if not isinstance(cve, str) or not cve.startswith("CVE-"):
            raise ValueError("report row has no CVE id")
        for raw in str(row.get("paths", "")).split(", "):
            relative = raw.removeprefix("/workspace/")
            if relative not in scanned:
                raise ValueError("report names a path outside the scanned projection")
            matches.append({"binary_path": relative, "vendor": str(row.get("vendor")), "product": str(row.get("product")),
                            "version": str(row.get("version")), "cve_id": cve, "source": "NVD", "match_basis": MATCH_BASIS})
    bom = json.loads(detected)
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise ValueError("detected-component SBOM is not CycloneDX")
    components = []
    for item in bom.get("components", []):
        cpe = item.get("cpe")
        if not cpe:
            continue          # the scanned directory itself ("CVEBINTOOL-<dir>"), not a component
        vendor = cpe.split(":")[2] if cpe.startswith("cpe:/a:") and cpe.count(":") >= 3 else None
        components.append({"vendor": vendor, "product": str(item.get("name")), "version": str(item.get("version")),
                           "cpe": cpe})
    matches.sort(key=lambda m: (m["binary_path"], m["vendor"], m["product"], m["version"], m["cve_id"]))
    for number, match in enumerate(matches, 1):
        match["match_id"] = f"BCM-{number:06d}"
    components.sort(key=lambda c: (c["product"], c["version"], c["cpe"]))
    return matches, components


def _request(*, run_id: str, attempt_id: str, source_root: Path, database_dir: Path, source_sha: str,
             now: str) -> dict[str, Any]:
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    if cvedb.IMAGE_ID not in registry:
        raise cvedb.DbUnavailable("IMAGE_UNAVAILABLE", f"{cvedb.IMAGE_ID} has no registered image record")
    image = registry[cvedb.IMAGE_ID]
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": JOB, "capabilities": []}
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source_sha, "now": now, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    argv = ["/opt/tool/bin/python", "-B", "/inputs/launcher/scan.py", "/inputs/cvedb", "--offline",
            "-d", ",".join(cvedb.DISABLED_SOURCES), "-f", "json", "-o", "/scratch/" + REPORT,
            "--sbom-output", "/scratch/" + DETECTED, "--sbom-type", "cyclonedx", "--sbom-format", "json", "/workspace"]
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
            "image": {"image_id": image["image_id"], "digest": image["digest"]}, "argv": argv,
            "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                            {"name": "NO_COLOR", "value": "1"}],
            "target_mounts": [{"host_path": str(Path(source_root).resolve()), "container_path": "/workspace"},
                              {"host_path": str(Path(database_dir).resolve()), "container_path": "/inputs/cvedb"},
                              {"host_path": str(LAUNCHER.resolve()), "container_path": "/inputs/launcher"}],
            "scratch_path": "scratch", "log_path": "logs/container", "network": {"mode": "none", "destinations": []},
            "permission": {"requirement": requirement, "grants": [], "decision": decision},
            "limits": tunables.container_limits(JOB)}


def _runtime(source_sha: str, now: str) -> ce.ContainerRuntime:
    import vendor_evidence_b13 as b13
    return b13._runtime(source_sha, lambda: now)


def scan(*, run_id: str, attempt_id: str, source_root: Path, database_dir: Path, execution_root: Path,
         source_sha: str, now: str, runtime_factory: Callable[..., Any] = _runtime,
         run_container: Callable[..., dict] = ce.run_container,
         verify: Callable[..., list[str]] = ce.verify_container_result) -> dict[str, Any]:
    """Run the pinned tool once and return {status, report, detected, evidence} or a terminal failure.
    Integrity problems (request, re-verification) BLOCK; a tool that ran and failed is FAILED."""
    import vendor_evidence_b13 as b13
    try:
        request = _request(run_id=run_id, attempt_id=f"cve-bin-tool-{attempt_id[:40]}", source_root=source_root,
                           database_dir=database_dir, source_sha=source_sha, now=now)
        runtime = runtime_factory(source_sha, now)
    except cvedb.DbUnavailable as exc:
        return {"status": "BLOCKED", "cause": exc.reason.lower()}
    except b13.VendorToolBlocked as exc:          # docker-unavailable
        return {"status": "BLOCKED", "cause": str(exc)}
    except ce.ContainerRequestError:
        return {"status": "BLOCKED", "cause": "request-invalid"}
    root = execution_root / "tools" / "cve-bin-tool"
    root.mkdir(parents=True, exist_ok=False)   # run_container requires an existing attempt root
    try:
        terminal = run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=request["attempt_id"],
                                 attempt_root=root, request=request)
    except ce.ContainerRequestError:
        # The boundary refused the request or runtime before starting anything (e.g. a root
        # container user): nothing ran, so this is BLOCKED, never a crash or an empty result.
        return {"status": "BLOCKED", "cause": "request-invalid"}
    errors = verify(root, run_id=run_id, job_id=JOB, attempt_id=request["attempt_id"], request=request,
                    images_dir=runtime.images_dir, expected_result_sha256=terminal["result_sha256"],
                    host_flavor=runtime.host_flavor, docker_host=runtime.docker_host,
                    docker_executable=runtime.docker_executable, container_user=runtime.container_user)
    if errors:
        return {"status": "BLOCKED", "cause": "b13-verification-failed"}
    if terminal["execution_status"] in ("BLOCKED", "CANCELED"):
        return {"status": "BLOCKED", "cause": str(terminal.get("cause") or "container-blocked").lower()}
    exit_code = terminal.get("exit_code")
    accepted = terminal["execution_status"] == "OK" or (
        terminal.get("cause") == "CONTAINER_EXIT_NONZERO" and exit_code in ACCEPTED_EXITS)
    outputs = {name: root / "scratch" / name for name in (REPORT, DETECTED)}
    if not accepted:
        return {"status": "FAILED", "cause": str(terminal.get("cause") or "tool-error").lower(), "exit_code": exit_code}
    if not all(path.is_file() and not path.is_symlink() for path in outputs.values()):
        return {"status": "FAILED", "cause": "expected-output-missing", "exit_code": exit_code}
    data = {name: path.read_bytes() for name, path in outputs.items()}
    return {"status": "OK", "report": data[REPORT], "detected": data[DETECTED],
            "evidence": {"image_id": request["image"]["image_id"], "image_digest": request["image"]["digest"],
                         "argv": request["argv"], "exit_code": exit_code,
                         "request_sha256": terminal.get("request_sha256"), "result_sha256": terminal["result_sha256"],
                         "raw_outputs": [{"name": name, "sha256": HASH(blob), "bytes": len(blob)}
                                         for name, blob in sorted(data.items())]}}


def build(run_id: str, attempt_id: str, *, source_root: Path, source_sha: str, now: datetime,
          execution_root: Path, nvd_data_root: Path | None = None, db_root: Path | None = None,
          tool: dict[str, str] | None = None, scanner: Callable[..., dict] = scan) -> dict[str, Any]:
    """The node's documents for one attempt; nothing is published here."""
    header = {"run_id": run_id, "job_id": JOB, "attempt_id": attempt_id, "source_snapshot_sha256": source_sha}
    binaries = scanned_binaries(source_root)
    result = {"schema": SCHEMA_ID, **header, "database": None, "scanned_binaries": binaries,
              "components": [], "matches": [], "gaps": [], "limitations": list(cvedb.LIMITATIONS)}
    status, cause, evidence = "OK_WITH_GAPS", None, None
    if not binaries:
        status = "SKIPPED"
    else:
        ceiling = timedelta(seconds=tunables.shared("reference_snapshot_max_age_seconds"))
        resolved = nvd.resolve_snapshot(nvd_data_root or cvedb.nvd_root(), max_age=ceiling, now=now)
        database = None
        if not resolved.usable:
            status, cause = ("FAILED" if resolved.outcome == "FAILED" else "BLOCKED"), "nvd-" + resolved.reason.lower()
        else:
            try:
                database = cvedb.resolve_db(db_root or cvedb.feed_root(), nvd_identity=resolved.identity,
                                            tool=tool or cvedb.pinned_tool(), now=now)
            except cvedb.DbUnavailable as exc:
                status, cause = "BLOCKED", exc.reason.lower()
        if database is not None:
            # Full manifest hashes, not the 16-hex snapshot ids: the publication redactor treats a
            # `sha256-<16 hex>` id as a high-entropy secret (reproduced) and 64-hex digests are exempt.
            result["database"] = {"db_manifest_sha256": database["manifest_sha256"],
                                  **{key: database[key] for key in ("nvd_manifest_sha256", "nvd_cursor", "image_digest",
                                                                    "tool_version", "built_at", "cve_count")}}
            outcome = scanner(run_id=run_id, attempt_id=attempt_id, source_root=source_root,
                              database_dir=Path(database["directory"]), execution_root=execution_root,
                              source_sha=source_sha, now=_utc(now))
            if outcome["status"] != "OK":
                status, cause = outcome["status"], outcome["cause"]
            else:
                try:
                    matches, components = normalize(outcome["report"], outcome["detected"],
                                                    {b["path"] for b in binaries})
                except (ValueError, UnicodeDecodeError) as exc:
                    status, cause = "FAILED", "output-invalid"
                else:
                    result["matches"], result["components"] = matches, components
                    result["gaps"] = [dict(gap) for gap in ALWAYS_GAPS]
                    if not components:
                        result["gaps"].append({"gap_id": "gap-cve-bin-tool-no-component-detected",
                                               "kind": "zero-detected-components",
                                               "detail": "no checker recognised an embedded component; this is not "
                                                         "evidence that the binaries contain no vulnerable code"})
                    evidence = outcome["evidence"]
        if cause:
            result["gaps"].append({"gap_id": f"gap-cve-bin-tool-{status.lower()}-{cause}"[:96],
                                   "kind": "tool-blocked" if status == "BLOCKED" else "tool-failed",
                                   "detail": f"cve-bin-tool did not complete ({status}: {cause})"})
    return {"status": status, "cause": cause, "header": header, "result": result,
            "database": result["database"], "evidence": evidence,
            "skip_reason": SKIP if status == "SKIPPED" else None}


def _receipts(header: dict[str, Any], documents: dict[str, Any]) -> tuple[dict, dict]:
    template = json.loads(registry_paths.template(JOB).read_text(encoding="utf-8"))
    lineage = {"header": header, "result": documents["result"], "evidence": documents["evidence"]}
    return ({"schema": PERMISSION_SCHEMA, "run_id": header["run_id"], "job_id": JOB,
             "source_snapshot_sha256": header["source_snapshot_sha256"], "permissions": template["permissions"]},
            {"schema": LINEAGE_SCHEMA, "run_id": header["run_id"], "job_id": JOB,
             "source_snapshot_sha256": header["source_snapshot_sha256"],
             "build_lineage_sha256": HASH(_dump(lineage))})


def fingerprint(documents: dict[str, Any]) -> str:
    return HASH(_dump({"implementation": IMPLEMENTATION, "header": documents["header"],
                       "database": documents["database"], "binaries": documents["result"]["scanned_binaries"]}))


def materialize(documents: dict[str, Any], attempt: Path, *, dagster_run_id: str, started_at: str,
                finished_at: str) -> dict[str, Any]:
    """Publish a closed immutable attempt through the redaction boundary; returns the envelope."""
    if attempt.exists():
        raise FileExistsError(str(attempt))
    staging = attempt.parent / (attempt.name + ".staging")
    staging.mkdir(parents=True)
    (staging / RESULT).write_bytes(_dump(documents["result"]))
    (staging / DATABASE).write_bytes(_dump({"schema": "appsec-review/cve-bin-tool-database-binding/1.0",
                                            **documents["header"], "database": documents["database"]}))
    (staging / TOOL_EVIDENCE).write_bytes(_dump({"schema": "appsec-review/pinned-tool-evidence/1.0",
                                                 **documents["header"], "tool": documents["evidence"]}))
    attempt.mkdir(parents=True)
    evidence_redaction.redact_tree(staging, attempt / "outputs", on_unhandled="refuse",
                                   limits=evidence_redaction.DEFAULT_LIMITS)
    shutil.rmtree(staging)
    header = documents["header"]
    permission, lineage = _receipts(header, documents)
    (attempt / "permission.json").write_bytes(_dump(permission))
    (attempt / "lineage.json").write_bytes(_dump(lineage))
    (attempt / "status.json").write_bytes(_dump({"status": documents["status"], "run_id": header["run_id"],
                                                 "attempt_id": header["attempt_id"], "dagster_run_id": dagster_run_id}))
    outputs = [{"path": p.relative_to(attempt).as_posix(), "sha256": HASH(p.read_bytes())}
               for p in sorted((attempt / "outputs").rglob("*")) if p.is_file()]
    (attempt / "manifest.json").write_bytes(_dump({"schema": MANIFEST_SCHEMA, "contract_id": CONTRACT, "outputs": outputs}))
    artifacts = ["manifest.json", "status.json", "permission.json", "lineage.json", *[o["path"] for o in outputs]]
    current = documents["status"] in ("OK", "OK_WITH_GAPS", "SKIPPED")
    envelope = terminal_envelope(
        run_id=header["run_id"], job_id=JOB, attempt_id=header["attempt_id"], worker_kind="pinned_container",
        execution_status=documents["status"], acceptance_status="CURRENT" if current else "NOT_ACCEPTED",
        input_fingerprint=fingerprint(documents), output_contract=CONTRACT, started_at=started_at,
        finished_at=finished_at, summary=f"{JOB}: {len(documents['result']['matches'])} CVE range matches",
        artifacts=artifact_records(attempt, artifacts), gaps=[g["gap_id"] for g in documents["result"]["gaps"]],
        skip_reason=documents["skip_reason"],
        cause=None if current else ("vendor-tool-unavailable" if documents["status"] == "BLOCKED" else "vendor-tool-failed"))
    errors = validate_worker_result(envelope)
    if errors:
        raise RuntimeError("common envelope invalid: " + "; ".join(errors))
    (attempt / "result.json").write_bytes(_dump(envelope))
    return envelope


CODE_FILES = ("binary_component_cve_match.py", "cve_bin_tool_db.py", "sca_nvd_snapshot.py",
              "binary_hardening_input.py", "container_mobile_binary_contracts.py", "producer_reuse.py",
              registry_paths.contract_rel(CONTRACT), registry_paths.template_rel(JOB))


def reuse_inputs(run_id: str, source: Path, generation: str, now: datetime, *, nvd_data_root: Path | None = None,
                 db_root: Path | None = None, tool: dict[str, str] | None = None, **_options: Any) -> dict[str, Any] | None:
    """What one attempt's evidence is a function of: the scanned binaries by content, the database the
    preflight resolves now, the pinned image, the scan launcher and the code. None when the preflight
    would not resolve a database (nothing to reuse; ``build`` records that failure)."""
    binaries, database = scanned_binaries(source), None
    try:
        tool = tool or cvedb.pinned_tool()
        if binaries:
            ceiling = timedelta(seconds=tunables.shared("reference_snapshot_max_age_seconds"))
            resolved = nvd.resolve_snapshot(nvd_data_root or cvedb.nvd_root(), max_age=ceiling, now=now)
            if not resolved.usable:
                return None
            found = cvedb.resolve_db(db_root or cvedb.feed_root(), nvd_identity=resolved.identity, tool=tool, now=now)
            database = {key: found[key] for key in ("manifest_sha256", "nvd_manifest_sha256", "nvd_cursor",
                                                     "image_digest", "tool_version", "built_at", "cve_count")}
    except cvedb.DbUnavailable:
        return None
    launcher = {path.relative_to(LAUNCHER).as_posix(): file_hash(path) for path in sorted(LAUNCHER.rglob("*"))
                if path.is_file() and "__pycache__" not in path.parts} if LAUNCHER.is_dir() else None
    return {"job_id": JOB, "run_id": run_id, "source_generation": generation, "binaries": binaries,
            "database": database, "tool": tool, "images": producer_reuse.images([cvedb.IMAGE_ID]),
            "launcher": launcher, "code": producer_reuse.code(CODE_FILES)}


def execute(*, run_id: str, dagster_run_id: str, now: datetime | None = None, **options: Any) -> dict[str, Any]:
    """Stage the accepted native-build binaries, build, publish one attempt (or record it non-current)."""
    run_id, dagster_run_id = identifier(run_id), identifier(dagster_run_id)
    moment = now or datetime.now(timezone.utc)
    source = binary_hardening_input.stage(run_id, job=JOB)
    generation = "sha256:" + file_hash(run_path(run_id) / "inputs" / "artifact-manifest.json")
    base = data_path(run_id, "jobs", JOB, "whole").absolute()
    content = reuse_inputs(run_id, source, generation, moment, **options)
    if content is not None:
        reused = producer_reuse.admit(base, content, run_id=run_id, job_id=JOB,
            verify=lambda _attempt, pointer, _record: validate_published(
                base, pointer, pointer["fingerprint"], expected_run_id=run_id, expected_job_id=JOB,
                consumer_job_id="02-evidence-assembly", reuse=True))
        if reused is not None:
            return reused
    attempt_id = "native-" + str(uuid.uuid4())     # the native-<uuid> shape evidence_redaction exempts
    attempt, execution = base / "attempts" / attempt_id, base / "executions" / attempt_id
    if attempt.exists() or execution.exists():
        raise Blocked(f"{JOB}: attempt {attempt_id} already exists")
    base.mkdir(parents=True, exist_ok=True)
    execution.mkdir(parents=True)
    mark_attempt_started(base, attempt_id)
    documents = build(run_id, attempt_id, source_root=source, source_sha=generation, now=moment,
                      execution_root=execution, **options)
    stamp = _utc(moment)
    envelope = materialize(documents, attempt, dagster_run_id=dagster_run_id, started_at=stamp, finished_at=stamp)
    envelope_path = attempt / "result.json"
    if envelope["acceptance_status"] != "CURRENT":
        pointer = record_noncurrent(base, envelope_path, envelope)
        raise Blocked(f"{JOB}: did not produce current evidence: {documents['status']} ({documents['cause']})"
                      + f" [{pointer['status']}]")
    pointer = publish_validated(base, attempt, envelope_path, envelope["input_fingerprint"], expected_run_id=run_id,
                                expected_job_id=JOB, consumer_job_id="02-evidence-assembly")
    if content is not None:
        producer_reuse.remember(base, content, pointer, run_id=run_id, job_id=JOB,
                                facts={"dagster_run_id": dagster_run_id})
    return pointer
