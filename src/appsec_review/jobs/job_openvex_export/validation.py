"""Pinned offline schemas and exact semantic/canonical validation for OpenVEX exports."""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import sys
from typing import Any, NoReturn

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable

from . import contracts as c
from .projection import assemble_export
from .settings import OpenVexExportSettings

_RESOURCE_LIMIT = 1048576


def _fail(message: str, reason: c.ExportFailureReason = c.ExportFailureReason.SEMANTIC_INVALID) -> NoReturn:
    raise c.ExportError(message, reason=reason, phase=c.ExportPhase.VALIDATE)


def schema_resource_root(repository_root: Path | None = None) -> Path:
    """Locate source resources first, then the wheel's complete share/ resource layout.

    An existing source directory is authoritative: a corrupt/incomplete copy fails pin
    verification rather than falling back to a second, apparently healthy copy.
    """
    root = Path(repository_root) if repository_root is not None else Path(__file__).resolve().parents[4]
    for candidate in (root / "docs" / "schemas" / "openvex-export",
                      Path(sys.prefix) / "share" / "appsec-review" / "schemas" / "openvex-export"):
        try:
            mode = candidate.stat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise c.ExportError("cannot inspect pinned OpenVEX schema resource directory",
                                reason=c.ExportFailureReason.IO_ERROR, phase=c.ExportPhase.VALIDATE) from exc
        if not stat.S_ISDIR(mode):
            _fail("pinned OpenVEX resource directory is not a directory", c.ExportFailureReason.INPUT_TAMPERED)
        return candidate
    _fail("pinned OpenVEX schema resource directory is missing", c.ExportFailureReason.INPUT_MISSING)


def _resources(repository_root: Path | None) -> dict[str, dict[str, Any]]:
    root = schema_resource_root(repository_root)
    pins = {**c.SCHEMA_SHA256, "upstream/upstream.lock.json": c.UPSTREAM_LOCK_SHA256,
            "upstream/LICENSE": c.UPSTREAM_LICENSE_SHA256}
    documents = {}
    for relative, expected in pins.items():
        try:
            with (root / relative).open("rb") as stream:
                payload = stream.read(_RESOURCE_LIMIT + 1)
        except FileNotFoundError as exc:
            raise c.ExportError(f"pinned OpenVEX resource is missing: {relative}",
                                reason=c.ExportFailureReason.INPUT_MISSING, phase=c.ExportPhase.VALIDATE) from exc
        except OSError as exc:
            raise c.ExportError(f"cannot read pinned OpenVEX resource: {relative}",
                                reason=c.ExportFailureReason.IO_ERROR, phase=c.ExportPhase.VALIDATE) from exc
        if len(payload) > _RESOURCE_LIMIT:
            _fail(f"pinned OpenVEX resource exceeds byte bound: {relative}", c.ExportFailureReason.BOUND_EXCEEDED)
        if hashlib.sha256(payload).hexdigest() != expected:
            _fail(f"pinned OpenVEX resource hash mismatch: {relative}", c.ExportFailureReason.INPUT_TAMPERED)
        if relative in c.SCHEMA_SHA256:
            documents[relative] = c.parse_json_bytes(payload, max_bytes=_RESOURCE_LIMIT)
    return documents


def _deny_remote(uri: str) -> Resource:
    raise NoSuchResource(ref=uri)


def _registry(documents: dict[str, dict[str, Any]]) -> Registry:
    registry = Registry(retrieve=_deny_remote)
    for document in documents.values():
        registry = registry.with_resource(document["$id"], Resource.from_contents(document))
    return registry


def schema_registry(*, repository_root: Path | None = None) -> Registry:
    """Verify pinned schemas, lock and license; expose only the seven schema identities."""
    return _registry(_resources(repository_root))


def _formats() -> FormatChecker:
    checker = FormatChecker(formats=())

    @checker.checks("uri", raises=ValueError)
    @checker.checks("iri", raises=ValueError)
    def uri(value: object) -> bool:
        if isinstance(value, str):
            c.validate_repository_iri(value)
        return True

    @checker.checks("date-time", raises=ValueError)
    def timestamp(value: object) -> bool:
        if isinstance(value, str):
            c.normalize_timestamp(value)
            # datetime accepts overflow minutes in offsets; RFC3339 does not.
            if not value.endswith("Z") and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
                raise ValueError("invalid RFC3339 offset")
        return True

    return checker


def _validator(name: str, documents: dict[str, dict[str, Any]], registry: Registry) -> Draft202012Validator:
    if name not in documents:
        _fail("unsupported offline OpenVEX schema resource", c.ExportFailureReason.SCHEMA_INVALID)
    return Draft202012Validator(documents[name], registry=registry, format_checker=_formats())


def schema_validator(name: str, *, repository_root: Path | None = None) -> Draft202012Validator:
    """Return a pin-verified, format-checking validator; arbitrary paths/URLs are refused."""
    documents = _resources(repository_root)
    return _validator(name, documents, _registry(documents))


def _check_document(document: c.JsonObject, inputs: c.VerifiedInputs, settings: OpenVexExportSettings) -> None:
    timestamp = inputs.gate_completed_at
    if (document["@context"] != c.OPENVEX_CONTEXT or document["author"] != settings.author
            or document["timestamp"] != timestamp):
        _fail("OpenVEX context, issuer or acceptance timestamp differs from frozen inputs")
    statements = document["statements"]
    product = c.source_product_id(inputs.source.repository_iri, inputs.source.target_snapshot,
                                  inputs.provenance.resolved_config_sha256)
    identities = set()
    for statement in statements:
        if (statement.get("action_statement") != settings.action_statement
                or not statement.get("action_statement", "").strip()):
            _fail("affected action must be the exact nonblank operator-authored statement")
        if c.json_body(statement.get("products")) != [{"@id": product}]:
            _fail("affected statement must identify exactly the reviewed-source product")
        if statement.get("timestamp") != timestamp or statement["status"] != c.VexStatus.AFFECTED:
            _fail("affected statement time/status differs from the accepted assertion")
        body = {key: c.json_body(value) for key, value in statement.items() if key != "@id"}
        identity = c.statement_id(settings.author, body)
        if statement.get("@id") != identity or identity in identities:
            _fail("statement identity is incorrect or duplicated")
        identities.add(identity)
    body = {key: c.json_body(value) for key, value in document.items() if key != "@id"}
    if document["@id"] != c.document_id(body):
        _fail("document identity does not bind its exact assertion content")


def validate_export(bundle: c.ExportBundle, verified_inputs: c.VerifiedInputs,
                    settings: OpenVexExportSettings) -> None:
    """Prove schemas, output bytes/bindings and exact projection of every accepted input.

    Exporter release is declared in the manifest; callers additionally compare it to their
    frozen component-release declaration. Filesystem custody/current pointers belong to
    the input verifier and acceptance unit, not this pure output validation boundary.
    """
    documents = _resources(None)
    registry = _registry(documents)
    prefix = bundle.result_ref.path.rsplit("/", 1)[0]
    for name, filename, schema, limit in (
        ("document", c.DOCUMENT_NAME, "upstream/openvex-v0.2.0.schema.json", settings.max_document_bytes),
        ("manifest", c.MANIFEST_NAME, "manifest.schema.json", settings.max_manifest_bytes),
        ("result", c.RESULT_NAME, "result.schema.json", c.MAX_RESULT_BYTES),
    ):
        body, payload, ref = getattr(bundle, name), getattr(bundle, f"{name}_bytes"), getattr(bundle, f"{name}_ref")
        if body is None:
            if name != "document" or payload is not None or ref is not None:
                _fail("only a genuine empty OpenVEX document may be absent")
            continue
        if len(payload) > limit:
            _fail(f"{filename} exceeds configured output bound", c.ExportFailureReason.BOUND_EXCEEDED)
        try:
            parsed = c.parse_json_bytes(payload, max_bytes=limit)
        except ValueError as exc:
            raise c.ExportError(f"invalid bounded JSON in {filename}", reason=c.ExportFailureReason.SEMANTIC_INVALID,
                                phase=c.ExportPhase.VALIDATE) from exc
        if c.canonical_bytes(body) != payload or c.canonical_bytes(parsed) != payload:
            _fail(f"{filename} is not its exact canonical JSON projection")
        try:
            expected_ref = c.output_reference(prefix, filename, payload)
        except ValueError as exc:
            raise c.ExportError(f"invalid output reference path for {filename}",
                                reason=c.ExportFailureReason.SEMANTIC_INVALID, phase=c.ExportPhase.VALIDATE) from exc
        if ref != expected_ref:
            _fail(f"{filename} reference does not bind its exact name, bytes and size",
                  c.ExportFailureReason.INPUT_TAMPERED)
        try:
            _validator(schema, documents, registry).validate(parsed)
        except (ValidationError, Unresolvable) as exc:
            raise c.ExportError(f"{filename} fails pinned offline schema validation",
                                reason=c.ExportFailureReason.SCHEMA_INVALID, phase=c.ExportPhase.VALIDATE) from exc
    if bundle.document is not None:
        _check_document(bundle.document, verified_inputs, settings)
    try:
        expected = assemble_export(verified_inputs, settings, bundle.manifest["provenance"]["exporter_release"],
                                   output_prefix=prefix)
    except c.ExportError as exc:
        raise c.ExportError(str(exc), reason=exc.reason, phase=c.ExportPhase.VALIDATE) from exc
    for name in ("document", "manifest", "result"):
        if getattr(bundle, f"{name}_bytes") != getattr(expected, f"{name}_bytes"):
            _fail(f"{name} does not exactly project the verified gate, settings and artifact relations")
