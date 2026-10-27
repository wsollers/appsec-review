"""Independent public-feed publication records and run-local consumption receipts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .atomic import canonical_json
from .shared import (SharedArtifacts, current, immutable_bytes, put_bytes, reference,
                     safe_path, verify_reference)

SCHEMA = "appsec-review/public-feed-publication/1"
PROOF_SCHEMA = "appsec-review/public-feed-use/1"
STEPS = {"nvd": "nvd_sync", "osv": "osv_sync", "mitre": "mitre_sync",
         "cve-bin-tool": "cve_bin_tool_db_build", "kev": "kev_sync", "epss": "epss_sync"}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _public_actor(actor: Mapping[str, Any]) -> dict[str, Any]:
    return {**{key: actor[key] for key in ("run_id", "job_id", "attempt_id")},
            "orchestration": {key: actor["orchestration"][key]
                              for key in ("system", "run_id", "node") if key in actor["orchestration"]}}


def _configured_root(run_root: Path, claim: Mapping[str, Any], feed: str) -> tuple[Path, dict[str, Any]]:
    if feed not in STEPS and feed != "grype":
        raise ValueError("unregistered public feed")
    config = reference(run_root, run_root / "data/configuration/resolved.json")
    if config["sha256"] != claim.get("resolved_config_sha256"):
        raise ValueError("feed provenance configuration differs from the attempt claim")
    document = json.loads(verify_reference(run_root, config).read_bytes())
    configured = ("data/feeds/grype" if feed == "grype" else
                  document["jobs"]["job_third_party_data_sync"]["steps"][STEPS[feed]]["settings"]["feed_root"])
    repository = Path(claim["repository_root"])
    path = Path(configured)
    path = path if path.is_absolute() else repository / path
    try:
        relative = path.relative_to(repository).as_posix()
    except ValueError:
        raise ValueError("public feed root is outside repository data") from None
    if not relative.startswith("data/"):
        raise ValueError("public feed root is outside repository data")
    return safe_path(repository, relative), config


def _claim(owner: SharedArtifacts) -> Mapping[str, Any]:
    return json.loads(verify_reference(owner.run_root, owner.actor["claim"]).read_bytes())


def check_root(root: Path, feed: str, *, producing: bool = False) -> None:
    """Check authority before publication has any externally visible side effects."""
    owner = current()
    if owner is not None:
        configured, _ = _configured_root(owner.run_root, _claim(owner), feed)
        if Path(root).absolute() != configured:
            raise ValueError("public feed is outside its configured root")
        if producing and (owner.actor["job_id"] != "job_third_party_data_sync" or feed not in STEPS):
            raise ValueError("only the feed-sync job may attest a public-feed computation")


def _publication(root: Path, ref: Mapping[str, Any], feed: str,
                 manifest: Mapping[str, Any]) -> dict[str, Any]:
    raw = verify_reference(root, ref).read_bytes()
    value = json.loads(raw)
    if (canonical_json(value) != raw or value.get("schema") != SCHEMA
            or value.get("feed_id") != feed or value.get("manifest") != manifest
            or ref["path"] != f"provenance/{Path(manifest['path']).parent.name}/{ref['sha256']}.json"
            or value.get("mode") != "computed"):
        raise ValueError("invalid immutable public-feed publication")
    actor = value["actor"]
    if (actor.get("job_id") != "job_third_party_data_sync" or feed not in STEPS
            or not all(isinstance(actor.get(key), str) and actor[key] for key in ("run_id", "attempt_id"))
            or not isinstance(actor.get("orchestration"), dict)
            or set(actor["orchestration"]) - {"system", "run_id", "node"}
            or any(not isinstance(k, str) or not isinstance(v, str)
                   for k, v in actor["orchestration"].items())
            or any(not re.fullmatch(r"[0-9a-f]{64}", value.get(key, ""))
                   for key in ("claim_sha256", "configuration_sha256", "computation_fingerprint"))
            or value["computation_fingerprint"] != _digest(value["computation"])):
        raise ValueError("invalid public-feed producer identity")
    return value


def _verify_snapshot(root: Path, manifest: Mapping[str, Any], feed: str) -> dict[str, Any]:
    from appsec_review.jobs.job_third_party_data_sync.publication import verify_snapshot_directory
    path = verify_reference(root, manifest)
    head = document = json.loads(path.read_bytes())
    if document.get("publication_provenance") not in {None, "required-v1"}:
        raise ValueError("unsupported public-feed provenance protocol")
    if document.get("feed_id") != feed or manifest["path"] != f"snapshots/{document['snapshot_id']}/manifest.json":
        raise ValueError("public-feed snapshot identity mismatch")
    verify_snapshot_directory(path.parent, document)
    if feed in STEPS and feed != "nvd":
        unsigned = {key: value for key, value in document.items() if key != "snapshot_id"}
        if document["snapshot_id"] != "sha256-" + _digest(unsigned)[:24]:
            raise ValueError("public-feed snapshot content identity mismatch")
    if feed == "nvd":
        seen = set()
        while True:
            if document["snapshot_id"] in seen:
                raise ValueError("public-feed NVD parent cycle")
            seen.add(document["snapshot_id"])
            unsigned = {key: value for key, value in document.items() if key != "snapshot_id"}
            from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher
            if document.get("feed_id") != feed or NvdPublisher._snapshot_id(unsigned) != document["snapshot_id"]:
                raise ValueError("public-feed NVD parent identity mismatch")
            for layer in document.get("layers", ()):
                for record in layer.get("pages", [layer]):
                    for field in ("raw_blob", "metadata_blob"):
                        if field in record:
                            try:
                                verify_reference(root, record[field])
                            except (ValueError, OSError) as exc:
                                raise ValueError(f"NVD blob integrity mismatch: {record[field]['path']}") from exc
            parent = document.get("parent_snapshot_id")
            if parent is None:
                break
            document = json.loads(safe_path(root, f"snapshots/{parent}/manifest.json").read_bytes())
            if document.get("snapshot_id") != parent:
                raise ValueError("public-feed NVD parent path mismatch")
    return head


def _select(root: Path, feed: str, manifest: Mapping[str, Any], document: Mapping[str, Any]
            ) -> dict[str, Any] | None:
    directory = safe_path(root, f"provenance/{document['snapshot_id']}")
    candidates = []
    if directory.exists():
        for path in sorted(directory.iterdir()):
            ref = reference(root, path)
            _publication(root, ref, feed, manifest)
            candidates.append(ref)
    if not candidates and document.get("publication_provenance") == "required-v1":
        raise ValueError("public-feed publication has no complete producer record")
    return candidates[0] if candidates else None


def record_snapshot(root: Path, feed: str, snapshot_id: str, *, computed: bool,
                    producer: Mapping[str, Any] | None = None, select_producer: bool = True
                    ) -> dict[str, Any] | None:
    check_root(root, feed, producing=computed)
    manifest = reference(root, safe_path(root, f"snapshots/{snapshot_id}/manifest.json"))
    document = _verify_snapshot(root, manifest, feed)
    owner = current()
    if owner is None:
        if not computed:
            if producer is not None:
                _publication(root, producer, feed, manifest)
            else:
                _select(root, feed, manifest, document)
        return None
    claim = _claim(owner)
    _, config = _configured_root(owner.run_root, claim, feed)
    mode = "computed" if computed else "reused"
    fingerprint = _digest({"feed_id": feed, "manifest": manifest, "mode": mode})
    slot = safe_path(owner.run_root, owner._slot("feed-snapshot", fingerprint))
    if slot.exists():
        from .shared import verify_receipt
        ref = reference(owner.run_root, slot)
        selected = verify_receipt(owner.run_root, ref)
        proof = json.loads(verify_reference(owner.run_root, selected["object"]).read_bytes())
        if not select_producer and proof["producer"] != producer:
            raise ValueError("feed selection differs from this attempt's immutable receipt")
        return ref
    if computed:
        sources = Path(__file__).parents[1] / "jobs/job_third_party_data_sync"
        implementation = hashlib.sha256(b"".join(
            p.read_bytes() for p in sorted(sources.rglob("*.py")))).hexdigest()
        computation = {"feed_id": feed, "configuration_sha256": config["sha256"],
                       "publisher_sha256": implementation,
                       "inputs_sha256": _digest({k: v for k, v in document.items()
                                                 if k not in {"files", "snapshot_id"}})}
        actor = _public_actor(owner.actor)
        value = {"schema": SCHEMA, "feed_id": feed, "manifest": manifest, "mode": "computed",
                 "actor": actor, "claim_sha256": owner.actor["claim"]["sha256"],
                 "configuration_sha256": config["sha256"], "computation": computation,
                 "computation_fingerprint": _digest(computation)}
        raw = canonical_json(value)
        producer = immutable_bytes(root, f"provenance/{snapshot_id}/{hashlib.sha256(raw).hexdigest()}.json", raw)
    elif producer is None and select_producer:
        producer = _select(root, feed, manifest, document)
    if producer is not None:
        _publication(root, producer, feed, manifest)
    elif document.get("publication_provenance") == "required-v1":
        raise ValueError("new public-feed publication cannot be treated as legacy")
    proof = {"schema": PROOF_SCHEMA, "feed_id": feed, "manifest": manifest,
             "configuration": config, "producer": producer,
             "origin": "verified-publication" if producer else "unknown-original-producer"}
    obj = put_bytes(owner.run_root, canonical_json(proof))
    return owner._record("feed-snapshot", fingerprint, obj, computation={
        "feed_id": feed, "snapshot_id": snapshot_id, "manifest_sha256": manifest["sha256"],
        "configuration_sha256": config["sha256"]}, mode=mode, layout="public-feed",
        legacy="unknown-original-producer" if producer is None else None)[1]


def verify_feed_receipt(run_root: Path, receipt: Mapping[str, Any], claim: Mapping[str, Any]) -> None:
    if receipt["object"]["path"] != f"data/shared/objects/{receipt['object']['sha256']}":
        raise ValueError("public-feed proof is not a run-local content-addressed object")
    raw = verify_reference(run_root, receipt["object"]).read_bytes()
    proof = json.loads(raw)
    if canonical_json(proof) != raw or proof.get("schema") != PROOF_SCHEMA:
        raise ValueError("invalid public-feed use proof")
    root, config = _configured_root(run_root, claim, proof["feed_id"])
    if proof["configuration"] != config or receipt["dependencies"] or receipt["producer_receipt"] is not None:
        raise ValueError("public-feed proof configuration or references changed")
    document = _verify_snapshot(root, proof["manifest"], proof["feed_id"])
    expected = {"feed_id": proof["feed_id"], "snapshot_id": document["snapshot_id"],
                "manifest_sha256": proof["manifest"]["sha256"], "configuration_sha256": config["sha256"]}
    if (receipt["computation"] != expected or receipt["fingerprint"] != _digest({
            "feed_id": proof["feed_id"], "manifest": proof["manifest"], "mode": receipt["mode"]})):
        raise ValueError("public-feed receipt computation differs from its selection")
    producer = proof["producer"]
    if producer is not None:
        original = _publication(root, producer, proof["feed_id"], proof["manifest"])
        if receipt["mode"] == "computed" and (
                original["actor"] != _public_actor(receipt["actor"])
                or original["claim_sha256"] != receipt["actor"]["claim"]["sha256"]
                or original["configuration_sha256"] != config["sha256"]):
            raise ValueError("public-feed computation differs from its producing invocation")
        if proof["origin"] != "verified-publication" or receipt["legacy"] is not None:
            raise ValueError("public-feed original producer was relabelled")
    elif (receipt["mode"] != "reused" or receipt["legacy"] != "unknown-original-producer"
          or proof["origin"] != "unknown-original-producer"
          or document.get("publication_provenance") == "required-v1"):
        raise ValueError("public-feed origin is unavailable")


def consume_pin(run_root: Path, pin: Mapping[str, Any]) -> dict[str, Any] | None:
    """Use a selected snapshot, never reselect from a mutable current pointer."""
    from .shared import verify_receipt
    owner = current()
    if owner is not None and owner.run_root != run_root:
        raise ValueError("feed input belongs to another run")
    producer = None
    if pin.get("provenance") is not None:
        selected = verify_receipt(run_root, pin["provenance"])
        if selected.get("layout") != "public-feed":
            raise ValueError("feed pin does not reference a public-feed receipt")
        proof = json.loads(verify_reference(run_root, selected["object"]).read_bytes())
        if (proof["feed_id"] != pin["feed_id"]
                or proof["manifest"]["sha256"] != pin["manifest_sha256"]
                or proof["manifest"]["path"] != f"snapshots/{pin['snapshot_id']}/manifest.json"):
            raise ValueError("feed pin differs from its immutable provenance")
        producer = proof["producer"]
        selected_claim = json.loads(verify_reference(run_root, selected["actor"]["claim"]).read_bytes())
        selected_root, _ = _configured_root(run_root, selected_claim, proof["feed_id"])
        if Path(pin["directory"]) != selected_root / Path(proof["manifest"]["path"]).parent:
            raise ValueError("feed pin directory differs from its configured provenance root")
    elif owner is None:
        return None  # Legacy offline pins retain their existing content-hash verification.
    directory = Path(pin["directory"])
    root = directory.parent.parent
    if directory != safe_path(root, f"snapshots/{pin['snapshot_id']}"):
        raise ValueError("feed pin directory differs from selected snapshot")
    check_root(root, pin["feed_id"])
    manifest = reference(root, safe_path(root, f"snapshots/{pin['snapshot_id']}/manifest.json"))
    if manifest["sha256"] != pin["manifest_sha256"]:
        raise ValueError("feed pin manifest hash mismatch")
    return record_snapshot(root, pin["feed_id"], pin["snapshot_id"], computed=False,
                           producer=producer, select_producer=pin.get("provenance") is None)
