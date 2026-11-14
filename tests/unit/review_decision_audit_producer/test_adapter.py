from copy import deepcopy
from dataclasses import replace
import hashlib
import json

import pytest

from appsec_review.review.decision_audit.publication import AuditUnavailable
from appsec_review.review.identity import sha256_hex
from appsec_review.review.ledger import LedgerWriter, canonical_key
from appsec_review.review.models import CellStatus, IntegrityError
from appsec_review.storage import canonical_json

from .helpers import BLUE, RED, VERIFIER, digest, document, fixture, reference


def repin(f, field, value):
    ref = getattr(f.refs, field)
    doc = document(f.root, ref["path"], value)
    f.refs = replace(f.refs, **{field: reference(doc)})
    return doc


@pytest.mark.parametrize("kind", ["disabled", "verification-input", "foreign-ledger", "canonical-ledger",
                                 "ambiguous-cell", "attempted-no-receipt", "unaccepted-lead"])
def test_adapter_accepted_source_boundaries(tmp_path, kind):
    f = fixture(tmp_path)
    error = IntegrityError
    if kind == "disabled":
        f.settings = replace(f.settings, enabled=False)
        error = AuditUnavailable
    elif kind == "verification-input":
        extra = document(f.root, "data/configuration/resolved.json", {"configuration": "frozen"})
        f.refs = replace(f.refs, verification_inputs=(reference(extra),))
        assert f.publish() is not None
        (f.root / extra.source.path).write_bytes(b"changed")
    elif kind == "foreign-ledger":
        f.refs = replace(f.refs, ledger={**f.refs.ledger, "path": "foreign/ledger.jsonl"})
    elif kind == "canonical-ledger":
        path = f.root / f.refs.ledger["path"]
        rows = [json.loads(row) for row in path.read_bytes().splitlines()]
        data = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
        path.write_bytes(data)
        f.refs = replace(f.refs, ledger={**f.refs.ledger, "sha256": hashlib.sha256(data).hexdigest()})
    elif kind == "unaccepted-lead":
        leads = (replace(f.inputs.collection.leads[0], shard_sha256=digest("unaccepted")), *f.inputs.collection.leads[1:])
        f.inputs = replace(f.inputs, collection=replace(f.inputs.collection, leads=leads))
    else:
        path = f.root / f.refs.ledger["path"]
        events = [json.loads(row) for row in path.read_bytes().splitlines()]
        streams = {event["stream"]: LedgerWriter(f.root / f"unused-{event['stream']}", event["stream"])
                   for event in events}
        for stream in sorted(streams):
            for event in sorted((row for row in events if row["stream"] == stream), key=lambda row: row["sequence"]):
                body = deepcopy(event["body"])
                if event["kind"] == "cell_terminal" and event["subject_id"] == RED:
                    if kind == "attempted-no-receipt":
                        body["cell"]["receipt_sha256"] = None
                    else:
                        extra = deepcopy(body)
                        extra["cell"]["status"] = "failed"
                        streams[stream].append(event["kind"], event["subject_id"], extra)
                streams[stream].append(event["kind"], event["subject_id"], body)
        data = b"".join(canonical_json(row) for row in sorted(
            (row for writer in streams.values() for row in writer.events), key=canonical_key))
        path.write_bytes(data)
        f.refs = replace(f.refs, ledger={**f.refs.ledger, "sha256": hashlib.sha256(data).hexdigest()})
    with pytest.raises(error):
        f.publish()


@pytest.mark.parametrize("kind", ["manifest", "package-identity", "package-conflict"])
def test_package_pins_are_reverified(tmp_path, kind):
    f = fixture(tmp_path)
    package_set = deepcopy(f.inputs.package_sets[0].value)
    if kind == "manifest":
        ref = package_set["package_manifest"]
        body = json.loads((f.root / ref["path"]).read_bytes())
        body["content_sha256"] = digest("changed")
        package_set["package_manifest"] = reference(document(f.root, ref["path"], body))
    elif kind == "package-identity":
        ref = package_set["packages"][0]
        body = {**f.inputs.packages[0].value, "package_id": "foreign"}
        package_set["packages"][0] = {**ref, **reference(document(f.root, ref["path"], body))}
    else:
        ref = package_set["packages"][0]
        changed = document(f.root, ref["path"].replace("package.json", "other-package.json"),
                           {**f.inputs.packages[0].value, "extra": "different"})
        package_set["packages"].append({**ref, **reference(changed)})
    changed = document(f.root, f.refs.package_sets[0]["path"], package_set)
    f.refs = replace(f.refs, package_sets=(reference(changed), *f.refs.package_sets[1:]))
    with pytest.raises(IntegrityError):
        f.publish()


@pytest.mark.parametrize("change", [{"seen_identities": "not-list"}, {"seen_identities": [1]},
    {"attempt": True},
    {"result": {"schema": "unsupported"}, "result_sha256": sha256_hex({"schema": "unsupported"})}],
    ids=["read-shape", "read-identity", "boolean-attempt", "result-schema"])
def test_original_receipt_types_and_versions_are_checked(tmp_path, change):
    with pytest.raises(IntegrityError):
        fixture(tmp_path, receipt_change=change).publish()


def test_hash_bound_valid_reused_receipt_and_missing_optional_inputs(tmp_path):
    f = fixture(tmp_path, capture=False, receipt_change={"reused_from": {
        "cell_id": BLUE, "attempt": 1, "receipt_sha256": digest("original"), "memo_key": digest("memo")}})
    f.inputs = replace(f.inputs, collection=None)
    assert f.publish() is not None


def test_unlaunched_cells_do_not_require_nonexistent_receipts(tmp_path):
    f = fixture(tmp_path, red_status=CellStatus.NOT_LAUNCHED, verifier_status=CellStatus.NOT_LAUNCHED)
    assert f.publish() is not None


@pytest.mark.parametrize("kind", ["foreign-path", "foreign-cell", "closed-keys", "boolean", "conflict"])
def test_hash_bound_request_checks_cannot_disagree_with_capture(tmp_path, kind):
    f = fixture(tmp_path)
    lane = deepcopy(f.inputs.lanes[0].value)
    capture = next(iter(lane["independence"].values()))[0]["audit"]
    check = f.inputs.request_checks[VERIFIER]
    value = dict(check.value)
    if kind == "foreign-path":
        capture["request_check"]["path"] = capture["request_check"]["path"].replace("attempt-1", "attempt-2")
    else:
        if kind == "foreign-cell":
            value["cell_id"] = "foreign"
        elif kind == "closed-keys":
            value["extra"] = "not accepted"
        elif kind == "boolean":
            value["contains_forbidden_marker"] = 0
        else:
            value["contains_forbidden_marker"] = True
        capture["request_check"] = reference(document(f.root, check.source.path, value))
    changed = document(f.root, f.refs.lanes[0]["path"], lane)
    f.refs = replace(f.refs, lanes=(reference(changed),))
    with pytest.raises(IntegrityError):
        f.publish()


def test_finding_identity_must_match_handoff_membership(tmp_path):
    f = fixture(tmp_path)
    finding = f.inputs.findings[0]
    changed = document(f.root, finding.source.path, {**finding.value, "finding_package_id": "foreign"})
    body = json.loads((f.root / f.refs.handoff["path"]).read_bytes())
    body["finding_packages"][0]["sha256"] = changed.source.sha256
    handoff = repin(f, "handoff", body)
    f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, review_handoff_sha256=handoff.source.sha256))
    with pytest.raises(IntegrityError, match="finding identity"):
        f.publish()
