from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json

import pytest

from appsec_review.deployment import (
    Limits, compare_observations, extract_inventory, import_observations, resolve_evidence,
)
from appsec_review.deployment.model import OBSERVATION_SCHEMA
from tests.deployment_support import SNAPSHOT, document


NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)


def batch(**changes):
    endpoint = {
        "id": "measurement-1", "service_id": None, "address": "127.0.0.1", "port": 6379,
        "transport": "tcp", "role": "configuration", "observed_at": "2026-11-06T11:00:00Z",
        "expires_at": "2026-11-06T13:00:00Z", "owner": "container:cache",
        "banner": "redis/999.99", "reachability": "not_tested", "vantage_point": None,
    }
    endpoint.update(changes)
    return {"schema": OBSERVATION_SCHEMA, "target_snapshot": SNAPSHOT, "environment": "customer",
            "endpoints": [endpoint]}


def imported(value, **kwargs):
    data = json.dumps(value).encode() if not isinstance(value, bytes) else value
    source = document(data, "observations", "observed.json", **kwargs)
    result = import_observations(source, target_snapshot=SNAPSHOT, environment="customer", as_of=NOW)
    return result, source


def test_observations_are_time_bound_untrusted_and_source_resolving():
    result, source = imported(batch(reachability="succeeded", vantage_point="operator-probe:customer-subnet"))
    assert result.outcome == "complete"
    endpoint = result.endpoints[0]
    assert endpoint.time_state == "current" and endpoint.authority == "imported_observation"
    assert endpoint.evidence_class == "observed_listener"
    assert endpoint.endpoint.reachability == "succeeded"
    assert result.evidence[0].authority == "imported_observation"
    assert resolve_evidence(result.evidence[0], source) == source.data
    assert not hasattr(endpoint, "product") and not hasattr(endpoint, "proven_reachability")


@pytest.mark.parametrize(("changes", "code"), [
    ({"port": 0}, "invalid_contract"),
    ({"port": True}, "invalid_contract"),
    ({"port": 65536}, "invalid_contract"),
    ({"address": "redis.example.com"}, "invalid_address"),
    ({"service_id": "cache"}, "invalid_service"),
    ({"observed_at": "2026-11-06T11:00:00"}, "invalid_contract"),
    ({"observed_at": "2026-11-99T11:00:00Z"}, "invalid_time"),
    ({"expires_at": "2026-11-06T10:00:00Z"}, "invalid_window"),
    ({"expires_at": "2027-01-06T13:00:00Z"}, "invalid_window"),
    ({"reachability": "succeeded"}, "missing_vantage"),
    ({"permission_to_scan": True}, "invalid_contract"),
    ({"role": "unknown"}, "invalid_contract"),
], ids=["zero", "boolean", "port-range", "hostname", "service-id", "timezone", "date", "reversed", "long",
        "vantage", "unknown-field", "role"])
def test_malformed_observations_publish_no_endpoint(changes, code):
    result, _ = imported(batch(**changes))
    assert result.outcome == "malformed"
    assert not result.endpoints and not result.evidence
    assert result.gaps[0].code == code


def test_duplicate_fields_duplicate_ids_unknown_versions_and_foreign_scopes_are_rejected():
    raw = json.dumps(batch()).encode().replace(b'"port": 6379', b'"port": 6379, "port": 6380')
    result, _ = imported(raw)
    assert result.outcome == "malformed" and result.gaps[0].code == "duplicate_key"
    data = batch()
    data["endpoints"].append(data["endpoints"][0].copy())
    assert imported(data)[0].gaps[0].code == "duplicate_endpoint"
    data = batch()
    data["schema"] = "appsec-review/deployment-observations/2"
    assert imported(data)[0].outcome == "unsupported"
    data["schema"] = []
    assert imported(data)[0].outcome == "malformed"
    data = batch()
    data["environment"] = "another-environment"
    assert imported(data)[0].gaps[0].code == "foreign_observation"
    data = batch()
    data["target_snapshot"] = "another-snapshot"
    assert imported(data)[0].gaps[0].code == "foreign_observation"
    assert imported(batch(), scope="analysis_platform")[0].outcome == "unsupported"


@pytest.mark.parametrize(("start", "end", "state"), [
    ("2026-11-06T09:00:00Z", "2026-11-06T12:00:00Z", "expired"),
    ("2026-11-06T13:00:00Z", "2026-11-06T14:00:00Z", "future"),
], ids=["expired-boundary", "future"])
def test_stale_observations_are_retained_as_gaps_not_current_evidence(start, end, state):
    result, _ = imported(batch(observed_at=start, expires_at=end))
    assert result.outcome == "partial"
    assert result.endpoints[0].time_state == state
    assert result.gaps[0].code == "observation_" + state


def test_drift_distinguishes_same_port_different_bind_and_absent_observation():
    source = document("bind 127.0.0.1\nport 6379\ntls-port 6380\n", "redis")
    static = extract_inventory([source], target_snapshot=SNAPSHOT)
    service_id = static.services[0].id
    observed, _ = imported(batch(service_id=service_id))
    rows = compare_observations(static, observed)
    assert {item.state for item in rows} == {"matched_declaration", "static_only"}
    assert all(item.evidence for item in rows)
    observed, _ = imported(batch(service_id=service_id, address="0.0.0.0"))
    assert {item.state for item in compare_observations(static, observed)} == {"bind_differs", "static_only"}
    observed, _ = imported(batch(service_id=service_id, port=9999))
    assert {item.state for item in compare_observations(static, observed)} == {"observed_only", "static_only"}
    observed, _ = imported(batch(port=6379))
    assert {item.state for item in compare_observations(static, observed)} == {"unbound", "static_only"}
    assert static.services[0].product is None and static.services[0].declared_version is None


def test_drift_does_not_match_host_listener_to_container_port_or_invent_unknown_bind():
    static = extract_inventory([document("services:\n  app:\n    ports: [6379]\n")], target_snapshot=SNAPSHOT)
    service_id = static.services[0].id
    observed, _ = imported(batch(service_id=service_id, role="published"))
    assert not any(item.state in {"matched_declaration", "port_matches_bind_unknown"}
                   for item in compare_observations(static, observed))
    observed, _ = imported(batch(service_id=service_id, role="container"))
    assert any(item.state == "port_matches_bind_unknown" for item in compare_observations(static, observed))
    observed.target_snapshot = "foreign"
    with pytest.raises(ValueError, match="another target"):
        compare_observations(static, observed)


def test_observation_byte_depth_and_record_limits_and_hash_binding():
    value = batch()
    source = document(json.dumps(value), "observations")
    for limits in (Limits(max_document_bytes=10), Limits(max_depth=1), Limits(max_nodes=4)):
        result = import_observations(source, target_snapshot=SNAPSHOT, environment="customer",
                                     as_of=NOW, limits=limits)
        assert result.outcome == "partial" and not result.endpoints
    result = import_observations(replace(source, data=source.data + b" "), target_snapshot=SNAPSHOT,
                                 environment="customer", as_of=NOW)
    assert result.outcome == "malformed" and result.gaps[0].code == "source_identity"
    value["endpoints"].append({**value["endpoints"][0], "id": "second"})
    result = import_observations(document(json.dumps(value), "observations"), target_snapshot=SNAPSHOT,
                                 environment="customer", as_of=NOW, limits=Limits(max_records=1))
    assert result.outcome == "partial" and not result.endpoints


@pytest.mark.parametrize("data", [b"[]", b"null", b'{"a": NaN}', b'{"a": Infinity}', b"{{", b"\xff"])
def test_invalid_observation_shapes_and_numbers(data):
    assert imported(data)[0].outcome == "malformed"


def test_empty_snapshot_and_unknown_root_fields_are_explicit():
    data = batch()
    data["endpoints"] = []
    result, _ = imported(data)
    assert result.outcome == "partial" and result.gaps[0].code == "no_observations"
    data["trusted"] = True
    assert imported(data)[0].outcome == "malformed"
