"""Run-scoped blue-cell result memo: round-free keys, strict pointers, and a fail-open store client."""
from __future__ import annotations

from dataclasses import replace
import logging
import sys
import time

import pytest

from appsec_review.config.inference_review import ResultCacheSettings
from appsec_review.review import result_cache
from appsec_review.review.result_cache import (
    GarnetResultCache, InMemoryResultCache, KEY_PREFIX, MemoPointer, cache_from_settings, memo_key,
)
from appsec_review.review.models import Lane, Role
from tests.review.test_cells import capability, spec

RUN = "2026-10-12-0001"
CLAIM = "claim-" + "9" * 64
CELL = "cell-" + "a" * 64
OTHER_CELL = "cell-" + "b" * 64
RECEIPT = "c" * 64
SECRET = "do-not-log-this-password"


def blue(**overrides):
    values = dict(lane=Lane.LEAD, role=Role.BLUE_TEAM_REFUTER, claim_id=CLAIM, persona="native_memory_safety",
                  strategy=None, task="blue_control", task_input={"claim": {"statement": "s", "id": CLAIM}},
                  output_schema="appsec-review/blue-result/1", validator_version="blue-validator/1")
    values.update(overrides)
    return spec(**values)


def blue_capability(**overrides):
    return capability(**{"role": Role.BLUE_TEAM_REFUTER, **overrides})


def key(cell_spec=None, cap=None, run_id: str = RUN) -> str:
    cell_spec = cell_spec or blue()
    return memo_key(cell_spec, cap or blue_capability(round=cell_spec.round), run_id)


def test_the_key_ignores_only_round_bearing_fields() -> None:
    base = key()
    later = blue(round=2, round_delta_sha256="d" * 64,
                 task_input={"claim": {"statement": "s", "id": CLAIM}, "round": 2, "round_delta_sha256": "e" * 64})
    assert key(later, blue_capability(round=2)) == base
    assert blue_capability(round=2).capability_sha256 != blue_capability().capability_sha256


@pytest.mark.parametrize("change", [
    {"claim_id": "claim-" + "8" * 64},
    {"task": "blue_reachability"},
    {"persona": "web_injection"},
    {"strategy": "sink_up"},
    {"task_input": {"claim": {"statement": "reworded", "id": CLAIM}}},
    {"task_input": {"claim": {"statement": "s", "id": CLAIM}, "package": {"round": 1}}},
    {"model": "other-model"},
    {"provider": "codex-cli"},
    {"reasoning": "low"},
    {"guidance_bundle_sha256": "5" * 64},
    {"evidence_set": ("asr:source_span:" + "e" * 64,)},
    {"reuse_basis": "6" * 64},
    {"max_output_tokens": 4000},
    {"max_input_tokens": 1000},
    {"timeout_seconds": 30},
    {"validator_version": "blue-validator/2"},
    {"output_schema": "appsec-review/blue-result/2"},
    {"package_sha256": "7" * 64},
])
def test_anything_else_that_shapes_the_request_changes_the_key(change) -> None:
    changed = blue(**change)
    cap = blue_capability(package_sha256=changed.package_sha256)
    assert key(changed, cap) != key()


def test_the_capability_semantic_body_and_the_run_change_the_key() -> None:
    assert key(cap=blue_capability(max_queries=2)) != key()
    assert key(cap=blue_capability(tools=("search",))) != key()
    assert key(run_id="2026-10-12-0002") != key()


def test_a_key_needs_a_claim_and_a_run() -> None:
    with pytest.raises(ValueError, match="claim"):
        key(blue(claim_id=None))
    with pytest.raises(ValueError, match="run id"):
        key(run_id="../x")


def test_pointer_round_trip_and_malformed_pointers_are_misses() -> None:
    pointer = MemoPointer(CELL, 2, RECEIPT)
    assert MemoPointer.decode(pointer.encode()) == pointer
    assert MemoPointer.decode(pointer.encode().decode()) == pointer
    good = pointer.encode().decode()
    for raw in (None, 7, b"\xff", "", "{", "[]", good.replace(CELL, "cell-xyz"), good.replace('"attempt":2', '"attempt":0'),
                good.replace('"attempt":2', '"attempt":"2"'), good.replace('"attempt":2', '"attempt":true'),
                good.replace(RECEIPT, "C" * 64), good.replace("pointer/1", "pointer/2"),
                good[:-1] + ',"extra":1}', "x" * 2000):
        assert MemoPointer.decode(raw) is None, raw
    with pytest.raises(ValueError):
        MemoPointer("cell-" + "a" * 63, 1, RECEIPT)


def test_in_memory_cache_puts_only_if_absent_and_can_be_unavailable() -> None:
    cache = InMemoryResultCache()
    assert cache.put_if_absent("k", MemoPointer(CELL, 1, RECEIPT))
    assert not cache.put_if_absent("k", MemoPointer(OTHER_CELL, 1, RECEIPT))
    assert cache.get("k") == MemoPointer(CELL, 1, RECEIPT) and cache.get("missing") is None
    cache.entries["bad"] = b"not json"
    assert cache.get("bad") is None
    down = InMemoryResultCache(available=False)
    assert down.get("k") is None and not down.put_if_absent("k", MemoPointer(CELL, 1, RECEIPT))
    assert down.unavailable == 2


def test_garnet_client_fails_open_fast_once_and_never_logs_the_password(caplog) -> None:
    caplog.set_level(logging.WARNING, logger=result_cache.__name__)
    cache = GarnetResultCache(endpoint="redis://127.0.0.1:1/0", run_id=RUN, ttl_seconds=60,
                              timeout_seconds=0.05, password=SECRET)
    started = time.monotonic()
    assert cache.available
    assert cache.get("k") is None
    assert not cache.available
    assert not cache.put_if_absent("k", MemoPointer(CELL, 1, RECEIPT)) and cache.get("k") is None
    assert time.monotonic() - started < 2
    assert cache.unavailable == 3
    events = [record.event for record in caplog.records if hasattr(record, "event")]
    assert len(events) == 1 and events[0]["event_type"] == "REVIEW_RESULT_CACHE_UNAVAILABLE"
    assert events[0]["operation"] == "get" and events[0]["endpoint"] == "redis://127.0.0.1:1/0"
    assert SECRET not in caplog.text and all(SECRET not in repr(record.__dict__) for record in caplog.records)
    assert cache.prefix == f"{KEY_PREFIX}{RUN}:"


def test_garnet_client_without_the_redis_library_is_an_unavailable_cache(monkeypatch, caplog) -> None:
    monkeypatch.setitem(sys.modules, "redis", None)
    cache = GarnetResultCache(endpoint="redis://result-cache:6379/0", run_id=RUN, ttl_seconds=60,
                              timeout_seconds=0.05, password=SECRET)
    assert not cache.available and cache.get("k") is None
    assert not cache.put_if_absent("k", MemoPointer(CELL, 1, RECEIPT))
    assert cache.unavailable == 3 and SECRET not in caplog.text


class _Client:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.calls: list[tuple] = []

    def get(self, name):
        self.calls.append(("get", name))
        return self.store.get(name)

    def set(self, name, value, *, ex, nx):
        self.calls.append(("set", name, ex, nx))
        if nx and name in self.store:
            return None
        self.store[name] = value
        return True


def test_garnet_client_uses_a_run_prefix_and_set_ex_nx() -> None:
    cache = GarnetResultCache(endpoint="redis://127.0.0.1:1/0", run_id=RUN, ttl_seconds=600, timeout_seconds=0.05)
    cache._client = client = _Client()
    assert cache.put_if_absent("k", MemoPointer(CELL, 1, RECEIPT))
    assert not cache.put_if_absent("k", MemoPointer(OTHER_CELL, 1, RECEIPT))
    assert cache.get("k") == MemoPointer(CELL, 1, RECEIPT)
    assert client.calls[0] == ("set", f"{KEY_PREFIX}{RUN}:k", 600, True)


def test_cache_from_settings_is_none_when_disabled_and_reads_the_password_from_the_environment() -> None:
    settings = ResultCacheSettings(enabled=True, connect_timeout_seconds=0.05)
    assert cache_from_settings(replace(settings, enabled=False), RUN) is None
    cache = cache_from_settings(settings, RUN, environ={"APPSEC_RESULT_CACHE_PASSWORD": SECRET})
    assert isinstance(cache, GarnetResultCache) and cache.available       # lazy: no connection yet
    assert cache._client.connection_pool.connection_kwargs["password"] == SECRET
    assert cache._client.connection_pool.connection_kwargs["socket_connect_timeout"] == 0.05
    anonymous = cache_from_settings(settings, RUN, environ={})
    assert anonymous._client.connection_pool.connection_kwargs.get("password") is None
