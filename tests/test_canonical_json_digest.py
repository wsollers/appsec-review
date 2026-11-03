import hashlib
import tracemalloc

import pytest

from appsec_review.storage.atomic import canonical_json, canonical_json_sha256


def test_canonical_wire_format_retains_sorting_utf8_and_trailing_newline():
    value = {"z": 1, "a": "caf\u00e9"}
    expected = b'{"a":"caf\xc3\xa9","z":1}\n'
    assert canonical_json(value) == expected
    assert canonical_json_sha256(value) == hashlib.sha256(expected).hexdigest()


@pytest.mark.parametrize("value", [
    None, True, 17, -0.0, float("inf"), float("nan"),
    {"text": "caf\u00e9\n\"quoted\"\\path", "items": [None, False, 1, 1.0]},
    {"z": {"b": 2, "a": 1}, "a": ("first", {"nested": []})},
    {10: "ten", 2: "two"},
])
def test_streamed_digest_matches_exact_canonical_wire_bytes(value):
    assert canonical_json_sha256(value) == hashlib.sha256(canonical_json(value)).hexdigest()


def test_streamed_digest_rejects_non_json_values():
    with pytest.raises(TypeError):
        canonical_json_sha256({"unsupported": object()})


def test_streamed_digest_does_not_allocate_a_complete_payload_copy():
    row = {"name": "library", "version": "1.2.3", "reason": "\u00e9" * 256}
    value = {"items": [row] * 4096}
    encoded = canonical_json(value)
    assert len(encoded) > 2 * 1024 * 1024
    expected = hashlib.sha256(encoded).hexdigest()
    del encoded
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        baseline = tracemalloc.get_traced_memory()[0]
        actual = canonical_json_sha256(value)
        peak = tracemalloc.get_traced_memory()[1] - baseline
    finally:
        tracemalloc.stop()
    assert actual == expected
    assert peak < 512 * 1024
