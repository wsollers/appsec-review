from copy import deepcopy
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_source_history_analysis import job


def _artifact(name):
    return {"path": f"artifacts/{name}", "sha256": "a" * 64, "size_bytes": 10}


@pytest.fixture
def inputs():
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    return {
        "snapshot": "snapshot",
        "source_identity": "b" * 64,
        "settings": deepcopy(dict(config.job("job_source_history_analysis").settings)),
        "ranked": {"artifact": _artifact("ranked"), "hotspots": _artifact("hotspots")},
        "normalized": {"artifact": _artifact("normalized")},
        "acquired": {
            "raw_log": _artifact("log"), "raw_messages": _artifact("messages"),
            "image_id": "sha256:" + "c" * 64,
        },
        "github": {"artifact": _artifact("github")},
    }


@pytest.mark.parametrize(("group", "name"), [
    ("ranked", "artifact"), ("ranked", "hotspots"), ("normalized", "artifact"),
    ("acquired", "raw_log"), ("acquired", "raw_messages"), ("github", "artifact"),
])
def test_every_producer_artifact_changes_the_fingerprint(inputs, group, name):
    baseline = job._history_index_fingerprint(**inputs)
    inputs[group][name]["sha256"] = "d" * 64
    assert job._history_index_fingerprint(**inputs) != baseline


def test_image_and_bounds_change_fingerprint_without_changing_rankings(inputs):
    baseline = job._history_index_fingerprint(**inputs)
    changed = deepcopy(inputs)
    changed["acquired"]["image_id"] = "sha256:" + "d" * 64
    assert job._history_index_fingerprint(**changed) != baseline
    changed = deepcopy(inputs)
    changed["settings"]["git"]["max_message_bytes"] += 1
    assert job._history_index_fingerprint(**changed) != baseline


def test_bounded_parser_and_newer_hotspot_identities_are_preserved(inputs, monkeypatch):
    captured = {}
    original = job.index_fingerprint

    def capture(**values):
        captured.update(values)
        return original(**values)

    monkeypatch.setattr(job, "index_fingerprint", capture)
    baseline = job._history_index_fingerprint(**inputs)
    assert captured["parser_identity"] == f"{job.PARSER_IDENTITY}+git-log-u0/1"
    assert captured["tool_identity"]["ranking"] == job.SII_IDENTITY
    assert captured["tool_identity"]["symbols"] == job.SYMBOL_IDENTITY
    assert captured["tool_identity"]["complexity"] == job.COMPLEXITY_IDENTITY
    monkeypatch.setattr(job, "PARSER_IDENTITY", "next-bounded-parser")
    assert job._history_index_fingerprint(**inputs) != baseline


def test_raw_artifact_metadata_does_not_replace_exact_byte_identity(inputs):
    baseline = job._history_index_fingerprint(**inputs)
    inputs["acquired"]["raw_log"]["diagnostic"] = "not an artifact identity field"
    assert job._history_index_fingerprint(**inputs) == baseline
    del inputs["acquired"]["raw_log"]["sha256"]
    with pytest.raises(KeyError, match="sha256"):
        job._history_index_fingerprint(**inputs)


def test_skipped_producers_have_a_deterministic_distinct_identity(inputs):
    baseline = job._history_index_fingerprint(**inputs)
    inputs["acquired"] = {"terminal_status": "SKIPPED_NA"}
    inputs["github"] = {"terminal_status": "SKIPPED_POLICY"}
    skipped = job._history_index_fingerprint(**inputs)
    assert skipped != baseline
    assert job._history_index_fingerprint(**inputs) == skipped
