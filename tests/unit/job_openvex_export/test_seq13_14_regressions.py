"""Unit regressions for seq=13 (OpenVEX original audit inputs & contract compatibility) and seq=14 (retired operational settings)."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

import pytest

from appsec_review.config import load_config
from appsec_review.config.inference_review import (
    parse_frozen_inference_review_settings,
    parse_inference_review_settings,
)
from appsec_review.config.operational import configuration_compatible, operational_changes
from appsec_review.jobs.job_openvex_export.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.runtime.configuration import ConfigurationSnapshot
from appsec_review.runtime.contracts import (
    Availability,
    EvidenceAuthority,
    InputRequirement,
    JobContract,
    MissingPolicy,
)
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.repair import compatible_dataset_change
from appsec_review.storage import canonical_json

ROOT = Path(__file__).resolve().parents[3]


def _openvex_mapping(**extra: object) -> dict[str, object]:
    base = dict(load_config(ROOT / "appsec-review.toml").job("job_openvex_export").settings)
    base.update(extra)
    return base


def _inference_mapping(**chain_extra: object) -> dict[str, object]:
    base = deepcopy(dict(load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").settings))
    chains = dict(base.get("attack_chains", {}))
    chains.update(chain_extra)
    base["attack_chains"] = chains
    return base


def test_openvex_frozen_mapping_accepts_retired_byte_caps_while_live_stays_closed() -> None:
    legacy = _openvex_mapping(max_artifact_bytes=16_777_216, max_total_input_bytes=67_108_864)
    with pytest.raises(ValueError, match="documented keys"):
        OpenVexExportSettings.from_mapping(legacy)
    parsed = OpenVexExportSettings.from_frozen_mapping(legacy)
    assert parsed.enabled is True
    for bad in (0, -1, True, "16"):
        with pytest.raises(ValueError, match="max_artifact_bytes"):
            OpenVexExportSettings.from_frozen_mapping(_openvex_mapping(max_artifact_bytes=bad))
    with pytest.raises(ValueError, match="documented keys"):
        OpenVexExportSettings.from_frozen_mapping(_openvex_mapping(unexpected_setting=1))


def test_frozen_inference_review_settings_accepts_retired_attack_chain_caps_only() -> None:
    legacy = _inference_mapping(max_challenge_cells=4, max_queries=24, max_turns=6)
    with pytest.raises(ValueError, match="known settings"):
        parse_inference_review_settings(legacy)
    parsed = parse_frozen_inference_review_settings(legacy)
    assert parsed.attack_chains is not None
    for bad in (0, -2, False, "4"):
        with pytest.raises(ValueError, match="max_turns"):
            parse_frozen_inference_review_settings(_inference_mapping(max_turns=bad))
    with pytest.raises(ValueError, match="known settings"):
        parse_frozen_inference_review_settings(_inference_mapping(unknown_cap=3))


def test_pre_8a016cff_snapshot_roundtrips_sha256_and_passes_symmetric_operational_changes(tmp_path: Path) -> None:
    live = load_config(ROOT / "appsec-review.toml", profile="copilot-dev-astra-6.2", compiler_target="clang")
    toml_text = live.source_path.read_text(encoding="utf-8")
    toml_text = re.sub(r"^operation_progress_interval_seconds\s*=.*\n", "", toml_text, flags=re.M)
    toml_text = re.sub(r"^operation_sample_interval_seconds\s*=.*\n", "", toml_text, flags=re.M)
    toml_text = toml_text.replace(
        "[jobs.job_openvex_export.settings]\n",
        "[jobs.job_openvex_export.settings]\nmax_artifact_bytes = 67108864\nmax_total_input_bytes = 268435456\n",
        1,
    )
    toml_text = toml_text.replace(
        "[jobs.job_inference_security_review.settings.attack_chains]\n",
        "[jobs.job_inference_security_review.settings.attack_chains]\nmax_challenge_cells = 4\nmax_queries = 24\nmax_turns = 6\n",
        1,
    )
    legacy_toml_bytes = toml_text.encode("utf-8")
    legacy_source_sha = hashlib.sha256(legacy_toml_bytes).hexdigest()
    legacy_doc = deepcopy(json.loads(live.resolved_json))
    legacy_doc["runtime"].pop("operation_progress_interval_seconds", None)
    legacy_doc["runtime"].pop("operation_sample_interval_seconds", None)
    legacy_doc["jobs"]["job_openvex_export"]["settings"]["max_artifact_bytes"] = 67_108_864
    legacy_doc["jobs"]["job_openvex_export"]["settings"]["max_total_input_bytes"] = 268_435_456
    chains = legacy_doc["jobs"]["job_inference_security_review"]["settings"]["attack_chains"]
    chains["max_challenge_cells"] = 4
    chains["max_queries"] = 24
    chains["max_turns"] = 6
    raw = (json.dumps(legacy_doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    (tmp_path / "appsec-review.toml").write_bytes(legacy_toml_bytes)
    if live.profile_path is not None:
        (tmp_path / "profile.toml").write_bytes(live.profile_path.read_bytes())
    if live.host_pins is not None:
        (tmp_path / "host-pins.toml").write_bytes(live.host_pins.content)
    sources = [dict(layer) for layer in live.layers]
    sources[0]["sha256"] = legacy_source_sha
    manifest = {
        "resolved_sha256": digest,
        "sources": sources,
        "selection": {
            "profile": live.profile,
            "overlay": str(live.overlay_path) if live.overlay_path else None,
            "compiler_target": live.compiler_target.value,
            "source": live.selection_source,
        },
    }
    snap_cfg = load_config(
        ROOT / "appsec-review.toml",
        _snapshot=ConfigurationSnapshot(directory=tmp_path, manifest=manifest, document=json.loads(raw)),
    )
    assert snap_cfg.resolved_sha256 == digest
    live_doc = json.loads(live.resolved_json)
    snap_doc = json.loads(snap_cfg.resolved_json)
    fwd = operational_changes(snap_doc, live_doc)
    rev = operational_changes(live_doc, snap_doc)
    assert len(fwd) == len(rev) == 5
    assert configuration_compatible(snap_doc, live_doc) is True
    assert configuration_compatible(live_doc, snap_doc) is True

    bad_doc = deepcopy(legacy_doc)
    bad_doc["jobs"]["job_openvex_export"]["settings"]["max_artifact_bytes"] = 0
    assert configuration_compatible(bad_doc, live_doc) is False

    semantic_doc = deepcopy(legacy_doc)
    semantic_doc["jobs"]["job_openvex_export"]["settings"]["author"] = "changed-author"
    assert configuration_compatible(semantic_doc, live_doc) is False


def test_compatible_dataset_change_allows_missing_policy_tightening_for_openvex() -> None:
    steps = ["acceptance", "export", "load"]
    old_inputs = tuple(
        InputRequirement(
            "job_dependency_intelligence",
            "handoff",
            "appsec-review/job-handoff/2",
            authority=EvidenceAuthority.PRODUCER_EVIDENCE,
            availability=Availability.OPTIONAL,
            missing=MissingPolicy.NOT_APPLICABLE,
        )
        if (row.producer, row.output_kind) == ("job_dependency_intelligence", "handoff")
        else row
        for row in CONTRACT.inputs
        if (row.producer, row.output_kind)
        not in {("job_clang_static_analysis", "handoff"), ("job_clang_static_analysis", "clang_static_observations")}
    )
    old_job_contract = JobContract(
        inputs=old_inputs,
        schedule_after=CONTRACT.schedule_after,
        dispatch=CONTRACT.dispatch,
        target_access=CONTRACT.target_access,
        always_execute=CONTRACT.always_execute,
        propagate_handoff=CONTRACT.propagate_handoff,
    )
    previous = json.loads(canonical_json(dataset_contract(
        "job_openvex_export", steps, DATASETS, job_contract=old_job_contract.document())))
    current = dataset_contract(
        "job_openvex_export", steps, DATASETS, job_contract=CONTRACT.document())
    assert compatible_dataset_change(previous, current) is True
    # Loosening gap -> not_applicable or dropping inputs is rejected.
    assert compatible_dataset_change(json.loads(canonical_json(current)), previous) is False
