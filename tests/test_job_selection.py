from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import pytest

from appsec_review.cli import GRAPH_JOB_IDS, main
from appsec_review.config import load_config
from appsec_review.jobs.job_review_data_indexing.job import _resolved_steps
from appsec_review.runtime import active_job_ids


ROOT = Path(__file__).parents[1]


def _set_enabled(source: str, job_id: str, enabled: bool) -> str:
    pattern = rf"(\[jobs\.{re.escape(job_id)}\.settings\][\s\S]*?\nenabled = )(?:true|false)(\n)"
    replaced, count = re.subn(pattern, rf"\g<1>{str(enabled).lower()}\g<2>", source, count=1)
    assert count == 1
    return replaced


def test_disabled_cpg_job_is_absent_from_the_application_graph() -> None:
    config = load_config(ROOT / "appsec-review.toml")

    selected = active_job_ids(config, GRAPH_JOB_IDS)

    assert "job_cpg_analysis" not in selected
    assert "job_cpp_symbol_index" in selected
    assert "job_codeql_analysis" in selected


def test_enabled_cpg_job_is_present_in_the_application_graph(tmp_path: Path) -> None:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_set_enabled(source, "job_cpg_analysis", True), encoding="utf-8")
    config = load_config(config_path)

    assert "job_cpg_analysis" in active_job_ids(config, GRAPH_JOB_IDS)


def test_job_level_enabled_flag_is_generic(tmp_path: Path) -> None:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_path = tmp_path / "appsec-review.toml"
    source = _set_enabled(source, "job_codeql_analysis", False)
    source = source.replace('execution_mode = "auto"', 'execution_mode = "disabled"', 1)
    config_path.write_text(source, encoding="utf-8")
    config = load_config(config_path)

    selected = active_job_ids(config, GRAPH_JOB_IDS)

    assert "job_codeql_analysis" not in selected
    assert "job_cpg_analysis" not in selected
    assert "job_evidence_collection" in selected


def test_direct_dispatch_rejects_disabled_cpg_job() -> None:
    with pytest.raises(ValueError, match="job is disabled by configuration: job_cpg_analysis"):
        main(["--config", str(ROOT / "appsec-review.toml"), "run", "job_cpg_analysis"])


def test_disabled_cpg_job_is_absent_from_resolved_inventory(tmp_path: Path) -> None:
    configuration = tmp_path / "data" / "configuration"
    configuration.mkdir(parents=True)
    resolved = json.dumps({"jobs": {
        "job_cpg_analysis": {"settings": {"enabled": False}, "steps": {"load": {}}},
        "job_review_intake": {"settings": {}, "steps": {"intake": {}}},
    }}, sort_keys=True).encode()
    (configuration / "resolved.json").write_bytes(resolved)
    (configuration / "manifest.json").write_text(json.dumps({
        "resolved_sha256": hashlib.sha256(resolved).hexdigest(),
    }), encoding="utf-8")

    assert _resolved_steps(tmp_path) == {"job_review_intake": ["intake"]}
