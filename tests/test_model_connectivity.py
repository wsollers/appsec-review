"""job_model_connectivity: the live model gate that opens every graph dispatch.

Unit tests: the real configuration file, the real runner, a fake provider check at the one external
boundary. No Docker, no model, no network, no target checkout.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.interchange import GAP_SCHEMA
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_model_connectivity import build_job
from appsec_review.jobs.job_model_connectivity.job import JOB_ID, ModelConnectivityBlocked, TOPOLOGY
from appsec_review.jobs.job_review_intake.job import PREFLIGHT_SCHEMA, configured_models, required_models
from appsec_review.runtime import GraphRunner

ROOT = Path(__file__).resolve().parents[1]
DISABLED_ONLY = "claude-disabled-only"


def _checkout(tmp_path: Path, *, rewrite=None) -> Path:
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    if rewrite is not None:
        path = tmp_path / "appsec-review.toml"
        path.write_text(rewrite(path.read_text(encoding="utf-8")), encoding="utf-8")
    return tmp_path / "appsec-review.toml"


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    return target


def _check(calls: list, *, unavailable: dict[str, str] | None = None, error: str | None = None):
    def check(provider: str, names, *, timeout_seconds: int):
        calls.append({"provider": provider, "names": tuple(sorted(names)), "timeout": timeout_seconds})
        if error is not None:
            return {"provider": provider, "transport": False, "method": "catalog", "listed": [],
                    "error": error, "models": {}}
        return {"provider": provider, "transport": True, "method": "catalog", "listed": sorted(names), "error": None,
                "models": {name: ({"available": False, "detail": (unavailable or {})[name]}
                                  if name in (unavailable or {}) else {"available": True, "detail": "listed"})
                           for name in names}}
    return check


def _run(tmp_path: Path, check, *, path: Path | None = None):
    """Run the gate alone. A failed gate raises from the runner; the run tree is returned either way."""
    path = path or _checkout(tmp_path)
    config = load_config(path, profile="dev")
    target = _target(tmp_path)
    try:
        outcome = GraphRunner(config, [build_job(check_models=check)]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    except RuntimeError as error:
        outcome = {"status": "FAILED", "error": str(error)}
    [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
    return config, outcome, run_root


def _disable_only_model(text: str) -> str:
    """Point the already-disabled post-build model setting at a model nothing else names."""
    block = '[jobs.job_post_build_security_assessment.settings.model]\nenabled = false\nprovider = "claude-cli"\nmodel = "claude-haiku-5-5"'
    assert text.count(block) == 1
    return text.replace(block, block.replace('model = "claude-haiku-5-5"', f'model = "{DISABLED_ONLY}"'))


# ------------------------------------------------------------------ the pure decision

def test_required_models_excludes_disabled_jobs_and_disabled_settings() -> None:
    document = {"jobs": {
        "job_a": {"settings": {"model": {"provider": "p", "model": "m-live"}}},
        "job_b": {"settings": {"enabled": False, "model": {"provider": "p", "model": "m-job-off"}}},
        "job_c": {"settings": {"model": {"provider": "p", "model": "m-setting-off", "enabled": False}}},
        "job_d": {"settings": {"enabled": True, "models": {"x": {"provider": "q", "model": "m-nested"}}}},
    }}
    required, not_required = required_models(document)
    assert [(item["job_id"], item["model"]) for item in required] == [("job_a", "m-live"), ("job_d", "m-nested")]
    assert {(item["job_id"], item["reason"]) for item in not_required} == {
        ("job_b", "job disabled"), ("job_c", "model setting disabled")}
    assert len(configured_models(document)) == 4


# ------------------------------------------------------------------ the runtime path

def test_gate_checks_every_configured_model_and_publishes_the_required_split(tmp_path: Path) -> None:
    calls: list = []
    path = _checkout(tmp_path, rewrite=_disable_only_model)
    config, outcome, run_root = _run(tmp_path, _check(calls), path=path)
    assert outcome["status"] == "SUCCEEDED", outcome
    # One provider call names every configured model, required or not.
    assert calls == [{"provider": "claude-cli", "names": (DISABLED_ONLY, "claude-haiku-5-5"),
                      "timeout": config.jobs[JOB_ID].settings["timeout_seconds"]}]
    attempt = next((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())
    document = json.loads((attempt / "steps/connectivity/tasks/verify_models/model-connectivity.json")
                          .read_text(encoding="utf-8"))
    assert document["schema"] == PREFLIGHT_SCHEMA
    assert document["unavailable"] == [] and document["unavailable_not_required"] == [] and document["gaps"] == []
    assert {item["model"] for item in document["required"]} == {"claude-haiku-5-5"}
    assert [(item["model"], item["reason"]) for item in document["not_required"]] == [
        (DISABLED_ONLY, "model setting disabled")]
    handoff = json.loads((attempt / "steps/publication/tasks/publish_handoff/model-connectivity-handoff.json")
                         .read_text(encoding="utf-8"))
    assert handoff["verified"] == [f"claude-cli/{DISABLED_ONLY}", "claude-cli/claude-haiku-5-5"]
    assert handoff["not_required"] == [f"claude-cli/{DISABLED_ONLY}"]
    assert (run_root / "data/jobs" / JOB_ID / "latest.json").is_file()


def test_a_missing_model_that_only_a_disabled_setting_names_is_a_gap_not_a_block(tmp_path: Path) -> None:
    calls: list = []
    path = _checkout(tmp_path, rewrite=_disable_only_model)
    config, outcome, run_root = _run(tmp_path, _check(calls, unavailable={DISABLED_ONLY: "not listed"}), path=path)
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    attempt = next((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())
    document = json.loads((attempt / "steps/connectivity/tasks/verify_models/model-connectivity.json")
                          .read_text(encoding="utf-8"))
    assert document["unavailable"] == []
    assert [item["model"] for item in document["unavailable_not_required"]] == [DISABLED_ONLY]
    [gap] = document["gaps"]
    assert gap["schema"] == GAP_SCHEMA and gap["code"] == "producer_blocked" and gap["retryable"] is True
    assert gap["scope_id"] == f"claude-cli/{DISABLED_ONLY}" and "disabled job_post_build_security_assessment" in gap["reason"]
    result = json.loads((attempt / "steps/connectivity/tasks/verify_models/result.json").read_text(encoding="utf-8"))
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["verified"] == ["claude-cli/claude-haiku-5-5"]
    # The gate still publishes: the review may start without the disabled job's model.
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_text(encoding="utf-8"))
    handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
    published = json.loads((run_root / handoff["outputs"]["publication.publish_handoff"]["artifact"]["path"])
                           .read_text(encoding="utf-8"))
    assert published["unavailable_not_required"] == [f"claude-cli/{DISABLED_ONLY}"]
    assert [gap["code"] for gap in handoff["outputs"]["connectivity.verify_models"]["gaps"]] == ["producer_blocked"]
    assert handoff["outputs"]["connectivity.verify_models"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    outcomes = json.loads((run_root / handoff["outcomes"]["path"]).read_text(encoding="utf-8"))
    assert [gap["code"] for gap in outcomes["gaps"]] == ["producer_blocked"]


def test_an_unavailable_required_model_fails_the_gate_with_a_named_gap_record(tmp_path: Path) -> None:
    calls: list = []
    config, outcome, run_root = _run(tmp_path, _check(calls, unavailable={"claude-haiku-5-5": "model not listed"}))
    assert outcome["status"] == "FAILED", outcome
    assert "connectivity.verify_models: model connectivity blocked the review" in outcome["error"]
    attempt = next((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())
    assert not (run_root / "data/jobs" / JOB_ID / "latest.json").exists()
    document = json.loads((attempt / "steps/connectivity/tasks/verify_models/model-connectivity.json")
                          .read_text(encoding="utf-8"))
    configured = [*document["required"], *document["not_required"]]
    assert document["unavailable"] == [{"provider": "claude-cli", "model": "claude-haiku-5-5", "detail": "model not listed",
                                        "jobs": sorted({item["job_id"] for item in configured})}]
    assert "job_post_build_security_assessment" in document["unavailable"][0]["jobs"]  # disabled setting, still named
    assert document["gaps"] == [] and document["unavailable_not_required"] == []
    receipt = json.loads((attempt / "steps/connectivity/tasks/verify_models/status.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "FAILED" and receipt["error"]["type"] == ModelConnectivityBlocked.__name__
    assert "claude-cli/claude-haiku-5-5 (model not listed)" in receipt["error"]["message"]
    publish = attempt / "steps/publication/tasks/publish_handoff/status.json"
    assert not publish.exists() or json.loads(publish.read_text(encoding="utf-8"))["status"] != "SUCCEEDED"


def test_a_provider_transport_error_is_reported_per_model_from_the_report_error(tmp_path: Path) -> None:
    calls: list = []
    config, outcome, run_root = _run(tmp_path, _check(calls, error="connection refused"))
    assert outcome["status"] == "FAILED"
    attempt = next((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())
    document = json.loads((attempt / "steps/connectivity/tasks/verify_models/model-connectivity.json")
                          .read_text(encoding="utf-8"))
    assert [item["detail"] for item in document["unavailable"]] == ["connection refused"]
    assert document["providers"]["claude-cli"]["transport"] is False


def test_the_gate_succeeds_again_on_resume_when_the_provider_recovers(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    config = load_config(path, profile="dev")
    target = _target(tmp_path)
    fingerprint = source_fingerprint(target)
    with pytest.raises(RuntimeError, match="down"):
        GraphRunner(config, [build_job(check_models=_check([], error="down"))]).run(
            target_root=target, source_fingerprint=fingerprint)
    [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
    second = GraphRunner(config, [build_job(check_models=_check([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_root.name)
    assert second["status"] == "SUCCEEDED", second
    attempts = sorted((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())
    assert len(attempts) == 2
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_text(encoding="utf-8"))
    assert attempts[1].name in pointer["handoff_path"]


# ------------------------------------------------------------------ claim-time refusals

def test_an_unwired_check_is_refused_before_any_unit_runs(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    config = load_config(path, profile="dev")
    target = _target(tmp_path)
    with pytest.raises(ValueError, match="not wired"):
        GraphRunner(config, [build_job()]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    runs = list(config.runtime.runs_dir.glob("*/data/jobs/" + JOB_ID + "/attempts/*/steps"))
    assert runs == [], "no unit may run when the gate cannot ask its question"


@pytest.mark.parametrize("timeout,message", [("120", "timeout"), (0, "timeout"), (601, "timeout")],
                         ids=["string", "zero", "too-large"])
def test_timeout_outside_the_bound_is_refused(tmp_path: Path, timeout, message) -> None:
    def rewrite(text: str) -> str:
        old = "[jobs.job_model_connectivity.settings]\n# Every graph dispatch makes a live, tool-disabled request to every configured model.\ntimeout_seconds = 120"
        assert text.count(old) == 1
        value = f'"{timeout}"' if isinstance(timeout, str) else str(timeout)
        return text.replace(old, old.replace("timeout_seconds = 120", f"timeout_seconds = {value}"))
    path = _checkout(tmp_path, rewrite=rewrite)
    config = load_config(path, profile="dev")
    target = _target(tmp_path)
    with pytest.raises(ValueError, match=message):
        GraphRunner(config, [build_job(check_models=_check([]))]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))


def test_configured_topology_matches_the_job() -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    job = config.jobs[JOB_ID]
    assert tuple(job.steps) == tuple(TOPOLOGY)
    for step, tasks in TOPOLOGY.items():
        assert tuple(job.step(step).tasks) == tasks
    built = build_job(check_models=_check([]))
    assert [unit.unit_id for unit in built.units] == [f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks]
    assert built.strict_gaps and built.always_execute and not built.propagate_handoff
