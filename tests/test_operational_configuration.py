from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json

import pytest

from appsec_review.config import load_config
from appsec_review.config.operational import MaterialConfigurationChange, operational_changes
from appsec_review.runtime import JobRunner, Unit
from appsec_review.runtime.configuration import (
    configuration_snapshot, context_configuration, persist_configuration_revision,
)
from appsec_review.runtime.repair import admit_repair, current_binding, plan_repair
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage.admission import verify_claim
from appsec_review.storage.shared import verify_handoff
from tests.test_repair_admission import fixture
from tests.openvex_support import enabled_settings
from tests.release_support import write_release


def configured(root, mode="strict"):
    config, jobs, calls = fixture(root)
    with config.source_path.open("a") as stream:
        stream.write('\n[jobs.job_openvex_export]\nname = "openvex_export"\nworkers = 1\n')
        stream.write('\n[jobs.job_openvex_export.settings]\n')
        for key, value in enabled_settings(enabled=False, timeout_seconds=120).to_mapping().items():
            stream.write(f"{key} = {json.dumps(value)}\n")
        stream.write(f'\n[review_policy]\nmode = "{mode}"\n')
        if mode == "first_party_managed":
            stream.write('project_id = "fixture"\napproved_first_party_projects = ["fixture"]\n')
            stream.write(f'target_root = {json.dumps(str(root))}\ncustody = "application_private_v1"\n')
    jobs = (*jobs, replace(jobs[0], job_id="job_openvex_export", name="openvex_export"))
    write_release(root, tuple(job.job_id for job in jobs))
    return load_config(config.source_path), jobs, calls


def increased(config):
    path = config.source_path
    path.write_text(path.read_text().replace("timeout_seconds = 120", "timeout_seconds = 1800"))
    return load_config(path)


@pytest.mark.parametrize("change", ["author", "workers", "policy", "unknown-timeout", "removed", "bool"])
def test_only_declared_execution_fields_are_compatible(tmp_path, change):
    config, _jobs, _calls = configured(tmp_path)
    before = json.loads(config.resolved_json)
    after = deepcopy(before)
    settings = after["jobs"]["job_openvex_export"]["settings"]
    settings["timeout_seconds"] = 1800
    assert operational_changes(before, after) == [{
        "job_id": "job_openvex_export", "path": ["settings", "timeout_seconds"],
        "category": "execution", "before": 120, "after": 1800,
    }]
    if change == "author":
        settings["author"] = "different output"
    elif change == "workers":
        after["jobs"]["job_fixture"]["workers"] = 2
    elif change == "policy":
        after["review_policy"]["mode"] = "first_party_managed"
    elif change == "unknown-timeout":
        settings["other_timeout_seconds"] = 1800
    elif change == "removed":
        del settings["timeout_seconds"]
    else:
        settings["timeout_seconds"] = True
    with pytest.raises(MaterialConfigurationChange):
        operational_changes(before, after)


def test_timeout_edit_preserves_accepted_jobs_without_writing_a_revision_during_preview(tmp_path):
    config, jobs, _calls = configured(tmp_path)
    output = JobRunner(config).run(jobs[0])
    root = config.runtime.runs_dir / output["status"]["run_id"]
    original = {path: path.read_bytes() for path in (root / "data/configuration").iterdir() if path.is_file()}
    changed = increased(config)
    plan = plan_repair(changed, root, jobs, "none")
    assert plan["admissible"], plan["refusals"]
    assert [row["action"] for row in plan["decisions"]] == ["REUSE", "RUN"]
    assert not (root / "data/configuration/revisions").exists()
    assert all(path.read_bytes() == payload for path, payload in original.items())
    assert current_binding(root)["repair"] is None
    with pytest.raises(ValueError, match="plan-repair"):
        JobRunner(changed)._bind_configuration(root)
    persist_configuration_revision(changed, root)
    with pytest.raises(ValueError, match="plan-repair"):
        JobRunner(changed)._bind_configuration(root)
    admit_repair(changed, root, jobs, plan)
    assert ResumePlanner(changed, root, jobs, "none").accepted(jobs[0], {})[0] == ()
    assert all(path.read_bytes() == payload for path, payload in original.items())
    verify_handoff(root, output["handoff"])


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_new_attempt_uses_admitted_timeout_and_preserves_failed_attempt(tmp_path, mode):
    config, jobs, _calls = configured(tmp_path, mode)

    def export(unit):
        timeout = unit.job.config.settings["timeout_seconds"]
        if timeout == 120:
            raise RuntimeError("startup exhausted the original allowance")
        assert context_configuration(unit.job)["jobs"]["job_openvex_export"]["settings"]["timeout_seconds"] == timeout
        return {"timeout_seconds": timeout}

    job = replace(jobs[1], units=(Unit("work.only", export),), consumes=("job_fixture",))
    runner = JobRunner(config)
    run_id, root = runner.runs.create(datetime.now(timezone.utc))
    origin = runner.run(jobs[0], run_id=run_id, target_root=tmp_path, source_fingerprint="a" * 64)
    upstream = {"job_fixture": origin["handoff_sha256"]}
    with pytest.raises(RuntimeError, match="partial failure"):
        runner.run(job, run_id=run_id, upstream_handoffs=upstream)
    prior = root / "data/jobs/job_openvex_export/attempts/attempt_0001"
    original = {name: (prior / name).read_bytes() for name in ("claim.json", "status.json")}
    changed = increased(config)
    plan = plan_repair(changed, root, (job,), "none")
    assert plan["admissible"], plan["refusals"]
    assert plan["unit_decisions"][job.job_id]["work.only"]["action"] == "RUN"
    admit_repair(changed, root, (job,), plan)
    result = JobRunner(changed).run(job, run_id=run_id, upstream_handoffs=upstream)
    assert result["status"]["status"] == "SUCCEEDED"
    assert result["status"]["attempt_id"] == "attempt_0002"
    claim = json.loads((root / "data/jobs/job_openvex_export/attempts/attempt_0002/claim.json").read_bytes())
    assert claim["resolved_config_sha256"] == changed.resolved_sha256 != config.resolved_sha256
    if mode == "first_party_managed":
        verify_claim(root, claim)
        verify_claim(root, json.loads(original["claim.json"]))
    verify_handoff(root, result["handoff"])
    paths = {item["path"] for item in result["handoff"]["artifacts"]}
    assert "data/configuration/resolved.json" in paths
    assert f"data/configuration/revisions/{changed.resolved_sha256}/resolved.json" in paths
    assert all((prior / name).read_bytes() == payload for name, payload in original.items())


def test_same_raw_configuration_still_rejects_a_changed_job_hash(tmp_path):
    config, jobs, _calls = configured(tmp_path)
    output = JobRunner(config).run(jobs[0])
    root = config.runtime.runs_dir / output["status"]["run_id"]
    mutated = replace(config, jobs={**config.jobs, jobs[0].job_id: replace(config.job(jobs[0].job_id), workers=2)})
    reasons, _ = ResumePlanner(mutated, root, jobs, "none").accepted(jobs[0], {})
    assert "job configuration identity changed" in reasons


@pytest.mark.parametrize("damage", ["resolved", "delta", "base"])
def test_revision_integrity_is_not_waived_for_compatible_settings(tmp_path, damage):
    config, _jobs, _calls = configured(tmp_path)
    runner = JobRunner(config)
    _run_id, root = runner.runs.create(datetime.now(timezone.utc))
    runner._bind_configuration(root)
    changed = increased(config)
    snapshot = persist_configuration_revision(changed, root)
    path = snapshot.directory / ("resolved.json" if damage == "resolved" else "manifest.json")
    document = json.loads(path.read_bytes())
    if damage == "resolved":
        document["jobs"]["job_openvex_export"]["settings"]["timeout_seconds"] = 600
    elif damage == "delta":
        document["operational_changes"][0]["after"] = 600
    else:
        document["base_resolved_sha256"] = "0" * 64
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="hash mismatch|deltas|original run"):
        configuration_snapshot(root, changed.resolved_sha256)
