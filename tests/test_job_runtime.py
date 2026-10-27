from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
from appsec_review.runtime.runner import _accepted_retrieval_manifest
from tests.capture_fakes import build_capture_toml


def write_config(root: Path) -> Path:
    path = root / "appsec-review.toml"
    path.write_text(
        """
[runtime]
runs_dir = "runs"
data_dir = "data"

[jobs.job_fixture]
name = "fixture"
workers = 1
""".strip() + "\n\n" + build_capture_toml(),
        encoding="utf-8",
    )
    return path


def test_job_composes_validators_around_handler(tmp_path: Path) -> None:
    calls: list[str] = []

    def pre(context, result):
        assert result is None
        calls.append("pre")

    def handler(context):
        calls.append("handler")
        return {"value": 7}

    def post(context, result):
        assert result["outputs"]["work.only"] == {"value": 7}
        calls.append("post")

    job = Job("job_fixture", "fixture", handler, (pre,), (post,), units=(Unit("work.only", handler),))
    outcome = JobRunner(load_config(write_config(tmp_path))).run(
        job,
        now=datetime(2026, 10, 8, tzinfo=timezone.utc),
    )

    assert calls == ["pre", "handler", "post"]
    assert outcome["status"]["status"] == "SUCCEEDED"
    assert outcome["status"]["run_id"] == "2026-10-08-0001"
    configuration = tmp_path / "runs" / "2026-10-08-0001" / "data" / "configuration"
    assert (configuration / "appsec-review.toml").read_bytes() == (tmp_path / "appsec-review.toml").read_bytes()
    manifest = json.loads((configuration / "manifest.json").read_text(encoding="utf-8"))
    resolved = configuration / "resolved.json"
    assert manifest["schema"] == "appsec-review/run-configuration/2"
    assert manifest["source_sha256"]
    assert resolved.read_bytes() == load_config(tmp_path / "appsec-review.toml").resolved_json
    assert manifest["resolved"] == {"path": "resolved.json",
                                     "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()}


def test_specialized_manifest_does_not_replace_global_retrieval_manifest(tmp_path: Path) -> None:
    standard = tmp_path / "data" / "indices" / "standard.json"
    specialized = tmp_path / "data" / "indexes" / "owasp" / "specialized.json"
    for path, schema in ((standard, "appsec-review/index-manifest/1"),
                         (specialized, "appsec-review/owasp-index-manifest/1")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": schema}), encoding="utf-8")
    artifacts = [{
        "path": path.relative_to(tmp_path).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    } for path in (standard, specialized)]

    selected = _accepted_retrieval_manifest(tmp_path, artifacts)

    assert selected is not None
    assert selected[1] == standard.resolve()
    assert _accepted_retrieval_manifest(tmp_path, artifacts[1:]) is None


def test_failed_job_has_a_terminal_receipt(tmp_path: Path) -> None:
    def fail(context):
        raise RuntimeError("expected failure")

    job = Job("job_fixture", "fixture", fail, units=(Unit("work.only", fail),))
    runner = JobRunner(load_config(write_config(tmp_path)))
    with pytest.raises(RuntimeError, match="expected failure"):
        runner.run(job, now=datetime(2026, 10, 8, tzinfo=timezone.utc))

    status_path = next((tmp_path / "runs").glob("*/data/jobs/job_fixture/attempts/*/status.json"))
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["status"] == "FAILED"
    assert status["error"]["type"] == "RuntimeError"


def test_failed_input_preparation_records_terminal_without_executing_unit(tmp_path):
    def forbidden(unit):
        pytest.fail("invalid upstream reached unit execution")

    job = Job("job_fixture", "fixture", forbidden, units=(Unit("work.only", forbidden),))
    runner = JobRunner(load_config(write_config(tmp_path)))
    with pytest.raises(ValueError, match="expected exactly one accepted handoff"):
        runner.begin_attempt(job, upstream_handoffs={"job_missing": "0" * 64})
    attempt = next((tmp_path / "runs").glob("*/data/jobs/job_fixture/attempts/attempt_0001"))
    claim = json.loads((attempt / "claim.json").read_text())
    assert claim["upstream_handoffs"] == {"job_missing": "0" * 64}
    assert "input_manifest_path" not in claim
    assert json.loads((attempt / "status.json").read_text())["status"] == "FAILED"
    assert not (attempt / "steps").exists()
    events = [json.loads(line) for line in (attempt / "logs/events.jsonl").read_text().splitlines()]
    preparation = [event for event in events if event.get("operation_id") == "attempt.prepare_inputs"]
    assert [event["event"] for event in preparation] == ["OPERATION_STARTED", "OPERATION_COMPLETED"]
    assert preparation[-1]["terminal_status"] == "FAILED"


def test_unit_executor_attempts_independent_branch_and_skips_only_dependents(tmp_path: Path) -> None:
    calls: list[str] = []

    def fail(context):
        calls.append(context.unit_id)
        raise RuntimeError("branch failure")

    def succeed(context):
        calls.append(context.unit_id)
        return {"ok": True}

    units = (
        Unit("first.fetch", fail),
        Unit("second.fetch", succeed),
        Unit("first.publish", succeed, ("first.fetch",)),
        Unit("second.publish", succeed, ("second.fetch",)),
    )
    runner = JobRunner(load_config(write_config(tmp_path)))
    with pytest.raises(RuntimeError, match="branch failure"):
        runner.run(Job("job_fixture", "fixture", UnitExecutor(units).execute, units=units),
                   now=datetime(2026, 10, 8, tzinfo=timezone.utc))

    attempt = next((tmp_path / "runs").glob("*/data/jobs/job_fixture/attempts/attempt_0001"))

    def receipt(unit_id: str) -> dict | None:
        step, task = unit_id.split(".")
        path = attempt / "steps" / step / "tasks" / task / "status.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    assert calls == ["first.fetch", "second.fetch", "second.publish"]
    assert receipt("first.fetch")["status"] == "FAILED"
    assert receipt("first.publish") is None
    assert receipt("second.publish")["status"] == "SUCCEEDED"
    assert json.loads((attempt / "status.json").read_text(encoding="utf-8"))["status"] == "FAILED"


@pytest.mark.parametrize("declared", (False, True), ids=("undeclared", "declared"))
@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_platform_declaration_controls_accepted_attempt_reuse(
        tmp_path: Path, declared: bool, mode: str) -> None:
    from appsec_review.runtime.launch import complete
    from appsec_review.runtime.resume import ResumePlanner

    path = write_config(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            f'\n[review_policy]\nmode = "{mode}"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}\n'
            '\n[review_policy.releases]\nvalidation = "fixture-validation/1"\n')
        if declared:
            stream.write('platform = "fixture-platform/1"\n')
    config = load_config(path)
    calls = []

    def produce(unit):
        calls.append(unit.job.attempt_id)
        artifact = unit.job.attempt_root / "fixture.json"
        artifact.write_text('{"value": 7}\n', encoding="utf-8")
        return {"artifact": {"path": artifact.relative_to(unit.job.run_root).as_posix(),
                             "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}}

    job = Job("job_fixture", "fixture", produce, units=(Unit("work.only", produce),))
    first = JobRunner(config).run(job, now=datetime(2026, 10, 8, tzinfo=timezone.utc),
                                 target_root=target, source_fingerprint="target")
    run_id = first["status"]["run_id"]
    run_root = config.runtime.runs_dir / run_id
    published = {item["path"]: item for item in first["handoff"]["artifacts"]}
    for name in ("status.json", "result.json"):
        receipt = Path(first["attempt_root"]) / "steps/work/tasks/only" / name
        reference = published[receipt.relative_to(run_root).as_posix()]
        assert reference["sha256"] == hashlib.sha256(receipt.read_bytes()).hexdigest()
        assert reference["size_bytes"] == receipt.stat().st_size
    if mode == "first_party_managed":
        from appsec_review.storage.admission import consume_admission
        from appsec_review.storage.validation import validation_scope
        with validation_scope(run_root):
            assert consume_admission(run_root, first["handoff"])
    original_claim_path = Path(first["attempt_root"]) / "claim.json"
    original_claim_bytes = original_claim_path.read_bytes()
    configuration_path = config.runtime.runs_dir / run_id / "data/configuration/resolved.json"
    configuration_bytes = configuration_path.read_bytes()
    reasons, accepted_hash = ResumePlanner(
        config, config.runtime.runs_dir / run_id, (job,), "target", target_root=target).accepted(job, {})
    assert reasons == (() if declared else ("missing_release_identity",))
    assert accepted_hash == first["handoff_sha256"]

    runner = JobRunner(config)
    claim = runner.begin_or_reuse_attempt(job, run_id=run_id,
                                        target_root=target, source_fingerprint="target")
    assert bool(claim.get("reused")) is declared
    assert claim["review_policy"] == config.review_policy.view()
    second = complete(runner, job, claim)
    assert second["status"]["status"] == "SUCCEEDED"
    assert len(calls) == (1 if declared else 2)
    assert (second["handoff"]["attempt_id"] == first["handoff"]["attempt_id"]) is declared
    assert original_claim_path.read_bytes() == original_claim_bytes
    assert configuration_path.read_bytes() == configuration_bytes


RUNTIME_IDENTITY_JOBS = ("job_ci_configuration_analysis", "job_evidence_collection",
                         "job_review_prioritization", "job_source_history_analysis")


@pytest.mark.parametrize("name", ("status.json", "result.json"))
@pytest.mark.parametrize("damage", ("missing", "symlink"))
def test_handoff_rejects_unsafe_terminal_receipts(tmp_path: Path, name: str, damage: str) -> None:
    def produce(unit):
        return {"value": 7}

    def damage_receipt(context, result):
        path = context.attempt_root / "steps/work/tasks/only" / name
        path.unlink()
        if damage == "symlink":
            path.symlink_to(context.attempt_root / "claim.json")

    job = Job("job_fixture", "fixture", produce, output_validators=(damage_receipt,),
              units=(Unit("work.only", produce),))
    with pytest.raises(ValueError, match="unit terminal receipt is missing or unsafe"):
        JobRunner(load_config(write_config(tmp_path))).run(
            job, now=datetime(2026, 10, 8, tzinfo=timezone.utc))
    assert not list((tmp_path / "runs").rglob("handoff.json"))


@pytest.mark.parametrize("job_id", RUNTIME_IDENTITY_JOBS)
def test_runtime_identity_uses_declarations_without_reading_checkout_or_working_directory(
        job_id: str, tmp_path: Path, monkeypatch) -> None:
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.runtime.registry import builtin_registry

    repository = Path(__file__).resolve().parents[1]
    job = builtin_registry().build(job_id)
    assert job.runtime_identity is None
    empty = tmp_path / "empty-root"
    empty.mkdir()
    releases = ComponentReleases({"platform": "fixture-platform/1", "validation": "fixture-validation/1"})

    def no_payload_read(*args, **kwargs):
        pytest.fail("job identity attempted to read supplied payloads")

    monkeypatch.setattr(Path, "open", no_payload_read)
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG", raising=False)
    monkeypatch.chdir(repository)
    expected = job.identities(repository, releases)
    assert expected == {"implementation": "fixture-platform/1", "schema": job.schema_identity,
                        "validation": "fixture-validation/1"}
    monkeypatch.chdir(tmp_path)
    assert job.identities(repository, releases) == job.identities(empty, releases) == expected
    assert job.identities(empty)["implementation"] == "undeclared"
    assert job.identities(empty)["validation"] == "undeclared"
    assert job.identities(repository, ComponentReleases({
        **releases.view(), job_id: "fixture-job/2"}))["implementation"] == "fixture-job/2"


def test_builtin_job_construction_does_not_discover_or_read_platform_source(tmp_path, monkeypatch):
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.runtime.registry import builtin_registry

    root = Path(__file__).resolve().parents[1]
    supplied = tuple(root / name for name in ("src", "containers", "rules", ".venv"))
    registry = builtin_registry()
    releases = ComponentReleases({"platform": "fixture/1", "validation": "fixture/1"})
    original_glob, original_rglob, original_open = Path.glob, Path.rglob, Path.open

    def is_supplied(path):
        return any(path.resolve().is_relative_to(directory) for directory in supplied)

    def glob(path, *args, **kwargs):
        assert not is_supplied(path), f"job construction discovered platform files: {path}"
        return original_glob(path, *args, **kwargs)

    def rglob(path, *args, **kwargs):
        assert not is_supplied(path), f"job construction traversed platform files: {path}"
        return original_rglob(path, *args, **kwargs)

    def open_file(path, *args, **kwargs):
        if path.suffix in {".py", ".ql", ".qll"} or path.name == "Dockerfile":
            assert not is_supplied(path), f"job construction read a platform payload: {path}"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "glob", glob)
    monkeypatch.setattr(Path, "rglob", rglob)
    monkeypatch.setattr(Path, "open", open_file)
    for job_id in registry.job_ids():
        job = registry.build(job_id)
        assert job.runtime_identity is None
        assert job.identities(root, releases) == {
            "implementation": "fixture/1", "validation": "fixture/1", "schema": job.schema_identity}
