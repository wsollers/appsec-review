from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.jobs.cataloging import raw_snapshot, source_fingerprint
from appsec_review.jobs.job_change_context_analysis import build_job as build_change_context
from appsec_review.jobs.job_source_history_analysis import load_accepted_history, load_accepted_hotspots
from appsec_review.jobs.job_source_history_analysis.discovery import discover_sources, github_repository, read_pinned
from appsec_review.jobs.job_source_history_analysis.github import _NoRedirect
from appsec_review.jobs.job_source_history_analysis.sources import history_identity
from appsec_review.config import load_config
from appsec_review.observability import EventLog
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.units import UnitContext
from appsec_review.runtime.job import JobContext
from appsec_review.storage import atomic_json, file_sha256
from tests.test_source_history_analysis import LocalDocker, ROOT, T0, commit, configured, git, history_job, write


def repository(root: Path) -> str:
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    write(root, "pyproject.toml", "[project]\nname = 'fixture'\n")
    write(root, "src/shared.py", "def check():\n    return True\n")
    commit(root, "initial", T0)
    write(root, "src/shared.py", "def check():\n    return False\n")
    return commit(root, "fix auth", T0 + 100)


def acquisition_fixture(root: Path, target: Path, revisions: dict[str, str]) -> None:
    record_root = root / "data" / "target-acquisitions" / "system"
    identities, components = {}, {}
    for name, revision in revisions.items():
        identity = {"kind": "git", "commit": revision}
        spec = {"kind": "git", "url": f"https://github.com/acme/{name}.git", "commit": revision}
        change_context = None
        if name == "worker":
            identity = {"kind": "review_export", "provider": "gitlab", "revision": revision,
                        "change": 7, "git": {"kind": "git", "commit": revision}}
            spec = {"kind": "review_export", "clone_url": "https://gitlab.example/acme/worker.git"}
            review_path = record_root / "components" / name / "review-records.json"
            atomic_json(review_path, {"schema": "appsec-review/review-records/1", "records": {
                revision: {"pull_request": 7, "head_sha": revision, "created_at": "2023-11-14T20:00:00Z",
                           "merged_at": "2023-11-14T22:15:00Z", "approvals": [
                               {"submitted_at": "2023-11-14T21:00:00Z", "commit_id": revision}]}}})
            change_context = {"source": "export", "export_path": review_path.relative_to(root).as_posix(),
                              "export_sha256": file_sha256(review_path)}
        manifest_path = record_root / "components" / name / "manifest.json"
        atomic_json(manifest_path, {"schema": "appsec-review/target-acquisition/1", "target_id": name,
                                   "target_path": (target / name).relative_to(root).as_posix(),
                                   "identity": identity, "spec": spec, "change_context": change_context})
        identities[name] = {"identity": identity}
        components[name] = {"status": "COMPLETE", "manifest": manifest_path.relative_to(root).as_posix(),
                            "manifest_sha256": file_sha256(manifest_path)}
    legacy = record_root / "components" / "legacy" / "manifest.json"
    atomic_json(legacy, {"schema": "appsec-review/target-acquisition/1", "target_id": "legacy",
                        "target_path": (target / "legacy").relative_to(root).as_posix(),
                        "identity": {"kind": "perforce", "changelist": 123}, "spec": {"kind": "perforce"}})
    identities["legacy"] = {"identity": {"kind": "perforce", "changelist": 123}}
    components["legacy"] = {"status": "COMPLETE", "manifest": legacy.relative_to(root).as_posix(),
                            "manifest_sha256": file_sha256(legacy)}
    components["missing"] = {"status": "FAILED", "manifest": None, "manifest_sha256": None}
    atomic_json(record_root / "manifest.json", {
        "schema": "appsec-review/target-system-acquisition/1", "system_id": "system",
        "target_path": target.relative_to(root).as_posix(), "status": "PARTIAL", "acquisition_id": "system@fixture",
        "identity": identities, "components": components, "tree": raw_snapshot(target), "gaps": []})


def read(run_root: Path, identity):
    return json.loads((run_root / identity["path"]).read_text())


def test_composed_acquisition_history_and_change_context_keep_sources_separate(tmp_path: Path, monkeypatch):
    config = configured(tmp_path)
    target = tmp_path / "targets" / "system"
    api = repository(target / "api")
    worker = repository(target / "worker")
    assert api == worker, "identical commits and paths must still retain distinct repository identity"
    write(target / "api", "src/shared.py", "def check():\n    return 'new main'\n")
    commit(target / "api", "later main", T0 + 200)
    git(target / "api", "checkout", "--detach", api)
    write(target, "legacy/src/shared.py", "def legacy():\n    return True\n")
    acquisition_fixture(tmp_path, target, {"api": api, "worker": worker})
    assert not (target / ".git").exists()
    monkeypatch.setenv("GITHUB_TOKEN", "fixture-token")
    calls = []

    def transport(url, headers, timeout):
        assert url.startswith("https://api.github.com/repos/acme/api/")
        assert headers["Authorization"] == "Bearer fixture-token"
        calls.append(url)
        if "/pulls?" in url:
            if api in url:
                return 200, {}, json.dumps([{
                    "number": 7, "merge_commit_sha": api, "merged_at": "2023-11-14T22:15:00Z",
                    "created_at": "2023-11-14T20:00:00Z", "user": {"login": "author"},
                    "head": {"sha": api}}]).encode()
            return 200, {}, b"[]"
        if "/reviews?" in url:
            return 200, {}, b"[]"
        if url.endswith("/pulls/7"):
            return 200, {}, json.dumps({"merged_by": {"login": "author"}, "head": {"sha": api}}).encode()
        return 200, {}, json.dumps({"sha": api, "commit": {"committer": {"date": "2023-11-14T22:14:00Z"}}}).encode()

    docker = LocalDocker()
    from appsec_review.container_runtime import ContainerExecutor, load_catalog
    change_job = build_change_context(executor_factory=lambda unit: ContainerExecutor(
        load_catalog(unit.job.repository_root), unit.job.run_root, runner=docker))
    outcome = GraphRunner(config, (build_intake(), build_catalog(),
                                   history_job(docker, github_transport=transport), change_job)).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    history = outcome["jobs"]["job_source_history_analysis"]["result"]["outputs"]
    context = outcome["jobs"]["job_change_context_analysis"]["result"]["outputs"]
    resolved = history["resolve_sources.resolve_history_source"]["by_source"]
    assert set(resolved) == {"api", "worker", "legacy", "missing"}
    assert resolved["api"]["git"]["snapshot_commit"] == api
    assert resolved["api"]["git"]["mainline_ref"] is None, "the approved pin wins over main"
    assert resolved["api"]["source"]["github_repository"] == "acme/api"
    assert "history_backend_unsupported:perforce" in resolved["legacy"]["gaps"]
    assert resolved["missing"]["git"]["decision"] == "GAP"
    assert calls
    for name in ("api", "worker"):
        binding = history["resolve_sources.bind_snapshot"]["by_source"][name]
        assert binding["binding"] == "exact"
        facts = binding["eligible"][f"{name}/src/shared.py"]
        assert facts["source_path"] == "src/shared.py" and facts["source_id"] == name
        assert facts["pinned_revision"] == api
        changes = read(run_root, history["acquire.normalize_changes"]["by_source"][name]["artifact"])["changes"]
        assert all(entry["path"].startswith(name + "/") for change in changes for entry in change["files"])
        loaded = context["load.accepted_history"]["by_source"][name]
        assert f"{name}/src/shared.py" in loaded["eligible"]
    worker_external = context["load.external_sources"]["by_source"]["worker"]
    assert worker_external["sources"]["review"]["source"] == "acquired_export"
    worker_reviews = read(run_root, worker_external["artifact"])["reviews"]
    assert worker_reviews[worker]["approved_by_other"] is True
    api_reviews = read(run_root, context["load.external_sources"]["by_source"]["api"]["artifact"])["reviews"]
    assert api_reviews[api]["pull_request"] == 7 and api_reviews[api]["approved_by_other"] is False
    accepted = load_accepted_history(run_root)
    assert {item["source_id"] for item in accepted["sources"]["repositories"]} == set(resolved)
    assert {item["path"] for item in accepted["ranking"]["files"]} >= {
        "api/src/shared.py", "worker/src/shared.py"}
    hotspots = load_accepted_hotspots(run_root)
    assert {item["source"]["source_path"] for item in hotspots["entries"]} >= {"src/shared.py"}
    from jsonschema import validate
    schema = json.loads((ROOT / "docs" / "schemas" / "history-hotspots.schema.json").read_text())
    validate({key: value for key, value in hotspots.items() if key != "handoff_sha256"}, schema)
    manifest = read(run_root, context["publish.index_change_context"]["manifest"])
    assert len([item for item in manifest["indexes"] if item["name"] == "history"]) == 8
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = core.query_change_context(scope="file", limit=20)["results"]
    assert {item["location"]["path"] for item in rows} >= {"api/src/shared.py", "worker/src/shared.py"}
    change_ids = [LogicalIdentity.derive(EntityKind.CHANGE, source_fingerprint(target),
                                        {"vcs": "git", "source_id": name, "change_id": api}).value
                  for name in ("api", "worker")]
    assert change_ids[0] != change_ids[1]
    assert all(core.find(identity=key, indexes=("history",))["results"] for key in change_ids)
    review_units = core.find(kind="review_unit", indexes=("history",), limit=20)["results"]
    assert len(review_units) == 2 and {item["payload"]["pull_request"] for item in review_units} == {7}
    assert {item["payload"]["repository_source"]["source_id"] for item in review_units} == {"api", "worker"}
    from appsec_review.jobs.job_target_analysis_plan.planning import history_priority
    priority = history_priority(accepted, {
        "files": [item for value in resolved.values() for item in value["inputs"]["files"]],
        "components": resolved["api"]["inputs"]["components"]})
    assert {item["source_id"] for item in priority["files"]} == {"api", "worker"}
    page = core.query_change_context(scope="file", limit=1)
    assert len(page["results"]) == 1 and page["pagination"]["next_cursor"]
    next_page = core.query_change_context(scope="file", limit=1, cursor=page["pagination"]["next_cursor"])
    assert page["results"][0]["identity"] != next_page["results"][0]["identity"]
    assert core.query_change_context(scope="file", path="worker/src/shared.py", limit=10)["results"]
    assert any("legacy:history_backend_unsupported:perforce" in gap
               for gap in history["publish.publish_handoff"]["gaps"])
    from appsec_review.jobs.job_review_prioritization import build_job as build_priority
    inputs = {
        "extract.syntax_metrics": {"files": {
            f"{name}/src/shared.py": {
                "language": "Python", "component_id": name, "cyclomatic_max": 1, "cognitive_max": 0,
                "complexity_density": 1, "share_above_threshold": {}, "suppression_count": 0,
                "sloc": 2, "signal_counts": {}, "signals": [], "suppressions": [], "units": [], "gaps": []}
            for name in ("api", "worker")}},
        "extract.dependency_graph": {"files": {}},
        "extract.semantic_evidence": {"codeql": {"languages": {}}, "semgrep_signals": [], "semantic_paths": []}}
    outputs = {}
    for name, value in inputs.items():
        path = run_root / "priority-fixture" / f"{name}.json"
        atomic_json(path, value)
        outputs[name] = {"artifact": {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}}
    priority_context = JobContext(
        run_id=outcome["run_id"], attempt_id="attempt_0001", trigger="test", repository_root=tmp_path,
        run_root=run_root, attempt_root=run_root / "priority-fixture", metadata_root=run_root / "metadata",
        orchestration={}, config=config.job("job_review_prioritization"), events=EventLog(run_root / "events.jsonl"),
        target_root=target, source_fingerprint=source_fingerprint(target))
    priority_unit = UnitContext(priority_context, "prioritize.score", "prioritize", "score",
                                run_root / "priority-fixture" / "score", outputs)
    scorer = next(item.handler for item in build_priority().units if item.unit_id == priority_unit.unit_id)
    priorities = scorer(priority_unit)
    assert priorities["history_status"] == "PARTIAL"
    scores = {item["path"]: item["features"]["history_hotspot"]
              for item in read(run_root, priorities["artifact"])["files"]}
    assert set(scores) == {"api/src/shared.py", "worker/src/shared.py"}
    assert scores == {item["path"]: item["score"] for item in accepted["ranking"]["files"] if item["path"] in scores}


def test_direct_target_discovery_is_bounded_and_nonexecuting(tmp_path: Path, monkeypatch):
    target = tmp_path / "target"
    revision = repository(target / "one")
    repository(target / "two")
    git(target / "one", "config", "remote.origin.url", "git@github.com:acme/one.git")
    git(target / "two", "config", "remote.origin.url", "https://[invalid/acme/two.git")
    git(target / "one", "config", "include.path", str(tmp_path / "outside-config"))
    (tmp_path / "outside-config").write_text('[remote "origin"]\nurl = https://attacker.invalid/escape\n')
    monkeypatch.setattr(Path, "rglob", lambda *args: pytest.fail("unbounded target scan"))
    values = discover_sources(target=target, repository=tmp_path, acquisition=None, components=[],
                              api_base="https://api.github.com")
    assert {item["root"] for item in values} == {"one", "two"}
    assert values[0]["github_repository"] == "acme/one" and values[1]["github_repository"] is None
    assert values[1]["git"]["decision"] == "SUCCEEDED", "an unusable remote must not discard local history"
    assert "config_includes_ignored" in values[0]["git"]["observations"]
    before = history_identity(target)
    (target / "one" / ".git" / "HEAD").write_text("f" * 40 + "\n")
    assert history_identity(target) != before
    (target / "one" / ".git" / "HEAD").write_text(revision + "\n")
    assert history_identity(target) == before
    monkeypatch.setattr("appsec_review.jobs.job_source_history_analysis.sources.MAX_DISCOVERY_ENTRIES", 1)
    with pytest.raises(ValueError, match="discovery_bound"):
        discover_sources(target=target, repository=tmp_path, acquisition=None, components=[],
                         api_base="https://api.github.com")


@pytest.mark.parametrize(("url", "api", "expected"), [
    ("https://github.com/acme/widget.git", "https://api.github.com", "acme/widget"),
    ("git@github.com:acme/widget.git", "https://api.github.com", "acme/widget"),
    ("ssh://git@github.com/acme/widget.git", "https://api.github.com", "acme/widget"),
    ("https://github.enterprise/acme/widget.git", "https://github.enterprise/api/v3", "acme/widget"),
    ("https://github.com.attacker.invalid/acme/widget", "https://api.github.com", None),
    ("https://github.com@attacker.invalid/acme/widget", "https://api.github.com", None),
    ("https://token@github.com/acme/widget", "https://api.github.com", None),
    ("https://github.com/acme/../widget", "https://api.github.com", None),
    ("https://github.com:444/acme/widget", "https://api.github.com", None),
    ("https://[invalid/acme/widget", "https://api.github.com", None),
    ("ext::helper", "https://api.github.com", None),
])
def test_github_discovery_never_selects_target_endpoints(url, api, expected):
    assert github_repository(url, api) == expected


def test_github_redirects_and_metadata_symlinks_are_refused(tmp_path: Path):
    assert _NoRedirect().redirect_request(None, None, 302, "", {}, "https://attacker.invalid") is None
    outside = tmp_path / "outside"
    outside.mkdir()
    atomic_json(outside / "record.json", {"records": {}})
    (tmp_path / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        read_pinned(tmp_path, "link/record.json", file_sha256(outside / "record.json"))
    with pytest.raises(ValueError, match="unsafe"):
        read_pinned(tmp_path, "../record.json", "a" * 64)


@pytest.mark.parametrize(("enabled", "credential", "reason"), [
    ("auto", None, "github_credentials_missing"),
    (False, "fixture-token", "github_enrichment_disabled"),
    ("auto", "fixture-token", "github_snapshot_unavailable"),
])
def test_direct_target_auto_enrichment_respects_credentials_and_deny_policy(
        tmp_path: Path, monkeypatch, enabled, credential, reason):
    from appsec_review.jobs.job_source_history_analysis import job as history_module
    target, run = tmp_path / "target", tmp_path / "run"
    revision = repository(target)
    git(target, "config", "remote.origin.url", "https://github.com/acme/discovered.git")
    config = load_config(ROOT / "appsec-review.toml").job("job_source_history_analysis")
    config = replace(config, settings={**config.settings, "github": {**config.settings["github"], "enabled": enabled}})
    monkeypatch.setattr(history_module, "_load_inputs", lambda root: {
        "source_fingerprint": "snapshot", "files": [], "components": [], "acquisition": None})
    if credential:
        monkeypatch.setenv("GITHUB_TOKEN", credential)
    else:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    calls = []

    def transport(url, headers, timeout):
        calls.append(url)
        raise OSError("fixture network unavailable")

    job = history_module.build_job(github_transport=transport)
    handlers = {item.unit_id: item.handler for item in job.units}
    context = JobContext(
        run_id="fixture", attempt_id="attempt_0001", trigger="test", repository_root=tmp_path,
        run_root=run, attempt_root=run / "attempt", metadata_root=run / "metadata",
        orchestration={}, config=config, events=EventLog(run / "events.jsonl"),
        target_root=target, source_fingerprint="snapshot")
    unit = UnitContext(context, "resolve_sources.resolve_history_source", "resolve_sources", "resolve_history_source",
                       run / "resolve", {})
    resolved = handlers[unit.unit_id](unit)
    assert resolved["source"]["github_repository"] == "acme/discovered"
    assert resolved["git"]["snapshot_commit"] == revision
    changes = run / "changes.json"
    atomic_json(changes, {"changes": []})
    normalized = {"artifact": {"path": "changes.json", "sha256": file_sha256(changes)}}
    result = handlers["acquire.github_enrichment"](replace(
        unit, unit_id="acquire.github_enrichment", unit_root=run / "github",
        outputs={"resolve_sources.resolve_history_source": resolved, "acquire.normalize_changes": normalized}))
    assert reason == result.get("reason") or reason in result["gaps"]
    assert len(calls) == (1 if enabled == "auto" and credential else 0)


def test_nested_catalog_source_metadata_is_part_of_resume_identity(tmp_path: Path, monkeypatch):
    from appsec_review.jobs.job_source_history_analysis import job as history_module
    target, run = tmp_path / "target", tmp_path / "run"
    repository(target / "nested" / "repo")
    atomic_json(run / "data" / "jobs" / "job_target_catalog" / "latest.json", {})
    monkeypatch.setattr(history_module, "_load_inputs", lambda root: {
        "components": [{"component_id": "nested", "root": "nested/repo"}]})
    job = history_module.build_job()
    before = job.probe_input_identity(target, run)
    cheap = history_identity(target)
    (target / "nested" / "repo" / ".git" / "HEAD").write_text("f" * 40 + "\n")
    assert history_identity(target) == cheap
    assert job.probe_input_identity(target, run) != before
    assert history_identity(target, ("../outside",)) != cheap


def test_failed_source_lane_is_reported_without_discarding_its_peer(tmp_path: Path):
    from types import SimpleNamespace
    from appsec_review.jobs.source_lanes import per_source
    events = EventLog(tmp_path / "events.jsonl")
    first = {"by_source": {"bad": {"source": {"source_id": "bad"}},
                            "good": {"source": {"source_id": "good"}}}}
    unit = UnitContext(SimpleNamespace(events=events), "acquire.git_history", "acquire", "git_history",
                       tmp_path / "unit", {"resolve_sources.resolve_history_source": first})
    called = []

    def handler(context):
        source = context.output("resolve_sources.resolve_history_source")["source"]["source_id"]
        called.append(source)
        if source == "bad":
            raise OSError("fixture producer failed")
        return {"artifact": {"path": "retained"}, "gaps": [], "terminal_status": "SUCCEEDED"}

    output = per_source(handler, "resolve_sources.resolve_history_source")(unit)
    assert called == ["bad", "good"]
    assert output["by_source"]["bad"]["source_error"] is True
    assert output["by_source"]["good"]["artifact"] == {"path": "retained"}
    assert output["gaps"] == ["bad:source_failed:acquire.git_history:OSError"]
    called.clear()
    next_unit = replace(unit, unit_id="acquire.normalize_changes",
                        outputs={**unit.outputs, "acquire.git_history": output})
    after = per_source(handler, "resolve_sources.resolve_history_source")(next_unit)
    assert called == ["good"]
    assert after["by_source"]["bad"]["reason"] == "upstream_source_failed"
    assert "SOURCE_LANE_FAILED" in (tmp_path / "events.jsonl").read_text()


def test_changed_component_manifest_is_a_gap_without_falling_back_to_target_remote(tmp_path: Path):
    target = tmp_path / "targets" / "system"
    revision = repository(target / "api")
    repository(target / "worker")
    write(target, "legacy/value.py", "VALUE = 1\n")
    acquisition_fixture(tmp_path, target, {"api": revision, "worker": revision})
    path = tmp_path / "data" / "target-acquisitions" / "system" / "manifest.json"
    accepted = json.loads(path.read_text())
    component_manifest = path.parent / "components" / "api" / "manifest.json"
    component_manifest.write_bytes(component_manifest.read_bytes() + b"\n")
    git(target / "api", "config", "remote.origin.url", "https://github.com/attacker/fallback.git")
    values = discover_sources(target=target, repository=tmp_path, acquisition=accepted, components=[],
                              api_base="https://api.github.com")
    api = next(value for value in values if value["source_id"] == "api")
    worker = next(value for value in values if value["source_id"] == "worker")
    assert api["git"]["decision"] == "GAP" and api["github_repository"] is None
    assert worker["git"]["decision"] == "SUCCEEDED"


@pytest.mark.parametrize(("review_source", "review_gap"), [
    ("export", "review_export_source_ambiguous"),
    ("none", "review_records_disabled"),
])
def test_composed_context_does_not_cross_attribute_global_exports(
        tmp_path: Path, monkeypatch, review_source, review_gap):
    from appsec_review.jobs.job_change_context_analysis import job as context_module
    config = load_config(ROOT / "appsec-review.toml").job("job_change_context_analysis")
    config = replace(config, settings={
        **config.settings,
        "review": {**config.settings["review"], "source": review_source, "export_path": "review.json"},
        "deployments": {**config.settings["deployments"], "enabled": True, "export_path": "deployments.json"}})

    def load_export(repository, target, settings, name):
        assert name == "organization", "ambiguous or denied exports must not be read"
        return None, None, ["organization_disabled"]

    monkeypatch.setattr(context_module, "load_export", load_export)
    run = tmp_path / "run"
    context = JobContext(
        run_id="fixture", attempt_id="attempt_0001", trigger="test", repository_root=tmp_path,
        run_root=run, attempt_root=run / "attempt", metadata_root=run / "metadata",
        orchestration={}, config=config, events=EventLog(run / "events.jsonl"),
        target_root=tmp_path / "target", source_fingerprint="snapshot")
    unit = UnitContext(context, "load.external_sources", "load", "external_sources", run / "external", {
        "load.accepted_history": {
            "source": {"source_id": "api", "source_count": 2}, "review_records": {"path": "must-not-read.json"}}})
    handlers = {item.unit_id: item.handler for item in context_module.build_job().units}
    output = handlers[unit.unit_id](unit)
    assert review_gap in output["gaps"] and "deployment_export_source_ambiguous" in output["gaps"]
    external = read(run, output["artifact"])
    assert external["reviews"] is None and external["deployments"] is None


def test_source_execution_failure_still_publishes_successful_history_and_context(tmp_path: Path):
    from appsec_review.container_runtime import ContainerExecutor, load_catalog
    from appsec_review.jobs.job_source_history_analysis import job as history_module
    from appsec_review.jobs.source_lanes import source_of
    config = configured(tmp_path)
    target = tmp_path / "target"
    repository(target / "bad")
    repository(target / "good")
    docker = LocalDocker()

    def factory(unit):
        if unit.unit_id == "acquire.git_history" and source_of(unit)["source_id"] == "bad":
            raise OSError("fixture history producer unavailable")
        return ContainerExecutor(load_catalog(unit.job.repository_root), unit.job.run_root, runner=docker)

    change_job = build_change_context(executor_factory=factory)
    outcome = GraphRunner(config, (build_intake(), build_catalog(),
                                   history_module.build_job(executor_factory=factory), change_job)).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    accepted = load_accepted_history(run_root)
    assert {item["source_id"] for item in accepted["ranking"]["files"]} == {"good"}
    assert any("bad:source_failed:acquire.git_history:OSError" in gap for gap in accepted["gaps"])
    context = RetrievalCore(config.runtime.runs_dir, outcome["run_id"]).query_change_context(scope="file")
    paths = {item["location"]["path"] for item in context["results"]}
    assert "good/src/shared.py" in paths and not any(path.startswith("bad/") for path in paths)
