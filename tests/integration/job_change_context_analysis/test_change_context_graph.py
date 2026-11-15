from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_change_context_analysis import build_job as build_change_context
from appsec_review.jobs.job_change_context_analysis.sources import identity_hash
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.integration.job_source_history_analysis.test_analysis import (
    GIT, LocalDocker, commit, configured, git, history_job, write,
)


DAY = 86_400
HOUR = 3_600
T0 = 1_700_000_000  # 2023-11-14T22:13:20Z, 17:13 in America/New_York (EST)
pytestmark = pytest.mark.skipif(GIT is None, reason="host git is required to emulate the tool-git image")


def build_target(target: Path) -> dict[str, str]:
    target.mkdir(parents=True)
    git(target, "init", "-q", "-b", "main")
    write(target, "pyproject.toml", "[project]\nname = 'fixture'\n")
    for name in ("lib", "svc_a", "svc_b"):
        write(target, f"{name}/pyproject.toml", f"[project]\nname = '{name}'\n")
    write(target, "lib/core.py", "VALUE = 0\n")
    write(target, "svc_a/api.py", "def route():\n    return 0\n")
    write(target, "svc_b/db.py", "def query():\n    return 0\n")
    ids = {"init": commit(target, "initial import", T0 - 400 * DAY)}
    write(target, "app/auth.py", "def check(user):\n    return True\n\n\ndef audit(user):\n    return None\n")
    write(target, "app/util.py", "def helper():\n    return 1\n")
    ids["c1"] = commit(target, "add app", T0)
    write(target, "app/auth.py", "def check(user):\n    return user.ok\n\n\ndef audit(user):\n    return None\n")
    ids["c2"] = commit(target, "fix: auth bypass", T0 + DAY)
    write(target, "app/auth.py", "def check(user):\n    return bool(user.ok)\n\n\ndef audit(user):\n    return None\n")
    ids["c3"] = commit(target, "refactor", T0 + 2 * DAY, author="two@example.test")
    write(target, "app/auth.py", "def check(user):\n    return bool(user and user.ok)\n\n\ndef audit(user):\n    return None\n")
    ids["c4"] = commit(target, "fix: null user", T0 + 10 * DAY + 3 * HOUR)
    write(target, "app/auth.py", "def check(user):\n    return bool(user and user.ok and user.active)\n\n\n"
                                 "def audit(user):\n    return None\n")
    ids["c5"] = commit(target, "fix crash on inactive user", T0 + 20 * DAY)
    git(target, "revert", "--no-edit", ids["c5"], when=T0 + 30 * DAY)
    ids["c6"] = git(target, "rev-parse", "HEAD")
    big = "".join(f"LINE_{index} = {index}\n" for index in range(130))
    write(target, "app/auth.py", "def check(user):\n    return bool(user and user.ok)\n\n\ndef audit(user):\n"
                                 "    return None\n" + big)
    write(target, "lib/core.py", "VALUE = 0\n" + big)
    write(target, "svc_a/api.py", "def route():\n    return 0\n" + big)
    write(target, "svc_b/db.py", "def query():\n    return 0\n" + big)
    ids["c7"] = commit(target, "rename constants everywhere", T0 + 40 * DAY)
    write(target, "app/util.py", "def helper():\n    return 1\n" + "".join(f"X{index} = {index}\n" for index in range(60)))
    ids["c8"] = commit(target, "extend helper", T0 + 45 * DAY)
    write(target, "app/auth.py", (target / "app/auth.py").read_text(encoding="utf-8").replace(
        "def audit(user):\n    return None\n", "def audit(user):\n    return user.id\n"))
    write(target, "tests/test_auth.py", "def test_audit():\n    assert True\n")
    ids["c9"] = commit(target, "audit returns id", T0 + 46 * DAY)
    return ids


def fake_tree_sitter(run_root: Path, target: Path, snapshot: str, paths: list[str]) -> None:
    """Publish an accepted Tree-sitter handoff whose nodes mirror Python ``def`` blocks."""
    lines: list[str] = []
    for path in paths:
        data = (target / path).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        text = data.decode()
        rows = text.splitlines(keepends=True)
        offsets = [0]
        for row in rows:
            offsets.append(offsets[-1] + len(row.encode()))

        def node(ordinal, kind, start_line, end_line, start_byte, end_byte, field=None):
            identity = "asr:ast_node:" + hashlib.sha256(f"{path}{ordinal}".encode()).hexdigest()
            return json.dumps({"identity": identity, "path": path, "file_sha256": sha, "grammar_native_type": kind,
                               "field": field, "has_error": False, "error": False, "missing": False, "language": "Python",
                               "location": {"start_byte": start_byte, "end_byte": end_byte, "start_line": start_line,
                                            "end_line": end_line, "start_column": 1, "end_column": 1,
                                            "producer_location": {"ordinal_path": ordinal}}}, sort_keys=True)

        lines.append(node([], "module", 1, len(rows), 0, len(data)))
        starts = [index for index, row in enumerate(rows) if row.startswith("def ")]
        for number, start in enumerate(starts):
            end = next((index for index in range(start + 1, len(rows)) if rows[index] and not rows[index][0].isspace()
                        and rows[index].strip()), len(rows)) - 1
            while end > start and not rows[end].strip():
                end -= 1
            lines.append(node([number], "function_definition", start + 1, end + 1, offsets[start], offsets[end + 1]))
            name = re.match(r"def (\w+)", rows[start]).group(1)
            lines.append(node([number, 0], "identifier", start + 1, start + 1, offsets[start] + 4,
                              offsets[start] + 4 + len(name), field="name"))
    root = run_root / "data" / "jobs" / "job_tree_sitter_ast" / "attempts" / "fake"
    shard = root / "nodes.jsonl"
    shard.parent.mkdir(parents=True, exist_ok=True)
    shard.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
    accepted = root / "accepted-tree-sitter-ast.json"
    atomic_json(accepted, {"schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": snapshot, "dispositions": [
        {"scope_id": "fake", "artifact": {"path": shard.relative_to(run_root).as_posix(), "sha256": file_sha256(shard)}}]})
    handoff = root / "handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(run_root, handoff, {"source_fingerprint": snapshot, "status": "ACCEPTED", "outputs": {
        "acceptance.publish_handoff": {"artifact": {"path": accepted.relative_to(run_root).as_posix(),
                                                    "sha256": file_sha256(accepted)}}}})
    atomic_json(root.parent.parent / "latest.json", {"handoff_path": handoff.relative_to(run_root).as_posix(),
                                                     "handoff_sha256": file_sha256(handoff)})


def change_context_job(docker: LocalDocker):
    from appsec_review.container_runtime import ContainerExecutor, load_catalog
    return build_change_context(executor_factory=lambda unit: ContainerExecutor(
        load_catalog(unit.job.repository_root), unit.job.run_root, runner=docker))


def run_review(config, target: Path, docker: LocalDocker, *, tree_sitter: bool = False):
    upstream = (build_intake(), build_catalog(), history_job(docker))
    fingerprint = source_fingerprint(target)
    first = GraphRunner(config, upstream).run(target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / first["run_id"]
    if tree_sitter:
        fake_tree_sitter(run_root, target, fingerprint, sorted(
            path.relative_to(target).as_posix() for path in target.rglob("*.py") if ".git" not in path.parts))
    outcome = GraphRunner(config, (*upstream, change_context_job(docker))).run(
        target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    return outcome, run_root


def produced(outcome) -> dict:
    return outcome["jobs"]["job_change_context_analysis"]["result"]["outputs"]


def signals(run_root: Path, outcome) -> dict:
    return json.loads((run_root / produced(outcome)["analyze.rank"]["artifact"]["path"]).read_text(encoding="utf-8"))


def coverage(core: RetrievalCore) -> dict[str, dict]:
    rows = [row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]]
    return {row["area"]: row for row in rows if row["area"] in {
        "git-change-context", "review-records", "deployment-events", "off-hours-schedule", "test-association",
        "organization-membership", "function-attribution", "fix-on-fix"}}


def test_git_only_run_publishes_git_signals_and_names_every_missing_source(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = tmp_path / "target"
    ids = build_target(target)
    outcome, run_root = run_review(config, target, LocalDocker())
    assert {item["job_id"]: item["action"] for item in outcome["decisions"]}["job_change_context_analysis"] == "RUN"
    result = signals(run_root, outcome)
    auth = result["files"]["app/auth.py"]
    assert auth["metrics"]["repeated_repair_peak"] == 4
    assert auth["details"]["repeated_repairs"]["flagged"] is True
    assert auth["details"]["repeated_repairs"]["changes"] == [ids["c2"], ids["c4"], ids["c5"], ids["c6"]]
    assert set(auth["details"]["repeated_repairs"]["classification_basis"]) == {"heuristic"}
    assert auth["metrics"]["fix_on_fix_event_count"] >= 1, "the revert fixes lines a prior fix introduced"
    events = json.loads((run_root / produced(outcome)["attribute.fix_on_fix"]["artifact"]["path"]).read_text())["events"]
    assert {"fix_change": ids["c6"], "prior_fix_change": ids["c5"], "path": "app/auth.py"}.items() <= next(
        event for event in events if event["fix_change"] == ids["c6"]).items()
    assert auth["metrics"]["sprawling_change_count"] == 1 and auth["details"]["sprawl"]["sprawling_changes"] == [ids["c7"]]
    changes = json.loads((run_root / produced(outcome)["analyze.change_signals"]["artifact"]["path"]).read_text())["changes"]
    assert changes[ids["c7"]]["sprawl"]["unrelated_group_count"] == 4
    assert changes[ids["c8"]]["tests"]["untested_production"] is True
    assert changes[ids["c9"]]["tests"]["association_rule_counts"] == {"subject": 1}
    assert changes[ids["c9"]]["tests"]["untested_production"] is False
    assert auth["metrics"]["lifetime_principal_author_share"] == 0.875
    assert auth["details"]["ownership"]["bus_factor"] == 1
    for signal in ("fast_review_change_count", "stale_approval_change_count", "unapproved_mainline_change_count",
                   "off_hours_change_count", "pre_deployment_change_count", "departed_dominant_owner"):
        assert auth["metrics"][signal] is None and auth["availability"][signal] == "unavailable", signal
    assert result["functions"] == {}
    assert produced(outcome)["publish.publish_handoff"]["terminal_status"] == "PARTIAL"
    gaps = set(produced(outcome)["publish.publish_handoff"]["gaps"])
    assert {"review_records_unavailable:github_repository_unavailable", "deployment_disabled", "organization_disabled",
            "time_zone_not_configured", "function_spans_unavailable:tree_sitter_not_accepted"} <= gaps

    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = coverage(core)
    assert rows["git-change-context"]["status"] == "complete"
    assert rows["review-records"] == {"area": "review-records", "status": "unavailable",
                                      "gap": "review_records_unavailable:github_repository_unavailable"}
    assert rows["deployment-events"]["status"] == "unavailable" and rows["organization-membership"]["status"] == "unavailable"
    assert rows["off-hours-schedule"]["gap"] == "time_zone_not_configured"
    assert rows["function-attribution"]["status"] == "unavailable"
    top = core.query_change_context(scope="file", limit=5)
    assert [item["payload"]["rank"] for item in top["results"]] == sorted(item["payload"]["rank"] for item in top["results"])
    assert top["results"][0]["location"]["path"] == "app/auth.py"
    assert any("review-records: unavailable" in gap for gap in top["coverage_gaps"])
    sprawling = core.query_change_context(signal="sprawling_change_count", scope="component", limit=10)
    assert len(sprawling["results"]) == 4
    traced = core.trace(identity=top["results"][0]["identity"], relations=("DERIVED_FROM",), depth=1, limit=50)
    c7 = LogicalIdentity.derive(EntityKind.CHANGE, source_fingerprint(target), {"vcs": "git", "change_id": ids["c7"]})
    assert c7.value in {item["target_id"] for item in traced["results"]}
    assert core.find(identity=c7.value, indexes=("history",))["results"][0]["payload"]["sprawl"]["sprawling"] is True
    history_rows = [row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]]
    assert {"area": "git-history", "status": "complete", "gap": None} in history_rows, "history shard stays composed"
    assert "one@example.test" not in json.dumps(top) and identity_hash("one@example.test") not in json.dumps(top)

    fresh, fresh_root = run_review(config, target, LocalDocker())
    assert (fresh_root / produced(fresh)["analyze.rank"]["artifact"]["path"]).read_bytes() == \
        (run_root / produced(outcome)["analyze.rank"]["artifact"]["path"]).read_bytes()


def test_external_sources_drive_review_deployment_schedule_ownership_and_function_signals(tmp_path: Path) -> None:
    target = tmp_path / "target"
    ids = build_target(target)
    data = tmp_path / "data" / "change-context"
    data.mkdir(parents=True)
    head = "9" * 40
    reviews = {"schema": "appsec-review/review-records/1", "records": {
        ids["c2"]: {"pull_request": 1, "created_at": "2023-11-15T22:00:00Z", "merged_at": "2023-11-15T22:13:20Z",
                    "head_sha": head, "head_committed_at": "2023-11-15T21:59:00Z",
                    "approvals": [{"submitted_at": "2023-11-15T22:02:00Z", "commit_id": head}]},
        ids["c3"]: {"pull_request": 2, "created_at": "2023-11-15T10:00:00Z", "merged_at": "2023-11-16T22:13:20Z",
                    "head_sha": head, "approvals": [{"submitted_at": "2023-11-16T09:00:00Z", "commit_id": "8" * 40}]},
        ids["c4"]: {"pull_request": None, "direct_push": True},
    }}
    deployments = {"schema": "appsec-review/deployment-events/1",
                   "coverage": {"start": "2023-11-01T00:00:00Z", "end": "2024-02-01T00:00:00Z"},
                   "events": [{"deployment_id": "rel-1", "environment": "production", "status": "success",
                               "deployed_at": "2023-11-25T03:00:00Z", "commit": ids["c4"]}]}
    organization = {"schema": "appsec-review/organization-membership/1", "as_of": "2024-02-01T00:00:00Z",
                    "members": [{"identity_sha256": identity_hash("one@example.test"), "status": "departed"}]}
    digests = {}
    for name, value in (("reviews", reviews), ("deployments", deployments), ("organization", organization)):
        (data / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
        digests[name] = file_sha256(data / f"{name}.json")
    config = configured(tmp_path)
    text = (tmp_path / "appsec-review.toml").read_text(encoding="utf-8")
    replacements = (
        ('source = "github_enrichment"\nexport_path = ""\nexport_sha256 = ""',
         f'source = "export"\nexport_path = "data/change-context/reviews.json"\nexport_sha256 = "{digests["reviews"]}"'),
        ('time_zone = ""', 'time_zone = "America/New_York"'),
        ('enabled = false\nexport_path = ""\nexport_sha256 = ""\nenvironments',
         f'enabled = true\nexport_path = "data/change-context/deployments.json"\n'
         f'export_sha256 = "{digests["deployments"]}"\nenvironments'),
        ('[jobs.job_change_context_analysis.settings.organization]\n'
         '# Departure comes only from an appsec-review/organization-membership/1 export, never Git inactivity.\n'
         'enabled = false\nexport_path = ""\nexport_sha256 = ""',
         '[jobs.job_change_context_analysis.settings.organization]\nenabled = true\n'
         f'export_path = "data/change-context/organization.json"\nexport_sha256 = "{digests["organization"]}"'),
    )
    for old, new in replacements:
        assert old in text, old
        text = text.replace(old, new)
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    config = load_config(tmp_path / "appsec-review.toml")
    outcome, run_root = run_review(config, target, LocalDocker(), tree_sitter=True)
    changes = json.loads((run_root / produced(outcome)["analyze.change_signals"]["artifact"]["path"]).read_text())["changes"]
    assert changes[ids["c2"]]["review"]["fast_approval"] is True
    assert changes[ids["c2"]]["review"]["merged_head_approved"] is True
    assert changes[ids["c2"]]["facts"]["landed_at_basis"] == "review_host_merged_at"
    assert changes[ids["c3"]]["review"]["stale_approval"] is True
    assert changes[ids["c4"]]["review"]["unapproved_mainline"] is True and changes[ids["c4"]]["review"]["direct_push"]
    assert changes[ids["c5"]]["review"]["status"] == "missing"
    assert changes[ids["c4"]]["schedule"]["off_hours"] is True, "20:13 local time is outside business hours"
    assert changes[ids["c1"]]["schedule"]["off_hours"] is False
    assert changes[ids["c4"]]["deployment"]["pre_deployment"] is True
    assert changes[ids["c2"]]["deployment"]["status"] == "shipped" and changes[ids["c2"]]["deployment"]["pre_deployment"] is False
    assert changes[ids["c9"]]["deployment"]["status"] == "not_deployed_in_coverage"
    result = signals(run_root, outcome)
    auth = result["files"]["app/auth.py"]
    assert auth["metrics"]["fast_review_change_count"] == 1 and auth["metrics"]["stale_approval_change_count"] == 1
    assert auth["metrics"]["unapproved_mainline_change_count"] == 1
    assert auth["availability"]["fast_review_change_count"] == "partial", "uncovered changes are partial, not clean"
    assert changes[ids["c7"]]["schedule"]["weekday"] == "sunday" and changes[ids["c9"]]["schedule"]["weekday"] == "saturday"
    assert auth["metrics"]["off_hours_change_count"] == 3 and auth["metrics"]["pre_deployment_change_count"] == 1
    assert auth["metrics"]["departed_dominant_owner"] is True
    check = next(value for value in result["functions"].values() if value["function"]["name"] == "check")
    audit = next(value for value in result["functions"].values() if value["function"]["name"] == "audit")
    assert check["attribution"] == "surviving-line" and check["location"]["start_line"] == 1
    assert ids["c6"] in check["supporting_changes"] and ids["c9"] not in check["supporting_changes"]
    assert audit["supporting_changes"] == [ids["c9"], ids["c1"]], "only changes with surviving lines in the span"
    assert check["availability"]["fix_on_fix_event_count"] == "unavailable"
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = coverage(core)
    assert rows["review-records"]["status"] == "complete" and rows["deployment-events"]["status"] == "complete"
    assert rows["organization-membership"]["status"] == "complete"
    assert rows["function-attribution"]["status"] == "complete"
    functions = core.query_change_context(scope="function", path="app/auth.py", limit=10)
    assert {item["name"] for item in functions["results"]} == {"check", "audit"}
    assert all(item["location"]["mapping_method"] == "tree-sitter-span+git-blame" for item in functions["results"])
    stale = core.query_change_context(signal="stale_approval_change_count", scope="file", limit=10)
    assert [item["location"]["path"] for item in stale["results"]] == ["app/auth.py"]
    found = core.find(kind="deployment_event", indexes=("history",))
    assert [item["native_id"] for item in found["results"]] == ["rel-1"]
    accepted = json.loads((run_root / produced(outcome)["publish.publish_handoff"]["artifact"]["path"]).read_text())
    assert accepted["authority"].startswith("change-context priorities order review work")
    assert set(accepted["raw_exports"]) == {"review", "deployment", "organization"}

    (data / "deployments.json").write_text(json.dumps({**deployments, "events": []}), encoding="utf-8")
    tampered, _ = run_review(config, target, LocalDocker())
    assert "deployment_export_hash_mismatch" in produced(tampered)["publish.publish_handoff"]["gaps"]
    tampered_auth = signals(config.runtime.runs_dir / tampered["run_id"], tampered)["files"]["app/auth.py"]
    assert tampered_auth["metrics"]["pre_deployment_change_count"] is None


def test_missing_history_publishes_unavailable_coverage(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    write(target, "main.py", "print('ok')\n")
    outcome, _ = run_review(config, target, LocalDocker())
    assert produced(outcome)["publish.publish_handoff"]["terminal_status"] == "SKIPPED_NA"
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = coverage(core)
    assert rows["git-change-context"] == {"area": "git-change-context", "status": "unavailable", "gap": "no_git_metadata"}
    assert {row["status"] for row in rows.values()} == {"unavailable"}
    assert core.query_change_context()["results"] == []
