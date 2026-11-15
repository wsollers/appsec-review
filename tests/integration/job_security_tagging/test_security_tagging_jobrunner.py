from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_security_tagging import build_job
from appsec_review.jobs.job_security_tagging.job import SCOPE_SCHEMA
from appsec_review.jobs.job_security_tagging.producers import component_topology_sha256, ownership_rules
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import JobRunner
from tests.test_security_tagging import RUN_ID, SNAPSHOT, _run_fixture


pytestmark = [
    pytest.mark.integration,
    pytest.mark.time_budget(30, reason="JobRunner security-tagging publication and rerun determinism"),
]


def _assignments(run_root: Path, outcome) -> list[dict]:
    artifact = outcome["result"]["outputs"]["integrity.validate_assignments"]["artifact"]
    return json.loads((run_root / artifact["path"]).read_text(encoding="utf-8"))["assignments"]


def test_job_tags_accepted_indexes_and_publishes_queryable_shards(tmp_path: Path) -> None:
    config, run_root, target = _run_fixture(tmp_path)
    outcome = JobRunner(config).run(build_job(), run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)
    assert outcome["status"]["status"] == "COMPLETED_WITH_GAPS"
    records = _assignments(run_root, outcome)
    by_tag: dict[str, list[dict]] = {}
    for record in records:
        by_tag.setdefault(record["tag"], []).append(record)

    assert by_tag["lang:python"][0]["basis"] == "declared"
    assert {"infra:container:image-build", "platform:docker", "infra:ci:workflow", "platform:github-actions",
            "infra:supply:dependency-manifest"} <= set(by_tag)
    sql = by_tag["cwe:89"][0]
    assert sql["basis"] == "reported" and sql["evidence"][0]["span"] == {"start_line": 1, "end_line": 1}
    capec = by_tag["capec:66"][0]
    assert capec["basis"] == "derived" and capec["derived_from"] == [sql["assignment_id"]]
    assert by_tag["cwe:798"][0]["producer"]["name"] == "tool-gitleaks"
    assert by_tag["vuln:severity:high"][0]["basis"] == "reported"
    jwt = by_tag["func:authn:jwt"][0]
    assert jwt["basis"] == "declared" and jwt["producer"]["mapping_rule"] == "pkg-jwt"
    applicable = [record for record in by_tag["asvs5:v9"] if record["crosswalk_rule"] == "jwt-signature-applicability"]
    assert applicable and applicable[0]["subject"]["kind"] == "component"
    assert {record["basis"] for record in by_tag["cwe:347"]} == {"derived"}
    boundary = by_tag["surface:boundary:ci-trust"][0]
    assert boundary["basis"] == "derived" and boundary["subject"]["native_address"] == \
        "ci_job:.github/workflows/ci.yml#build"
    unmapped = by_tag["gap:crosswalk-unmapped"]
    assert [record["producer"]["name"] for record in unmapped] == ["tool-semgrep"]
    assert "gap:no-sast:tool-semgrep" in by_tag and "gap:catalog-fixture" in by_tag
    assert not any(tag.startswith(("nist53r5:", "ssdf:", "cicd-top10:")) for tag in by_tag)
    assert "clean" not in json.dumps([record["tag"] for record in records])

    scope = json.loads((run_root / outcome["result"]["outputs"]["scope.resolve_inputs"]["artifact"]["path"])
                       .read_text(encoding="utf-8"))
    assert scope["schema"] == SCOPE_SCHEMA and scope["ownership_rules"] == ownership_rules()
    assert scope["component_topology_sha256"] == component_topology_sha256(scope["components"], ownership_rules())
    assert {record["subject"]["component_ownership"] for record in records} >= {"owned", "not_applicable"}

    pointer = json.loads((run_root / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
    assert pointer["manifest_path"].endswith("tags-attempt_0001.json")
    core = RetrievalCore(config.runtime.runs_dir, RUN_ID)
    hits = core.search(query="cwe", indexes=("tags",), kinds=("tag_assignment",), limit=100)
    assert any(hit["name"] == "cwe:89" for hit in hits["results"])
    assert {item["shard_id"] for item in core.manifest["indexes"] if item["name"] == "tags"} == {
        "code-facts", "controls", "facets", "gap", "threat", "weakness"}
    auth = by_tag["role:auth"]
    assert {record["basis"] for record in auth} == {"declared", "derived"}
    assert any(record["evidence"][0]["rule"] == "lex-py-auth-import" for record in auth)
    library = by_tag["target:library"][0]
    assert library["basis"] == "derived" and library["evidence"][0]["rests_on_absence"] is True

    handoff = outcome["result"]["outputs"]["publication.publish_handoff"]
    assert handoff["security_findings"] == [] and handoff["gaps"]
    cloud = json.loads((run_root / outcome["result"]["outputs"]["publication.publish_tag_cloud"]["artifact"]["path"])
                       .read_text(encoding="utf-8"))
    nodes = {node["node"]: node for node in cloud["nodes"]}
    assert nodes["func:authn"]["fill"] == "outline" and nodes["cwe:89"]["fill"] == "strong-tint"
    assert nodes["gap:no-sast"]["fill"] == "hatched"
    assert nodes["lang:python"]["component_count"] == 1
    assert "capec:66" in cloud["views"]["red"]


def test_rerun_is_deterministic_and_replaces_earlier_tag_shards(tmp_path: Path) -> None:
    config, run_root, target = _run_fixture(tmp_path)
    runner = JobRunner(config)
    first = runner.run(build_job(), run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)
    second = runner.run(build_job(), run_id=RUN_ID, target_root=target, source_fingerprint=SNAPSHOT)
    assert _assignments(run_root, first) == _assignments(run_root, second)
    core = RetrievalCore(config.runtime.runs_dir, RUN_ID)
    tags = [item for item in core.manifest["indexes"] if item["name"] == "tags"]
    assert len(tags) == len({item["shard_id"] for item in tags}) == 6
