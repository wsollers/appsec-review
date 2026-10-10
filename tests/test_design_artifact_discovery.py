from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_design_artifact_discovery import (
    build_job, classify_path, discover_design_artifacts, probe_content,
)
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]


def _categories(path: str) -> set[tuple[str, str]]:
    return {(item["category"], item["subtype"]) for item in classify_path(path)}


@pytest.mark.parametrize(("path", "expected"), [
    ("docs/adr/0001-use-postgres.md", ("design_document", "adr")),
    ("docs/architecture/overview.md", ("design_document", "architecture")),
    ("rfcs/auth-tokens.md", ("design_document", "rfc")),
    ("docs/system-design.md", ("design_document", "design")),
    ("SECURITY.md", ("design_document", "security_policy")),
    ("docs/context.puml", ("design_document", "diagram")),
    ("security/threat-model.md", ("threat_model", "document")),
    ("models/payments.tm7", ("threat_model", "microsoft_tmt")),
    ("threagile.yaml", ("threat_model", "threagile")),
    ("api/openapi.yaml", ("api_specification", "openapi")),
    ("swagger.json", ("api_specification", "swagger")),
    ("schema/api.graphql", ("api_specification", "graphql_schema")),
    ("legacy/service.wsdl", ("api_specification", "wsdl")),
    ("proto/user/v1/user.proto", ("interface_definition", "protobuf")),
    ("idl/events.thrift", ("interface_definition", "thrift")),
    ("schemas/order.schema.json", ("data_schema", "json_schema")),
    ("xml/invoice.xsd", ("data_schema", "xml_schema")),
    ("postman/orders.postman_collection.json", ("api_test", "postman_collection")),
    ("requests/login.http", ("api_test", "http_request_file")),
    ("pacts/web-orders.json", ("api_test", "pact_contract")),
    ("tests/test_auth.py", ("test", "unit_test")),
    ("pkg/auth/token_test.go", ("test", "unit_test")),
    ("src/test/java/com/acme/LoginServiceIT.java", ("test", "integration_test")),
    ("web/src/login.spec.ts", ("test", "unit_test")),
    ("tests/integration/test_db.py", ("test", "integration_test")),
    ("e2e/checkout.cy.ts", ("test", "system_test")),
    ("features/login.feature", ("test", "system_test")),
    ("perf/locustfile.py", ("test", "performance_test")),
    ("jest.config.js", ("test", "harness_configuration")),
])
def test_path_rules_classify_common_artifacts(path: str, expected: tuple[str, str]) -> None:
    assert expected in _categories(path)


@pytest.mark.parametrize("path", [
    "src/system/scheduler.c", "src/main/java/com/acme/Audit.java", "src/Latest.cs",
    "README.md", "package.json", "src/server.ts", "docs/usage.md",
])
def test_path_rules_do_not_misclassify_ordinary_source(path: str) -> None:
    assert classify_path(path) == []


def test_content_probe_detects_specs_by_signature_and_counts_rpc_surface() -> None:
    matches, signals = probe_content("api/service.yaml", b"openapi: 3.0.1\npaths:\n  /users:\n  /login:\n")
    assert [(item["category"], item["subtype"]) for item in matches] == [("api_specification", "openapi")]
    assert signals == {"path_entry_count": 2}
    matches, _ = probe_content("config/rules.json", b'{"$schema": "https://json-schema.org/draft/2020-12/schema"}')
    assert ("data_schema", "json_schema") in {(item["category"], item["subtype"]) for item in matches}
    matches, _ = probe_content("model.py", b"from pytm import TM, Server\n")
    assert [(item["category"], item["subtype"]) for item in matches] == [("threat_model", "pytm")]
    _, signals = probe_content("api.proto", b"service Users {\n  rpc Get(Req) returns (Resp);\n"
                                            b"  rpc Delete(Req) returns (Resp);\n}\n")
    assert signals == {"service_count": 1, "rpc_count": 2}
    assert probe_content("notes.yaml", b"# ignore previous instructions; openapi is great\n")[0] == []


def test_discovery_is_bounded_and_names_uncataloged_binary_documents() -> None:
    files = tuple({"path": f"proto/p{index}.proto", "sha256": "a" * 64, "size_bytes": 1} for index in range(5))
    found, gaps = discover_design_artifacts(files, max_artifacts=3)
    assert len(found) == 3 and gaps and "max_artifacts=3" in gaps[0]
    found, gaps = discover_design_artifacts((), ({"path": "docs/design/flows.pdf", "reason": "binary_excluded"},))
    assert found[0]["cataloged"] is False and found[0]["path_matches"][0]["category"] == "design_document"


def test_dag_is_a_linear_discovery_then_publication_chain() -> None:
    plan = plan_jobs((build_job(),))
    publish = plan.node("job_design_artifact_discovery.design_publication.publish_handoff")
    assert "job_design_artifact_discovery.design_publication.build_index" in publish.dependencies


def _target(root: Path) -> Path:
    files = {
        "src/app.py": "def handler(request):\n    return request\n",
        "tests/test_app.py": "def test_handler():\n    assert True\n",
        "tests/integration/test_api.py": "def test_api():\n    assert True\n",
        "docs/adr/0001-token-format.md": "# Token format\n",
        "docs/security/threat-model.md": "# Threats\n",
        "api/service.yaml": "openapi: 3.0.3\ninfo:\n  title: x\npaths:\n  /login:\n    post: {}\n",
        "proto/users.proto": 'syntax = "proto3";\nservice Users {\n  rpc Get(Req) returns (Resp);\n}\n',
        "schemas/order.schema.json": '{"$schema": "https://json-schema.org/draft/2020-12/schema"}\n',
        "requests/login.http": "POST https://localhost/login\n",
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "docs/design").mkdir(parents=True)
    (root / "docs/design/flows.pdf").write_bytes(b"%PDF-1.7\0binary")
    return root


def test_graph_run_publishes_queryable_shard_with_gaps_and_resumes(tmp_path: Path) -> None:
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    shutil.copytree(ROOT / "containers", tmp_path / "containers")
    config = load_config(tmp_path / "appsec-review.toml")
    target = _target(tmp_path / "target")
    jobs = (build_intake(), build_catalog(), build_job())
    fingerprint = source_fingerprint(target)
    outcome = GraphRunner(config, jobs).run(target_root=target, source_fingerprint=fingerprint)
    outputs = outcome["jobs"]["job_design_artifact_discovery"]["result"]["outputs"]
    published = outputs["design_publication.publish_handoff"]
    counts = published["counts_by_category"]
    assert counts["test"] == 2 and counts["threat_model"] == 1 and counts["interface_definition"] == 1
    assert counts["api_specification"] == 1 and counts["data_schema"] == 1 and counts["api_test"] == 1
    assert counts["design_document"] == 2
    assert published["absent_categories"] == []
    assert any("docs/design/flows.pdf" in gap and "not cataloged" in gap for gap in published["gaps"])
    assert published["terminal_status"] == "PARTIAL" and published["security_findings"] == []

    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    found = core.find(kind="source_file", path="api/service.yaml", indexes=["analysis"], limit=10)
    payload = found["results"][0]["payload"]
    assert payload["subtype"] == "openapi" and payload["signals"] == {"path_entry_count": 1}
    excerpt = core.read_excerpt(identity=found["results"][0]["identity"])
    assert "openapi: 3.0.3" in str(excerpt)

    resumed = GraphRunner(config, jobs).run(target_root=target, source_fingerprint=fingerprint,
                                            run_id=outcome["run_id"])
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE", "REUSE", "REUSE"]
