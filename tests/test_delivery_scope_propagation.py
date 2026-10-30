"""Fake-only coverage for delivery routing; no containers, models, or real scanners."""
import io
import json
from pathlib import Path
import tarfile
from types import SimpleNamespace

import pytest

from appsec_review.config.assurance import SCOPE_VERSION, ScopeRole
from appsec_review.jobs.delivery_scope import (
    POLICY_IDENTITY, analysis_scope, apply_scope, delivery_gap, scope_fields,
)
from appsec_review.jobs.job_language_build import node
from appsec_review.jobs.job_tree_sitter_ast.model import plan_scopes
from appsec_review.storage import file_sha256


ROLES = [
    ("target_source", "target", True, False),
    ("deliverable", "target", True, False),
    ("shipped_dependency", "target", True, False),
    ("runtime_dependency", "supply_chain", False, False),
    ("build_chain", "supply_chain", False, False),
    ("build_dependency", "supply_chain", False, False),
    ("supplied_platform", "excluded", False, False),
    ("intermediate_evidence", "evidence", False, False),
    ("unknown", "target", True, True),
]


@pytest.mark.parametrize("role,lane,native,unknown", ROLES)
def test_scope_roles_are_independent_of_origin_and_directory(role, lane, native, unknown):
    for origin in ("target-intake", "build-output", "copied-sdk"):
        row = {"scope_role": role, "artifact_origin": origin,
               "workspace_path": "dist/node_modules/sdk/generated/runtime.dll"}
        fields = scope_fields(row)
        assert fields["scope_version"] == SCOPE_VERSION
        assert fields["scope_role"] == role and fields["analysis_lane"] == lane
        assert fields["artifact_origin"] == origin
        assert analysis_scope(row, "native")[0] is native
        assert analysis_scope(row, "inventory")[0] is (role != "supplied_platform")
        assert analysis_scope(row, "syft")[0] is (lane in {"target", "supply_chain"})
        assert bool(delivery_gap(row)) is unknown


def test_runtime_dependency_is_supply_chain_review_without_established_delivery():
    row = {"scope_role": "runtime_dependency", "artifact_origin": "build-output",
           "workspace_path": "node_modules/express/package.json"}
    fields = scope_fields(row)
    assert ScopeRole.RUNTIME_DEPENDENCY.value == "runtime_dependency"
    assert fields["analysis_reason"] == "accepted-runtime-dependency-review"
    assert fields["analysis_lane"] == "supply_chain"
    assert fields["delivery_status"] == "not_established"
    for capability in ("inventory", "packages", "syft", "grype", "osv"):
        assert analysis_scope(row, capability) == (True, "accepted-runtime-dependency-review")
    for capability in ("native", "jvm", "wasm", "spotbugs", "blint"):
        assert analysis_scope(row, capability)[0] is False
    assert delivery_gap(row) is None
    assert apply_scope([dict(row)]) == []


@pytest.mark.parametrize("kind", ["native-addon", "shared-library", "executable", "native-extension"])
def test_blint_reviews_runtime_dependency_native_binaries_only(kind):
    runtime = {"scope_role": "runtime_dependency", "kind": kind,
               "workspace_path": "node_modules/sharp/build/Release/sharp.node"}
    assert analysis_scope(runtime, "blint") == (True, "accepted-runtime-dependency-review")
    for capability in ("native", "jvm", "wasm", "spotbugs"):
        assert analysis_scope(runtime, capability)[0] is False
    for role in ("build_dependency", "build_chain", "supplied_platform", "intermediate_evidence"):
        assert analysis_scope({**runtime, "scope_role": role}, "blint")[0] is False
    for other in ("package-metadata", "package", "native-symbols", "generated-code", None):
        assert analysis_scope({**runtime, "kind": other}, "blint")[0] is False


def test_scope_and_delivery_policy_versions_reject_prior_role_vocabulary():
    assert SCOPE_VERSION == "appsec-review/delivered-scope/2"
    assert POLICY_IDENTITY == "appsec-review/delivery-propagation/2"
    with pytest.raises(ValueError, match="unsupported delivery scope version"):
        scope_fields({"scope_version": "appsec-review/delivered-scope/1", "scope_role": "unknown"})
    with pytest.raises(ValueError, match="unsupported delivery scope version"):
        apply_scope([{"scope_version": "appsec-review/delivered-scope/1",
                      "scope_role": "runtime_dependency"}])


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_fresh_catalog_scope_gates_fake_scanner_before_payload_access(tmp_path, monkeypatch, mode):
    from appsec_review.jobs.job_artifact_security_analysis import job as security

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifacts = []
    for role, *_ in ROLES:
        if role == "supplied_platform":
            # This identity has no payload: even attempting access must fail.
            artifacts.append({"path": "supplied/no-payload.dll", "workspace_path": "platform.dll",
                              "scope_role": role, "sha256": "f" * 64, "artifact_id": role})
            continue
        path = workspace / (role + ".dll")
        path.write_bytes(b"fake-customer-runtime")
    fresh, gaps = node.catalog(tmp_path, workspace, {}, 100, "fixture-build")
    assert gaps and all("delivery status is unknown" in gap for gap in gaps)
    for row in fresh:
        role = Path(row["workspace_path"]).stem
        artifacts.append({**row, "scope_role": role, "artifact_id": role,
                          "delivery_evidence": {"kind": "accepted-fixture-fact", "sha256": row["sha256"]}})
    apply_scope(artifacts)
    accesses, scanned = [], []

    def safe_file(root, artifact):
        assert artifact["scope_role"] != "supplied_platform"
        accesses.append(artifact["artifact_id"])
        return root / artifact["path"]

    def fake_scan(unit, artifact, capability, runner):
        scanned.append((capability, artifact["scope_role"]))
        return {"artifact": artifact, "gaps": [], "terminal_status": "SUCCEEDED"}

    monkeypatch.setattr(security, "_safe_file", safe_file)
    monkeypatch.setattr(security, "classify", lambda *args, **kwargs: {"family": "native", "format": "pe"})
    monkeypatch.setattr(security, "_scan_one", fake_scan)
    loaded = {"artifacts": artifacts}
    unit = SimpleNamespace(
        job=SimpleNamespace(run_root=tmp_path, review_policy=SimpleNamespace(mode=mode)),
        output=lambda _: loaded,
    )
    units = {item.unit_id: item for item in security.build_job(scanner_runner=lambda *args: None).units}
    inventory = units["analyze.inventory"].handler(unit)
    native = units["analyze.native"].handler(unit)
    assert inventory["observation_count"] == 8
    assert native["observation_count"] == 4
    assert {role for capability, role in scanned if capability == "native"} == {
        "target_source", "deliverable", "shipped_dependency", "unknown",
    }
    assert "supplied_platform" not in accesses
    assert any("delivery_fact_unavailable" in gap for gap in native["gaps"])
    assert len(native["scope_dispositions"]) == 9
    assert all(row["analysis_reason"] for row in native["scope_dispositions"])


def _packed_node_fixture(tmp_path):
    workspace = tmp_path / "workspace"
    root = workspace / "web"
    root.mkdir(parents=True)
    (root / "package.json").write_text('{"name":"fixture"}')
    contents = {
        "dist/generated/app.js": b"function delivered() { return 1; }\n",
        "dist/node_modules/sdk/index.js": b"module.exports = 'copied sdk';",
        "dist/addon.node": b"fake-addon-linked-to-helper.dll",
        "dist/helper.dll": b"fake-companion-library",
        "node_modules/build-helper/index.js": b"build-only-or-unknown",
    }
    for relative, payload in contents.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    package = root / "fixture.tgz"
    with tarfile.open(package, "w:gz") as archive:
        for relative, payload in contents.items():
            if relative.startswith("node_modules/build-helper"):
                continue
            member = tarfile.TarInfo("package/" + relative)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    after = {path.relative_to(workspace).as_posix(): file_sha256(path)
             for path in workspace.rglob("*") if path.is_file()}
    stdout = json.dumps([{"filename": package.name, "integrity": "sha512-fixture"}]).encode()
    rows, gaps = node.invocation_rows(workspace, "web", ("npm", "pack", "--json"),
                                     success=True, before={}, after=after, diagnostic_streams=(stdout,))
    assert not gaps
    return workspace, rows[0]["package_integrity"]


def test_accepted_package_members_retain_copied_sdk_and_addon_companion(tmp_path):
    workspace, facts = _packed_node_fixture(tmp_path)
    artifacts, gaps = node.catalog(tmp_path, workspace, {}, 100, "fixture", package_facts=facts)
    rows = {row["workspace_path"]: row for row in artifacts}
    assert rows["web/fixture.tgz"]["scope_role"] == "deliverable"
    sdk = rows["web/dist/node_modules/sdk/index.js"]
    assert sdk["scope_role"] == "shipped_dependency"
    assert sdk["delivery_evidence"]["member"] == "package/dist/node_modules/sdk/index.js"
    for relative in ("dist/generated/app.js", "dist/addon.node", "dist/helper.dll"):
        assert rows["web/" + relative]["scope_role"] == "deliverable"
    unknown = rows["web/node_modules/build-helper/index.js"]
    assert unknown["scope_role"] == "unknown"
    assert sorted(gaps) == sorted([
        delivery_gap(unknown),
        "web/node_modules: npm installer record unavailable (missing); "
        "dependency files cataloged per-file in the target lane",
        "web/dist/node_modules: npm installer record unavailable (missing); "
        "dependency files cataloged per-file in the target lane",
    ])


@pytest.mark.parametrize("mutation", ["no_fact", "digest_changed", "member_changed", "script_not_pack"])
def test_delivery_requires_bound_package_fact_not_path_or_diagnostics(tmp_path, mutation):
    workspace, facts = _packed_node_fixture(tmp_path)
    if mutation == "no_fact":
        facts = []
    elif mutation == "digest_changed":
        facts = [{**facts[0], "sha256": "0" * 64}]
    elif mutation == "member_changed":
        (workspace / "web/dist/helper.dll").write_bytes(b"different")
    else:
        rows, _ = node.invocation_rows(
            workspace, "web", ("npm", "run", "pack", "--json"), success=True,
            before={}, after={facts[0]["workspace_path"]: facts[0]["sha256"]},
            diagnostic_streams=(json.dumps([{"filename": "fixture.tgz", "integrity": "spoof"}]).encode(),))
        facts = rows[0].get("package_integrity", [])
    artifacts, gaps = node.catalog(tmp_path, workspace, {}, 100, "fixture", package_facts=facts)
    companion = next(row for row in artifacts if row["workspace_path"] == "web/dist/helper.dll")
    assert companion["scope_role"] == "unknown"
    assert any("web/dist/helper.dll: delivery status is unknown" in gap for gap in gaps)


def test_node_discovery_bound_is_a_named_delivery_gap(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for ordinal in range(11):
        (workspace / f"{ordinal}.js").write_text("module.exports = 1;")
    artifacts, gaps = node.catalog(tmp_path, workspace, {}, 1, "fixture")
    assert not artifacts
    assert gaps == ["Node workspace discovery bound reached; delivery coverage incomplete"]


def test_php_and_generic_catalogs_keep_scope_and_runtime_candidates(tmp_path):
    from appsec_review.jobs.job_language_build import job as language, php

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "helper.dll").write_bytes(b"fake-dll")
    (workspace / "config.php").write_text("<?php return 1;")
    (workspace / "composer.json").write_text('{"name":"fixture/app"}')
    (workspace / "composer.lock").write_text(json.dumps({
        "packages": [{"name": "fixture/runtime", "version": "1.0"}],
        "packages-dev": [{"name": "fixture/builder", "version": "1.0"}],
    }))
    artifacts, gaps = php.catalog(tmp_path, workspace, {}, 100, "fixture")
    assert all(row["scope_version"] == SCOPE_VERSION and row["analysis_reason"] for row in artifacts)
    companion = next(row for row in artifacts if row["workspace_path"] == "helper.dll")
    assert companion["scope_role"] == "unknown" and delivery_gap(companion) in gaps
    metadata, gaps = php.composer_metadata(workspace, ".")
    assert [row["scope_role"] for row in metadata["packages"]] == ["unknown", "build_dependency"]
    assert any("fixture/runtime" in gap and "delivery status is unknown" in gap for gap in gaps)
    (workspace / "compile_commands.json").write_text("[]")
    generic, _ = language._catalog(tmp_path, workspace, {}, 100, "fixture")
    evidence = next(row for row in generic if row["kind"] == "compile-database")
    assert evidence["scope_role"] == "intermediate_evidence"
    assert evidence["analysis_reason"] == "build-provenance-inventory"
    assert analysis_scope(evidence, "inventory")[0]
    assert not analysis_scope(evidence, "native")[0]


def test_generated_source_catalog_reaches_path_symbols_and_ast(tmp_path, monkeypatch):
    from appsec_review.jobs.job_target_catalog import job as catalog

    target = tmp_path / "target"
    source = target / "generated/app.js"
    source.parent.mkdir(parents=True)
    source.write_text("function delivered() { return 1; }\n")
    run = tmp_path / "run"
    outputs = {}
    job = SimpleNamespace(target_root=target, run_root=run, attempt_root=run / "attempt",
                          source_fingerprint="a" * 64, config=SimpleNamespace(exclusions=None))
    units = {item.unit_id: item for item in catalog.build_job().units}

    def context(name):
        return SimpleNamespace(job=job, unit_id=name, output=lambda key: outputs[key])

    name = "repository_discovery.partition_repository"
    outputs[name] = units[name].handler(context(name))
    [file] = outputs[name]["files"]
    assert file["generated"] and file["scope_role"] == "target_source"
    entities = []

    class FakeIndex:
        def __init__(self, path, **kwargs):
            self.path = path

        def add_entity(self, row):
            entities.append(row)

        def add_relation(self, row):
            pass

        def add_coverage(self, *args):
            pass

        def build(self):
            return "b" * 64

    monkeypatch.setattr(catalog, "IndexBuilder", FakeIndex)
    monkeypatch.setattr(catalog, "_run_artifact", lambda *args: {"path": "fake", "sha256": "b" * 64})
    for name in ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index"):
        assert units[name].handler(context(name))["item_count"] == 1
    assert len(entities) == 2
    assert all(row.payload["generated"] and row.payload["scope_role"] == "target_source" for row in entities)
    scopes = plan_scopes({"files": outputs["repository_discovery.partition_repository"]["files"]})
    assert len(scopes) == 1 and scopes[0].files[0]["generated"]
    assert scopes[0].files[0]["analysis_reason"] == "target-source-review"


def test_ast_scope_excludes_platform_but_not_generated_origin():
    files = [{"path": f"generated/{role}.js", "sha256": "a" * 64, "size_bytes": 30,
              "language": "JavaScript", "generated": True, "scope_role": role}
             for role, *_ in ROLES]
    scopes = plan_scopes({"files": files}, max_files_per_scope=2)
    retained = [row for scope in scopes for row in scope.files]
    assert {row["scope_role"] for row in retained} == {
        "target_source", "deliverable", "shipped_dependency", "runtime_dependency",
        "build_chain", "build_dependency", "unknown",
    }
    assert all(len(scope.files) <= 2 for scope in scopes)


def test_generated_source_is_scored_from_fake_accepted_ast(tmp_path, monkeypatch):
    from appsec_review.config.assurance import ReviewPolicy
    from appsec_review.jobs.job_review_prioritization import job as priority
    from appsec_review.jobs.job_review_prioritization.syntax import Node

    path = "generated/app.js"
    payload = b"const value = 1;\n"
    source = tmp_path / path
    source.parent.mkdir(parents=True)
    source.write_bytes(payload)
    digest = file_sha256(source)
    files = {path: {"sha256": digest, "size_bytes": len(payload), "language": "JavaScript",
                    "generated": True, "scope_role": "deliverable", "component_id": "fixture"}}
    shard = tmp_path / "shard.jsonl"
    shard.write_bytes(json.dumps({"path": path, "file_sha256": digest,
                                  "location": {"producer_location": {"grammar": "javascript"}}}).encode() + b"\n")
    loaded = {"files_artifact": "files", "inputs": {"tree_sitter_artifact": "tree"}}
    documents = {"files": files, "tree": {"dispositions": [
        {"artifact": {"path": "shard.jsonl", "sha256": file_sha256(shard)}}]}}
    monkeypatch.setattr(priority, "read_json", lambda root, identity: documents[identity])
    root = Node("program", None, True, False, 0, len(payload), 1, 1, 1, len(payload))
    monkeypatch.setattr(priority, "build_tree", lambda rows: (root, 0))
    monkeypatch.setattr(priority, "_settings", lambda _: {
        "max_functions": 10, "max_files": 10, "max_file_bytes": 4096,
        "cyclomatic_thresholds": [10, 20, 50], "count_error_propagation": True,
        "max_signals_per_file": 100, "max_import_records": 100,
        "custom_parsing_min_operations": 1, "custom_parsing_min_density": 0.1,
        "state_mutation_min_operations": 1,
        "syntax_metrics_reservation": {"cpu": 1, "memory_mb": 64, "io_slots": 0, "admission_timeout_seconds": 5},
    })
    unit = SimpleNamespace(job=SimpleNamespace(run_root=tmp_path, target_root=tmp_path,
                                               metadata_root=tmp_path / "metadata", review_policy=ReviewPolicy(),
                                               events=SimpleNamespace(write=lambda *args, **kwargs: None)),
                           unit_id="extract.syntax_metrics", unit_root=tmp_path / "unit", output=lambda _: loaded)
    task = next(item for item in priority.build_job().units if item.unit_id == "extract.syntax_metrics")
    result = task.handler(unit)
    assert result["file_count"] == 1
    row = json.loads((tmp_path / "unit" / "artifacts" / "syntax-facts.json").read_text(encoding="utf-8"))["files"][path]
    assert row["generated"] and row["scope_role"] == "deliverable"
    assert not any("generated_file_not_scored" in gap for gap in result["gaps"])