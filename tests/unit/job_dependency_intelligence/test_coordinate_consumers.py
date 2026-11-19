"""Real package normalization and SCA reader regressions (T-5126)."""

from dataclasses import replace
import json

import jsonschema
import pytest

from appsec_review.jobs.job_dependency_intelligence import build_job, normalize_dependencies
from appsec_review.jobs.job_dependency_intelligence.reachability import (
    DependencyIntelligenceSettings, _match_osv_indexed, evaluate_sca_reachability,
)
from appsec_review.jobs.job_evidence_collection.adapters import _syft_parser
from appsec_review.jobs.job_review_prioritization.composite import _load_sca_reachability
from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT as PRIORITY_CONTRACT
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference
from tests.unit.job_dependency_intelligence.test_job_graph import _framework, _owner_scope
from tests.unit.job_dependency_intelligence.test_native_discovery import discover
from tests.unit.job_dependency_intelligence.test_publication_contract import (
    _context, _publish, _snapshot, _unit,
)
from tests.unit.job_dependency_intelligence.test_sca_reachability import (
    ROOT, SNAPSHOT, _build_osv_sqlite, _files, _pin,
)


def _normalize(*, packages=(), native=()):
    return normalize_dependencies(
        [], packages, native, supported_hosts=("github.com",), max_dependencies=100)


@pytest.mark.parametrize("ecosystem,name,purl,osv_name", [
    ("Maven", "log4j-core", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
     "org.apache.logging.log4j:log4j-core"),
    ("npm", "@example/parser", "pkg:npm/%40example/parser@2.14.1", "@example/parser"),
    ("Go", "example.org/parser", "pkg:golang/example.org/parser@2.14.1", "example.org/parser"),
    ("PyPI", "Example_Parser", None, "example-parser"),
], ids=["maven-namespace", "npm-scope", "go-module", "purl-less-pypi"])
def test_real_package_parser_normalization_reaches_osv(tmp_path, ecosystem, name, purl, osv_name):
    observations = _syft_parser(json.dumps({"artifacts": [{
        "id": "installed", "name": name, "version": "2.14.1", "purl": purl,
    }]}).encode())
    # Ecosystem/directness are also accepted from structured package observations.
    dependencies, gaps = _normalize(packages=[
        {**row, "ecosystem": ecosystem, "direct": False} for row in observations])
    assert gaps == []
    database = tmp_path / "osv.sqlite"
    _build_osv_sqlite(database, [{"id": "ADV-package", "affected": [{
        "package": {"ecosystem": ecosystem, "name": osv_name}, "versions": ["2.14.1"],
    }]}])
    matches, gaps = _match_osv_indexed(database, dependencies, 10, max_candidates_per_package=10)
    assert gaps == []
    assert [(row["package_name"], row["package_version"], row["direct"]) for row in matches] == [
        (osv_name, "2.14.1", False)]
    assert matches[0]["dependency_ids"] == [dependencies[0]["dependency_id"]]


def test_normalization_keeps_ecosystems_case_sensitive_versions_and_roots_separate():
    rows = [
        {"name": "same", "version": version, "ecosystem": ecosystem,
         "root_id": root, "package_root": "deps/same", "domain": domain}
        for ecosystem, version, root, domain in [
            ("npm", "1.0", "a", "target"), ("PyPI", "1.0", "a", "target"),
            ("npm", "1.0", "b", "target"), ("npm", "1.0", "a", "workspace"),
            ("npm", "1.0-RC", "a", "target"), ("npm", "1.0-rc", "a", "target"),
        ]
    ]
    dependencies, gaps = _normalize(packages=rows)
    reversed_dependencies, _ = _normalize(packages=list(reversed(rows)))
    assert gaps == []
    assert dependencies == reversed_dependencies
    assert len({row["dependency_id"] for row in dependencies}) == len(rows)
    assert {(row["ecosystem"], row["version"], row["root_id"], row["domain"])
            for row in dependencies} == {
        (row["ecosystem"], row["version"], row["root_id"], row["domain"]) for row in rows}


@pytest.mark.parametrize("status", ["corroborated", "inferred", "conflicted", "unknown"])
def test_nested_release_grades_survive_normalization_and_purl_matching(tmp_path, status):
    discovery, _ = discover({"vendor/zlib/zlib.h": '#define ZLIB_VERSION "1.3.1"\n'})
    candidate = discovery["candidates"][0]
    candidate = {**candidate, "purl": "pkg:generic/zlib@1.3.1",
                 "release": {**candidate["release"], "status": status}}
    dependencies, gaps = _normalize(native=[candidate])
    assert gaps == []
    assert dependencies[0]["version"] == ("1.3.1" if status == "corroborated" else None)
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=None, dependencies=dependencies,
        native_advisory_matches=[{"cve_id": "CVE-2026-1234", "name": "zlib",
                                 "version": "1.3.1", "purl": candidate["purl"]}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert doc["advisories"][0]["dependency_ids"] == (
        [dependencies[0]["dependency_id"]] if status == "corroborated" else [])
    assert doc["advisories"][0]["reachability"] == "unknown"
    assert dependencies[0]["release"] == candidate["release"]


@pytest.mark.parametrize("grade,expected", [("corroborated", 1), ("inferred", 0), ("conflicted", 0)])
def test_nested_version_is_decoded_without_stringifying_or_promoting(tmp_path, grade, expected):
    dependencies, _ = _normalize(packages=[{
        "name": "same", "ecosystem": "npm", "purl": "pkg:npm/same@1.0.0",
        "version": {"value": "1.0.0", "status": grade, "evidence_ids": ["package:1"]},
    }])
    database = tmp_path / "osv.sqlite"
    _build_osv_sqlite(database, [{"id": "ADV-package", "affected": [{
        "package": {"ecosystem": "npm", "name": "same"}, "versions": ["1.0.0"],
    }]}])
    matches, gaps = _match_osv_indexed(database, dependencies, 10, max_candidates_per_package=10)
    assert len(matches) == expected
    assert dependencies[0]["version"] == ("1.0.0" if expected else None)
    assert dependencies[0]["observations"][0]["version"]["status"] == grade
    assert bool(gaps) is not bool(expected)


def test_declared_constraint_does_not_become_installed_version(tmp_path):
    dependencies, _ = normalize_dependencies(
        [{"name": "same", "ecosystem": "npm", "constraint": "1.0.0"}], [], [],
        supported_hosts=("github.com",), max_dependencies=10)
    database = tmp_path / "osv.sqlite"
    _build_osv_sqlite(database, [{"id": "ADV-package", "affected": [{
        "package": {"ecosystem": "npm", "name": "same"}, "versions": ["1.0.0"],
    }]}])
    matches, gaps = _match_osv_indexed(database, dependencies, 10, max_candidates_per_package=10)
    assert matches == []
    assert gaps == [f"osv_dependency_identity_incomplete:{dependencies[0]['dependency_id']}"]
    assert dependencies[0]["constraint"] == "1.0.0"


def test_distinct_installed_roots_do_not_certify_an_import_instance(tmp_path):
    dependencies, _ = _normalize(packages=[
        {"name": "demo", "purl": "pkg:pypi/demo@1.0", "version": "1.0",
         "root_id": root, "package_root": "lib/demo"}
        for root in ("first", "second")
    ])
    (tmp_path / "app.py").write_text("import demo\ndemo.unsafe()\n", encoding="utf-8")
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, dependencies=dependencies,
        partition_files=_files(tmp_path, ["app.py"]),
        scanner_advisories=[{"advisory": "ADV-package", "package": "demo",
                             "purl": "pkg:pypi/demo@1.0", "affected_modules": ["demo"],
                             "affected_symbols": ["unsafe"]}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert len(dependencies) == 2
    assert doc["advisories"][0]["dependency_ids"] == sorted(row["dependency_id"] for row in dependencies)
    assert doc["advisories"][0]["reachability"] == "package_imported"
    assert "reachability_package_binding_ambiguous:ADV-package:demo" in doc["gaps"]


def _published(tmp_path):
    ctx = _context(tmp_path)
    outputs = {}
    with _owner_scope(ctx):
        for unit in build_job().units:
            if unit.unit_id == "publication.publish_context":
                break
            outputs[unit.unit_id] = unit.handler(_unit(ctx, unit.unit_id, outputs))
    result, doc = _publish(ctx, outputs, _snapshot(tmp_path / "snapshot"))
    return ctx, result, doc


def _coordinate_publication(tmp_path, packages):
    ctx = _context(tmp_path)
    outputs = {}
    with _owner_scope(ctx):
        for unit in build_job().units:
            if unit.unit_id == "publication.publish_context":
                break
            outputs[unit.unit_id] = unit.handler(_unit(ctx, unit.unit_id, outputs))
    dependencies, _ = _normalize(packages=packages)
    outputs["resolution.infer_repositories"] = {
        **outputs["resolution.infer_repositories"], "dependencies": dependencies,
    }
    database = tmp_path / "coordinates.sqlite"
    _build_osv_sqlite(database, [{"id": "ADV-coordinates", "affected": [
        {"package": {"ecosystem": ecosystem, "name": "demo"}, "versions": ["1.0.0"]}
        for ecosystem in sorted({row["ecosystem"] for row in packages})
    ]}])
    snapshot = _pin(tmp_path / "feed", database)
    result, doc = _publish(ctx, outputs, snapshot)
    return ctx, outputs, snapshot, result, doc


def _published_sca_rows(ctx, result):
    manifest = result["index_manifest"]
    core = RetrievalCore(
        ctx.run_root.parent, ctx.run_id, manifest_path=ctx.run_root / manifest["path"],
        manifest_sha256=manifest["sha256"])
    return core.query_sca_reachability(package="demo", advisory_id="ADV-coordinates")["results"]


@pytest.mark.parametrize("distinction", ["ecosystems", "qualifiers", "subpaths"])
def test_publication_keeps_distinct_package_coordinates(tmp_path, distinction):
    packages = [{"name": "demo", "version": "1.0.0", "ecosystem": ecosystem}
                for ecosystem in (("PyPI", "npm") if distinction == "ecosystems" else ("npm", "npm"))]
    if distinction != "ecosystems":
        suffixes = (
            ["?repository_url=https%3A%2F%2Fregistry.first.test",
             "?repository_url=https%3A%2F%2Fregistry.second.test"]
            if distinction == "qualifiers" else ["#packages/first", "#packages/second"]
        )
        for package, suffix in zip(packages, suffixes):
            package["purl"] = "pkg:npm/demo@1.0.0" + suffix
    ctx, outputs, snapshot, result, doc = _coordinate_publication(tmp_path, packages)
    rows = _published_sca_rows(ctx, result)
    assert len(rows) == len({row["identity"] for row in rows}) == 2
    assert {(row["payload"]["ecosystem"], row["payload"]["purl"]) for row in rows} == {
        (package["ecosystem"], package.get("purl")) for package in packages}
    assert {tuple(row["payload"]["dependency_ids"]) for row in rows} == {
        (dependency["dependency_id"],) for dependency in outputs["resolution.infer_repositories"]["dependencies"]}
    reversed_dependencies, _ = _normalize(packages=list(reversed(packages)))
    outputs["resolution.infer_repositories"]["dependencies"] = reversed_dependencies
    repeated, repeated_doc = _publish(ctx, outputs, snapshot)
    assert repeated["index_identity"] == result["index_identity"]
    assert repeated_doc == doc


def test_publication_signal_identity_binds_sorted_root_instances(tmp_path):
    first = {"name": "demo", "version": "1.0.0", "ecosystem": "PyPI",
             "purl": "pkg:pypi/demo@1.0.0", "root_id": "first", "package_root": "lib/demo"}
    ctx, outputs, snapshot, result, doc = _coordinate_publication(tmp_path, [first])
    original_rows = _published_sca_rows(ctx, result)
    assert len(original_rows) == 1
    second = {**first, "root_id": "second"}
    dependencies, _ = _normalize(packages=[second, first])
    outputs["resolution.infer_repositories"]["dependencies"] = dependencies
    expanded, expanded_doc = _publish(ctx, outputs, snapshot)
    expanded_rows = _published_sca_rows(ctx, expanded)
    assert len(expanded_rows) == 1
    assert expanded_rows[0]["identity"] != original_rows[0]["identity"]
    assert expanded_doc["advisories"][0]["dependency_ids"] == sorted(
        row["dependency_id"] for row in dependencies)
    assert len(expanded_doc["advisories"][0]["dependency_ids"]) == 2
    assert doc["advisories"][0]["dependency_ids"] != expanded_doc["advisories"][0]["dependency_ids"]
    assert doc["advisories"][0]["reachability"] == expanded_doc["advisories"][0]["reachability"]
    dependencies, _ = _normalize(packages=[first, second])
    outputs["resolution.infer_repositories"]["dependencies"] = dependencies
    repeated, repeated_doc = _publish(ctx, outputs, snapshot)
    assert repeated["index_identity"] == expanded["index_identity"]
    assert repeated_doc == expanded_doc


def test_real_publication_supports_exact_reachability_filters_and_read_receipts(tmp_path):
    ctx, result, doc = _published(tmp_path)
    manifest = result["index_manifest"]
    published = _framework(ctx.run_root, "job_dependency_intelligence", {
        "acceptance.publish_handoff": result,
    }, [manifest, result["sca_reachability"],
        reference(ctx.run_root, ctx.run_root / result["index_identity"]["relative_path"])])
    consumer = replace(ctx, config=replace(ctx.config, job_id="job_review_prioritization"),
                       contract=PRIORITY_CONTRACT,
                       upstream_handoffs={"job_dependency_intelligence": published["sha256"]})
    core = RetrievalCore(
        ctx.run_root.parent, ctx.run_id, manifest_path=ctx.run_root / manifest["path"],
        manifest_sha256=manifest["sha256"])
    # The query keeps its public argument spelling but reads the producer's actual field.
    with input_read_scope(consumer) as reads:
        hits = core.query_sca_reachability(
            package="demo", advisory_id="GHSA-demo-0001", reachability_class="symbol_reachable")
    assert len(hits["results"]) == 1
    assert hits["results"][0]["payload"]["reachability"] == doc["advisories"][0]["reachability"]
    assert any(row["output_kind"] == "dependency_context" and row["read"]
               and row["sha256"] == result["index_identity"]["sha256"]
               for row in reads.document()["reads"])
    identity = hits["results"][0]["identity"]
    assert len(core.query_sca_reachability(
        subject=identity, package="pkg:pypi/demo@1.0.0",
        reachability_class="symbol_reachable", limit=1)["results"]) == 1
    for filters in ({"package": "dem"}, {"advisory_id": "GHSA-demo"},
                    {"reachability_class": "unknown"}):
        assert core.query_sca_reachability(**filters)["results"] == []
    with input_read_scope(consumer):
        _, leads, _, _ = _load_sca_reachability(ctx.run_root, True)
    assert len(leads) == 1
    assert leads[0]["package_name"] == "demo"
    assert leads[0]["attack_class"] == "vulnerable_dependency_reachability"
    assert leads[0]["reachability"] == "symbol_reachable"


def test_priority_reads_real_package_ffi_sites_and_keeps_coordinates_distinct(tmp_path):
    ctx = _context(tmp_path)
    (ctx.target_root / "app.py").write_text(
        'import ctypes\nz = ctypes.CDLL("libz.so")\n', encoding="utf-8")
    dependencies, _ = _normalize(packages=[
        {"name": "z", "version": version, "purl": f"pkg:generic/z@{version}"}
        for version in ("1.0", "2.0")
    ])
    doc = evaluate_sca_reachability(
        source_fingerprint=ctx.source_fingerprint, repository_root=ROOT,
        run_root=ctx.run_root, target_root=ctx.target_root, dependencies=dependencies,
        partition_files=_files(ctx.target_root, ["app.py"]),
        native_advisory_matches=[
            {"cve_id": "CVE-2026-1234", "name": "z", "version": row["version"],
             "purl": row["purl"], "dependency_ids": [row["dependency_id"]]}
            for row in dependencies
        ],
        scanner_advisories=[{"advisory": "ADV-unbound", "package": "z",
                             "version": "3.0", "purl": "pkg:generic/z@3.0"}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"))
    assert {row["reachability"] for row in doc["advisories"]} == {"package_imported", "unknown"}
    path = ctx.attempt_root / "steps/publication/tasks/publish_context/sca-reachability.json"
    atomic_json(path, doc)
    artifact = reference(ctx.run_root, path)
    published = _framework(ctx.run_root, "job_dependency_intelligence", {
        "acceptance.publish_handoff": {"sca_reachability": artifact},
    }, [artifact])
    consumer = replace(ctx, config=replace(ctx.config, job_id="job_review_prioritization"),
                       contract=PRIORITY_CONTRACT,
                       upstream_handoffs={"job_dependency_intelligence": published["sha256"]})
    with input_read_scope(consumer) as reads:
        status, leads, files, sites = _load_sca_reachability(ctx.run_root, True)
    assert len(leads) == 2
    assert len({lead["lead_id"] for lead in leads}) == 2
    assert {lead["subject"] for lead in leads} == {"pkg:generic/z@1.0", "pkg:generic/z@2.0"}
    assert all(lead["package_name"] == "z" for lead in leads)
    assert all(lead["attack_class"] == "native_ffi_vulnerable_dependency" for lead in leads)
    assert all(lead["reachability"] == "package_imported" for lead in leads)
    assert all("static evidence only" in lead["summary"] for lead in leads)
    schema = json.loads((ROOT / "docs/schemas/review-prioritization/prioritization-signals.schema.json").read_text())
    for lead in leads:
        jsonschema.validate(lead, schema["properties"]["promoted_leads"]["items"])
    assert files == {"app.py": pytest.approx(.70)}
    assert sites == [("app.py", 2, pytest.approx(.70))] * 2
    assert any(row["producer"] == "job_dependency_intelligence"
               and row["output_kind"] == "sca_reachability" and row["read"]
               for row in reads.document()["reads"])
