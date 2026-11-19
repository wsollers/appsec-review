"""Unit tests for indexed OSV matching, exact fallback, and symbol/FFI reachability (T-170)."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import jsonschema
import pytest

from appsec_review.jobs.job_dependency_intelligence.reachability import (
    DependencyIntelligenceSettings,
    REACHABILITY_IMPORTED,
    REACHABILITY_SCHEMA,
    REACHABILITY_SYMBOL,
    REACHABILITY_TRANSITIVE,
    REACHABILITY_UNKNOWN,
    evaluate_sca_reachability,
    scan_target_reachability_index,
    _resolve_osv_source,
)
from appsec_review.jobs.job_third_party_data_sync.publication import publish_snapshot
from appsec_review.storage import file_sha256


ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = ROOT / "docs" / "schemas" / "dependency-intelligence" / "sca-reachability.schema.json"
SNAPSHOT = "a" * 64


def _build_osv_sqlite(db_path: Path, records: list[dict]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE advisory (id TEXT PRIMARY KEY, modified TEXT, summary TEXT, withdrawn TEXT, raw_json TEXT NOT NULL)")
        conn.execute("CREATE TABLE package (advisory_id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL)")
        ecosystems = sorted({
            aff["package"]["ecosystem"]
            for rec in records
            for aff in rec.get("affected", [])
            if "package" in aff
        })
        conn.execute("INSERT INTO metadata VALUES ('ecosystems', ?)", (json.dumps(ecosystems),))
        for rec in records:
            conn.execute(
                "INSERT INTO advisory VALUES (?, ?, ?, ?, ?)",
                (rec["id"], "2026-01-01T00:00:00Z", rec.get("summary", ""), rec.get("withdrawn"), json.dumps(rec)),
            )
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {})
                conn.execute(
                    "INSERT INTO package VALUES (?, ?, ?)",
                    (rec["id"], pkg.get("ecosystem", ""), pkg.get("name", "")),
                )


def _pin(root: Path, database: Path | None) -> dict:
    published = publish_snapshot(
        root, feed_id="osv", schema="appsec-review/osv-snapshot/1",
        files={"index/osv.sqlite": database} if database else {},
        manifest_fields={},
    )
    return {"feed_id": "osv", "snapshot_id": published["snapshot_id"],
            "manifest_sha256": published["manifest_sha256"],
            "directory": str(root / "snapshots" / published["snapshot_id"])}


def _files(target: Path, paths: list[str]) -> list[dict]:
    return [{"path": path, "sha256": file_sha256(target / path),
             "size_bytes": (target / path).stat().st_size} for path in paths]


def test_default_settings_use_index_mode_and_validate_bounds() -> None:
    cfg = DependencyIntelligenceSettings.from_settings({})
    assert cfg.osv_version_matching == "index"
    assert cfg.reachability_enabled is True
    with pytest.raises(ValueError, match="osv_version_matching"):
        DependencyIntelligenceSettings.from_settings({"osv_version_matching": "bogus"})


def test_indexed_osv_matching_keeps_unsupported_binding_as_context(tmp_path: Path) -> None:
    osv_root = tmp_path / "osv_snapshot"
    _build_osv_sqlite(
        osv_root / "index" / "osv.sqlite",
        [
            {
                "id": "GHSA-sym-0001",
                "aliases": ["CVE-2026-1001"],
                "database_specific": {"severity": "CRITICAL"},
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "semver-parse"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}]}],
                        "ecosystem_specific": {"imports": [{"path": "semver-parse", "symbols": ["parseUnsafeRange"]}]},
                    }
                ],
            },
            {
                "id": "GHSA-imp-0002",
                "aliases": ["CVE-2026-1002"],
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "jinja2"},
                        "versions": ["3.1.2"],
                        "ecosystem_specific": {"functions": ["xmlattr_filter"]},
                    }
                ],
            },
            {
                "id": "GHSA-trn-0003",
                "aliases": ["CVE-2026-1003"],
                "database_specific": {"severity": "MODERATE"},
                "affected": [
                    {
                        "package": {"ecosystem": "crates.io", "name": "smallvec"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.6.1"}]}],
                    }
                ],
            },
            {
                "id": "GHSA-unr-0004",
                "aliases": ["CVE-2026-1004"],
                "database_specific": {"severity": "LOW"},
                "affected": [
                    {
                        "package": {"ecosystem": "Go", "name": "golang.org/x/net"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.1.0"}, {"fixed": "0.23.0"}]}],
                    }
                ],
            },
        ],
    )

    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.ts").write_text(
        "import { parseUnsafeRange } from 'semver-parse';\nexport const r = parseUnsafeRange(input);\n",
        encoding="utf-8",
    )
    (target / "src" / "views.py").write_text(
        "import jinja2\nenv = jinja2.Environment(autoescape=True)\n",
        encoding="utf-8",
    )
    # Vendored file calling golang.org/x/net must NOT count as first-party usage
    (target / "vendor" / "net_wrap.go").mkdir(parents=True)
    (target / "vendor" / "net_wrap.go" / "wrap.go").write_text(
        'package wrap\nimport "golang.org/x/net/http2"\n',
        encoding="utf-8",
    )

    dependencies = [
        {"dependency_id": "dep-1", "name": "semver-parse", "version": "1.2.0", "purl": "pkg:npm/semver-parse@1.2.0", "direct": True},
        {"dependency_id": "dep-2", "name": "jinja2", "version": "3.1.2", "purl": "pkg:pypi/jinja2@3.1.2", "direct": True},
        {"dependency_id": "dep-3", "name": "smallvec", "version": "1.4.0", "purl": "pkg:cargo/smallvec@1.4.0", "direct": False},
        {"dependency_id": "dep-4", "name": "golang.org/x/net", "version": "0.19.0", "purl": "pkg:golang/golang.org/x/net@0.19.0", "direct": True},
    ]

    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT,
        repository_root=ROOT,
        run_root=tmp_path / "run",
        target_root=target,
        dependencies=dependencies,
        osv_snapshot=_pin(osv_root, osv_root / "index/osv.sqlite"),
        partition_files=_files(target, ["src/app.ts", "src/views.py", "vendor/net_wrap.go/wrap.go"]),
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)

    assert doc["schema"] == REACHABILITY_SCHEMA
    assert doc["osv_matching_mode"] == "index"
    assert doc["osv_fallback_reason"] is None
    assert doc["telemetry"]["osv_matching_mode"] == "index"
    assert doc["telemetry"]["advisories_matched"] == 4
    assert doc["telemetry"]["symbol_reachable_count"] == 0

    by_id = {item["advisory_id"]: item for item in doc["advisories"]}
    assert by_id["GHSA-sym-0001"]["reachability"] == REACHABILITY_IMPORTED
    assert by_id["GHSA-sym-0001"]["call_sites"] == [{
        "path": "src/app.ts", "line": 1, "symbol": "semver-parse", "kind": "package_import",
        "ffi_mechanism": None, "file_sha256": file_sha256(target / "src/app.ts"),
    }]
    assert "reachability_symbol_binding_unsupported:src/app.ts" in doc["gaps"]
    assert by_id["GHSA-imp-0002"]["reachability"] == REACHABILITY_IMPORTED
    assert by_id["GHSA-trn-0003"]["reachability"] == REACHABILITY_TRANSITIVE
    assert by_id["GHSA-unr-0004"]["reachability"] == REACHABILITY_UNKNOWN
    assert doc["coverage"] == "partial"
    assert doc["osv_snapshot"]["index_sha256"] == file_sha256(osv_root / "index/osv.sqlite")


def test_missing_index_does_not_fallback_to_unverified_raw_directory(tmp_path: Path, monkeypatch) -> None:
    raw_dir = tmp_path / "osv_unindexed"
    raw_dir.mkdir(parents=True)
    (raw_dir / "PYSEC-2026-99.json").write_text(
        json.dumps({
            "id": "PYSEC-2026-99",
            "aliases": ["CVE-2026-9999"],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pyyaml"},
                    "versions": ["5.3.1"],
                    "ecosystem_specific": {"functions": ["full_load"]},
                }
            ],
        }),
        encoding="utf-8",
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "loader.py").write_text("from pyyaml import full_load\nfull_load(raw)\n", encoding="utf-8")

    monkeypatch.setattr(Path, "rglob", lambda *_: pytest.fail("no unverified file walk"))
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT,
        repository_root=ROOT,
        run_root=tmp_path / "run",
        target_root=target,
        dependencies=[{"dependency_id": "d-yaml", "name": "pyyaml", "version": "5.3.1", "ecosystem": "pypi"}],
        osv_snapshot=_pin(raw_dir, None),
        partition_files=_files(target, ["loader.py"]),
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)
    assert doc["configured_osv_mode"] == "index"
    assert doc["osv_matching_mode"] == "index"
    assert doc["osv_fallback_reason"] == "osv_snapshot_index_unavailable"
    assert "osv_snapshot_index_unavailable" in doc["gaps"]
    assert doc["telemetry"]["advisories_matched"] == 0


def test_eight_ecosystem_native_ffi_context_does_not_prove_vulnerable_symbol_use(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "bridge.py").write_text(
        'import ctypes\nz = ctypes.CDLL("libz.so.1")\nz.inflate(buf)\n', encoding="utf-8"
    )
    (target / "src" / "NativePin.cs").write_text(
        'using System.Runtime.InteropServices;\nclass P { [DllImport("libexpat", EntryPoint="XML_Parse")] static extern int XML_Parse(nint p); }\n',
        encoding="utf-8",
    )
    (target / "src" / "JniBridge.java").write_text(
        'class JniBridge { static { System.loadLibrary("lz4"); } public native int LZ4_decompress_fast(byte[] s); }\n',
        encoding="utf-8",
    )
    (target / "src" / "ffi_wrap.rb").write_text(
        'require "ffi"\nmodule Bz; extend FFI::Library; ffi_lib "bz2"; attach_function :BZ2_bzDecompress, [:pointer], :int; end\n',
        encoding="utf-8",
    )
    (target / "src" / "ffi.rs").write_text(
        '#[link(name = "zstd")]\nextern "C" { fn ZSTD_decompress(dst: *mut u8) -> usize; }\n',
        encoding="utf-8",
    )
    (target / "src" / "cgo.go").write_text(
        'package main\n// #cgo LDFLAGS: -lwebp\nimport "C"\nfunc dec() { C.WebPDecodeRGBA(nil, 0, nil, nil) }\n',
        encoding="utf-8",
    )
    (target / "src" / "ffi.php").write_text(
        '<?php\n$ffi = FFI::cdef("int cJSON_Parse(const char *v);", "libcjson.so");\n$ffi->cJSON_Parse($s);\n',
        encoding="utf-8",
    )
    (target / "src" / "dl.cpp").write_text(
        'extern "C" int archive_read_data(void* a);\nvoid run(void* h) { dlopen("libarchive.so", 1); archive_read_data(h); }\n',
        encoding="utf-8",
    )

    native_matches = [
        {"cve_id": "CVE-2022-37434", "name": "z", "version": "1.2.12", "purl": "pkg:generic/z@1.2.12", "severity": "CRITICAL", "dependency_ids": ["d1"]},
        {"cve_id": "CVE-2022-25235", "name": "expat", "version": "2.4.4", "purl": "pkg:generic/expat@2.4.4", "severity": "CRITICAL", "dependency_ids": ["d2"]},
        {"cve_id": "CVE-2019-17543", "name": "lz4", "version": "1.9.1", "purl": "pkg:generic/lz4@1.9.1", "severity": "HIGH", "dependency_ids": ["d3"]},
        {"cve_id": "CVE-2019-12900", "name": "bz2", "version": "1.0.6", "purl": "pkg:generic/bz2@1.0.6", "severity": "CRITICAL", "dependency_ids": ["d4"]},
        {"cve_id": "CVE-2022-4899", "name": "zstd", "version": "1.5.2", "purl": "pkg:generic/zstd@1.5.2", "severity": "HIGH", "dependency_ids": ["d5"]},
        {"cve_id": "CVE-2023-4863", "name": "webp", "version": "1.3.1", "purl": "pkg:generic/webp@1.3.1", "severity": "CRITICAL", "dependency_ids": ["d6"]},
        {"cve_id": "CVE-2024-31755", "name": "cjson", "version": "1.7.17", "purl": "pkg:generic/cjson@1.7.17", "severity": "HIGH", "dependency_ids": ["d7"]},
        {"cve_id": "CVE-2024-20696", "name": "archive", "version": "3.7.1", "purl": "pkg:generic/archive@3.7.1", "severity": "HIGH", "dependency_ids": ["d8"]},
    ]

    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT,
        repository_root=ROOT,
        run_root=tmp_path / "run",
        target_root=target,
        dependencies=[{"dependency_id": row["dependency_ids"][0], "name": row["name"],
                       "version": row["version"], "purl": row["purl"]} for row in native_matches],
        native_advisory_matches=native_matches,
        partition_files=_files(target, [
            "src/bridge.py", "src/NativePin.cs", "src/JniBridge.java", "src/ffi_wrap.rb",
            "src/ffi.rs", "src/cgo.go", "src/ffi.php", "src/dl.cpp",
        ]),
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)
    assert doc["telemetry"]["advisories_matched"] == 8
    assert doc["telemetry"]["ffi_boundary_matches"] == 8
    assert doc["telemetry"]["symbol_reachable_count"] == 0
    for adv in doc["advisories"]:
        assert adv["reachability"] == REACHABILITY_IMPORTED
        assert adv["ffi_mechanisms"]
        assert adv["call_sites"]
        assert all(site["kind"] == "ffi_boundary" for site in adv["call_sites"])
        assert f"reachability_native_symbol_binding_not_established:{adv['advisory_id']}" in doc["gaps"]


def test_empty_partition_never_walks_target_and_has_unknown_reachability(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "hidden.py").write_text("import pyyaml\n", encoding="utf-8")
    monkeypatch.setattr(Path, "rglob", lambda *_: pytest.fail("empty inventory is not permission to scan"))
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=target, dependencies=[],
        scanner_advisories=[{"advisory": "CVE-2026-1111", "package": "pyyaml"}],
    )
    assert doc["advisories"][0]["reachability"] == REACHABILITY_UNKNOWN
    assert any("reachability_partition_empty" in gap for gap in doc["gaps"])
    assert "osv_snapshot_not_admitted" in doc["gaps"]


@pytest.mark.parametrize("defect", ["unhashed", "tampered", "symlink"])
def test_reachability_source_requires_accepted_hash_and_path_custody(tmp_path, defect):
    source = tmp_path / "app.py"
    source.write_text("import pyyaml\n", encoding="utf-8")
    files = _files(tmp_path, ["app.py"])
    if defect == "unhashed":
        files[0].pop("sha256")
    elif defect == "tampered":
        source.write_text("import pillow\n", encoding="utf-8")
    else:
        source.rename(tmp_path / "other.py")
        source.symlink_to(tmp_path / "other.py")
    with pytest.raises(ValueError):
        scan_target_reachability_index(target_root=tmp_path, partition_files=files)


def test_source_and_callsite_caps_are_named_gaps(tmp_path):
    (tmp_path / "a.py").write_text("import pyyaml\npyyaml.load(x)\npyyaml.load(y)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import pyyaml\n", encoding="utf-8")
    files = _files(tmp_path, ["a.py", "b.py"])
    index = scan_target_reachability_index(target_root=tmp_path, partition_files=files, max_source_files=1)
    assert any("source_files_truncated" in gap for gap in index["gaps"])
    index = scan_target_reachability_index(target_root=tmp_path, partition_files=files, max_bytes_per_file=1)
    assert len(index["gaps"]) == 2 and not index["imports"]
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=files,
        dependencies=[{"dependency_id": "yaml", "name": "pyyaml", "version": "1.0",
                       "purl": "pkg:pypi/pyyaml@1.0"}],
        scanner_advisories=[{"advisory": "CVE-2026-1111", "package": "pyyaml",
                            "version": "1.0", "purl": "pkg:pypi/pyyaml@1.0",
                            "affected_symbols": ["load"], "affected_modules": ["pyyaml"]}],
        settings=DependencyIntelligenceSettings(max_call_sites_per_advisory=1),
    )
    assert any("call_sites_truncated" in gap for gap in doc["gaps"])
    assert len(doc["advisories"][0]["call_sites"]) == 1


def test_osv_pin_rejects_unverified_sources_tampering_and_foreign_claim(tmp_path):
    from types import SimpleNamespace
    from appsec_review.jobs.job_dependency_intelligence.datasets import CONTRACT
    from appsec_review.runtime.inputs import input_read_scope

    database = tmp_path / "build.sqlite"
    _build_osv_sqlite(database, [])
    pin = _pin(tmp_path / "feed", database)
    for unverified in (database, lambda *_: pin, {"directory": pin["directory"]}):
        with pytest.raises(ValueError, match="immutable snapshot pin"):
            _resolve_osv_source(ROOT, tmp_path, unverified)
    context = SimpleNamespace(
        run_root=tmp_path, config=SimpleNamespace(job_id="job_dependency_intelligence"),
        upstream_handoffs={}, contract=CONTRACT,
        external_input_selection={"inputs": [{
            "producer": "job_third_party_data_sync", "output_kind": "feed_snapshot",
            "schema": "appsec-review/public-feed-use/1", "status": "available",
            "identity": {"feed_id": "osv", "snapshot_id": "different-snapshot"},
        }]},
    )
    with pytest.raises(ValueError, match="claimed immutable selection"), input_read_scope(context):
        _resolve_osv_source(ROOT, tmp_path, pin)
    path = Path(pin["directory"]) / "index/osv.sqlite"
    path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="index hash mismatch"):
        _resolve_osv_source(ROOT, tmp_path, pin)
    manifest = Path(pin["directory"]) / "manifest.json"
    manifest.write_bytes(b"{}")
    with pytest.raises(ValueError, match="manifest hash mismatch"):
        _resolve_osv_source(ROOT, tmp_path, pin)


def test_osv_caps_and_exact_matching_use_verified_index_without_foreign_package_hit(tmp_path):
    database = tmp_path / "build.sqlite"
    records = [
        {"id": f"ADV-{i}", "affected": [{"package": {"ecosystem": "npm", "name": "pkg"},
                                       "versions": ["1.0"]}]} for i in range(3)
    ]
    records.insert(0, {"id": "ADV--foreign", "affected": [
        {"package": {"ecosystem": "npm", "name": "pkg"}, "ranges": [{"type": "GIT", "events": []}]},
        {"package": {"ecosystem": "npm", "name": "other"}, "versions": ["1.0"]},
    ]})
    _build_osv_sqlite(database, records)
    pin = _pin(tmp_path / "feed", database)
    arguments = dict(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=None, dependencies=[{"name": "pkg", "version": "1.0", "ecosystem": "npm"}],
        osv_snapshot=pin,
    )
    capped = evaluate_sca_reachability(**arguments, settings=DependencyIntelligenceSettings(
        max_osv_candidates_per_package=2))
    assert any("truncated:advisories_per_package" in gap for gap in capped["gaps"])
    assert [r["advisory_id"] for r in capped["advisories"]] == ["ADV-0"]
    exact = evaluate_sca_reachability(**arguments, settings=DependencyIntelligenceSettings(
        osv_version_matching="exact", max_advisories=1))
    assert [r["advisory_id"] for r in exact["advisories"]] == ["ADV-0"]
    assert exact["advisories"][0]["match_sources"] == ["osv-exact"]
    assert "osv_advisories_truncated" in exact["gaps"]


def test_claim_selected_osv_snapshot_ignores_new_current_and_records_read(tmp_path):
    from types import SimpleNamespace
    from appsec_review.jobs.job_dependency_intelligence.datasets import CONTRACT
    from appsec_review.runtime.inputs import input_read_scope
    from appsec_review.storage import atomic_json

    database = tmp_path / "build.sqlite"
    _build_osv_sqlite(database, [])
    pin = _pin(tmp_path / "data/feeds/osv", database)
    run_root = tmp_path / "run"
    resolved = run_root / "data/configuration/resolved.json"
    atomic_json(resolved, {"jobs": {"job_third_party_data_sync": {"steps": {
        "osv_sync": {"settings": {"feed_root": "data/feeds/osv"}},
    }}}})
    atomic_json(resolved.parent / "manifest.json", {"resolved_sha256": file_sha256(resolved)})
    atomic_json(tmp_path / "data/feeds/osv/current.json", {"snapshot_id": "newer-unadmitted"})
    identity = {key: pin[key] for key in ("feed_id", "snapshot_id", "manifest_sha256")}
    selection = {"inputs": [{
        "producer": "job_third_party_data_sync", "output_kind": "feed_snapshot", "selector": "osv",
        "schema": "appsec-review/public-feed-use/1", "status": "available", "identity": identity, "reason": None,
    }]}
    context = SimpleNamespace(
        run_root=run_root, config=SimpleNamespace(job_id="job_dependency_intelligence"),
        upstream_handoffs={}, contract=CONTRACT, external_input_selection=selection,
    )
    with input_read_scope(context) as reads:
        path, observed, gap = _resolve_osv_source(tmp_path, run_root, None, selection)
        assert path == Path(pin["directory"]) / "index/osv.sqlite"
        assert observed["manifest_sha256"] == pin["manifest_sha256"] and gap is None
        records = reads.document()["reads"]
        assert len(records) == 1 and records[0]["output_kind"] == "feed_snapshot"


def test_malformed_pinned_osv_database_preserves_database_error(tmp_path):
    database = tmp_path / "invalid.sqlite"
    database.write_bytes(b"not a database")
    pin = _pin(tmp_path / "feed", database)
    with pytest.raises(sqlite3.DatabaseError, match="not a database"):
        evaluate_sca_reachability(
            source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
            target_root=None, dependencies=[], osv_snapshot=pin,
        )


def _python_advisory(
    tmp_path: Path, source: str, *, cap: int = 32, additional_sources: dict[str, str] | None = None,
) -> dict:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    for path, text in (additional_sources or {}).items():
        (tmp_path / path).write_text(text, encoding="utf-8")
    database = tmp_path / "build.sqlite"
    _build_osv_sqlite(database, [{
        "id": "PYSEC-binding",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "danger"},
            "versions": ["1.0"],
            "ecosystem_specific": {"imports": [{"path": "danger", "symbols": ["parse"]}]},
        }],
    }])
    return evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py", *sorted(additional_sources or {})]),
        dependencies=[{"dependency_id": "danger-old", "name": "danger", "version": "1.0",
                       "purl": "pkg:pypi/danger@1.0"}],
        osv_snapshot=_pin(tmp_path / "feed", database),
        settings=DependencyIntelligenceSettings(max_call_sites_per_advisory=cap),
    )


@pytest.mark.parametrize("source", [
    "from danger import parse\n",
    "import danger\ndef parse(x): return x\nparse(value)\n",
    "from danger import parse\ndef wrapper(parse): return parse(value)\n",
    "import danger\ndef wrapper(danger): return danger.parse(value)\n",
    "from danger import parse\nparse = local\nparse(value)\n",
    "from danger import parse\nother.parse(value)\n",
    "import danger\n# danger.parse(value)\ntext = 'danger.parse(value)'\n",
], ids=["import-only", "local-function", "shadowed-function", "shadowed-module",
        "reassignment", "foreign-receiver", "comment-string"])
def test_imports_and_unrelated_calls_do_not_establish_symbol_use(tmp_path, source):
    doc = _python_advisory(tmp_path, source)
    record = doc["advisories"][0]
    assert record["reachability"] == REACHABILITY_IMPORTED
    assert not any(site["kind"] == "symbol_call" for site in record["call_sites"])
    assert doc["telemetry"]["symbol_reachable_count"] == 0


@pytest.mark.parametrize("source", [
    "from danger import parse as decode\ndecode(value)\n",
    "import danger as parser\nparser.parse(value)\n",
], ids=["symbol-alias", "module-alias"])
def test_unambiguous_import_bound_calls_have_real_source_locations(tmp_path, source):
    doc = _python_advisory(tmp_path, source)
    record = doc["advisories"][0]
    assert record["reachability"] == REACHABILITY_SYMBOL
    assert record["call_sites"] == [{
        "path": "app.py", "line": 2, "symbol": "parse", "kind": "symbol_call",
        "ffi_mechanism": None, "file_sha256": file_sha256(tmp_path / "app.py"),
    }]
    jsonschema.validate(doc, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


@pytest.mark.parametrize("cap", [3, 32, 35, 64])
def test_callsite_limit_counts_unique_locations_without_hidden_cap(tmp_path, cap):
    doc = _python_advisory(tmp_path, "import danger\n" + "danger.parse(value)\n" * 40, cap=cap)
    sites = doc["advisories"][0]["call_sites"]
    assert [site["line"] for site in sites] == list(range(2, 2 + min(cap, 40)))
    truncation = [gap for gap in doc["gaps"] if "reachability_call_sites_truncated:" in gap]
    assert truncation == (
        [f"reachability_call_sites_truncated:PYSEC-binding:pkg:pypi/danger@1.0:omitted={40 - cap}"]
        if cap < 40 else []
    )


def test_native_library_load_does_not_bind_unrelated_print_call(tmp_path):
    (tmp_path / "app.py").write_text(
        'import ctypes\nz = ctypes.CDLL("libz.so.1")\nprint("hello")\n', encoding="utf-8")
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py"]),
        dependencies=[{"dependency_id": "z-old", "name": "z", "version": "1.0",
                       "purl": "pkg:generic/z@1.0"}],
        native_advisory_matches=[{"cve_id": "CVE-2026-1234", "name": "z", "version": "1.0",
                                 "purl": "pkg:generic/z@1.0", "dependency_ids": ["z-old"]}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert doc["advisories"][0]["reachability"] == REACHABILITY_IMPORTED
    assert all(site["symbol"] != "print" for site in doc["advisories"][0]["call_sites"])


def test_local_module_prevents_external_package_symbol_binding(tmp_path):
    doc = _python_advisory(
        tmp_path, "import danger\ndanger.parse(value)\n",
        additional_sources={"danger.py": "def parse(value): return value\n"},
    )
    assert doc["advisories"][0]["reachability"] == REACHABILITY_UNKNOWN
    assert "reachability_python_binding_ambiguous:app.py" in doc["gaps"]


def test_invalid_python_remains_unknown_with_parse_gap(tmp_path):
    doc = _python_advisory(tmp_path, "from danger import parse\nif (: parse(value)\n")
    assert doc["advisories"][0]["reachability"] == REACHABILITY_UNKNOWN
    assert "reachability_python_parse_failed:app.py" in doc["gaps"]


@pytest.mark.parametrize("purl,version,expected", [
    ("pkg:npm/same@1.0", "1.0", ["old"]),
    ("pkg:npm/same@1.0", None, ["old"]),
    ("pkg:npm/same@1.0", "2.0", []),
    (None, "1.0", []),
    ("pkg:npm/other/same@1.0", "1.0", []),
], ids=["exact", "purl-version", "conflict", "unknown", "foreign-namespace"])
def test_scanner_binding_uses_coordinates_not_display_name(tmp_path, purl, version, expected):
    from appsec_review.indexing.links import advisory_pairs

    observations = advisory_pairs({"payload": {"scanner_identity": "grype/fixture", "observation": {
        "matches": [{"vulnerability": {"id": "CVE-2026-1234"},
                     "artifact": {"name": "same", "version": version, "purl": purl}}],
    }}})
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=None, dependencies=[
            {"dependency_id": identifier, "name": "same", "version": release,
             "purl": f"pkg:{eco}/same@{release}"}
            for identifier, eco, release in [
                ("old", "npm", "1.0"), ("fixed", "npm", "2.0"), ("foreign", "pypi", "1.0"),
            ]
        ], scanner_advisories=observations,
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    record = doc["advisories"][0]
    assert record["dependency_ids"] == expected
    if not expected:
        assert record["reachability"] == REACHABILITY_UNKNOWN
        assert any("sca_dependency_binding_unresolved:" in gap for gap in doc["gaps"])


def test_same_advisory_separates_ecosystems_and_osv_fixed_versions(tmp_path):
    database = tmp_path / "build.sqlite"
    _build_osv_sqlite(database, [{
        "id": "CVE-2026-1234", "affected": [{
            "package": {"ecosystem": "npm", "name": "same"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
        }],
    }])
    dependencies = [
        {"dependency_id": identifier, "name": "same", "version": release,
         "purl": f"pkg:{eco}/same@{release}"}
        for identifier, eco, release in [
            ("old", "npm", "1.0.0"), ("fixed", "npm", "2.0.0"), ("foreign", "pypi", "1.0.0"),
        ]
    ]
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=None, dependencies=dependencies, osv_snapshot=_pin(tmp_path / "feed", database),
        scanner_advisories=[{"advisory": "CVE-2026-1234", "package": "same", "version": "1.0.0",
                             "purl": "pkg:pypi/same@1.0.0"}],
    )
    assert [(row["ecosystem"], row["dependency_ids"]) for row in doc["advisories"]] == [
        ("PyPI", ["foreign"]), ("npm", ["old"]),
    ]


def test_scanner_binding_preserves_purl_qualifiers_and_explicit_instance_ids(tmp_path):
    base = "pkg:generic/same@1.0"
    dependencies = [
        {"dependency_id": identifier, "name": "same", "version": "1.0", "purl": base + qualifier}
        for identifier, qualifier in [("plain", ""), ("x86", "?arch=x86"), ("arm", "?arch=arm")]
    ]
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=None, dependencies=dependencies,
        scanner_advisories=[{"advisory": "CVE-2026-1234", "package": "same",
                             "purl": base + "?arch=arm", "version": "1.0"}],
        native_advisory_matches=[{"cve_id": "CVE-2026-1235", "name": "same",
                                 "purl": base, "version": "1.0", "dependency_ids": ["arm"]}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    by_id = {row["advisory_id"]: row for row in doc["advisories"]}
    assert by_id["CVE-2026-1234"]["dependency_ids"] == ["arm"]
    assert by_id["CVE-2026-1235"]["dependency_ids"] == []


def test_osv_symbols_are_taken_only_from_the_version_matched_affected_entry(tmp_path):
    database = tmp_path / "build.sqlite"
    _build_osv_sqlite(database, [{
        "id": "PYSEC-binding", "affected": [
            {"package": {"ecosystem": "PyPI", "name": "danger"}, "versions": [version],
             "ecosystem_specific": {"imports": [{"path": "danger", "symbols": [symbol]}]}}
            for version, symbol in [("1.0", "other"), ("2.0", "parse")]
        ],
    }])
    (tmp_path / "app.py").write_text("import danger\ndanger.parse(value)\n", encoding="utf-8")
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py"]),
        dependencies=[{"dependency_id": "old", "name": "danger", "purl": "pkg:pypi/danger@1.0"}],
        osv_snapshot=_pin(tmp_path / "feed", database),
    )
    assert doc["advisories"][0]["affected_symbols"] == ["danger.other"]
    assert doc["advisories"][0]["reachability"] == REACHABILITY_IMPORTED


def test_multiple_installed_versions_do_not_select_a_source_import_instance(tmp_path):
    (tmp_path / "app.py").write_text("import danger\ndanger.parse(value)\n", encoding="utf-8")
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py"]),
        dependencies=[{"dependency_id": version, "name": "danger", "purl": f"pkg:pypi/danger@{version}"}
                      for version in ["1.0", "2.0"]],
        scanner_advisories=[{"advisory": "PYSEC-binding", "package": "danger", "version": "1.0",
                             "purl": "pkg:pypi/danger@1.0", "affected_symbols": ["parse"],
                             "affected_modules": ["danger"]}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert doc["advisories"][0]["dependency_ids"] == ["1.0"]
    assert doc["advisories"][0]["reachability"] == REACHABILITY_IMPORTED
    assert "reachability_package_binding_ambiguous:PYSEC-binding:danger" in doc["gaps"]


@pytest.mark.parametrize("purl,modules,expected", [
    ("pkg:npm/danger@1.0", ["danger"], REACHABILITY_UNKNOWN),
    ("pkg:pypi/danger@1.0", [], REACHABILITY_IMPORTED),
], ids=["foreign-source-ecosystem", "missing-module-map"])
def test_source_name_alone_does_not_bind_package_symbols(tmp_path, purl, modules, expected):
    (tmp_path / "app.py").write_text("import danger\ndanger.parse(value)\n", encoding="utf-8")
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py"]),
        dependencies=[{"dependency_id": "dep", "name": "danger", "purl": purl}],
        scanner_advisories=[{"advisory": "ADV-binding", "package": "danger", "purl": purl,
                             "affected_symbols": ["parse"], "affected_modules": modules}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert doc["advisories"][0]["dependency_ids"] == ["dep"]
    assert doc["advisories"][0]["reachability"] == expected
    assert "reachability_symbol_binding_not_established:ADV-binding" in doc["gaps"]


def test_merged_observations_do_not_invent_module_symbol_pairs(tmp_path):
    (tmp_path / "app.py").write_text("import danger\ndanger.parse(value)\n", encoding="utf-8")
    observation = {"advisory": "ADV-binding", "package": "danger", "purl": "pkg:pypi/danger@1.0"}
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py"]),
        dependencies=[{"dependency_id": "dep", "name": "danger", "purl": observation["purl"]}],
        scanner_advisories=[
            {**observation, "affected_symbols": ["parse"]},
            {**observation, "affected_symbols": ["other"], "affected_modules": ["danger"]},
        ],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert len(doc["advisories"]) == 1
    assert doc["advisories"][0]["reachability"] == REACHABILITY_IMPORTED


@pytest.mark.parametrize("defect", ["missing-instance-id", "incomplete-competing-release"])
def test_incomplete_dependency_evidence_never_fabricates_symbol_binding(tmp_path, defect):
    (tmp_path / "app.py").write_text("import danger\ndanger.parse(value)\n", encoding="utf-8")
    dependencies = [{"name": "danger", "purl": "pkg:pypi/danger@1.0"}]
    if defect == "incomplete-competing-release":
        dependencies[0]["dependency_id"] = "old"
        dependencies.append({"dependency_id": "other", "name": "danger"})
    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT, repository_root=ROOT, run_root=tmp_path / "run",
        target_root=tmp_path, partition_files=_files(tmp_path, ["app.py"]), dependencies=dependencies,
        scanner_advisories=[{"advisory": "ADV-binding", "package": "danger", "purl": "pkg:pypi/danger@1.0",
                             "affected_symbols": ["parse"], "affected_modules": ["danger"]}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )
    assert doc["advisories"][0]["dependency_ids"] == (
        [] if defect == "missing-instance-id" else ["old"])
    assert doc["advisories"][0]["reachability"] == (
        REACHABILITY_UNKNOWN if defect == "missing-instance-id" else REACHABILITY_IMPORTED)
