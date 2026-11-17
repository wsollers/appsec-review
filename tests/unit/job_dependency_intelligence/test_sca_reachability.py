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
    REACHABILITY_UNREACHABLE,
    evaluate_sca_reachability,
)


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


def test_default_settings_use_index_mode_and_validate_bounds() -> None:
    cfg = DependencyIntelligenceSettings.from_settings({})
    assert cfg.osv_version_matching == "index"
    assert cfg.reachability_enabled is True
    with pytest.raises(ValueError, match="osv_version_matching"):
        DependencyIntelligenceSettings.from_settings({"osv_version_matching": "bogus"})


def test_indexed_osv_matching_and_four_reachability_classifications(tmp_path: Path) -> None:
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
        osv_snapshot=osv_root,
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)

    assert doc["schema"] == REACHABILITY_SCHEMA
    assert doc["osv_matching_mode"] == "index"
    assert doc["osv_fallback_reason"] is None
    assert doc["telemetry"]["osv_matching_mode"] == "index"
    assert doc["telemetry"]["advisories_matched"] == 4
    assert doc["telemetry"]["symbol_reachable_count"] == 1

    by_id = {item["advisory_id"]: item for item in doc["advisories"]}
    assert by_id["GHSA-sym-0001"]["reachability"] == REACHABILITY_SYMBOL
    assert any(cs["path"] == "src/app.ts" and cs["symbol"] == "parseUnsafeRange" for cs in by_id["GHSA-sym-0001"]["call_sites"])
    assert by_id["GHSA-imp-0002"]["reachability"] == REACHABILITY_IMPORTED
    assert by_id["GHSA-trn-0003"]["reachability"] == REACHABILITY_TRANSITIVE
    assert by_id["GHSA-unr-0004"]["reachability"] == REACHABILITY_UNREACHABLE


def test_graceful_fallback_to_exact_when_osv_index_tables_absent(tmp_path: Path) -> None:
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

    doc = evaluate_sca_reachability(
        source_fingerprint=SNAPSHOT,
        repository_root=ROOT,
        run_root=tmp_path / "run",
        target_root=target,
        dependencies=[{"dependency_id": "d-yaml", "name": "pyyaml", "version": "5.3.1", "ecosystem": "pypi"}],
        osv_snapshot=raw_dir,
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)
    assert doc["configured_osv_mode"] == "index"
    assert doc["osv_matching_mode"] == "exact"
    assert doc["osv_fallback_reason"] is not None
    assert doc["telemetry"]["osv_matching_mode"] == "exact"
    assert doc["telemetry"]["advisories_matched"] == 1
    assert doc["advisories"][0]["reachability"] == REACHABILITY_SYMBOL


def test_eight_ecosystem_native_ffi_boundary_reachability(tmp_path: Path) -> None:
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
        dependencies=[],
        native_advisory_matches=native_matches,
    )

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema)
    assert doc["telemetry"]["advisories_matched"] == 8
    assert doc["telemetry"]["ffi_boundary_matches"] == 8
    assert doc["telemetry"]["symbol_reachable_count"] == 8
    for adv in doc["advisories"]:
        assert adv["reachability"] == REACHABILITY_SYMBOL
        assert adv["ffi_mechanisms"]
        assert adv["call_sites"]
